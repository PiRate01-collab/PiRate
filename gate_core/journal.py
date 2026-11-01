"""Checksummed, atomic, strict-schema operation journal. Contains no argv or secrets."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid
from .plans import ConnectionState, TRANSITIONS
from .resources import ResourceKind


class JournalError(ValueError):
    pass


def operation_id(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise JournalError('Invalid operation ID') from None
    return value


def resource_name(owner, kind):
    operation_id(owner)
    return 'gate_' + uuid.UUID(owner).hex + '_' + ResourceKind(kind).value


def private_directory(path):
    path = Path(path)
    # Reject symlinks in every existing ancestor, including the directory itself.
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise JournalError('Unsafe journal directory')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise JournalError('Journal directory must be private and owned by current user')
    return path


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def atomic_json(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.journal-', delete=False) as out:
            temporary = Path(out.name)
            os.fchmod(out.fileno(), 0o600)
            out.write(canonical(data))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise JournalError('Journal persistence failed; reload required') from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate(data):
    try:
        if not isinstance(data, dict) or set(data) != {'schema', 'owner', 'mode', 'operation_id', 'state', 'resources'}:
            raise ValueError()
        if type(data['schema']) is not int or data['schema'] != 1 or data['owner'] != 'gate-native' or data['mode'] != 'simulation':
            raise ValueError()
        owner = operation_id(data['operation_id'])
        ConnectionState(data['state'])
        if not isinstance(data['resources'], list) or len(data['resources']) > len(ResourceKind):
            raise ValueError()
        kinds = set()
        for record in data['resources']:
            if not isinstance(record, dict) or set(record) != {'kind', 'name', 'status'}:
                raise ValueError()
            kind = ResourceKind(record['kind'])
            if kind in kinds or record['name'] != resource_name(owner, kind):
                raise ValueError()
            kinds.add(kind)
            if record['status'] not in ('pending', 'acquired', 'released', 'cleanup_failed'):
                raise ValueError()
        if data['state'] == 'stopped' and any(r['status'] != 'released' for r in data['resources']):
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise JournalError('Invalid journal schema or ownership') from None


class PersistentJournal:
    def __init__(self, directory, data):
        self.directory = private_directory(directory)
        validate(data)
        self._data = copy.deepcopy(data)
        self.valid = True

    @property
    def data(self):
        if not self.valid:
            raise JournalError('Journal must be reloaded')
        return copy.deepcopy(self._data)

    @property
    def path(self):
        return self.directory / (self._data['operation_id'] + '.json')

    @classmethod
    def create(cls, directory):
        data = {'schema': 1, 'owner': 'gate-native', 'mode': 'simulation', 'operation_id': str(uuid.uuid4()),
                'state': 'planned', 'resources': []}
        journal = cls(directory, data)
        if journal.path.exists():
            raise JournalError('Operation already exists')
        journal.save(data)
        return journal

    @classmethod
    def load(cls, directory, identifier):
        identifier = operation_id(identifier)
        directory = private_directory(directory)
        path = directory / (identifier + '.json')
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                    raise JournalError('Unsafe journal file')
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise JournalError('Journal too large')
            def unique_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise JournalError('Duplicate journal field')
                    result[key] = value
                return result
            envelope = json.loads(raw, object_pairs_hook=unique_pairs)
            if not isinstance(envelope, dict) or set(envelope) != {'data', 'sha256'}:
                raise JournalError('Invalid journal envelope')
            data = envelope['data']
            if envelope['sha256'] != hashlib.sha256(canonical(data)).hexdigest():
                raise JournalError('Journal integrity failure')
            validate(data)
            if data['operation_id'] != identifier:
                raise JournalError('Journal identity mismatch')
            return cls(directory, data)
        except (OSError, ValueError, TypeError, RecursionError):
            raise JournalError('Journal unreadable or invalid; recovery required') from None

    def save(self, data):
        if not self.valid:
            raise JournalError('Journal must be reloaded')
        validate(data)
        if data['operation_id'] != self._data['operation_id']:
            raise JournalError('Operation identity immutable')
        envelope = {'data': data, 'sha256': hashlib.sha256(canonical(data)).hexdigest()}
        try:
            atomic_json(self.path, envelope)
        except JournalError:
            self.valid = False
            raise
        self._data = copy.deepcopy(data)

    def transition(self, target):
        data = self.data
        target = ConnectionState(target)
        if target not in TRANSITIONS[ConnectionState(data['state'])]:
            raise JournalError('Invalid connection transition')
        data['state'] = target.value
        self.save(data)

    def intend(self, kind):
        data = self.data
        kind = ResourceKind(kind)
        if any(r['kind'] == kind.value for r in data['resources']):
            raise JournalError('Resource already recorded')
        record = {'kind': kind.value, 'name': resource_name(data['operation_id'], kind), 'status': 'pending'}
        data['resources'].append(record)
        self.save(data)
        return record

    def mark(self, kind, status):
        if status not in ('acquired', 'released', 'cleanup_failed'):
            raise JournalError('Invalid resource status')
        data = self.data
        for record in data['resources']:
            if record['kind'] == ResourceKind(kind).value:
                if record['status'] == 'released':
                    if status == 'released':
                        return
                    raise JournalError('Released resource cannot be reacquired')
                record['status'] = status
                self.save(data)
                return
        raise JournalError('Unknown resource')
