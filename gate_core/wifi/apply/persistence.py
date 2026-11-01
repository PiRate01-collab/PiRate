"""Private atomic checked records. File names never come from journal commands."""
import hashlib
import json
import os
import re
import stat
from ...journal import atomic_json, canonical, private_directory, JournalError
from ..models import profile_id
from .state import ApplyError


class PersistenceError(ApplyError):
    pass


def interface_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', value) or value in ('.', '..', 'lo'):
        raise ApplyError('Invalid mock interface identifier')
    return value


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class CheckedRecords:
    def __init__(self, root, kind):
        if kind not in ('operations', 'snapshots', 'radio', 'recovery'):
            raise PersistenceError('Unsupported private record type')
        try:
            self.root = private_directory(root)
            self.directory = private_directory(self.root / kind)
        except (OSError, JournalError):
            raise PersistenceError('Private mock storage unavailable') from None
        self.kind = kind

    def path(self, identifier):
        profile_id(identifier)
        return self.directory / (identifier + '.json')

    def write(self, identifier, data, *, create=False):
        path = self.path(identifier)
        if path.is_symlink() or (create and path.exists()):
            raise PersistenceError('Private record collision or symlink')
        try:
            atomic_json(path, {'data': data, 'sha256': fingerprint(data)})
        except (OSError, JournalError):
            raise PersistenceError('Private record write failed; reload required') from None

    def read(self, identifier):
        path = self.path(identifier)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise PersistenceError('Unsafe private record')
                raw = stream.read(65537)
            def unique(pairs):
                data = {}
                for key, value in pairs:
                    if key in data:
                        raise PersistenceError('Duplicate private record field')
                    data[key] = value
                return data
            if len(raw) > 65536:
                raise PersistenceError('Private record too large')
            envelope = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(envelope, dict) or set(envelope) != {'data', 'sha256'} or envelope['sha256'] != fingerprint(envelope['data']):
                raise PersistenceError('Private record integrity failure')
            return envelope['data']
        except (OSError, ValueError, TypeError, RecursionError):
            raise PersistenceError('Private record unreadable or invalid') from None

    def identifiers(self):
        for path in sorted(self.directory.glob('*.json')):
            try:
                yield profile_id(path.stem)
            except ValueError:
                raise PersistenceError('Unknown private record; recovery required') from None
