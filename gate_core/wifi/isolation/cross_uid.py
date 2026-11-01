"""Separate-owner synthetic protocol. Does not call the Wi-Fi executor.

Broker owns authorization + intent journal. Watchdog alone owns recovery, snapshot
and a synthetic resource. Arm durably transfers a fixed binding; all subsequent
requests repeat it. No shared writable record or client-selected filesystem path.
"""
import os
import json
import stat
from pathlib import Path
import time
import uuid
from ..broker.contracts import BrokerError
from ..models import profile_id
from ..system.storage import PrivateRecords, digest, FoundationError

RESOURCE = 'ap-primary'
INVENTORY = '00000000-0000-4000-8000-000000000021'
SESSION = '00000000-0000-4000-8000-000000000022'
RESERVED = {INVENTORY, SESSION}
BASELINE = 'synthetic-baseline'
BINDING = {'operation_id', 'resource_id', 'artifact_id', 'grant_id', 'grant_digest', 'subject_uid', 'subject_gid', 'deadline', 'arm_generation'}
STATES = {'armed', 'awaiting_confirmation', 'confirmed', 'rolled_back', 'recovery_required'}


def identifier(value):
    try:
        result = profile_id(value)
        if result in RESERVED:
            raise ValueError()
        return result
    except ValueError:
        raise BrokerError('invalid_request') from None


def validate_binding(binding):
    if not isinstance(binding, dict) or set(binding) != BINDING or binding['resource_id'] != RESOURCE:
        raise BrokerError('resource_denied')
    for key in ('operation_id', 'artifact_id', 'grant_id', 'arm_generation'):
        identifier(binding[key])
    for key in ('subject_uid', 'subject_gid', 'deadline'):
        if type(binding[key]) is not int or not 0 <= binding[key] <= 2**63 - 1:
            raise BrokerError('invalid_request')
    value = binding['grant_digest']
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise BrokerError('invalid_grant')
    return binding


def validate_grant(grant, binding):
    fields = (BINDING - {'grant_digest'}) | {'owner'}
    if not isinstance(grant, dict) or set(grant) != fields or grant['owner'] != 'broker-synthetic':
        raise BrokerError('invalid_grant')
    candidate = {key: grant[key] for key in BINDING - {'grant_digest'}}
    candidate['grant_digest'] = digest(grant)
    validate_binding(candidate)
    if candidate != binding:
        raise BrokerError('invalid_grant')
    return grant


def request_schema(request, actions, fields):
    if not isinstance(request, dict) or set(request) != {'version', 'action', 'nonce'} | fields or type(request['version']) is not int or request['version'] != 1 or type(request['action']) is not str or request['action'] not in actions:
        raise BrokerError('invalid_request')
    identifier(request['nonce'])


def response(binding, state, generation):
    return {'binding': binding, 'state': state, 'generation': generation, 'dry_run': True, 'real_execution_available': False}


def check_response(result, binding, generation, allowed=STATES):
    if not isinstance(result, dict) or set(result) != {'binding', 'state', 'generation', 'dry_run', 'real_execution_available'} or result['binding'] != binding or result['generation'] != generation or result['state'] not in allowed or result['dry_run'] is not True or result['real_execution_available'] is not False:
        raise BrokerError('readiness_unknown')
    # Equality alone would accept bools as integers.
    validate_binding(result['binding'])
    return result


class RecoveryOwner:
    def __init__(self, root, web_subject, *, clock=time.time):
        self.root = PrivateRecords(root)
        self.recovery = PrivateRecords(Path(root) / 'recovery')
        self.snapshots = PrivateRecords(Path(root) / 'snapshots')
        self.grants = PrivateRecords(Path(root) / 'grants')
        self.resource = PrivateRecords(Path(root) / 'resource')
        self.web_subject, self.clock = web_subject, clock
        self.generation = str(uuid.uuid4())
        self.blocked = False
        self.guard = self.root.lock()
        self.guard.__enter__()  # One recovery owner for the complete process lifetime.
        try:
            self._startup()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.guard is not None:
            self.guard.__exit__(None, None, None)
            self.guard = None

    def _inventory(self):
        value = self.resource.read(INVENTORY)
        if not isinstance(value, dict) or set(value) != {'owner', 'lease', 'value'} or value['owner'] != 'watchdog-synthetic' or type(value['value']) is not str:
            raise FoundationError('Synthetic ownership unknown')
        if value['lease'] is not None:
            identifier(value['lease'])
        return value

    def _record(self, operation):
        record = self.recovery.read(operation)
        if not isinstance(record, dict) or set(record) != {'owner', 'binding', 'state'} or record['owner'] != 'watchdog-synthetic' or record['state'] not in STATES:
            raise FoundationError('Recovery ownership unknown')
        validate_binding(record['binding'])
        if record['binding']['operation_id'] != operation or (record['binding']['subject_uid'], record['binding']['subject_gid']) != self.web_subject:
            raise FoundationError('Recovery binding unknown')
        return record

    def _save(self, binding, state, *, create=False):
        self.recovery.write(binding['operation_id'], {'owner': 'watchdog-synthetic', 'binding': binding, 'state': state}, create=create)

    def _snapshot(self, binding):
        grant = self.grants.read(binding['operation_id'])
        validate_grant(grant, binding)
        snapshot = self.snapshots.read(binding['operation_id'])
        if not isinstance(snapshot, dict) or set(snapshot) != {'owner', 'binding', 'before'} or snapshot['owner'] != 'watchdog-synthetic' or snapshot['binding'] != binding or snapshot['before'] != BASELINE:
            raise FoundationError('Snapshot binding unknown')
        validate_binding(snapshot['binding'])
        return snapshot

    def _rollback(self, record):
        binding = record['binding']
        try:
            snapshot = self._snapshot(binding)
            inventory = self._inventory()
            if inventory['lease'] not in (None, binding['operation_id']):
                raise FoundationError('Foreign synthetic resource')
            if inventory['lease'] is None and inventory['value'] != snapshot['before']:
                raise FoundationError('Unowned synthetic resource')
            if inventory['lease'] == binding['operation_id'] and inventory['value'] != binding['artifact_id']:
                raise FoundationError('Synthetic artifact unknown')
            self.resource.write(INVENTORY, {'owner': 'watchdog-synthetic', 'lease': None, 'value': snapshot['before']})
            self._save(binding, 'rolled_back')
            return 'rolled_back'
        except (ValueError, OSError):
            self._save(binding, 'recovery_required')
            self.blocked = True
            return 'recovery_required'

    def _startup(self):
        try:
            if not self.resource.exists(INVENTORY):
                # Never initialize over an existing recovery history.
                if self.recovery.identifiers() or self.snapshots.identifiers() or self.grants.identifiers():
                    raise FoundationError('Missing synthetic resource')
                self.resource.write(INVENTORY, {'owner': 'watchdog-synthetic', 'lease': None, 'value': BASELINE}, create=True)
            records = [self._record(op) for op in self.recovery.identifiers() if op != SESSION]
            inventory = self._inventory()
            if inventory['lease'] is not None and not any(r['binding']['operation_id'] == inventory['lease'] for r in records):
                raise FoundationError('Orphan synthetic lease')
            if any(op not in {r['binding']['operation_id'] for r in records} for op in self.snapshots.identifiers() + self.grants.identifiers()):
                raise FoundationError('Orphan synthetic snapshot')
            for record in records:
                self._snapshot(record['binding'])
                if record['state'] in ('armed', 'awaiting_confirmation'):
                    self._rollback(record)  # Restart never silently rebinds old proofs.
                elif record['state'] == 'recovery_required':
                    self.blocked = True
            self.recovery.write(SESSION, {'generation': self.generation, 'state': 'recovery_required' if self.blocked else 'ready'})
        except (ValueError, OSError):
            self.blocked = True
            self.recovery.write(SESSION, {'generation': self.generation, 'state': 'recovery_required'})

    def tick(self):
        if self.blocked:
            return
        try:
            operations = self.recovery.identifiers()
            if any(op not in operations for op in self.snapshots.identifiers() + self.grants.identifiers()):
                raise FoundationError('Orphan recovery evidence')
            for op in operations:
                if op == SESSION:
                    continue
                record = self._record(op)
                self._snapshot(record['binding'])
                self._inventory()
                if record['state'] in ('armed', 'awaiting_confirmation') and self.clock() >= record['binding']['deadline']:
                    self._rollback(record)
        except (ValueError, OSError):
            self.blocked = True
            self.recovery.write(SESSION, {'generation': self.generation, 'state': 'recovery_required'})

    def dispatch(self, peer, request):
        action = request.get('action') if isinstance(request, dict) else None
        if action == 'readiness':
            request_schema(request, {'readiness'}, set())
            self.tick()
            if self.blocked:
                raise BrokerError('recovery_required')
            return {'generation': self.generation, 'ready': True, 'dry_run': True}
        request_schema(request, {'arm', 'install', 'confirm', 'timeout', 'rollback', 'status'}, {'generation', 'binding'} | ({'grant'} if action == 'arm' else set()))
        binding = validate_binding(request['binding'])
        if request['generation'] != self.generation:
            raise BrokerError('readiness_unknown')
        if (binding['subject_uid'], binding['subject_gid']) != self.web_subject:
            raise BrokerError('invalid_grant')
        self.tick()
        if self.blocked:
            raise BrokerError('recovery_required')
        operation = binding['operation_id']
        if action == 'arm':
            validate_grant(request['grant'], binding)
            if binding['arm_generation'] != self.generation or not self.clock() < binding['deadline'] <= self.clock() + 120:
                raise BrokerError('authorization_expired')
            if self.recovery.exists(operation):
                record = self._record(operation)
                if record['binding'] != binding or record['state'] != 'armed':
                    raise BrokerError('transaction_denied')
                self._snapshot(binding)
                return response(binding, 'armed', self.generation)
            inventory = self._inventory()
            if inventory['lease'] is not None or inventory['value'] != BASELINE or any(self._record(op)['state'] in ('armed', 'awaiting_confirmation') for op in self.recovery.identifiers() if op != SESSION):
                raise BrokerError('busy')
            # Durable grant copy + snapshot + arm, before any synthetic mutation.
            self.grants.write(operation, request['grant'], create=True)
            self.snapshots.write(operation, {'owner': 'watchdog-synthetic', 'binding': binding, 'before': inventory['value']}, create=True)
            self._save(binding, 'armed', create=True)
            return response(binding, 'armed', self.generation)
        record = self._record(operation)
        if record['binding'] != binding:
            raise BrokerError('transaction_denied')
        self._snapshot(binding)
        state = record['state']
        if action == 'status':
            return response(binding, state, self.generation)
        if action in ('rollback', 'timeout'):
            if action == 'timeout' and self.clock() < binding['deadline']:
                raise BrokerError('state_denied')
            if state in ('armed', 'awaiting_confirmation'):
                state = self._rollback(record)
            elif state != 'rolled_back':
                raise BrokerError('state_denied')
            return response(binding, state, self.generation)
        if binding['arm_generation'] != self.generation or self.clock() >= binding['deadline']:
            raise BrokerError('authorization_expired')
        inventory = self._inventory()
        if action == 'install' and state == 'armed' and inventory == {'owner': 'watchdog-synthetic', 'lease': None, 'value': BASELINE}:
            self.resource.write(INVENTORY, {'owner': 'watchdog-synthetic', 'lease': operation, 'value': binding['artifact_id']})
            self._save(binding, 'awaiting_confirmation')
            state = 'awaiting_confirmation'
        elif action == 'confirm' and state == 'awaiting_confirmation' and inventory == {'owner': 'watchdog-synthetic', 'lease': operation, 'value': binding['artifact_id']}:
            # Confirmation is durable first. Resource stays bound to confirmed operation;
            # a separate future baseline transition is required for another operation.
            self._save(binding, 'confirmed')
            state = 'confirmed'
        else:
            raise BrokerError('state_denied')
        return response(binding, state, self.generation)


class SyntheticBroker:
    def __init__(self, root, watchdog, web_subject, *, clock=time.time, lifetime=30):
        if type(lifetime) is not int or not 1 <= lifetime <= 120:
            raise BrokerError('invalid_policy')
        self.root = PrivateRecords(root)
        self.grants = PrivateRecords(Path(root) / 'grants')
        self.journal = PrivateRecords(Path(root) / 'journal')
        self.watchdog, self.web_subject = watchdog, web_subject
        self.clock, self.lifetime = clock, lifetime
        self.policy_enabled = True
        self.policy = None
        self.guard = self.root.lock()
        self.guard.__enter__()

    def close(self):
        if self.guard is not None:
            self.guard.__exit__(None, None, None)
            self.guard = None

    def _generation(self):
        result = self.watchdog.call({'version': 1, 'action': 'readiness'})
        if set(result) != {'generation', 'ready', 'dry_run'} or result['ready'] is not True or result['dry_run'] is not True:
            raise BrokerError('readiness_unknown')
        return identifier(result['generation'])

    def _binding(self, operation, subject):
        grant = self.grants.read(operation)
        if not isinstance(grant, dict) or set(grant) != {'owner', 'operation_id', 'resource_id', 'artifact_id', 'grant_id', 'subject_uid', 'subject_gid', 'deadline', 'arm_generation'} or grant['owner'] != 'broker-synthetic' or grant['operation_id'] != operation or (grant['subject_uid'], grant['subject_gid']) != subject:
            raise BrokerError('invalid_grant')
        binding = {key: grant[key] for key in BINDING - {'grant_digest'}}
        binding['grant_digest'] = digest(grant)
        validate_binding(binding)
        intent = self.journal.read(operation)
        if not isinstance(intent, dict) or set(intent) != {'owner', 'binding', 'state'} or intent['owner'] != 'broker-synthetic' or intent['binding'] != binding or intent['state'] not in STATES | {'intent'}:
            raise BrokerError('transaction_denied')
        validate_binding(intent['binding'])
        return binding, intent['state']

    def dispatch(self, peer, request):
        request_schema(request, {'apply', 'confirm', 'rollback', 'status'}, {'operation_id', 'resource_id'})
        if request['resource_id'] != RESOURCE:
            raise BrokerError('resource_denied')
        operation = identifier(request['operation_id'])
        subject = peer.uid, peer.gid
        if subject != self.web_subject:
            raise BrokerError('identity_denied')
        enabled = self.policy() if self.policy is not None else self.policy_enabled
        if not enabled and request['action'] != 'status':
            raise BrokerError('action_denied')
        with self.journal.lock():
            generation = self._generation()
            action = request['action']
            if action == 'apply' and not self.grants.exists(operation):
                if self.journal.exists(operation):
                    raise BrokerError('recovery_required')
                grant = {'owner': 'broker-synthetic', 'operation_id': operation, 'resource_id': RESOURCE, 'artifact_id': str(uuid.uuid4()), 'grant_id': str(uuid.uuid4()), 'subject_uid': peer.uid, 'subject_gid': peer.gid, 'deadline': int(self.clock()) + self.lifetime, 'arm_generation': generation}
                # A crash between grant and intent remains operator-visible; no reissue.
                self.grants.write(operation, grant, create=True)
                binding = {key: grant[key] for key in BINDING - {'grant_digest'}}
                binding['grant_digest'] = digest(grant)
                self.journal.write(operation, {'owner': 'broker-synthetic', 'binding': binding, 'state': 'intent'}, create=True)
            binding, state = self._binding(operation, subject)
            def exchange(verb, allowed=STATES):
                message = {'version': 1, 'action': verb, 'generation': generation, 'binding': binding}
                if verb == 'arm':
                    message['grant'] = self.grants.read(operation)
                result = self.watchdog.call(message)
                return check_response(result, binding, generation, allowed)
            if action == 'apply':
                if state != 'intent':
                    result = exchange('status')  # Replay never installs again.
                else:
                    exchange('arm', {'armed'})
                    result = exchange('install', {'awaiting_confirmation'})
            else:
                result = exchange(action)
            self.journal.write(operation, {'owner': 'broker-synthetic', 'binding': binding, 'state': result['state']})
            # Web receives public state only, never grant, artifact or snapshot contents.
            return {'operation_id': operation, 'state': result['state'], 'deadline': binding['deadline'], 'dry_run': True, 'real_execution_available': False}


class RootPolicy:
    """Operator-only revocation file, re-read before EVERY Web action.

    The directory and file are fixed launcher inputs; not exposed through RPC.
    Supplementary groups are not consulted. Invalid/unreadable policy fails closed.
    """
    def __init__(self, path, subject):
        self.path, self.subject = Path(path).absolute(), subject

    def __call__(self):
        from .unix_transport import open_directory
        try:
            directory = open_directory(self.path.parent, 0, 0, 0o755)
            try:
                fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            finally:
                os.close(directory)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o644:
                    raise ValueError()
                raw = stream.read(1025)
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError()
                    value[key] = item
                return value
            data = json.loads(raw, object_pairs_hook=unique)
            if len(raw) > 1024 or not isinstance(data, dict) or set(data) != {'enabled', 'uid', 'gid'} or type(data['enabled']) is not bool or any(type(data[key]) is not int for key in ('uid', 'gid')) or (data['uid'], data['gid']) != self.subject:
                raise ValueError()
            return data['enabled']
        except (OSError, ValueError):
            raise BrokerError('invalid_policy') from None
