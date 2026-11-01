"""Serialized durable Safe Apply simulation. Never instantiates a real executor."""
import uuid
from ...process_lock import ProcessLock
from ..models import profile_id, validate_saved, FIELDS
from ..validation import validate_configuration
from .state import ApplyError, ApplyState, TERMINAL, transition
from .persistence import CheckedRecords, PersistenceError, fingerprint, interface_name
from .snapshots import SnapshotManager
from .executor import MockRadioExecutor, OwnershipError
from .clock import SystemClock

CODES = {'apply_failed', 'rollback_failed', 'ownership_or_snapshot_invalid',
         'preapply_recovered', 'confirmation_expired', 'restart_recovery', 'clock_changed'}
FIELDS_OPERATION = {'owner', 'mode', 'operation_id', 'interface', 'profile_id',
                    'target_digest', 'before_digest', 'state', 'started_at',
                    'expires_at', 'snapshot_ref', 'sequence', 'diagnostics'}


class ApplyController:
    def __init__(self, root, executor, *, store=None, capabilities=None, secrets=None,
                 clock=None, watchdog_ready=False):
        if type(executor) is not MockRadioExecutor:
            raise ApplyError('Only the mock radio executor is permitted')
        self.records = CheckedRecords(root, 'operations')
        if executor.records.root != self.records.root:
            raise ApplyError('Mock executor storage mismatch')
        self.snapshots = SnapshotManager(root)
        self.recovery_reports = CheckedRecords(root, 'recovery')
        self.executor, self.store = executor, store
        self.capabilities, self.secrets = capabilities, secrets
        self.clock = clock or SystemClock()
        self.watchdog_ready = watchdog_ready

    def _now(self):
        now = self.clock.now()
        if type(now) is not int or now < 0:
            raise ApplyError('Invalid watchdog clock')
        return now

    def _lock(self, interface):
        return ProcessLock(self.records.root / ('interface-' + fingerprint(interface_name(interface)) + '.lock'), timeout=0)

    def _read(self, identifier):
        data = self.records.read(identifier)
        try:
            if not isinstance(data, dict) or set(data) != FIELDS_OPERATION:
                raise ValueError()
            if data['owner'] != 'pirate-mock-apply' or data['mode'] != 'simulation' or data['operation_id'] != identifier:
                raise ValueError()
            profile_id(identifier); profile_id(data['profile_id']); interface_name(data['interface'])
            ApplyState(data['state'])
            for field in ('target_digest', 'before_digest'):
                value = data[field]
                if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                    raise ValueError()
            if data['snapshot_ref'] not in (None, identifier):
                raise ValueError()
            if any(type(data[k]) is not int for k in ('started_at', 'expires_at', 'sequence')) or data['started_at'] < 0 or not 15 <= data['expires_at'] - data['started_at'] <= 300 or data['sequence'] < 1:
                raise ValueError()
            if not isinstance(data['diagnostics'], list) or len(data['diagnostics']) > len(CODES) or any(type(x) is not str or x not in CODES for x in data['diagnostics']) or len(set(data['diagnostics'])) != len(data['diagnostics']):
                raise ValueError()
        except (ValueError, TypeError):
            raise PersistenceError('Operation ownership or schema invalid; recovery required') from None
        return data

    def _all(self):
        records = [self._read(i) for i in self.records.identifiers()]
        keys = [(x['interface'], x['sequence']) for x in records]
        if len(set(keys)) != len(keys):
            raise PersistenceError('Operation ordering invalid; recovery required')
        for interface in {x['interface'] for x in records}:
            same = [x for x in records if x['interface'] == interface]
            latest = max(x['sequence'] for x in same)
            if any(x['state'] not in TERMINAL and x['sequence'] != latest for x in same):
                raise PersistenceError('Overlapping operation journal; recovery required')
        return records

    def _latest(self, operation):
        same = [x for x in self._all() if x['interface'] == operation['interface']]
        if max(same, key=lambda x: x['sequence'])['operation_id'] != operation['operation_id']:
            raise ApplyError('Stale operation cannot be confirmed or rolled back')

    def _move(self, operation, state, code=None):
        proposed = {**operation, 'state': transition(operation['state'], state),
                    'diagnostics': list(operation['diagnostics'])}
        if code and code not in proposed['diagnostics']:
            proposed['diagnostics'].append(code)
        self.records.write(operation['operation_id'], proposed)
        operation.update(proposed)

    def _public(self, operation):
        return {k: operation[k] for k in ('operation_id', 'profile_id', 'interface', 'state', 'expires_at', 'diagnostics')} | {
            'mock_only': True, 'real_apply_available': False,
            'remaining_seconds': max(0, operation['expires_at'] - self._now()) if operation['state'] == 'awaiting_confirmation' else 0}

    def status(self, identifier=None):
        if identifier is not None:
            return self._public(self._read(profile_id(identifier)))
        return {'operations': [self._public(x) for x in self._all()], 'mock_only': True, 'real_apply_available': False}

    def _profile(self, identifier):
        if self.store is None:
            raise ApplyError('Saved mock profile store unavailable')
        profile = next((x for x in self.store.list() if x['id'] == profile_id(identifier)), None)
        if profile is None:
            raise ApplyError('Saved Wi-Fi profile not found')
        return validate_saved(profile)

    def preview(self, identifier, interface):
        target = self._profile(identifier)
        before = self.executor.inspect(interface_name(interface))['profile']
        # References and snapshot contents are never part of public preview data.
        fields = sorted(FIELDS - {'password_ref'})
        return {'mock_only': True, 'real_apply_available': False, 'changes': [
            {'field': k, 'before': before[k] if before else None, 'after': target[k]}
            for k in fields if before is None or before[k] != target[k]],
            'credential_reference_changed': before is None or before['password_ref'] != target['password_ref']}

    def start(self, identifier, interface, timeout=60, operation_id=None):
        interface_name(interface); profile_id(identifier)
        operation_id = profile_id(operation_id) if operation_id is not None else str(uuid.uuid4())
        if type(timeout) is not int or not 15 <= timeout <= 300:
            raise ApplyError('Confirmation timeout must be 15..300 seconds')
        # Registry lock prevents a caller-supplied UUID collision across interfaces.
        with self._lock(interface), ProcessLock(self.records.root / 'registry.lock', timeout=0):
            records = self._all()
            old = next((x for x in records if x['operation_id'] == operation_id), None)
            if old is not None:
                if (old['profile_id'], old['interface'], old['expires_at'] - old['started_at']) != (identifier, interface, timeout):
                    raise ApplyError('Operation ID already used for a different request')
                self._latest(old)
                return self._public(old)
            same = [x for x in records if x['interface'] == interface]
            if any(x['state'] not in TERMINAL for x in same):
                raise ApplyError('An unfinished operation requires confirmation or recovery')
            target = self._profile(identifier)
            if self.capabilities is None or self.capabilities.source != 'mock' or self.capabilities.interface != interface:
                raise ApplyError('Verified synthetic hardware capabilities required')
            report = validate_configuration({k: target[k] for k in FIELDS}, self.capabilities, self.secrets, identifier=identifier)
            if report['status'] != 'compatible':
                raise ApplyError('Profile settings or secret references are not verified for mock hardware')
            if self.watchdog_ready is not True or self.executor.rollback_available is not True:
                raise ApplyError('Independent watchdog and rollback must be available')
            before = self.executor.inspect(interface)
            now = self._now()
            operation = {'owner': 'pirate-mock-apply', 'mode': 'simulation', 'operation_id': operation_id,
                         'interface': interface, 'profile_id': identifier, 'target_digest': fingerprint(target),
                         'before_digest': fingerprint(before), 'state': 'idle', 'started_at': now,
                         'expires_at': now + timeout, 'snapshot_ref': None,
                         'sequence': max((x['sequence'] for x in same), default=0) + 1, 'diagnostics': []}
            self.records.write(operation_id, operation, create=True)
            try:
                self._move(operation, 'validating')
                self._move(operation, 'snapshotting')
                self.snapshots.save(operation_id, interface, before)
                operation['snapshot_ref'] = operation_id
                self._move(operation, 'applying')  # Deadline and snapshot durable before mutation.
                if self.executor.apply(interface, operation_id, target, operation['before_digest']) is not True or self.executor.verify(interface, operation_id, operation['target_digest']) is not True:
                    raise ApplyError('Mock apply result not verified')
                self._move(operation, 'awaiting_confirmation')
                current_time = self._now()
                if current_time < now or current_time >= operation['expires_at']:
                    self._rollback(operation, 'clock_changed' if current_time < now else 'confirmation_expired')
            except PersistenceError:
                # An ambiguous write cannot be followed by more changes using stale state.
                raise
            except Exception:
                self._rollback(operation, 'apply_failed')
            return self._public(operation)

    def confirm(self, identifier):
        operation = self._read(profile_id(identifier))
        with self._lock(operation['interface']):
            operation = self._read(identifier); self._latest(operation)
            if operation['state'] == 'confirmed':
                return self._public(operation)
            if operation['state'] != 'awaiting_confirmation':
                raise ApplyError('Operation is not awaiting confirmation')
            now = self._now()
            if now < operation['started_at'] or now >= operation['expires_at']:
                self._rollback(operation, 'clock_changed' if now < operation['started_at'] else 'confirmation_expired')
            else:
                try:
                    verified = self.executor.verify(operation['interface'], identifier, operation['target_digest'])
                except Exception:
                    verified = False
                if verified is not True:
                    self._rollback(operation, 'apply_failed')
                else:
                    # Verification can consume the remaining confirmation window.
                    checked_at = self._now()
                    if checked_at < operation['started_at'] or checked_at >= operation['expires_at']:
                        self._rollback(operation, 'clock_changed' if checked_at < operation['started_at'] else 'confirmation_expired')
                    else:
                        self._move(operation, 'confirmed')
            return self._public(operation)

    def _rollback(self, operation, code):
        if operation['state'] == 'rolled_back':
            return
        if operation['state'] == 'confirmed':
            raise ApplyError('Confirmed operation cannot be rolled back')
        try:
            current = self.executor.inspect(operation['interface'])
            if operation['state'] in ('idle', 'validating', 'snapshotting', 'failed'):
                if fingerprint(current) != operation['before_digest']:
                    raise ApplyError('Preapply baseline changed')
                if operation['state'] != 'failed':
                    self._move(operation, 'failed', code)
                self._move(operation, 'rolled_back', 'preapply_recovered')
                return
            snapshot = self.snapshots.load(operation['operation_id'], operation['interface'])
            if operation['snapshot_ref'] != operation['operation_id'] or snapshot['before_digest'] != operation['before_digest']:
                raise ApplyError('Snapshot does not match operation')
            if operation['state'] != 'rolling_back':
                self._move(operation, 'rolling_back', code)
            if self.executor.restore(operation['interface'], operation['operation_id'], snapshot['before']) is not True:
                raise ApplyError('Rollback result not verified')
            if self.executor.verify(operation['interface'], operation['operation_id'], fingerprint(snapshot['before']['profile'])) is not True:
                raise ApplyError('Rollback verification failed')
            self._move(operation, 'rolled_back')
        except PersistenceError:
            # Snapshot corruption also uses PersistenceError; reload operation first.
            operation.update(self._read(operation['operation_id']))
            if operation['state'] not in TERMINAL and operation['state'] != 'recovery_required':
                self._move(operation, 'recovery_required', 'ownership_or_snapshot_invalid')
        except OwnershipError:
            if operation['state'] not in TERMINAL and operation['state'] != 'recovery_required':
                self._move(operation, 'recovery_required', 'ownership_or_snapshot_invalid')
        except Exception:
            if operation['state'] not in TERMINAL and operation['state'] != 'recovery_required':
                self._move(operation, 'recovery_required', 'rollback_failed')

    def rollback(self, identifier):
        operation = self._read(profile_id(identifier))
        with self._lock(operation['interface']):
            operation = self._read(identifier); self._latest(operation)
            self._rollback(operation, 'restart_recovery')
            return self._public(operation)

    def _report(self, result):
        self.recovery_reports.write(str(uuid.uuid5(uuid.NAMESPACE_URL, 'pirate-mock-recovery-report')), result)
        return result

    def recover(self, *, reboot=False):
        try:
            records = self._all()
        except ApplyError:
            return self._report({'state': 'recovery_required', 'diagnostics': ['journal_invalid'], 'mock_only': True, 'real_apply_available': False})
        results = []
        for initial in records:
            if initial['state'] in TERMINAL:
                continue
            with self._lock(initial['interface']):
                operation = self._read(initial['operation_id'])
                if operation['state'] in TERMINAL:
                    continue
                self._latest(operation)
                now = self._now()
                expired = now >= operation['expires_at'] or now < operation['started_at']
                if operation['state'] != 'awaiting_confirmation' or reboot or expired:
                    self._rollback(operation, 'clock_changed' if now < operation['started_at'] else 'confirmation_expired' if expired else 'restart_recovery')
                results.append(self._public(operation))
        return self._report({'operations': results, 'mock_only': True, 'real_apply_available': False})
