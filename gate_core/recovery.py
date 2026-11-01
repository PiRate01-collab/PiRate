"""Recovery uses typed mock operations only, never journal-provided commands."""
from pathlib import Path
from .executor import MockExecutor, ResourceOwnershipError
from .journal import PersistentJournal, JournalError, private_directory, atomic_json
from .process_lock import ProcessLock


class RecoveryManager:
    def __init__(self, directory, executor, *, lock_timeout=0):
        if type(executor) is not MockExecutor:
            raise TypeError('Only MockExecutor permitted at this stage')
        self.directory = private_directory(directory)
        self.executor = executor
        self.lock_timeout = lock_timeout

    def discover(self):
        operations, invalid = [], []
        for path in sorted(self.directory.glob('*.json')):
            if path.name == 'recovery-report.json':
                continue
            try:
                journal = PersistentJournal.load(self.directory, path.stem)
                if journal.data['state'] != 'stopped':
                    operations.append(journal)
            except JournalError:
                # Do not include untrusted file names in logs or execute their contents.
                invalid.append('unreadable_operation')
        return operations, invalid

    def cleanup_plan(self, journal):
        data = journal.data
        # Reload validates ownership and integrity before constructing typed actions.
        verified = PersistentJournal.load(self.directory, data['operation_id']).data
        if verified != data:
            raise JournalError('Journal changed; reload required')
        records = [r for r in reversed(data['resources']) if r['status'] != 'released']
        for record in records:
            owner = self.executor.resource('inspect', data['operation_id'], record['kind'])
            if owner not in (None, data['operation_id']):
                raise JournalError('Foreign resource; recovery required')
        return records

    def _cleanup_locked(self, journal):
        data = journal.data
        if data['state'] == 'stopped':
            return 'stopped'
        try:
            records = self.cleanup_plan(journal)
        except Exception:
            if journal.data['state'] != 'recovery_required':
                journal.transition('recovery_required')
            return 'recovery_required'
        if journal.data['state'] != 'stopping':
            # Recovery is permitted even from planned/preparing after a crash.
            if journal.data['state'] == 'planned':
                journal.transition('recovery_required')
            journal.transition('stopping')
        for record in records:
            try:
                result = self.executor.resource('cleanup', data['operation_id'], record['kind'])
                if result.returncode != 0:
                    raise RuntimeError('Mock cleanup failed')
            except ResourceOwnershipError:
                journal.transition('recovery_required')
                return 'recovery_required'
            except Exception:
                journal.mark(record['kind'], 'cleanup_failed')
                journal.transition('cleanup_failed')
                return 'cleanup_failed'
            journal.mark(record['kind'], 'released')
        journal.transition('stopped')
        return 'stopped'

    def recover(self):
        with ProcessLock(self.directory / 'operation.lock', self.lock_timeout):
            operations, invalid = self.discover()
            results = []
            for journal in operations:
                try:
                    state = self._cleanup_locked(journal)
                except JournalError:
                    state = 'recovery_required'
                results.append({'operation_id': journal.data['operation_id'] if journal.valid else journal.path.stem,
                                'state': state})
            report = {'simulation': True, 'state': 'recovery_required' if invalid or any(r['state'] != 'stopped' for r in results) else 'stopped',
                      'invalid_operations': len(invalid), 'operations': results}
            atomic_json(self.directory / 'recovery-report.json', report)
            return report
