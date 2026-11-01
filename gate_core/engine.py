"""Serialized connection lifecycle simulation. No OS/network executor exists."""
from .executor import MockExecutor
from .journal import PersistentJournal, JournalError, private_directory
from .plans import ConnectionPlan
from .network_policy import NetworkPolicy
from .openvpn_config import ValidatedOpenVPN
from .process_lock import ProcessLock
from .recovery import RecoveryManager


class EngineError(RuntimeError):
    pass


class ConnectionEngine:
    def __init__(self, directory, executor, *, lock_timeout=0):
        if type(executor) is not MockExecutor:
            raise TypeError('Only MockExecutor permitted at this stage')
        self.directory = private_directory(directory)
        self.executor = executor
        self.lock_timeout = lock_timeout

    def start(self, plan, policy, configuration):
        if not isinstance(plan, ConnectionPlan) or not isinstance(policy, NetworkPolicy) or not isinstance(configuration, ValidatedOpenVPN):
            raise EngineError('Validated plan, policy and configuration required')
        policy.validate()
        configuration.validate()
        if plan.backend != 'openvpn' or (plan.server, plan.port) != (policy.endpoint, policy.port):
            raise EngineError('Plan and endpoint policy mismatch')
        if (configuration.endpoint, configuration.port, configuration.protocol) != (policy.endpoint, policy.port, policy.protocol):
            raise EngineError('Configuration and policy mismatch')
        if plan.dns_mode != policy.dns_mode:
            raise EngineError('Plan and DNS policy mismatch')
        with ProcessLock(self.directory / 'operation.lock', self.lock_timeout):
            unfinished, invalid = RecoveryManager(self.directory, self.executor).discover()
            if unfinished or invalid:
                raise EngineError('Unfinished operation; recovery or stop required')
            try:
                journal = PersistentJournal.create(self.directory)
            except JournalError:
                raise EngineError('Journal creation failed; inspect recovery status') from None
            try:
                journal.transition('preparing')
                for kind in ('namespace', 'link', 'nft_table'):
                    self._acquire(journal, kind)
                journal.transition('connecting')
                self._acquire(journal, 'process')
                # Explicit mock handshake acknowledgement, never inferred from interface existence.
                result = self.executor.run(['gate-simulation', 'handshake'])
                if result.returncode:
                    raise EngineError('Simulated handshake failed')
                journal.transition('connected')
            except JournalError:
                # Disk state may be ahead of memory after fsync failure. No more executor actions.
                raise EngineError('Journal write failed; recovery required') from None
            except Exception:
                journal.transition('failed')
                raise EngineError('Simulated connection failed; stop or recover required') from None
            return journal.data

    def _acquire(self, journal, kind):
        journal.intend(kind)  # Write-ahead intent before mock acquisition.
        result = self.executor.resource('create', journal.data['operation_id'], kind)
        if result.returncode:
            raise EngineError('Simulated resource acquisition failed')
        journal.mark(kind, 'acquired')

    def stop(self, identifier):
        with ProcessLock(self.directory / 'operation.lock', self.lock_timeout):
            journal = PersistentJournal.load(self.directory, identifier)
            return RecoveryManager(self.directory, self.executor)._cleanup_locked(journal)

    def status(self, identifier):
        return PersistentJournal.load(self.directory, identifier).data

    def tunnel_lost(self, identifier):
        """Simulated tunnel-loss event. Policy model in failed permits no traffic."""
        with ProcessLock(self.directory / 'operation.lock', self.lock_timeout):
            journal = PersistentJournal.load(self.directory, identifier)
            journal.transition('failed')
            return journal.data
