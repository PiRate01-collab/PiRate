"""Future transaction ordering, executed only against a durable synthetic fixture."""
import uuid
from ..models import profile_id
from .storage import PrivateRecords, FoundationError, digest
from .executor import DryRunRadioExecutor, RESOURCE
from .watchdog import PersistentDryRunWatchdog

TERMINAL={'confirmed','rolled_back'}
STATES={'preflight','snapshotting','arming','applying','verifying','awaiting_confirmation',
        'confirmed','rolling_back','rolled_back','recovery_required'}
TRANSITIONS={'preflight':{'snapshotting','rolled_back'},'snapshotting':{'arming','rolled_back'},
             'arming':{'applying','rolling_back'},'applying':{'verifying','rolling_back'},
             'verifying':{'awaiting_confirmation','rolling_back'},'awaiting_confirmation':{'confirmed','rolling_back'},
             'rolling_back':{'rolled_back'},'recovery_required':{'rolling_back','rolled_back'},'confirmed':set(),'rolled_back':set()}
for state in STATES-TERMINAL-{'recovery_required'}:TRANSITIONS[state].add('recovery_required')
FIELDS={'owner','mode','operation_id','resource_id','artifact_id','interface','state','before_digest',
        'started_at','deadline','boot_id','sequence','diagnostics'}
CODES={'transaction_failed','rollback_failed','restart_recovery','deadline_expired','clock_or_boot_changed'}


class DryRunTransaction:
    def __init__(self, root, executor, watchdog, *, clock=None, before_apply=None):
        if type(executor) is not DryRunRadioExecutor or type(watchdog) is not PersistentDryRunWatchdog:
            raise FoundationError('Dry-run backend and watchdog required')
        self.root_records=PrivateRecords(root)
        self.root=self.root_records.root
        self.records=PrivateRecords(self.root/'transactions')
        self.reports=PrivateRecords(self.root/'recovery')
        if executor.root.absolute()!=self.root.absolute() or watchdog.records.root!=self.root.absolute()/'watchdog':
            raise FoundationError('Dry-run storage binding mismatch')
        self.executor,self.watchdog=executor,watchdog
        self.before_apply=before_apply
        self.clock=clock or executor.clock
        if self.clock is not executor.clock or self.clock is not watchdog.clock or executor.boot_id!=watchdog.boot_id:
            raise FoundationError('Watchdog clock or boot binding mismatch')

    def _lock(self):
        return self.records.lock()

    def _now(self):
        value=self.clock.now()
        if type(value) is not int or value<0:raise FoundationError('Clock unknown')
        return value

    def _read(self, operation):
        data=self.records.read(profile_id(operation))
        try:
            if not isinstance(data,dict) or set(data)!=FIELDS or data['owner']!='pirate-dry-run-transaction' or data['mode']!='dry-run' or data['operation_id']!=operation or data['resource_id']!=RESOURCE or data['state'] not in STATES:
                raise ValueError()
            profile_id(data['artifact_id'])
            if type(data['sequence']) is not int or data['sequence']<1 or type(data['started_at']) is not int or type(data['deadline']) is not int or data['started_at']<0 or not 15<=data['deadline']-data['started_at']<=300:
                raise ValueError()
            if not isinstance(data['interface'],str) or not data['interface'] or not isinstance(data['boot_id'],str) or not data['boot_id'] or not isinstance(data['before_digest'],str) or len(data['before_digest'])!=64 or any(c not in '0123456789abcdef' for c in data['before_digest']):raise ValueError()
            if not isinstance(data['diagnostics'],list) or len(data['diagnostics'])>len(CODES) or any(type(x) is not str or x not in CODES for x in data['diagnostics']):raise ValueError()
        except (ValueError,TypeError):raise FoundationError('Transaction journal unknown') from None
        return data

    def _all(self):
        records=[self._read(x) for x in self.records.identifiers()]
        if len({x['sequence'] for x in records})!=len(records) or any(x['state'] not in TERMINAL and x['sequence']!=max(y['sequence'] for y in records) for x in records):
            raise FoundationError('Transaction ordering unknown')
        return records

    def _latest(self, operation):
        records=self._all()
        if not records or max(records,key=lambda x:x['sequence'])['operation_id']!=operation['operation_id']:
            raise FoundationError('Stale operation denied')

    def _move(self, operation, state, code=None):
        if state not in TRANSITIONS[operation['state']]:raise FoundationError('Invalid transaction transition')
        proposed={**operation,'state':state,'diagnostics':list(operation['diagnostics'])}
        if code and code not in proposed['diagnostics']:proposed['diagnostics'].append(code)
        self.records.write(operation['operation_id'],proposed)
        operation.update(proposed)

    def _public(self, operation):
        return {k:operation[k] for k in ('operation_id','state','deadline','diagnostics')} | {'dry_run':True,'real_execution_available':False}

    def status(self, operation):
        return self._public(self._read(operation))

    def _action(self, action, operation, **extra):
        result=self.executor.execute({'action':action,'operation_id':operation['operation_id'],'resource_id':RESOURCE,**extra})
        if result.get('verified') is not True or result.get('dry_run') is not True or result.get('real_execution_available') is not False:
            raise FoundationError('Dry-run result unknown')
        return result

    def start(self, artifact, *, timeout=60, operation_id=None):
        profile_id(artifact)
        operation_id=profile_id(operation_id) if operation_id is not None else str(uuid.uuid4())
        if type(timeout) is not int or not 15<=timeout<=300:raise FoundationError('Invalid confirmation timeout')
        with self._lock():
            previous=self._all()
            known={x['operation_id'] for x in previous}
            if any(x not in known for x in self.watchdog.records.identifiers()):
                raise FoundationError('Unowned watchdog arm blocks apply')
            existing=next((x for x in previous if x['operation_id']==operation_id),None)
            if existing:
                self._latest(existing)
                if existing['artifact_id']!=artifact or existing['deadline']-existing['started_at']!=timeout:raise FoundationError('Operation ID request mismatch')
                return self._public(existing)
            if any(x['state'] not in TERMINAL for x in previous):raise FoundationError('Unfinished transaction blocks apply')
            if self.watchdog.ready is not True:raise FoundationError('Independent watchdog readiness unknown')
            baseline=self.executor.inventory()
            if baseline['lease'] is not None:raise FoundationError('Resource reservation unknown')
            now=self._now()
            operation={'owner':'pirate-dry-run-transaction','mode':'dry-run','operation_id':operation_id,
                       'resource_id':RESOURCE,'artifact_id':artifact,'interface':baseline['interface'],
                       'state':'preflight','before_digest':digest(baseline),'started_at':now,'deadline':now+timeout,
                       'boot_id':self.watchdog.boot_id,'sequence':max((x['sequence'] for x in previous),default=0)+1,'diagnostics':[]}
            self.records.write(operation_id,operation,create=True)
            try:
                self._action('check',operation,artifact_id=artifact)
                self._move(operation,'snapshotting')
                result=self._action('snapshot',operation)
                if result['before_digest']!=operation['before_digest']:raise FoundationError('Snapshot baseline changed')
                self._move(operation,'arming')
                receipt=self.watchdog.arm(operation)
                if receipt.get('armed') is not True:raise FoundationError('Watchdog arm result unknown')
                self._permit(operation)
                if self.before_apply is not None:
                    self.before_apply(operation)
                self._move(operation,'applying')
                self._action('install',operation,artifact_id=artifact,snapshot_id=operation_id)
                self._action('restart',operation)
                self._move(operation,'verifying')
                self._action('verify',operation,artifact_id=artifact)
                self._move(operation,'awaiting_confirmation')
                if self._expired(operation):self._rollback(operation,'deadline_expired')
            except FoundationError:
                # Reload first: an atomic replacement may have succeeded before fsync failed.
                operation=self._read(operation_id)
                self._rollback(operation,'transaction_failed')
            return self._public(operation)

    def _permit(self, operation):
        ticket=self.watchdog.read(operation['operation_id'])
        for field in ('artifact_id','interface','before_digest','started_at','deadline','boot_id'):
            if ticket[field]!=operation[field]:raise FoundationError('Watchdog ticket binding unknown')
        if self._expired(operation):raise FoundationError('Watchdog permit expired')

    def _expired(self, operation):
        now=self._now()
        return not operation['started_at']<=now<operation['deadline'] or operation['boot_id']!=self.watchdog.boot_id

    def confirm(self, identifier):
        with self._lock():
            operation=self._read(identifier);self._latest(operation)
            if operation['state']=='confirmed':return self._public(operation)
            if operation['state']!='awaiting_confirmation':raise FoundationError('Confirmation state denied')
            try:
                self._permit(operation)
                self._action('verify',operation,artifact_id=operation['artifact_id'])
                self._permit(operation)  # Recheck deadline after verification.
                self.executor.release(identifier,operation['artifact_id'])
                self._permit(operation)
                self._move(operation,'confirmed')
            except FoundationError:
                operation=self._read(identifier)
                if operation['state']!='confirmed':self._rollback(operation,'transaction_failed')
                else:raise  # Ambiguous persistence must not be returned as fresh success.
            return self._public(operation)

    def _rollback(self, operation, code):
        if operation['state']=='rolled_back':return
        if operation['state']=='confirmed':raise FoundationError('Committed transaction cannot be rolled back')
        try:
            if not self.executor.records.exists(operation['operation_id']):
                if digest(self.executor.inventory())!=operation['before_digest'] or operation['state'] not in ('preflight','snapshotting','recovery_required'):
                    raise FoundationError('Rollback snapshot or ownership unknown')
                self._move(operation,'rolled_back',code)
                return
            snapshot=self.executor.snapshot(operation['operation_id'])
            if snapshot['before_digest']!=operation['before_digest'] or snapshot['before']['interface']!=operation['interface']:
                raise FoundationError('Rollback snapshot not bound')
            if operation['state'] in ('preflight','snapshotting'):
                self._move(operation,'recovery_required',code)
            if operation['state']!='rolling_back':self._move(operation,'rolling_back',code)
            self._action('restore',operation,snapshot_id=operation['operation_id'])
            self._action('verify',operation,artifact_id=snapshot['before']['artifact_id'])
            self._move(operation,'rolled_back')
        except FoundationError:
            operation.update(self._read(operation['operation_id']))
            if operation['state'] not in TERMINAL and operation['state']!='recovery_required':
                self._move(operation,'recovery_required','rollback_failed')
            elif operation['state'] in TERMINAL:
                raise  # Do not report success after an ambiguous terminal write.

    def rollback(self, identifier):
        with self._lock():
            operation=self._read(identifier);self._latest(operation)
            self._rollback(operation,'restart_recovery')
            return self._public(operation)

    def recover(self, *, reboot=False):
        with self._lock():
            try:
                operations=self._all()
                # Arms without journals cannot be interpreted as permission to change resources.
                known={x['operation_id'] for x in operations}
                if any(x not in known for x in self.watchdog.records.identifiers()):raise FoundationError('Orphan watchdog ticket')
                inventory=self.executor.inventory()
                if inventory['lease'] is not None and inventory['lease'] not in known or inventory['holder'] is not None and inventory['holder'] not in known:
                    raise FoundationError('Orphan resource ownership')
                results=[]
                for operation in operations:
                    if operation['state'] in TERMINAL:continue
                    if operation['state']!='awaiting_confirmation' or reboot or self._expired(operation):
                        self._rollback(operation,'clock_or_boot_changed' if reboot or operation['boot_id']!=self.watchdog.boot_id else 'deadline_expired' if self._expired(operation) else 'restart_recovery')
                    else:
                        try:self._permit(operation)
                        except FoundationError:self._rollback(operation,'transaction_failed')
                    results.append(self._public(operation))
                report={'operations':results,'dry_run':True,'real_execution_available':False}
            except FoundationError:
                report={'state':'recovery_required','diagnostics':['journal_or_resource_unknown'],'dry_run':True,'real_execution_available':False}
            self.reports.write(str(uuid.uuid5(uuid.NAMESPACE_URL,'pirate-dry-run-recovery-report')),report)
            return report
