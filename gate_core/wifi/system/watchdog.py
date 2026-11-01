"""Independent persistent dry-run arm/rollback contract; no system runner."""
from ..apply.clock import SystemClock
from ..models import profile_id
from .storage import PrivateRecords, FoundationError

TICKET_FIELDS={'owner','mode','kind','operation_id','resource_id','interface','artifact_id',
               'snapshot_id','before_digest','started_at','deadline','boot_id','armed'}


def validate_ticket(ticket, operation):
    import re
    if not isinstance(ticket,dict) or set(ticket)!=TICKET_FIELDS or ticket['owner']!='pirate-dry-run-watchdog' or ticket['mode']!='dry-run' or ticket['kind']!='arm' or ticket['operation_id']!=operation or ticket['resource_id']!='ap-primary' or ticket['snapshot_id']!=operation or ticket['armed'] is not True:
        raise FoundationError('Watchdog arm ownership unknown')
    for key in ('operation_id','artifact_id','snapshot_id'):profile_id(ticket[key])
    if type(ticket['started_at']) is not int or type(ticket['deadline']) is not int or ticket['started_at']<0 or not 15<=ticket['deadline']-ticket['started_at']<=300 or not isinstance(ticket['boot_id'],str) or not ticket['boot_id'] or len(ticket['boot_id'])>80:
        raise FoundationError('Watchdog deadline or boot identity unknown')
    if not isinstance(ticket['interface'],str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',ticket['interface']) or not isinstance(ticket['before_digest'],str) or not re.fullmatch(r'[0-9a-f]{64}',ticket['before_digest']) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',ticket['boot_id']):
        raise FoundationError('Watchdog resource identity unknown')
    return ticket


class PersistentDryRunWatchdog:
    def __init__(self, root, *, clock=None, boot_id='synthetic-boot', ready=True, faults=None):
        from pathlib import Path
        self.records=PrivateRecords(Path(root)/'watchdog')
        self.clock=clock or SystemClock()
        self.boot_id=boot_id
        self.ready=ready
        self.faults=faults or {}

    def arm(self, operation):
        if self.ready is not True:
            raise FoundationError('Independent watchdog readiness unknown')
        result=self.faults.get('arm',[])
        if result:
            outcome=result.pop(0)
            if isinstance(outcome,BaseException):raise outcome
            if outcome is not True:raise FoundationError('Watchdog arm unverified')
        ticket={'owner':'pirate-dry-run-watchdog','mode':'dry-run','kind':'arm',
                'operation_id':operation['operation_id'],'resource_id':'ap-primary',
                'interface':operation['interface'],'artifact_id':operation['artifact_id'],
                'snapshot_id':operation['operation_id'],'before_digest':operation['before_digest'],
                'started_at':operation['started_at'],'deadline':operation['deadline'],
                'boot_id':self.boot_id,'armed':True}
        validate_ticket(ticket,operation['operation_id'])
        if not operation['started_at']<=self.clock.now()<operation['deadline']:
            raise FoundationError('Watchdog arm deadline invalid')
        self.records.write(operation['operation_id'],ticket,create=True)
        if self.read(operation['operation_id'])!=ticket:
            raise FoundationError('Watchdog arm persistence unverified')
        return {'operation_id':operation['operation_id'],'armed':True,'dry_run':True}

    def read(self, operation):
        return validate_ticket(self.records.read(profile_id(operation)),operation)

    def tick(self, transaction, *, reboot=False):
        # Persistent journal, not a browser, decides which armed operations remain pending.
        return transaction.recover(reboot=reboot)


def main():
    import argparse
    import json
    from pathlib import Path
    from .executor import DryRunRadioExecutor
    from .transaction import DryRunTransaction
    parser=argparse.ArgumentParser(description='PiRate dry-run-only independent watchdog')
    parser.add_argument('--state-dir',required=True)
    parser.add_argument('--reboot',action='store_true')
    args=parser.parse_args()
    try:
        root=Path(args.state_dir)
        clock=SystemClock()
        watchdog=PersistentDryRunWatchdog(root,clock=clock)
        transaction=DryRunTransaction(root,DryRunRadioExecutor(root,clock=clock),watchdog)
        report=watchdog.tick(transaction,reboot=args.reboot)
    except (ValueError,OSError,TimeoutError):
        report={'state':'recovery_required','diagnostics':['storage_or_lock_unknown'],'dry_run':True,'real_execution_available':False}
    print(json.dumps(report,sort_keys=True))
    return 1 if report.get('state')=='recovery_required' or any(x['state']=='recovery_required' for x in report.get('operations',[])) else 0


if __name__=='__main__':
    raise SystemExit(main())
