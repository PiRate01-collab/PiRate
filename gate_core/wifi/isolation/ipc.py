"""Inherited AF_UNIX capability channel. Synthetic only, never a system executor.

A trusted launcher passes one endpoint to broker and one to watchdog, neither to Web.
Current harness uses same UID. Separate-user deployment/FD passing remains pending.
"""
import socket
import threading
import time
import uuid
from ..broker.transport import encode_frame,receive_request,peer_identity
from ..models import profile_id
from ..system.storage import FoundationError,PrivateRecords
from ..system.transaction import DryRunTransaction
from .watchdog import MockWatchdogReadiness

BINDING=('operation_id','artifact_id','resource_id','boot_id','deadline')


def check_channel(channel,uid,gid):
    if channel.family!=socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM:
        raise FoundationError('Watchdog channel denied')
    peer=peer_identity(channel)
    if any(type(x) is not int or x<0 for x in (uid,gid)) or (peer.uid,peer.gid)!=(uid,gid):
        raise FoundationError('Watchdog peer denied')


class WatchdogIPCClient:
    def __init__(self,channel,clock,*,uid,gid,timeout=.5):
        if type(timeout) not in (float,int) or not .05<=timeout<=2:raise FoundationError('Watchdog timeout denied')
        check_channel(channel,uid,gid)
        self.channel,self.clock,self.timeout=channel,clock,timeout
        self.generation=None
        self.lock=threading.Lock()

    def _exchange(self,request):
        with self.lock:
            try:
                request={**request,'nonce':str(uuid.uuid4())}
                self.channel.settimeout(self.timeout)
                self.channel.sendall(encode_frame(request))
                reply=receive_request(self.channel,time.monotonic()+self.timeout)
                fields={'ready','generation','dry_run','nonce'}|({'binding'} if request['action']=='check' else set())
                if not isinstance(reply,dict) or set(reply)!=fields or reply['ready'] is not True or reply['dry_run'] is not True:
                    raise FoundationError('Watchdog readiness denied')
                profile_id(reply['generation'])
                if reply['nonce']!=request['nonce']:raise FoundationError('Watchdog reply replay denied')
                if request['action']=='check':
                    binding=reply['binding']
                    if not isinstance(binding,dict) or set(binding)!=set(BINDING) or any(type(binding[key]) is not type(request[key]) or binding[key]!=request[key] for key in BINDING):
                        raise FoundationError('Watchdog reply binding denied')
                return reply
            except Exception:
                self.channel.close()
                raise FoundationError('Watchdog IPC unavailable') from None

    def available(self):
        reply=self._exchange({'version':1,'action':'available'})
        self.generation=reply['generation']

    def check(self,operation):
        if self.generation is None:raise FoundationError('Watchdog generation missing')
        reply=self._exchange({'version':1,'action':'check','generation':self.generation,
                              **{key:operation[key] for key in BINDING}})
        if reply['generation']!=self.generation:raise FoundationError('Watchdog generation changed')
        if not operation['started_at']<=self.clock.now()<operation['deadline']:
            raise FoundationError('Watchdog deadline expired')

    def close(self):self.channel.close()


class MockWatchdogIPCService:
    def __init__(self,channel,transaction,*,uid,gid):
        if type(transaction) is not DryRunTransaction:raise FoundationError('Dry-run transaction required')
        check_channel(channel,uid,gid)
        self.channel,self.transaction=channel,transaction
        self.grant_subject=(uid,gid)  # Same-UID mock harness; future role ACL pending.
        self.proofs=MockWatchdogReadiness(transaction.root/'ipc-readiness',transaction.clock)
        self.blocked=False

    def recover(self,*,reboot=False):
        try:
            # Unknown authorization ownership never permits automatic cleanup.
            grants=PrivateRecords(self.transaction.root/'broker-grants')
            from ..broker.core import validate_grant
            for identifier in grants.identifiers():
                grant=validate_grant(grants.read(identifier),identifier)
                if (grant['uid'],grant['gid'])!=self.grant_subject:
                    raise FoundationError('Recovery grant ownership unknown')
                if grant['phase'] not in ('issued','dispatched'):raise FoundationError('Recovery grant state unknown')
                if self.transaction.records.exists(identifier):
                    operation=self.transaction._read(identifier)
                    if grant['phase']!='dispatched' or grant['artifact_id']!=operation['artifact_id'] or grant['baseline_digest']!=operation['before_digest']:
                        raise FoundationError('Recovery grant binding unknown')
                elif grant['phase']=='dispatched':raise FoundationError('Recovery intent without journal')
            if any(not grants.exists(op['operation_id']) for op in self.transaction._all()):
                raise FoundationError('Recovery journal without grant')
            report=self.transaction.recover(reboot=reboot)
            self.blocked=report.get('state')=='recovery_required' or any(x['state']=='recovery_required' for x in report.get('operations',[]))
            return report
        except TimeoutError:
            return None  # Broker transaction currently locked; retry, never claim ready.
        except (ValueError,OSError):
            self.blocked=True
            report={'state':'recovery_required','diagnostics':['journal_or_resource_unknown'],'dry_run':True,'real_execution_available':False}
            self.transaction.reports.write(str(uuid.uuid5(uuid.NAMESPACE_URL,'pirate-dry-run-recovery-report')),report)
            return report

    def start(self,*,reboot=False):
        report=self.recover(reboot=reboot)
        if report is None:raise FoundationError('Watchdog startup recovery busy')
        self.proofs.restart(lifetime=300)
        return report

    def dispatch(self,request):
        if self.blocked or not isinstance(request,dict) or type(request.get('version')) is not int or request['version']!=1:
            raise FoundationError('Watchdog request denied')
        session=self.proofs._session()
        try:profile_id(request.get('nonce'))
        except ValueError:raise FoundationError('Watchdog request denied') from None
        if request.get('action')=='available' and set(request)=={'version','action','nonce'}:
            pass
        elif request.get('action')=='check' and set(request)=={'version','action','generation','nonce',*BINDING}:
            if request['generation']!=session['generation']:raise FoundationError('Watchdog generation stale')
            operation=self.transaction._read(profile_id(request['operation_id']))
            if operation['state'] not in ('arming','awaiting_confirmation') or any(type(request[key]) is not type(operation[key]) or request[key]!=operation[key] for key in BINDING):
                raise FoundationError('Watchdog operation denied')
            snapshot=self.transaction.executor.snapshot(operation['operation_id'])
            if snapshot['before_digest']!=operation['before_digest']:raise FoundationError('Watchdog snapshot denied')
            self.transaction._permit(operation)
            inventory=self.transaction.executor.inventory()
            if inventory['lease'] not in (None,operation['operation_id']):raise FoundationError('Watchdog ownership unknown')
            if operation['state']=='arming':
                self.proofs.acknowledge(operation,snapshot_valid=True,rollback_ready=True,journal_valid=True)
            self.proofs.check(operation)
        else:raise FoundationError('Watchdog request denied')
        reply={'ready':True,'generation':session['generation'],'dry_run':True,'nonce':request['nonce']}
        if request['action']=='check':reply['binding']={key:request[key] for key in BINDING}
        return reply

    def serve(self,stop):
        """Independent periodic recovery; IPC loss does not stop deadline processing."""
        channel_open=True
        try:
            while not stop.is_set():
                # Avoid taking the transaction lock for healthy pending operations.
                # In-progress phases still attempt recovery: flock denies concurrent
                # work while broker is alive and releases automatically after a crash.
                try:
                    operations=self.transaction._all()
                    if any(op['state'] not in ('confirmed','rolled_back') and (op['state']!='awaiting_confirmation' or self.transaction._expired(op)) for op in operations):
                        self.recover()
                except (ValueError,OSError):self.recover()
                if not channel_open:
                    stop.wait(.02);continue
                # Poll readability before bounded whole-frame receive; never discard partial frames.
                import select
                if not select.select([self.channel],[],[],.02)[0]:continue
                try:
                    request=receive_request(self.channel,time.monotonic()+.5)
                    reply=self.dispatch(request)
                    self.channel.settimeout(.5);self.channel.sendall(encode_frame(reply))
                except Exception:
                    self.channel.close();channel_open=False
        finally:self.channel.close()
