"""Authorized high-level transactions. Raw executor/file actions are never RPCs."""
import re
from ..models import profile_id
from ..system.executor import DryRunRadioExecutor,RESOURCE
from ..system.transaction import DryRunTransaction
from ..system.watchdog import PersistentDryRunWatchdog
from ..system.storage import PrivateRecords,FoundationError,digest
from .contracts import BrokerError,PeerPolicy,request_schema
from .secrets import SyntheticSecretResolver,SecretContext,SecretPurpose,validate_context
from .readiness import MockReadinessProvider

GRANT_FIELDS={'owner','mode','operation_id','uid','gid','resource_id','profile_id','artifact_id',
              'artifact_digest','baseline_digest','secret_ref','issued_at','expires_at','timeout',
              'actions','phase'}


def validate_grant(grant,identifier):
    try:
        if not isinstance(grant,dict) or set(grant)!=GRANT_FIELDS or grant['owner']!='pirate-secure-broker' or grant['mode']!='dry-run' or grant['operation_id']!=identifier or grant['resource_id']!=RESOURCE or grant['phase'] not in ('issued','dispatched'):
            raise ValueError()
        for key in ('profile_id','artifact_id'):profile_id(grant[key])
        if any(type(grant[x]) is not int or grant[x]<0 for x in ('uid','gid','issued_at','expires_at','timeout')) or not 15<=grant['timeout']<=300 or not 15<=grant['expires_at']-grant['issued_at']<=3600:
            raise ValueError()
        if not isinstance(grant['actions'],list) or any(type(x) is not str or x not in ('apply','confirm','rollback','status') for x in grant['actions']) or len(set(grant['actions']))!=len(grant['actions']):raise ValueError()
        for field in ('artifact_digest','baseline_digest'):
            if not isinstance(grant[field],str) or not re.fullmatch('[0-9a-f]{64}',grant[field]):raise ValueError()
        validate_context(grant['secret_ref'],SecretContext(grant['uid'],grant['profile_id'],RESOURCE,SecretPurpose.WIFI_PSK))
    except (ValueError,TypeError):raise BrokerError('recovery_required') from None
    return grant


class BrokerCore:
    def __init__(self,transaction,policy,readiness,secrets,*,watchdog_readiness=None):
        from ..isolation.watchdog import MockWatchdogReadiness
        from ..isolation.ipc import WatchdogIPCClient
        if watchdog_readiness is not None and (type(watchdog_readiness) not in (MockWatchdogReadiness,WatchdogIPCClient) or watchdog_readiness.clock is not transaction.clock):
            raise BrokerError('readiness_unknown')
        if type(transaction) is not DryRunTransaction or type(transaction.executor) is not DryRunRadioExecutor or type(transaction.watchdog) is not PersistentDryRunWatchdog or type(policy) is not PeerPolicy or type(readiness) is not MockReadinessProvider or type(secrets) is not SyntheticSecretResolver:
            raise BrokerError('dry_run_only')
        self.transaction=transaction
        self.watchdog_readiness=watchdog_readiness
        self.policy,self.readiness,self.secrets=policy,readiness,secrets
        self.grants=PrivateRecords(transaction.root/'broker-grants')
        # The check runs after a verified actual dry snapshot and arm, before install.
        if transaction.before_apply is not None:raise BrokerError('dry_run_only')
        transaction.before_apply=self._before_apply

    def provision(self,operation_id,uid,gid,artifact_id,secret_ref,*,timeout=60,lifetime=300,actions=None):
        """Trusted local operator interface, never a socket request or Web endpoint."""
        profile_id(operation_id);profile_id(artifact_id)
        if any(type(x) is not int or x<0 for x in (uid,gid)) or type(timeout) is not int or not 15<=timeout<=300 or type(lifetime) is not int or not 15<=lifetime<=3600:
            raise BrokerError('invalid_grant')
        actions=frozenset(('apply','confirm','rollback','status')) if actions is None else actions
        if not isinstance(actions,frozenset) or not actions<=frozenset(('apply','confirm','rollback','status')):
            raise BrokerError('invalid_grant')
        configuration=self.transaction.executor._configuration(artifact_id)
        context=SecretContext(uid,configuration['profile_id'],RESOURCE,SecretPurpose.WIFI_PSK)
        validate_context(secret_ref,context)
        baseline=self.transaction.executor.inventory()
        if baseline['lease'] is not None or configuration['interface']!=baseline['interface']:
            raise BrokerError('resource_denied')
        now=self.transaction._now()
        grant={'owner':'pirate-secure-broker','mode':'dry-run','operation_id':operation_id,
               'uid':uid,'gid':gid,'resource_id':RESOURCE,'profile_id':configuration['profile_id'],
               'artifact_id':artifact_id,'artifact_digest':configuration['sha256'],
               'baseline_digest':digest(baseline),'secret_ref':secret_ref,'issued_at':now,'expires_at':now+lifetime,
               'timeout':timeout,'actions':sorted(actions),'phase':'issued'}
        with self.grants.lock():
            if self.transaction.records.exists(operation_id) or self.transaction.watchdog.records.exists(operation_id) or self.transaction.executor.records.exists(operation_id):
                raise BrokerError('invalid_grant')
            self.grants.write(operation_id,grant,create=True)

    def _grant(self,identifier):
        return validate_grant(self.grants.read(identifier),identifier)

    def _context(self,grant):return SecretContext(grant['uid'],grant['profile_id'],RESOURCE,SecretPurpose.WIFI_PSK)

    def _readiness(self,grant):
        self.readiness.check(grant['profile_id'],RESOURCE)
        if self.transaction.watchdog.ready is not True or not self.secrets.available(grant['secret_ref'],self._context(grant)):
            raise BrokerError('readiness_unknown')
        configuration=self.transaction.executor._configuration(grant['artifact_id'])
        inventory=self.transaction.executor.inventory()
        if configuration['profile_id']!=grant['profile_id'] or configuration['sha256']!=grant['artifact_digest'] or configuration['interface']!=inventory['interface']:
            raise BrokerError('resource_denied')

    def _before_apply(self,operation):
        # BrokerError is converted to FoundationError so transaction rolls back.
        try:
            grant=self._grant(operation['operation_id'])
            if grant['phase']!='dispatched' or grant['artifact_id']!=operation['artifact_id'] or grant['baseline_digest']!=operation['before_digest']:
                raise BrokerError('transaction_denied')
            self._readiness(grant)
            snapshot=self.transaction.executor.snapshot(operation['operation_id'])
            if snapshot['before_digest']!=grant['baseline_digest']:
                raise BrokerError('resource_denied')
            if self.watchdog_readiness is not None:self.watchdog_readiness.check(operation)
        except (BrokerError,FoundationError):raise FoundationError('Broker readiness denied') from None

    def _bound_operation(self,grant):
        operation=self.transaction._read(grant['operation_id'])
        if operation['artifact_id']!=grant['artifact_id'] or operation['before_digest']!=grant['baseline_digest']:
            raise BrokerError('transaction_denied')
        self.transaction._latest(operation)
        inventory=self.transaction.executor.inventory()
        if operation['state']=='awaiting_confirmation' and (inventory['holder']!=operation['operation_id'] or inventory['lease'] not in (None,operation['operation_id'])):
            raise BrokerError('resource_denied')
        return operation

    def dispatch(self,peer,request):
        self.policy.authenticate(peer)
        data=request_schema(request)
        self.policy.authorize(peer,data['action'])
        with self.grants.lock():
            grant=self._grant(data['operation_id'])
            if (peer.uid,peer.gid)!=(grant['uid'],grant['gid']) or data['action'] not in grant['actions']:
                raise BrokerError('transaction_denied')
            now=self.transaction._now()
            # Expired grants cannot authorize new apply/confirm. Rollback/status remain
            # available to the owner: deadline must never block emergency cleanup.
            if data['action'] in ('apply','confirm') and not grant['issued_at']<=now<grant['expires_at']:
                raise BrokerError('authorization_expired')
            if data['action']=='apply':
                if grant['phase']=='issued':
                    if self.watchdog_readiness is not None:self.watchdog_readiness.available()
                    self._readiness(grant)
                    if digest(self.transaction.executor.inventory())!=grant['baseline_digest']:
                        raise BrokerError('resource_denied')
                    proposed={**grant,'phase':'dispatched'}
                    self.grants.write(grant['operation_id'],proposed)
                    # Grant consumption is durable before any transaction side effect.
                    result=self.transaction.start(grant['artifact_id'],timeout=grant['timeout'],operation_id=grant['operation_id'])
                else:
                    # A crash before journal creation is uncertain, never execute twice.
                    operation=self._bound_operation(grant)
                    result=self.transaction._public(operation)
            elif data['action']=='status' and grant['phase']=='issued':
                result={'operation_id':grant['operation_id'],'state':'authorized','dry_run':True,'real_execution_available':False}
            else:
                operation=self._bound_operation(grant)
                if data['action']=='confirm':
                    if operation['state'] not in ('awaiting_confirmation','confirmed'):raise BrokerError('state_denied')
                    if self.watchdog_readiness is not None and operation['state']=='confirmed':raise BrokerError('state_denied')
                    if self.watchdog_readiness is not None:self.watchdog_readiness.check(operation)
                    configuration=self.transaction.executor._configuration(grant['artifact_id'])
                    if configuration['profile_id']!=grant['profile_id'] or configuration['sha256']!=grant['artifact_digest']:
                        raise BrokerError('resource_denied')
                    result=self.transaction.confirm(grant['operation_id'])
                elif data['action']=='rollback':
                    if operation['state']=='confirmed':raise BrokerError('state_denied')
                    result=self.transaction.rollback(grant['operation_id'])
                else:result=self.transaction._public(operation)
            success=result['state']!='recovery_required' and (data['action'] not in ('apply','confirm') or result['state'] in ('awaiting_confirmation','confirmed'))
            response={'ok':success,'result':result,'dry_run':True,'real_execution_available':False}
            if not success:response['error']='recovery_required' if result['state']=='recovery_required' else 'transaction_not_applied'
            return response

    def recover_after_restart(self):
        """Independent trusted startup recovery. Never callable by a client."""
        with self.grants.lock():
            grants=[self._grant(x) for x in self.grants.identifiers()]
            report=self.transaction.recover()
            missing=[g for g in grants if g['phase']=='dispatched' and not self.transaction.records.exists(g['operation_id'])]
            if missing or report.get('state')=='recovery_required':raise BrokerError('recovery_required')
            return report
