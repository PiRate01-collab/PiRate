"""Synthetic independent-service leases, bound to operation and service generation."""
import uuid
from ..models import profile_id
from ..system.storage import PrivateRecords, FoundationError

SESSION='00000000-0000-4000-8000-000000000002'

class MockWatchdogReadiness:
    def __init__(self, root, clock):
        self.records=PrivateRecords(root)
        self.clock=clock

    def _session(self):
        data=self.records.read(SESSION)
        if not isinstance(data,dict) or set(data)!={'owner','generation','expires_at'} or data['owner']!='pirate-watchdog-mock' or type(data['expires_at']) is not int:
            raise FoundationError('Watchdog readiness unknown')
        profile_id(data['generation'])
        if not 0<=self.clock.now()<data['expires_at']:
            raise FoundationError('Watchdog readiness expired')
        return data

    def restart(self, *, lifetime=60):
        if type(lifetime) is not int or not 1<=lifetime<=300:raise FoundationError('Invalid readiness lifetime')
        with self.records.lock():
            self.records.write(SESSION,{'owner':'pirate-watchdog-mock','generation':str(uuid.uuid4()),'expires_at':self.clock.now()+lifetime})

    def available(self):
        self._session()

    def acknowledge(self, operation, *, snapshot_valid, rollback_ready, journal_valid):
        """Trusted mock watchdog interface, never a client RPC. No real hardware proof."""
        identifier=profile_id(operation['operation_id'])
        if identifier==SESSION:raise FoundationError('Reserved readiness identifier')
        if any(x is not True for x in (snapshot_valid,rollback_ready,journal_valid)):
            raise FoundationError('Watchdog recovery readiness unknown')
        with self.records.lock():
            session=self._session()
            if not operation['started_at']<=self.clock.now()<operation['deadline']:
                raise FoundationError('Watchdog operation deadline expired')
            proof={'owner':'pirate-watchdog-mock','generation':session['generation'],
                   'operation_id':identifier,'artifact_id':operation['artifact_id'],
                   'resource_id':operation['resource_id'],'boot_id':operation['boot_id'],
                   'deadline':operation['deadline'],'expires_at':min(operation['deadline'],session['expires_at']),
                   'snapshot_valid':True,'rollback_ready':True,'journal_valid':True}
            if self.records.exists(identifier):
                if self.records.read(identifier)!=proof:raise FoundationError('Readiness replay denied')
            else:self.records.write(identifier,proof,create=True)

    def check(self, operation):
        with self.records.lock():
            session=self._session()
            proof=self.records.read(profile_id(operation['operation_id']))
            if not isinstance(proof,dict) or any(proof.get(key) is not True for key in ('snapshot_valid','rollback_ready','journal_valid')) or any(type(proof.get(key)) is not int for key in ('deadline','expires_at')):
                raise FoundationError('Independent watchdog proof invalid')
            expected={'owner':'pirate-watchdog-mock','generation':session['generation'],
                      **{key:operation[key] for key in ('operation_id','artifact_id','resource_id','boot_id','deadline')},
                      'expires_at':min(operation['deadline'],session['expires_at']),
                      'snapshot_valid':True,'rollback_ready':True,'journal_valid':True}
            if proof!=expected or not operation['started_at']<=self.clock.now()<proof['expires_at']:
                raise FoundationError('Independent watchdog proof invalid')
