"""Bounded privileged-executor contract with ONLY a dry-run implementation.

No command runner, subprocess, shell, system path or runtime backend selector.
"""
from dataclasses import dataclass
import copy
import os
import re
import uuid
from typing import Protocol
from ..models import profile_id
from .storage import PrivateRecords, FoundationError, digest
from .renderer import PreparedConfiguration, configuration_hash
from ..apply.clock import SystemClock

OWNER = 'pirate-radio-dry-run'
RESOURCE = 'ap-primary'
ACTIONS = {
    'check': {'artifact_id'}, 'snapshot': set(), 'install': {'artifact_id','snapshot_id'},
    'restart': set(), 'verify': {'artifact_id'}, 'restore': {'snapshot_id'},
}
INVENTORY_ID = str(uuid.uuid5(uuid.NAMESPACE_URL,'pirate-radio-dry-run-inventory'))


@dataclass(frozen=True)
class RadioRequest:
    action: str
    operation_id: str
    resource_id: str
    artifact_id: str | None = None
    snapshot_id: str | None = None

    @classmethod
    def parse(cls, data):
        if not isinstance(data,dict) or type(data.get('action')) is not str or data['action'] not in ACTIONS:
            raise FoundationError('Unsupported executor request')
        action=data['action']
        if set(data) != {'action','operation_id','resource_id'} | ACTIONS[action] or data['resource_id'] != RESOURCE:
            raise FoundationError('Executor request schema or resource denied')
        try:
            for field in ('operation_id',*ACTIONS[action]):profile_id(data[field])
        except ValueError:
            raise FoundationError('Invalid executor record identifier') from None
        return cls(**data)


class RestrictedRadioExecutor(Protocol):
    """Future broker: authorization and attested ownership precede every action.

    No argv, shell, destination path or service name is accepted from clients.
    Implementations must prove file/interface ownership via pinned FDs and live
    identity, resolve fixed resource mappings, and return non-secret diagnostics.
    """
    def execute(self, request: dict) -> dict: ...


class DryRunRadioExecutor:
    def __init__(self, root, *, faults=None, clock=None, boot_id="synthetic-boot"):
        self.root_records=PrivateRecords(root)
        self.root=self.root_records.root
        self.records=PrivateRecords(self.root/'backend')
        self.faults=faults or {}
        self.calls=[]
        self.clock=clock or SystemClock()
        self.boot_id=boot_id

    def _lock(self):
        return self.records.lock()

    def _read(self, identifier, kind):
        data=self.records.read(identifier)
        if not isinstance(data,dict) or data.get('owner')!=OWNER or data.get('mode')!='dry-run' or data.get('kind')!=kind:
            raise FoundationError('Resource ownership unknown')
        return data

    def _configuration(self, identifier):
        return self._configuration_data(self._read(identifier,'configuration'))

    def _configuration_data(self, data):
        if not isinstance(data,dict) or data.get('owner')!=OWNER or data.get('mode')!='dry-run' or data.get('kind')!='configuration':
            raise FoundationError('Configuration ownership unknown')
        if set(data)!={'owner','mode','kind','interface','profile_id','text','sha256'}:
            raise FoundationError('Configuration record schema unknown')
        profile_id(data['profile_id'])
        validate_text(data['text'],data['interface'])
        if data['sha256']!=configuration_hash(data['text']):
            raise FoundationError('Prepared configuration integrity unknown')
        return data

    def prepare(self, configuration):
        if type(configuration) is not PreparedConfiguration or configuration.mode!='dry-run':
            raise FoundationError('Only prepared dry-run configurations accepted')
        validate_text(configuration.text,configuration.interface)
        profile_id(configuration.profile_id)
        if configuration.sha256!=configuration_hash(configuration.text):
            raise FoundationError('Prepared configuration integrity unknown')
        identifier=str(uuid.uuid4())
        with self._lock():
            self.records.write(identifier,{'owner':OWNER,'mode':'dry-run','kind':'configuration',
                'interface':configuration.interface,'profile_id':configuration.profile_id,
                'text':configuration.text,'sha256':configuration.sha256},create=True)
        return identifier

    def seed(self, artifact_id):
        """Explicit fixture creation. Never called by recovery or a Web endpoint."""
        with self._lock():
            configuration=self._configuration(profile_id(artifact_id))
            self.records.write(INVENTORY_ID,{'owner':OWNER,'mode':'dry-run','kind':'inventory',
                'resource_id':RESOURCE,'interface':configuration['interface'],'service':'hostapd.service',
                'uid':os.geteuid(),'artifact_id':artifact_id,'active_digest':configuration['sha256'],
                'holder':None,'lease':None},create=True)

    def inventory(self):
        return self._inventory(self._read(INVENTORY_ID,'inventory'))

    def _inventory(self, data, configuration=None):
        if not isinstance(data,dict) or data.get('owner')!=OWNER or data.get('mode')!='dry-run' or data.get('kind')!='inventory':
            raise FoundationError('Resource ownership unknown')
        if set(data)!={'owner','mode','kind','resource_id','interface','service','uid','artifact_id','active_digest','holder','lease'} or data['resource_id']!=RESOURCE or data['service']!='hostapd.service' or type(data['uid']) is not int or data['uid']!=os.geteuid():
            raise FoundationError('Resource mapping or owner unknown')
        profile_id(data['artifact_id'])
        configuration=self._configuration(data['artifact_id']) if configuration is None else self._configuration_data(configuration)
        if configuration['interface']!=data['interface']:
            raise FoundationError('Interface identity unknown')
        for key in ('holder','lease'):
            if data[key] is not None:profile_id(data[key])
        if not isinstance(data['active_digest'],str) or not re.fullmatch('[0-9a-f]{64}',data['active_digest']):
            raise FoundationError('Service result unknown')
        return copy.deepcopy(data)

    def snapshot(self, operation):
        snapshot=self._read(profile_id(operation),'snapshot')
        if set(snapshot)!={'owner','mode','kind','operation_id','before','configuration','before_digest'} or snapshot['operation_id']!=operation or snapshot['before_digest']!=digest(snapshot['before']):
            raise FoundationError('Snapshot integrity or ownership unknown')
        before=snapshot['before']
        configuration=self._configuration_data(snapshot['configuration'])
        baseline=self._inventory(before,configuration)
        if configuration['sha256']!=baseline['active_digest'] or baseline['lease'] is not None:
            raise FoundationError('Incomplete baseline snapshot')
        return snapshot

    def _fault(self, action):
        values=self.faults.get(action,[])
        result=values.pop(0) if values else True
        if isinstance(result,BaseException):raise result
        return result

    def execute(self, request):
        try:
            return self._execute(request)
        except FoundationError:
            raise
        except Exception:
            raise FoundationError('Dry-run action unverified; recovery required') from None

    def _execute(self, request):
        req=RadioRequest.parse(request)
        with self._lock():
            if req.action=='restore':
                rollback_snapshot=self.snapshot(req.snapshot_id)
                raw=self._read(INVENTORY_ID,'inventory')
                inventory=self._inventory(raw,rollback_snapshot['configuration']) if raw.get('artifact_id')==rollback_snapshot['before']['artifact_id'] else self.inventory()
            else:
                inventory=self.inventory()
            self.calls.append((req.action,req.operation_id))
            outcome=self._fault(req.action)
            if outcome is False:raise FoundationError('Dry-run executor result unverified')
            extra={}
            if req.action=='check':
                config=self._configuration(req.artifact_id)
                if config['interface']!=inventory['interface'] or inventory['active_digest']!=self._configuration(inventory['artifact_id'])['sha256']:
                    raise FoundationError('Preflight resource state unknown')
                extra={'configuration_digest':config['sha256']}
            elif req.action=='snapshot':
                if inventory['lease'] not in (None,req.operation_id):
                    raise FoundationError('Resource reserved by another operation')
                if self.records.exists(req.operation_id):
                    snapshot=self.snapshot(req.operation_id)
                else:
                    if inventory['lease'] is not None:
                        raise FoundationError('Incomplete reservation snapshot')
                    config=self._configuration(inventory['artifact_id'])
                    if inventory['active_digest']!=config['sha256']:
                        raise FoundationError('Baseline result unknown')
                    snapshot={'owner':OWNER,'mode':'dry-run','kind':'snapshot','operation_id':req.operation_id,
                              'before':inventory,'configuration':config,'before_digest':digest(inventory)}
                    self.records.write(req.operation_id,snapshot,create=True)
                if inventory['lease'] is None and digest(inventory)!=snapshot['before_digest']:
                    raise FoundationError('Snapshot belongs to a stale baseline')
                inventory['lease']=req.operation_id
                self.records.write(INVENTORY_ID,inventory)
                extra={'snapshot_id':req.operation_id,'before_digest':snapshot['before_digest']}
            elif req.action=='install':
                snapshot=self.snapshot(req.snapshot_id)
                config=self._configuration(req.artifact_id)
                if req.snapshot_id!=req.operation_id or inventory['lease']!=req.operation_id or config['interface']!=inventory['interface']:
                    raise FoundationError('Install ownership or snapshot unknown')
                expected={**snapshot['before'],'lease':req.operation_id}
                if digest(inventory)!=digest(expected) and not (inventory['holder']==req.operation_id and inventory['artifact_id']==req.artifact_id):
                    raise FoundationError('Resource changed outside transaction')
                self._armed(req.operation_id,req.artifact_id,snapshot)
                inventory.update(artifact_id=req.artifact_id,holder=req.operation_id)
                self.records.write(INVENTORY_ID,inventory)
            elif req.action=='restart':
                if inventory['lease']!=req.operation_id or inventory['holder']!=req.operation_id:
                    raise FoundationError('Restart ownership unknown')
                self._armed(req.operation_id,inventory['artifact_id'],self.snapshot(req.operation_id))
                inventory['active_digest']=self._configuration(inventory['artifact_id'])['sha256']
                self.records.write(INVENTORY_ID,inventory)
            elif req.action=='verify':
                config=self._configuration(req.artifact_id)
                if inventory['holder']!=req.operation_id or inventory['artifact_id']!=req.artifact_id or inventory['active_digest']!=config['sha256']:
                    raise FoundationError('Applied result not verified')
            else:
                snapshot=self.snapshot(req.snapshot_id)
                if req.snapshot_id!=req.operation_id or inventory['lease'] not in (None,req.operation_id):
                    raise FoundationError('Rollback ownership unknown')
                unchanged=digest(inventory)==snapshot['before_digest']
                reserved=digest(inventory)==digest({**snapshot['before'],'lease':req.operation_id})
                if inventory['holder']!=req.operation_id and not unchanged and not reserved:
                    raise FoundationError('Rollback resource belongs to another operation')
                baseline_id=snapshot['before']['artifact_id']
                if self.records.exists(baseline_id):
                    if self._configuration(baseline_id)!=snapshot['configuration']:
                        raise FoundationError('Baseline artifact ownership or integrity unknown')
                else:
                    # Snapshot is self-contained; never rely on an old staging artifact.
                    self.records.write(baseline_id,snapshot['configuration'],create=True)
                inventory={**snapshot['before'],'holder':req.operation_id,'lease':None}
                self.records.write(INVENTORY_ID,inventory)
            if outcome=='partial':raise FoundationError('Simulated partial executor failure')
            return {'action':req.action,'operation_id':req.operation_id,'resource_id':RESOURCE,
                    'verified':True,'dry_run':True,'real_execution_available':False,**extra}

    def _armed(self, operation, artifact, snapshot):
        from .watchdog import validate_ticket
        ticket=validate_ticket(PrivateRecords(self.root/'watchdog').read(operation),operation)
        if ticket['artifact_id']!=artifact or ticket['interface']!=snapshot['before']['interface'] or ticket['before_digest']!=snapshot['before_digest'] or ticket['boot_id']!=self.boot_id or not ticket['started_at']<=self.clock.now()<ticket['deadline']:
            raise FoundationError('Watchdog permit unknown or expired')

    def release(self, operation, artifact):
        # Trusted transaction commit bookkeeping; never part of client request schema.
        with self._lock():
            inventory=self.inventory()
            if inventory['holder']!=operation or inventory['lease'] not in (None,operation) or inventory['artifact_id']!=artifact or inventory['active_digest']!=self._configuration(artifact)['sha256']:
                raise FoundationError('Commit ownership unknown')
            self._armed(operation,artifact,self.snapshot(operation))
            inventory['lease']=None
            self.records.write(INVENTORY_ID,inventory)


PATTERNS = {
    'interface':r'[a-zA-Z0-9_-]{1,15}', 'driver':r'nl80211', 'ctrl_interface':r'/run/hostapd',
    'ssid2':r'(?:[0-9a-f]{2}){1,32}', 'ignore_broadcast_ssid':r'[01]', 'country_code':r'[A-Z]{2}',
    'ieee80211d':r'1', 'hw_mode':r'[ga]', 'channel':r'[0-9]{1,3}',
    'beacon_int':r'[0-9]{2,5}', 'dtim_period':r'[0-9]{1,3}', 'wmm_enabled':r'[01]',
    'ap_isolate':r'[01]', 'ieee80211n':r'[01]', 'ieee80211ac':r'[01]',
    'bssid':r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', 'ht_capab':r'\[HT40[+-]\]',
    'vht_oper_chwidth':r'[01]', 'vht_oper_centr_freq_seg0_idx':r'[0-9]{1,3}',
    'auth_algs':r'1', 'wpa':r'2', 'rsn_pairwise':r'CCMP', 'wpa_key_mgmt':r'(?:WPA-PSK|SAE)',
    'ieee80211w':r'[02]', 'sae_require_mfp':r'1', 'sae_password':r'[0-9a-f]{32}', 'wpa_psk':r'[0-9a-f]{64}',
}


def validate_text(text, interface):
    if not isinstance(text,str) or len(text)>16384 or not text.endswith('\n'):
        raise FoundationError('Prepared configuration text invalid')
    values={}
    for line in text.splitlines():
        key,separator,value=line.partition('=')
        if not separator or key not in PATTERNS or key in values or not re.fullmatch(PATTERNS[key],value):
            raise FoundationError('Unsupported or unsafe configuration directive')
        values[key]=value
    required=set(PATTERNS)-{'bssid','ht_capab','vht_oper_chwidth','vht_oper_centr_freq_seg0_idx','sae_require_mfp','sae_password','wpa_psk'}
    if not required<=set(values) or values['interface']!=interface or values['interface']=='lo' or not 15<=int(values['beacon_int'])<=65535 or not 1<=int(values['dtim_period'])<=255:
        raise FoundationError('Incomplete prepared configuration')
    channel=int(values['channel'])
    if values['hw_mode']=='g' and not 1<=channel<=13 or values['hw_mode']=='a' and channel not in (36,40,44,48,149,153,157,161,165):
        raise FoundationError('Prepared channel outside supported subset')
    if ('vht_oper_chwidth' in values)!=('vht_oper_centr_freq_seg0_idx' in values) or values['ieee80211ac']=='1' and ('vht_oper_chwidth' not in values or values['ieee80211n']!='1' or values['hw_mode']!='a') or values['ieee80211ac']=='0' and 'vht_oper_chwidth' in values or 'ht_capab' in values and values['ieee80211n']!='1':
        raise FoundationError('Prepared radio parameter combination unsupported')
    if values['ieee80211n']=='1' and values['wmm_enabled']!='1':
        raise FoundationError('HT requires WMM')
    secondary=None
    if 'ht_capab' in values:
        secondary=channel+(4 if values['ht_capab']=='[HT40+]' else -4)
        if values['hw_mode']=='g' and not 1<=secondary<=13 or values['hw_mode']=='a' and secondary not in (36,40,44,48,149,153,157,161,165):
            raise FoundationError('Prepared secondary channel unsupported')
    if 'vht_oper_chwidth' in values:
        center=int(values['vht_oper_centr_freq_seg0_idx'])
        if values['vht_oper_chwidth']=='1':
            if center not in (42,155) or channel not in (center-6,center-2,center+2,center+6) or secondary!=(channel+4 if channel in (center-6,center+2) else channel-4):
                raise FoundationError('Prepared VHT80 layout unsupported')
        elif center!=(channel if secondary is None else (channel+secondary)//2):
            raise FoundationError('Prepared VHT20/40 center unsupported')
    if values['country_code'] in ('XX','ZZ'):
        raise FoundationError('Prepared regulatory domain unknown')
    if 'bssid' in values:
        from ..models import valid_mac
        valid_mac(values['bssid'],local=True)
    # No actual secrets accepted by this dry-run foundation.
    import hashlib
    synthetic=hashlib.sha256(b'PiRate dry-run synthetic credential; never deploy').hexdigest()
    if values['wpa_key_mgmt']=='WPA-PSK':
        if values.get('wpa_psk')!=synthetic or 'sae_password' in values or 'sae_require_mfp' in values or values['ieee80211w']!='0':
            raise FoundationError('Only synthetic WPA2 credentials accepted')
    elif values.get('sae_password')!=synthetic[:32] or 'wpa_psk' in values or values['ieee80211w']!='2' or values.get('sae_require_mfp')!='1':
        raise FoundationError('Only synthetic WPA3 credentials accepted')
