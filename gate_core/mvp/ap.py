"""Process-owned hostapd/dnsmasq with the connection Safe Apply transaction."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from functools import wraps
from .proxy import ConnectionError
from .router import configuration, isolated_lab_namespace, network_command, permitted, operation_scope


def normalize(raw, prior=None, identity=None):
    # Optional identity metadata; carried by the existing AP snapshots, never hostapd.
    if isinstance(raw,dict) and 'saved_profile_id' in raw:
        import uuid
        try:
            if str(uuid.UUID(raw['saved_profile_id'])) != raw['saved_profile_id']:raise ValueError()
        except (ValueError,TypeError,AttributeError):raise ConnectionError('Invalid saved AP profile ID') from None
        identifier=raw['saved_profile_id'];raw={k:v for k,v in raw.items() if k!='saved_profile_id'}
    else:identifier=None
    defaults={'interface':'wlan0','backend':'wifi','ssid':'PiRate','security':'wpa2',
              'password':'','country':'US','channel':1,'band':'auto','width':'auto','subnet':'10.42.0.1/24',
              'mac_mode':'keep','mac_address':'','fingerprint':'default','dhcp_start':'10.42.0.10','dhcp_end':'10.42.0.200','lease_minutes':60}
    if not isinstance(raw,dict) or set(raw)-set(defaults):raise ConnectionError('Invalid AP configuration')
    value=dict(defaults,**raw)
    if not value['password'] and prior:value['password']=prior['password']
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',str(value['interface'])) or value['interface']=='lo':raise ConnectionError('Invalid AP interface')
    if value['backend'] not in ('wifi','virtual'):raise ConnectionError('Invalid AP backend')
    if value['backend']=='virtual' and not isolated_lab_namespace():raise ConnectionError('Virtual AP requires isolated user/network/mount namespaces')
    if not isinstance(value['ssid'],str) or not 1<=len(value['ssid'].encode())<=32 or '\x00' in value['ssid']:raise ConnectionError('SSID must be 1–32 UTF-8 bytes')
    if value['security'] not in ('wpa2','wpa3'):raise ConnectionError('AP security must be WPA2 or WPA3')
    if not isinstance(value['password'],str) or not re.fullmatch(r'[ -~]{8,63}',value['password']):raise ConnectionError('AP password must be 8–63 printable ASCII characters')
    if not re.fullmatch('[A-Z]{2}|00',str(value['country'])) or type(value['channel']) is not int or not 0<=value['channel']<=196:raise ConnectionError('Invalid country or channel')
    if value['band'] not in ('auto','2.4','5') or str(value['width']) not in ('auto','20','40','80'):raise ConnectionError('Invalid band or width')
    value['width']=str(value['width'])
    try:
        address=ipaddress.IPv4Interface(value['subnet']);start=ipaddress.IPv4Address(value['dhcp_start']);end=ipaddress.IPv4Address(value['dhcp_end'])
    except (ValueError,TypeError):raise ConnectionError('Invalid LAN subnet or DHCP range') from None
    if not 16<=address.network.prefixlen<=29 or address.ip in (address.network.network_address,address.network.broadcast_address) or address.ip.is_multicast or address.ip.is_loopback:raise ConnectionError('Invalid LAN gateway subnet')
    if not (address.network.network_address<start<=end<address.network.broadcast_address) or start<=address.ip<=end:raise ConnectionError('DHCP range must be inside subnet and exclude gateway')
    if type(value['lease_minutes']) is not int or not 2<=value['lease_minutes']<=1440:raise ConnectionError('DHCP lease must be 2–1440 minutes')
    if value['mac_mode'] not in ('keep','generate','manual','hardware'):raise ConnectionError('Invalid MAC mode')
    from .mac import validate,generate
    if value['mac_mode']=='generate' and not value['mac_address']:
        value['mac_address']=(prior or {}).get('mac_address','') if prior and prior.get('mac_mode')=='generate' and prior.get('interface')==value['interface'] else ''
        if not value['mac_address'] and identity and identity.get('interface')==value['interface'] and identity.get('mac_mode')=='generate':value['mac_address']=identity.get('mac_address','')
        if not value['mac_address']:value['mac_address']=generate()
    if value['mac_mode'] in ('generate','manual'):value['mac_address']=validate(value['mac_address'])
    if value['fingerprint'] not in ('default','ttl64','ttl128'):raise ConnectionError('Invalid fingerprint/TTL')
    value['subnet']=str(address)
    if identifier:value['saved_profile_id']=identifier
    return value


def capabilities(interface):
    from .wifi_performance import inspect_radio, plans
    radio=inspect_radio(interface,network_command)
    for band,details in radio['bands'].items():
        for channel in details['channels']:
            try:channel['widths']=sorted({p['width_mhz'] for p in plans({'band':band,'channel':channel['number'],'width':'auto'},radio)})
            except ConnectionError:channel['widths']=[20]
    return {'interface':interface,'ap_mode':radio['ap_mode'],'security':radio.get('security',[]),
            'channels':[c['number'] for band in radio['bands'].values() for c in band['channels']],
            'radio':radio,'physical_test':'NOT TESTED','limits':'Current driver/regulatory snapshot; hostapd validates AP at startup'}


def binary(name):
    path=shutil.which(name,path=os.environ.get('PATH','')+':/usr/sbin:/sbin')
    if not path:raise ConnectionError(name+' unavailable; install Debian package')
    return path


def serialized(method):
    @wraps(method)
    def locked(self,*args,**kwargs):
        with self.lifecycle_lock, operation_scope(method.__name__,(args[0] if method.__name__=='prepare' and args and isinstance(args[0],dict) else self.active or self.saved or {}).get('interface'),self.record_operation):
            try:
                result=method(self,*args,**kwargs)
                if method.__name__=='rollback' and self.apply_failure:
                    self.apply_failure['rollback']={'result':self.last_action,'control':self.health.get('control_state'),'beacons':'UNVERIFIED','at':time.time()}
                if method.__name__=='stop_processes':self.stop_failed=False
                self.record_operation({'operation':method.__name__,'stage':method.__name__,'interface':(self.active or self.saved or {}).get('interface'),'initiated_by':'PiRate','result':'OK','at':time.time()})
                return result
            except Exception as exc:
                self.record_operation({'operation':method.__name__,'stage':method.__name__,'interface':(self.active or self.saved or {}).get('interface'),'initiated_by':'PiRate','result':'Failed','detail':str(exc)[:1000],'at':time.time()})
                if method.__name__=='rollback' and self.apply_failure:
                    self.apply_failure['rollback']={'result':'FAILED','detail':str(exc)[:1000],'operation':getattr(exc,'operation',None),'at':time.time()}
                    self.save()
                if method.__name__=='prepare':
                    self.apply_failure={'stage':'prepare','interface':(self.active or {}).get('interface'),'detail':str(exc)[:1000],'operation':getattr(exc,'operation',None),'at':time.time()}
                    self.save()
                if method.__name__=='stop_processes':self.stop_failed=True
                raise
            finally:
                if method.__name__ in ('launch','rollback','stop'):self.starting=False
    return locked


class AccessPoint:
    def __init__(self,app):
        self.app=app;self.init_runtime();self.directory=app.directory/'ap';self.directory.mkdir(mode=0o700,exist_ok=True)
        self.path=self.directory/'state.json';self.active=None;self.previous=None;self.pending=False
        self.baseline=None;self.owned=None;self.processes=[];self.records=[];self.last_action='DISABLED'
        self.saved=None;self.radio_status={};self.saved_radio=None;self.failure=None
        from .management import Management
        self.management=Management(app)
        if self.path.exists():
            state=json.loads(self.path.read_text())
            if state.get('baseline') or state.get('owned') or state.get('processes'):permitted()
            self.requested_identity=state.get('requested_identity');self.operations=state.get('operations',[])[-48:];self.apply_failure=state.get('apply_failure');self.ownership=state.get('ownership',{})
            self.controls=state.get('controls',[]);self.recovery.update(state.get('recovery',{}))
            self.saved_radio=state.get('confirmed_radio');self.saved=state.get('confirmed');self.baseline=state.get('baseline');self.owned=state.get('owned')
            self.records=state.get('processes',[])
            try:
                self.stop_processes();self.restore_address()
                self.last_action='RECOVERED_BLOCKED'
            except (OSError,ConnectionError) as exc:
                from .wifi_performance import diagnose
                self.failure=diagnose(exc);self.last_action='RECOVERY_REQUIRED'
            self.save()

    def public(self):
        config=self.active or self.saved
        if not config and self.management.config and self.management.config.get('ap_interface'):
            deployment=self.management.config
            address=ipaddress.IPv4Interface(deployment['subnet'])
            config={'interface':deployment['ap_interface'],'backend':'wifi','ssid':'PiRate','security':'wpa2',
                    'country':'US','channel':1,'band':'auto','width':'auto','subnet':str(address),'dhcp_start':str(address.network[10]),
                    'dhcp_end':str(address.network[200]),'lease_minutes':60}
        clean={k:v for k,v in config.items() if k!='password'} if config else None
        if self.active:self.refresh_health()
        health=dict(self.health)
        if not self.active:
            health['state']='Unsupported' if self.failure and self.failure.get('code')=='ap_unsupported' else 'Error' if self.failure else 'Ready' if config else 'Unknown'
            health['hostapd_process']='Unknown' if self.records else 'Stopped'
            health['control_state']='UNKNOWN' if self.records else 'STOPPED'
        if self.recovery.get('latched') and not self.recovering:health['state']='Error'
        return {'state':('ACTIVE' if self.healthy() and health.get('state')=='Active' else 'UNKNOWN' if health.get('state')=='Unknown' else 'DEGRADED') if self.active else 'DEGRADED' if self.failure else 'DISABLED',
                'health':health,'power_save':self.power,'recovery':dict(self.recovery,retry_after=self.retry_after()),'control_directory':str(self.control.directory) if self.control else None,'service':'Running','radio':self.radio_status,'failure':self.failure,'config':clean,'password_saved':bool(config and config.get('password')),'pending':self.pending,
                'apply_failure':self.apply_failure,'ownership':self.ownership,'last_action':self.last_action,'dns':'dnsmasq -> PiRate selected upstream; no direct fallback',
                'physical_wifi':'NOT TESTED','reboot_policy':'Restore confirmed router only after firewall; failed upstream stays BLOCKED'}

    def save(self):
        data={'requested_identity':self.requested_identity,'operations':self.operations,'apply_failure':self.apply_failure,'ownership':self.ownership,'health':self.health,'failure':self.failure,'last_action':self.last_action,'controls':self.controls,'recovery':self.recovery,'power_save':self.power,'kernel_targets':sorted(getattr(self.kernel,'targets',[])) if self.kernel else [],'confirmed_radio':self.saved_radio,'confirmed':self.saved,'active':self.active,'previous':self.previous,'pending':self.pending,
              'baseline':self.baseline,'owned':self.owned,'processes':self.records}
        temp=self.path.with_suffix('.tmp')
        with temp.open('w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(data,f);f.flush();os.fsync(f.fileno())
        os.replace(temp,self.path)
        fd=os.open(self.directory,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def record_operation(self,operation):
        self.operations.append(operation);self.operations=self.operations[-48:]
        if hasattr(self,'path'):self.save()

    def inspect_ownership(self,interface):
        report={'interface':interface,'owner':'Unknown','mode':None,'evidence':[]}
        info=network_command('iw','dev',interface,'info',check=False)
        mode=re.search(r'^\s*type\s+(\S+)',info.stdout,re.M)
        if mode:report['mode']=mode[1]
        if info.returncode:
            report['reason']='Interface inspection unavailable; driver result required'
        elif self.active or self.baseline:
            report['owner']='PiRate';report['evidence'].append('owned AP transaction')
        else:
            associated=network_command('iw','dev',interface,'link',check=False)
            if 'Connected to ' in associated.stdout:
                report['owner']='Foreign connection';report['evidence'].append('iw reports associated station')
        nm=shutil.which('nmcli')
        if nm:
            reply=network_command(nm,'-g','GENERAL.STATE,GENERAL.NM-MANAGED','device','show',interface,check=False)
            fields=reply.stdout.strip().splitlines()
            if reply.returncode==0 and len(fields)==2:
                state=re.match(r'([0-9]+)',fields[0]);managed=fields[1].strip().lower()
                report['network_manager']={'state':int(state[1]) if state else None,'managed':managed if managed in ('yes','no') else 'unknown'}
                if state and int(state[1])>=30 and managed=='yes':
                    report['owner']='NetworkManager';report['evidence'].append('per-interface GENERAL.NM-MANAGED=yes')
        tool=shutil.which('wpa_cli')
        if tool:
            reply=network_command(tool,'-i',interface,'status',check=False)
            if reply.returncode==0 and re.search(r'^wpa_state=',reply.stdout,re.M):
                report['owner']='wpa_supplicant';report['evidence'].append('per-interface control STATUS answered')
        if report['owner']=='Unknown' and report['mode']=='managed':report['owner']='Free managed / no proven foreign owner'
        self.ownership=report;self.save()
        if report['owner'] in ('Foreign connection','wpa_supplicant','NetworkManager'):
            raise ConnectionError('Selected interface is owned by '+report['owner']+'; release this interface or choose another adapter')
        if report['mode']=='AP' and report['owner']!='PiRate':
            raise ConnectionError('Existing AP interface ownership is unconfirmed; select a free adapter before changing its MAC or mode')
        return report

    def write(self,name,content):
        path=self.directory/name
        with path.open('w') as f:os.fchmod(f.fileno(),0o600);f.write(content)
        return path

    @serialized
    def stop_processes(self):
        self.management.stop()
        if self.control:self.control.close()
        for record in self.records:
            try:
                proc=Path('/proc')/str(record['pid'])
                if proc.joinpath('stat').read_text().split()[21]!=record['birth']:continue
                if os.stat(proc/'ns/net').st_ino!=record['net_inode']:continue
                if str(self.directory).encode() not in proc.joinpath('cmdline').read_bytes():continue
                os.kill(record['pid'],signal.SIGTERM)
            except (OSError,IndexError,KeyError):pass
        for process in self.processes:
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:raise ConnectionError('Owned AP process stuck after SIGKILL; refusing a second hostapd') from None
        # Recovered orphans have no Popen handle; wait before reusing sockets.
        if self.records:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                alive=False
                for record in self.records:
                    try:
                        fields=Path('/proc',str(record['pid']),'stat').read_text().split()
                        alive|=fields[21]==record.get('birth') and fields[2]!='Z' and os.stat(Path('/proc',str(record['pid']),'ns/net')).st_ino==record.get('net_inode') and str(self.directory).encode() in Path('/proc',str(record['pid']),'cmdline').read_bytes()
                    except (OSError,IndexError,KeyError):pass
                if not alive:break
                time.sleep(.05)
            if alive:raise ConnectionError('Owned AP daemon did not stop; LAN remains BLOCKED')
        self.records=[];self.processes=[]
        self.cleanup_controls();self.last_launch_key=None

    @serialized
    def restore_address(self):
        try:self._restore_address()
        except (OSError,ConnectionError):
            interfaces={item['interface'] for item in (self.baseline,self.owned) if item}
            if interfaces and all(not (Path('/sys/class/net')/name).exists() for name in interfaces):
                # USB unplug removed its MAC/address along with the netdev. Keep
                # confirmed settings but do not prevent the independent WebUI boot.
                self.baseline=None;self.owned=None
                return
            raise

    def _restore_address(self):
        self.release_address()
        if self.baseline and self.baseline.get('mac'):
            from .mac import apply
            apply(self.baseline['interface'],self.baseline['mac'])
        if self.baseline and self.baseline.get('backend','wifi')=='wifi':
            from .mac import restore_mode
            mode=self.baseline.get('mode') or 'managed'
            restore_mode(self.baseline['interface'],'managed' if mode=='AP' else mode,failed=(self.apply_failure or {}).get('operation') if not (self.apply_failure or {}).get('historical') else None)
        if self.baseline:
            self.set_link_state(self.baseline['interface'],self.baseline['up'],rollback=True)
        self.baseline=None

    def set_link_state(self,interface,up,rollback=False):
        rows=json.loads(network_command('ip','-j','link','show','dev',interface).stdout)
        if not rows:raise ConnectionError('No such device: '+interface)
        actual=rows[0]
        if ('UP' in actual.get('flags',[]))==up:return
        args=('ip','link','set',interface,'up' if up else 'down')
        failed=(self.apply_failure or {}).get('operation') or {}
        if rollback and not (self.apply_failure or {}).get('historical') and failed.get('arguments')==list(args):
            raise ConnectionError('Rollback link restoration unverified: refusing to repeat the failed '+failed['operation']+' operation')
        network_command(*args)
        rows=json.loads(network_command('ip','-j','link','show','dev',interface).stdout)
        if not rows:raise ConnectionError('No such device: '+interface)
        actual=rows[0]
        if ('UP' in actual.get('flags',[]))!=up:raise ConnectionError('Interface link state was not verified')

    def release_address(self):
        if not self.owned:return
        owned=self.owned
        rows=json.loads(network_command('ip','-j','-4','addr','show','dev',owned['interface']).stdout)
        if any(a.get('local','')+'/'+str(a.get('prefixlen'))==owned['address'] for row in rows for a in row.get('addr_info',[])):
            network_command('ip','addr','del',owned['address'],'dev',owned['interface'])
        self.owned=None;self.save()

    def spawn(self,name,args):
        self.record_operation({'operation':name+'_start','stage':'launch','interface':self.active['interface'],'initiated_by':'PiRate','arguments':list(args),'result':'Started','at':time.time()})
        log=self.directory/(name+'.log')
        with log.open('wb') as f:
            os.fchmod(f.fileno(),0o600)
            process=subprocess.Popen(args,stdout=f,stderr=f)
        self.processes.append(process)
        self.records.append({'name':name,'pid':process.pid,'birth':Path('/proc',str(process.pid),'stat').read_text().split()[21],
                             'net_inode':os.stat('/proc/self/ns/net').st_ino})
        self.save()
        return process

    def init_runtime(self):
        import threading
        self.lifecycle_lock=threading.RLock()
        self.requested_identity=None;self.operations=[];self.apply_failure=None;self.ownership={}
        self.controls=[];self.control=None;self.kernel=None;self.power={};self.power_attempted=set()
        self.health={'state':'Unknown','control_state':'UNKNOWN','driver':{'state':'Unknown'},'confirmed_fault':False,'beacons':'UNVERIFIED'}
        self.recovery={'auto_attempts':0,'last_at':0,'reason':None,'latched':False}
        self.recovering=False;self.starting=False;self.last_probe=0;self.last_launch_key=None;self.stop_failed=False;self.reused=False;self.events=[]

    def power_save_off(self):
        interface=self.active['interface']
        try:identity=(interface,(Path('/sys/class/net')/interface/'ifindex').read_text().strip())
        except OSError:identity=(interface,'unknown')
        if identity in self.power_attempted:return
        self.power_attempted.add(identity)
        self.power={'requested':'off','result':'Unknown','observed':None,'checked_at':time.time(),'cause':'Power saving is not a proven cause of a radio failure'}
        try:
            before=network_command('iw','dev',interface,'get','power_save',check=False)
            prior=re.search(r'Power save:\s*(on|off)',getattr(before,'stdout',''),re.I)
            if prior:self.power['observed']=prior[1].lower()
            if re.search(r'Power save:\s*off',getattr(before,'stdout',''),re.I):self.power.update(result='Disabled',observed='off');return
            result=network_command('iw','dev',interface,'set','power_save','off',check=False)
            if result.returncode:
                self.power['result']='Unsupported' if re.search(r'not supported|\b95\b',result.stderr,re.I) else 'Failed'
                return
            after=network_command('iw','dev',interface,'get','power_save',check=False)
            observed=re.search(r'Power save:\s*(on|off)',getattr(after,'stdout',''),re.I)
            self.power.update(observed=observed[1].lower() if observed else None,result='Disabled' if observed and observed[1].lower()=='off' else 'Unverified')
        except (ConnectionError,OSError):self.power['result']='Unavailable'

    def new_control(self):
        import uuid
        from .wifi_health import HostapdControl
        parent=self.directory/'control'
        parent.mkdir(mode=0o700,exist_ok=True)
        stat=parent.lstat()
        if parent.is_symlink() or stat.st_uid!=os.geteuid() or stat.st_mode&0o077:raise ConnectionError('AP control directory must be private and owned')
        directory=parent/uuid.uuid4().hex[:16];directory.mkdir(mode=0o700)
        record={'directory':directory.name,'dir_inode':directory.stat().st_ino,'interface':self.active['interface'],'socket_inode':None}
        self.controls.append(record);self.save()
        self.control=HostapdControl(directory,self.active['interface'])
        return directory

    def capture_control(self):
        import stat
        if not self.control:return
        path=self.control.directory/self.control.interface
        if not path.exists():return  # STATUS cannot succeed without it outside mocked tests.
        info=path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.geteuid():raise ConnectionError('Unexpected AP control socket owner/type')
        os.chmod(path,0o600)
        self.controls[-1]['socket_inode']=info.st_ino;self.save()

    @serialized
    def cleanup_controls(self):
        import stat
        from .wifi_health import HostapdControl
        if self.control:self.control.close();self.control=None
        retained=[]
        for record in self.controls:
            name=record.get('directory','');interface=record.get('interface','')
            if not re.fullmatch(r'[0-9a-f]{16}',name) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface):retained.append(record);continue
            directory=self.directory/'control'/name
            try:
                info=directory.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_ino!=record.get('dir_inode'):
                    retained.append(record);continue
                path=directory/interface
                if path.exists() or path.is_symlink():
                    socket_info=path.lstat()
                    if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid!=os.geteuid():retained.append(record);continue
                    probe=HostapdControl(directory,interface)
                    if probe.request('PING')=='PONG':raise ConnectionError('AP control socket still responds after stop; refusing a second hostapd')
                    if socket_info.st_ino==record.get('socket_inode'):path.unlink()
                    else:retained.append(record);continue  # Unknown inode is never deleted.
                directory.rmdir()
            except FileNotFoundError:pass
            except OSError:retained.append(record)
        self.controls=retained

    @serialized
    def refresh_health(self,force=False):
        from .wifi_health import KernelHealth
        now=time.monotonic()
        if not force and now-self.last_probe<5:return self.health
        self.last_probe=now
        if not self.active:return self.health
        if self.active['backend']=='virtual':
            self.health={'state':'Active' if self.process_alive() else 'Error','confirmed_fault':not self.process_alive(),'control_state':'NOT APPLICABLE','driver':{'state':'NOT APPLICABLE'},'beacons':'NOT APPLICABLE'}
            return self.health
        if self.kernel is None:self.kernel=KernelHealth(self.active['interface'])
        driver=self.kernel.poll();present=self.interface_present();alive=self.process_alive()
        status=self.control.status() if self.control and alive and present else {}
        control_state=status.get('state','UNKNOWN')
        if self.control:self.events=(self.events+self.control.events())[-16:]
        info=''
        if present:
            try:info=network_command('iw','dev',self.active['interface'],'info',check=False).stdout
            except ConnectionError:pass
        interface_type=re.search(r'(?m)^\s*type\s+(\S+)',info)
        interface_state=interface_type[1] if interface_type else 'Unknown' if present else 'Missing'
        fault=not present or not alive or control_state in ('DISABLED','UNINITIALIZED') or driver['confirmed_fault'] or interface_state not in ('AP','Unknown')
        state='Starting' if self.starting else 'Error' if self.recovery.get('latched') and not self.recovering or fault else 'Degraded' if driver['state']=='Degraded' else 'Unknown' if control_state!='ENABLED' or interface_state=='Unknown' or driver['state']=='Unknown' else 'Active'
        reason='Wi-Fi adapter disconnected' if not present else 'hostapd/dnsmasq process stopped' if not alive else driver.get('reason') or ('AP control is '+control_state if control_state not in ('ENABLED','UNKNOWN') else 'Interface is not in AP mode' if interface_state not in ('AP','Unknown') else None)
        self.health={'state':state,'confirmed_fault':fault or self.recovery.get('latched',False) and not self.recovering,'control_state':control_state,'hostapd_process':'Running' if self.hostapd_alive() else 'Stopped',
                     'interface':interface_state,'control_station_count':int(status['num_sta']) if str(status.get('num_sta','')).isdigit() else None,'driver':driver,'checked_at':time.time(),'reason':reason,'events':list(self.events),'beacons':'UNVERIFIED',
                     'note':'Control ENABLED and type AP do not prove beacon transmission. Zero clients is not a fault.'}
        return self.health

    def process_alive(self):
        return bool(self.processes and all(p.poll() is None for p in self.processes))

    def hostapd_alive(self):
        return any(r.get('name')=='hostapd' and p.poll() is None for r,p in zip(self.records,self.processes))

    def equivalent(self,value):
        if not self.active or not self.healthy():return False
        physical=('interface','backend','ssid','password','security','country','subnet','dhcp_start','dhcp_end','lease_minutes')
        if any(value[k]!=self.active[k] for k in physical):return False
        target=value.get('mac_address') if value['mac_mode']!='keep' else self.active.get('mac_address')
        if target!=self.active.get('mac_address'):return False
        if all(value[k]==self.active[k] for k in ('band','channel','width')):return True
        from .wifi_performance import inspect_radio,plans
        first=plans(value,inspect_radio(value['interface'],network_command))[0]
        return all(first[k]==self.radio_status.get(k) for k in ('band','channel','width_mhz','configuration_mode'))

    def retry_after(self):
        return max(0,min(60,int(60-(time.time()-self.recovery.get('last_at',0)))))

    @serialized
    def claim_recovery(self,manual=False):
        if self.retry_after():raise ConnectionError('Wi-Fi retry cooldown: '+str(self.retry_after())+' seconds')
        if not manual and self.recovery.get('auto_attempts',0)>=1:raise ConnectionError('Automatic Wi-Fi recovery exhausted; use Retry Wi-Fi')
        self.recovery.update(last_at=time.time(),auto_attempts=0 if manual else 1,latched=False)
        self.save()

    @serialized
    def latch_recovery(self,reason):
        self.recovery.update(latched=True,auto_attempts=1,last_at=time.time(),reason=reason)
        self.save()

    @serialized
    def recover(self,manual=False):
        if self.pending:raise ConnectionError('Confirm or roll back Safe Apply before Retry Wi-Fi')
        if not self.active or not self.interface_present():raise ConnectionError('Wi-Fi adapter unavailable; reconnect it before Retry Wi-Fi')
        self.claim_recovery(manual)
        reason=self.health.get('reason') or 'Manual Retry Wi-Fi'
        self.recovery['reason']=reason;self.recovery['latched']=True;self.recovering=True;self.save()
        try:
            # Preserve the selected band/channel/upper width limit. A current
            # valid plan is tried first, followed by only supported lower modes.
            self.stop_processes();self.launch()
            self.refresh_health(force=True)
            if self.health.get('control_state') not in ('ENABLED','NOT APPLICABLE') or self.health.get('state') in ('Error','Degraded') or not self.process_alive():raise ConnectionError(self.health.get('reason') or 'AP control recovery unverified')
            if not manual and re.search(r'firmware|USB',reason,re.I) and self.health.get('driver',{}).get('state')=='Unknown':raise ConnectionError('Driver health Unknown after communication fault; automatic recovery cannot verify it')
            self.recovery['latched']=False;self.last_action='RECOVERY_CONTROL_VERIFIED';self.save()
        except (OSError,ValueError,ConnectionError) as exc:
            self.recovery.update(latched=True,reason=reason)
            self.failure={'code':'recovery_failed','message':'Wi-Fi unavailable. Retry Wi-Fi; if it repeats, reconnect the adapter or check driver compatibility.','detail':str(exc)}
            self.last_action='RECOVERY_FAILED';self.save();raise
        finally:self.recovering=False;self.starting=False

    def interface_present(self):
        # An unplugged USB interface must not remain ACTIVE just because a child lives.
        return self.active.get('backend')=='virtual' or (Path('/sys/class/net')/self.active['interface']).exists()

    def healthy(self):
        if not self.process_alive() or self.active and not self.interface_present():return False
        if not self.active or self.active['backend']=='virtual':return True
        report=self.refresh_health()
        return report.get('control_state')=='ENABLED' and report.get('state') not in ('Error','Degraded','Starting') and not self.recovery.get('latched')

    @serialized
    def prepare(self,raw,gateway):
        permitted();value=normalize(raw,self.active or self.saved,self.requested_identity)
        if value['mac_mode']=='generate':
            self.requested_identity={k:value[k] for k in ('interface','mac_mode','mac_address')};self.save()
        config=configuration(dict(gateway,lan_subnet=str(ipaddress.IPv4Interface(value['subnet']).network),fingerprint=value['fingerprint']))
        if self.management.config:config['management_port']=8766
        if value['interface']!=config['lan_interface'] or value['interface']==config['wan_interface']:raise ConnectionError('AP interface must match gateway LAN and differ from WAN')
        if self.active and value['interface']!=self.active['interface']:raise ConnectionError('Сначала отключи роутер, затем выбери другой Wi-Fi interface и запусти снова')
        if self.pending:raise ConnectionError('AP transaction already pending')
        from .management_guard import protect_ssh
        protect_ssh(value['interface'])
        if value['mac_mode']=='hardware':
            from .mac import hardware
            value['mac_address']=hardware(value['interface'])
        self.refresh_health(force=True) if self.active else None
        if self.active and value['mac_mode']=='keep':value['mac_address']=self.active.get('mac_address','')
        if self.equivalent(value):
            self.previous=self.active;self.active=value;self.pending=True;self.reused=True;self.last_launch_key=json.dumps({k:v for k,v in value.items() if k!='fingerprint'},sort_keys=True);self.save()
            config['ap_dns_address']=str(ipaddress.IPv4Interface(value['subnet']).ip)
            if self.apply_failure:self.apply_failure['historical']=True
            self.last_action='UNCHANGED_AP_AWAITING_CONFIRMATION'
            return config
        self.reused=False
        if value['backend']=='wifi':self.inspect_ownership(value['interface'])
        if value['backend']=='wifi' and self.baseline is None and self.active is None:
            existing=json.loads(network_command('ip','-j','-4','addr','show','dev',value['interface']).stdout)
            if any(item.get('addr_info') for item in existing):raise ConnectionError('Wi-Fi interface уже имеет IPv4; выбери свободный AP interface, чтобы сохранить управление')
            if 'Connected to ' in network_command('iw','dev',value['interface'],'link',check=False).stdout:
                raise ConnectionError('Wi-Fi interface используется клиентским подключением; выбери свободный AP interface')
        binary('dnsmasq')
        if value['backend']=='wifi':
            binary('hostapd')
            # iw reports are advisory. Keep secure WPA/CCMP/PMF settings and let
            # hostapd validate the actual driver, country and channel at runtime.
        network=ipaddress.IPv4Interface(value['subnet']).network
        for link in json.loads(network_command('ip','-j','-4','addr').stdout):
            if link['ifname']==value['interface']:continue
            for address in link.get('addr_info',[]):
                if network.overlaps(ipaddress.ip_network(address['local']+'/'+str(address['prefixlen']),strict=False)):raise ConnectionError('LAN subnet overlaps another interface')
        # Protect LAN before changing its address or starting hostapd/dnsmasq.
        if self.app.router.blocked_config:
            previous=self.app.router.blocked_config
            if previous['lan_interface']!=value['interface'] and self.app.router.current is not None:
                raise ConnectionError('Сначала отключи роутер перед сменой AP interface')
            config['protected_lans']=list(dict.fromkeys([*previous.get('protected_lans',[]),previous['lan_interface'],value['interface']]))
            config=configuration(config)
        if self.app.router.current is None:
            self.app.router.blocked_config=config;self.app.router.save();self.app.router.install(config)
        rows=json.loads(network_command('ip','-j','link','show','dev',value['interface']).stdout)
        if not rows:raise ConnectionError('No such device: '+value['interface'])
        link=rows[0]
        if self.baseline is None:
            self.baseline={'interface':value['interface'],'up':'UP' in link['flags'],'mac':link.get('address'),'mode':self.ownership.get('mode'),'backend':value['backend']}
        if value['mac_mode']=='keep':value['mac_address']=link.get('address','')
        self.starting=True;self.previous=self.active;self.pending=True;self.active=value;self.save()
        self.stop_processes()
        self.release_address()
        if value['mac_mode']!='keep':
            from .mac import apply
            apply(value['interface'],value['mac_address'])
        links=json.loads(network_command('ip','-j','-4','addr','show','dev',value['interface']).stdout)
        addresses=links[0].get('addr_info',[]) if links else []
        if not any(a['local']+'/'+str(a['prefixlen'])==value['subnet'] for a in addresses):
            self.owned={'interface':value['interface'],'address':value['subnet']};self.save()
            network_command('ip','addr','add',value['subnet'],'dev',value['interface'])
        self.set_link_state(value['interface'],True)
        self.app.router.start_dns()
        config['ap_dns_address']=str(ipaddress.IPv4Interface(value['subnet']).ip)
        self.launch()
        if self.apply_failure:self.apply_failure['historical']=True;self.save()
        return config

    def daemon_error(self,name,reason):
        # Return bounded diagnostics without exposing configured Wi-Fi secrets.
        path=self.directory/(name+'.log')
        with path.open('rb') as stream:
            stream.seek(0,2);stream.seek(max(0,stream.tell()-4096))
            detail=stream.read().decode('utf-8',errors='replace')
        password=(self.active or {}).get('password','')
        ssid=(self.active or {}).get('ssid','')
        derived=hashlib.pbkdf2_hmac('sha1',password.encode(),ssid.encode(),4096,32).hex() if password and ssid else ''
        for secret in (password,derived):
            if secret:detail=detail.replace(secret,'[redacted]')
        detail=re.sub(r'(?im)^.*(?:password|passphrase|psk|key=|sae_password).*$','[redacted]',detail)
        detail='; '.join(line for line in detail.splitlines() if line.strip())[-1500:]
        error=ConnectionError(name+': '+reason+('; '+detail if detail else ''))
        operation={'operation':name+'_start','stage':'launch','interface':self.active.get('interface'),'initiated_by':'PiRate','result':'Failed','detail':str(error),'at':time.time(),'returncode':None}
        for record,process in zip(getattr(self,'records',[]),getattr(self,'processes',[])):
            if record.get('name')==name:operation['returncode']=process.poll()
        if hasattr(self,'operations'):self.record_operation(operation)
        error.operation=operation
        return error

    @serialized
    def launch(self):
        if self.stop_failed:raise ConnectionError('Previous AP stop unverified; refuse a second hostapd until cleanup succeeds')
        launch_key=json.dumps({k:v for k,v in self.active.items() if k!='fingerprint'},sort_keys=True)
        if self.processes:
            if self.last_launch_key==launch_key and self.healthy():return
            raise ConnectionError('Stop owned AP daemons before launching another configuration')
        self.starting=True
        value=self.active;address=ipaddress.IPv4Interface(value['subnet'])
        if value['backend']=='wifi':
            from .wifi_performance import inspect_radio, plans
            from .wifi_health import KernelHealth
            if self.kernel is None or self.kernel.interface!=value['interface']:self.kernel=KernelHealth(value['interface'])
            self.kernel.begin();self.power_save_off()
            candidates=plans(value,inspect_radio(value['interface'],network_command))
            if self.recovering:
                old=dict(self.radio_status);rank=lambda mode:2 if mode.startswith('VHT') else 1 if mode.startswith('HT') else 0
                candidates=[p for p in candidates if p['width_mhz']<=old.get('width_mhz',20) and (p['width_mhz']<old.get('width_mhz',20) or rank(p['configuration_mode'])<=rank(old.get('configuration_mode','legacy')))]
                candidates.sort(key=lambda p:(p['band']!=old.get('band'),p['channel']!=old.get('channel')))
                selected={}
                for plan in candidates:selected.setdefault(plan['band'],plan['channel'])
                candidates=[p for p in candidates if p['channel']==selected[p['band']]][:10]
                if not candidates:raise ConnectionError('No permitted recovery mode; choose Auto or another allowed channel')
            elif value==self.saved and self.saved_radio:
                candidates.sort(key=lambda p:not all(p.get(k)==self.saved_radio.get(k) for k in ('band','channel','width_mhz','configuration_mode')))
        dns=self.write('dnsmasq.conf',f'''interface={value['interface']}
bind-interfaces
log-facility=-
listen-address={address.ip}
no-resolv
no-hosts
cache-size=0
server=127.0.0.1#{self.app.router.dns_tcp.server_address[1]}
dhcp-range={value['dhcp_start']},{value['dhcp_end']},{address.network.netmask},{value['lease_minutes']}m
dhcp-option=option:router,{address.ip}
dhcp-option=option:dns-server,{address.ip}
dhcp-authoritative
dhcp-leasefile={self.directory}/leases
pid-file={self.directory}/dnsmasq.pid
user=root
group=root
''')
        if self.management.config:
            with dns.open('a') as f:f.write(f'address=/pirate.home.arpa/{address.ip}\nlocal=/pirate.home.arpa/\n')
        tested=network_command(binary('dnsmasq'),'--test','--conf-file='+str(dns),check=False)
        if tested.returncode:
            self.write('dnsmasq.log',tested.stderr)
            raise self.daemon_error('dnsmasq','configuration rejected')
        # Debug foreground mode skips setgroups, which is prohibited in an
        # unprivileged user namespace. It is restricted to the virtual backend.
        foreground='--no-daemon' if value['backend']=='virtual' else '--keep-in-foreground'
        self.spawn('dnsmasq',[binary('dnsmasq'),foreground,'--conf-file='+str(dns)])
        if value['backend']=='wifi':
            psk=hashlib.pbkdf2_hmac('sha1',value['password'].encode(),value['ssid'].encode(),4096,32).hex()
            security=('wpa_key_mgmt=WPA-PSK\nwpa_psk='+psk+'\nieee80211w=0\n') if value['security']=='wpa2' else 'wpa_key_mgmt=SAE\nieee80211w=2\nsae_require_mfp=1\nsae_password='+value['password']+'\n'
            regulatory='' if value['country']=='00' else f"country_code={value['country']}\nieee80211d=1\n"
            fallback=None
            for attempt,plan in enumerate(candidates):
                self.radio_status={k:v for k,v in plan.items() if k!='directives'}
                self.radio_status['fallback_reason']=fallback
                control_directory=self.new_control()
                host=self.write('hostapd.conf',f"ctrl_interface={control_directory}\nctrl_interface_group={os.getegid()}\ninterface={value['interface']}\ndriver=nl80211\nssid2={value['ssid'].encode().hex()}\n{regulatory}wmm_enabled=1\nauth_algs=1\nwpa=2\nrsn_pairwise=CCMP\nap_isolate=1\n"+security+plan['directives'])
                process=self.spawn('hostapd',[binary('hostapd'),str(host)])
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if self.controls[-1].get('socket_inode') is None:self.capture_control()
                    if process.poll() is not None:
                        error=self.daemon_error('hostapd','startup failed')
                        from .wifi_health import DRIVER_ERRORS,USB_ERRORS
                        observed=self.kernel.poll()
                        if observed['state'] in ('Error','Degraded') or DRIVER_ERRORS.search(str(error)) or USB_ERRORS.search(str(error)):
                            fault=ConnectionError('Adapter firmware/USB communication error; AP startup stopped; '+str(error))
                            fault.operation=getattr(error,'operation',None)
                            raise fault
                        if attempt+1<len(candidates) and re.search(r'(?i)HT|VHT|width|channel|beacon|frequency|hw_mode|configured mode|does not support AP',str(error)) and not re.search(r'(?i)Device or resource busy|\bEBUSY\b|Invalid country code|Operation not permitted|Permission denied|No such device',str(error)):
                            # The failed child is already exited. Reap it and remove
                            # its ownership record without disturbing DHCP/firewall.
                            process.wait(timeout=2)
                            self.processes.remove(process)
                            self.records=[r for r in self.records if r['pid']!=process.pid]
                            self.cleanup_controls()
                            fallback=str(error)
                            self.save()
                            break
                        raise error
                    if re.search(r'(?m)^\S+:\s+AP-ENABLED\s*$',(self.directory/'hostapd.log').read_text()) and self.control.status().get('state')=='ENABLED':break
                    time.sleep(.1)
                else:raise self.daemon_error('hostapd','AP-ENABLED timeout (control STATUS=ENABLED required)')
                if process.poll() is None:break
        time.sleep(.3)
        for name,process in zip(('dnsmasq','hostapd'),self.processes):
            if process.poll() is not None:raise self.daemon_error(name,'startup failed')
        self.starting=False;self.capture_control();self.last_probe=0
        if value['backend']=='wifi':self.events=(self.events+[{'at':time.time(),'event':'AP-ENABLED','source':'startup log + STATUS'}])[-16:]
        self.refresh_health(force=True)
        if self.active['backend']=='wifi' and (self.health.get('control_state')!='ENABLED' or self.health.get('state') in ('Error','Degraded')):
            raise ConnectionError(self.health.get('reason') or 'AP control startup unverified')
        self.last_launch_key=launch_key
        self.management.start(str(address.ip),value['interface'])
        self.failure=None;self.last_action='AWAITING_CONFIRMATION';self.save()

    @serialized
    def confirm(self):
        if not self.pending:return
        self.refresh_health(force=True)
        if not self.healthy():raise ConnectionError('AP driver/control health does not permit confirmation')
        old=(self.saved,self.previous,self.pending,self.last_action,self.saved_radio)
        self.saved=self.active;self.saved_radio=dict(self.radio_status);self.previous=None;self.pending=False;self.last_action='CONFIRMED'
        try:self.save()
        except OSError:
            self.saved,self.previous,self.pending,self.last_action,self.saved_radio=old
            raise

    @serialized
    def rollback(self):
        if not self.pending:return
        prior=self.previous
        if self.reused:
            self.refresh_health(force=True)
            if self.healthy():
                self.active=prior;self.previous=None;self.pending=False;self.reused=False
                self.last_launch_key=json.dumps({k:v for k,v in prior.items() if k!='fingerprint'},sort_keys=True) if prior else None
                self.last_action='ROLLED_BACK_CONTROL_VERIFIED';self.save();return
            self.reused=False  # Restore the prior configuration once; verify real control/driver observations.
        self.stop_processes()
        self.release_address()
        self.active=prior;self.previous=None;self.pending=False
        if prior:
            from .mac import apply
            prior_mac=prior.get('mac_address') or (self.baseline or {}).get('mac')
            if prior_mac:apply(prior['interface'],prior_mac)
            self.set_link_state(prior['interface'],True,rollback=True)
            links=json.loads(network_command('ip','-j','-4','addr','show','dev',prior['interface']).stdout)
            addresses=links[0].get('addr_info',[]) if links else []
            if not any(a['local']+'/'+str(a['prefixlen'])==prior['subnet'] for a in addresses):
                self.owned={'interface':prior['interface'],'address':prior['subnet']};self.save()
                network_command('ip','addr','add',prior['subnet'],'dev',prior['interface'])
            self.launch()
        else:
            self.restore_address();self.radio_status={}
        self.starting=False;self.last_action='ROLLED_BACK_CONTROL_VERIFIED' if prior else 'ROLLED_BACK_RESOURCES_ONLY_NO_PREVIOUS_AP';self.save()

    @serialized
    def stop(self):
        self.stop_processes();self.restore_address();self.active=self.previous=None;self.pending=False
        self.radio_status={};self.failure=None;self.starting=False;self.health={'state':'Ready','control_state':'STOPPED','driver':{'state':'Unknown'},'confirmed_fault':False,'beacons':'UNVERIFIED'};self.last_action='STOPPED_BLOCKED';self.save()
