"""Opt-in Ethernet HTTPS, bounded mDNS publication and public login status."""
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from .admin import atomic_json, command, interfaces, listeners, validate_access
from .management import Management, private_json
from .proxy import ConnectionError

TABLE='pirate_management'
CERTIFICATE_LOCK=threading.RLock()


def ensure_certificate(config,address):
    with CERTIFICATE_LOCK:_ensure_certificate(config,address)


def _ensure_certificate(config,address):
    cert=Path(config['tls_cert'])
    decoded=ssl._ssl._test_decode_cert(str(cert))
    names=decoded.get('subjectAltName',())
    if ('IP Address',address) in names and ('DNS','pirate.local') in names:return
    if not config.get('tls_managed'):raise ConnectionError('TLS certificate does not cover current management address; direct URL disabled')
    dns={v for kind,v in names if kind=='DNS'}|{'pirate.local','pirate.home.arpa'}
    ips={v for kind,v in names if kind=='IP Address'}|{str(ipaddress.IPv4Address(address))}
    # Only installer-issued names/IPs are carried forward. No shell interpolation.
    san=','.join(['DNS:'+name for name in sorted(dns)]+['IP:'+ip for ip in sorted(ips)])
    fd,name=tempfile.mkstemp(prefix='.tls-',dir=cert.parent);os.close(fd)
    try:
        result=subprocess.run(['openssl','req','-x509','-new','-key',config['tls_key'],'-sha256','-days','365',
            '-subj','/CN=pirate.home.arpa','-addext','subjectAltName='+san,
            '-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature,keyEncipherment',
            '-addext','extendedKeyUsage=serverAuth','-out',name],capture_output=True,text=True,timeout=30)
        if result.returncode:raise ConnectionError('Could not extend local TLS certificate; Ethernet HTTPS disabled')
        os.chmod(name,0o600);os.replace(name,cert)
    finally:Path(name).unlink(missing_ok=True)


class EthernetFirewall:
    def __init__(self):self.owner=None;self.snapshot=None

    def existing(self):
        result=command('nft','-j','list','table','inet',TABLE)
        if result.returncode:
            # A failed listing is not proof of absence; the following add is atomic
            # and fails if a table already exists or privileges are unavailable.
            return False
        rows=json.loads(result.stdout)['nftables']
        tables=[row['table'] for row in rows if 'table' in row]
        if len(tables)!=1 or tables[0].get('comment')!='PiRate management '+str(self.owner):
            raise ConnectionError('Management firewall belongs to another owner; Ethernet disabled')
        return True

    def install(self,config):
        self.owner=config['management_owner']
        if not re.fullmatch('[a-f0-9]{32}',self.owner):raise ConnectionError('Invalid management firewall owner')
        present=self.existing()
        net=str(ipaddress.IPv4Network(config['management_subnet']))
        interface=config['management_interface']
        validate_access(config)
        address=str(ipaddress.IPv4Address(config['management_address']))
        if ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(net):raise ConnectionError('Management address outside trusted subnet')
        ap_rule=''
        if config.get('ap_interface') and config.get('subnet'):
            ap=config['ap_interface']
            if not re.fullmatch('[A-Za-z0-9_.-]{1,15}',ap):raise ConnectionError('Invalid AP interface')
            lan=ipaddress.IPv4Interface(config['subnet'])
            ap_rule=f'iifname "{ap}" ip saddr {lan.network} ip daddr {lan.ip} tcp dport 8766 accept'
        script=('delete table inet '+TABLE+'\n' if present else '')+f'''table inet {TABLE} {{
 comment "PiRate management {self.owner}"
 chain input {{
  type filter hook input priority -20; policy accept;
  iifname "{interface}" ip saddr {net} ip daddr {address} tcp dport 8766 accept
  {ap_rule}
  tcp dport 8766 drop
 }}
}}\n'''
        result=subprocess.run(['nft','-f','-'],input=script,capture_output=True,text=True,timeout=5)
        if result.returncode:raise ConnectionError('Management firewall could not be installed; Ethernet disabled')
        current=command('nft','-s','list','table','inet',TABLE)
        if current.returncode:raise ConnectionError('Management firewall could not be verified')
        self.snapshot=current.stdout

    def other_input_clear(self):
        # An accept in our chain cannot override a drop in another base chain.
        # Do not advertise a URL when an unrelated input firewall may block it.
        result=command('nft','-j','list','ruleset')
        if result.returncode:return False
        rows=json.loads(result.stdout)['nftables']
        own={('inet',TABLE),('inet','pirate_gateway')}
        foreign=set()
        for row in rows:
            chain=row.get('chain',{})
            if chain.get('hook')=='input' and chain.get('family')!='ip6' and (chain.get('family'),chain.get('table')) not in own:
                if chain.get('policy','accept')!='accept':return False
                foreign.add((chain.get('family'),chain.get('table'),chain.get('name')))
        return not any((rule.get('family'),rule.get('table'),rule.get('chain')) in foreign for row in rows if (rule:=row.get('rule')))

    def healthy(self):
        current=command('nft','-s','list','table','inet',TABLE)
        return self.snapshot is not None and current.returncode==0 and current.stdout==self.snapshot

    def close(self):
        if self.owner and self.existing():
            result=command('nft','delete','table','inet',TABLE)
            if result.returncode:raise ConnectionError('Management firewall cleanup failed; reserved port stays blocked')
        self.snapshot=None


class MDNS:
    def __init__(self):self.process=None;self.address=None;self.ready=False;self.note='mDNS не объявлен; используется IP/tunnel.'

    def refresh(self,address):
        if self.address!=address:self.stop()
        if not shutil.which('avahi-publish-address') or not shutil.which('avahi-resolve-host-name'):
            self.stop()
            self.note='mDNS недоступен (нет avahi-utils/daemon); используется IP/tunnel.';return False
        resolved=command('avahi-resolve-host-name','-4','pirate.local')
        ips={part for line in resolved.stdout.splitlines() for part in line.split() if part==address}
        if resolved.returncode==0 and not ips:
            self.stop();self.note='mDNS: конфликт pirate.local; имя не используется.';return False
        if self.process is None:
            try:self.process=subprocess.Popen(['avahi-publish-address','--no-reverse','pirate.local',address],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            except OSError:
                self.ready=False;self.note='mDNS publisher unavailable; используется IP.';return False
            self.address=address
        if self.process.poll() is not None:
            self.stop();self.note='mDNS: публикация не подтверждена/конфликт имени; используется IP.';return False
        self.ready=resolved.returncode==0 and bool(ips)
        self.note='mDNS pirate.local объявлен и разрешается локальным Avahi.' if self.ready else 'mDNS: ожидается подтверждение; используется IP.'
        return self.ready

    def stop(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=2)
        self.process=None;self.address=None;self.ready=False


class ManagementAccess:
    def __init__(self,app,loopback,config_path,status_path='/run/pirate/status.json'):
        self.app=app;self.loopback=loopback;self.config_path=config_path;self.path=Path(status_path)
        self.stop_event=threading.Event();self.thread=None
        self.ethernet=Management(app);self.firewall=EthernetFirewall();self.mdns=MDNS();self.identity=None;self.firewall_scope=None
        self.path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        stat=self.path.parent.stat()
        if self.path.parent.is_symlink() or stat.st_uid!=os.geteuid() or stat.st_mode&0o022:
            raise ConnectionError('Runtime status directory must be owned by runtime user and not writable by others')

    def start(self):
        self.tick()
        self.thread=threading.Thread(target=self.watch,daemon=True);self.thread.start()

    def watch(self):
        while not self.stop_event.wait(2):self.tick()

    def close_ethernet(self):
        self.mdns.stop();self.ethernet.stop();self.identity=None;self.firewall_scope=None
        self.firewall.close()

    def cached_ap_ready(self):
        health=getattr(self.app.ap,'health',{})
        return isinstance(health,dict) and health.get('control_state')=='ENABLED' and health.get('state') not in ('Error','Degraded','Starting') and time.monotonic()-getattr(self.app.ap,'last_probe',0)<15 and self.app.ap.process_alive()

    def tick(self):
        notes=[];remote=[]
        try:
            config=validate_access(private_json(self.config_path))
            # Explicit tunnel origins apply only to the loopback listener.
            self.loopback.management={'authorities':['127.0.0.1:'+str(port) for port in dict.fromkeys([self.loopback.server_address[1],*config.get('tunnel_ports',[8765])])],'scheme':'http'}
            self.ethernet.config=config
            self.ethernet.auth.refresh()
            if config.get('management_interface') and not self.ethernet.auth.bootstrap_only:
                interface=config['management_interface'];net=ipaddress.IPv4Network(config['management_subnet'])
                if self.app.router.blocked_config and interface in [self.app.router.blocked_config.get('lan_interface'),*self.app.router.blocked_config.get('protected_lans',[])]:
                    raise ConnectionError('Management Ethernet is already protected as router LAN; use another management interface or tunnel')
                # Ethernet only; never automatically classify the WAN as trusted.
                link=Path('/sys/class/net')/interface
                if (link/'type').read_text().strip()!='1' or (link/'wireless').exists() or (link/'phy80211').exists():
                    raise ConnectionError('Selected management interface is not Ethernet')
                addresses=sorted(a['local'] for item in interfaces() if item['ifname']==interface for a in item.get('addr_info',[]) if a.get('family')=='inet' and ipaddress.IPv4Address(a['local']) in net and not a.get('tentative'))
                if not addresses:raise ConnectionError('No IPv4 in selected trusted subnet; Ethernet HTTPS disabled')
                pinned=config.get('management_address')
                if pinned and pinned not in addresses:raise ConnectionError('Configured management IPv4 is not assigned; trusted LAN HTTPS disabled, loopback remains available')
                address=pinned or addresses[0];runtime_config=dict(config,management_address=address);identity=(interface,address,str(net),config['management_owner'])
                active=dict(self.app.ap.active or {})
                if active:runtime_config.update(ap_interface=active['interface'],subnet=active['subnet'])
                ap_scope=(runtime_config.get('ap_interface'),runtime_config.get('subnet'))
                if self.identity!=identity or not self.firewall.healthy() or self.ethernet.server is None:
                    self.close_ethernet()
                    if (address,8766) in listeners() or any((a,8766) in listeners() for a in ('0.0.0.0','*','::')):raise ConnectionError('TCP 8766 is already in use on management IP; Ethernet disabled')
                    if not self.firewall.other_input_clear():raise ConnectionError('Unrelated input firewall prevents confirming Ethernet access; use SSH tunnel')
                    self.firewall.install(runtime_config)
                    ensure_certificate(config,address)
                    if self.stop_event.is_set():raise ConnectionError('Management stopping')
                    self.ethernet.start(address,interface,port=8766,subnet=str(net),names=['pirate.local'])
                    self.identity=identity;self.firewall_scope=ap_scope
                elif self.firewall_scope!=ap_scope:
                    # AP address/interface changes update its scoped exception
                    # atomically, without restarting the trusted Ethernet listener.
                    self.firewall.install(runtime_config);self.firewall_scope=ap_scope
                if not self.firewall.healthy() or not self.firewall.other_input_clear():raise ConnectionError('Input firewall changed; Ethernet access not confirmed, use SSH tunnel')
                published=self.mdns.refresh(address)
                remote.append({'address':address,'port':8766,'scheme':'https','scope':str(net),'mdns':published})
                notes.append(self.mdns.note)
            else:
                self.close_ethernet()
                notes.append('Ethernet: tunnel-only.' if not config.get('management_interface') else 'Ethernet/AP WebUI disabled: empty admin password.')
            # AP Apply/Rollback owns app.lock. Never bind a second listener
            # while launch is still preparing the same AP address.
            if self.app.lock.acquire(blocking=False):
                try:
                    ap=self.app.ap.management
                    ap.config=config
                    ap.auth.refresh()
                    if ap.auth.bootstrap_only:ap.stop()
                    elif ap.server is None and self.app.ap.active and not self.app.ap.pending and self.cached_ap_ready():
                        active=self.app.ap.active
                        ap.start(str(ipaddress.IPv4Interface(active['subnet']).ip),active['interface'])
                    if ap.server and ap.server.socket.fileno()>=0:
                        address,port=ap.server.server_address
                        remote.append({'address':address,'port':port,'scheme':'https','scope':'AP','mdns':False})
                finally:self.app.lock.release()
        except Exception as exc:
            try:self.close_ethernet()
            except Exception:pass
            notes.append('Ethernet management unavailable: '+str(exc))
        verified=[]
        for listener in remote:
            server=self.app.ap.management.server if listener['scope']=='AP' else self.ethernet.server
            fingerprint=getattr(server,'tls_sha256',None)
            if isinstance(fingerprint,str) and re.fullmatch('[a-f0-9]{64}',fingerprint):
                listener['tls_sha256']=fingerprint;verified.append(listener)
        remote=verified
        # Private runtime state is never copied to the public banner file.
        ap_state=lan=connection='CHANGING';wifi={};control_directory=None
        if self.app.lock.acquire(blocking=False):
            try:
                if self.app.ap.active:
                    ok=self.cached_ap_ready()
                    health=getattr(self.app.ap,'health',{})
                    if not isinstance(health,dict):health={}
                    ap_state='UNKNOWN' if health.get('state')=='Unknown' else 'STARTING' if health.get('state')=='Starting' else 'ON' if ok else 'ERROR'
                    wifi={k:health.get(k) for k in ('state','hostapd_process','control_state','interface','control_station_count','beacons','reason')}
                    wifi['driver']=(health.get('driver') or {}).get('state','Unknown')
                    control=getattr(self.app.ap,'control',None)
                    if control:control_directory=str(control.directory)
                else:
                    failure=getattr(self.app.ap,'failure',None)
                    if isinstance(failure,dict):wifi={'reason':failure.get('message')}
                    ap_state='UNSUPPORTED' if isinstance(failure,dict) and failure.get('code')=='ap_unsupported' else 'ERROR' if failure else 'OFF'
                current=self.app.current if hasattr(self.app,'current') else None
                kind=current.profile.get('type') if current else None
                connection='Direct' if kind=='direct' else 'VPN' if kind in ('wireguard','openvpn') else 'Proxy' if kind in ('http','socks5') else 'Off'
                lan='ACTIVE' if self.app.router.current and self.app.router.policy_active else 'BLOCKED' if self.app.router.blocked_config else 'NOT CONFIGURED'
            finally:self.app.lock.release()
        if self.loopback.socket.fileno()>=0:
            remote.insert(0,{'address':self.loopback.server_address[0],'port':self.loopback.server_address[1],'scheme':'http','scope':'loopback',
                'tunnel_ports':[int(host.rsplit(':',1)[1]) for host in self.loopback.management['authorities']]})
        if self.stop_event.is_set():return
        dns_observation=getattr(self.app.router,'dns_observation',{})
        dns_observation=dict(dns_observation) if isinstance(dns_observation,dict) else {}
        dns_observation['enabled']=getattr(self.app.router,'policy_active',False) is True and getattr(self.app.router,'dns_selected',None) is not None
        tcp=getattr(self.app.router,'dns_tcp',None)
        address=getattr(tcp,'server_address',None)
        if isinstance(address,tuple) and len(address)==2:dns_observation['listener_port']=address[1]
        current=getattr(self.app.router,'current',None)
        policy=getattr(current,'policy',None)
        if isinstance(getattr(policy,'last_result',None),str):
            dns_observation.update(upstream_result=policy.last_result,upstream_checked_at=getattr(policy,'checked_at',None))
        try:
            atomic_json(self.path,{'dns':dns_observation,'updated_at':time.time(),'pid':os.getpid(),'process_birth':Path('/proc/self/stat').read_text().split()[21],
                'wifi_health':wifi,'wifi_control_directory':control_directory,'listeners':remote,'ap':ap_state,'connection':connection,'lan':lan,'notes':notes},0o644)
        except OSError:pass  # A missing status is safer than invented URLs.

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=45)
        self.close_ethernet();self.path.unlink(missing_ok=True)
