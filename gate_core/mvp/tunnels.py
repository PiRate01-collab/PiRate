"""OpenVPN/WireGuard in private namespaces; explicit native mode on a test Pi."""
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from gate_core.core import ProfileError
from gate_core.openvpn_config import validate_openvpn, ConfigurationError
from .proxy import ProxyBackend, ConnectionError, socks_connect

REPO = Path(__file__).resolve().parents[2]

def same_native_identity(first, second):
    """Parallel sessions must not evict the retained rollback session."""
    if first['type']!=second['type']:return False
    if first['type']=='wireguard':
        return bool(first.get('wg_private_key') and
                    first.get('wg_private_key')==second.get('wg_private_key') and
                    first.get('wg_peer_key')==second.get('wg_peer_key'))
    if first['type']=='openvpn':
        if (first.get('server'),first.get('port'))!=(second.get('server'),second.get('port')):return False
        def certificate(profile):
            match=re.search(r'<cert>\s*(.*?)\s*</cert>',profile.get('config',''),re.S)
            return ''.join(match[1].split()) if match else None
        cert=certificate(first)
        return bool(cert and cert==certificate(second) or
                    first.get('username') and first.get('username')==second.get('username') or
                    first.get('config') and first.get('config')==second.get('config'))
    return False

def native_allowed():
    if os.environ.get('PIRATE_NATIVE_TUNNELS')!='1':
        raise ConnectionError('VPN NOT TESTED: enable --native-vpn with CAP_NET_ADMIN in an isolated network namespace')
    from .router import permitted
    permitted()

def run(*args, check=True, input=None):
    try:
        result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=15)
    except (OSError,subprocess.TimeoutExpired):
        raise ConnectionError('Required network tool unavailable or timed out') from None
    if check and result.returncode:
        raise ConnectionError('Network backend step failed: '+args[0]+' '+args[1])
    return result

def normalize_openvpn(content,endpoint,port,remote_index=None,protocol_override='',server_name='',allow_imported_ca=False):
    """Allow a strict self-contained client subset; never execute imported hooks.

    Validate before replacing remote; reject all unknown directives and paths.
    DNS and full tunnel routes are managed by PiRate, not imported scripts/pushes.
    """
    from .openvpn_import import check_text, select_remote, MAX_CONFIG
    try:
        check_text(content)
        from .openvpn_compat import compile_options
        content,_=compile_options(content)
        if server_name:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',server_name):raise ProfileError('Invalid expected server certificate name')
            from .openvpn_import import inspect_config
            names=[d['args'] for d in inspect_config(content)['directives'] if d['key']=='verify-x509-name']
            if names and any(n != [server_name,'name'] for n in names):raise ProfileError('Expected server certificate name conflicts with imported verification; original pin retained')
            if not names:content+='\nverify-x509-name '+server_name+' name\n'
        if remote_index is not None:content=select_remote(content,remote_index,protocol_override)
    except ProfileError as exc:
        error=ConnectionError(str(exc));error.category=getattr(exc,'category','unsupported_feature');error.line=getattr(exc,'line',None)
        raise error from None
    from .openvpn_import import inspect_config
    parsed=inspect_config(content);by_line={d['line']:d for d in parsed['directives']}
    block_lines=set()
    for block in parsed['blocks']:
        if block['kind'] not in {'ca','cert','key','tls-auth','tls-crypt'}:
            error=ConnectionError(f"OpenVPN original line {block['start']+1}: unsupported inline block");error.category='unsupported_feature'
            raise error
        block_lines.update(range(block['start'],block['end']+1))
    output=[];auth=False;protocol=None;remote=None
    for number,line in enumerate(parsed['lines']):
        line=line.rstrip('\r\n')
        if number in block_lines:
            output.append(line);continue
        d=by_line.get(number)
        if d is None:output.append(line);continue
        directive=d['key'];parts=[directive,*d['args']]
        if directive=='auth-user-pass':
            if len(parts)!=1 or auth:raise ConnectionError('OpenVPN credentials must be supplied in profile, without file paths')
            auth=True;output.append('');continue
        if directive=='remote':
            if remote is not None or len(parts) not in (2,3,4):raise ConnectionError('OpenVPN requires exactly one endpoint')
            remote=parts;output.append('');continue
        if directive=='proto':
            if protocol is not None or len(parts)!=2:raise ConnectionError('OpenVPN invalid transport')
            protocol={'tcp':'tcp-client','udp4':'udp','tcp4-client':'tcp-client'}.get(parts[1],parts[1]);output.append('');continue
        if directive=='dhcp-option':
            if len(parts)!=3 or parts[1]!='DNS':raise ConnectionError('OpenVPN supports only explicit DNS options')
            try:ipaddress.IPv4Address(parts[2])
            except ValueError:raise ConnectionError('OpenVPN requires IPv4 DNS') from None
            output.append('');continue
        if directive in ('verb','mute','resolv-retry'):
            if len(parts)!=2 or not (parts[1].isdigit() or directive=='resolv-retry' and parts[1]=='infinite'):
                raise ConnectionError('OpenVPN invalid client option')
            output.append('');continue
        if directive=='redirect-gateway':
            if any(value not in ('def1','bypass-dhcp') for value in parts[1:]):raise ConnectionError('OpenVPN unsupported route policy')
            output.append('');continue
        if directive in ('pull','explicit-exit-notify'):
            if directive=='pull' and len(parts)!=1 or directive=='explicit-exit-notify' and (len(parts)>2 or len(parts)==2 and not parts[1].isdigit()):raise ConnectionError('OpenVPN invalid client option')
            output.append('');continue
        output.append(line)
    protocol=protocol or 'udp'
    if protocol not in ('udp','tcp-client') or remote is None:raise ConnectionError('OpenVPN requires UDP/TCP IPv4 endpoint')
    if len(remote)==4 and {'tcp':'tcp-client','udp4':'udp','tcp4-client':'tcp-client'}.get(remote[3],remote[3])!=protocol:
        raise ConnectionError('OpenVPN conflicting transport')
    if len(remote)>=3 and (not remote[2].isdigit() or not 1<=int(remote[2])<=65535):raise ConnectionError('OpenVPN invalid remote port')
    try:ipaddress.IPv4Address(endpoint)
    except ValueError:raise ConnectionError('VPN endpoint resolution requires IPv4') from None
    normalized='\n'.join(output)+f'\nproto {protocol}\nremote {endpoint} {port} {protocol}\n'
    try:validated=validate_openvpn(normalized,max_bytes=MAX_CONFIG,compatible=True,allow_imported_ca=allow_imported_ca)
    except ConfigurationError as exc:
        error=ConnectionError('OpenVPN import (original config): '+str(exc));error.category=getattr(exc,'category','local_security_policy')
        raise error from None
    if validated.file_references:raise ConnectionError('OpenVPN requires inline certificates/keys')
    return normalized,protocol,auth

def resource_for(token, wan):
    if not re.fullmatch('[a-f0-9]{10}',token) or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',wan):
        raise ConnectionError('Invalid native resource identity')
    index=int(token[:3],16)
    network=ipaddress.ip_network(f'198.18.{index//64}.{(index%64)*4}/30')
    return {'token':token,'namespace':'pr-'+token,'veth':'pv'+token,'wan':wan,
            'network':str(network),'host':str(network[1]),'guest':str(network[2])}

def routing_id(resource):
    # Separate route table/mark per generation: nft switches the mark atomically.
    return 0x50000000 + int(resource['token'][:7],16)


def host_rules(resource, endpoint, port, protocol, lan_interface=None, lan_subnets=()):
    r=resource; transport='tcp' if protocol.startswith('tcp') else 'udp'
    if lan_interface is not None and (not re.fullmatch('[A-Za-z0-9_.-]{1,15}',lan_interface) or lan_interface==r['wan']):raise ConnectionError('Invalid PMTU LAN interface')
    pmtu='\n  '.join('iifname "'+r['veth']+'" oifname "'+lan_interface+'" ip daddr '+str(ipaddress.IPv4Network(net))+' ct state related meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } counter accept' for net in lan_subnets) if lan_interface else ''
    return f'''table inet pn_{r['token']} {{
 chain guard {{ type filter hook forward priority -20; policy accept;
  iifname "{r['veth']}" meta nfproto ipv6 drop
  iifname "{r['veth']}" oifname "{r['wan']}" ip daddr {endpoint} {transport} dport {port} accept
  iifname "{r['veth']}" oifname "{r['wan']}" drop
  {pmtu}
  iifname "{r['veth']}" ip saddr {r['network']} drop
 }}
 chain transport_nat {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr {r['network']} oifname "{r['wan']}" ip daddr {endpoint} {transport} dport {port} masquerade
 }}
}}
'''


def tunnel_rules(interface, endpoint, port, protocol, mtu=None, lan_subnets=()):
    transport='tcp' if protocol.startswith('tcp') else 'udp'
    pmtu='\n '.join('oifname "eth0" ip daddr '+str(ipaddress.IPv4Network(net))+' ct state related meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } counter accept' for net in lan_subnets)
    clamp=''
    if mtu is not None:
        if type(mtu) is not int or not 576<=mtu<=9000:raise ConnectionError('Invalid observed tunnel MTU')
        mss=mtu-40
        clamp=f'''chain client_mss {{ type filter hook forward priority mangle; policy accept;
 iifname "eth0" oifname "{interface}" meta nfproto ipv4 tcp flags & (syn | rst) == syn tcp option maxseg size > {mss} counter tcp option maxseg size set {mss}
 iifname "{interface}" oifname "eth0" meta nfproto ipv4 tcp flags & (syn | rst) == syn tcp option maxseg size > {mss} counter tcp option maxseg size set {mss}
 }}'''
    return f'''table inet pirate_tunnel {{
 {clamp}
 chain output {{ type filter hook output priority -20; policy drop;
  oifname "lo" accept
  {pmtu}
  meta nfproto ipv4 oifname "{interface}" accept
  oifname "eth0" ip daddr {endpoint} {transport} dport {port} accept
 }}
 chain forward {{ type filter hook forward priority -20; policy drop;
  iifname "eth0" oifname "{interface}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} accept
  iifname "{interface}" oifname "eth0" meta nfproto ipv4 ct state established,related accept
 }}
 chain nat {{ type nat hook postrouting priority srcnat; policy accept;
  oifname "{interface}" meta nfproto ipv4 masquerade
 }}
}}
'''

def cleanup(resource, directory):
    expected=resource_for(resource['token'],resource['wan'])
    if resource!=expected:raise ConnectionError('Unexpected native recovery state; resources retained')
    ns=resource['namespace']
    ppp_session=(Path(directory)/ns/'ppp').exists()
    # Kill only processes in this exact recorded owned namespace.
    for raw in run('ip','netns','pids',ns,check=False).stdout.split():
        try:os.kill(int(raw),signal.SIGTERM)
        except ProcessLookupError:pass
    if ppp_session:
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            pids=run('ip','netns','pids',ns,check=False).stdout.split()
            if not pids:break
            time.sleep(.1)
        else:
            for raw in pids:
                try:os.kill(int(raw),signal.SIGKILL)
                except ProcessLookupError:pass
    route_id=str(routing_id(resource))
    run('ip','-4','rule','del','priority','10500','fwmark',route_id,'table',route_id,check=False)
    run('ip','-4','route','flush','table',route_id,check=False)
    run('/usr/sbin/nft','delete','table','inet','pn_'+resource['token'],check=False)
    run('ip','netns','delete',ns,check=False)
    run('ip','link','delete',resource['veth'],check=False)
    resolver=Path('/etc/netns')/ns/'resolv.conf'
    resolver.unlink(missing_ok=True)
    if resolver.parent.exists():resolver.parent.rmdir()
    folder=Path(directory)/ns
    if folder.exists():
        if (folder/'ppp').exists():
            from .legacy_cleanup import remove_files
            remove_files(folder)
        for name in ('bridge.sock','vpn.conf','auth.txt','vpn.log'):
            (folder/name).unlink(missing_ok=True)
        folder.rmdir()

def recover_namespaces(resources, directory):
    pending=Path(directory)/'native-pending.json'
    if pending.exists():
        resources=resources+json.loads(pending.read_text()).get('native_resources',[])
    if resources:
        native_allowed()
        seen=set()
        for resource in resources:
            if resource['token'] not in seen:
                cleanup(resource,directory);seen.add(resource['token'])
    pending.unlink(missing_ok=True)

class TunnelBackend(ProxyBackend):
    scope='TUNNEL_NAMESPACE'
    def __init__(self,profile,directory,wan=None):
        if profile.get('type') not in ('openvpn','wireguard'):raise ConnectionError('Unsupported connection type')
        native_allowed()
        super().__init__(profile)
        self.kind='native'
        self.directory=Path(directory)
        wan=wan or os.environ.get('PIRATE_WAN_INTERFACE','')
        if not wan:
            routes=json.loads(run('ip','-j','-4','route','show','default').stdout)
            if len(routes)!=1:raise ConnectionError('Set PIRATE_WAN_INTERFACE to an unambiguous uplink')
            wan=routes[0]['dev']
        self.resource=resource_for(uuid.uuid4().hex[:10],wan)
        self.folder=self.directory/self.resource['namespace']
        self.process=None
        self.bridge=None
        self.created=False
        self.gateway_ready=False
        self.events=[];self.lan_interface=None;self.lan_networks=[];self.tunnel_mtu=None;self.transport_protocol=None

    @property
    def interface(self):
        return {'wireguard':'wg0','openvpn':'tun0'}[self.profile['type']]

    def ns(self,*args,**kwargs):
        return run('ip','netns','exec',self.resource['namespace'],*args,**kwargs)

    def write(self,name,content):
        with (self.folder/name).open('x') as f:
            os.chmod(f.name,0o600);f.write(content);f.flush();os.fsync(f.fileno())

    def endpoint(self):
        try:return socket.getaddrinfo(self.profile['server'],self.profile['port'],socket.AF_INET,socket.SOCK_DGRAM)[0][4][0]
        except OSError:raise ConnectionError('VPN endpoint DNS failed; host bootstrap resolution required') from None

    def openvpn_config(self,endpoint):
        from .profile_v1 import profile_ca_identity
        normalized,protocol,auth=normalize_openvpn(self.profile.get('config',''),endpoint,self.profile['port'],
                                                     self.profile.get('ovpn_remote',0),self.profile.get('ovpn_proto',''),self.profile.get('ovpn_server_name',''),profile_ca_identity(self.profile))
        if auth:
            if not self.profile.get('username') or not self.profile.get('password'):raise ConnectionError('OpenVPN requires explicit username/password in dedicated fields')
            self.write('auth.txt',self.profile['username']+'\n'+self.profile.get('password','')+'\n')
            normalized+='auth-user-pass '+str(self.folder/'auth.txt')+'\n'
        return normalized,protocol

    def start(self):
        p=self.profile;r=self.resource
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()!='1':
            raise ConnectionError('Native tunnels require existing IPv4 forwarding; PiRate does not change this host setting')
        os.environ['PATH']=os.environ.get('PATH','')+':/usr/sbin:/sbin'
        for binary in ('ip','/usr/sbin/nft', {'openvpn':'openvpn','wireguard':'wg'}[p['type']]):
            if not shutil.which(binary):raise ConnectionError('Missing backend binary: '+binary+'; VPN NOT TESTED')
        from .dns_auto import candidates
        initial_dns=candidates(p)
        if not p['server'] or not p['port']:raise ConnectionError('Set VPN endpoint and port')
        endpoint=self.endpoint();self.endpoint_ip=endpoint
        selected=json.loads(run('ip','-j','-4','route','get',endpoint).stdout)
        if not selected or selected[0].get('dev')!=r['wan']:raise ConnectionError('VPN endpoint does not route through selected WAN')
        identifier=str(routing_id(r))
        if run('ip','-4','route','show','table',identifier,check=False).stdout.strip():raise ConnectionError('VPN routing identity already occupied')
        if any(rule.get('table')==int(identifier) for rule in json.loads(run('ip','-j','-4','rule','show').stdout)):raise ConnectionError('VPN routing identity already occupied')
        if Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text().strip()=='1':raise ConnectionError('VPN namespace gateway requires non-strict host rp_filter; host setting left unchanged')
        self.folder.mkdir(mode=0o700)
        if p['type']=='openvpn':configuration,protocol=self.openvpn_config(endpoint)
        else:
            protocol='udp'
            if not p['wg_private_key'] or not p['wg_peer_key'] or not p['wg_address']:raise ConnectionError('WireGuard needs private key, peer key and interface address')
            if '0.0.0.0/0' not in p['wg_allowed_ips']:raise ConnectionError('MVP WireGuard requires full IPv4 AllowedIPs 0.0.0.0/0')
            if any(ipaddress.ip_interface(a).version!=4 for a in p['wg_address']):raise ConnectionError('IPv6 WireGuard addressing is not supported by MVP')
            configuration='[Interface]\nPrivateKey = '+p['wg_private_key']+'\n[Peer]\nPublicKey = '+p['wg_peer_key']+'\n'
            if p['wg_preshared_key']:configuration+='PresharedKey = '+p['wg_preshared_key']+'\n'
            configuration+=f'Endpoint = {endpoint}:{p["port"]}\nAllowedIPs = '+','.join(p['wg_allowed_ips'])+f'\nPersistentKeepalive = {p.get("wg_keepalive",25)}\n'
        self.transport_protocol=protocol
        self.write('vpn.conf',configuration)
        existing=json.loads(run('ip','-j','route','show').stdout)
        for route in existing:
            dest=route.get('dst','default')
            if dest!='default' and ipaddress.ip_network(dest,strict=False).overlaps(ipaddress.ip_network(r['network'])):
                raise ConnectionError('Namespace transport subnet conflicts with existing route')
        run('ip','netns','add',r['namespace']);self.created=True
        run('ip','link','add',r['veth'],'type','veth','peer','name','eth0','netns',r['namespace'])
        run('ip','addr','add',r['host']+'/30','dev',r['veth']);run('ip','link','set',r['veth'],'up')
        self.ns('ip','addr','add',r['guest']+'/30','dev','eth0');self.ns('ip','link','set','eth0','up');self.ns('ip','link','set','lo','up')
        run('/usr/sbin/sysctl','-q','-w','net.ipv4.conf.'+r['veth']+'.rp_filter=0')
        self.ns('ip','route','add',endpoint+'/32','via',r['host']);self.ns('ip','route','add','default','via',r['host'])
        interface=self.interface
        self.ns('/usr/sbin/nft','-f','-',input=tunnel_rules(interface,endpoint,p['port'],protocol))
        self.ns('/usr/sbin/sysctl','-q','-w','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.eth0.rp_filter=0','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1')
        run('/usr/sbin/nft','-f','-',input=host_rules(r,endpoint,p['port'],protocol))
        self.events.append({'event':'TRANSPORT_FILTER_INSTALLED','at':time.time()})
        dnsdir=Path('/etc/netns')/r['namespace'];dnsdir.mkdir(parents=True,mode=0o700)
        (dnsdir/'resolv.conf').write_text(''.join('nameserver '+ip+'\n' for ip in initial_dns))
        if p['type']=='wireguard':
            self.ns('ip','link','add','wg0','type','wireguard');self.ns('wg','setconf','wg0',str(self.folder/'vpn.conf'))
            for address in p['wg_address']:self.ns('ip','addr','add',address,'dev','wg0')
            self.ns('ip','link','set','wg0','mtu',str(p.get('wg_mtu',1420)),'up');self.ns('ip','route','replace','default','dev','wg0')
        else:
            if not Path('/dev/net/tun').exists():raise ConnectionError('OpenVPN TUN device unavailable; NOT TESTED')
            log=(self.folder/'vpn.log').open('xb');os.chmod(log.name,0o600)
            self.process=subprocess.Popen(['ip','netns','exec',r['namespace'],'openvpn','--config',str(self.folder/'vpn.conf'), '--dev','tun0','--script-security','1','--route-nopull','--auth-nocache','--verb','3','--pull-filter','ignore','redirect-gateway','--pull-filter','ignore','route','--pull-filter','ignore','dhcp-option'],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
            log.close()
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                if self.process.poll() is not None:
                    from .diagnostics import tail
                    error=ConnectionError(openvpn_failure(tail(self.folder/'vpn.log',32768)));error.category='runtime_failure'
                    raise error
                if 'Initialization Sequence Completed' in (self.folder/'vpn.log').read_text(errors='replace'):break
                time.sleep(.25)
            else:
                from .diagnostics import tail
                error=ConnectionError(openvpn_failure(tail(self.folder/'vpn.log',32768),timed_out=True));error.category='runtime_failure'
                raise error
        if p['type']=='openvpn':self.ns('ip','route','replace','default','dev',interface)
        observed=json.loads(self.ns('ip','-j','link','show','dev',interface).stdout)
        if not observed or type(observed[0].get('mtu')) is not int:raise ConnectionError('Tunnel MTU unavailable; client forwarding not prepared')
        self.tunnel_mtu=observed[0]['mtu']
        self.refresh_packet_policy()
        self.events.append({'event':'TUNNEL_INTERFACE_UP','at':time.time()})
        env=dict(os.environ,PYTHONPATH=str(REPO))
        self.bridge=subprocess.Popen(['ip','netns','exec',r['namespace'],sys.executable,'-m','gate_core.mvp.bridge',str(self.folder/'bridge.sock')],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+5
        while not (self.folder/'bridge.sock').exists():
            if self.bridge.poll() is not None or time.monotonic()>deadline:raise ConnectionError('Tunnel bridge failed to start')
            time.sleep(.05)

    def set_resolver(self,resolver):
        resolver=str(ipaddress.IPv4Address(resolver))
        (Path('/etc/netns')/self.resource['namespace']/'resolv.conf').write_text('nameserver '+resolver+'\n')

    def refresh_packet_policy(self):
        interface=self.interface
        script='delete table inet pirate_tunnel\n'+tunnel_rules(interface,self.endpoint_ip,self.profile['port'],self.transport_protocol,self.tunnel_mtu,self.lan_networks)
        self.ns('/usr/sbin/nft','-f','-',input=script)
        guard='delete table inet pn_'+self.resource['token']+'\n'+host_rules(self.resource,self.endpoint_ip,self.profile['port'],self.transport_protocol,getattr(self,'lan_interface',None),self.lan_networks)
        run('/usr/sbin/nft','-f','-',input=guard)

    def prepare_gateway(self,config):
        r=self.resource;identifier=str(routing_id(r))
        if config['wan_interface']!=r['wan']:raise ConnectionError('VPN uplink differs from selected WAN')
        # Pin return routes for all directly attached LAN subnets before tunnel default.
        addresses=json.loads(run('ip','-j','-4','addr','show','dev',config['lan_interface']).stdout)
        if not addresses:raise ConnectionError('LAN interface disappeared before VPN routing')
        networks=[]
        for info in addresses[0]['addr_info']:
            if info['family']=='inet':
                subnet=str(ipaddress.ip_network(info['local']+'/'+str(info['prefixlen']),strict=False))
                networks.append(subnet)
                self.ns('ip','route','replace',subnet,'via',r['host'],'dev','eth0')
        if not networks:raise ConnectionError('No IPv4 LAN return route for native VPN')
        self.lan_interface=config['lan_interface'];self.lan_networks=sorted(set(networks));self.refresh_packet_policy()
        if self.gateway_ready:
            for subnet in self.lan_networks:run('ip','-4','route','replace',subnet,'dev',config['lan_interface'],'table',identifier)
            return
        existing=json.loads(run('ip','-j','-4','rule','show').stdout)
        if any(rule.get('table')==int(identifier) or rule.get('fwmark')==hex(int(identifier)) for rule in existing):
            raise ConnectionError('VPN policy routing identity conflict')
        if run('ip','-4','route','show','table',identifier,check=False).stdout.strip():raise ConnectionError('VPN routing table already occupied')
        for subnet in self.lan_networks:run('ip','-4','route','add',subnet,'dev',config['lan_interface'],'table',identifier)
        run('ip','-4','route','add','default','via',r['guest'],'dev',r['veth'],'table',identifier)
        # Missing veth route cannot fall through to the host WAN route.
        run('ip','-4','route','add','unreachable','default','metric','32767','table',identifier)
        run('ip','-4','rule','add','priority','10500','fwmark',identifier,'table',identifier)
        self.gateway_ready=True
        self.events.append({'event':'LAN_ROUTES_PREPARED','at':time.time()})

    def open(self,host,port):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(8)
        try:
            sock.connect(str(self.folder/'bridge.sock'))
            return self.track(socks_connect(sock,host,port))
        except Exception:sock.close();raise

    def observed(self):
        alive=bool(self.bridge and self.bridge.poll() is None and (self.process is None or self.process.poll() is None))
        result={'backend':self.profile['type'],'namespace':self.resource['namespace'],'scope':self.scope,'alive':alive,'test_status':getattr(self,'last_check',{'status':'NOT TESTED'})['status'] if alive else 'FAIL'}
        result['logs']=self.events[-20:]
        if alive:
            link_result=self.ns('ip','-j','link','show','dev',self.interface,check=False)
            try:interfaces=json.loads(link_result.stdout) if link_result.stdout.strip() else []
            except ValueError:interfaces=None
            result['interface_active']=None if link_result.returncode or interfaces is None else bool(interfaces and 'UP' in interfaces[0]['flags'])
            result['alive']=result['interface_active']
            route_result=self.ns('ip','-j','route','show',check=False)
            result['routes']=route_result.stdout
            try:routes=json.loads(route_result.stdout)
            except ValueError:routes=[]
            interface=self.interface
            result['tunnel_routing']='AVAILABLE' if route_result.returncode==0 and any(row.get('dst')=='default' and row.get('dev')==interface for row in routes) else 'UNAVAILABLE' if route_result.returncode==0 else 'UNKNOWN'
            result['alive']=bool(result['alive'] and result['tunnel_routing']=='AVAILABLE')
            result['host_policy_prepared']=self.gateway_ready
            result['mtu']=interfaces[0].get('mtu') if interfaces else None
            result['mss_clamp_mtu']=getattr(self,'tunnel_mtu',None)
            if self.profile['type']=='wireguard':
                handshake=self.ns('wg','show','wg0','latest-handshakes',check=False)
                values=handshake.stdout.split()
                stamps=[int(values[i]) for i in range(1,len(values),2) if values[i].isdigit()]
                result['handshake_age_seconds']=int(time.time()-max(stamps)) if stamps and max(stamps)>0 else None
                result['handshake']='UNKNOWN' if handshake.returncode else 'VALID' if result['handshake_age_seconds'] is not None and 0<=result['handshake_age_seconds']<180 else 'MISSING_OR_STALE'
                result['alive']=result['alive'] and result['handshake']=='VALID'
        result.setdefault('interface_active',False if not alive else None)
        result.setdefault('tunnel_routing','UNKNOWN')
        result.setdefault('handshake','UNKNOWN' if self.profile['type']=='wireguard' else 'NOT_APPLICABLE')
        result['client_connectivity']={'status':'UNVERIFIED','reason':'Tunnel-originated checks do not test LAN clients'}
        return result

    def stop(self):
        super().stop()
        if self.created:cleanup(self.resource,self.directory)
        elif self.folder.exists():
            if (self.folder/'ppp').exists():
                from .legacy_cleanup import remove_files
                remove_files(self.folder)
            for name in ('vpn.conf','auth.txt','vpn.log'):(self.folder/name).unlink(missing_ok=True)
            self.folder.rmdir()
        for process in (self.bridge,self.process):
            if process:
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)


def openvpn_failure(log, timed_out=False):
    """One cause from real private backend output; never return raw log/secrets."""
    text=log.lower()
    if 'auth_failed' in text:return 'VPN-сервер отклонил логин или пароль. Проверь данные подключения.'
    if any(s in text for s in ('alert protocol version','unsupported protocol','version too low','no protocols available')):
        return 'VPN-сервер не поддерживает требуемую версию TLS. Нужен TLS 1.2 или новее; обнови настройки сервера.'
    if any(s in text for s in ('certificate has expired','certificate is not yet valid')):
        return 'Сертификат VPN просрочен или ещё не действует. Проверь дату на Pi и сертификат сервера.'
    if any(s in text for s in ('verify error','certificate verify failed','cannot load certificate','cannot load private key','pem routines')):
        return 'Не удалось проверить сертификат или ключ VPN. Нужен корректный полный клиентский профиль.'
    if any(s in text for s in ('no shared cipher','no cipher match','failed to negotiate cipher','no suitable signature','no shared signature','unsupported cipher')):
        return 'VPN-сервер не согласовал безопасное шифрование. Обнови его настройки или клиентский профиль.'
    if any(s in text for s in ('network is unreachable','connection refused','no route to host','cannot resolve host')):
        return 'VPN-сервер недоступен. Проверь его адрес, порт и подключение Pi к Интернету.'
    if timed_out:return 'VPN-сервер не завершил защищённое соединение вовремя. Проверь доступность сервера и актуальность профиля.'
    return 'OpenVPN завершил подключение с ошибкой. Подробности доступны в диагностике; исходный профиль сохранён.'
