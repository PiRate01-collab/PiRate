"""LAN IPv4 TCP gateway: nft REDIRECT, proxy transport, DNS and fail-closed LAN.

Only this module changes its own nft table, after explicit router mode activation.
Existing AP addressing/DHCP/WAN configuration and default routes are preserved.
"""
import http.client
from contextvars import ContextVar
from contextlib import contextmanager, nullcontext
import errno
import fcntl
import ipaddress
import json
import os
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from .proxy import ConnectionError, exact, relay

TABLE='pirate_gateway'

# Transaction-local attribution: never record stdin, arbitrary configuration or secrets.
AP_OPERATION=ContextVar('pirate_ap_operation',default=None)

@contextmanager
def operation_scope(stage,interface,record):
    token=AP_OPERATION.set((stage,interface,record))
    try:yield
    finally:AP_OPERATION.reset(token)


def command_failure(args,result,operation=None):
    detail=(result.stderr.strip() or 'operation failed')[:300]
    error=ConnectionError('Network operation '+ ' '.join(args)+': '+detail)
    error.operation=operation;error.returncode=result.returncode
    return error


def network_command(*args, check=True, input=None):
    context=AP_OPERATION.get();operation=None
    # Only these argument vocabularies contain no credentials. hostapd configs
    # are represented by a path, never their contents. nft stdin is omitted.
    safe=os.path.basename(args[0]) in ('ip','iw','ethtool','wpa_cli','hostapd','dnsmasq')
    if context and safe:
        stage,interface,record=context
        operation={'stage':stage,'interface':interface,'initiated_by':'PiRate','arguments':list(args),
                   'operation':operation_name(args),'at':time.time(),'result':'Started'}
        record(dict(operation))
    try:
        result=subprocess.run(args,input=input,capture_output=True,text=True,timeout=10,env=dict(os.environ,LC_ALL='C'))
        number=None
        if result.returncode:
            for pattern,value in ((r'busy|\(-16\)',errno.EBUSY),(r'not supported|\(-95\)',errno.EOPNOTSUPP),
                                  (r'No such device|\(-19\)',errno.ENODEV),(r'not permitted',errno.EPERM)):
                if re.search(pattern,result.stderr,re.I):number=value;break
        if operation:
            operation.update(result='Failed' if result.returncode else 'OK',returncode=result.returncode,
                errno=number,errno_source='stderr inference' if number else None,detail=result.stderr.strip()[:300])
            record(dict(operation));result.pirate_operation=dict(operation)
    except (OSError,subprocess.TimeoutExpired) as exc:
        if operation:
            operation.update(result='Failed',returncode=None,errno=getattr(exc,'errno',None),
                errno_source='OS exception',detail='timeout' if isinstance(exc,subprocess.TimeoutExpired) else str(exc)[:300])
            record(dict(operation))
        error=ConnectionError('Network tools unavailable: '+' '.join(args)+'; '+str(exc)[:200])
        error.operation=operation
        raise error from None
    if check and result.returncode:raise command_failure(args,result,operation)
    return result


def operation_name(args):
    if args[0]=='ip' and 'link' in args and 'set' in args:
        return 'mac_change' if 'address' in args else 'interface_down' if 'down' in args else 'interface_up' if 'up' in args else 'link_set'
    if args[0]=='iw' and 'set' in args and 'type' in args:return 'interface_mode'
    return os.path.basename(args[0])+'_'+('_'.join(args[1:3]))

def isolated_lab_namespace():
    """Verify kernel ownership, never trust an environment opt-in for VM260."""
    try:
        mapping=Path('/proc/self/uid_map').read_text().split()
        if os.geteuid()!=0 or len(mapping)!=3 or mapping[0]!='0' or mapping[2]!='1':return False
        user_inode=os.stat('/proc/self/ns/user').st_ino
        for kind in ('net','mnt'):
            with open('/proc/self/ns/'+kind,'rb') as namespace:
                owner=fcntl.ioctl(namespace.fileno(),0xb701) # NS_GET_USERNS
                try:
                    if os.fstat(owner).st_ino!=user_inode:return False
                finally:os.close(owner)
        return True
    except (OSError,ValueError):return False

def permitted():
    if os.uname().nodename=='pirate-lab' and not isolated_lab_namespace():
        raise ConnectionError('Router changes disabled on VM260 outside isolated user/network/mount namespaces')
    if os.environ.get('PIRATE_ROUTER_MODE')!='1':raise ConnectionError('Router NOT TESTED: enable PIRATE_ROUTER_MODE=1 in an isolated network namespace or test Pi')
    # CAP_NET_ADMIN is necessary even when euid0 is user-namespace mapped.
    caps=next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    if not int(caps,16)&(1<<12):raise ConnectionError('Router NOT TESTED: CAP_NET_ADMIN unavailable')

def configuration(raw):
    allowed={'lan_interface','wan_interface','dns_mode','dns_server','dns_port','doh_url','dns_check_name','ap_dns_address','management_port','dns_auto','dns_fallbacks','dns_candidates','dns_manual','dns_doh_fallbacks','lan_subnet','fingerprint','protected_lans'}
    if not isinstance(raw,dict) or set(raw)-allowed:raise ConnectionError('Invalid LAN gateway configuration')
    value=dict(lan_interface='wlan0',wan_interface='eth0',dns_mode='tcp',dns_server='9.9.9.9',dns_port=53,
               doh_url='',dns_check_name='example.com',ap_dns_address='',management_port=0)
    value.update(raw)
    if type(value['management_port']) is not int or value['management_port'] not in (0,8766):raise ConnectionError('Invalid AP management port')
    if value['ap_dns_address']:
        try:value['ap_dns_address']=str(ipaddress.IPv4Address(value['ap_dns_address']))
        except (ValueError,TypeError):raise ConnectionError('Invalid AP DNS address') from None
    for key in ('lan_interface','wan_interface'):
        if not isinstance(value[key],str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,15}',value[key]) or value[key]=='lo':raise ConnectionError('Invalid LAN/WAN interface')
    if value['lan_interface']==value['wan_interface']:raise ConnectionError('LAN and WAN must differ')
    protected=value.get('protected_lans',[])
    if not isinstance(protected,list) or len(protected)>16 or any(not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',name) or name=='lo' for name in protected):raise ConnectionError('Invalid protected LAN list')
    if value['wan_interface'] in protected:raise ConnectionError('Бывший AP interface защищён как LAN и не может стать WAN без восстановления установки')
    value['protected_lans']=list(dict.fromkeys(protected))
    if value['dns_mode'] not in ('auto','tcp','doh'):raise ConnectionError('DNS policy must be TCP via upstream or DoH via upstream')
    value.setdefault('dns_manual',False);value.setdefault('dns_auto',value['dns_mode']=='auto');value.setdefault('dns_fallbacks',[])
    if value['dns_mode']=='auto':value['dns_mode']='tcp'
    value.setdefault('dns_doh_fallbacks',[])
    if not isinstance(value['dns_doh_fallbacks'],list) or len(value['dns_doh_fallbacks'])>4:raise ConnectionError('Invalid DoH fallback list')
    for url in value['dns_doh_fallbacks']:
        parsed=urlsplit(url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:raise ConnectionError('Invalid DoH fallback')
    if type(value['dns_manual']) is not bool or type(value['dns_auto']) is not bool or not isinstance(value['dns_fallbacks'],list) or len(value['dns_fallbacks'])>13:raise ConnectionError('Invalid DNS selection')
    try:
        value['dns_fallbacks']=[str(ipaddress.IPv4Address(ip)) for ip in value['dns_fallbacks']]
        if 'dns_candidates' in value:
            if not isinstance(value['dns_candidates'],list) or not 1<=len(value['dns_candidates'])<=13:raise ValueError('Invalid candidate count')
            value['dns_candidates']=[str(ipaddress.IPv4Address(ip)) for ip in value['dns_candidates']]
        if value.get('lan_subnet'):value['lan_subnet']=str(ipaddress.IPv4Network(value['lan_subnet']))
    except (ValueError,TypeError):raise ConnectionError('Invalid DNS/subnet') from None
    if value.get('fingerprint','default') not in ('default','ttl64','ttl128'):raise ConnectionError('Invalid client TTL')
    try:value['dns_server']=str(ipaddress.IPv4Address(value['dns_server']))
    except (ValueError,TypeError):raise ConnectionError('TCP DNS requires a numeric IPv4 resolver') from None
    if type(value['dns_port']) is not int or not 1<=value['dns_port']<=65535:raise ConnectionError('Invalid DNS port')
    name=value['dns_check_name']
    if not isinstance(name,str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,253}',name):raise ConnectionError('Invalid DNS check name')
    if value['dns_mode']=='doh':
        parsed=urlsplit(value['doh_url'])
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:raise ConnectionError('DoH requires an HTTPS URL without credentials/query/fragment')
    return value

def original_destination(sock):
    raw=sock.getsockopt(socket.SOL_IP,80,16) # Linux SO_ORIGINAL_DST
    if struct.unpack('H',raw[:2])[0]!=socket.AF_INET:raise ConnectionError('Transparent gateway supports IPv4 TCP only')
    return socket.inet_ntoa(raw[4:8]),struct.unpack('!H',raw[2:4])[0]

class RedirectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self,backend,interface=None):
        self.backend=backend;self.opened=0;self.failed=0;self.last_destination=None;self.last_source=None;self.last_result='NOT TESTED'
        super().__init__(('0.0.0.0',0),RedirectHandler,bind_and_activate=False)
        try:
            if interface:self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
            self.server_bind();self.server_activate()
        except BaseException:self.server_close();raise

class RedirectHandler(socketserver.BaseRequestHandler):
    def handle(self):
        backend=None;outgoing=None
        try:
            host,port=original_destination(self.request)
            if port==self.server.server_address[1]:raise ConnectionError('Direct access to transparent relay denied')
            self.server.last_destination=f'{host}:{port}'
            self.server.last_source=self.client_address[0]
            backend=self.server.backend()
            if backend is None:raise ConnectionError('Gateway blocked; no selected upstream')
            outgoing=backend.open(host,port)
            self.server.opened+=1
            self.server.last_result='UPSTREAM_CONNECTED'
            relay(self.request,outgoing)
        except (OSError,ValueError,ConnectionError):
            if outgoing is None:
                self.server.failed+=1;self.server.last_result='UPSTREAM_UNAVAILABLE'
        finally:
            if outgoing is not None:backend.release(outgoing)


def question_end(query):
    if not 12<=len(query)<=4096:raise ConnectionError('Invalid DNS request size')
    flags,questions=struct.unpack('!HH',query[2:6])
    if flags&0x8000 or flags&0x7800 or questions!=1:raise ConnectionError('DNS supports a single standard question')
    offset=12
    while True:
        if offset>=len(query):raise ConnectionError('Truncated DNS question')
        size=query[offset];offset+=1
        if size==0:break
        if size>63 or offset+size>len(query):raise ConnectionError('Invalid DNS label')
        offset+=size
    if offset+4>len(query):raise ConnectionError('Truncated DNS question')
    return offset+4

def dns_error(query,rcode=2):
    try:
        end=question_end(query)
        # Preserve RD, report recursion available; no synthetic answer or fallback.
        flags=0x8080|(struct.unpack('!H',query[2:4])[0]&0x0100)|rcode
        return query[:2]+struct.pack('!HHHHH',flags,1,0,0,0)+query[12:end]
    except ConnectionError:return query[:2]+struct.pack('!HHHHH',0x8082,0,0,0,0)

def dns_query(name):
    labels=name.rstrip('.').encode('idna').split(b'.')
    if any(not 1<=len(label)<=63 for label in labels):raise ConnectionError('Invalid DNS check labels')
    return os.urandom(2)+struct.pack('!HHHHH',0x0100,1,0,0,0)+b''.join(bytes([len(label)])+label for label in labels)+b'\x00\x00\x01\x00\x01'

class DNSPolicy:
    def __init__(self,config,backend):
        self.config=config;self.backend=backend;self.success=0;self.failure=0;self.last_result='NOT TESTED';self.resolver=config['doh_url'] if config['dns_mode']=='doh' else config['dns_server']
    def exchange(self,query,backend=None,valid=None,transport=None):
        resolvers=list(dict.fromkeys([self.resolver,*self.config.get('dns_fallbacks',[]),*self.config.get('dns_doh_fallbacks',[])])) if self.config.get('dns_auto') else [self.resolver]
        for resolver in resolvers:
            if valid is not None and not valid():raise ConnectionError('DNS policy changed; no fallback through retained backend')
            try:
                answer=self._exchange(query,backend,resolver,valid,transport)
                if answer[3]&15 in (2,5):raise ConnectionError('Resolver returned SERVFAIL/REFUSED')
                self.resolver=resolver;return answer
            except (OSError,ValueError,ConnectionError) as exc:self.last_error=str(exc)
        self.last_result='SERVFAIL_NO_FALLBACK'
        raise ConnectionError('DNS через выбранное соединение недоступен: '+getattr(self,'last_error','нет ответа')+'; прямой fallback запрещён')

    def _exchange(self,query,backend=None,resolver=None,valid=None,transport=None):
        end=question_end(query)
        # No IPv6 client egress. AAAA receives NODATA, never a fake IPv4 answer.
        if struct.unpack('!H',query[end-4:end-2])[0]==28:return dns_error(query,0)
        selected=backend if backend is not None else self.backend()
        if selected is None:raise ConnectionError('DNS blocked: no selected upstream')
        sock=None
        try:
            resolver=resolver or self.resolver
            if not resolver.startswith('https://'):
                with transport() if transport else nullcontext():
                    sock=selected.open(resolver or self.config['dns_server'],self.config['dns_port']);sock.settimeout(4)
                    if valid is not None and not valid():raise ConnectionError('DNS policy changed before send')
                    sock.sendall(struct.pack('!H',len(query))+query)
                answer=exact(sock,struct.unpack('!H',exact(sock,2))[0])
            else:
                parsed=urlsplit(resolver);port=parsed.port or 443
                with transport() if transport else nullcontext():
                    plain=selected.open(parsed.hostname,port)
                    sock=plain;plain.settimeout(4)
                    if valid is not None and not valid():raise ConnectionError('DNS policy changed before TLS')
                    sock=ssl.create_default_context().wrap_socket(plain,server_hostname=parsed.hostname)
                    with selected.socket_lock:selected.sockets.discard(plain)
                    selected.track(sock)
                    body=query
                    header=(f'POST {parsed.path or "/dns-query"} HTTP/1.1\r\nHost: {parsed.hostname}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode('ascii')
                    if valid is not None and not valid():raise ConnectionError('DNS policy changed before DoH send')
                    sock.sendall(header+body)
                response=http.client.HTTPResponse(sock);response.begin()
                if response.status!=200 or response.getheader('Content-Type','').split(';')[0].strip()!='application/dns-message':raise ConnectionError('DoH resolver rejected request')
                answer=response.read(65536)
            if not 12<=len(answer)<=65535 or answer[:2]!=query[:2] or not answer[2]&0x80:raise ConnectionError('Invalid upstream DNS answer')
            # Question must still match, including queried name/type/class.
            response_question=bytearray(answer);response_question[2]&=0x7f
            response_end=question_end(bytes(response_question))
            if answer[12:response_end]!=query[12:end]:raise ConnectionError('DNS response question mismatch')
            if answer[3]&15 in (2,5):raise ConnectionError('Resolver returned SERVFAIL/REFUSED')
            self.success+=1;self.last_result='UPSTREAM_RESPONSE';self.checked_at=time.time();return answer
        except (OSError,ValueError,ConnectionError) as exc:
            self.failure+=1;self.last_result='SERVFAIL_NO_FALLBACK'
            reason=str(exc) if isinstance(exc,ConnectionError) else type(exc).__name__
            raise ConnectionError('DNS transport: '+reason) from None
        finally:
            if sock is not None:selected.release(sock)
    def handle(self,query):
        try:return self.exchange(query)
        except (OSError,ValueError,ConnectionError):return dns_error(query)
    def check(self,backend):
        answer=self.exchange(dns_query(self.config['dns_check_name']),backend)
        if answer[3]&15 or struct.unpack('!H',answer[6:8])[0]==0:raise ConnectionError('DNS запрос не вернул IPv4 ответ')
        return {'status':'PASS','resolver':self.resolver,'policy':'doh' if self.resolver.startswith('https://') else 'tcp','via':'selected upstream','checked_at':time.time()}

class DNSUDP(socketserver.ThreadingUDPServer):
    daemon_threads=True
    def __init__(self,port,policy,interface=None):
        self.policy=policy;super().__init__(('0.0.0.0',port),DNSUDPHandler,bind_and_activate=False)
        try:
            if interface:self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
            self.server_bind();self.server_activate()
        except BaseException:self.server_close();raise
class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query,sock=self.request;answer=self.server.policy.handle(query)
        if len(answer)>1232:
            answer=bytearray(dns_error(query,0));answer[2]|=2;answer=bytes(answer) # TC: client retries TCP.
        try:
            sock.sendto(answer,self.client_address)
            if hasattr(self.server.policy,'dns_sent'):self.server.policy.dns_sent(answer,True)
        except OSError:
            if hasattr(self.server.policy,'dns_sent'):self.server.policy.dns_sent(answer,False)
class DNSTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self,policy,interface=None):
        self.policy=policy;super().__init__(('0.0.0.0',0),DNSTCPHandler,bind_and_activate=False)
        try:
            if interface:self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
            self.server_bind();self.server_activate()
        except BaseException:self.server_close();raise
class DNSTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            # One request per connection. Do not assume UDP-size DNS messages.
            query=exact(self.request,struct.unpack('!H',exact(self.request,2))[0]);answer=self.server.policy.handle(query)
            self.request.sendall(struct.pack('!H',len(answer))+answer)
            if hasattr(self.server.policy,'dns_sent'):self.server.policy.dns_sent(answer,True)
        except (OSError,ValueError,ConnectionError):
            if hasattr(self.server.policy,'dns_sent'):self.server.policy.dns_sent(b'',False)

class GatewayGeneration:
    def __init__(self,config,backend,dns_tcp,native=None,direct=False):
        self.config=config;self.native=native;self.direct=direct;self.policy=DNSPolicy(config,backend)
        self.tcp=RedirectServer(backend,config['lan_interface']);self.dns_tcp=dns_tcp
        threading.Thread(target=self.tcp.serve_forever,daemon=True).start()
    def close(self):
        self.tcp.shutdown();self.tcp.server_close()


def ruleset(config,tcp_port=None,dns_port=None,owner=None,native=None,direct=False):
    lan=config['lan_interface'];redirect=''
    if tcp_port is not None:
        redirect=f'''chain intercept {{ type nat hook prerouting priority dstnat; policy accept;
 iifname "{lan}" meta nfproto ipv4 udp dport 53 counter redirect to :{dns_port}
 iifname "{lan}" meta nfproto ipv4 tcp dport 53 counter redirect to :{dns_port}
 iifname "{lan}" meta nfproto ipv4 fib daddr type != local meta l4proto tcp counter redirect to :{tcp_port}
 }}'''
    permit=f'iifname "{lan}" meta nfproto ipv4 tcp dport {{ {tcp_port}, {dns_port} }} counter accept\n iifname "{lan}" meta nfproto ipv4 udp dport {dns_port} counter accept' if tcp_port is not None else ''
    forwarding=''
    marking=''
    if native is not None:
        from .tunnels import routing_id
        veth=native.resource['veth'];mark=routing_id(native.resource)
        # Only DNS is redirected for native VPN. TCP/UDP packets enter the real IP tunnel.
        redirect=f'''chain intercept {{ type nat hook prerouting priority dstnat; policy accept;
 iifname "{lan}" meta nfproto ipv4 udp dport 53 counter redirect to :{dns_port}
 iifname "{lan}" meta nfproto ipv4 tcp dport 53 counter redirect to :{dns_port}
 }}'''
        networks=getattr(native,'lan_networks',None) or ([config['lan_subnet']] if config.get('lan_subnet') else [])
        local='\n '.join('iifname "'+lan+'" ip daddr '+str(ipaddress.IPv4Network(net))+' counter return' for net in networks)
        marking=f'''chain vpn_route {{ type filter hook prerouting priority mangle; policy accept;
 iifname "{lan}" meta nfproto ipv4 udp dport 67 return
 iifname "{lan}" meta nfproto ipv4 fib daddr type local counter return
 iifname "{lan}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 counter return
 {local}
 iifname "{lan}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} counter meta mark set {mark}
 }}'''
        permit=f'iifname "{lan}" meta nfproto ipv4 tcp dport {dns_port} counter accept\n iifname "{lan}" meta nfproto ipv4 udp dport {dns_port} counter accept'
        forwarding=f'''iifname "{lan}" oifname "{veth}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} counter accept
 iifname "{veth}" oifname "{lan}" meta nfproto ipv4 ct state established,related counter accept'''
    old_lans=[name for name in config.get('protected_lans',[]) if name!=lan]
    protected=''
    if old_lans:
        names='{ '+', '.join('\"'+name+'\"' for name in old_lans)+' }'
        protected=f'''chain previous_lan_input {{ type filter hook input priority -25; policy accept;
 iifname {names} counter drop
 }}
 chain previous_lan_forward {{ type filter hook forward priority -25; policy accept;
 iifname {names} counter drop
 oifname {names} counter drop
 }}'''
    dns_guard=''
    if dns_port is not None:
        dns_guard=f'''chain dns_guard {{ type filter hook input priority -30; policy accept;
 iifname != {{ "lo", "{lan}" }} meta l4proto {{ tcp, udp }} th dport {dns_port} counter drop
 }}'''
    nat=''
    if direct:
        subnet=str(ipaddress.IPv4Network(config['lan_subnet']));wan=config['wan_interface']
        redirect=f'''chain intercept {{ type nat hook prerouting priority dstnat; policy accept;
 iifname "{lan}" meta nfproto ipv4 udp dport 53 counter redirect to :{dns_port}
 iifname "{lan}" meta nfproto ipv4 tcp dport 53 counter redirect to :{dns_port}
 }}'''
        forwarding=f'''iifname "{lan}" oifname "{wan}" ip saddr {subnet} meta l4proto {{ tcp, udp, icmp }} counter accept
 iifname "{wan}" oifname "{lan}" ip daddr {subnet} ct state established,related counter accept'''
        nat=f'''chain direct_nat {{ type nat hook postrouting priority srcnat; policy accept;
 iifname "{lan}" oifname "{wan}" ip saddr {subnet} counter masquerade
 }}'''
    fingerprint=''
    if (native or direct or tcp_port is not None) and config.get('fingerprint','default')!='default':
        ttl=64 if config['fingerprint']=='ttl64' else 128
        fingerprint=f'''chain client_ttl {{ type filter hook forward priority mangle; policy accept;
 iifname "{lan}" meta nfproto ipv4 ip ttl set {ttl}
 }}'''
    observers=''
    if config.get('ap_dns_address'):
        address=config['ap_dns_address']
        observers=f'''chain dns_requests {{ type filter hook prerouting priority -160; policy accept;
 iifname "{lan}" ip daddr {address} meta l4proto {{ tcp, udp }} th dport 53 counter comment "client_dns_request"
 }}
 chain dns_replies {{ type filter hook output priority filter; policy accept;
 oifname "{lan}" ip saddr {address} meta l4proto {{ tcp, udp }} th sport 53 counter comment "client_dns_reply"
 }}'''
    tag=f'comment "PiRate {owner}";' if owner else ''
    if config.get('management_port') and config.get('ap_dns_address'):
        permit+=f'\n iifname "{lan}" ip daddr {config["ap_dns_address"]} tcp dport {config["management_port"]} counter accept'
    if config.get('ap_dns_address'):
        redirect=redirect.replace('udp dport 53',f'ip daddr != {config["ap_dns_address"]} udp dport 53').replace('tcp dport 53',f'ip daddr != {config["ap_dns_address"]} tcp dport 53')
        permit+=f'\n iifname "{lan}" ip daddr {config["ap_dns_address"]} meta l4proto {{ tcp, udp }} th dport 53 counter accept'
    return f'''table inet {TABLE} {{
 {tag}
 {redirect}
 {marking}
 {observers}
 {nat}
 {dns_guard}
 {protected}
 {fingerprint}
 chain lan_input {{ type filter hook input priority -10; policy accept;
 iifname "{lan}" meta nfproto ipv4 udp dport 67 counter accept
 {permit}
 iifname "{lan}" counter drop
 }}
 chain lan_forward {{ type filter hook forward priority -10; policy accept;
 {forwarding}
 iifname "{lan}" counter drop
 oifname "{lan}" counter drop
 }}
}}\n'''

class RouterGateway:
    def __init__(self,app):
        self.app=app;self.path=app.directory/'router.json';self.current=None;self.previous=None;self.pending=False;self.blocked_config=None;self.dns_tcp=None;self.dns_udp=None
        self.dns_condition=threading.Condition();self.dns_senders=0
        self.transition_uncertain=False;self.dns_selected=None;self.dns_observation={'requests':0,'responses':0,'servfail':0,'send_errors':0,'last_request_at':None,'last_response_at':None}
        self.last_dns={'status':'NOT TESTED'};self.owner=uuid.uuid4().hex;self.policy_active=False
        if self.path.exists():
            permitted();saved=json.loads(self.path.read_text());self.blocked_config=configuration(saved['config'])
            if not re.fullmatch('[a-f0-9]{32}',saved.get('owner','')):raise ConnectionError('Router saved ownership invalid')
            self.owner=saved['owner']
            self.install(self.blocked_config);self.save()
    def exists(self):
        result=network_command('/usr/sbin/nft','-j','list','table','inet',TABLE,check=False)
        if result.returncode:return False
        tables=[entry['table'] for entry in json.loads(result.stdout)['nftables'] if 'table' in entry]
        if len(tables)!=1 or tables[0].get('comment')!='PiRate '+self.owner:
            raise ConnectionError('Existing pirate_gateway table belongs to another runtime; left unchanged')
        return True
    def install(self,config,generation=None):
        permitted()
        present=self.exists()
        if present and self.current is None and self.blocked_config is None and not self.path.exists():raise ConnectionError('Existing pirate_gateway table is not owned by this runtime')
        script=('delete table inet '+TABLE+'\n' if present else '')+ruleset(config,generation.tcp.server_address[1] if generation else None,generation.dns_tcp.server_address[1] if generation else self.dns_tcp.server_address[1] if self.dns_tcp else None,self.owner,generation.native if generation else None,generation.direct if generation else False)
        prior_dns=getattr(self,'dns_selected',None);prior_active=self.policy_active
        self.dns_selected=None
        # Stop admitting sends through the old generation before committing nft.
        # Concurrent queries remain parallel; receive waits do not hold a lease.
        with self.dns_condition:
            if not self.dns_condition.wait_for(lambda:self.dns_senders==0,timeout=10):
                self.dns_selected=prior_dns
                raise ConnectionError('DNS transport busy; firewall unchanged, previous configuration retained')
        try:network_command('/usr/sbin/nft','-f','-',input=script)
        except ConnectionError as exc:
            # nft -f commits atomically. A completed rejection retains the old
            # policy; a tool timeout/OS failure cannot prove which policy is live.
            if getattr(exc,'returncode',None) is not None:
                self.dns_selected=prior_dns;self.policy_active=prior_active
            else:self.policy_active=False;self.transition_uncertain=True
            raise
        self.transition_uncertain=False
        self.policy_active=generation is not None
        if generation is not None and getattr(generation,'selected_backend',None) is not None:
            self.dns_selected=(generation,generation.selected_backend)
    def validate(self,config,backend,dns_policy=None):
        permitted()
        for key in ('lan_interface','wan_interface'):
            data=json.loads(network_command('ip','-j','link','show','dev',config[key]).stdout)
            if not data or 'UP' not in data[0]['flags']:raise ConnectionError('LAN/WAN interface must already be UP')
            if key=='lan_interface' and data[0].get('master'):raise ConnectionError('Bridged/enslaved LAN is not supported; use an L3 gateway interface')
        # Do not silently send selected upstream through a different host route.
        try:endpoint=getattr(backend,'endpoint_ip',None) or socket.getaddrinfo(backend.profile['server'],backend.profile['port'],socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
        except OSError:raise ConnectionError('Cannot resolve upstream endpoint') from None
        route=json.loads(network_command('ip','-j','-4','route','get',endpoint).stdout)
        if not route or route[0].get('dev')!=config['wan_interface']:raise ConnectionError('Upstream endpoint does not route through configured WAN')
        self.upstream_route=route
        self.last_dns=(dns_policy or DNSPolicy(config,self.app.active)).check(backend)
        if hasattr(backend,'set_resolver') and config['dns_mode']=='tcp':backend.set_resolver(self.last_dns['resolver'])
    def arm(self,raw):
        config=configuration(raw);permitted()
        if self.blocked_config and config['lan_interface']!=self.blocked_config['lan_interface']:
            raise ConnectionError('Changing protected LAN interface requires stopping and explicit manual reconfiguration')
        for key in ('lan_interface','wan_interface'):
            data=json.loads(network_command('ip','-j','link','show','dev',config[key]).stdout)
            if not data or 'UP' not in data[0]['flags']:raise ConnectionError('LAN/WAN interface must already be UP')
            if key=='lan_interface' and data[0].get('master'):raise ConnectionError('Bridged/enslaved LAN is not supported; use an L3 gateway interface')
        lan_addresses=json.loads(network_command('ip','-j','-4','addr','show','dev',config['lan_interface']).stdout)
        if not lan_addresses or not lan_addresses[0].get('addr_info'):raise ConnectionError('LAN requires an existing IPv4 gateway address')
        if self.current is None:
            if self.exists() and self.blocked_config is None and not self.path.exists():raise ConnectionError('Existing pirate_gateway table is not owned by this runtime')
            self.blocked_config=config
            self.save()
            self.install(config) # Arm kill-switch BEFORE trying an unavailable upstream.
        # This also supports an installation initially made without a Wi-Fi adapter.
        # Change routing prerequisites only after the selected LAN has a DROP policy.
        network_command('/usr/sbin/sysctl','-q','-w','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=2')
        return config

    def handle(self,query):
        # Immutable pair published only after owned nft policy installation.
        # No app.lock: Apply/health probes must not stall local DNS requests.
        selection=getattr(self,'dns_selected',None)
        observation=getattr(self,'dns_observation',None)
        if observation is not None:
            observation['requests']+=1;observation['last_request_at']=time.time()
        if selection is None or not self.policy_active:return dns_error(query)
        generation,backend=selection
        try:
            answer=generation.policy.exchange(query,backend,valid=lambda:self.dns_selected is selection and self.policy_active,transport=lambda:self.dns_transport(selection))
            # Discard in-flight answers if policy changed while upstream replied.
            if self.dns_selected is not selection or not self.policy_active:return dns_error(query)
            return answer
        except (OSError,ValueError,ConnectionError):return dns_error(query)

    @contextmanager
    def dns_transport(self,selection):
        with self.dns_condition:
            if self.dns_selected is not selection or not self.policy_active:raise ConnectionError('DNS policy changed; no transport opened')
            self.dns_senders+=1
        try:yield
        finally:
            with self.dns_condition:self.dns_senders-=1;self.dns_condition.notify_all()

    def dns_sent(self,answer,success):
        observation=self.dns_observation
        if success:
            observation['responses']+=1;observation['last_response_at']=time.time()
            if len(answer)>3 and answer[3]&15==2:observation['servfail']+=1
        else:observation['send_errors']+=1

    def start_dns(self):
        if self.dns_tcp is not None:return
        interface=(self.blocked_config or {}).get('lan_interface')
        if not interface:raise ConnectionError('Select a dedicated LAN interface before DNS startup')
        # dnsmasq reaches this stable listener over loopback; LAN REDIRECT uses
        # the same port. The generation's dns_guard excludes every other device.
        tcp=DNSTCP(self)
        try:udp=DNSUDP(tcp.server_address[1],self)
        except BaseException:tcp.server_close();raise
        self.dns_tcp,self.dns_udp=tcp,udp
        try:self.install(self.blocked_config,self.current if self.policy_active else None)
        except BaseException:
            tcp.server_close();udp.server_close();self.dns_tcp=self.dns_udp=None
            raise
        for server in (tcp,udp):threading.Thread(target=server.serve_forever,daemon=True).start()

    def prepare(self,raw,backend):
        config=configuration(raw)
        self.validate(config,backend)
        self.start_dns()
        native=backend if hasattr(backend,'prepare_gateway') else None
        if native:native.prepare_gateway(config)
        generation=GatewayGeneration(config,self.app.active,self.dns_tcp,native,backend.profile['type']=='direct')
        generation.selected_backend=backend
        try:
            # First activation is durably recorded before installing packet policy.
            self.save(config)
            self.install(config,generation)
        except BaseException:
            generation.close();self.save();raise
        self.previous=self.current;self.current=generation;self.pending=True;self.blocked_config=config
    def check(self,backend):
        if self.current:
            self.validate(self.current.config,backend,self.current.policy)
            if self.current.native and not self.current.native.observed()['alive']:raise ConnectionError('VPN interface/process/handshake health check failed')
    def confirm(self):
        if self.previous:self.previous.close()
        self.previous=None;self.pending=False;self.save()
    def rollback(self):
        if not self.pending:return
        candidate=self.current
        prior=self.previous
        self.install(prior.config if prior else candidate.config,prior)
        self.current,self.previous=prior,None;self.pending=False
        self.blocked_config=(prior or candidate).config
        candidate.close();self.save()
    def save(self,config=None):
        value=config or (self.current.config if self.current else self.blocked_config)
        if value is None:return
        temp=self.path.with_suffix('.tmp')
        with temp.open('w') as file:
            os.fchmod(file.fileno(),0o600);json.dump({'schema':1,'owner':self.owner,'config':value},file);file.flush();os.fsync(file.fileno())
        os.replace(temp,self.path)
        directory=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    def stop(self):
        if self.current or self.blocked_config:
            config=self.current.config if self.current else self.blocked_config
            self.install(config) # Keep LAN locked even after server stop.
        for generation in (self.current,self.previous):
            if generation:generation.close()
        self.current=self.previous=None;self.pending=False
        self.last_dns={'status':'NOT TESTED'};self.save()

    def close(self):
        self.stop()
        for server in (self.dns_tcp,self.dns_udp):
            if server:server.shutdown();server.server_close()
        self.dns_tcp=self.dns_udp=None
        if self.blocked_config:self.install(self.blocked_config) # Remove guards for sockets now released.
    def status(self):
        active=self.policy_active and self.current is not None and self.app.current is not None
        generation=self.current
        config=generation.config if generation else self.blocked_config
        native=generation.native if generation else None
        native_report=native.observed() if native else None
        degraded=(native_report and not native_report['alive']) or generation and (generation.policy.last_result=='SERVFAIL_NO_FALLBACK' or generation.tcp.last_result=='UPSTREAM_UNAVAILABLE')
        value={'state':('DEGRADED' if degraded else 'ACTIVE') if active else 'BLOCKED' if config else 'DISABLED','config':config,
               'tcp':('IPv4 Direct NAT' if generation and generation.direct else 'IPv4 IP tunnel' if native else 'TRANSPARENT IPv4 via selected upstream') if active else 'BLOCKED' if config else 'DISABLED','udp':'IPv4 Direct NAT' if generation and generation.direct else 'IPv4 IP tunnel' if native else 'NOT SUPPORTED (DNS UDP is translated to upstream TCP/DoH)',
               'ipv6':'BLOCKED on LAN' if config else 'NOT CONFIGURED','kill_switch':('Explicit Direct: selected LAN subnet to WAN NAT only' if generation and generation.direct else 'LAN forward only to selected VPN veth; namespace forward only to tunnel; no WAN fallback' if native else 'LAN FORWARD always DROP; no WAN fallback') if config else 'NOT CONFIGURED',
               'client_connectivity':{'status':'UNVERIFIED','reason':'Namespace/proxy probes and firewall counters do not prove client HTTPS/DNS delivery'},
               'dns_local':dict(getattr(self,'dns_observation',{}),listener_port=self.dns_tcp.server_address[1] if self.dns_tcp else None,scope='PiRate listener; loopback dnsmasq upstream and redirected client requests'),
               'dns_check':dict(self.last_dns,resolver=generation.policy.resolver,status='FAIL' if generation.policy.last_result=='SERVFAIL_NO_FALLBACK' else self.last_dns.get('status','NOT TESTED'),checked_at=getattr(generation.policy,'checked_at',self.last_dns.get('checked_at')),reason=getattr(generation.policy,'last_error',None) if generation.policy.last_result=='SERVFAIL_NO_FALLBACK' else None) if generation else self.last_dns,'pending':self.pending}
        if getattr(self,'transition_uncertain',False):value.update(state='UNPROTECTED',kill_switch='Firewall transition unverified; reapply required')
        if value['dns_check'].get('status')=='PASS' and time.time()-value['dns_check'].get('checked_at',0)>90:value['dns_check']['status']='UNKNOWN'
        if config and not active:value['dns_check']=dict(value['dns_check'],status='FAIL',reason='DNS blocked: no active firewall/backend generation')
        if native_report:value['vpn']=native_report
        if generation:
            value['connections']={'opened':generation.tcp.opened,'failed':generation.tcp.failed,'last_original_destination':generation.tcp.last_destination,'last_client_ip':generation.tcp.last_source,'last_result':generation.tcp.last_result}
            value['dns']={'success':generation.policy.success,'failure':generation.policy.failure,'last_result':generation.policy.last_result}
        if config:
            value['upstream_route']=getattr(self,'upstream_route',None)
            value['egress_probe']=getattr(self.app.current,'last_check',{'status':'NOT TESTED'})
            firewall=network_command('/usr/sbin/nft','-a','list','table','inet',TABLE,check=False)
            value['firewall']=firewall.stdout
            if firewall.returncode:
                value['state']='UNPROTECTED';value['kill_switch']='MISSING; requires reapply'
            if generation and generation.tcp.last_source:
                value['route_to_client']=network_command('ip','-j','-4','route','get',generation.tcp.last_source,check=False).stdout
            value['lan_routes']=network_command('ip','-j','-4','route','show','dev',config['lan_interface'],check=False).stdout
            value['wan_routes']=network_command('ip','-j','-4','route','show','dev',config['wan_interface'],check=False).stdout
        return value
