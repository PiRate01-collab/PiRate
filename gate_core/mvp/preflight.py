"""Saved-profile checks only. Never constructs a backend or changes networking."""
import concurrent.futures
import ipaddress
import json
import os
import shutil
import socket
import sys
import threading
import time
import uuid
from .support import bounded_command, sanitize, secret_values
from .profiles import Profiles

NOTICE='Success requires authenticated proxy transport, HTTPS traffic and a valid public exit IP. Isolated VPN checks are unavailable; no tunnel or active connection is changed.'

def resolve(host):
    # A disposable process bounds libc resolver delays; never leave stuck DNS threads.
    code=('import socket,json,sys; print(json.dumps(sorted(set(x[4][0] for x in '
          'socket.getaddrinfo(sys.argv[1],None,socket.AF_INET,socket.SOCK_STREAM)))[:16]))')
    result=bounded_command([sys.executable,'-I','-c',code,host],timeout=2,limit=4096)
    if result['limited']:raise TimeoutError('DNS resolution timed out')
    if result['exit']!=0:raise ValueError('Server hostname could not be resolved')
    return json.loads(result['output'])


def safe_addresses(addresses):
    if not addresses:raise ValueError('No IPv4 endpoint addresses')
    for text in addresses:
        ip=ipaddress.ip_address(text)
        if str(ip)=='168.63.129.16' or not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            return False
    # Do not probe this device even if it has a globally routable address.
    result=bounded_command(['ip','-j','address','show'],timeout=1,limit=32768)
    if result['exit']!=0 or result['limited']:return False
    local={a['local'] for item in json.loads(result['output']) for a in item.get('addr_info',[])}
    return not local.intersection(addresses)


def check(profile,cancel,authorized=lambda: True):
    checks=[];known=secret_values(profile)
    def result(status,reason):
        return {'status':status,'reason':sanitize(reason,known),'checks':checks,'checked_at':time.time(),'notice':NOTICE}
    try:
        if cancel.is_set():return result('inconclusive','Cancelled')
        if not authorized():return result('inconclusive','Profile changed/removed or a matching account is active; no conflicting test session started')
        p=Profiles.values({k:v for k,v in profile.items() if k not in ('id','state')})
        kind=p['type'];protocol='tcp'
        if kind=='direct':return result('inconclusive','Direct is not a saved VPN/proxy endpoint')
        if not p.get('server') or not isinstance(p.get('port'),int):return result('failed','Server and numeric port are required')
        checks.append('Configuration and credential/key presence validated; contents not returned')
        binaries={'wireguard':('wg','ip','nft'),'openvpn':('openvpn','ip','nft')}.get(kind,())
        missing=[b for b in binaries if not shutil.which(b,path=os.environ.get('PATH','')+':/usr/sbin:/sbin')]
        if missing:return result('failed','Missing local tools: '+', '.join(missing))
        if kind=='wireguard':
            if not p.get('wg_private_key') or not p.get('wg_peer_key') or not p.get('wg_address'):
                return result('failed','WireGuard requires private key, peer key and interface address')
            if '0.0.0.0/0' not in p.get('wg_allowed_ips',[]):return result('failed','WireGuard requires IPv4 AllowedIPs 0.0.0.0/0')
            protocol='udp'
            checks.append('WireGuard key/address syntax checked; peer authentication and UDP not tested')
        elif kind=='openvpn':
            from .tunnels import normalize_openvpn
            from .profile_v1 import profile_ca_identity
            _,protocol,auth=normalize_openvpn(p['config'],'1.1.1.1',p['port'],p.get('ovpn_remote'),p.get('ovpn_proto',''),p.get('ovpn_server_name',''),profile_ca_identity(p))
            if auth and not (p.get('username') and p.get('password')):return result('failed','OpenVPN username/password required')
            checks.append('OpenVPN local security policy and inline certificate/key presence checked; validity/authentication not verified')
        checks.append('Required local dependencies available')
        if cancel.is_set():return result('inconclusive','Cancelled')
        if not authorized():return result('inconclusive','Profile changed/removed or a matching account is active; no conflicting test session started')
        addresses=resolve(p['server'])
        checks.append('Server hostname resolved (IPv4)')
        if not safe_addresses(addresses):return result('inconclusive','Endpoint is local/private/reserved or local-address inventory unavailable; network probe blocked by SSRF policy')
        if kind in ('wireguard','openvpn'):
            return result('inconclusive','A safe isolated VPN test is not available in this release. No session was opened; authentication and traffic were not verified. Use Connect / Confirm for an actual connection.')
        if cancel.is_set():return result('inconclusive','Cancelled')
        if not authorized():return result('inconclusive','Profile changed or conflicts with an active connection')
        outcome=proxy_check(p,addresses[0],cancel,authorized)
        if outcome.get('ok'):
            checks.extend(['Proxy authentication/negotiation completed', 'Verified HTTPS traffic through proxy',
                           'Public exit IPv4 received: '+outcome['exit_ip'], 'Temporary sockets/process closed'])
            return result('passed','Proxy connection and traffic verified; exit IP '+outcome['exit_ip'])
        return result('failed',outcome.get('error','Proxy check failed'))
    except TimeoutError:return result('inconclusive','DNS/TCP/protocol timeout; reachability not confirmed')
    except (OSError,ValueError) as exc:return result('failed',f'{type(exc).__name__}: {exc}')
    except Exception as exc:
        # ProfileError/ConnectionError contain precise sanitized validation messages.
        return result('failed',f'{type(exc).__name__}: {exc}')


class Preflight:
    def __init__(self,app,support):
        self.app=app;self.support=support;self.lock=threading.RLock()
        self.pool=concurrent.futures.ThreadPoolExecutor(max_workers=3,thread_name_prefix='pirate-preflight')
        self.cancel_event=threading.Event();self.results={};self.snapshots={};self.running=0;self.job=None
        self.last_started=0

    def start(self,identifier=None):
        with self.lock:
            if self.running:raise ValueError('A preflight batch is already running; cancel or wait')
            if time.monotonic()-self.last_started<3:raise ValueError('Wait three seconds between preflight batches')
            valid={p['id'] for p in self.app.profiles.list()}
            self.results={k:v for k,v in self.results.items() if k in valid}
            self.snapshots={k:v for k,v in self.snapshots.items() if k in valid}
            profiles=[self.app.profiles.get(identifier)] if identifier is not None else self.app.profiles.list(private=True)
            profiles=[p for p in profiles if p['type'] in ('wireguard','openvpn','socks5','http')]
            if len(profiles)>100:raise ValueError('Maximum 100 preflight profiles')
            self.last_started=time.monotonic();self.job=uuid.uuid4().hex;self.cancel_event=threading.Event()
            self.running=len(profiles)
            for p in profiles:
                self.snapshots[p['id']]=p
                self.results[p['id']]={'status':'checking','reason':'Queued / checking','checks':[],'checked_at':None,'notice':NOTICE}
            for p in profiles:self.pool.submit(self._one,p,self.cancel_event)
            return self.status()

    def _one(self,p,cancel):
        try:
            def authorized():
                try:
                    if self.app.profiles.get(p['id'])!=p:return False
                    for backend in (getattr(self.app,'current',None),getattr(self.app,'previous',None)):
                        active=getattr(backend,'profile',{})
                        if active.get('type')==p['type'] and active.get('server')==p['server'] and active.get('username')==p.get('username'):
                            return False
                    return True
                except Exception:return False
            value=check(p,cancel,authorized)
            if cancel.is_set():value=dict(value,status='inconclusive',reason='Cancelled; partial checks only')
            with self.lock:self.results[p['id']]=value
            self.support.events.add(p['type'],'Check '+value['status']+': '+value['reason']+'; '+'; '.join(value['checks']),
                                    'error' if value['status']=='failed' else 'warning' if value['status']=='inconclusive' else 'info',p,secret_values(p),attempt_id=uuid.uuid4().hex)
        finally:
            with self.lock:self.running-=1

    def status(self):
        with self.lock:
            public={}
            for p in self.app.profiles.list(private=True):
                if p['type']=='direct':continue
                value=self.results.get(p['id']) if p==self.snapshots.get(p['id']) else None
                public[p['id']]=value or {'status':'not_checked','reason':'Not checked, or profile changed','checks':[],'checked_at':None,'notice':NOTICE}
            return {'job_id':self.job,'running':self.running,'results':public,'notice':NOTICE}

    def cancel(self):
        self.cancel_event.set()
        return self.status()

    def close(self):
        self.cancel_event.set();self.pool.shutdown(wait=False,cancel_futures=True)


def proxy_check(profile, endpoint, cancel, authorized):
    """Reuse production proxy I/O in a disposable process with a wall deadline."""
    import subprocess
    from pathlib import Path
    payload={k:profile.get(k,'') for k in ('type','server','port','username','password')}
    payload['endpoint_ip']=endpoint
    process=subprocess.Popen([sys.executable,'-B','-m','gate_core.mvp.preflight','--proxy-worker'],
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                             env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2])))
    data=json.dumps(payload).encode();deadline=time.monotonic()+12
    try:
        while True:
            if cancel.is_set() or not authorized():return {'error':'Cancelled or account/profile changed; no success recorded'}
            if time.monotonic()>deadline:return {'error':'Proxy traffic check timed out (12 seconds)'}
            try:
                raw,_=process.communicate(input=data,timeout=.1)
                if process.returncode or len(raw)>4096:return {'error':'Proxy check process failed'}
                return json.loads(raw)
            except subprocess.TimeoutExpired:data=None
    finally:
        if process.poll() is None:process.kill()
        process.wait()
        for stream in (process.stdin,process.stdout):
            if stream:stream.close()


def proxy_worker():
    from .proxy import ProxyBackend
    profile=json.loads(sys.stdin.buffer.read(4096))
    backend=ProxyBackend(profile);backend.endpoint_ip=profile['endpoint_ip']
    try:
        response=backend.request('https://api.ipify.org/')
        address=ipaddress.ip_address(response['body'].strip())
        if address.version!=4 or not address.is_global:raise ValueError('Check endpoint did not return a public IPv4')
        result={'ok':True,'exit_ip':str(address)}
    except Exception as exc:
        result={'ok':False,'error':sanitize(type(exc).__name__+': '+str(exc),secret_values(profile))}
    finally:backend.stop()
    print(json.dumps(result))


if __name__=='__main__' and sys.argv[1:]==['--proxy-worker']:
    proxy_worker()
