"""Bounded, authenticated support data. Fixed sources; no caller-selected paths."""
import contextvars
import datetime
import socket
import collections
import functools
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import threading
import time
import uuid
import zipfile

COMPONENTS = ('core','openvpn','wireguard','socks5','http','wifi','dns','firewall','system','preflight')
LEVELS = ('info','warning','error')
LIMIT = 32768
ATTEMPT = contextvars.ContextVar('connection_attempt', default=None)


def read_tail(path, limit=LIMIT):
    path=Path(path)
    try:
        if any(p.is_symlink() for p in (path,*path.parents)):return ''
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):return ''
            offset=max(0,os.fstat(stream.fileno()).st_size-limit)
            stream.seek(offset);raw=stream.read(limit)
            if offset:raw=raw.partition(b'\n')[2] # Never export a partial key/log line.
            return raw.decode('utf-8',errors='replace')
    except OSError:return ''


def bounded_command(args, timeout=2, limit=LIMIT):
    """Fixed read-only commands; bound wall time and output before buffering."""
    try:
        with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as proc:
            output=bytearray();deadline=time.monotonic()+timeout
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout,selectors.EVENT_READ)
                while time.monotonic()<deadline and len(output)<limit:
                    if not selector.select(min(.1,max(0,deadline-time.monotonic()))):continue
                    part=os.read(proc.stdout.fileno(),min(4096,limit-len(output)))
                    if not part:break
                    output.extend(part)
            truncated=len(output)>=limit or time.monotonic()>=deadline
            if truncated:proc.kill()
            try:code=proc.wait(timeout=max(.01,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                proc.kill();code=proc.wait(timeout=1);truncated=True
            return {'exit':code,'output':output.decode(errors='replace'),'limited':truncated}
    except (OSError,subprocess.SubprocessError) as exc:
        return {'exit':None,'output':type(exc).__name__,'limited':True}


def secret_values(value):
    from .diagnostics import secrets
    found=secrets(value)
    if isinstance(value,dict):
        # Encoded original uploads are already covered by key-material masking;
        # do not construct megabyte-sized literal regex alternatives for them.
        for key in ('import_source','ovpn_source'):
            if isinstance(value.get(key),str):found.discard(value[key])
        config=value.get('config','')
        if isinstance(config,str):
            for block in re.findall(r'<(?:key|tls-auth|tls-crypt|auth-user-pass)>(.*?)</[^>]+>',config,re.S|re.I):
                found.update(line.strip() for line in block.splitlines() if line.strip())
        if value.get('ssid') and value.get('password'):
            found.add(hashlib.pbkdf2_hmac('sha1',value['password'].encode(),value['ssid'].encode(),4096,32).hex())
        for item in value.values():found.update(secret_values(item))
    elif isinstance(value,list):
        for item in value:found.update(secret_values(item))
    if isinstance(value,list):
        for item in value:
            if isinstance(item,dict):
                for key in ('import_source','ovpn_source'):
                    if isinstance(item.get(key),str):found.discard(item[key])
    return found


def sanitize(text, known=()):
    from .redaction import sanitize_diagnostic
    text=str(text)
    text=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)','[PRIVATE KEY REDACTED]',text,flags=re.S)
    text=re.sub(r'<(key|tls-auth|tls-crypt|auth-user-pass)>.*?(?:</\1>|\Z)','[SECRET BLOCK REDACTED]',text,flags=re.S|re.I)
    text=re.sub(r'(?i)(\b(?:private[_ -]?key|wg_private_key|wg_preshared_key|wpa_psk|sae_password|scrypt|salt|access_token|refresh_token|api[_-]?key|session[_-]?(?:id|token))\s*[:=]\s*)("[^"]*"|\S+)',r'\1[REDACTED]',text)
    text=re.sub(r'''(?i)(["']?(?:password|passwd|passphrase|private[_ -]?key|token|cookie|authorization|credential|username|scrypt|salt|wg_preshared_key|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?(?:id|token))["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'[^']*'|[^\s,;}]+)''',lambda m:m[1]+'"[REDACTED]"',text)
    # Keep harmless 'password authentication failed' lines and exit details.
    # Raw PPP option lines redact only their value, not the diagnostic suffix.
    def option(match):
        if match[2].lower() in ('authentication','required','missing','not','is','was','rejected','verification','failed'):
            return match[0]
        return match[1]+'[REDACTED]'+match[3]
    text=re.sub(r'(?im)^(\s*(?:user|username|password|passwd|secret)\s+)(\S+)(.*)$',option,text)
    long_known=[v for v in known if len(v)>=4]
    for value in sorted((v for v in known if 0<len(v)<4),key=len,reverse=True):
        text=re.sub(r'(?<!\w)'+re.escape(value)+r'(?!\w)','[REDACTED]',text)
    text='\n'.join(sanitize_diagnostic('diagnostic: '+line,long_known).removeprefix('diagnostic: ') for line in text.splitlines())
    # Covers standalone key material and truncated PEM blocks as well.
    text=re.sub(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/])','[KEY MATERIAL REDACTED]',text)
    return text


def severity(text):
    if re.search(r'fail|error|denied|refused|unavailable|exit [1-9-]',text,re.I):return 'error'
    if re.search(r'warn|timeout|disconnect|blocked|inconclusive',text,re.I):return 'warning'
    return 'info'


class EventLog:
    def __init__(self,path):
        self.path=Path(path);self.lock=threading.RLock()
        self.rows=collections.deque(maxlen=300)
        for line in read_tail(path,400000).splitlines():
            try:
                row=json.loads(line)
                if isinstance(row,dict) and row.get('component') in COMPONENTS:self.rows.append(row)
            except ValueError:pass

    def add(self,component,message,level='info',profile=None,known=(),exit_code=None,attempt_id=None,source=None):
        row={'id':uuid.uuid4().hex,'time':time.time(),'process':'pirate','pid':os.getpid(),'host':socket.gethostname(),'attempt_id':attempt_id or ATTEMPT.get(),'component':component if component in COMPONENTS else 'core',
             'severity':level,'message':sanitize(message,known)[:1200],
             'profile_id':profile.get('id') if profile else None,
             'profile':sanitize(profile.get('name',''),known)[:80] if profile else None,
             'exit_code':exit_code if isinstance(exit_code,int) else None}
        if source:
            row.update({k:v for k,v in source.items() if k in ('time','observed_at','process','pid')})
        with self.lock:
            self.rows.append(row)
            try:
                # atomic_json is for JSON objects; retain the bounded ring as JSONL.
                self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                temp=self.path.with_name(self.path.name+'.tmp')
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as stream:
                    os.fchmod(stream.fileno(),0o600)
                    stream.write(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in self.rows))
                os.replace(temp,self.path)
            except OSError:pass # Logging never alters connection lifecycle.
        return row


_LOCK=threading.RLock()

def service(app):
    with _LOCK:
        if not hasattr(app,'support'):app.support=Support(app)
        return app.support


def record(app,component,message,level='info',profile=None,exit_code=None,known=()):
    try:
        svc=service(app)
        attempt=ATTEMPT.get()
        if not attempt and profile:
            for backend in (getattr(app,'current',None),getattr(app,'previous',None)):
                if getattr(backend,'profile',{}).get('id')==profile.get('id'):
                    attempt=getattr(backend,'attempt_id',None);break
        svc.events.add(component,message,level,profile,svc.known()|secret_values(profile or {})|set(known),exit_code,attempt_id=attempt)
    except Exception:pass # Observability must not break Safe Apply/rollback.


def connection_event(fn):
    @functools.wraps(fn)
    def wrapped(self,*args,**kwargs):
        profile=None
        try:profile=self.profiles.get(args[0]) if fn.__name__=='connect' and args else getattr(self.current,'profile',None)
        except Exception:pass
        component=(profile or {}).get('type','core')
        attempt=uuid.uuid4().hex if fn.__name__=='connect' else getattr(getattr(self,'current',None),'attempt_id',None)
        token=ATTEMPT.set(attempt)
        try:
            record(self,component,f'{fn.__name__}: attempt started',profile=profile)
            try:result=fn(self,*args,**kwargs)
            except Exception as exc:
                record(self,component,f'{fn.__name__}: {type(exc).__name__}: {exc}','error',profile,known=secret_values(kwargs.get('ap_config',{})))
                raise
            record(self,component,f'{fn.__name__}: completed',profile=profile)
            return result
        finally:ATTEMPT.reset(token)
    return wrapped


def backend_evidence(app,backend,reason):
    if not backend:return
    try:
        profile=backend.profile
        process=getattr(backend,'process',None)
        code=process.poll() if process else None
        message=reason+'; process exit '+str(code if code is not None else 'not exited / not applicable')
        record(app,profile['type'],message,'error' if reason=='connection failed' else 'info',profile,code)
        if hasattr(backend,'folder'):
            text=sanitize(read_tail(backend.folder/'vpn.log',12000),secret_values(profile))
            for line in text.splitlines()[-20:]:
                pid=getattr(process,'pid',None)
                service(app).events.add(profile['type'],line,severity(line),profile,service(app).known()|secret_values(profile),code,
                    attempt_id=ATTEMPT.get() or getattr(backend,'attempt_id',None),
                    source={'time':None,'observed_at':time.time(),'process':profile['type'],'pid':pid if isinstance(pid,int) else None})
    except Exception:pass


class Support:
    def __init__(self,app):
        self.app=app;self.events=EventLog(app.directory/'support-events.jsonl')
        self.preflight=None;self.export_lock=threading.Lock();self.collection_lock=threading.Lock();self.cached=(0,[]);self.started=time.time()

    def known(self):
        values=secret_values(self.app.profiles.list(private=True))
        try:values.update(secret_values(json.loads(read_tail(self.app.profiles.path,2*1024*1024))))
        except (AttributeError,ValueError):pass
        for backend in (getattr(self.app,'current',None),getattr(self.app,'previous',None)):
            values.update(secret_values(getattr(backend,'profile',None)))
        ap=getattr(self.app,'ap',None)
        for key in ('active','saved','previous'):values.update(secret_values(getattr(ap,key,None)))
        for name in ('/etc/pirate/bootstrap-credentials.json','/etc/pirate/admin.json'):
            try:values.update(secret_values(json.loads(read_tail(name))))
            except ValueError:pass
        return values

    def rows(self):
        known=self.known()
        with self.collection_lock:
            now=time.time()
            if now-self.cached[0]>5:
                rows=[]
                sources=[]
                for component,filename,process in (('wifi','hostapd.log','hostapd'),('dns','dnsmasq.log','dnsmasq')):
                    sources.append((component,read_tail(self.app.directory/'ap'/filename),None,None,process,None))
                for backend in (getattr(self.app,'current',None),getattr(self.app,'previous',None)):
                    if backend and hasattr(backend,'folder'):
                        sources.append((backend.profile['type'],read_tail(backend.folder/'vpn.log'),backend.profile.get('id'),
                                        getattr(backend,'attempt_id',None),backend.profile['type'],getattr(getattr(backend,'process',None),'pid',None)))
                for component,text,profile,attempt,process,pid in sources:
                    for line in sanitize(text,known).splitlines()[-80:]:
                        if not line:continue
                        # Untimestamped source text has no invented event timestamp.
                        rows.append({'id':hashlib.sha256((component+line).encode()).hexdigest()[:20],
                            'time':None,'observed_at':now,'component':component,'severity':severity(line),
                            'message':line[:1200],'profile_id':profile,'attempt_id':attempt,'process':process,'pid':pid})
                for unit,component in (('pirate-ap.service','core'),('pirate-lan-block.service','firewall')):
                    result=bounded_command(['journalctl','-b','-u',unit,'--since=@'+str(int(self.started)),
                                            '-n','60','--no-pager','-o','json'])
                    for line in result['output'].splitlines():
                        try:
                            item=json.loads(line);message=item.get('MESSAGE','')
                            if not isinstance(message,str):continue
                            rows.append({'time':int(item['__REALTIME_TIMESTAMP'])/1e6,'component':component,
                                'severity':severity(message),'message':sanitize(message,known)[:1200],
                                'process':sanitize(item.get('SYSLOG_IDENTIFIER') or item.get('_COMM') or 'system',known),
                                'pid':int(item['_PID']) if str(item.get('_PID','')).isdigit() else None,
                                'host':sanitize(item.get('_HOSTNAME',''),known)})
                        except (ValueError,KeyError,TypeError):continue
                for line in read_tail('/var/log/pirate-installer.log').splitlines()[-40:]:
                    try:
                        row=json.loads(line)
                        if isinstance(row,dict) and isinstance(row.get('time'),(int,float)) and row['time']>=now-3600:rows.append(row)
                    except ValueError:pass
                self.cached=(now,rows)
            with self.events.lock:rows=[r for r in self.events.rows if (r.get('time') or r.get('observed_at',0))>=self.started]+self.cached[1]
        return [{**r,'message':sanitize(r['message'],known),'profile':sanitize(r.get('profile') or '',known)} for r in rows][-600:]

    def logs(self,filters):
        if not isinstance(filters,dict) or set(filters)-{'component','severity','profile_id','search'}:raise ValueError('Invalid log filters')
        component=filters.get('component','all');level=filters.get('severity','all');profile=filters.get('profile_id');query=filters.get('search','')
        if not isinstance(query,str) or len(query)>200:raise ValueError('Invalid log search')
        if component not in ('all',*COMPONENTS) or level not in ('all',*LEVELS):raise ValueError('Invalid log filters')
        if profile is not None:self.app.profiles.get(profile)
        rows=self.rows();attempt=None
        if profile:
            scoped=[r for r in rows if r.get('profile_id')==profile]
            attempts=[r for r in scoped if r.get('attempt_id') and r.get('time') is not None]
            if attempts:attempt=max(attempts,key=lambda r:r.get('time') or r.get('observed_at',0))['attempt_id']
            rows=[r for r in scoped if not attempt or r.get('attempt_id')==attempt]
        rows=[r for r in rows if (component=='all' or r['component']==component) and
              (level=='all' or r['severity']==level) and query.casefold() in r['message'].casefold()]
        entries=sorted(rows,key=lambda r:r.get('time') or r.get('observed_at',0))[-300:]
        return {'entries':[{**r,'line':log_line(r)} for r in entries],'limit':300,'attempt_id':attempt,'timezone':'UTC'}

    def report(self):
        from gate_core import VERSION
        known=self.known()
        logs=self.logs({})
        # Read controller attributes, never invoke active probes or app.status().
        current=getattr(self.app,'current',None)
        state={'version':VERSION,'collected_at':time.time(),'profile_id':getattr(current,'profile',{}).get('id'),
               'process_exit':getattr(current,'process',None).poll() if getattr(current,'process',None) else None,
               'last_action':self.app.last_action,'last_error':self.app.last_error,
               'last_check':self.app.last_check,'pending':bool(self.app.pending),
               'notice':'Bounded diagnostic snapshot; not proof of VPN or client connectivity.'}
        files={'summary.json':json.dumps(state,ensure_ascii=False,indent=2),
               'recent-logs.json':json.dumps(logs,ensure_ascii=False,indent=2)}
        commands={'services.txt':['systemctl','show','pirate-ap.service','pirate-lan-block.service','--property=Id,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus'],
                  'addresses.json':['ip','-j','address','show'],
                  'routes.json':['ip','-j','-4','route','show','table','all'],
                  'rules.json':['ip','-j','-4','rule','show'],
                  'firewall.txt':['nft','list','table','inet','pirate_gateway'],
                  'listeners.txt':['ss','-H','-lntu']}
        resource=getattr(current,'resource',None)
        if resource:
            from .tunnels import resource_for
            if resource==resource_for(resource['token'],resource['wan']):
                commands['tunnel-routes.json']=['ip','netns','exec',resource['namespace'],'ip','-j','-4','route','show']
                if current.profile['type']=='wireguard':
                    commands['wireguard-handshakes.txt']=['ip','netns','exec',resource['namespace'],'wg','show','wg0','latest-handshakes']
        for name,args in commands.items():files[name]=json.dumps(bounded_command(args),ensure_ascii=False)
        files['ap-state.json']=read_tail(self.app.directory/'ap'/'state.json',131072)
        files['README.txt']='Sanitized bounded snapshot. Source logs may be unavailable after cleanup. Collection timestamps are labelled; no network probe or tunnel is started.\n'
        files['dns-state.json']=read_tail(self.app.directory/'router.json')
        files['resolver.txt']=read_tail('/etc/resolv.conf')
        if self.preflight:files['preflight.json']=json.dumps(self.preflight.status())
        output=io.BytesIO()
        def clean(value):
            if isinstance(value,dict):
                from .diagnostics import SENSITIVE
                return {k:('[REDACTED]' if SENSITIVE.search(k) else clean(v)) for k,v in value.items()}
            if isinstance(value,list):return [clean(v) for v in value[:300]]
            return sanitize(value,known)[:4000] if isinstance(value,str) else value
        total=0
        with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
            for name,text in files.items():
                if name.endswith('.json'):
                    try:raw=json.dumps(clean(json.loads(text)),ensure_ascii=False,indent=2).encode()
                    except ValueError:raw=b'{"notice":"Source unavailable"}'
                    if len(raw)>450000:raw=b'{"notice":"Source omitted: size limit"}'
                else:raw=sanitize(text,known).encode()[:450000]
                total+=len(raw)
                if total>2000000:raise ValueError('Diagnostic uncompressed size limit exceeded')
                archive.writestr(name,raw)
        if output.tell()>2000000:raise ValueError('Diagnostic size limit exceeded')
        return output.getvalue()


def log_line(row):
    stamp=datetime.datetime.fromtimestamp(row['time'],datetime.timezone.utc).strftime('%b %d %H:%M:%S') if row.get('time') is not None else '--- -- --:--:--'
    process=row.get('process') or row.get('component','system')
    pid=str(row['pid']) if row.get('pid') is not None else '?'
    message=' '.join(str(row.get('message','')).splitlines())
    return f"{stamp} {row.get('host') or '-'} {process}[{pid}]: {row.get('severity','info').upper()}: {message}"
