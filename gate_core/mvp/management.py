"""Authenticated TLS management bound to an explicit interface and IPv4 address."""
import base64
import hashlib
import hmac
import json
import ipaddress
import os
from pathlib import Path
import socket
import socketserver
import ssl
import threading
import time
from http.server import ThreadingHTTPServer
from .proxy import ConnectionError

class ManagementHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.getfqdn() performs reverse DNS during bind. Management
        # must start and roll back even when upstream/system DNS is unavailable.
        socketserver.TCPServer.server_bind(self)
        self.server_name='pirate.home.arpa';self.server_port=self.server_address[1]


def private_json(path):
    path=Path(path);stat=path.stat()
    if path.is_symlink() or stat.st_mode&0o077 or stat.st_uid!=os.geteuid():
        raise ConnectionError('Management configuration must be private and owned by the runtime user')
    return json.loads(path.read_text())


class Authentication:
    def __init__(self,path):
        self.path=Path(path);self.stamp=None
        self.attempts={};self.lock=threading.Lock()
        self.refresh()

    def refresh(self):
        stat=self.path.stat();stamp=(stat.st_ino,stat.st_mtime_ns,stat.st_size)
        if stamp==self.stamp:return
        value=private_json(self.path)
        salt=bytes.fromhex(value['salt']);digest=bytes.fromhex(value['scrypt'])
        if len(salt)!=16 or len(digest)!=32:raise ConnectionError('Invalid management credentials')
        empty=hashlib.scrypt(b'',salt=salt,n=16384,r=8,p=1,dklen=32)
        with self.lock:
            self.username=value['username'];self.salt=salt;self.digest=digest
            self.bootstrap_only=hmac.compare_digest(empty,digest)
            self.password_limit=value.get('password_limit',128)
            self.attempts={};self.stamp=stamp

    def verify(self,header,peer,remote=False):
        try:self.refresh()
        except (OSError,ValueError,KeyError,ConnectionError):return False
        now=time.monotonic()
        with self.lock:
            if remote and self.bootstrap_only:return False
            salt,expected,user,limit=self.salt,self.digest,self.username,self.password_limit
            count,until=self.attempts.get(peer,(0,now+60))
            if now>until:count,until=0,now+60
            if count>=5:return False
        valid=False
        try:
            if len(header)>1024 or not header.startswith('Basic '):return False
            raw=base64.b64decode(header[6:],validate=True).decode('utf-8')
            username,password=raw.split(':',1)
            if len(password)>limit:return False
            digest=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
            valid=hmac.compare_digest(username.encode(),user.encode()) and hmac.compare_digest(digest,expected)
        except (ValueError,UnicodeError):pass
        with self.lock:
            if len(self.attempts)>256:self.attempts.clear()
            if valid:self.attempts.pop(peer,None)
            else:self.attempts[peer]=(count+1,until)
        return valid


class Management:
    def __init__(self,app):
        self.app=app;self.server=None;self.thread=None;self.config=None
        path=os.environ.get('PIRATE_DEPLOYMENT_CONFIG')
        if path:
            self.config=private_json(path)
            self.auth=Authentication(self.config['auth_file'])
            if self.config['management_port']!=8766:raise ConnectionError('Management port must be 8766')

    def start(self,address,interface,port=None,subnet=None,names=None):
        if not self.config:return
        self.auth.refresh()
        if self.auth.bootstrap_only:return
        from .management_runtime import ensure_certificate,CERTIFICATE_LOCK
        port=port or self.config['management_port']
        if subnet:ipaddress.IPv4Network(subnet)
        from web.server import Handler
        server=ManagementHTTPServer((address,port),Handler,bind_and_activate=False)
        server.daemon_threads=True
        try:
            server.socket.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
            server.server_bind();server.server_activate()
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            with CERTIFICATE_LOCK:
                ensure_certificate(self.config,address)
                context.load_cert_chain(self.config['tls_cert'],self.config['tls_key'])
                server.tls_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(self.config['tls_cert']).read_text())).hexdigest()
            server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
            server.management={'authorities':[host+':'+str(port) for host in [address,*(names if names is not None else ['pirate.home.arpa'])]],'scheme':'https'}
            server.remote_management=True;server.allowed_subnet=subnet
            server.auth=self.auth;server.pirate_app=self.app
            self.server=server;self.thread=threading.Thread(target=server.serve_forever,daemon=True);self.thread.start()
        except Exception:
            server.server_close();raise

    def stop(self):
        if self.server:
            self.server.shutdown();self.server.server_close();self.server=None
