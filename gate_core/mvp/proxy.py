"""Real TCP proxy transport: upstream DNS, auth, HTTP forwarding and CONNECT."""
import base64
import http.client
import ipaddress
import select
import socket
import socketserver
import ssl
import struct
import threading
import time
from urllib.parse import urlsplit

class ConnectionError(RuntimeError):
    pass

def exact(sock, size):
    raw = b''
    while len(raw) < size:
        chunk = sock.recv(size - len(raw))
        if not chunk:
            raise ConnectionError('Proxy closed the connection')
        raw += chunk
    return raw

def authority(host, port):
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'

def socks_connect(sock, host, port, username='', password=''):
    authenticated = bool(username)
    sock.sendall(b'\x05\x01' + (b'\x02' if authenticated else b'\x00'))
    if exact(sock, 2) != b'\x05' + (b'\x02' if authenticated else b'\x00'):
        raise ConnectionError('SOCKS5 authentication method rejected')
    if authenticated:
        u, p = username.encode(), password.encode()
        sock.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if exact(sock, 2) != b'\x01\x00':
            raise ConnectionError('SOCKS5 credentials rejected')
    try:
        ip = ipaddress.ip_address(host)
        address = (b'\x01' if ip.version == 4 else b'\x04') + ip.packed
    except ValueError:
        name = host.encode('idna')
        if not 1 <= len(name) <= 255:
            raise ConnectionError('Invalid destination name')
        address = b'\x03' + bytes([len(name)]) + name
    sock.sendall(b'\x05\x01\x00' + address + struct.pack('!H', port))
    reply = exact(sock, 4)
    if reply[:3] != b'\x05\x00\x00':
        raise ConnectionError('SOCKS5 destination rejected')
    length = {1:4, 4:16}.get(reply[3])
    if reply[3] == 3:
        length = exact(sock, 1)[0]
    if length is None:
        raise ConnectionError('Invalid SOCKS5 reply')
    exact(sock, length + 2)
    return sock

class ProxyBackend:
    scope = 'LOCAL_PROXY'
    def __init__(self, profile):
        self.profile = profile
        self.kind = profile['type']
        self.socket_lock = threading.Lock()
        self.sockets = set()
        self.stopped = False
        self.outbound_interface = None
        self.endpoint_ip = None

    def auth_header(self):
        if not self.profile.get('username'):
            return b''
        credentials = (self.profile['username'] + ':' + self.profile.get('password','')).encode()
        return b'Proxy-Authorization: Basic ' + base64.b64encode(credentials) + b'\r\n'

    def track(self, sock):
        with self.socket_lock:
            if self.stopped:
                sock.close()
                raise ConnectionError('Connection has been disconnected')
            self.sockets.add(sock)
        return sock

    def release(self, sock):
        with self.socket_lock:self.sockets.discard(sock)
        sock.close()

    def upstream(self):
        if not self.profile['server'] or not self.profile['port']:
            raise ConnectionError('Set proxy server and port')
        # Resolve only during bootstrap; active proxy requests reuse the verified
        # endpoint IP instead of sending repeated host DNS queries on the WAN.
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,0,'',(self.endpoint_ip,self.profile['port']))] if self.endpoint_ip else socket.getaddrinfo(self.profile['server'],self.profile['port'],socket.AF_INET,socket.SOCK_STREAM)
        for family,kind,protocol,_,address in addresses:
            sock=socket.socket(family,kind,protocol);sock.settimeout(8)
            try:
                if self.outbound_interface:sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,self.outbound_interface.encode()+b'\0')
                sock.connect(address);self.endpoint_ip=address[0]
                return self.track(sock)
            except OSError:sock.close()
        raise ConnectionError('Upstream unavailable on configured WAN interface')

    def open(self, host, port):
        sock = self.upstream()
        try:
            if self.kind == 'socks5':
                return socks_connect(sock, host, port, self.profile.get('username',''), self.profile.get('password',''))
            address = authority(host, port).encode('ascii')
            sock.sendall(b'CONNECT ' + address + b' HTTP/1.1\r\nHost: ' + address + b'\r\n' + self.auth_header() + b'\r\n')
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                header += exact(sock, 1)
                if len(header) > 16384:
                    raise ConnectionError('Proxy response headers too large')
            first = header.split(b'\r\n',1)[0].split()
            if len(first) < 2 or first[1] != b'200':
                raise ConnectionError('HTTP CONNECT rejected')
            return sock
        except Exception:
            self.release(sock)
            raise

    def request(self, url):
        parsed = urlsplit(url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ConnectionError('Check URL must be HTTP(S) without credentials or fragment')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        # HTTP proxies receive an absolute URI for plain HTTP, avoiding local DNS.
        plain_forward = self.kind == 'http' and parsed.scheme == 'http'
        sock = self.upstream() if plain_forward else self.open(parsed.hostname, port)
        try:
            if parsed.scheme == 'https':
                plain = sock
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
                with self.socket_lock:self.sockets.discard(plain)
                self.track(sock)
            target = url if plain_forward else (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
            request = f'GET {target} HTTP/1.1\r\nHost: {authority(parsed.hostname,port)}\r\nConnection: close\r\n'.encode('ascii')
            sock.sendall(request + (self.auth_header() if plain_forward else b'') + b'\r\n')
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read(65537)
            if not 200 <= response.status < 300:
                raise ConnectionError('Connectivity check returned HTTP ' + str(response.status))
            if len(body) > 65536:
                raise ConnectionError('Check response exceeds 64 KiB')
            return {'status':'PASS', 'http_status':response.status, 'body':body.decode('utf-8',errors='replace')[:512], 'url':url, 'checked_at':time.time()}
        finally:
            self.release(sock)

    def observed(self):
        return {'backend':self.kind, 'transport':'TCP upstream with remote destination DNS', 'scope':self.scope, 'outbound_interface':self.outbound_interface}

    def stop(self):
        with self.socket_lock:
            self.stopped = True
            sockets = list(self.sockets)
            self.sockets.clear()
        for sock in sockets:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            sock.close()

def relay(left, right):
    left.settimeout(None)
    right.settimeout(None)
    while True:
        readable, _, _ = select.select([left, right], [], [], 60)
        if not readable:
            return
        for source in readable:
            raw = source.recv(65536)
            if not raw:
                return
            (right if source is left else left).sendall(raw)

class Gateway(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, address, backend):
        self.backend = backend
        self.bytes_sent = 0
        super().__init__(address, GatewayHandler)

class GatewayHandler(socketserver.StreamRequestHandler):
    def handle(self):
        upstream = None
        backend = None
        responded = False
        try:
            self.request.settimeout(10)
            line = self.rfile.readline(8193)
            if len(line) > 8192:
                raise ConnectionError('Request line too long')
            method, target, version = line.decode('ascii').strip().split(' ')
            headers = []
            total = 0
            while True:
                raw = self.rfile.readline(8193)
                total += len(raw)
                if not raw or total > 32768:
                    raise ConnectionError('Invalid headers')
                if raw == b'\r\n':
                    break
                if b':' not in raw:
                    raise ConnectionError('Invalid header')
                key, value = raw.split(b':',1)
                if key.lower() not in (b'proxy-authorization', b'proxy-connection', b'connection'):
                    headers.append((key, value.strip()))
            backend = self.server.backend()
            if backend is None:
                raise ConnectionError('No active connection; direct fallback disabled')
            if method == 'CONNECT':
                parsed = urlsplit('//'+target)
                if not parsed.hostname or not parsed.port:
                    raise ConnectionError('CONNECT requires host:port')
                upstream = backend.open(parsed.hostname, parsed.port)
                self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                self.wfile.flush()
                responded = True
                # rfile must be unbuffered so pipelined TLS bytes remain on socket.
                relay(self.request, upstream)
            else:
                if method not in ('GET','HEAD','POST','PUT','DELETE','PATCH','OPTIONS'):
                    raise ConnectionError('Unsupported HTTP method')
                parsed = urlsplit(target)
                if parsed.scheme != 'http' or not parsed.hostname or parsed.username or parsed.password:
                    raise ConnectionError('Use an absolute HTTP URI or HTTPS CONNECT')
                if any(k.lower()==b'transfer-encoding' for k,v in headers):
                    raise ConnectionError('Chunked request bodies are not supported')
                lengths = [v for k,v in headers if k.lower()==b'content-length']
                if len(lengths)>1:
                    raise ConnectionError('Duplicate Content-Length')
                size = int(lengths[0]) if lengths else 0
                if not 0 <= size <= 1048576:
                    raise ConnectionError('Request body exceeds 1 MiB')
                body = self.rfile.read(size)
                if len(body)!=size:
                    raise ConnectionError('Incomplete request body')
                forward = backend.kind == 'http'
                upstream = backend.upstream() if forward else backend.open(parsed.hostname, parsed.port or 80)
                path = target if forward else (parsed.path or '/') + ('?'+parsed.query if parsed.query else '')
                header = f'{method} {path} HTTP/1.1\r\n'.encode('ascii')
                # Host always follows URI; never forward a conflicting user header.
                headers = [(k,v) for k,v in headers if k.lower()!=b'host']
                header += b'Host: '+authority(parsed.hostname,parsed.port or 80).encode('ascii')+b'\r\n'
                header += b''.join(k+b': '+v+b'\r\n' for k,v in headers)
                header += b'Connection: close\r\n'+(backend.auth_header() if forward else b'')+b'\r\n'
                upstream.sendall(header+body)
                responded = True
                while True:
                    raw = upstream.recv(65536)
                    if not raw:
                        break
                    self.wfile.write(raw)
                    self.server.bytes_sent += len(raw)
        except (OSError, ValueError, ConnectionError):
            if not responded:
                try:self.wfile.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 42\r\nConnection: close\r\n\r\nPiRate connection unavailable; no fallback')
                except OSError:pass
        finally:
            if upstream is not None:
                backend.release(upstream)
    rbufsize = 0


class DirectBackend(ProxyBackend):
    """Explicit Direct transport. Kernel forwarding is scoped by RouterGateway NAT."""
    scope='DIRECT'
    def __init__(self,profile):
        super().__init__(profile);self.kind='direct';self.endpoint_ip='1.1.1.1'

    def open(self,host,port):
        addresses=socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM)
        for family,kind,protocol,_,address in addresses:
            sock=socket.socket(family,kind,protocol);sock.settimeout(8)
            try:
                if self.outbound_interface:sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,self.outbound_interface.encode()+b'\0')
                sock.connect(address);return self.track(sock)
            except OSError:sock.close()
        raise ConnectionError('Direct: WAN недоступен')

    def observed(self):
        return {'backend':'direct','alive':not self.stopped,'outbound_interface':self.outbound_interface,'scope':self.scope}
