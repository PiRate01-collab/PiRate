"""Private Unix socket -> TCP bridge; DNS runs inside the tunnel namespace."""
import os
import socket
import socketserver
import struct
import sys
from pathlib import Path
from gate_core.mvp.proxy import exact, relay

class Bridge(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        remote = None
        try:
            self.request.settimeout(10)
            if exact(self.request,3)!=b'\x05\x01\x00':return
            self.request.sendall(b'\x05\x00')
            header=exact(self.request,4)
            if header[:3]!=b'\x05\x01\x00':return
            if header[3]==1:host=socket.inet_ntop(socket.AF_INET,exact(self.request,4))
            elif header[3]==4:host=socket.inet_ntop(socket.AF_INET6,exact(self.request,16))
            elif header[3]==3:host=exact(self.request,exact(self.request,1)[0]).decode('idna')
            else:return
            port=struct.unpack('!H',exact(self.request,2))[0]
            remote=socket.create_connection((host,port),timeout=8)
            self.request.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            relay(self.request,remote)
        except (OSError,ValueError,RuntimeError):
            try:self.request.sendall(b'\x05\x01\x00\x01'+b'\0'*6)
            except OSError:pass
        finally:
            if remote:remote.close()

def main():
    path=Path(sys.argv[1])
    os.umask(0o077)
    with Bridge(str(path),Handler) as server:
        os.chmod(path,0o600)
        server.serve_forever()
if __name__=='__main__':main()
