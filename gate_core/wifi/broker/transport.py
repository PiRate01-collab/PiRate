"""One bounded JSON frame per Linux Unix-stream connection. No TCP or subprocess."""
import errno
import json
import math
import os
import socket
import stat
import struct
import time
from collections import deque
from ..system.storage import PrivateRecords,FoundationError
from .contracts import BrokerError,PeerIdentity,public_response
from .core import BrokerCore

MAX_MESSAGE=4096
SOCKET_NAME='broker.sock'


def encode_frame(data):
    raw=json.dumps(data,separators=(',',':'),allow_nan=False).encode('utf-8')
    if len(raw)>MAX_MESSAGE:raise BrokerError('message_too_large')
    return struct.pack('!I',len(raw))+raw


def peer_identity(connection):
    if not hasattr(socket,'SO_PEERCRED'):raise BrokerError('identity_unavailable')
    try:
        raw=connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
        pid,uid,gid=struct.unpack('3i',raw)
        if uid<0 or gid<0:raise ValueError()
        return PeerIdentity(pid,uid,gid)
    except (OSError,ValueError,struct.error):raise BrokerError('identity_unavailable') from None


def remaining(connection,deadline):
    seconds=deadline-time.monotonic()
    if seconds<=0:raise BrokerError('timeout')
    connection.settimeout(seconds)


def receive_exact(connection,length,deadline):
    data=bytearray()
    while len(data)<length:
        remaining(connection,deadline)
        try:chunk=connection.recv(length-len(data))
        except TimeoutError:raise BrokerError('timeout') from None
        except OSError:raise BrokerError('disconnected') from None
        if not chunk:raise BrokerError('disconnected')
        data.extend(chunk)
    return bytes(data)


def receive_request(connection,deadline):
    length=struct.unpack('!I',receive_exact(connection,4,deadline))[0]
    if not 1<=length<=MAX_MESSAGE:raise BrokerError('message_too_large')
    raw=receive_exact(connection,length,deadline)
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise BrokerError('invalid_json')
            result[key]=value
        return result
    def invalid_constant(_):raise BrokerError('invalid_json')
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=invalid_constant)
    except (ValueError,UnicodeError,RecursionError):raise BrokerError('invalid_json') from None


class UnixBroker:
    def __init__(self,core,socket_directory,*,timeout=2.0,backlog=8):
        if type(core) is not BrokerCore:raise BrokerError('dry_run_only')
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not .02<=timeout<=10 or type(backlog) is not int or not 1<=backlog<=16:
            raise BrokerError('invalid_transport')
        self.core=core
        self.storage=PrivateRecords(socket_directory)
        self.path=self.storage.root/SOCKET_NAME
        self.timeout,self.backlog=timeout,backlog
        self.listener=None
        self._guard=None
        self._identity=None
        self.events=deque(maxlen=64)  # Fixed error codes only, never request/exception text.

    @staticmethod
    def _safe_socket(info):
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077:
            raise BrokerError('socket_ownership_unknown')

    def _remove_stale(self,directory):
        try:info=os.stat(SOCKET_NAME,dir_fd=directory,follow_symlinks=False)
        except FileNotFoundError:return
        self._safe_socket(info)
        # Catalog flock plus kernel connect refusal, not PID/name, establishes staleness.
        probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            probe.settimeout(self.timeout)
            try:probe.connect(f'/proc/self/fd/{directory}/{SOCKET_NAME}')
            except OSError as exc:
                if exc.errno!=errno.ECONNREFUSED:raise BrokerError('socket_busy') from None
            else:raise BrokerError('socket_busy')
        finally:probe.close()
        current=os.stat(SOCKET_NAME,dir_fd=directory,follow_symlinks=False)
        self._safe_socket(current)
        if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):raise BrokerError('socket_ownership_unknown')
        os.unlink(SOCKET_NAME,dir_fd=directory)

    def start(self):
        if self.listener is not None:raise BrokerError('socket_busy')
        guard=self.storage.lock();guard.__enter__()
        listener=None
        try:
            self.core.recover_after_restart()
            with self.storage.directory() as directory:
                self._remove_stale(directory)
                listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                # bind is anchored to a pinned catalog FD, never a client-supplied path.
                listener.bind(f'/proc/self/fd/{directory}/{SOCKET_NAME}')
                info=os.stat(SOCKET_NAME,dir_fd=directory,follow_symlinks=False)
                self._identity=(info.st_dev,info.st_ino)
                os.chmod(SOCKET_NAME,0o600,dir_fd=directory,follow_symlinks=False)
                self._safe_socket(os.stat(SOCKET_NAME,dir_fd=directory,follow_symlinks=False))
                listener.listen(self.backlog);listener.settimeout(.1)
            self.listener,self._guard=listener,guard
        except BaseException:
            if listener is not None:listener.close()
            self._unlink_owned()
            guard.__exit__(None,None,None)
            raise
        return self

    def _unlink_owned(self):
        if self._identity is None:return
        try:
            with self.storage.directory() as directory:
                info=os.stat(SOCKET_NAME,dir_fd=directory,follow_symlinks=False)
                self._safe_socket(info)
                if (info.st_dev,info.st_ino)==self._identity:
                    os.unlink(SOCKET_NAME,dir_fd=directory)
        except (OSError,FoundationError,BrokerError):
            pass  # Never remove an unknown/replaced object, leave it for operator review.
        self._identity=None

    def close(self):
        if self.listener is not None:
            self.listener.close();self.listener=None
        self._unlink_owned()
        if self._guard is not None:
            self._guard.__exit__(None,None,None);self._guard=None

    def handle(self,connection):
        deadline=time.monotonic()+self.timeout
        try:
            peer=peer_identity(connection)
            self.core.policy.authenticate(peer)  # Before reading untrusted message bytes.
            request=receive_request(connection,deadline)
            response=public_response(self.core.dispatch(peer,request))
        except BrokerError as exc:
            self.events.append(exc.code)
            response={'ok':False,'error':exc.code,'dry_run':True,'real_execution_available':False}
        except TimeoutError:
            self.events.append('busy')
            response={'ok':False,'error':'busy','dry_run':True,'real_execution_available':False}
        except (FoundationError,OSError):
            self.events.append('recovery_required')
            response={'ok':False,'error':'recovery_required','dry_run':True,'real_execution_available':False}
        except Exception:
            self.events.append('internal_error')
            response={'ok':False,'error':'internal_error','dry_run':True,'real_execution_available':False}
        try:
            remaining(connection,deadline)
            connection.sendall(encode_frame(response))
        except (OSError,BrokerError):pass
        finally:connection.close()  # Every request/error terminates the connection.

    def serve_once(self):
        if self.listener is None:raise BrokerError('not_listening')
        try:connection,_=self.listener.accept()
        except TimeoutError:return False
        self.handle(connection)
        return True

    def serve_forever(self,stop_event):
        try:
            while not stop_event.is_set():self.serve_once()
        finally:self.close()

    def __enter__(self):return self.start()
    def __exit__(self,*_):self.close()
