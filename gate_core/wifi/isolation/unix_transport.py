"""Linux pathname AF_UNIX RPC, bounded and explicitly authenticated both ways.

Supplementary groups only permit filesystem traversal; never authorize RPC.
One synchronous worker, bounded backlog, one frame/connection and total deadline.
"""
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat
import time
import uuid
from ..broker.contracts import BrokerError
from ..broker.transport import encode_frame, peer_identity, receive_request, remaining


def authenticate(connection, subjects):
    peer = peer_identity(connection)
    if (peer.uid, peer.gid) not in subjects:
        raise BrokerError('identity_denied')
    return peer


def open_directory(path, owner, group, mode):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise BrokerError('socket_ownership_unknown')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            if info.st_uid not in (0, owner):
                raise BrokerError('socket_ownership_unknown')
            if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise BrokerError('socket_ownership_unknown')
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (owner, group, mode):
            raise BrokerError('socket_ownership_unknown')
        return fd
    except BaseException:
        os.close(fd)
        raise


class PathRPCServer:
    def __init__(self, directory, handler, subjects, *, group=None, timeout=.5, backlog=8, tick=None, clock=time.monotonic, tick_interval=.05):
        if not .05 <= timeout <= 2 or type(backlog) is not int or not 1 <= backlog <= 16:
            raise BrokerError('invalid_transport')
        if not .01 <= tick_interval <= 2:
            raise BrokerError('invalid_transport')
        self.clock, self.tick_interval, self.next_tick = clock, tick_interval, None
        self.owner = os.geteuid()
        self.group = os.getegid() if group is None else group
        self.mode = 0o700 if group is None else 0o710
        self.socket_mode = 0o600 if group is None else 0o660
        self.directory = Path(directory).absolute()
        self.handler, self.subjects, self.tick = handler, frozenset(subjects), tick
        if not self.subjects or any(len(s) != 2 or any(type(n) is not int or n < 0 for n in s) for s in self.subjects):
            raise BrokerError('invalid_policy')
        self.timeout, self.backlog = timeout, backlog
        self.fd = self.lock_fd = self.listener = self.identity = None

    def _socket_info(self):
        info = os.stat('rpc.sock', dir_fd=self.fd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_nlink != 1 or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (self.owner, self.group, self.socket_mode):
            raise BrokerError('socket_ownership_unknown')
        return info.st_dev, info.st_ino

    def start(self):
        try:
            self.fd = open_directory(self.directory, self.owner, self.group, self.mode)
            self.lock_fd = os.open('.listener.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise BrokerError('socket_ownership_unknown')
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BrokerError('socket_busy') from None
            address = f'/proc/self/fd/{self.fd}/rpc.sock'
            try:
                stale = self._socket_info()
            except FileNotFoundError:
                stale = None
            if stale:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(self.timeout)
                    try:
                        probe.connect(address)
                    except OSError as exc:
                        if exc.errno != errno.ECONNREFUSED:
                            raise BrokerError('socket_busy') from None
                    else:
                        raise BrokerError('socket_busy')
                if self._socket_info() != stale:
                    raise BrokerError('socket_ownership_unknown')
                os.unlink('rpc.sock', dir_fd=self.fd)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(address)
            info = os.stat('rpc.sock', dir_fd=self.fd, follow_symlinks=False)
            self.identity = info.st_dev, info.st_ino
            os.chown('rpc.sock', self.owner, self.group, dir_fd=self.fd, follow_symlinks=False)
            os.chmod('rpc.sock', self.socket_mode, dir_fd=self.fd, follow_symlinks=False)
            self._socket_info()
            self.listener.listen(self.backlog)
            self.listener.settimeout(.05)
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if self.fd is not None:
            if self.identity:
                try:
                    if self._socket_info() == self.identity:
                        os.unlink('rpc.sock', dir_fd=self.fd)
                except (OSError, BrokerError):
                    pass
            os.close(self.fd)
            self.fd = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        self.identity = None

    def handle(self, connection):
        deadline = time.monotonic() + self.timeout
        nonce = None
        try:
            peer = authenticate(connection, self.subjects)
            request = receive_request(connection, deadline)
            if not isinstance(request, dict) or type(request.get('nonce')) is not str:
                raise BrokerError('invalid_request')
            from ..models import profile_id
            try:
                nonce = profile_id(request['nonce'])
            except ValueError:
                raise BrokerError('invalid_request') from None
            result = self.handler(peer, request)
            reply = {'ok': True, 'result': result, 'nonce': nonce, 'dry_run': True}
        except BrokerError as exc:
            if exc.code == 'disconnected':
                connection.close()
                return  # Passive EOF never dispatches or sends a JSON response.
            reply = {'ok': False, 'error': exc.code, 'nonce': nonce, 'dry_run': True}
        except TimeoutError:
            reply = {'ok': False, 'error': 'busy', 'nonce': nonce, 'dry_run': True}
        except Exception:
            reply = {'ok': False, 'error': 'recovery_required', 'nonce': nonce, 'dry_run': True}
        try:
            remaining(connection, deadline)
            connection.sendall(encode_frame(reply))
        except (OSError, BrokerError):
            pass
        finally:
            connection.close()

    def scheduled_tick(self):
        """Clock-driven recovery. Connection count never advances the schedule."""
        if self.tick is None:
            return
        now = self.clock()
        if self.next_tick is None:
            self.next_tick = now + self.tick_interval
        if now >= self.next_tick:
            self.tick()
            # Fixed clock slots; skip missed slots rather than running a burst.
            slots = int((now - self.next_tick) / self.tick_interval) + 1
            self.next_tick += slots * self.tick_interval

    def serve(self, stop):
        try:
            self.scheduled_tick()  # Establish timer without a startup tick.
            while not stop.is_set():
                self.scheduled_tick()
                wait = .05 if self.next_tick is None else min(.05, max(.001, self.next_tick - self.clock()))
                self.listener.settimeout(wait)
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                self.handle(connection)
        finally:
            self.close()


class PathRPCClient:
    def __init__(self, directory, *, server_uid, server_gid, directory_gid=None, timeout=.5):
        self.directory = directory
        self.subject = (server_uid, server_gid)
        self.group = server_gid if directory_gid is None else directory_gid
        self.mode = 0o700 if directory_gid is None else 0o710
        if not .05 <= timeout <= 2:
            raise BrokerError('invalid_transport')
        self.timeout = timeout

    def call(self, request):
        fd = open_directory(self.directory, self.subject[0], self.group, self.mode)
        try:
            info = os.stat('rpc.sock', dir_fd=fd, follow_symlinks=False)
            expected_mode = 0o600 if self.mode == 0o700 else 0o660
            if not stat.S_ISSOCK(info.st_mode) or info.st_nlink != 1 or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (self.subject[0], self.group, expected_mode):
                raise BrokerError('socket_ownership_unknown')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                deadline = time.monotonic() + self.timeout
                remaining(connection, deadline)
                connection.connect(f'/proc/self/fd/{fd}/rpc.sock')
                authenticate(connection, {self.subject})
                nonce = str(uuid.uuid4())
                connection.sendall(encode_frame({**request, 'nonce': nonce}))
                reply = receive_request(connection, deadline)
                if not isinstance(reply, dict) or type(reply.get('ok')) is not bool or reply.get('dry_run') is not True or reply.get('nonce') != nonce:
                    raise BrokerError('invalid_request')
                if reply['ok']:
                    if set(reply) != {'ok', 'result', 'nonce', 'dry_run'} or not isinstance(reply['result'], dict):
                        raise BrokerError('invalid_request')
                    return reply['result']
                if set(reply) != {'ok', 'error', 'nonce', 'dry_run'}:
                    raise BrokerError('invalid_request')
                raise BrokerError(reply['error'])
        finally:
            os.close(fd)


def namespace_identity(pid):
    """Best-effort observation only; namespace visibility never authorizes RPC."""
    try:
        return {'id': os.readlink('/proc/' + str(pid) + '/ns/net'), 'available': True}
    except OSError:
        return {'id': None, 'available': False}


def passive_transport(directory, *, server_uid, server_gid, directory_gid=None, timeout=.5, server_pid=None):
    """Connect, authenticate server via kernel, close. Sends zero bytes.

    Does not prove that the server accepted the client's allowlist identity.
    Requires the new clock-driven server to avoid connection-triggered tick.
    """
    if any(type(value) is not int or value < 0 for value in (server_uid, server_gid)) or (directory_gid is not None and (type(directory_gid) is not int or directory_gid < 0)):
        raise BrokerError('invalid_transport')
    client = PathRPCClient(directory, server_uid=server_uid, server_gid=server_gid, directory_gid=directory_gid, timeout=timeout)
    if server_pid is not None and (type(server_pid) is not int or server_pid <= 0):
        raise BrokerError('invalid_transport')
    fd = open_directory(directory, server_uid, client.group, client.mode)
    try:
        info = os.stat('rpc.sock', dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_nlink != 1 or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (server_uid, client.group, 0o600 if client.mode == 0o700 else 0o660):
            raise BrokerError('socket_ownership_unknown')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            remaining(channel, time.monotonic() + timeout)
            channel.connect(f'/proc/self/fd/{fd}/rpc.sock')
            peer = authenticate(channel, {(server_uid, server_gid)})
            if server_pid is not None and peer.pid != server_pid:
                raise BrokerError('identity_denied')
            result = {'server': {'pid': peer.pid, 'uid': peer.uid, 'gid': peer.gid}, 'client': {'pid': os.getpid(), 'uid': os.geteuid(), 'gid': os.getegid()}, 'network_namespaces': {'client': namespace_identity(os.getpid()), 'server': namespace_identity(peer.pid)}, 'namespace_observation': 'best_effort_not_authorization', 'bytes_sent': 0, 'rpc_dispatched': False, 'server_identity_verified': True, 'client_authorization': 'not_attested', 'daemon_origin': 'probe_process_not_broker_daemon', 'persistent_state_inspected': False, 'background_recovery_may_change_state': True}
            channel.shutdown(socket.SHUT_WR)
            return result
    finally:
        os.close(fd)
