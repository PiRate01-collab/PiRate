"""Private dry-run records; all operations relative to pinned directory FDs."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid
from contextlib import contextmanager
from ...journal import canonical
from ...process_lock import LockTimeout
import fcntl
from ..models import profile_id


class FoundationError(ValueError):
    """Safe diagnostic only, never interpolate input or exception text."""


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


class PrivateRecords:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if '..' in self.root.parts:
            raise FoundationError('Private storage traversal denied')
        self.identity = None
        with self.directory(create=True):
            pass

    @contextmanager
    def directory(self, *, create=False):
        # Each ancestor opened with NOFOLLOW; later reads/renames use this inode,
        # never resolve the path again during a record operation.
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in self.root.parts[1:]:
                try:
                    new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, 0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                    new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd);fd = new
            info = os.fstat(fd)
            identity=(info.st_dev,info.st_ino)
            if self.identity is not None and identity!=self.identity:
                raise FoundationError('Private storage inode changed')
            self.identity=identity
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise FoundationError('Private storage ownership unknown')
            yield fd
        except TimeoutError:
            raise  # Lock contention is retryable, not evidence of corrupt ownership.
        except OSError:
            raise FoundationError('Private dry-run storage unavailable') from None
        finally:
            os.close(fd)

    @contextmanager
    def lock(self):
        with self.directory() as directory:
            fd=os.open('.lock',os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,0o600,dir_fd=directory)
            try:
                self._safe(os.fstat(fd))
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise LockTimeout('Dry-run operation busy') from None
                yield
            finally:
                os.close(fd)  # Kernel releases the lock even after process termination.

    @staticmethod
    def _safe(info):
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise FoundationError('Record ownership or permissions unknown')

    def read(self, identifier):
        name = profile_id(identifier) + '.json'
        with self.directory() as directory:
            # Replace can unlink an open snapshot; no-clobber publication can
            # briefly have two links. Reopen, retaining every safety guard.
            for attempt in range(8):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                except FileNotFoundError:
                    raise FoundationError('Required dry-run record missing') from None
                with os.fdopen(fd, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if info.st_nlink != 1 and attempt < 7:
                        # Let a preempted publisher finish removing its temporary
                        # link. Persistent hardlinks still fail the strict guard.
                        time.sleep(0.001 * (2 ** attempt))
                        continue
                    # Validate the same stat snapshot used for the link check:
                    # another fstat here would introduce the replacement race again.
                    self._safe(info)
                    raw = stream.read(131073)
                    break
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise FoundationError('Duplicate record field')
                    result[key] = value
                return result
            try:
                data = json.loads(raw, object_pairs_hook=unique)
                if len(raw) > 131072 or not isinstance(data, dict) or set(data) != {'data','sha256'} or data['sha256'] != digest(data['data']):
                    raise ValueError()
                return data['data']
            except (ValueError, TypeError, RecursionError):
                raise FoundationError('Record integrity unknown') from None

    def exists(self, identifier):
        with self.directory() as directory:
            try:
                info = os.stat(profile_id(identifier) + '.json', dir_fd=directory, follow_symlinks=False)
                self._safe(info)
                return True
            except FileNotFoundError:
                return False

    def write(self, identifier, data, *, create=False):
        name = profile_id(identifier) + '.json'
        raw = canonical({'data':data, 'sha256':digest(data)})
        if len(raw) > 131072:
            raise FoundationError('Dry-run record too large')
        with self.directory() as directory:
            temporary = '.pending-' + str(uuid.uuid4())
            try:
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    self._safe(info)
                    if create:
                        raise FoundationError('Dry-run record ID collision')
                except FileNotFoundError:
                    pass
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                with os.fdopen(fd, 'wb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(raw);stream.flush();os.fsync(stream.fileno())
                if create:
                    # Atomic no-clobber publication, even against same-ID writers.
                    os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                    os.unlink(temporary, dir_fd=directory)
                else:
                    os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            except OSError:
                raise FoundationError('Record persistence ambiguous; recovery required') from None
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def identifiers(self):
        with self.directory() as directory:
            names = os.listdir(directory)
        result = []
        for name in names:
            if name.startswith('.pending-') or name=='.lock':
                continue  # Inert, never commands and never used as completed records.
            if not name.endswith('.json'):
                raise FoundationError('Unknown private record')
            result.append(profile_id(name[:-5]))
        return sorted(result)
