"""Linux flock ownership; caller supplies a private runtime directory."""
import fcntl
import math
import os
from pathlib import Path
import stat
import time


class LockTimeout(TimeoutError):
    pass


class ProcessLock:
    def __init__(self, path, timeout=0):
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
            raise ValueError('Invalid lock timeout')
        self.path = Path(path)
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        if self.fd is not None:
            raise RuntimeError('Lock instance already held')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            os.close(fd)
            raise ValueError('Unsafe lock file')
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.fd = fd
                    return self
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise LockTimeout('Connection operation lock busy') from None
                    time.sleep(min(.01, max(0, deadline - time.monotonic())))
        except BaseException:
            os.close(fd)
            raise

    def __exit__(self, *args):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        # Never unlink: replacement would allow concurrent holders of different inodes.
