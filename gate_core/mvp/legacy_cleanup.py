"""Removal-only recovery of recorded pre-upgrade session files. No VPN runtime."""
from pathlib import Path

def remove_files(folder):
    directory=Path(folder)/'ppp'
    for name in ('options','resolv.conf'):
        (directory/name).unlink(missing_ok=True)
    directory.rmdir()
