#!/usr/bin/env python3
"""Safely manage the loopback PiRate WebUI; never terminate untracked port owners."""
import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

SERVER = (Path(__file__).resolve().parent / 'server.py').resolve()
RUNDIR = Path.home() / '.local' / 'state' / 'gate-native'
PIDFILE = RUNDIR / 'web-preview.pid'
HOST = '127.0.0.1'

def port():
    return int(os.environ.get('GATE_WEB_PORT', '8765'))

def proc_info(pid):
    """Return cmdline and state for same-user processes; None if not visible."""
    try:
        args = [a.decode(errors='replace') for a in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') if a]
        state = Path(f'/proc/{pid}/status').read_text().split('State:',1)[1].splitlines()[0].strip()
        return {'pid':pid,'args':args,'state':state}
    except (OSError, ValueError, IndexError):
        return None

def is_ours(pid):
    info = proc_info(pid)
    if not info or len(info['args']) < 2 or not info['args'][0]:
        return False
    # Match either python /absolute/path/server.py or python web/server.py in this repository.
    for arg in info['args'][1:]:
        if arg.endswith('server.py'):
            try:
                if Path(arg).is_absolute() and Path(arg).resolve() == SERVER:
                    return True
            except OSError:
                pass
    return False

def tracked_pid():
    try: pid = int(PIDFILE.read_text().strip())
    except (ValueError,OSError): return None
    return pid if is_ours(pid) else None

def port_owner():
    """Discover listening inode and process via /proc (Linux); never infer from filename alone."""
    target = f'{port():04X}'
    inodes = set()
    for path in ('/proc/net/tcp','/proc/net/tcp6'):
        try:
            for line in Path(path).read_text().splitlines()[1:]:
                parts=line.split()
                if len(parts)>9 and parts[1].rsplit(':',1)[-1].upper()==target and parts[3]=='0A':
                    inodes.add(parts[9])
        except OSError: pass
    if not inodes: return None
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal(): continue
        try:
            for fd in (proc/'fd').iterdir():
                if os.readlink(fd) in {f'socket:[{i}]' for i in inodes}:
                    return proc_info(int(proc.name))
        except (OSError,PermissionError): continue
    return {'pid':None,'args':[], 'state':'unknown'}

def busy():
    with socket.socket() as s:
        s.settimeout(.3)
        return s.connect_ex((HOST,port())) == 0

def describe_occupant():
    info=port_owner()
    if info is None: return 'Port appears occupied; owner could not be identified'
    if info['pid'] is None: return 'Listener detected (PID inaccessible)'
    return f"PID {info['pid']} ({info['state']}): {' '.join(info['args'])[:180]}"

def start():
    pid=tracked_pid()
    if pid and busy():
        print(f'Already running: PID {pid} · http://{HOST}:{port()}')
        return 0
    if busy():
        print(f'Port {port()} occupied: {describe_occupant()}\nStop that process manually; no process was killed.',file=sys.stderr)
        return 1
    RUNDIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(RUNDIR,0o700)
    log=RUNDIR/'web-preview.log'
    with log.open('ab') as output:
        child=subprocess.Popen([sys.executable,str(SERVER)], stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
    PIDFILE.write_text(str(child.pid))
    os.chmod(PIDFILE,0o600)
    for _ in range(20):
        if child.poll() is not None:
            PIDFILE.unlink(missing_ok=True)
            print(f'Server exited with code {child.returncode}; see {log}',file=sys.stderr)
            return 1
        if busy():
            print(f'Running PID {child.pid} · http://{HOST}:{port()} · log: {log}')
            return 0
        time.sleep(.1)
    print(f'Server did not start listening; inspect {log}',file=sys.stderr)
    return 1

def stop():
    pid=tracked_pid()
    if not pid:
        print('No managed process found; nothing stopped.')
        return 0
    info=proc_info(pid)
    if info and info['state'].startswith(('T','t')):
        print(f'Managed PID {pid} is stopped (T). Sending SIGCONT before SIGTERM.')
        os.kill(pid,signal.SIGCONT)
    os.kill(pid,signal.SIGTERM)
    for _ in range(30):
        if not is_ours(pid):
            PIDFILE.unlink(missing_ok=True)
            print(f'Stopped PID {pid}')
            return 0
        time.sleep(.1)
    print(f'PID {pid} did not stop. Manual inspection needed; no SIGKILL sent.',file=sys.stderr)
    return 1

def main():
    parser=argparse.ArgumentParser(description='Manage PiRate loopback WebUI')
    parser.add_argument('command',choices=['start','stop','restart','status'])
    args=parser.parse_args()
    if args.command=='start':return start()
    if args.command=='stop':return stop()
    if args.command=='status':
        pid=tracked_pid()
        if pid: print(f'Managed PID {pid}, state {proc_info(pid)["state"]}; port '+('listening' if busy() else 'not listening'))
        elif busy():print(f'Port occupied by untracked process: {describe_occupant()}')
        else:print('Stopped')
        return 0
    if stop():return 1
    return start()

if __name__=='__main__':sys.exit(main())
