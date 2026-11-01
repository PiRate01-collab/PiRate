"""Shared SSH route guard for AP runtime and installation. Errors fail closed."""
import ipaddress
import json
import subprocess


def _run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=10)


def protect_ssh(interface, *, run=None):
    run = _run if run is None else run
    sessions=run('ss','-H','-tnp','state','established').stdout.splitlines()
    for line in sessions:
        if 'sshd' not in line and 'dropbear' not in line:continue
        fields=line.split()
        if len(fields)<4:continue
        peer=fields[3].rsplit(':',1)[0].strip('[]')
        try:ipaddress.ip_address(peer.split('%')[0])
        except ValueError:continue
        route=json.loads(run('ip','-j','route','get',peer).stdout)
        if route and route[0].get('dev')==interface:raise ValueError('Selected AP interface carries SSH; use wired management or console')

