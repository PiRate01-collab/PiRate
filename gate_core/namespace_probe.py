"""Read-only namespace preflight and explicit isolated namespace smoke test.

Only CLI --run (root) changes state: creates a fresh empty namespace and a
DUMMY link INSIDE it, then removes the namespace in finally. No veth,
upstream connection, default route, DNS, VPN, firewall, or SSH modifications.
Never execute this privileged code from the unauthenticated web server.
"""
from . import VERSION
import argparse
import json
import os
import shutil
import subprocess
import uuid


class NamespaceProbeError(RuntimeError):
    pass


def preflight(which=shutil.which, platform='linux'):
    ip = which('ip')
    return {
        'version': VERSION,
        'platform': platform,
        'ip_binary': ip,
        'namespace_possible': bool(platform == 'linux' and ip),
        'root_required_for_smoke_test': True,
        'web_can_execute': False,
        'mode': 'read_only',
        'run_command': 'sudo python3 -m gate_core.namespace_probe --run',
        'note': 'Smoke test uses an isolated dummy interface only; no tunnel is started.'
    }


def _execute(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout.strip()


def smoke_test(run=_execute, uid=os.geteuid, which=shutil.which, identifier=None):
    """Run only when explicitly called from CLI. Cleanup always attempted."""
    if uid() != 0:
        raise NamespaceProbeError('Root privileges required; use sudo for CLI smoke test')
    ip=which('ip')
    if not ip:
        raise NamespaceProbeError('Missing iproute2 (ip command)')
    ident=(identifier or uuid.uuid4().hex[:12])
    if not (len(ident)==12 and all(c in '0123456789abcdef' for c in ident)):
        raise NamespaceProbeError('Invalid namespace identifier')
    ns='gatep7-'+ident
    link='gatep7dummy'
    before_route=run([ip,'-4','route','show','default'])
    before_dns=run(['/usr/bin/cat','/etc/resolv.conf'])
    created=False
    failure=None
    result=None
    try:
        run([ip,'netns','add',ns])
        created=True
        run([ip,'-n',ns,'link','add',link,'type','dummy'])
        run([ip,'-n',ns,'link','set',link,'up'])
        inside=run([ip,'-n',ns,'-o','link','show','dev',link])
        outside=run([ip,'-o','link','show'])
        if link not in inside or link in outside:
            raise NamespaceProbeError('Interface isolation check failed')
        # No namespace uplink; this only checks isolation of a dummy interface.
        result={'namespace':ns,'dummy_isolated':True,'tunnel_started':False,
                'default_route_unchanged':None,'dns_unchanged':None,'cleanup_ok':None}
    except Exception as exc:
        failure=exc
    finally:
        if created:
            try:
                run([ip,'netns','del',ns])
            except Exception as exc:
                failure=NamespaceProbeError('Namespace cleanup failed; inspect with ip netns list: '+str(exc))
    if failure is not None:
        raise NamespaceProbeError(str(failure)) from failure
    remaining=run([ip,'netns','list'])
    after_route=run([ip,'-4','route','show','default'])
    after_dns=run(['/usr/bin/cat','/etc/resolv.conf'])
    result.update(cleanup_ok=ns not in remaining, default_route_unchanged=before_route==after_route,
                  dns_unchanged=before_dns==after_dns)
    result['ok']=all((result['dummy_isolated'],result['cleanup_ok'],result['default_route_unchanged'],result['dns_unchanged']))
    return result


def main():
    parser=argparse.ArgumentParser(description='gate-native isolated namespace smoke test')
    parser.add_argument('--run',action='store_true',help='explicitly create/remove an isolated namespace; requires root')
    args=parser.parse_args()
    try:
        result=smoke_test() if args.run else preflight()
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0 if result.get('ok',True) else 1
    except (NamespaceProbeError,subprocess.SubprocessError,OSError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
