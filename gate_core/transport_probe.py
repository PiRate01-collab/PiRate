"""Explicit, short-lived host<->netns veth smoke test (NO WAN access).

Does NOT change default routes, resolv.conf, firewall, or ip_forward.
Only run locally as root from CLI; never grant the web API these privileges.
Adds one temporary host veth + connected /30 route, then removes them.
"""
from . import VERSION
import argparse
import json
import os
import shutil
import subprocess
import uuid


class TransportError(RuntimeError):
    pass


def execute(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=12).stdout.strip()


def preflight(which=shutil.which):
    return {
        'version': VERSION,
        'ip_binary': which('ip'), 'ping_binary': which('ping'),
        'ready_for_test': bool(which('ip') and which('ping')),
        'web_can_execute': False, 'vpn_started': False,
        'uplink_enabled': False,
        'run_command': 'sudo python3 -m gate_core.transport_probe --run',
        'note': 'Local veth pair only; no WAN uplink, NAT, VPN, or forwarding.'
    }


def smoke_test(run=execute, uid=os.geteuid, which=shutil.which, identifier=None):
    if uid() != 0:
        raise TransportError('Root required for explicit transport test')
    ip, ping = which('ip'), which('ping')
    if not ip or not ping:
        raise TransportError('Missing iproute2 or ping')
    ident = identifier or uuid.uuid4().hex[:8]
    if len(ident) != 8 or any(ch not in '0123456789abcdef' for ch in ident):
        raise TransportError('Invalid identifier')
    ns = 'gatep8-' + ident
    host = 'gp8h' + ident
    peer = 'gp8n' + ident
    main_route_before = run([ip, '-4', 'route', 'show', 'default'])
    if run([ip, '-4', 'route', 'show', '169.254.240.0/30']):
        raise TransportError('Test subnet 169.254.240.0/30 already in use; refusing to modify links')
    dns_before = run(['/usr/bin/cat', '/etc/resolv.conf'])
    ns_created, veth_created = False, False
    failure = None
    reachable = False
    try:
        run([ip, 'netns', 'add', ns]); ns_created = True
        run([ip, 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer]); veth_created = True
        run([ip, 'link', 'set', peer, 'netns', ns])
        run([ip, 'address', 'add', '169.254.240.1/30', 'dev', host])
        run([ip, 'link', 'set', host, 'up'])
        run([ip, '-n', ns, 'address', 'add', '169.254.240.2/30', 'dev', peer])
        run([ip, '-n', ns, 'link', 'set', peer, 'up'])
        run([ip, '-n', ns, 'link', 'set', 'lo', 'up'])
        inside_default = run([ip, '-n', ns, '-4', 'route', 'show', 'default'])
        if inside_default:
            raise TransportError('Unexpected default route inside namespace')
        run([ip, 'netns', 'exec', ns, ping, '-n', '-c', '1', '-W', '2', '169.254.240.1'])
        reachable = True
    except Exception as exc:
        failure = exc
    finally:
        cleanup_errors = []
        if ns_created:
            try: run([ip, 'netns', 'del', ns])
            except Exception as exc: cleanup_errors.append('namespace: ' + str(exc))
        if veth_created:
            # The host veth is normally destroyed with its peer on netns deletion.
            try:
                run([ip, 'link', 'del', host])
            except subprocess.CalledProcessError:
                pass  # verify actual absence below; deletion may already have happened
            except Exception as exc:
                cleanup_errors.append('veth: ' + str(exc))
        if cleanup_errors:
            raise TransportError('Cleanup failure: ' + '; '.join(cleanup_errors)) from failure
    if failure:
        raise TransportError(str(failure)) from failure
    ns_list = run([ip, 'netns', 'list'])
    host_links = run([ip, '-o', 'link', 'show'])
    route_after = run([ip, '-4', 'route', 'show', 'default'])
    dns_after = run(['/usr/bin/cat', '/etc/resolv.conf'])
    result = {
        'namespace': ns, 'veth_reachable': reachable,
        'namespace_removed': ns not in ns_list,
        'veth_removed': host not in host_links,
        'default_route_unchanged': main_route_before == route_after,
        'dns_unchanged': dns_before == dns_after,
        'wan_uplink': False, 'vpn_started': False,
    }
    result['ok'] = all([result['veth_reachable'], result['namespace_removed'], result['veth_removed'],
                        result['default_route_unchanged'], result['dns_unchanged']])
    return result


def main():
    parser = argparse.ArgumentParser(description='gate-native isolated veth transport test')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    try:
        result = smoke_test() if args.run else preflight()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get('ok', True) else 1
    except (TransportError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
