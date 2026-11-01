"""0.2.10-dev: opt-in, temporary namespace routed over existing VPN uplink.

No VPN bypass mode. Root-only CLI. Host routes and DNS are never set.
Temporary veth, nft NAT and forwarding are cleaned up in finally.
"""
from . import VERSION
import argparse
import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path


class UplinkError(RuntimeError):
    pass


def execute(argv, timeout=10):
    return subprocess.run(argv, check=True, text=True, capture_output=True,
                          timeout=timeout).stdout.strip()


def preflight(which=shutil.which):
    needed = ('ip', 'nft', 'ping', 'nslookup')
    bins = {key: which(key) for key in needed}
    return {
        'version': VERSION,
        'binaries': bins,
        'ready_for_cli_test': all(bins.values()),
        'root_required': True,
        'web_can_execute': False,
        'vpn_started': False,
        'run_command': 'sudo python3 -m gate_core.uplink_probe --run --ack-temporary-forwarding --uplink vpn --interface tun0',
        'warning': 'Root-only: temporary IPv4 forwarding, nftables and veth; use on dev ThinkPad only. VPN bypass is not supported.',
    }


def _dev(output):
    m = re.search(r'\bdev\s+([a-zA-Z0-9_.:-]+)', output)
    return m.group(1) if m else None


def _is_tunnel(dev):
    return bool(dev and (dev.startswith(('tun', 'tap', 'wg', 'ppp'))))


def _route(run, ip, target, *, source=None, incoming=None):
    args = [ip, '-4', 'route', 'get', target]
    if source is not None:
        args += ['from', source]
    if incoming is not None:
        args += ['iif', incoming]
    output = run(args)
    dev = _dev(output)
    if not dev:
        raise UplinkError('No output interface in route lookup: ' + output)
    return dev, output


def smoke_test(run=execute, uid=os.geteuid, which=shutil.which, identifier=None,
               acknowledge=False, uplink_mode='vpn', interface=None):
    if not acknowledge:
        raise UplinkError('Pass --ack-temporary-forwarding for temporary host forwarding/NAT')
    if uid() != 0:
        raise UplinkError('Root required')
    if uplink_mode not in ('vpn', 'auto'):
        raise UplinkError('Only vpn/auto are supported; direct WAN bypass intentionally unavailable')
    if interface is not None and not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', interface):
        raise UplinkError('Invalid interface')
    bins = {k: which(k) for k in ('ip', 'nft', 'ping', 'nslookup')}
    if not all(bins.values()):
        raise UplinkError('Missing: ' + ', '.join(k for k, v in bins.items() if not v))
    ip, nft, ping, nslookup = (bins[k] for k in ('ip', 'nft', 'ping', 'nslookup'))
    ident = identifier or uuid.uuid4().hex[:8]
    if not re.fullmatch(r'[a-f0-9]{8}', ident):
        raise UplinkError('Invalid identifier')
    ns, host, peer, table = ('gatep92-' + ident, 'gp9h' + ident, 'gp9n' + ident, 'gp92_' + ident)
    host_ip, ns_ip, network = '10.251.241.1', '10.251.241.2', '10.251.241.0/30'
    target = '1.1.1.1'
    host_uplink, host_route = _route(run, ip, target)
    if not _is_tunnel(host_uplink):
        raise UplinkError('Host route is not a tunnel (' + host_uplink + '); refusing to bypass VPN')
    if interface is not None and host_uplink != interface:
        raise UplinkError('Host VPN route uses ' + host_uplink + ', not requested ' + interface)
    default_before = run([ip, '-4', 'route', 'show', 'default'])
    if run([ip, '-4', 'route', 'show', network]):
        raise UplinkError('Test subnet already has a route')
    if ns in run([ip, 'netns', 'list']) or host in run([ip, '-o', 'link', 'show']):
        raise UplinkError('Temporary names already exist')
    dns_before = Path('/etc/resolv.conf').read_bytes()
    forward_path = Path('/proc/sys/net/ipv4/ip_forward')
    forwarding_before = forward_path.read_text().strip()
    if forwarding_before not in ('0', '1'):
        raise UplinkError('Unexpected forwarding setting')
    created_ns = created_link = created_table = changed_forward = False
    test_ping = test_dns = False
    namespace_route = ''
    routed_uplink = None
    error = None
    cleanup_errors = []
    changed_forward_before_route = False
    try:
        run([ip, 'netns', 'add', ns]); created_ns = True
        run([ip, 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer]); created_link = True
        run([ip, 'link', 'set', peer, 'netns', ns])
        run([ip, 'addr', 'add', host_ip + '/30', 'dev', host])
        run([ip, 'link', 'set', host, 'up'])
        run([ip, '-n', ns, 'addr', 'add', ns_ip + '/30', 'dev', peer])
        run([ip, '-n', ns, 'link', 'set', 'lo', 'up'])
        run([ip, '-n', ns, 'link', 'set', peer, 'up'])
        run([ip, '-n', ns, 'route', 'add', 'default', 'via', host_ip])
        # IPv4 forwarding must be enabled before checking a forwarded route.
        # On some Linux kernels `ip route get ... iif <veth>` returns ENETUNREACH otherwise.
        if forwarding_before == '0':
            forward_path.write_text('1\n')
            changed_forward = True
            changed_forward_before_route = True
        try:
            routed_uplink, namespace_route = _route(run, ip, target, source=ns_ip, incoming=host)
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or '').strip()
            raise UplinkError('Forwarded route lookup failed after forwarding enabled: ' +
                              (detail or str(exc)) +
                              '; check VPN forwarding policy and reverse path routing') from exc
        if routed_uplink != host_uplink or not _is_tunnel(routed_uplink):
            raise UplinkError('Forwarded route mismatch: host=' + host_uplink + ', namespace=' + routed_uplink)
        # Own table. Do not insert an allow rule into another program's firewall.
        run([nft, 'add', 'table', 'ip', table]); created_table = True
        run([nft, 'add', 'chain', 'ip', table, 'postrouting', '{', 'type', 'nat', 'hook', 'postrouting', 'priority', 'srcnat', ';', 'policy', 'accept', ';', '}'])
        run([nft, 'add', 'rule', 'ip', table, 'postrouting', 'ip', 'saddr', network, 'oifname', routed_uplink, 'masquerade'])
        try:
            run([ip, 'netns', 'exec', ns, ping, '-n', '-c', '1', '-W', '3', target])
            test_ping = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        try:
            run([ip, 'netns', 'exec', ns, nslookup, 'example.com', target], timeout=8)
            test_dns = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    except Exception as exc:
        error = exc
    finally:
        if changed_forward:
            try: forward_path.write_text(forwarding_before + '\n')
            except Exception as exc: cleanup_errors.append('forwarding: ' + str(exc))
        if created_table:
            try: run([nft, 'delete', 'table', 'ip', table])
            except Exception as exc: cleanup_errors.append('nft table: ' + str(exc))
        if created_ns:
            try: run([ip, 'netns', 'del', ns])
            except Exception as exc: cleanup_errors.append('namespace: ' + str(exc))
        if created_link:
            try:
                if host in run([ip, '-o', 'link', 'show']):
                    run([ip, 'link', 'del', host])
            except Exception as exc: cleanup_errors.append('veth: ' + str(exc))
    if cleanup_errors:
        raise UplinkError('Cleanup incomplete: ' + '; '.join(cleanup_errors)) from error
    if error:
        raise UplinkError(str(error)) from error
    default_after = run([ip, '-4', 'route', 'show', 'default'])
    forwarding_after = forward_path.read_text().strip()
    dns_after = Path('/etc/resolv.conf').read_bytes()
    ns_gone = ns not in run([ip, 'netns', 'list'])
    link_gone = host not in run([ip, '-o', 'link', 'show'])
    out = {
        'namespace': ns,
        'host_route': host_route,
        'forwarded_route': namespace_route,
        'uplink': routed_uplink,
        'external_ip_reachable': test_ping,
        'external_dns_reachable': test_dns,
        'namespace_removed': ns_gone,
        'veth_removed': link_gone,
        'nft_table_cleanup_succeeded': True,
        'forwarding_restored': forwarding_before == forwarding_after,
        'forwarding_enabled_before_route_check': changed_forward_before_route or forwarding_before == '1',
        'default_route_unchanged': default_before == default_after,
        'dns_unchanged': dns_before == dns_after,
        'vpn_started': False,
    }
    out['ok'] = all([test_ping, test_dns, ns_gone, link_gone,
                     out['forwarding_restored'], out['default_route_unchanged'], out['dns_unchanged']])
    return out


def main():
    p = argparse.ArgumentParser(description='gate-native isolated uplink probe (VPN only)')
    p.add_argument('--run', action='store_true')
    p.add_argument('--ack-temporary-forwarding', action='store_true')
    p.add_argument('--uplink', choices=('auto', 'vpn'), default='vpn')
    p.add_argument('--interface', help='Expected VPN uplink interface, e.g. tun0')
    args = p.parse_args()
    try:
        out = smoke_test(acknowledge=args.ack_temporary_forwarding,
                         uplink_mode=args.uplink, interface=args.interface) if args.run else preflight()
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if out.get('ok', True) else 1
    except (UplinkError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
