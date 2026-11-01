"""Explicit synthetic CLI roles; no provisioning and no real executor imports."""
import argparse
import json
import os
import signal
import sys
import threading
from .cross_uid import RecoveryOwner, SyntheticBroker, RootPolicy
from .unix_transport import PathRPCClient, PathRPCServer
from ..broker.contracts import BrokerError


def parser():
    root = argparse.ArgumentParser(description='PiRate synthetic separate-UID test roles')
    roles = root.add_subparsers(dest='role', required=True)
    for role in ('broker', 'watchdog'):
        p = roles.add_parser(role)
        p.add_argument('--state', required=True)
        p.add_argument('--socket-dir', required=True)
        p.add_argument('--socket-gid', type=int, required=True)
        p.add_argument('--web-uid', type=int, required=True)
        p.add_argument('--web-gid', type=int, required=True)
        if role == 'watchdog':
            p.add_argument('--broker-uid', type=int, required=True)
            p.add_argument('--broker-gid', type=int, required=True)
        else:
            p.add_argument('--watchdog-dir', required=True)
            p.add_argument('--watchdog-uid', type=int, required=True)
            p.add_argument('--watchdog-gid', type=int, required=True)
            p.add_argument('--watchdog-socket-gid', type=int, required=True)
            p.add_argument('--lifetime', type=int, default=30)
            p.add_argument('--policy-file')
    p = roles.add_parser('web')
    p.add_argument('--broker-dir', required=True)
    p.add_argument('--broker-uid', type=int, required=True)
    p.add_argument('--broker-gid', type=int, required=True)
    p.add_argument('--broker-socket-gid', type=int, required=True)
    p.add_argument('--action', choices=('apply', 'confirm', 'rollback', 'status'), required=True)
    p.add_argument('--operation-id', required=True)
    p.add_argument('--check-isolation', action='store_true')
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    service = server = None
    try:
        if args.role == 'web':
            if args.check_isolation:
                paths = ['/var/lib/pirate-cross-uid-test/broker', '/var/lib/pirate-cross-uid-test/watchdog', '/var/lib/pirate-cross-uid-test/secrets/synthetic-reference.json', '/run/pirate-cross-uid-test/watchdog']
                for path in paths:
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    except PermissionError:
                        continue
                    else:
                        os.close(fd)
                        raise BrokerError('secret_denied')
                from pathlib import Path
                status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
                if int(status['CapEff'].strip(), 16) != 0 or status['NoNewPrivs'].strip() != '1':
                    raise BrokerError('identity_denied')
                print(json.dumps({'ok': True, 'isolation': 'permission_denied', 'capabilities': 0, 'no_new_privileges': True, 'dry_run': True}))
                return 0
            client = PathRPCClient(args.broker_dir, server_uid=args.broker_uid, server_gid=args.broker_gid, directory_gid=args.broker_socket_gid, timeout=2)
            result = client.call({'version': 1, 'action': args.action, 'operation_id': args.operation_id, 'resource_id': 'ap-primary'})
            print(json.dumps({'ok': True, 'result': result, 'dry_run': True}))
            return 0
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        web = args.web_uid, args.web_gid
        if args.role == 'watchdog':
            service = RecoveryOwner(args.state, web)
            subjects = {(args.broker_uid, args.broker_gid)}
            tick = service.tick
        else:
            client = PathRPCClient(args.watchdog_dir, server_uid=args.watchdog_uid, server_gid=args.watchdog_gid, directory_gid=args.watchdog_socket_gid, timeout=.5)
            service = SyntheticBroker(args.state, client, web, lifetime=args.lifetime)
            if args.policy_file:
                service.policy = RootPolicy(args.policy_file, web)
                service.policy()  # Validate operator provisioning before listening.
            subjects, tick = {web}, None
        server = PathRPCServer(args.socket_dir, service.dispatch, subjects, group=args.socket_gid, timeout=2 if args.role == 'broker' else .5, tick=tick)
        server.start()
        server.serve(stop)
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, BrokerError) else 'recovery_required'
        print(json.dumps({'ok': False, 'error': code, 'dry_run': True}), file=sys.stderr)
        return 1
    finally:
        if server:
            server.close()
        if service:
            service.close()


if __name__ == '__main__':
    raise SystemExit(main())
