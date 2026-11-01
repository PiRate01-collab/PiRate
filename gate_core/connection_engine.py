"""0.2.10-dev: read-only backend inspection and isolated tunnel *planning*.

No VPN/proxy daemon is started; no firewall, routing, DNS or host settings are changed.
"""
import shutil
from .core import ProfileStore
from .plans import ConnectionPlan
from . import VERSION

BACKENDS = {'openvpn':'openvpn', 'wireguard':'wg', 'socks5':None, 'http':None}


def capabilities(which=shutil.which):
    return {kind: {'binary': binary, 'installed':bool(which(binary)) if binary else False,
                   'supported_in_preview':False}
            for kind,binary in BACKENDS.items()}


def inspect_profile(payload,which=shutil.which):
    profile=ProfileStore.validate(payload)
    required=BACKENDS[profile['type']]
    missing=[]
    if not profile['server']:missing.append('server')
    if profile['port'] is None:missing.append('port')
    if required and not which(required):missing.append('binary:'+required)
    missing.append('connection_config_and_credentials')
    return {'type':profile['type'],'ready_to_connect':False,'missing':missing,
            'mode':'inspection_only','route_changes':False,'dns_changes':False,'process_started':False}


def tunnel_plan(payload,which=shutil.which):
    """Return metadata-only checklist, not executable shell arguments or a command."""
    profile=ProfileStore.validate(payload)
    kind=profile['type']
    result=inspect_profile(payload,which=which)
    plan=ConnectionPlan.from_profile(payload)
    tunnel=kind in ('openvpn','wireguard')
    return {
        'version': VERSION, 'connection_plan': plan.as_dict(),
        'mode':'plan_only', 'type':kind, 'name':profile['name'],
        'execution_available':False, 'process_started':False,
        'route_changes':False,'dns_changes':False,'firewall_changes':False,
        'isolated_tunnel_supported_in_future':tunnel,
        'planned_checks':([
            'validate_config_and_secret_references',
            'preserve_ssh_and_default_route',
            'start_in_separate_network_namespace',
            'observe_interface_and_handshake',
            'verify_tunnel_only_traffic',
            'stop_and_clean_up_namespace',
        ] if tunnel else [
            'validate_profile', 'select_compatible_proxy_backend',
            'verify_dns_policy_and_authentication',
        ]),
        'blockers':result['missing'] + ['execution_disabled'],
        'note':'This is a plan. No VPN connection or network namespace is created.'
    }
