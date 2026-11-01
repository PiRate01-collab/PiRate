#!/usr/bin/env python3
"""ARM64 Pi deployment, bounded configuration backup and explicit restore."""
import argparse
from contextlib import contextmanager
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
PROFILE='''# PiRate login hint: interactive terminals only; no sudo, no password output.
case $- in
  *i*)
    if [ -t 0 ] && [ -t 1 ] && [ -x /usr/local/bin/pirate ]; then
      /usr/local/bin/pirate status --brief 2>/dev/null || :
    fi
    ;;
esac
'''

CHANGED=('opt/pirate','etc/pirate','var/lib/pirate','etc/systemd/system/pirate-ap.service',
         'etc/systemd/system/pirate-lan-block.service','etc/NetworkManager/conf.d/90-pirate-ap.conf',
         'etc/sysctl.d/90-pirate-ap.conf','etc/modules-load.d/90-pirate-pptp.conf','etc/profile.d/pirate.sh','usr/local/bin/pirate','etc/pirate-status.json')
CONTEXT=('etc/hostapd','etc/default/hostapd','etc/dnsmasq.conf','etc/dnsmasq.d','etc/nftables.conf','etc/nftables.d')
UNITS=('pirate-ap.service','pirate-lan-block.service')
# Commands used by the native controller, AP, PPTP, management and installer.
# dnsmasq-base supplies the process without a competing system DHCP service.
PACKAGES = {
    'python3': ('python3',), 'openssl': ('openssl',),
    'iproute2': ('ip', 'ss'), 'iw': ('iw',), 'nftables': ('nft',),
    'wireguard-tools': ('wg',), 'openvpn': ('openvpn',),
    'hostapd': ('hostapd',), 'dnsmasq-base': ('dnsmasq',),
    'procps': ('sysctl',), 'systemd': ('systemctl', 'journalctl'),
    'tar': ('tar',), 'util-linux': ('unshare',), 'mount': ('mount',),
    'kmod': ('modinfo', 'modprobe'), 'coreutils': ('true', 'env', 'dirname'),
    'ethtool': ('ethtool',), 'conntrack': ('conntrack',),
    'ca-certificates': (),
}
REQUIRED = tuple(command for commands in PACKAGES.values() for command in commands)


def missing_dependencies():
    packages, binaries = [], []
    for package, commands in PACKAGES.items():
        status = run('dpkg-query', '-W', '-f=${Status}', package, check=False)
        if status.returncode or status.stdout.split()[-2:] != ['ok', 'installed']:
            packages.append(package)
        binaries.extend(f'{command} -> {package}' for command in commands
                        if not shutil.which(command, path=os.environ.get('PATH', '') + ':/usr/sbin:/sbin'))
    return packages, binaries


@contextmanager
def inhibit_package_services(policy=Path('/usr/sbin/policy-rc.d')):
    # Keep the original file/symlink and its metadata; never execute or follow it.
    temp = Path(tempfile.mkdtemp(prefix='.pirate-apt-', dir=policy.parent))
    saved = temp / 'original'
    deny = temp / 'deny'
    deny.write_text('#!/bin/sh\n# PiRate dependency provisioning only\nexit 101\n')
    deny.chmod(0o755)
    present = policy.exists() or policy.is_symlink()
    if present:
        os.replace(policy, saved)
    try:
        os.replace(deny, policy)
        yield
    finally:
        # If restoration itself fails, keep the original on disk for recovery.
        if present:
            os.replace(saved, policy)
        else:
            policy.unlink(missing_ok=True)
        shutil.rmtree(temp)


def ensure_dependencies(install_missing=False):
    packages, binaries = missing_dependencies()
    if not packages and not binaries:
        return
    detail = 'Missing packages/tools: ' + ', '.join(binaries or packages)
    if packages:
        detail += '; Debian packages: ' + ' '.join(packages)
    if not install_missing:
        raise ValueError(detail + '; install/upgrade installs missing packages automatically (inspect is read-only)')
    if not packages:
        raise ValueError(detail + '; packages are installed but binaries are missing; repair the damaged installation first')
    if run('dpkg', '--audit').stdout.strip():
        raise ValueError('Resolve dpkg --audit problems before dependency installation')
    if not shutil.which('apt-get'):
        raise ValueError('apt-get is required to install missing Debian packages')
    print('Installing missing Debian packages: ' + ' '.join(packages), flush=True)
    environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    # No short timeout: killing dpkg in the middle of configuration is unsafe.
    with inhibit_package_services():
        subprocess.run(['apt-get', '--error-on=any', 'update'], env=environment, check=True)
        subprocess.run(['apt-get', '-y', '--no-install-recommends', '--no-remove', '--no-upgrade',
                        '-o', 'Dpkg::Options::=--force-confold', 'install', *packages],
                       env=environment, check=True)
    packages, binaries = missing_dependencies()
    if packages or binaries or run('dpkg', '--audit').stdout.strip():
        raise ValueError('Dependency installation incomplete: ' + ', '.join(packages + binaries) +
                         '; check dpkg --audit; PiRate configuration and services were not changed')



def run(*args,check=True,input=None):
    return subprocess.run(args,input=input,check=check,capture_output=True,text=True,timeout=120)


def write(path,text,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(text);path.chmod(mode)


def target(root,name):
    path=root/name
    # Standard usr-merge /bin and /lib symlinks are never modified here.
    for parent in (path,*path.parents):
        if parent==root:break
        if parent.is_symlink():raise ValueError('Refuse symlink in target: '+str(parent))
    return path


def remove(path):
    if path.is_symlink() or path.is_file():path.unlink()
    elif path.exists():shutil.rmtree(path)


def os_release(root):
    return dict(line.split('=',1) for line in (root/'etc/os-release').read_text().replace('"','').splitlines() if '=' in line)


def inspect(args,root,install_missing=False):
    distro=os_release(root)
    if distro.get('ID') not in ('debian','raspbian') or distro.get('VERSION_ID') not in ('12','13'):
        raise ValueError('Requires Debian/Raspberry Pi OS 12 or 13')
    if args.image_root:
        arch=(root/'var/lib/dpkg/arch').read_text().strip().splitlines()[0]
        if arch!='arm64':raise ValueError('Staging image must have arm64 dpkg architecture')
        return {'architecture':'arm64','os':distro,'execution':'IMAGE STAGING ONLY; hardware/systemd/network NOT TESTED'}
    if os.geteuid()!=0:raise ValueError('Run inspect/install/restore from a root console or sudo')
    if platform.machine() not in ('aarch64','arm64') or run('dpkg','--print-architecture').stdout.strip()!='arm64':
        raise ValueError('Real installation requires ARM64; use --image-root only for filesystem staging')
    caps=int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')),16)
    if not caps&(1<<12) or not caps&(1<<21):raise ValueError('CAP_NET_ADMIN and CAP_SYS_ADMIN required')
    ensure_dependencies(install_missing=install_missing)
    versions={name:run(name,'--version',check=False).stdout.splitlines()[:2] for name in ('python3','nft','wg','openvpn','dnsmasq')}
    versions['openssl']=run('openssl','version').stdout.splitlines()
    versions['hostapd']=run('hostapd','-v',check=False).stderr.splitlines()[:2]
    if sys.version_info<(3,11):raise ValueError('Python >=3.11 required')
    for package,minimum in [('openssl','3.0'),('openvpn','2.6'),('dnsmasq-base','2.89'),('hostapd','2:2.10'),('nftables','1.0'),('wireguard-tools','1.0')]:
        version=run('dpkg-query','-W','-f=${Version}',package).stdout
        if run('dpkg','--compare-versions',version,'ge',minimum,check=False).returncode:raise ValueError(package+' version too old: '+version)
    if run('dpkg','--audit').stdout.strip():raise ValueError('Resolve dpkg --audit problems first')
    if not Path('/dev/net/tun').is_char_device():raise ValueError('/dev/net/tun unavailable')
    if install_missing:run('unshare','--net','--mount','--','true')
    if not Path('/sys/module/wireguard').exists() and run('modinfo','wireguard',check=False).returncode:
        raise ValueError('Kernel WireGuard support not available')
    sys.path.insert(0,str(SOURCE))
    from gate_core.mvp.ap import capabilities
    links=json.loads(run('ip','-j','link').stdout)
    radios=[];warnings=[]
    for link in links:
        try:
            if run('iw','dev',link['ifname'],'info',check=False).returncode==0:radios.append(link['ifname'])
        except (OSError,subprocess.SubprocessError):
            warnings.append('Wi-Fi inspection unavailable for '+link['ifname'])
    info={'architecture':'arm64','os':distro,'versions':versions,'wifi_interfaces':radios,'interfaces':[x['ifname'] for x in links],'warnings':warnings}
    if args.ap_interface:
        if args.ap_interface==args.wan_interface or args.ap_interface not in info['interfaces']:raise ValueError('Choose distinct existing AP and WAN interfaces')
        try:caps=capabilities(args.ap_interface)
        except Exception as exc:
            caps={'ap_mode':None,'security':[],'channels':[]}
            info['warnings'].append('Wi-Fi inspection unavailable: '+type(exc).__name__)
        info['ap_capabilities']=caps
        selected=next(link for link in links if link['ifname']==args.ap_interface)
        if selected.get('master'):raise ValueError('Dedicated AP must not be a bridge/bond member')
        if caps['ap_mode'] is not True or 'wpa2' not in caps['security'] or not caps['channels']:
            info['warnings'].append('AP/CCMP/channel capabilities unverified; hostapd will validate the selected settings at Apply')
    if args.wan_interface:
        wan=next((x for x in links if x['ifname']==args.wan_interface),None)
        if not wan or 'UP' not in wan['flags']:raise ValueError('Selected WAN must be UP')
        routes=json.loads(run('ip','-j','-4','route','show','default').stdout)
        if not any(x.get('dev')==args.wan_interface for x in routes):raise ValueError('Default IPv4 WAN route must already exist; installer will not change it')
    if not radios:info['warnings'].append('No Wi-Fi adapter detected; WebUI and VPN/proxy remain available')
    for warning in info['warnings']:print('WARNING: '+warning,file=sys.stderr)
    return info


def protect_ssh(interface):
    try:
        from gate_core.mvp.management_guard import protect_ssh as guard
    except ModuleNotFoundError as exc:
        if not exc.name.startswith('gate_core'):raise
        # Standalone backup restore must keep the same guard without a checkout.
        import importlib.util
        path=Path(__file__).with_name('management_guard.py')
        if path.is_symlink() or not path.is_file():raise ValueError('Backup SSH guard is unavailable; restore stopped') from exc
        spec=importlib.util.spec_from_file_location('pirate_backup_management_guard',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        guard=module.protect_ssh
    return guard(interface, run=run)


def protect_management(args):
    if args.ap_interface:protect_ssh(args.ap_interface)
    if run('nft','list','table','inet','pirate_gateway',check=False).returncode==0:
        raise ValueError('Existing pirate_gateway firewall: restore/stop previous deployment explicitly before installing beta')
    for unit in (('hostapd.service','dnsmasq.service','pirate-ap.service') if args.ap_interface else ('pirate-ap.service',)):
        if run('systemctl','is-active',unit,check=False).returncode==0:raise ValueError(unit+' is active; inspect and stop conflicting service explicitly before installation')
    if not args.ap_interface:return
    addresses=json.loads(run('ip','-j','-4','addr','show','dev',args.ap_interface).stdout)
    if any(x.get('addr_info') for x in addresses):raise ValueError('Selected AP interface already has IPv4; owner must free a dedicated AP interface first')
    if 'Connected to ' in run('iw','dev',args.ap_interface,'link',check=False).stdout:raise ValueError('Selected Wi-Fi interface is associated; do not take over an existing management connection')
    all_addresses=json.loads(run('ip','-j','addr','show','dev',args.ap_interface).stdout)
    if any(not ipaddress.ip_address(a['local']).is_link_local for item in all_addresses for a in item.get('addr_info',[])):
        raise ValueError('Selected AP interface already carries network addresses')
    if shutil.which('nmcli'):
        managed=run('nmcli','-g','GENERAL.NM-MANAGED','device','show',args.ap_interface,check=False).stdout.strip()
        if managed not in ('yes','no'):raise ValueError('Cannot verify NetworkManager ownership of AP interface')
        if managed=='yes' and not args.manage_ap_interface:raise ValueError('NetworkManager owns AP interface; specify --manage-ap-interface for this dedicated interface only')
    if shutil.which('networkctl') and run('systemctl','is-active','systemd-networkd.service',check=False).returncode==0:
        status=run('networkctl','--no-pager','status',args.ap_interface).stdout
        if re.search(r'Network File:\s*/',status):raise ValueError('systemd-networkd manages AP interface; owner must dedicate it explicitly')
    if run('systemctl','is-active','dhcpcd.service',check=False).returncode==0:
        text=Path('/etc/dhcpcd.conf').read_text() if Path('/etc/dhcpcd.conf').exists() else ''
        if not re.search(r'^denyinterfaces\s+.*\b'+re.escape(args.ap_interface)+r'\b',text,re.M):raise ValueError('dhcpcd may manage AP interface; owner must exclude it explicitly')
    for path in (Path('/etc/network/interfaces'),*Path('/etc/network/interfaces.d').glob('*')):
        if path.is_file() and re.search(r'^\s*iface\s+'+re.escape(args.ap_interface)+r'\s',path.read_text(),re.M):raise ValueError('ifupdown configures AP interface; owner must dedicate it explicitly')


def backup(root,args):
    name=time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    directory=target(root,'var/backups/pirate')/name;directory.mkdir(parents=True,mode=0o700)
    present=[p for p in (*CHANGED,*CONTEXT) if (root/p).exists() or (root/p).is_symlink()]
    with tarfile.open(directory/'configuration.tar.gz','w:gz',dereference=False) as tar:
        for name in present:tar.add(root/name,arcname=name,recursive=True)
    (directory/'configuration.tar.gz').chmod(0o600)
    metadata={'root':str(root),'present':present,'changed':list(CHANGED),'context':list(CONTEXT),
              'archive_sha256':hashlib.sha256((directory/'configuration.tar.gz').read_bytes()).hexdigest(),
              'ap_interface':args.ap_interface,'wan_interface':args.wan_interface,'units':{},'sysctl':{},'nm_managed':None,
              'machine_id':(root/'etc/machine-id').read_text().strip() if (root/'etc/machine-id').exists() else None}
    if not args.image_root:
        for unit in UNITS:
            metadata['units'][unit]={'enabled':run('systemctl','is-enabled',unit,check=False).stdout.strip(),
                                     'active':run('systemctl','is-active',unit,check=False).returncode==0}
        metadata['sysctl']={key:run('sysctl','-n',key).stdout.strip() for key in ('net.ipv4.ip_forward','net.ipv4.conf.all.rp_filter')}
        if args.ap_interface and shutil.which('nmcli'):metadata['nm_managed']=run('nmcli','-g','GENERAL.NM-MANAGED','device','show',args.ap_interface,check=False).stdout.strip()
        write(directory/'nft-ruleset.txt',run('nft','-s','list','ruleset').stdout)
    write(directory/'backup.json',json.dumps(metadata,indent=2)+'\n')
    shutil.copy2(Path(__file__),directory/'restore.py');(directory/'restore.py').chmod(0o700)
    shutil.copy2(SOURCE/'gate_core/mvp/management_guard.py',directory/'management_guard.py')
    (directory/'management_guard.py').chmod(0o600)
    installer_event(args,'Backup: '+str(directory))
    return directory,metadata


def credentials(args):
    from gate_core.mvp.admin import prompt_password
    return prompt_password(args.admin_user)


def access_options(args,config):
    from gate_core.mvp.admin import validate_access
    config=dict(config)
    if getattr(args,'tunnel_only',False) and (getattr(args,'management_interface',None) or getattr(args,'management_subnet',None)):
        raise ValueError('--tunnel-only cannot be combined with Ethernet management options')
    if getattr(args,'tunnel_only',False):
        config['management_interface']=None;config['management_subnet']=None;config['management_address']=None
    if getattr(args,'management_interface',None) is not None:config['management_interface']=args.management_interface
    if getattr(args,'management_subnet',None) is not None:config['management_subnet']=args.management_subnet
    if getattr(args,'management_address',None) is not None:config['management_address']=args.management_address
    if getattr(args,'tunnel_port',None):config['tunnel_ports']=list(dict.fromkeys([*args.tunnel_port,*config.get('tunnel_ports',[8765])]))
    config.setdefault('tunnel_ports',[8765]);config.setdefault('management_owner',uuid.uuid4().hex)
    config.setdefault('tls_managed',True)
    validate_access(config)
    return config


def install_code(root):
    code=target(root,'opt/pirate');remove(code);code.mkdir(parents=True)
    for name in ('gate_core','web','lib','bin','extra','docs'):
        shutil.copytree(SOURCE/name,code/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    (code/'tools').mkdir()
    for name in ('install_pi.py','build_mvp_release.py'):shutil.copy2(SOURCE/'tools'/name,code/'tools'/name)
    for name in ('VERSION','README.md','install-pi.sh','install.sh'):shutil.copy2(SOURCE/name,code/name)
    for name in ('INSTALL.md','CONFIGURATION.md','TROUBLESHOOTING.md','SECURITY.md','CHANGELOG.md','LICENSE'):
        if (SOURCE/name).is_file():shutil.copy2(SOURCE/name,code/name)
    # Old module autoload file is covered by the unchanged rollback ledger.
    target(root,'etc/modules-load.d/90-pirate-pptp.conf').unlink(missing_ok=True)
    return code


def install_login(root,config,auth):
    from gate_core.mvp.admin import atomic_json,public_config
    write(target(root,'etc/profile.d/pirate.sh'),PROFILE,0o644)
    write(target(root,'usr/local/bin/pirate'),'#!/bin/sh\nexec /opt/pirate/bin/pirate "$@"\n',0o755)
    atomic_json(target(root,'etc/pirate-status.json'),public_config(config,auth),0o644)


def installation_banner(root,args,auth):
    if args.image_root:
        print('IMAGE ONLY: network/services not started; hardware NOT TESTED.')
        return
    from gate_core.mvp.admin import read_public,live_status,listeners,interfaces
    for attempt in range(75):
        status=read_public('/run/pirate/status.json');sockets=listeners()
        loop=next((v for v in status.get('listeners',[]) if v['scope']=='loopback' and v['address']=='127.0.0.1' and (v['address'],v['port']) in sockets),None)
        if live_status(status) and loop:break
        time.sleep(.2)
    else:raise ValueError('WebUI listener readiness not confirmed; check pirate-ap.service logs')
    url='http://127.0.0.1:'+str(loop['port'])
    target_ip=None;ssh_port=22
    addresses={a['local'] for link in interfaces() for a in link.get('addr_info',[]) if a.get('family')=='inet'}
    fields=os.environ.get('SSH_CONNECTION','').split()
    if len(fields)==4:
        try:
            candidate=str(ipaddress.IPv4Address(fields[2]));ssh_port=int(fields[3])
            if candidate in addresses and any((a,ssh_port) in sockets for a in (candidate,'0.0.0.0','*','::')):target_ip=candidate
        except ValueError:pass
    if target_ip is None:
        routes=json.loads(run('ip','-j','-4','route','get','1.1.1.1').stdout)
        candidate=routes[0].get('prefsrc') if routes else None
        if candidate in addresses and any((a,22) in sockets for a in (candidate,'0.0.0.0','*','::')):target_ip=candidate;ssh_port=22
    user=os.environ.get('SUDO_USER','')
    if not re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,31}',user) or user=='root':user=None
    print('========================================')
    print('       PiRate установлен' if args.action!='upgrade' else '       PiRate обновлён')
    print('========================================\n')
    if args.action!='upgrade':print('Завершите настройку Wi-Fi и подключения в панели.\nAP и интернет включатся после Применить → Подтвердить.\n')
    print('На Raspberry Pi (если есть браузер):\n'+url+'\n')
    if target_ip and user:
        import shlex
        print('На компьютере:\n1. Откройте терминал (PowerShell, Linux или macOS).\n2. Выполните:\n')
        print('ssh -N -L '+shlex.quote('127.0.0.1:'+str(loop['port'])+':127.0.0.1:'+str(loop['port']))+(' -p '+str(ssh_port) if ssh_port!=22 else '')+' '+shlex.quote(user+'@'+target_ip))
        print('\n3. Откройте браузер:\n'+url+'\n')
    else:print('SSH-пользователь или адрес не определён надёжно. Используйте локальный адрес выше; инструкция SSH — в INSTALL.md.\n')
    print('Логин: '+auth['username'])
    if auth.get('bootstrap_only'):print('Задайте пароль панели: sudo pirate passwd')
    print('========================================')


def upgrade(args,root):
    # Preserve credentials, certificates, profiles, router ownership and AP settings.
    etc=target(root,'etc/pirate')
    config=json.loads((etc/'deployment.json').read_text());auth=json.loads((etc/'admin.json').read_text())
    installed=(target(root,'opt/pirate')/'VERSION').read_text().strip()
    if installed not in ('0.4.1-beta','0.4.2-beta','0.5.0-beta','0.5.1-beta','0.5.2-beta','0.5.3-beta','0.5.4-beta','0.5.4.1-beta','0.5.4.2-beta','0.5.5-beta','0.5.5.1-beta','0.5.6-beta','0.5.6.1-beta','0.5.6.2-beta','0.5.7-beta','0.5.8-beta','0.5.9-rc1','0.5.9-rc2','0.5.9-rc3','0.5.9-rc4','0.5.9-beta.1'):raise ValueError('Upgrade requires installed 0.4.1-beta, 0.4.2-beta, 0.5.0-beta, 0.5.1-beta, 0.5.2-beta, 0.5.3-beta, 0.5.4-beta, 0.5.4.1-beta 0.5.4.2-beta 0.5.5-beta 0.5.5.1-beta 0.5.6-beta, 0.5.6.1-beta, 0.5.6.2-beta 0.5.7-beta or 0.5.8-beta/0.5.9-rc1/0.5.9-rc2/0.5.9-rc3')
    config=access_options(args,config)
    args.ap_interface=config.get('ap_interface');args.wan_interface=config['wan_interface']
    # No AP heuristic/takeover check: upgrade never activates AP or changes WAN.
    selected=args.ap_interface
    try:
        args.ap_interface=None;info=inspect(args,root,install_missing=True)
    finally:args.ap_interface=selected
    if not args.image_root and selected:protect_ssh(selected)
    for name in CHANGED:target(root,name)
    directory,metadata=backup(root,args)
    try:
        if not args.image_root:run('systemctl','stop','pirate-ap.service')
        install_code(root)
        write(etc/'deployment.json',json.dumps(config,indent=2)+'\n')
        install_login(root,config,auth)
        state=json.loads((etc/'installation.json').read_text());state['upgrade_backup']=str(directory)
        write(etc/'installation.json',json.dumps(state)+'\n')
        write(directory/'preflight.json',json.dumps(info,indent=2)+'\n')
        if not args.image_root:
            run('systemctl','daemon-reload');run('systemctl','start','pirate-ap.service')
            run('systemctl','is-active','pirate-ap.service')
        installer_event(args,'Upgrade complete; saved settings retained; unconfirmed setup remains OFF/BLOCKED')
        installer_event(args,'Rollback: sudo python3 '+str(directory/'restore.py')+' restore --backup '+str(directory))
        installation_banner(root,args,auth)
    except (Exception,KeyboardInterrupt):
        print('Upgrade failed; restoring previous version and configuration.',file=sys.stderr)
        restore(root,directory,bool(args.image_root));raise


def automatic_action(root):
    required = ('opt/pirate/VERSION', 'etc/pirate/deployment.json',
                'etc/pirate/admin.json', 'etc/pirate/installation.json')
    present = [(root/name).is_file() for name in required]
    if all(present):return 'upgrade'
    if any(present) or (root/'var/lib/pirate').exists() or (root/'etc/pirate').exists():
        raise ValueError('Incomplete existing installation; restore its backup before retrying')
    return 'install'


def detect_bootstrap(args, info):
    """Read-only selection. Never detach an occupied interface or guess a radio."""
    from gate_core.mvp.ap import capabilities
    from gate_core.mvp.wifi_performance import phy_interfaces
    links = {v['ifname']:v for v in json.loads(run('ip','-j','link').stdout)}
    defaults = json.loads(run('ip','-j','-4','route','show','default').stdout)
    routes = [r for r in defaults if r.get('dev') in links and
              'UP' in links[r['dev']].get('flags',[]) and not r.get('nexthops') and
              not set(r.get('flags',[])) & {'linkdown','dead'}]
    if not args.wan_interface:
        if not routes:raise ValueError('No active default IPv4 route; connect Ethernet WAN first')
        metric = min(r.get('metric',0) for r in routes)
        choices = {r['dev'] for r in routes if r.get('metric',0)==metric}
        if len(choices)!=1:raise ValueError('Ambiguous WAN; specify --wan-interface')
        args.wan_interface = choices.pop()
    if args.wan_interface not in {r['dev'] for r in routes}:
        raise ValueError('Selected WAN has no active default IPv4 route')
    selected = json.loads(run('ip','-j','-4','route','get','1.1.1.1').stdout)
    if not selected or selected[0].get('dev')!=args.wan_interface:
        raise ValueError('Default/policy routing disagrees with selected WAN; inspect routing first')
    addresses = {v['ifname']:v.get('addr_info',[]) for v in json.loads(run('ip','-j','addr').stdout)}
    phy = phy_interfaces(run('iw','dev').stdout)
    candidates = []
    for name in ([args.ap_interface] if args.ap_interface else info['wifi_interfaces']):
        if name not in phy or name==args.wan_interface or name not in links or links[name].get('master'):continue
        if sum(value==phy[name] for value in phy.values())!=1:continue
        if any(not ipaddress.ip_address(a['local']).is_link_local for a in addresses.get(name,[])):continue
        link = run('iw','dev',name,'link',check=False)
        if link.returncode or 'Not connected.' not in link.stdout:continue
        mode = run('iw','dev',name,'info').stdout
        if not re.search(r'\btype managed\b',mode):continue
        try:protect_ssh(name)
        except ValueError:continue
        caps = capabilities(name)
        if caps['ap_mode'] is not True or 'wpa2' not in caps['security'] or not caps['channels']:continue
        candidates.append(name)
    if len(candidates)!=1:
        raise ValueError('Need exactly one idle dedicated AP radio; use --ap-interface or free an unused radio (SSH/WAN will not be detached)')
    args.ap_interface = candidates[0]
    if shutil.which('nmcli'):
        managed = run('nmcli','-g','GENERAL.NM-MANAGED','device','show',args.ap_interface).stdout.strip()
        if managed not in ('yes','no'):raise ValueError('Cannot verify NetworkManager ownership')
        if managed=='yes':
            state = run('nmcli','-g','GENERAL.STATE','device','show',args.ap_interface).stdout.strip()
            if not state.startswith('30 '):raise ValueError('AP NetworkManager device is not idle/disconnected')
            args.manage_ap_interface = True
    countries = set(re.findall(r'country ([A-Z]{2}):',run('iw','reg','get').stdout))
    country = args.country or (next(iter(countries)) if len(countries)==1 else '00')
    if len(countries)>1 and not args.country:raise ValueError('Ambiguous Wi-Fi region; specify --country')
    if not re.fullmatch(r'[A-Z]{2}|00',country):raise ValueError('Invalid --country')
    args.country = country
    # Trusted wired UI is scoped to the existing private WAN subnet. Public WAN
    # stays tunnel/AP-only; never bind management to an arbitrary public network.
    if not args.tunnel_only and not args.management_interface and not args.management_subnet:
        from gate_core.mvp.admin import PRIVATE_NETS
        wired = args.wan_interface not in phy
        subnets = [ipaddress.IPv4Interface(a['local']+'/'+str(a['prefixlen']))
                   for a in addresses.get(args.wan_interface,[]) if a['family']=='inet']
        private = [a for a in subnets if a.network.prefixlen<=30 and
                   any(a.network.subnet_of(n) for n in PRIVATE_NETS)]
        if wired and len(private)==1:
            args.management_interface=args.wan_interface
            args.management_subnet=str(private[0].network)
            args.management_address=str(private[0].ip)
    protect_management(args)


def bootstrap_api(port, secret, path, data=None):
    import base64
    import http.client
    connection = http.client.HTTPConnection('127.0.0.1',port,timeout=180)
    header = base64.b64encode((secret['username']+':'+secret['admin_password']).encode()).decode()
    try:
        connection.request('GET' if data is None else 'POST','/api/mvp/'+path,
                           body=None if data is None else json.dumps(data),
                           headers={'Authorization':'Basic '+header,'Content-Type':'application/json',
                                    'Origin':f'http://127.0.0.1:{port}'})
        response=connection.getresponse();body=response.read()
        if response.status not in (200,201):raise ValueError(f'Bootstrap {path}: HTTP {response.status}; see PiRate diagnostics')
        return json.loads(body)
    finally:connection.close()



def install(args,root):
    if (root/'etc/pirate/installation.json').exists():
        raise ValueError('PiRate is already installed; use upgrade to preserve profiles and settings')
    info=inspect(args,root,install_missing=True)
    automatic=getattr(args,'automatic',False)
    if automatic:
        if args.image_root:raise ValueError('Auto-detection requires live hardware; use explicit install flags for image staging')
        detect_bootstrap(args,info)
    if not args.wan_interface:raise ValueError('Explicit --wan-interface required; inspect lists candidates')
    if args.manage_ap_interface and not args.ap_interface:raise ValueError('--manage-ap-interface requires --ap-interface')
    if (SOURCE/'VERSION').read_text().strip() not in ('0.5.7-beta','0.5.8-beta','0.5.9-rc1','0.5.9-rc2','0.5.9-rc3','0.5.9-rc4','0.5.9-beta.1'):raise ValueError('Installer requires a validated 0.5.7-beta, 0.5.8-beta, 0.5.9-rc1, 0.5.9-rc2 or 0.5.9-rc3 release tree')
    for name in filter(None,(args.ap_interface,args.wan_interface)):
        if not re.fullmatch('[A-Za-z0-9_.-]{1,15}',name) or name=='lo':raise ValueError('Invalid interface')
    address=ipaddress.IPv4Interface(args.subnet)
    if address.network.prefixlen!=24 or address.ip!=address.network[1] or address.ip.is_loopback or address.ip.is_multicast:raise ValueError('Initial beta AP subnet must use first host of an IPv4 /24')
    if not args.image_root:
        protect_management(args)
        for item in (json.loads(run('ip','-j','-4','addr').stdout) if args.ap_interface else []):
            for entry in item.get('addr_info',[]):
                if address.network.overlaps(ipaddress.IPv4Network(entry['local']+'/'+str(entry['prefixlen']),strict=False)):raise ValueError('AP subnet overlaps existing interface')
    for path in CHANGED:target(root,path)
    secret=None
    if automatic:
        from gate_core.mvp.admin import password_hash
        auth=password_hash(args.admin_user,'')
    else:auth=credentials(args)
    directory,metadata=backup(root,args)
    write(directory/'preflight.json',json.dumps(info,indent=2)+'\n')
    try:
        code=install_code(root)
        etc=target(root,'etc/pirate');etc.mkdir(parents=True,exist_ok=True);etc.chmod(0o700)
        data=target(root,'var/lib/pirate');data.mkdir(parents=True,exist_ok=True);data.chmod(0o700)
        write(etc/'admin.json',json.dumps(auth)+'\n')
        if secret:write(etc/'bootstrap-credentials.json',json.dumps(secret,indent=2)+'\n')
        run('openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','365',
            '-subj','/CN=pirate.home.arpa','-addext',f'subjectAltName=DNS:pirate.home.arpa,IP:{address.ip}',
            '-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature,keyEncipherment','-addext','extendedKeyUsage=serverAuth',
            '-keyout',str(etc/'tls.key'),'-out',str(etc/'tls.crt'))
        (etc/'tls.key').chmod(0o600);(etc/'tls.crt').chmod(0o600)
        deployment={'ap_interface':args.ap_interface,'wan_interface':args.wan_interface,'subnet':str(address),
                    'management_port':8766,'auth_file':'/etc/pirate/admin.json','tls_cert':'/etc/pirate/tls.crt','tls_key':'/etc/pirate/tls.key'}
        deployment=access_options(args,deployment)
        write(etc/'deployment.json',json.dumps(deployment,indent=2)+'\n')
        install_login(root,deployment,auth)
        runtime=data/'runtime';runtime.mkdir(mode=0o700,exist_ok=True)
        config={'lan_interface':args.ap_interface,'wan_interface':args.wan_interface,'dns_server':'1.1.1.1',
                'ap_dns_address':str(address.ip),'management_port':8766}
        owner=uuid.uuid4().hex
        if args.ap_interface:
            write(runtime/'router.json',json.dumps({'schema':1,'owner':owner,'config':config})+'\n')
        elif (runtime/'router.json').exists():
            raise ValueError('Existing LAN configuration requires explicit restore before installation without AP')
        for unit in UNITS:
            text=(SOURCE/'extra'/unit).read_text()
            if unit=='pirate-ap.service':text=text.replace('Environment=PATH=', 'Environment=PIRATE_DEPLOYMENT_CONFIG=/etc/pirate/deployment.json\nEnvironment=PATH=')
            text=text.replace('Conflicts=hostapd.service dnsmasq.service\n','')
            write(target(root,'etc/systemd/system/'+unit),text,0o644)
        if args.ap_interface:
            write(target(root,'etc/sysctl.d/90-pirate-ap.conf'),'# PiRate: early LAN DROP must precede AP activation\nnet.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=2\n',0o644)
        if args.manage_ap_interface:
            write(target(root,'etc/NetworkManager/conf.d/90-pirate-ap.conf'),f'[device-pirate-ap]\nmatch-device=interface-name:{args.ap_interface}\nmanaged=0\n',0o644)
        write(etc/'installation.json',json.dumps({'backup':str(directory),'owner':owner})+'\n')
        if not args.image_root:
            run('systemctl','daemon-reload')
            if args.manage_ap_interface and shutil.which('nmcli'):
                protect_ssh(args.ap_interface)
                if automatic:protect_management(args)
                run('nmcli','device','set',args.ap_interface,'managed','no')
            run(str(code/'bin/pirate'),'--data-dir','/var/lib/pirate','--restore-lan-block')
            if args.ap_interface:run('sysctl','-w','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=2')
            run('systemctl','enable',*UNITS);run('systemctl','start',*UNITS)
            run('systemctl','is-active','pirate-ap.service')
        installation_banner(root,args,auth)
        if args.image_root:print('IMAGE STAGING PASS; physical install NOT TESTED')
        installer_event(args,'Restore: python3 '+str(directory/'restore.py')+' restore --backup '+str(directory))
    except (Exception,KeyboardInterrupt):
        print('Installation failed; restoring this backup.',file=sys.stderr)
        restore(root,directory,args.image_root)
        raise


def restore(root,directory,image=False):
    directory=Path(directory).resolve()
    if directory.stat().st_uid!=os.geteuid() or directory.stat().st_mode&0o077:raise ValueError('Backup must be privately owned by caller/root')
    metadata=json.loads((directory/'backup.json').read_text())
    if metadata['root']!=str(root) or metadata['changed']!=list(CHANGED) or metadata['context']!=list(CONTEXT):raise ValueError('Backup scope/root mismatch')
    machine_id=(root/'etc/machine-id').read_text().strip() if (root/'etc/machine-id').exists() else None
    if metadata.get('machine_id')!=machine_id:raise ValueError('Backup belongs to a different device/image')
    archive=directory/'configuration.tar.gz'
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=metadata['archive_sha256']:raise ValueError('Backup checksum mismatch')
    with tarfile.open(archive) as tar:
        members=[m for m in tar.getmembers() if any(m.name==n or m.name.startswith(n+'/') for n in CHANGED)]
        links=[m.name for m in members if m.issym()]
        for member in members:
            if '..' in Path(member.name).parts or member.name.startswith('/') or any(member.name.startswith(n+'/') for n in links):raise ValueError('Unsafe archive member')
            if member.islnk() and not any(member.linkname==n or member.linkname.startswith(n+'/') for n in CHANGED):raise ValueError('Unsafe archive hardlink')
    if not image:
        if os.geteuid()!=0:raise ValueError('Root required')
        if metadata['ap_interface']:protect_ssh(metadata['ap_interface'])
        run('systemctl','stop',*UNITS,check=False)
        deployment=root/'etc/pirate/deployment.json'
        if deployment.exists():
            current=json.loads(deployment.read_text())
            table=run('nft','-j','list','table','inet','pirate_management',check=False)
            if table.returncode==0:
                tables=[row['table'] for row in json.loads(table.stdout)['nftables'] if 'table' in row]
                if not tables or not current.get('management_owner') or tables[0].get('comment')!='PiRate management '+current['management_owner']:
                    raise ValueError('Management firewall ownership changed; restore stopped')
                run('nft','delete','table','inet','pirate_management')
        ownership=root/'etc/pirate/installation.json'
        if ownership.exists():
            expected=json.loads(ownership.read_text())['owner']
            table=run('nft','-j','list','table','inet','pirate_gateway',check=False)
            if table.returncode==0:
                tables=[row['table'] for row in json.loads(table.stdout)['nftables'] if 'table' in row]
                if not tables or tables[0].get('comment')!='PiRate '+expected:raise ValueError('Firewall ownership changed; restore stopped for manual review')
                run('nft','delete','table','inet','pirate_gateway')
    # Only installer-modified paths are restored. Context snapshots remain
    # available for explicit owner recovery; unrelated live nft rules never flushed.
    for name in CHANGED:remove(target(root,name))
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if not any(member.name==name or member.name.startswith(name+'/') for name in CHANGED):continue
            if '..' in Path(member.name).parts or member.name.startswith('/'):raise ValueError('Unsafe archive member')
            if hasattr(tarfile,'data_filter'):tar.extract(member,path=root,filter='fully_trusted')
            else:tar.extract(member,path=root)
    if not image:
        run('systemctl','daemon-reload')
        for unit,state in metadata['units'].items():
            run('systemctl','disable',unit,check=False)
            if state['enabled']=='enabled':run('systemctl','enable',unit)
            elif state['enabled']=='masked':run('systemctl','mask',unit)
        for key,value in metadata['sysctl'].items():run('sysctl','-w',key+'='+value)
        if metadata['nm_managed']=='yes' and shutil.which('nmcli'):run('nmcli','device','set',metadata['ap_interface'],'managed','yes')
        for unit,state in metadata['units'].items():
            if state['active']:run('systemctl','start',unit)
    print('Original installer-managed configuration restored; SSH/WAN settings left intact.')


def installer_event(args,message,level='info',exit_code=None):
    if args.image_root or getattr(args,'action',None)=='inspect':return
    try:
        from gate_core.mvp.support import EventLog
        EventLog('/var/log/pirate-installer.log').add('system',message,level,exit_code=exit_code)
    except Exception:pass


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',nargs='?',default='auto',choices=('auto','inspect','install','upgrade','restore'))
    parser.add_argument('--country',help='AP country override; default uses existing regulatory domain')
    parser.add_argument('--ssid',help='SSID override for automatic fresh installation')
    parser.add_argument('--ap-interface');parser.add_argument('--wan-interface')
    parser.add_argument('--management-interface');parser.add_argument('--management-subnet');parser.add_argument('--management-address')
    parser.add_argument('--tunnel-only',action='store_true')
    parser.add_argument('--tunnel-port',type=int,action='append',help='Explicit allowed local SSH tunnel port')
    parser.add_argument('--subnet',default='10.42.0.1/24');parser.add_argument('--admin-user',default='admin')
    parser.add_argument('--manage-ap-interface',action='store_true');parser.add_argument('--backup')
    parser.add_argument('--image-root',help='Offline filesystem staging only; never runs target network/systemd commands')
    args=parser.parse_args();root=Path(args.image_root).resolve() if args.image_root else Path('/')
    if args.image_root and (root==Path('/') or not root.is_dir()):parser.error('Choose an existing disposable image directory')
    os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin:'+os.environ.get('PATH','')
    os.environ['LC_ALL']='C'
    lock_fd=None
    try:
        args.automatic=args.action=='auto' or (args.action=='install' and not args.wan_interface and not args.ap_interface)
        if args.action=='auto':args.action=automatic_action(root)
        if not args.image_root and args.action=='restore' and platform.machine() not in ('aarch64','arm64'):raise ValueError('Real restore requires the original ARM64 device')
        if args.action in ('install','upgrade','restore'):
            if not args.image_root and (os.geteuid()!=0 or platform.machine() not in ('aarch64','arm64')):raise ValueError('Real install/restore requires root on ARM64')
            lock_path=target(root,'run/pirate-installer.lock');lock_path.parent.mkdir(parents=True,exist_ok=True)
            lock_fd=os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        installer_event(args,'Installer '+args.action+' started')
        if args.action=='inspect':print(json.dumps(inspect(args,root),indent=2))
        elif args.action=='install':install(args,root)
        elif args.action=='upgrade':upgrade(args,root)
        elif args.backup:restore(root,args.backup,bool(args.image_root))
        else:parser.error('restore requires --backup')
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        installer_event(args,'Installer '+args.action+' failed: '+type(exc).__name__+': '+str(exc),'error',getattr(exc,'returncode',None))
        print('Установка остановлена: '+str(exc)+'\nДиагностика: sudo journalctl -u pirate-ap.service -n 50 --no-pager; sudo tail -n 20 /var/log/pirate-installer.log',file=sys.stderr);return 1
    finally:
        if lock_fd is not None:os.close(lock_fd)
    installer_event(args,'Installer '+args.action+' completed')
    return 0
if __name__=='__main__':sys.exit(main())
