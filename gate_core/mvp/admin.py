"""Management discovery and local administration. Never stores a cleartext password."""
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time

CONFIG=Path('/etc/pirate/deployment.json')
PUBLIC=Path('/etc/pirate-status.json')
STATUS=Path('/run/pirate/status.json')
PRIVATE_NETS=tuple(ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def command(*args):
    try:return subprocess.run(args,capture_output=True,text=True,timeout=3)
    except (OSError,subprocess.SubprocessError):return subprocess.CompletedProcess(args,1,'','unavailable')


def atomic_json(path,value,mode=0o600):
    path=Path(path)
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('Refuse symlink in management configuration')
    fd,name=tempfile.mkstemp(prefix='.pirate-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),mode);json.dump(value,stream);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:Path(name).unlink(missing_ok=True)


def password_hash(username,password):
    if not re.fullmatch('[A-Za-z0-9_.-]{1,32}',username):raise ValueError('Invalid admin username')
    if len(password)>20:raise ValueError('Admin password must be 0–20 characters')
    salt=os.urandom(16)
    return {'username':username,'salt':salt.hex(),
            'scrypt':hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex(),
            'bootstrap_only':password=='','password_limit':20}


def prompt_password(username):
    password=getpass.getpass('PiRate admin password (0–20 characters; empty = local bootstrap only): ')
    if password!=getpass.getpass('Repeat admin password: '):raise ValueError('Passwords differ')
    return password_hash(username,password)


def validate_access(config):
    interface=config.get('management_interface');subnet=config.get('management_subnet')
    if bool(interface)!=bool(subnet):raise ValueError('Specify both management interface and trusted IPv4 subnet')
    if interface:
        if not re.fullmatch('[A-Za-z0-9_.-]{1,15}',interface) or interface=='lo' or interface==config.get('ap_interface'):
            raise ValueError('Management requires a dedicated Ethernet interface, distinct from AP')
        net=ipaddress.IPv4Network(subnet,strict=True)
        if not any(net.subnet_of(private) for private in PRIVATE_NETS) or net.prefixlen>30:
            raise ValueError('Management subnet must be an RFC1918 network with usable hosts')
        address=config.get('management_address')
        if address and (ipaddress.IPv4Address(address) not in net or ipaddress.IPv4Address(address) in (net.network_address,net.broadcast_address)):
            raise ValueError('Management IP must be a usable address inside the explicitly trusted subnet')
    ports=config.get('tunnel_ports',[8765])
    if not isinstance(ports,list) or not ports or any(type(p) is not int or not 1<=p<=65535 for p in ports):
        raise ValueError('Tunnel ports must be explicit TCP ports 1–65535')
    return config


def public_config(config,auth):
    return {'username':auth['username'],'bootstrap_only':bool(auth.get('bootstrap_only',False)),
            'tunnel_ports':config.get('tunnel_ports',[8765])}


def require_root(action):
    if os.geteuid()!=0:raise ValueError('Use sudo pirate '+action)


def change_password(config_path=CONFIG,public_path=PUBLIC):
    from .management import private_json
    require_root('passwd')
    config=private_json(config_path);path=Path(config['auth_file']);prior=private_json(path)
    value=prompt_password(prior['username'])
    atomic_json(path,value)
    atomic_json(public_path,public_config(config,value),0o644)
    print('Admin password changed. '+('Local bootstrap only; remote WebUI disabled.' if value['bootstrap_only'] else 'Remote WebUI requires this password.'))


def tunnel_port(port,config_path=CONFIG,public_path=PUBLIC):
    from .management import private_json
    require_root('tunnel-port PORT')
    config=private_json(config_path)
    config['tunnel_ports']=list(dict.fromkeys([port,*config.get('tunnel_ports',[8765])]))
    validate_access(config);atomic_json(config_path,config)
    atomic_json(public_path,public_config(config,private_json(config['auth_file'])),0o644)
    print('Explicit tunnel Host/Origin enabled; runtime reloads within a few seconds.')


def trusted_management(action,interface=None,subnet=None,address=None,config_path=CONFIG):
    """Explicit owner opt-in; runtime independently validates/binds the actual IP."""
    from .management import private_json,Authentication
    import uuid
    require_root('management '+action)
    config=private_json(config_path)
    if action=='enable':
        if not interface or not subnet or not address:raise ValueError('Specify --interface, --subnet and --address; enable explicitly trusts only that interface/subnet')
        auth=Authentication(config['auth_file'])
        if auth.bootstrap_only:raise ValueError('Set a nonempty admin password first: sudo pirate passwd')
        config.update(management_interface=interface,management_subnet=subnet,management_address=address)
        config.setdefault('management_owner',uuid.uuid4().hex)
        validate_access(config)
        # Verify the requested IP belongs to this netdev now, without changing it.
        if not any(a.get('local')==address for link in interfaces() if link['ifname']==interface for a in link.get('addr_info',[]) if a.get('family')=='inet'):
            raise ValueError('Requested IPv4 is not currently assigned to the selected interface; no network settings changed')
        link=Path('/sys/class/net')/interface
        if (link/'type').read_text().strip()!='1' or (link/'wireless').exists() or (link/'phy80211').exists():raise ValueError('Trusted management requires Ethernet')
    elif action=='disable':
        config.update(management_interface=None,management_subnet=None,management_address=None)
    else:raise ValueError('Use management enable or management disable')
    atomic_json(config_path,config)
    print('Trusted LAN management '+('enabled for '+interface+' / '+subnet+' at https://'+address+':8766' if action=='enable' else 'disabled; loopback SSH fallback retained'))
    print('Runtime reloads within a few seconds. Verify listener and TLS fingerprint: pirate status')


def interfaces():
    result=command('ip','-j','-4','addr','show','up')
    if result.returncode:return []
    try:return json.loads(result.stdout)
    except ValueError:return []


def listeners():
    result=command('ss','-H','-ltn');found=set()
    if result.returncode:return found
    for line in result.stdout.splitlines():
        fields=line.split()
        if len(fields)<4:continue
        try:
            address,port=fields[3].rsplit(':',1);found.add((address.strip('[]'),int(port)))
        except ValueError:continue
    return found


def read_public(path):
    try:
        path=Path(path)
        if path.is_symlink() or path.stat().st_mode&0o022 or path.stat().st_size>65536:return {}
        value=json.loads(path.read_text())
        return value if isinstance(value,dict) else {}
    except (OSError,ValueError):return {}


def live_process(status):
    try:
        proc=Path('/proc')/str(int(status['pid']))/'stat'
        return proc.read_text().split()[21]==status['process_birth']
    except (KeyError,ValueError,OSError,IndexError):return False


def live_status(status):
    try:
        age=time.time()-status['updated_at']
        return 0<=age<15 and live_process(status)
    except (KeyError,ValueError,OSError,IndexError):return False


def banner(brief=False,public_path=PUBLIC,status_path=STATUS):
    public=read_public(public_path);status=read_public(status_path)
    from gate_core import VERSION
    print('PiRate '+VERSION)
    try:device=Path('/proc/device-tree/model').read_text().rstrip('\x00\n')
    except OSError:device=os.uname().nodename
    print('Device: '+device[:100])
    username=public.get('username','')
    if not re.fullmatch('[A-Za-z0-9_.-]{1,32}',str(username)):username='не подтверждён'
    print('Admin: '+username)
    fresh=live_status(status)
    sockets=listeners();links=interfaces()
    addresses={a['local'] for link in links for a in link.get('addr_info',[]) if a.get('family')=='inet'}
    active=[]
    if live_process(status):
        for item in status.get('listeners',[]):
            if not fresh and item.get('scope')!='loopback':continue
            if public.get('bootstrap_only') and item['scope']!='loopback':continue
            if (item['address'],item['port']) in sockets and (item['address']=='127.0.0.1' or item['address'] in addresses):active.append(item)
    for item in active:
        label='локально на Pi' if item['scope']=='loopback' else 'только из '+item['scope']
        print(('Management URL: ' if item['scheme']=='https' and item['scope']!='AP' else 'WebUI: ')+item['scheme']+'://'+item['address']+':'+str(item['port'])+' ('+label+')')
        if item.get('mdns'):print('mDNS: https://pirate.local:'+str(item['port']))
    fingerprints={item.get('tls_sha256') for item in active if item.get('tls_sha256')}
    for fingerprint in fingerprints:
        if re.fullmatch('[a-f0-9]{64}',fingerprint):print('TLS SHA256: '+fingerprint)
    loopback=next((item for item in active if item['scope']=='loopback'),None)
    if loopback:
        target=None;ssh_port=None
        fields=os.environ.get('SSH_CONNECTION','').split()
        if len(fields)==4:
            try:
                candidate=str(ipaddress.IPv4Address(fields[2]));port=int(fields[3])
                if (candidate,port) in sockets or ('0.0.0.0',port) in sockets or ('*',port) in sockets or ('::',port) in sockets:
                    target=candidate;ssh_port=port
            except ValueError:pass
        if target is None:
            candidates=sorted(addresses-{'127.0.0.1'})
            if candidates and any((address,22) in sockets for address in ('0.0.0.0','*','::',*candidates)):
                target=candidates[0];ssh_port=22
        if target:
            user=os.environ.get('SUDO_USER') or getpass.getuser()
            if not re.fullmatch('[A-Za-z0-9_.-]{1,32}',user):user='USER'
            ports=loopback.get('tunnel_ports',[loopback['port']])
            preferred=public.get('tunnel_ports',[8765])[0]
            local=preferred if preferred in ports else loopback['port']
            print('SSH tunnel (на своём компьютере): ssh -N -L '+shlex.quote('127.0.0.1:'+str(local)+':127.0.0.1:'+str(loopback['port']))+' -p '+str(ssh_port)+' '+shlex.quote(user+'@'+target))
            print('После запуска tunnel: http://127.0.0.1:'+str(local))
        else:print('SSH listener/IPv4 не подтверждён; доступен локальный WebUI на Pi.')
    elif not active:print('WebUI: доступный listener не подтверждён. sudo systemctl status pirate-ap.service')
    if fresh:
        print('Wi-Fi: '+{'ON':'Active (control only)','OFF':'Stopped','ERROR':'Error','UNKNOWN':'Unknown','STARTING':'Starting','UNSUPPORTED':'Unsupported'}.get(status.get('ap'),status.get('ap','Unknown')))
        wifi=status.get('wifi_health') or {}
        if wifi:print('hostapd: '+str(wifi.get('hostapd_process','Unknown'))+' · control: '+str(wifi.get('control_state','Unknown'))+' · driver: '+str(wifi.get('driver','Unknown'))+' · beacons: UNVERIFIED')
        if wifi.get('reason'):print('Wi-Fi reason: '+str(wifi['reason'])[:300])
        if status.get('wifi_control_directory'):print('AP control directory: '+status['wifi_control_directory'])
        print('Connection: '+status.get('connection','Unknown'))
        print('Служба WebUI: RUNNING · AP '+status.get('ap','UNKNOWN')+' · LAN '+status.get('lan','UNKNOWN'))
        for note in status.get('notes',[]):print(note)
    else:print('Wi-Fi: Unknown · AP/connection runtime недоступен или устарел; management listeners проверены отдельно.')
    if not any(item['scheme']=='https' and item['scope']!='AP' for item in active):
        print('Trusted LAN: sudo pirate management enable --interface INTERFACE --subnet TRUSTED_CIDR --address LOCAL_IP')
    if public.get('bootstrap_only'):print('Пустой пароль: только локальный bootstrap. Для AP/Ethernet задай пароль: sudo pirate passwd')
    print('Help: pirate status')
    if not brief:print('Далее: создай профиль VPN/proxy; AP включается только через Apply/Confirm. Повторить: pirate status')
