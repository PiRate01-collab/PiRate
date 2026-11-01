"""Opt-in, local, bounded support archive. No upload, credentials or broad /etc copy."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ipaddress
import tarfile
import time
import uuid
from .wifi_health import execute,HostapdControl,KernelHealth
from .proxy import ConnectionError

SENSITIVE=re.compile(r'password|passphrase|psk|private.?key|token|cookie|authorization|credential|username|scrypt|salt|ovpn_source|import_source',re.I)
CONFIG_FIELDS={'interface','backend','ssid','security','country','band','channel','width','mac_mode','mac_address','fingerprint','subnet','dhcp_start','dhcp_end','lease_minutes'}
DEPLOYMENT_FIELDS={'ap_interface','wan_interface','subnet','management_interface','management_subnet','management_address','management_port','tls_managed'}


def read_json(path):
    try:
        path=Path(path)
        if path.is_symlink() or path.stat().st_size>1048576:return None
        value=json.loads(path.read_text())
        return value if isinstance(value,(dict,list)) else None
    except (OSError,ValueError):return None


def secrets(value):
    result=set()
    if isinstance(value,dict):
        for key,item in value.items():
            if SENSITIVE.search(key) and isinstance(item,str) and item:result.add(item)
            result.update(secrets(item))
    elif isinstance(value,list):
        for item in value:result.update(secrets(item))
    elif isinstance(value,str):
        for block in re.findall(r'-----BEGIN [^-]*PRIVATE KEY-----\s*(.*?)-----END [^-]*PRIVATE KEY-----',value,re.S):
            result.update(line.strip() for line in block.splitlines() if line.strip())
    return result


def redact(text,known=()):
    text=str(text)
    text=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)','[PRIVATE KEY REDACTED]',text,flags=re.S)
    text=re.sub(r'<(?:key|tls-auth|tls-crypt|auth-user-pass)>.*?(?:</(?:key|tls-auth|tls-crypt|auth-user-pass)>|\Z)','[VPN KEY REDACTED]',text,flags=re.S|re.I)
    text=re.sub(r'(?im)^.*(?:password|passphrase|\bpsk\b|wpa_psk|private.?key|authorization|cookie|auth.?token|credential|scrypt|sae_password).*$','[SECRET LINE REDACTED]',text)
    text=re.sub(r'(?i)(https?|socks5?)://[^\s/@]+:[^\s/@]+@',r'\1://[REDACTED]@',text)
    text=re.sub(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]+','[AUTH REDACTED]',text)
    for value in sorted(set(known),key=len,reverse=True):
        if value:text=text.replace(value,'[REDACTED]')
    return text


def tail(path,limit=16384):
    try:
        path=Path(path)
        if path.is_symlink():return 'Symlink omitted'
        with path.open('rb') as stream:
            stream.seek(0,2);stream.seek(max(0,stream.tell()-limit));return stream.read(limit).decode(errors='replace')
    except OSError:return 'Unavailable'


def dns_probe(address,port):
    from .router import dns_query,question_end
    query=dns_query('example.com')
    result={'address':address,'port':port,'scope':'host-local probe; not LAN-client verification','checked_at':time.time()}
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(2);sock.sendto(query,(address,port));answer=sock.recv(4096)
        if len(answer)<12 or answer[:2]!=query[:2] or not answer[2]&0x80:raise ValueError('Invalid DNS response')
        packet=bytearray(answer);packet[2]&=0x7f
        end=question_end(bytes(packet))
        if answer[12:end]!=query[12:question_end(query)]:raise ValueError('Mismatched DNS response')
        result.update(status='AVAILABLE' if answer[3]&15==0 else 'UNAVAILABLE',rcode=answer[3]&15,bytes=len(answer))
    except (OSError,ValueError,ConnectionError) as exc:result.update(status='UNKNOWN' if isinstance(exc,PermissionError) else 'UNAVAILABLE',error=type(exc).__name__,errno=getattr(exc,'errno',None))
    return result


def collect(data_dir='/var/lib/pirate',config_path='/etc/pirate/deployment.json',output=None,run=execute):
    from .admin import require_root
    require_root('diagnostics collect')
    root=Path(data_dir);ap_dir=root/'runtime/ap'
    source_state=read_json(ap_dir/'state.json');source_deployment=read_json(config_path)
    state=source_state if isinstance(source_state,dict) else {};deployment=source_deployment if isinstance(source_deployment,dict) else {}
    profiles=read_json(root/'profiles.json');confirmed=read_json(root/'runtime/confirmed-router.json')
    known=secrets(state)|secrets(profiles)|secrets(confirmed)
    # hostapd stores a derived WPA2 PSK. Mask it even if a debug log omitted its key label.
    for config in (state.get('active'),state.get('confirmed'),state.get('previous')):
        if isinstance(config,dict) and config.get('password') and config.get('ssid'):
            known.add(hashlib.pbkdf2_hmac('sha1',config['password'].encode(),config['ssid'].encode(),4096,32).hex())
    active=state.get('active') or state.get('confirmed') or {}
    interface=active.get('interface') or deployment.get('ap_interface') or (state.get('apply_failure') or {}).get('interface') or state.get('ownership',{}).get('interface')
    if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface):interface=None
    public={'version':__import__('gate_core',fromlist=['VERSION']).VERSION,'collected_at':time.time(),
        'deployment':{k:v for k,v in deployment.items() if k in DEPLOYMENT_FIELDS},
        'ap':{'config':{k:v for k,v in active.items() if k in CONFIG_FIELDS},'pending':state.get('pending'),'requested_identity':state.get('requested_identity'),'apply_failure':state.get('apply_failure'),'operations':state.get('operations',[])[-48:],'ownership':state.get('ownership',{}),'owned_processes':state.get('processes',[]),
              'recovery':state.get('recovery',{}),'power_save':state.get('power_save',{}),'radio':state.get('confirmed_radio'),'health':state.get('health'),'failure':state.get('failure'),'last_action':state.get('last_action')},
        'notice':'Control/process/type AP do not prove beacons; this archive does not diagnose a proven power-saving cause.'}
    owned=[]
    for record in state.get('processes',[]):
        item={k:v for k,v in record.items() if k in ('name','pid','birth','net_inode')}
        item['verified_owned']=False
        try:
            proc=Path('/proc')/str(int(record['pid']))
            item['verified_owned']=(proc.joinpath('stat').read_text().split()[21]==record['birth'] and os.stat(proc/'ns/net').st_ino==record['net_inode'] and str(ap_dir).encode() in proc.joinpath('cmdline').read_bytes())
            item['process_state']=proc.joinpath('stat').read_text().split()[2]
        except (OSError,ValueError,KeyError,IndexError):item['process_state']='Unavailable'
        owned.append(item)
    files={'hostapd-ownership.json':json.dumps({'recorded_processes':owned,'interface_evidence':state.get('ownership',{}),'notice':'A global supplicant/service process alone does not prove interface ownership.'}), 'summary.json' :json.dumps(public,ensure_ascii=False,indent=2),'dhcp-leases.txt':tail(ap_dir/'leases')}
    router=read_json(root/'runtime/router.json') or {}
    config=router.get('config',{}) if isinstance(router,dict) else {}
    files['dns-routing.json']=json.dumps({k:v for k,v in config.items() if k in ('lan_interface','wan_interface','lan_subnet','dns_mode','dns_server','dns_port','ap_dns_address','management_port','fingerprint')},indent=2)
    commands={
        'service.txt':('systemctl','show','pirate-ap.service','--property=ActiveState,SubState,Result,MainPID'),
        'listeners.txt':('ss','-H','-ltnp'),
        'addresses.json':('ip','-j','address','show'),
        'routes.json':('ip','-j','-4','route','show','table','all'),
        'policy-rules.json':('ip','-j','-4','rule','show'),
        'udp-listeners.txt':('ss','-H','-lunp'),
        'gateway-firewall.txt':('nft','list','table','inet','pirate_gateway'),
        'management-firewall.txt':('nft','list','table','inet','pirate_management'),
    }
    client_sample=None;gateway_sample=None;lan_network=None
    try:
        lan=ipaddress.IPv4Interface(active['subnet']);gateway_sample=str(lan.ip);lan_network=str(lan.network)
        for line in files['dhcp-leases.txt'].splitlines():
            fields=line.split()
            if len(fields)>2 and ipaddress.IPv4Address(fields[2]) in lan.network:
                client_sample=str(ipaddress.IPv4Address(fields[2]));break
    except (ValueError,KeyError,TypeError):pass
    if interface:
        commands['packet-sysctls.txt']=('sysctl','net.ipv4.ip_forward','net.ipv4.conf.all.rp_filter','net.ipv4.conf.'+interface+'.rp_filter','net.ipv4.conf.all.src_valid_mark','net.ipv4.conf.'+interface+'.src_valid_mark','net.ipv4.fwmark_reflect')
        if lan_network:commands['dns-conntrack.txt']=('conntrack','-L','-f','ipv4','-p','udp','--orig-src',lan_network,'--dport','53','-o','extended')
        if client_sample:commands['route-client-unmarked.txt']=('ip','-4','route','get',client_sample,'from',gateway_sample)
        commands.update({'wifi-link.json':('ip','-j','-d','link','show','dev',interface),'wifi-interface.txt':('iw','dev',interface,'info'),'wifi-stations.txt':('iw','dev',interface,'station','dump'),
                         'wifi-power-save.txt':('iw','dev',interface,'get','power_save'),
                         'wifi-supplicant.txt':('wpa_cli','-i',interface,'status'),
                         'wifi-networkmanager.txt':('nmcli','-g','GENERAL.STATE,GENERAL.CONNECTION','device','show',interface)})
        monitor=KernelHealth(interface,run=run)
        monitor.targets.update(target for target in state.get('kernel_targets',[]) if isinstance(target,str) and len(target)<128)
        monitor.since=max(0,time.monotonic()-30)
        files['wifi-kernel.json']=json.dumps(monitor.poll(),ensure_ascii=False,indent=2)
        for record in reversed(state.get('controls',[])):
            name=record.get('directory','')
            if record.get('interface')!=interface or not re.fullmatch(r'[0-9a-f]{16}',name):continue
            directory=ap_dir/'control'/name
            try:
                if directory.is_symlink() or directory.stat().st_ino!=record['dir_inode']:continue
                if (directory/interface).lstat().st_ino!=record.get('socket_inode'):continue
            except OSError:continue
            control=HostapdControl(directory,interface)
            status=control.status()
            files['hostapd-control.json']=json.dumps({'status':{k:v for k,v in status.items() if k in ('state','phy','freq','channel','num_sta','secondary_channel','vht_oper_chwidth')},'stations':control.stations()},indent=2)
            break
    connection=read_json(root/'runtime/connection.json') or {}
    from .tunnels import resource_for,routing_id
    for resource in connection.get('native_resources',[])[:2] if isinstance(connection,dict) else []:
        try:
            if resource!=resource_for(resource['token'],resource['wan']):continue
        except (ValueError,KeyError,TypeError,RuntimeError):continue
        namespace=resource['namespace'];token=resource['token'];identifier=str(routing_id(resource))
        for suffix,args in {
            'links':('ip','-j','link','show'), 'routes':('ip','-j','-4','route','show','table','all'),
            'firewall':('nft','-a','list','table','inet','pirate_tunnel'),
            'handshakes':('wg','show','wg0','latest-handshakes'),
            'transfer':('wg','show','wg0','transfer'),
        }.items():commands['vpn-'+token+'-'+suffix+'.txt']=('ip','netns','exec',namespace,*args)
        if client_sample:commands['vpn-'+token+'-route-client-marked.txt']=('ip','-4','route','get',client_sample,'from',gateway_sample,'mark',identifier)
        commands['vpn-'+token+'-host-table.txt']=('ip','-4','route','show','table',identifier)
        commands['vpn-'+token+'-transport-guard.txt']=('nft','list','table','inet','pn_'+token)
    command_results={}
    for name,args in commands.items():
        result=run(*args);command_results[name]=result
        files[name]=json.dumps({'exit':result.returncode,'stdout':result.stdout[-32768:],'stderr':result.stderr[-4096:]}) if name.endswith('.json') else ('exit='+str(result.returncode)+'\n'+result.stdout+'\n'+result.stderr)[-32768:]
    # Do not include application log lines if secret sources could not be read.
    wifi_secrets_available=any(isinstance(state.get(key),dict) and state[key].get('password') for key in ('active','confirmed','previous'))
    if profiles is not None and isinstance(source_state,dict) and wifi_secrets_available:
        for name in ('hostapd','dnsmasq'):files[name+'.log']=tail(ap_dir/(name+'.log'))
        result=run('journalctl','-b','-u','pirate-ap.service','-n','80','--no-pager','-o','cat')
        files['pirate-service.log']=result.stdout[-16384:]
    else:files['application-logs.txt']='Application logs omitted: profile/Wi-Fi secret inventory unavailable for reliable redaction after cleanup.'
    status=read_json('/run/pirate/status.json') or {}
    from .admin import live_status
    dns={'dnsmasq_udp':'UNKNOWN','dnsmasq_tcp':'UNKNOWN','runtime_fresh':live_status(status),'runtime':status.get('dns',{}),'client_delivery':'UNVERIFIED; inspect client_dns_request/client_dns_reply counters; no packet capture was started','probes':[]}
    try:gateway=str(ipaddress.IPv4Interface(active['subnet']).ip)
    except (ValueError,TypeError,KeyError):gateway=None
    for name,key in (('udp-listeners.txt','dnsmasq_udp'),('listeners.txt','dnsmasq_tcp')):
        result=command_results[name]
        if result.returncode==0 and gateway:
            dns[key]='NOT_LISTENING'
            for line in result.stdout.splitlines():
                fields=line.split()
                if len(fields)<4:continue
                if fields[3] not in (gateway+':53','0.0.0.0:53','*:53'):continue
                dns[key]='SOCKET_PRESENT_OWNER_UNKNOWN'
                if any(item.get('name')=='dnsmasq' and item['verified_owned'] and 'pid='+str(item['pid'])+',' in line for item in owned):dns[key]='LISTENING_OWNED'
    port=(status.get('dns') or {}).get('listener_port')
    if dns['runtime_fresh'] and type(port) is int and 1024<=port<=65535:
        dns['probes'].append(dns_probe('127.0.0.1',port))
        try:gateway=str(ipaddress.IPv4Interface(active['subnet']).ip)
        except (ValueError,TypeError,KeyError):gateway=None
        if gateway:dns['probes'].append(dns_probe(gateway,53))
    else:dns['note']='No fresh owned runtime/listener port; local DNS probes omitted'
    files['dns-path.json']=json.dumps(dns,ensure_ascii=False,indent=2)
    files['management.json']=json.dumps({k:v for k,v in status.items() if k in ('updated_at','listeners','ap','connection','lan','notes')},ensure_ascii=False,indent=2)
    files['README.txt']='Local support bundle. No upload performed. Review before sharing.\nNo raw profiles, hostapd config, auth store, private keys, /etc tree or shell history is included.\nLogs are bounded and redacted; inspect the archive yourself for site-specific sensitive information.\n'
    output=Path(output or ('pirate-diagnostics-'+time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]+'.tar.gz')).absolute()
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        with tarfile.open(fileobj=stream,mode='w:gz') as archive:
            for name,text in files.items():
                if name.endswith('.json'):
                    def clean(value):
                        if isinstance(value,dict):return {k:clean(v) for k,v in value.items()}
                        if isinstance(value,list):return [clean(v) for v in value]
                        return redact(value,known) if isinstance(value,str) else value
                    raw=json.dumps(clean(json.loads(text)),ensure_ascii=False,indent=2).encode()
                else:raw=redact(text,known).encode()
                member=tarfile.TarInfo('pirate-diagnostics/'+name)
                member.mode=0o600;member.size=len(raw);member.mtime=int(time.time());archive.addfile(member,io.BytesIO(raw))
    print('Diagnostics archive (private 0600): '+str(output))
    print('Review files: tar -tzf '+shlex.quote(str(output)))
    print('Read summary: tar -xOf '+shlex.quote(str(output))+' pirate-diagnostics/summary.json')
    print('Review locally before sharing; nothing was uploaded.')
    return output
