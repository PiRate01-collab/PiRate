"""Functional MVP routes, sharing the existing loopback HTTP admission layer."""
import os
import shutil
import threading
from pathlib import Path
from gate_core.core import ProfileError, import_config
from gate_core.mvp.profiles import Profiles
from gate_core.mvp.connections import Connections
from gate_core.mvp.openvpn_import import preview_upload, MAX_JSON
from gate_core.mvp.proxy import ConnectionError

_LOCK=threading.Lock()
_RUNTIME=None

def runtime():
    global _RUNTIME
    with _LOCK:
        if _RUNTIME is None:
            data=Path(os.environ.get('PIRATE_DATA_DIR',str(Path.home()/'.local/share/pirate')))
            profiles=Profiles(data/'profiles.json')
            # Copy legacy metadata once; never rewrite the original database.
            legacy=Path(os.environ.get('GATE_PROFILE_PATH',str(Path.home()/'.local/share/gate-native/profiles.json')))
            if not profiles.path.exists() and legacy.exists():
                from gate_core.core import ProfileStore
                for item in ProfileStore(legacy).list():
                    if item['type'] in ('http','socks5','openvpn','wireguard'):
                        profiles.create({k:v for k,v in item.items() if k not in ('id','state')})
            if not profiles.list():profiles.create({'name':'Direct','type':'direct'})
            _RUNTIME=Connections(profiles,data/'runtime',int(os.environ.get('PIRATE_PROXY_PORT','8088')),
                                 os.environ.get('PIRATE_CHECK_URL','https://api.ipify.org/'))
        return _RUNTIME

def handle(handler,method,path):
    if not path.startswith('/api/mvp/'):
        return False
    try:
        app=getattr(getattr(handler,'server',None),'pirate_app',None) or runtime()
        suffix=path.removeprefix('/api/mvp/')
        if suffix.startswith('support/'):
            # Unlike the historical preview API, diagnostics/probes require admin auth.
            if getattr(getattr(handler,'server',None),'auth',None) is None:
                handler.send_data(403,{'error':'Admin authentication required'});return True
            from gate_core.mvp.support import service
            from gate_core.mvp.preflight import Preflight
            support=service(app)
            if suffix=='support/preflight' and method=='GET':
                with _LOCK:
                    if support.preflight is None:support.preflight=Preflight(app,support)
                result=support.preflight.status()
            elif method=='POST':
                data=handler.read_json(2000)
                if not isinstance(data,dict):raise ProfileError('Expected object')
                if suffix in ('support/logs','support/logs.log'):
                    result=support.logs(data)
                    if suffix.endswith('.log'):
                        raw='\n'.join(r['line'] for r in result['entries']).encode()
                        handler.send_data(200,raw,'text/plain; charset=utf-8',extra_headers={'Content-Disposition':'attachment; filename="pirate-filtered.log"'})
                        return True
                elif suffix=='support/diagnostics.zip':
                    if data:raise ProfileError('Expected empty object')
                    # Serialize expensive exports, also bounding simultaneous memory.
                    if not support.export_lock.acquire(blocking=False):raise ProfileError('Diagnostic export already running')
                    try:raw=support.report()
                    finally:support.export_lock.release()
                    handler.send_data(200,raw,'application/zip',extra_headers={'Content-Disposition':'attachment; filename="pirate-diagnostics.zip"'})
                    return True
                elif suffix in ('support/preflight','support/preflight-cancel'):
                    with _LOCK:
                        if support.preflight is None:support.preflight=Preflight(app,support)
                    if suffix.endswith('-cancel'):
                        if data:raise ProfileError('Expected empty object')
                        result=support.preflight.cancel()
                    else:
                        if set(data) not in ({'profile_id'},{'all'}):raise ProfileError('Supply saved profile_id or all=true only')
                        if 'all' in data and data['all'] is not True:raise ProfileError('Expected all=true')
                        if 'profile_id' in data and not isinstance(data['profile_id'],str):raise ProfileError('Invalid saved profile ID')
                        result=support.preflight.start(data.get('profile_id'))
                else:raise ProfileError('Unknown support endpoint')
            else:raise ProfileError('Unsupported support method')
            handler.send_data(200,result);return True
        if suffix=='ap-profiles' or suffix.startswith('ap-profiles/'):
            from gate_core.mvp.ap_profiles import store,selection
            from gate_core.mvp.router_service import RouterService
            with app.lock:
                db=store(app)
                if suffix=='ap-profiles' and method=='GET':
                    result={'profiles':db.list(),**selection(app)}
                elif suffix=='ap-profiles' and method=='POST':
                    result=db.create(handler.read_json(15000))
                elif suffix.startswith('ap-profiles/'):
                    parts=suffix.split('/');identifier=parts[1]
                    if len(parts)==3 and method=='POST' and parts[2] in ('duplicate','apply'):
                        if handler.read_json(1000)!={}:raise ProfileError('Expected empty object')
                        if parts[2]=='duplicate':result=db.duplicate(identifier)
                        else:
                            if not hasattr(app,'simple_router'):app.simple_router=RouterService(app)
                            result=app.simple_router.apply_wifi_profile(identifier)
                    elif len(parts)==2 and method in ('PUT','DELETE'):
                        if identifier in selection(app)['protected_ids']:
                            raise ProfileError('Активный, подтверждённый или ожидающий отката профиль защищён. Создайте копию либо подтвердите другой профиль.')
                        result=db.update(identifier,handler.read_json(15000)) if method=='PUT' else db.delete(identifier)
                    else:return handler.send_data(404,{'error':'Not found'}) or True
                else:return handler.send_data(404,{'error':'Not found'}) or True
            handler.send_data(201 if method=='POST' and (suffix=='ap-profiles' or suffix.endswith('/duplicate')) else 200,result)
            return True
        if method=='GET':
            if suffix in ('dashboard','setup','system'):
                from gate_core.mvp.router_service import RouterService
                if not hasattr(app,'simple_router'):app.simple_router=RouterService(app)
                result=getattr(app.simple_router,suffix)()
                if suffix=='system':result['password_change_available']=getattr(getattr(handler,'server',None),'auth',None) is not None
            elif suffix=='profiles':result={'profiles':app.profiles.list()}
            elif suffix.startswith('profiles/') and suffix.endswith('/editor'):
                item=app.profiles.get(suffix[len('profiles/'):-len('/editor')])
                # Same authenticated owner-only/no-store admission as preview.
                from gate_core.mvp.profile_v1 import editable_config
                result={'config':editable_config(item.get('config','')) if item['type']=='openvpn' else '',
                        'ovpn_server_name':item.get('ovpn_server_name','')}
            elif suffix=='status':result=app.status()
            elif suffix=='diagnostics':result=app.diagnostics()
            elif suffix=='router':result=app.router.status()
            elif suffix=='ap':
                from gate_core.mvp.ap import capabilities
                result=app.ap.public()
                result['capabilities']=capabilities((result.get('config') or {}).get('interface','wlan0'))
            elif suffix=='capabilities':
                result={'http':{'implemented':True,'requires_root':False},'socks5':{'implemented':True,'requires_root':False},
                        'native_enabled':os.environ.get('PIRATE_NATIVE_TUNNELS')=='1',
                        'openvpn':{'implemented':True,'binary_installed':bool(shutil.which('openvpn',path=os.environ.get('PATH','')+':/usr/sbin:/sbin')),'test_status':'NOT TESTED'},
                        'wireguard':{'implemented':True,'binary_installed':bool(shutil.which('wg')),'test_status':'NOT TESTED'},
                        'scope':'Proxy clients and opt-in LAN IPv4 TCP/UDP through native VPN; runtime probes determine connectivity',
                        'router':{'tcp':'IMPLEMENTED','udp':'Native VPN IPv4; proxy profiles DNS only','requires':'CAP_NET_ADMIN and PIRATE_ROUTER_MODE=1','default':'DISABLED'}}
            else:return handler.send_data(404,{'error':'Not found'}) or True
        elif method=='POST':
            data=handler.read_json(MAX_JSON if suffix in ('convert-config','openvpn-preview','profiles','import') else 150000)
            if not isinstance(data,dict):raise ProfileError('Expected JSON object')
            if suffix=='router-apply':
                from gate_core.mvp.router_service import RouterService
                if not hasattr(app,'simple_router'):app.simple_router=RouterService(app)
                result=app.simple_router.apply(data)
            elif suffix=='dns-test':
                if set(data)-{'profile_id','servers','wan_interface','doh_url'} or 'profile_id' not in data:raise ProfileError('Expected DNS test settings')
                result=app.test_dns(data['profile_id'],data.get('servers'),data.get('wan_interface'),data.get('doh_url'))
            elif suffix=='mac-generate':
                if data:raise ProfileError('Expected empty object')
                from gate_core.mvp.mac import generate
                result={'mac':generate()}
            elif suffix=='hardware-mac':
                import re
                if set(data)!={'interface'} or not isinstance(data['interface'],str) or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',data['interface']):raise ProfileError('Expected interface')
                from gate_core.mvp.mac import hardware
                result={'mac':hardware(data['interface'])}
            elif suffix=='ap-capabilities':
                import re
                from gate_core.mvp.ap import capabilities
                if set(data)!={'interface'} or not isinstance(data['interface'],str) or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',data['interface']):raise ProfileError('Expected AP interface')
                result=capabilities(data['interface'])
            elif suffix=='convert-config':
                from gate_core.mvp.config_converter import Drafts,analyze
                with _LOCK:
                    if not hasattr(app,'conversion_drafts'):app.conversion_drafts=Drafts()
                token=app.conversion_drafts.add(analyze(data));result=app.conversion_drafts.public(token)
            elif suffix=='openvpn-preview':result=preview_upload(data)
            elif suffix=='system':
                auth=getattr(getattr(handler,'server',None),'auth',None)
                if auth is None:raise ProfileError('Смена пароля доступна только в панели с настроенной аутентификацией.')
                if set(data)!={'current_password','new_password'}:raise ProfileError('Укажите текущий и новый пароль.')
                current,new=data['current_password'],data['new_password']
                if not isinstance(current,str) or not isinstance(new,str) or not 8<=len(new)<=20 or any(c in new for c in '\r\n\x00'):
                    raise ProfileError('Новый пароль должен содержать от 8 до 20 символов.')
                import base64
                header='Basic '+base64.b64encode((auth.username+':'+current).encode()).decode()
                if not auth.verify(header,handler.client_address[0]):raise ProfileError('Текущий пароль неверен или превышен лимит попыток.')
                from gate_core.mvp.admin import atomic_json,password_hash
                atomic_json(auth.path,password_hash(auth.username,new))
                auth.refresh()
                result={'changed':True}
            elif suffix=='profiles':
                if 'duplicate_from' in data:
                    if set(data)!={'duplicate_from'}:raise ProfileError('Expected duplicate_from only')
                    source=app.profiles.get(data['duplicate_from'])
                    data={k:v for k,v in source.items() if k not in ('id','state')}
                    data['name']=data['name'][:70]+' (копия)'
                token=data.get('converter_draft')
                if 'converter_draft' in data:
                    if not hasattr(app,'conversion_drafts'):raise ProfileError('Import draft unavailable; upload again')
                    data=app.conversion_drafts.payload(data)
                result=app.profiles.create(data)
                if token:app.conversion_drafts.discard(token)
            elif suffix=='import':
                if set(data)!={'type','content'}:raise ProfileError('Expected type and content')
                if data['type']=='openvpn':
                    import base64
                    from gate_core.mvp.openvpn_import import check_text
                    check_text(data['content'])
                    draft=preview_upload({'file_base64':base64.b64encode(data['content'].encode()).decode()})
                    imported={'profile':draft['profile']}
                else:imported=import_config(data['type'],data['content'])
                # Retain full private source so import can actually start a tunnel.
                values=imported['profile'];values['config']=data['content'] if data['type']=='openvpn' else ''
                if data['type']!='openvpn':values['dns_servers']=[]
                if data['type']=='wireguard':
                    import configparser
                    parser=configparser.ConfigParser(strict=True,interpolation=None)
                    try:parser.read_string(data['content'])
                    except configparser.Error:raise ProfileError('Invalid WireGuard configuration') from None
                    allowed={'Interface':{'PrivateKey','Address','DNS','MTU'},'Peer':{'PublicKey','PresharedKey','Endpoint','AllowedIPs','PersistentKeepalive'}}
                    for section in parser.sections():
                        if section not in allowed or any(k.lower() not in {x.lower() for x in allowed[section]} for k in parser[section]):
                            raise ProfileError('WireGuard import supports one interface/peer; hooks and extra directives unsupported')
                    if set(parser.sections())!={'Interface','Peer'}:
                        raise ProfileError('WireGuard requires one [Interface] and one [Peer] section')
                    interface=parser['Interface'];peer=parser['Peer']
                    try:values.update(wg_mtu=int(interface.get('MTU','1420')),wg_keepalive=int(peer.get('PersistentKeepalive','25')))
                    except ValueError:raise ProfileError('Invalid WireGuard MTU/keepalive') from None
                    values.update(wg_private_key=interface.get('PrivateKey',''),wg_peer_key=peer.get('PublicKey',''),
                                  wg_preshared_key=peer.get('PresharedKey',''),wg_address=[x.strip() for x in interface.get('Address','').split(',') if x.strip()],
                                  wg_allowed_ips=[x.strip() for x in peer.get('AllowedIPs','0.0.0.0/0').split(',') if x.strip()],
                                  dns_servers=[x.strip() for x in interface.get('DNS','').split(',') if x.strip()])
                result=app.profiles.create(values)
            elif suffix=='connect':
                if set(data)-{'profile_id','timeout','gateway','ap'} or 'profile_id' not in data:raise ProfileError('Expected profile_id and timeout')
                if isinstance(data.get('ap'),dict) and 'saved_profile_id' in data['ap']:raise ProfileError('Use router-apply with wifi_profile_id for saved AP settings')
                result=app.connect(data['profile_id'],data.get('timeout',60),gateway_config=data.get('gateway'),ap_config=data.get('ap'))
            elif suffix=='retry-wifi':
                if data:raise ProfileError('Expected empty object')
                result=app.retry_wifi()
            elif suffix in ('confirm','rollback','disconnect'):
                if data:raise ProfileError('Expected empty object')
                result=getattr(app,suffix)()
            elif suffix=='probe':
                if data:raise ProfileError('Expected empty object')
                result=app.diagnostics(probe=True)
            else:return handler.send_data(404,{'error':'Not found'}) or True
        elif method in ('PUT','DELETE') and suffix.startswith('profiles/'):
            identifier=suffix.removeprefix('profiles/')
            # Editing a live profile would make displayed settings differ from the backend.
            with app.lock:
                if identifier in [b.profile['id'] for b in (app.current,app.previous) if b]:
                    raise ProfileError('Сначала отключите этот профиль, чтобы изменить или удалить его. Можно создать копию без отключения.')
                result=app.profiles.update(identifier,handler.read_json(MAX_JSON)) if method=='PUT' else app.profiles.delete(identifier)
        else:return handler.send_data(404,{'error':'Not found'}) or True
        handler.send_data(201 if method=='POST' and suffix in ('profiles','import') else 200,result)
    except (ProfileError,ConnectionError) as exc:
        error={'error':str(exc)}
        if hasattr(exc,'category'):error['error_kind']=exc.category
        message=connection_message(str(exc))
        if message!=str(exc):error['message']=message
        handler.send_data(getattr(exc,'status',400),error)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        if isinstance(exc,ValueError) and path.startswith('/api/mvp/support/'):
            from gate_core.mvp.support import sanitize
            handler.send_data(400,{'error':sanitize(str(exc))[:500]})
        else:handler.send_data(503,{'error':'Backend or saved state unavailable; check server log'})
    return True


def connection_message(text):
    """Keep technical cause in error/details; use one specific primary sentence."""
    lower=text.lower()
    if 'auth-user-pass requires' in lower or 'explicit username/password' in lower:return 'Введи логин и пароль VPN.'
    if 'draft expired' in lower or 'draft unavailable' in lower:return 'Время ввода истекло. Загрузи файл подключения ещё раз.'
    if 'vpn endpoint dns failed' in lower:return 'Не удалось найти адрес VPN-сервера. Проверь Интернет и адрес сервера.'
    if 'missing backend binary: openvpn' in lower:return 'На Pi не установлен OpenVPN. Установи пакет OpenVPN и повтори подключение.'
    if 'connection is empty' in lower or 'configuration is empty' in lower:return 'В файле нет конфигурации OpenVPN. Загрузи полный клиентский профиль.'
    return text
