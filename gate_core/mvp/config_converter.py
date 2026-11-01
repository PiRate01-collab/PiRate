"""Deterministic Config Converter v1; local validation is NOT a connection test."""
import base64
import hashlib
import ipaddress
import re
import secrets
import threading
import time
from gate_core.core import ProfileError
from .openvpn_import import check_text,decode_upload,analyze_openvpn,diagnostic
from .profile_v1 import PRIVATE,editable_config,merge_editable


def wireguard(content,filename):
    """Single peer, existing native IPv4/full-route scope; never execute wg-quick."""
    check_text(content)
    if len(content.encode())>65536:raise ProfileError('WireGuard upload exceeds 64 KiB')
    allowed={'Interface':{'PrivateKey','Address','DNS','MTU'},'Peer':{'PublicKey','PresharedKey','Endpoint','AllowedIPs','PersistentKeepalive'}}
    sections={};section=None;lines={};diagnostics=[];incompatible=False
    for number,raw in enumerate(content.splitlines(),1):
        text=raw.strip()
        if not text or text.startswith(('#',';')):continue
        if text.startswith('[') and text.endswith(']'):
            section=text[1:-1]
            if section not in allowed or section in sections:
                diagnostics.append(diagnostic(number,'section','incompatible','Exactly one Interface and Peer section supported.'));incompatible=True;section=None
            else:sections[section]={}
            continue
        if section is None or '=' not in text:
            diagnostics.append(diagnostic(number,'syntax','incompatible','Expected an option inside Interface or Peer.'));incompatible=True;continue
        key,value=[x.strip() for x in text.split('=',1)]
        # Never echo an unknown key or its value: it might contain secret text.
        if key not in allowed[section] or key in sections[section]:
            diagnostics.append(diagnostic(number,key if key in allowed[section] else 'unsupported_option','incompatible','Unknown/duplicate option or hook is not executed.'));incompatible=True;continue
        sections[section][key]=value;lines[key]=number
        diagnostics.append(diagnostic(number,key,'preserved','Retained privately.' if key in ('PrivateKey','PresharedKey') else 'Mapped to the existing WireGuard runtime field.'))
    interface=sections.get('Interface',{});peer=sections.get('Peer',{});required=[]
    def split(value):return [v.strip() for v in value.split(',') if v.strip()]
    endpoint=peer.get('Endpoint','');server,sep,port=endpoint.rpartition(':')
    profile={'name':re.sub(r'\.conf$','',re.split(r'[/\\]',filename)[-1],flags=re.I)[:80] or 'WireGuard',
        'type':'wireguard','server':server,'port':int(port) if sep and port.isascii() and port.isdecimal() and len(port)<=5 else 0,
        'config':content,'wg_private_key':interface.get('PrivateKey',''),'wg_peer_key':peer.get('PublicKey',''),
        'wg_preshared_key':peer.get('PresharedKey',''),'wg_address':split(interface.get('Address','')),
        'wg_allowed_ips':split(peer.get('AllowedIPs','0.0.0.0/0')),'dns_servers':split(interface.get('DNS',''))}
    for k,source,default in [('wg_mtu','MTU',1420),('wg_keepalive','PersistentKeepalive',25)]:
        value=(interface if source=='MTU' else peer).get(source,str(default))
        profile[k]=int(value) if value.isascii() and value.isdecimal() and len(value)<=5 else -1
    for key in ('wg_private_key','wg_peer_key','wg_address'):
        if not profile[key]:required.append(key)
    def reject(key,message):
        nonlocal incompatible
        incompatible=True;diagnostics.append(diagnostic(lines.get(key,1),key,'incompatible',message))
    from gate_core.core import ProfileStore
    if not endpoint:required.extend(('server','port'))
    else:
        try:
            if ':' in server:raise ProfileError('IPv6 endpoint unsupported')
            ProfileStore.validate({'name':profile['name'],'type':'wireguard','server':server,'port':profile['port']})
        except ProfileError:reject('Endpoint','Valid IPv4/hostname endpoint and port 1–65535 required; IPv6 endpoint is unsupported.')
    for field,key in [('wg_private_key','PrivateKey'),('wg_peer_key','PublicKey'),('wg_preshared_key','PresharedKey')]:
        if not profile[field]:continue
        try:
            if len(base64.b64decode(profile[field],validate=True))!=32:raise ValueError()
        except ValueError:reject(key,'Key must be base64 of exactly 32 bytes; key value omitted.')
    for field,key,parser in [('wg_address','Address',ipaddress.ip_interface),('wg_allowed_ips','AllowedIPs',lambda v:ipaddress.ip_network(v,strict=False)),('dns_servers','DNS',ipaddress.ip_address)]:
        try:
            values=[parser(v) for v in profile[field]]
            if len(values)>10 or field=='wg_address' and any(v.version!=4 for v in values):raise ValueError()
            profile[field]=[str(v) for v in values]
        except ValueError:reject(key,'Invalid or unsupported address list; existing IPv4 runtime scope is preserved.')
    if '0.0.0.0/0' not in profile['wg_allowed_ips']:reject('AllowedIPs','Existing WireGuard runtime requires full IPv4 AllowedIPs 0.0.0.0/0; split policy is not silently rewritten.')
    for field,key,low,high in [('wg_mtu','MTU',576,9000),('wg_keepalive','PersistentKeepalive',0,65535)]:
        if not low<=profile[field]<=high:reject(key,'Value outside the supported range.')
    if not incompatible:
        # Canonical option order; no wg-quick hooks or unmanaged routing options.
        profile['config']=render_wireguard(profile)
    return profile,diagnostics,required,False,incompatible,[]


def analyze(data):
    if not isinstance(data,dict) or set(data)-{'file_base64','filename','encoding','automatic'}:raise ProfileError('Expected file_base64, filename and optional encoding')
    filename=data.get('filename','')
    if not isinstance(filename,str) or len(filename)>1024:raise ProfileError('Invalid filename')
    kind='openvpn' if filename.lower().endswith('.ovpn') else 'wireguard' if filename.lower().endswith('.conf') else None
    if kind is None:raise ProfileError('Upload .ovpn or WireGuard .conf')
    if type(data.get('automatic',False)) is not bool:raise ProfileError('Invalid automatic import option')
    content,encoding=decode_upload(data.get('file_base64'),data.get('encoding'))
    try:
        if kind=='openvpn':
            result=analyze_openvpn(content,filename,data.get('automatic',False))
            profile,diagnostics,required,confirmation,incompatible,remotes=(result[key] for key in ('profile','diagnostics','required_fields','confirmation_required','incompatible','remotes'))
        else:profile,diagnostics,required,confirmation,incompatible,remotes=wireguard(content,filename)
    except ProfileError as exc:
        match=re.search(r'line (\d+)',str(exc),re.I)
        diagnostics=[dict(diagnostic(int(match[1]) if match else 1,'syntax','incompatible',str(exc)),error_kind=getattr(exc,'category','invalid_syntax'))]
        profile={'name':'Imported VPN','type':kind,'server':'','port':0,'config':content}
        required=[];confirmation=False;incompatible=True;remotes=[]
    profile.update(profile_version=1,import_source=data['file_base64'],import_encoding=encoding)
    if kind=='openvpn':profile.update(ovpn_source=data['file_base64'],ovpn_encoding=encoding)
    # Keep the existing response vocabulary for older clients. Local OpenVPN
    # rejections require input; they do not establish server incompatibility.
    status=('needs_user_input' if kind=='openvpn' else 'incompatible_server') if incompatible else 'needs_user_input' if required or confirmation else 'convertible'
    validation={}
    if kind=='openvpn':
        failure=next((d for d in diagnostics if d['classification']=='incompatible'),None)
        validation={'save_allowed':not incompatible,'error_kind':failure.get('error_kind','local_security_policy') if failure else 'missing_credentials' if any(k in required for k in ('username','password')) else None}

    return {**validation,'reason':import_reason(diagnostics,required),'profile':profile,'diagnostics':diagnostics,'required_fields':required,'confirmation_required':confirmation,
            'remotes':remotes,'status':status,'connectivity':'NOT_TESTED','source_sha256':hashlib.sha256(base64.b64decode(data['file_base64'])).hexdigest()}


class Drafts:
    """Bounded transient per-runtime drafts, not an additional persistent store."""
    def __init__(self):self.items={};self.lock=threading.RLock()
    def add(self,result):
        with self.lock:
            self.items={k:v for k,v in self.items.items() if v[0]>time.monotonic()}
            if len(self.items)>=16:raise ProfileError('Too many import drafts; save a draft or wait 15 minutes')
            token=secrets.token_urlsafe(32);self.items[token]=(time.monotonic()+900,result)
            return token
    def get(self,token):
        with self.lock:
            if not isinstance(token,str) or token not in self.items or self.items[token][0]<=time.monotonic():raise ProfileError('Import draft expired; upload the original file again')
            return self.items[token][1]
    def public(self,token):
        result=self.get(token);p=result['profile'];public={k:v for k,v in p.items() if k not in PRIVATE|{'username'}}
        if p['type']=='openvpn' and result['status']!='incompatible_server' and result.get('save_allowed',True):public['config']=editable_config(p['config'])
        else:public['config']=''
        public.update({k+'_saved':bool(p.get(k)) for k in ('username','password','wg_private_key','wg_preshared_key')})
        return {**{k:v for k,v in result.items() if k!='profile'},'profile':public,'draft_id':token,'schema':'pirate-profile','version':1}
    def discard(self,token):
        with self.lock:self.items.pop(token,None)
    def payload(self,data):
        data=dict(data);token=data.pop('converter_draft',None);confirmed=data.pop('converter_confirmed',False);result=self.get(token)
        if result['status']=='incompatible_server' or not result.get('save_allowed',True):
            exc=ProfileError(result['reason']);exc.category=result.get('error_kind','unsupported_feature');exc.diagnostics=result['diagnostics']
            raise exc
        if result['confirmation_required'] and confirmed is not True:raise ProfileError('Explicit confirmation of proposed security changes required')
        p=dict(result['profile'])
        if data.get('type')!=p['type']:raise ProfileError('Imported profile type cannot change; start a new profile')
        if 'config' in data and p['type']=='openvpn':
            if not isinstance(data['config'],str) or not data['config'].strip():raise ProfileError('Converted OpenVPN config cannot be empty')
            data['config']=merge_editable(data['config'],p['config'])
        for key,value in data.items():
            if key in ('import_source','import_encoding','ovpn_source','ovpn_encoding','profile_version'):continue
            if key in ('username','password','wg_private_key','wg_preshared_key') and value=='':continue
            p[key]=value
        return p


def render_wireguard(p):
    """Canonical source for the validated editable fields; not executed by wg-quick."""
    return '[Interface]\n'+''.join(k+' = '+v+'\n' for k,v in [('PrivateKey',p['wg_private_key']),('Address',', '.join(p['wg_address'])),('DNS',', '.join(p['dns_servers'])),('MTU',str(p['wg_mtu']))] if v)+'[Peer]\n'+''.join(k+' = '+v+'\n' for k,v in [('PublicKey',p['wg_peer_key']),('PresharedKey',p['wg_preshared_key']),('Endpoint',p['server']+':'+str(p['port'])),('AllowedIPs',', '.join(p['wg_allowed_ips'])),('PersistentKeepalive',str(p['wg_keepalive']))] if v)


def import_reason(diagnostics,required):
    bad=next((d for d in diagnostics if d['classification']=='incompatible'),None)
    if bad:
        key=bad['directive'];text=bad['message'].lower()
        if key=='tls-version-min':return 'Локальная политика PiRate разрешает TLS 1.2 или 1.3. Сервер ещё не проверен.'
        if key=='tls-cipher':return 'В файле нет поддерживаемого безопасного TLS-шифра. Нужен актуальный профиль VPN-сервера.'
        if key=='reneg-sec':return 'Интервал reneg-sec превышает локальный предел PiRate: 604800 секунд.' if bad.get('error_kind')=='local_security_policy' else 'Неверные аргументы reneg-sec: нужны неотрицательные max [min], min не больше max. Значение 0 допустимо.'
        if 'certificate' in text or 'trusted ca' in text or key=='key':return 'Сертификат или ключ в файле отсутствует, зашифрован либо не поддерживается. Экспортируй полный клиентский профиль.'
        if key in ('up','down','plugin','config','tls-verify','iproute','route-up'):return 'Этот профиль требует внешнего скрипта или файла. Нужен самостоятельный клиентский профиль без скриптов.'
        if 'transport' in text or 'ipv4' in text:return 'Этот профиль использует неподдерживаемый сетевой режим. Нужен клиентский профиль IPv4 UDP или TCP.'
        if key in ('cipher','data-ciphers','auth'):return 'В файле заданы неподдерживаемые настройки шифрования. Обнови клиентский профиль на VPN-сервере.'
        return 'PiRate не поддерживает эту настройку ('+key+'). Подробности ниже; сервер ещё не проверен.'
    if 'username' in required:return 'Введи логин и пароль VPN.'
    if 'password' in required:return 'Введи пароль VPN.'
    if 'ovpn_server_name' in required:return 'В файле не хватает данных для проверки сервера. Нужен полный клиентский профиль с CA и проверкой серверного сертификата.'
    return 'Профиль готов к подключению.'
