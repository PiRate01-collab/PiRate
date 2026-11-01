"""Private functional profile store; retains the existing metadata validator."""
import base64
import ipaddress
import json
import os
import threading
import uuid
from pathlib import Path
from gate_core.core import ProfileStore, ProfileError

class Profiles(ProfileStore):
    def __init__(self, path):
        super().__init__(path)
        self.lock = threading.RLock()

    @staticmethod
    def values(data, previous=None, validate_vpn=True):
        if not isinstance(data, dict):
            raise ProfileError('Expected profile object')
        base = {'name', 'type', 'server', 'port', 'dns_mode', 'notes'}
        extra = {'profile_version','import_source','import_encoding','username', 'password', 'config', 'dns_servers', 'wg_address', 'ovpn_remote', 'ovpn_proto', 'ovpn_source', 'ovpn_encoding', 'ovpn_server_name',
                 'wg_private_key', 'wg_peer_key', 'wg_preshared_key', 'wg_allowed_ips', 'wg_mtu', 'wg_keepalive'}
        if set(data) - base - extra:
            raise ProfileError('Unknown profile field')
        original={k:v for k,v in data.items() if k in base}
        direct=original.get('type')=='direct'
        common = ProfileStore.validate(dict(original,type='http') if direct else original)
        if direct:
            common.update(type='direct',server='',port=None)
            data=dict(data,username='',password=None,config=None,wg_private_key=None,wg_peer_key=None,wg_preshared_key=None,wg_address=[],wg_allowed_ips=[],dns_servers=[])
        if common['type'] not in ('direct','http', 'socks5', 'wireguard', 'openvpn'):
            raise ProfileError('Поддерживаются Direct, HTTP CONNECT, SOCKS5, OpenVPN и WireGuard')
        result = dict(common)
        result['dns_mode'] = 'automatic' if direct else 'remote' if common['type'] in ('http','socks5') else 'tunnel'
        previous = previous or {}
        from .openvpn_import import MAX_CONFIG, MAX_UPLOAD, ENCODINGS
        if 'profile_version' in data or 'profile_version' in previous:
            version=data.get('profile_version',previous.get('profile_version'))
            if type(version) is not int or version!=1:raise ProfileError('Unsupported PiRate Profile schema version')
            if common['type'] not in ('openvpn','wireguard'):raise ProfileError('Profile v1 converter supports OpenVPN and WireGuard only')
            result['profile_version']=1
            source=data.get('import_source',previous.get('import_source',''))
            if previous.get('import_source') and source!=previous['import_source']:raise ProfileError('Original upload is immutable; create a new imported profile')
            encoding=data.get('import_encoding',previous.get('import_encoding','utf-8'))
            if not isinstance(source,str) or not source:raise ProfileError('Profile v1 requires a private original upload')
            if previous.get('import_encoding') and encoding!=previous['import_encoding']:raise ProfileError('Original upload encoding is immutable')
            from .openvpn_import import decode_upload
            decode_upload(source,encoding)
            result.update(import_source=source,import_encoding=encoding)
        if common['type']=='openvpn':
            result['ovpn_remote']=data.get('ovpn_remote',previous.get('ovpn_remote',0))
            result['ovpn_proto']=data.get('ovpn_proto',previous.get('ovpn_proto',''))
            if type(result['ovpn_remote']) is not int or not 0<=result['ovpn_remote']<64:raise ProfileError('Invalid OpenVPN remote selection')
            if result['ovpn_proto'] not in ('','udp','udp4','udp6','tcp','tcp-client','tcp4-client','tcp6-client'):raise ProfileError('Invalid OpenVPN transport')
            source=data.get('ovpn_source',previous.get('ovpn_source',''))
            if not isinstance(source,str) or len(source)>4*((MAX_UPLOAD+2)//3):raise ProfileError('OpenVPN original upload exceeds 256 KiB')
            try:
                if len(base64.b64decode(source,validate=True))>MAX_UPLOAD:raise ValueError()
            except ValueError:raise ProfileError('Invalid OpenVPN original upload') from None
            result['ovpn_encoding']=data.get('ovpn_encoding',previous.get('ovpn_encoding',''))
            if not isinstance(result['ovpn_encoding'],str) or result['ovpn_encoding'] not in ENCODINGS|{''}:raise ProfileError('Invalid OpenVPN source encoding')
            result['ovpn_source']=source
            result['ovpn_server_name']=data.get('ovpn_server_name',previous.get('ovpn_server_name',''))
            import re
            if not isinstance(result['ovpn_server_name'],str) or result['ovpn_server_name'] and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',result['ovpn_server_name']):raise ProfileError('Invalid expected server certificate name')
        for key in ('username', 'password', 'config', 'wg_private_key', 'wg_peer_key', 'wg_preshared_key'):
            value = data.get(key, previous.get(key, ''))
            # Empty secret on edit means retain; use an explicit null to remove it.
            if value == '' and key in ('password', 'config', 'wg_private_key', 'wg_preshared_key'):
                value = previous.get(key, '')
            if key=='username' and common['type']=='openvpn' and value=='' and previous.get('username'):value=previous['username']
            if key=='config' and common['type']=='openvpn' and value:
                from .profile_v1 import merge_editable,MARKER
                if previous.get('config'):value=merge_editable(value,previous['config'])
                if MARKER in value:raise ProfileError('Secret placeholder has no source; re-upload the original config')
            if value is None:
                value = ''
            if not isinstance(value, str) or '\x00' in value or len(value.encode()) > (MAX_CONFIG if key == 'config' and common['type']=='openvpn' else 65536 if key=='config' else 1024):
                raise ProfileError('Invalid ' + key)
            if key in ('username', 'password') and ('\r' in value or '\n' in value):
                raise ProfileError('Credentials cannot contain newlines')
            result[key] = value
        for key in ('dns_servers', 'wg_address', 'wg_allowed_ips'):
            value = data.get(key, previous.get(key, []))
            if not isinstance(value, list) or len(value) > 10:
                raise ProfileError('Invalid ' + key)
            try:
                result[key] = [str(ipaddress.ip_address(v) if key == 'dns_servers' else
                                   ipaddress.ip_interface(v) if key == 'wg_address' else
                                   ipaddress.ip_network(v, strict=False)) for v in value]
            except (ValueError, TypeError):
                raise ProfileError('Invalid ' + key) from None
        for key in ('wg_private_key', 'wg_peer_key', 'wg_preshared_key'):
            if result[key]:
                try:
                    if len(base64.b64decode(result[key], validate=True)) != 32:
                        raise ValueError()
                except ValueError:
                    raise ProfileError('WireGuard keys must be base64 32-byte keys') from None
        for key,default,low,high in [('wg_mtu',1420,576,9000),('wg_keepalive',25,0,65535)]:
            value=data.get(key,previous.get(key,default))
            if type(value) is not int or not low<=value<=high:raise ProfileError('Invalid '+key)
            result[key]=value
        if common['type'] == 'socks5' and any(len(result[k].encode()) > 255 for k in ('username', 'password')):
            raise ProfileError('SOCKS5 credentials exceed 255 bytes')
        if result['password'] and not result['username']:
            raise ProfileError('Password requires username')
        if common['type']=='openvpn' and not result['config'] and result['ovpn_source']:
            from .openvpn_import import decode_upload
            result['config'],_=decode_upload(result['ovpn_source'],result['ovpn_encoding'] or None)
        if validate_vpn and common['type']=='openvpn':
            from .tunnels import normalize_openvpn
            from .proxy import ConnectionError
            from .profile_v1 import profile_ca_identity
            # A documentation IPv4 validates syntax without resolving or contacting the endpoint.
            try:
                _,_,auth=normalize_openvpn(result['config'],'192.0.2.1',common['port'] or 1194,
                                  result['ovpn_remote'],result['ovpn_proto'],result['ovpn_server_name'],profile_ca_identity(result))
                if auth and (not result['username'] or not result['password']):raise ConnectionError('auth-user-pass requires explicit username and password in the dedicated fields')
            except ConnectionError as exc:
                error=ProfileError(str(exc));error.category='missing_credentials' if str(exc).startswith('auth-user-pass requires') else getattr(exc,'category','local_security_policy')
                raise error from None
        if validate_vpn and result.get('profile_version')==1 and common['type']=='wireguard':
            if not result['config'].strip() or not result['wg_private_key'] or not result['wg_peer_key'] or not result['wg_address']:raise ProfileError('Converted WireGuard profile requires config, private key, peer key and address')
            if '0.0.0.0/0' not in result['wg_allowed_ips'] or any(ipaddress.ip_interface(a).version!=4 for a in result['wg_address']):raise ProfileError('WireGuard runtime requires full IPv4 routing; imported policy is not silently rewritten')
            from .config_converter import render_wireguard
            result['config']=render_wireguard(result)
        return result

    def list(self, private=False):
        with self.lock:
            if not self.path.exists():
                return []
            entries = json.loads(self.path.read_text())
            if not isinstance(entries, list) or len(entries) > 100:
                raise ProfileError('Invalid profile database')
            ids = set()
            for item in entries:
                if not isinstance(item, dict) or str(uuid.UUID(item['id'])) != item['id'] or item['id'] in ids:
                    raise ProfileError('Invalid profile ID')
                ids.add(item['id'])
                if item.get('type')=='pptp':
                    continue  # Retained on disk for owner backup; never exposed or activated.
                normalized=self.values({k:v for k,v in item.items() if k not in ('id','state')},validate_vpn=False)
                # Include recovered original config in readers (editor/runtime),
                # not only in a discarded validation result. No read-time write.
                item.update(normalized)
            supported=[item for item in entries if item.get('type')!='pptp']
            return supported if private else [self.public(item) for item in supported]

    @staticmethod
    def public(item):
        result = {k:v for k,v in item.items() if k not in ('password','config','wg_private_key','wg_preshared_key','ovpn_source','import_source')}
        result.update({k + '_saved': bool(item.get(k)) for k in ('password','config','wg_private_key','wg_preshared_key','ovpn_source','import_source')})
        if item.get('profile_version')==1 or item.get('type')=='openvpn':
            result.pop('username',None);result['username_saved']=bool(item.get('username'))
        if item.get('type')=='openvpn' and item.get('config'):
            from .openvpn_import import inspect_config
            try:result['ovpn_remotes']=inspect_config(item['config'])['remotes']
            except ProfileError:result['ovpn_remotes']=[]
        return result

    def get(self, identifier):
        for item in self.list(private=True):
            if item['id'] == identifier:
                return item
        raise ProfileError('Profile not found')

    def create(self, payload):
        with self.lock:
            values = self.values(payload)
            values.update(id=str(uuid.uuid4()), state='saved')
            entries = self.list(private=True)
            if len(entries) >= 100:
                raise ProfileError('Maximum 100 profiles')
            self._save(entries + [values])
            return self.public(values)

    def update(self, identifier, payload):
        with self.lock:
            entries = self.list(private=True)
            for index, item in enumerate(entries):
                if item['id'] == identifier:
                    entries[index] = dict(self.values(payload, item), id=identifier, state='saved')
                    self._save(entries)
                    return self.public(entries[index])
            raise ProfileError('Profile not found')

    def delete(self, identifier):
        with self.lock:
            entries = self.list(private=True)
            after = [item for item in entries if item['id'] != identifier]
            if len(after) == len(entries):
                raise ProfileError('Profile not found')
            self._save(after)
            return {'deleted': True}

    def _save(self, entries):
        # Never discard disabled legacy records when saving a supported profile.
        old=json.loads(self.path.read_text()) if self.path.exists() else []
        retained=[p for p in old if p.get('type')=='pptp']
        if len(entries)+len(retained)>100:raise ProfileError('Maximum 100 stored profiles including disabled legacy records')
        super()._save(entries+retained)
