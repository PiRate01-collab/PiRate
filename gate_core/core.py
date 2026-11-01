"""Read-only host diagnostics and validated non-secret connection profiles."""
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from . import VERSION
TYPES = ('openvpn', 'wireguard', 'socks5', 'http')
_LOCK = threading.RLock()

def command(*args):
    try:
        process = subprocess.run(args, capture_output=True, text=True, timeout=3, check=False)
        return process.stdout.strip() if process.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None

def get_conf():
    # Never elevate privileges to read sensitive configuration from the web process.
    conf = Path('/etc/gate/gate.conf')
    if not conf.is_file() or not os.access(conf, os.R_OK):
        return {}
    result = {}
    for line in conf.read_text().splitlines():
        match = re.fullmatch(r'([A-Z_]+)="([^"\n]*)"', line.strip())
        if match and match[1] in ('WAN_IF', 'AP_IFACE', 'AP_ADDR', 'AP_PREFIX', 'SSID'):
            result[match[1]] = match[2]
    return result

def snapshot():
    conf = get_conf()
    route = command('ip', '-4', 'route', 'show', 'default')
    interfaces = [x for x in [conf.get('WAN_IF'), conf.get('AP_IFACE')] if x]
    if not interfaces:
        interfaces = ['eth0', 'wlan0']
    return {
        'version': VERSION,
        'services': {name: command('systemctl', 'is-active', name) or 'unknown' for name in ('gate-router','hostapd','dnsmasq')},
        'route': route, 'interfaces': {name: command('ip','-4','-o','addr','show','dev',name,'scope','global') for name in dict.fromkeys(interfaces)},
        'forwarding': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() if Path('/proc/sys/net/ipv4/ip_forward').exists() else 'unknown',
        'config': conf,
        'dns': {'resolvers': [line.strip() for line in Path('/etc/resolv.conf').read_text().splitlines() if line.strip().startswith('nameserver ')] if Path('/etc/resolv.conf').is_file() else [], 'policy': 'Not configured in preview'},
    }

class ProfileError(ValueError):
    pass

class ProfileStore:
    def __init__(self, path):
        self.path = Path(path).expanduser()

    def list(self):
        with _LOCK:
            if not self.path.exists():
                return []
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(data, list):
                raise ProfileError('Profile database format invalid')
            for item in data:
                if not isinstance(item, dict) or set(item) != {'id', 'state', 'name', 'type', 'server', 'port', 'dns_mode', 'notes'}:
                    raise ProfileError('Profile database record invalid')
                self.validate({k: v for k, v in item.items() if k not in ('id', 'state')})
                if item['state'] != 'saved_only' or not isinstance(item['id'], str):
                    raise ProfileError('Profile database record invalid')
                try:
                    uuid.UUID(item['id'])
                except ValueError:
                    raise ProfileError('Profile database ID invalid') from None
            if len({item['id'] for item in data}) != len(data):
                raise ProfileError('Duplicate profile IDs')
            return data

    @staticmethod
    def validate(data):
        if not isinstance(data, dict):
            raise ProfileError('Expected JSON object')
        allowed = {'name', 'type', 'server', 'port', 'dns_mode', 'notes'}
        extras = set(data) - allowed
        if extras:
            raise ProfileError('Unsupported fields: ' + ', '.join(sorted(extras)))
        name = data.get('name')
        kind = data.get('type')
        server = data.get('server', '')
        port = data.get('port')
        dns_mode = data.get('dns_mode', 'automatic')
        notes = data.get('notes', '')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ProfileError('Name must be 1-80 characters')
        if kind not in TYPES:
            raise ProfileError('Unsupported connection type')
        if not isinstance(server, str) or len(server) > 253 or any(c.isspace() for c in server):
            raise ProfileError('Invalid server')
        if not isinstance(port, (int, type(None))) or isinstance(port, bool) or (port is not None and not 1 <= port <= 65535):
            raise ProfileError('Port must be 1-65535 or empty')
        if dns_mode not in ('automatic','tunnel','custom','remote'):
            raise ProfileError('Unsupported DNS mode')
        if not isinstance(notes, str) or len(notes) > 300:
            raise ProfileError('Notes must be shorter than 300 characters')
        # No passwords, keys or credentials accepted in this release.
        return {'name': name.strip(), 'type': kind, 'server': server, 'port': port,
                'dns_mode': dns_mode, 'notes': notes}

    def create(self, payload):
        profile = self.validate(payload)
        profile['id'] = str(uuid.uuid4())
        profile['state'] = 'saved_only'
        with _LOCK:
            entries = self.list()
            if len(entries) >= 100:
                raise ProfileError('Maximum 100 profiles')
            entries.append(profile)
            self._save(entries)
        return profile

    def update(self, profile_id, payload):
        values = self.validate(payload)
        with _LOCK:
            entries = self.list()
            for item in entries:
                if item.get('id') == profile_id:
                    item.update(values)
                    self._save(entries)
                    return item
        return None

    def test(self, payload):
        values = self.validate(payload)
        messages = []
        if not values['server']:
            messages.append('Сервер не указан (можно сохранить черновик)')
        if not values['port']:
            messages.append('Порт не указан (можно сохранить черновик)')
        if values['dns_mode'] == 'custom':
            messages.append('Custom DNS пока не настраивается')
        return {'valid': True, 'complete': bool(values['server'] and values['port']),
                'messages': messages, 'checked': 'structure_only', 'connected': False}

    def delete(self, profile_id):
        with _LOCK:
            entries = self.list()
            after = [x for x in entries if x.get('id') != profile_id]
            if len(entries) == len(after):
                return False
            self._save(after)
            return True

    def _save(self, entries):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=self.path.parent, prefix='.profiles-', delete=False) as out:
                tmp_path = Path(out.name)
                os.fchmod(out.fileno(), 0o600)
                json.dump(entries, out, ensure_ascii=False, indent=2)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp_path, self.path)
        finally:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink()


def import_config(kind, content):
    """Extract only non-secret metadata; never persist source material."""
    if kind not in ('openvpn', 'wireguard'):
        raise ProfileError('Импорт поддерживает только OpenVPN и WireGuard')
    if not isinstance(content, str) or len(content.encode('utf-8')) > 65536 or '\x00' in content:
        raise ProfileError('Файл пустой, бинарный или слишком большой (лимит 64 КБ)')
    if not content.strip():
        raise ProfileError('Пустой файл')
    server = ''
    port = None
    dns_mode = 'automatic'
    warnings = ['Ключи, сертификаты и пароли не импортируются и не сохраняются']
    if kind == 'openvpn':
        proto = ''
        from .openvpn_syntax import parse_document, OpenVPNSyntaxError
        try:document=parse_document(content)
        except OpenVPNSyntaxError as exc:
            error=ProfileError(str(exc));error.category=exc.category
            raise error from None
        for directive in document['directives']:
            parts=[directive['key'],*directive['args']]
            key=parts[0].lower()
            if key == 'remote' and len(parts) >= 2 and not server:
                server = parts[1]
                if len(parts) >= 3 and parts[2].isdigit():
                    port = int(parts[2])
            elif key == 'port' and len(parts) >= 2 and parts[1].isdigit() and port is None:
                port = int(parts[1])
            elif key == 'proto' and len(parts) >= 2:
                proto = parts[1].lower()
            elif key == 'dhcp-option' and len(parts) >= 3 and parts[1].upper() == 'DNS':
                dns_mode = 'tunnel'
        if not server:
            raise ProfileError('OpenVPN: не найдена строка remote SERVER [PORT]')
        if proto:
            warnings.append('OpenVPN transport: ' + proto[:30] + ' (не сохраняется в 0.2.10-dev)')
    else:
        section = ''
        for line in content.splitlines():
            line = line.strip()
            if line.startswith(('#',';')) or not line:
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1].strip().lower()
                continue
            if '=' not in line:
                continue
            key, val = [v.strip() for v in line.split('=', 1)]
            if section == 'peer' and key.lower() == 'endpoint' and not server:
                if val.startswith('[') and ']:' in val:
                    server, possible_port = val[1:].split(']:', 1)
                elif ':' in val:
                    server, possible_port = val.rsplit(':', 1)
                else:
                    server, possible_port = val, ''
                if possible_port.isdigit():
                    port = int(possible_port)
            elif section == 'interface' and key.lower() == 'dns':
                dns_mode = 'tunnel'
        if not server:
            raise ProfileError('WireGuard: не найден [Peer] Endpoint = SERVER:PORT')
    payload = {'name': f'Imported {kind.upper()}', 'type': kind, 'server': server,
               'port': port, 'dns_mode': dns_mode, 'notes': ''}
    return {'profile': ProfileStore.validate(payload), 'warnings': warnings, 'credentials_imported': False}
