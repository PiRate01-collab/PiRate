#!/usr/bin/env python3
"""Loopback PiRate WebUI: functional connections plus retained Wi-Fi preview."""
import json
import ipaddress
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gate_core import VERSION
from web import mvp_api
from gate_core.core import ProfileStore, ProfileError, snapshot, import_config
from gate_core.connection_engine import capabilities, inspect_profile, tunnel_plan
from gate_core.namespace_probe import preflight
from gate_core.transport_probe import preflight as transport_preflight
from gate_core.uplink_probe import preflight as uplink_preflight
from gate_core.core import get_conf
from gate_core.wifi.store import WiFiProfileStore, WiFiStoreError
from gate_core.wifi.models import WiFiError, profile_id
from gate_core.wifi.apply import ApplyError
from gate_core.wifi.apply.persistence import PersistenceError
from web.mock_apply import controller as mock_apply_controller, INTERFACE as MOCK_INTERFACE
from gate_core.wifi.radio import UnknownRadioProvider, IwRadioProvider
from gate_core.wifi.validation import validate_configuration, preview_configuration, UnknownSecretReferences

HOST = '127.0.0.1'  # Deliberately hardcoded until authentication exists.
PORT = int(os.environ.get('GATE_WEB_PORT', '8765'))
STORE = ProfileStore(os.environ.get('GATE_PROFILE_PATH', str(Path.home() / '.local/share/gate-native/profiles.json')))
WIFI_STORE = WiFiProfileStore(os.environ.get('PIRATE_WIFI_PROFILE_PATH', str(Path.home() / '.local/share/gate-native/wifi/profiles.json')))
RADIO = IwRadioProvider() if os.environ.get('PIRATE_WIFI_DIAGNOSTICS') == 'iw' else UnknownRadioProvider()
WIFI_SECRETS = UnknownSecretReferences()
MOCK_APPLY_PATH = Path(os.environ.get('PIRATE_MOCK_APPLY_PATH', str(Path.home() / '.local/state/gate-native/wifi-mock-apply')))
FILES = {'/openvpn_import.js': ('openvpn_import.js','application/javascript; charset=utf-8'),'/router.css': ('router.css','text/css; charset=utf-8'),'/': ('index.html', 'text/html; charset=utf-8'), '/index.html': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'application/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'), '/wifi.js': ('wifi.js', 'application/javascript; charset=utf-8'), '/safe-apply.js': ('safe-apply.js', 'application/javascript; charset=utf-8')}

REQUEST_TIMEOUT = 5

class RequestError(ProfileError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT)

    def request_allowed(self):
        subnet=getattr(getattr(self,'server',None),'allowed_subnet',None)
        if subnet and ipaddress.ip_address(self.client_address[0]) not in ipaddress.ip_network(subnet):
            self.send_data(403, {'error':'Management subnet denied'});return False
        hosts = self.headers.get_all('Host', [])
        settings=getattr(getattr(self,'server',None),'management',None)
        authorities=settings['authorities'] if isinstance(settings,dict) else [f'{HOST}:{PORT}']
        if len(hosts)!=1 or hosts[0] not in authorities:
            self.send_data(403, {'error': 'Host denied'})
            return False
        if not self.allowed_origin():
            self.send_data(403, {'error': 'Origin denied'})
            return False
        auth=getattr(getattr(self,'server',None),'auth',None)
        if getattr(getattr(self,'server',None),'remote_management',False):
            if auth is None:
                self.send_data(403,{'error':'Remote management requires authentication'});return False
            if getattr(self,'command','GET') in ('POST','PUT','DELETE','PATCH') and (not self.headers.get('Origin') or self.headers.get('Sec-Fetch-Site')=='cross-site'):
                self.send_data(403,{'error':'Same-origin request required'});return False
        if auth is not None:
            headers=self.headers.get_all('Authorization',[])
            if len(headers)!=1 or not auth.verify(headers[0],self.client_address[0],remote=bool(getattr(self.server,'remote_management',False))):
                self.send_data(401,{'error':'Authentication required'},extra_headers={'WWW-Authenticate':'Basic realm="PiRate", charset="UTF-8"'})
                return False
        return True

    def send_data(self, code, data, mime='application/json; charset=utf-8',extra_headers=None):
        body = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Gate-Version', VERSION)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'")
        self.send_header('X-Frame-Options', 'DENY')
        for key,value in (extra_headers or {}).items():self.send_header(key,value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.request_allowed():
            return
        path = urlsplit(self.path).path
        if mvp_api.handle(self, 'GET', path):
            return
        try:
            if path == '/api/wifi/mock-apply/status':
                if not MOCK_APPLY_PATH.exists() and not MOCK_APPLY_PATH.is_symlink():
                    return self.send_data(200, {'operations': [], 'mock_only': True, 'real_apply_available': False})
                return self.send_data(200, mock_apply_controller(MOCK_APPLY_PATH, WIFI_STORE).status())
            if path == '/api/wifi/profiles':
                return self.send_data(200, {'profiles': WIFI_STORE.list(), 'preview_only': True, 'apply_available': False})
            if path == '/api/wifi/capabilities':
                return self.send_data(200, RADIO.snapshot().as_dict())
            if path == '/api/wifi/status':
                conf = get_conf()
                caps = RADIO.snapshot()
                identity_matches = not conf.get('AP_IFACE') or conf.get('AP_IFACE') == caps.interface
                return self.send_data(200, {'current_ap': {'configured_ssid': conf.get('SSID'),
                    'interface': conf.get('AP_IFACE') or caps.interface, 'address': conf.get('AP_ADDR'),
                    'hardware_mac': caps.hardware_mac if identity_matches else None, 'observed_mac': caps.observed_mac if identity_matches else None, 'operational_status': 'unknown'},
                    'capabilities': caps.as_dict(), 'preview_only': True, 'apply_available': False})
            if path == '/api/version':
                return self.send_data(200, {'version': VERSION})
            if path == '/api/status':
                return self.send_data(200, snapshot())
            if path == '/api/uplink-preflight':
                return self.send_data(200, uplink_preflight())
            if path == '/api/transport-preflight':
                return self.send_data(200, transport_preflight())
            if path == '/api/namespace-preflight':
                return self.send_data(200, preflight())
            if path == '/api/connection-capabilities':
                return self.send_data(200, {'capabilities': capabilities(), 'mode': 'inspection_only'})
            if path == '/api/profiles':
                return self.send_data(200, {'profiles': STORE.list()})
            if path in ('/', '/index.html', '/mvp.js'):
                filename = 'mvp.js' if path == '/mvp.js' else 'mvp.html'
                mime = 'application/javascript; charset=utf-8' if path == '/mvp.js' else 'text/html; charset=utf-8'
                return self.send_data(200, (ROOT / 'web' / filename).read_bytes(), mime)
            if path == '/preview':return self.send_data(404,{'error':'Not found'})
            if path in FILES:
                filename, mime = FILES[path]
                return self.send_data(200, (ROOT / 'web' / filename).read_bytes(), mime)
            self.send_data(404, {'error':'Not found'})
        except PersistenceError:
            self.send_data(500, {'state': 'recovery_required', 'error': 'Mock storage invalid; independent recovery required', 'mock_only': True, 'real_apply_available': False})
        except TimeoutError:
            self.send_data(503, {'error': 'Mock storage busy; retry later'})
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.send_data(500, {'error':'Storage or diagnostics unavailable'})

    def allowed_origin(self):
        origins = self.headers.get_all('Origin', [])
        settings=getattr(getattr(self,'server',None),'management',None)
        allowed=[settings['scheme']+'://'+host for host in settings['authorities']] if isinstance(settings,dict) else [f'http://{HOST}:{PORT}']
        return not origins or len(origins)==1 and origins[0] in allowed

    def read_json(self, limit=4096):
        if self.headers.get_all('Transfer-Encoding', []):
            raise RequestError(400, 'Transfer-Encoding unsupported')
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            raise RequestError(415, 'Content-Type: application/json required')
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            raise RequestError(400, 'Single valid Content-Length required')
        if len(lengths[0]) > 10:
            raise RequestError(413, 'Payload too large')
        length = int(lengths[0])
        if length > limit:
            raise RequestError(413, 'Payload too large')
        try:
            body = self.rfile.read(length)
        except (socket.timeout, TimeoutError):
            raise RequestError(408, 'Request body timeout') from None
        if len(body) != length:
            raise RequestError(400, 'Incomplete request body')
        try:
            return json.loads(body.decode('utf-8'))
        except (UnicodeError, ValueError, RecursionError):
            raise RequestError(400, 'Invalid JSON body') from None

    def do_POST(self):
        if not self.request_allowed():
            return
        path = urlsplit(self.path).path
        if mvp_api.handle(self, 'POST', path):
            return
        try:
            if path in ('/api/wifi/mock-apply/start', '/api/wifi/mock-apply/preview',
                        '/api/wifi/mock-apply/confirm', '/api/wifi/mock-apply/rollback', '/api/wifi/mock-apply/recover'):
                data = self.read_json()
                action = path.rsplit('/', 1)[1]
                allowed = {'start': {'profile_id', 'operation_id', 'timeout'}, 'preview': {'profile_id'},
                           'confirm': {'operation_id'}, 'rollback': {'operation_id'}, 'recover': set()}[action]
                required = {'start': {'profile_id'}, 'preview': {'profile_id'},
                            'confirm': {'operation_id'}, 'rollback': {'operation_id'}, 'recover': set()}[action]
                if not isinstance(data, dict) or set(data) - allowed or not required <= set(data):
                    raise ApplyError('Invalid mock request schema')
                engine = mock_apply_controller(MOCK_APPLY_PATH, WIFI_STORE, initialize=action in ('start', 'preview'))
                if action == 'start':
                    result = engine.start(data['profile_id'], MOCK_INTERFACE, data.get('timeout', 60), data.get('operation_id'))
                elif action == 'preview':
                    result = engine.preview(data['profile_id'], MOCK_INTERFACE)
                elif action == 'recover':
                    result = engine.recover()
                else:
                    result = getattr(engine, action)(data['operation_id'])
                return self.send_data(200, result)
            if path == '/api/wifi/profiles':
                return self.send_data(201, WIFI_STORE.create(self.read_json()))
            if path in ('/api/wifi/validate', '/api/wifi/preview'):
                data = self.read_json()
                if not isinstance(data, dict) or set(data) - {'profile', 'profile_id'} or 'profile' not in data:
                    raise WiFiError('Expected profile and optional profile_id')
                identifier = data.get('profile_id')
                if identifier is not None:
                    profile_id(identifier)
                action = preview_configuration if path.endswith('/preview') else validate_configuration
                return self.send_data(200, action(data['profile'], RADIO.snapshot(), WIFI_SECRETS, identifier=identifier))
            if path.startswith('/api/wifi/profiles/') and path.endswith('/duplicate'):
                identifier = path.removeprefix('/api/wifi/profiles/').removesuffix('/duplicate')
                if self.read_json() != {}:
                    raise WiFiError('Duplicate accepts an empty JSON object')
                result = WIFI_STORE.duplicate(identifier)
                return self.send_data(201, result) if result else self.send_data(404, {'error': 'Wi-Fi profile not found'})
            if path == '/api/import':
                data = self.read_json(90000)
                if not isinstance(data, dict) or set(data) != {'type','content'}:
                    raise ProfileError('Expected type and content')
                return self.send_data(200, import_config(data['type'], data['content']))
            if path == '/api/profiles/plan':
                return self.send_data(200, tunnel_plan(self.read_json()))
            if path == '/api/profiles/inspect':
                return self.send_data(200, inspect_profile(self.read_json()))
            if path == '/api/profiles/test':
                return self.send_data(200, STORE.test(self.read_json()))
            if path == '/api/connection-capabilities':
                return self.send_data(200, {'capabilities': capabilities(), 'mode': 'inspection_only'})
            if path == '/api/profiles':
                return self.send_data(201, STORE.create(self.read_json()))
            return self.send_data(404, {'error':'Not found'})
        except PersistenceError:
            return self.send_data(500, {'state': 'recovery_required', 'error': 'Mock storage invalid or unavailable; independent recovery required', 'mock_only': True, 'real_apply_available': False})
        except WiFiStoreError:
            return self.send_data(500, {'error': 'Wi-Fi database unavailable; reload or inspect saved data'})
        except ApplyError:
            return self.send_data(400, {'error': 'Mock operation rejected: verify profile, capabilities, operation ID and pending recovery', 'mock_only': True, 'real_apply_available': False})
        except RequestError as exc:
            return self.send_data(exc.status, {'error':str(exc)})
        except (ValueError, ProfileError, json.JSONDecodeError, TypeError) as exc:
            return self.send_data(400, {'error':str(exc)})
        except TimeoutError:
            return self.send_data(503, {'error': 'Storage busy; retry later'})
        except OSError as exc:
            return self.send_data(500, {'error':'Storage or diagnostics unavailable'})

    def do_PUT(self):
        if not self.request_allowed():
            return
        path = urlsplit(self.path).path
        if mvp_api.handle(self, 'PUT', path):
            return
        if not path.startswith(('/api/profiles/', '/api/wifi/profiles/')):
            return self.send_data(404, {'error':'Not found'})
        try:
            if path.startswith('/api/wifi/profiles/'):
                result = WIFI_STORE.update(path.removeprefix('/api/wifi/profiles/'), self.read_json())
                return self.send_data(200, result) if result else self.send_data(404, {'error': 'Wi-Fi profile not found'})
            profile_id = path.removeprefix('/api/profiles/')
            if len(profile_id) > 64 or not profile_id:
                raise ProfileError('Invalid ID')
            result = STORE.update(profile_id, self.read_json())
            return self.send_data(200, result) if result else self.send_data(404, {'error':'Profile not found'})
        except WiFiStoreError:
            return self.send_data(500, {'error': 'Wi-Fi database unavailable; reload or inspect saved data'})
        except RequestError as exc:
            return self.send_data(exc.status, {'error':str(exc)})
        except (ValueError, ProfileError, json.JSONDecodeError, TypeError) as exc:
            return self.send_data(400, {'error':str(exc)})
        except TimeoutError:
            return self.send_data(503, {'error': 'Storage busy; retry later'})
        except OSError as exc:
            return self.send_data(500, {'error':'Storage or diagnostics unavailable'})

    def do_DELETE(self):
        if not self.request_allowed():
            return
        path = urlsplit(self.path).path
        if mvp_api.handle(self, 'DELETE', path):
            return
        if path.startswith('/api/wifi/profiles/'):
            try:
                deleted = WIFI_STORE.delete(path.removeprefix('/api/wifi/profiles/'))
                return self.send_data(200 if deleted else 404, {'deleted': deleted})
            except WiFiStoreError:
                return self.send_data(500, {'error': 'Wi-Fi database unavailable; reload or inspect saved data'})
            except WiFiError:
                return self.send_data(400, {'error': 'Invalid Wi-Fi profile ID'})
            except (OSError, TimeoutError):
                return self.send_data(503, {'error': 'Wi-Fi store busy or unavailable'})
        if not path.startswith('/api/profiles/'):
            return self.send_data(404, {'error':'Not found'})
        profile_id = path.removeprefix('/api/profiles/')
        if not profile_id or len(profile_id) > 64:
            return self.send_data(400, {'error':'Invalid ID'})
        try:
            deleted = STORE.delete(profile_id)
            return self.send_data(200 if deleted else 404, {'deleted': deleted})
        except (OSError, ValueError) as exc:
            return self.send_data(500, {'error':'Storage or diagnostics unavailable'})

if __name__ == '__main__':
    print(f'PiRate {VERSION}: http://{HOST}:{PORT}', flush=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    if os.environ.get('PIRATE_DEPLOYMENT_CONFIG'):
        from gate_core.mvp.management import Authentication,private_json
        deployment=private_json(os.environ['PIRATE_DEPLOYMENT_CONFIG'])
        server.auth=Authentication(deployment['auth_file'])
    access=None
    import signal
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        app=mvp_api.runtime()
        if os.environ.get('PIRATE_DEPLOYMENT_CONFIG'):
            from gate_core.mvp.management_runtime import ManagementAccess
            access=ManagementAccess(app,server,os.environ['PIRATE_DEPLOYMENT_CONFIG'],os.environ.get('PIRATE_STATUS_FILE','/run/pirate/status.json'));access.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if access:access.stop()
        finally:
            if mvp_api._RUNTIME is not None:
                mvp_api._RUNTIME.close()
            server.server_close()
