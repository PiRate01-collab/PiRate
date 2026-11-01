"""Focused management, login and upgrade tests; no network or machine mutations."""
import argparse
import base64
from contextlib import redirect_stdout
from email.message import Message
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from gate_core.mvp import admin
from gate_core.mvp.management import Authentication, Management
from gate_core.mvp.management_runtime import EthernetFirewall, MDNS, ManagementAccess
from gate_core.mvp.proxy import ConnectionError
from tools import install_pi
from web.server import Handler


def basic(password):return 'Basic '+base64.b64encode(('admin:'+password).encode()).decode()


def handler(host,origin=None,peer='192.168.10.20',remote=True,auth=None):
    obj=Handler.__new__(Handler);obj.headers=Message();obj.headers['Host']=host
    if origin:obj.headers['Origin']=origin
    obj.headers['Authorization']=basic('fixture-password')
    obj.client_address=(peer,1234);obj.send_data=Mock()
    obj.server=SimpleNamespace(management={'authorities':['192.168.10.2:8766','pirate.local:8766'] if remote else ['127.0.0.1:8765','127.0.0.1:18765'],'scheme':'https' if remote else 'http'},
        remote_management=remote,allowed_subnet='192.168.10.0/24' if remote else None,auth=auth or Mock())
    return obj


class AuthenticationTests(unittest.TestCase):
    def test_password_limits_and_empty_remote_denial(self):
        for password in ('','x','x'*20):
            with self.subTest(length=len(password)),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'auth';admin.atomic_json(path,admin.password_hash('admin',password))
                auth=Authentication(path)
                self.assertTrue(auth.verify(basic(password),'local'))
                self.assertEqual(auth.verify(basic(password),'remote',remote=True),bool(password))
                self.assertFalse(auth.verify(basic('wrong'),'remote',remote=True))
                self.assertNotIn('password',json.loads(path.read_text()))
                self.assertEqual(path.stat().st_mode&0o777,0o600)
        with self.assertRaisesRegex(ValueError,'0–20'):admin.password_hash('admin','x'*21)

    def test_password_rotation_reload_and_plaintext_never_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);auth_path=root/'auth';config=root/'deployment';public=root/'public'
            admin.atomic_json(auth_path,admin.password_hash('admin','old'))
            admin.atomic_json(config,{'auth_file':str(auth_path),'tunnel_ports':[8765]})
            auth=Authentication(auth_path)
            with patch('gate_core.mvp.admin.require_root'),patch('gate_core.mvp.admin.getpass.getpass',return_value='new'),redirect_stdout(io.StringIO()):
                admin.change_password(config,public)
            self.assertTrue(auth.verify(basic('new'),'peer',remote=True))
            self.assertFalse(auth.verify(basic('old'),'peer',remote=True))
            self.assertEqual(set(json.loads(public.read_text())),{'username','bootstrap_only','tunnel_ports'})
            with patch('gate_core.mvp.admin.require_root'),patch('gate_core.mvp.admin.getpass.getpass',return_value=''),redirect_stdout(io.StringIO()):
                admin.change_password(config,public)
            self.assertFalse(auth.verify(basic(''),'peer',remote=True));self.assertTrue(auth.verify(basic(''),'local'))

    def test_empty_password_never_starts_remote_listener(self):
        obj=Management.__new__(Management);obj.config={'management_port':8766};obj.auth=Mock();obj.auth.bootstrap_only=True
        with patch('gate_core.mvp.management.ManagementHTTPServer') as server:
            obj.start('10.42.0.1','wlan1');server.assert_not_called()

    def test_host_origin_subnet_and_explicit_tunnel_port(self):
        for host,origin in [('192.168.10.2:8766','https://192.168.10.2:8766'),('pirate.local:8766','https://pirate.local:8766')]:
            self.assertTrue(handler(host,origin).request_allowed())
        for host,origin,peer in [('evil:8766',None,'192.168.10.20'),('pirate.local:8766','http://pirate.local:8766','192.168.10.20'),('pirate.local:8766',None,'203.0.113.2')]:
            self.assertFalse(handler(host,origin,peer).request_allowed())
        self.assertTrue(handler('127.0.0.1:18765','http://127.0.0.1:18765',remote=False).request_allowed())
        self.assertFalse(handler('127.0.0.1:9999',remote=False).request_allowed())
        obj=handler('127.0.0.1:18765',remote=False);obj.headers['Host']='evil'
        self.assertFalse(obj.request_allowed())

    def test_tls_certificate_extension_preserves_key_and_covers_ip_and_mdns(self):
        from gate_core.mvp.management_runtime import ensure_certificate
        import ssl
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cert=root/'tls.crt';key=root/'tls.key'
            result=subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=pirate.home.arpa',
                '-addext','subjectAltName=DNS:pirate.home.arpa,IP:10.42.0.1','-keyout',str(key),'-out',str(cert)],capture_output=True)
            self.assertEqual(result.returncode,0);original_key=key.read_bytes()
            ensure_certificate({'tls_cert':str(cert),'tls_key':str(key),'tls_managed':True},'192.168.10.2')
            names=ssl._ssl._test_decode_cert(str(cert))['subjectAltName']
            self.assertIn(('DNS','pirate.local'),names);self.assertIn(('IP Address','192.168.10.2'),names)
            self.assertIn(('IP Address','10.42.0.1'),names);self.assertEqual(key.read_bytes(),original_key)

    def test_tunnel_port_config_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            config=Path(tmp)/'config';auth=Path(tmp)/'auth';public=Path(tmp)/'public'
            admin.atomic_json(auth,admin.password_hash('admin','valid'))
            admin.atomic_json(config,{'auth_file':str(auth),'tunnel_ports':[8765]})
            with patch('gate_core.mvp.admin.require_root'),redirect_stdout(io.StringIO()):admin.tunnel_port(18765,config,public)
            self.assertEqual(json.loads(config.read_text())['tunnel_ports'],[18765,8765])
            with self.assertRaises(ValueError):admin.validate_access({'tunnel_ports':[0]})


class DiscoveryTests(unittest.TestCase):
    def status(self,root,age=0):
        admin.atomic_json(root/'public',{'username':'operator','tunnel_ports':[18765],'bootstrap_only':False},0o644)
        state={'updated_at':time.time()-age,'pid':os.getpid(),'process_birth':Path('/proc/self/stat').read_text().split()[21],
            'listeners':[{'address':'127.0.0.1','port':8765,'scheme':'http','scope':'loopback','tunnel_ports':[8765,18765]},
                         {'address':'192.168.10.2','port':8766,'scheme':'https','scope':'192.168.10.0/24','mdns':False}],
            'ap':'OFF','lan':'BLOCKED','notes':[]}
        admin.atomic_json(root/'status',state,0o644)

    def banner(self,root,sockets):
        with patch('gate_core.mvp.admin.listeners',return_value=sockets),patch('gate_core.mvp.admin.interfaces',return_value=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'192.168.10.2'}]}]),patch.dict(os.environ,{'SSH_CONNECTION':'192.168.10.20 44444 192.168.10.2 2222','SUDO_USER':'pi'}),redirect_stdout(io.StringIO()) as out:
            admin.banner(public_path=root/'public',status_path=root/'status')
            return out.getvalue()

    def test_current_urls_and_actual_ssh_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.status(root)
            out=self.banner(root,{('127.0.0.1',8765),('192.168.10.2',8766),('0.0.0.0',2222)})
            self.assertIn('https://192.168.10.2:8766',out);self.assertIn('Admin: operator',out)
            self.assertIn('-p 2222 pi@192.168.10.2',out);self.assertIn('127.0.0.1:18765:127.0.0.1:8765',out)
            self.assertNotIn('https://pirate.local',out)

    def test_stale_or_missing_listener_never_publishes_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.status(root,age=60)
            out=self.banner(root,{('192.168.10.2',8766)})
            self.assertNotIn('https://',out);self.assertNotIn('http://',out)
            self.status(root)
            out=self.banner(root,{('127.0.0.1',8765)})
            self.assertNotIn('https://',out);self.assertIn('http://127.0.0.1:8765',out)

    def test_mdns_conflict_disables_name(self):
        mdns=MDNS()
        with patch('gate_core.mvp.management_runtime.shutil.which',return_value='/usr/bin/tool'),patch('gate_core.mvp.management_runtime.command',return_value=SimpleNamespace(returncode=0,stdout='pirate.local\t192.168.10.99')),patch('gate_core.mvp.management_runtime.subprocess.Popen') as spawn:
            self.assertFalse(mdns.refresh('192.168.10.2'));spawn.assert_not_called();self.assertIn('конфликт',mdns.note)

    def test_mdns_requires_live_publisher_and_matching_resolution(self):
        mdns=MDNS();process=Mock();process.poll.return_value=None
        with patch('gate_core.mvp.management_runtime.shutil.which',return_value='/usr/bin/tool'),patch('gate_core.mvp.management_runtime.command',return_value=SimpleNamespace(returncode=0,stdout='pirate.local\t192.168.10.2')),patch('gate_core.mvp.management_runtime.subprocess.Popen',return_value=process):
            self.assertTrue(mdns.refresh('192.168.10.2'))
            process.poll.return_value=1
            self.assertFalse(mdns.refresh('192.168.10.2'));self.assertFalse(mdns.ready)

    def test_login_hook_silent_without_interactive_tty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'profile.sh';path.write_text(install_pi.PROFILE)
            for flags in (['-c'],['--noprofile','--norc','-ic']):
                result=subprocess.run(['bash',*flags,'. "$1"; printf protocol','test',str(path)],capture_output=True,text=True)
                self.assertEqual(result.stdout,'protocol')
            self.assertIn('case $-',path.read_text());self.assertIn('[ -t 0 ] && [ -t 1 ]',path.read_text())


    def test_login_hook_runs_on_interactive_terminal(self):
        import pty
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fake=root/'pirate';profile=root/'profile.sh'
            fake.write_text('#!/bin/sh\nprintf PIRATE_LOGIN_BANNER\n');fake.chmod(0o755)
            profile.write_text(install_pi.PROFILE.replace('/usr/local/bin/pirate',str(fake)))
            master,slave=pty.openpty()
            try:
                process=subprocess.Popen(['bash','--noprofile','--norc','-ic','. "$1"','test',str(profile)],stdin=slave,stdout=slave,stderr=slave)
                os.close(slave);slave=None
                output=b''
                while True:
                    try:
                        chunk=os.read(master,4096)
                        if not chunk:break
                        output+=chunk
                    except OSError:break
                self.assertEqual(process.wait(timeout=3),0)
                self.assertIn(b'PIRATE_LOGIN_BANNER',output)
            finally:
                os.close(master)
                if slave is not None:os.close(slave)


class EthernetTests(unittest.TestCase):
    def test_apply_cannot_take_over_trusted_management_ethernet(self):
        from gate_core.mvp.connections import Connections
        with tempfile.TemporaryDirectory() as tmp:
            app=Connections.__new__(Connections);app.directory=Path(tmp);app.lock=threading.RLock()
            app.current=None;app.pending=None;app.previous=None
            app.profiles=Mock();app.profiles.get.return_value={'id':'new','type':'http'}
            app.router=Mock();app.router.current=None
            app.ap=Mock();app.ap.active=None;app.ap.management.config={'management_interface':'eth0'};app.persist=Mock()
            with self.assertRaisesRegex(ConnectionError,'Trusted management Ethernet'):
                app.connect('new',gateway_config={'lan_interface':'eth0','wan_interface':'eth1'})
            app.router.arm.assert_not_called();app.ap.prepare.assert_not_called()

    def test_public_and_incomplete_management_scopes_rejected(self):
        for config in ({'management_interface':'eth0'}, {'management_interface':'eth0','management_subnet':'8.8.8.0/24'},
                       {'management_interface':'wlan0','ap_interface':'wlan0','management_subnet':'192.168.0.0/24'}):
            with self.subTest(config=config),self.assertRaises(ValueError):admin.validate_access(config)
        admin.validate_access({'management_interface':'eth0','wan_interface':'eth0','management_subnet':'192.168.0.0/24'})

    def test_firewall_interface_source_and_reserved_port_drop(self):
        firewall=EthernetFirewall();config={'management_owner':'a'*32,'management_interface':'eth0','management_subnet':'192.168.10.0/24','management_address':'192.168.10.2'}
        def command(*args):return SimpleNamespace(returncode=1 if '-j' in args else 0,stdout='verified rules')
        with patch('gate_core.mvp.management_runtime.command',side_effect=command),patch('gate_core.mvp.management_runtime.subprocess.run',return_value=SimpleNamespace(returncode=0)) as run:
            firewall.install(config);self.assertTrue(firewall.healthy())
            rules=run.call_args.kwargs['input']
            self.assertIn('iifname "eth0" ip saddr 192.168.10.0/24 ip daddr 192.168.10.2 tcp dport 8766 accept',rules)
            self.assertIn('tcp dport 8766 drop',rules);self.assertNotIn('0.0.0.0',rules)
        with patch('gate_core.mvp.management_runtime.command',return_value=SimpleNamespace(returncode=0,stdout='changed')):
            self.assertFalse(firewall.healthy())

    def runtime_case(self,root,scope=True,empty=False,addresses=True,healthy=True,ap_change=False):
        config={'management_port':8766,'management_owner':'a'*32,'tunnel_ports':[18765],'tls_cert':str(root/'cert')}
        if scope:config.update(management_interface='eth0',management_subnet='192.168.10.0/24',management_address='192.168.10.2')
        admin.atomic_json(root/'config',config)
        ap_management=Mock();ap_management.auth.bootstrap_only=empty;ap_management.server=None
        app=SimpleNamespace(lock=threading.RLock(),ap=SimpleNamespace(active=None,management=ap_management,healthy=lambda:False),
            router=SimpleNamespace(current=None,policy_active=False,blocked_config=None))
        loopback=Mock();loopback.server_address=('127.0.0.1',8765);loopback.socket.fileno.return_value=10
        ethernet=Mock();ethernet.auth.bootstrap_only=empty;ethernet.server=None
        def start(*args,**kw):ethernet.server=SimpleNamespace(socket=SimpleNamespace(fileno=lambda:11),tls_sha256='a'*64)
        def stop():ethernet.server=None
        ethernet.start.side_effect=start;ethernet.stop.side_effect=stop
        with patch('gate_core.mvp.management_runtime.Management',return_value=ethernet):
            access=ManagementAccess(app,loopback,root/'config',root/'status')
        access.firewall=Mock();access.firewall.healthy.return_value=healthy;access.mdns=Mock();access.mdns.refresh.return_value=False;access.mdns.note='mDNS unavailable'
        original=Path.read_text
        def read(path,*args,**kw):
            return '1' if str(path)=='/sys/class/net/eth0/type' else original(path,*args,**kw)
        links=[{'ifname':'eth0','addr_info':[{'family':'inet','local':addresses if isinstance(addresses,str) else '192.168.10.2'}]}] if addresses else []
        with patch.object(Path,'read_text',read),patch('gate_core.mvp.management_runtime.interfaces',return_value=links),patch('gate_core.mvp.management_runtime.listeners',return_value=set()),patch('gate_core.mvp.management_runtime.ensure_certificate'),patch('gate_core.mvp.management_runtime.ssl.PEM_cert_to_DER_cert',return_value=b'certificate'):
            (root/'cert').write_text('certificate')
            access.tick()
            if ap_change:
                app.ap.active={'interface':'wlan1','subnet':'10.42.0.1/24'};app.ap.pending=True
                access.tick()
        return access,ethernet,json.loads((root/'status').read_text()),loopback

    def test_ethernet_is_opt_in_and_empty_password_suppresses_remote(self):
        for scope,empty in ((False,False),(True,True)):
            with self.subTest(scope=scope,empty=empty),tempfile.TemporaryDirectory() as tmp:
                access,ethernet,state,loopback=self.runtime_case(Path(tmp),scope,empty)
                ethernet.start.assert_not_called()
                self.assertEqual([item['scope'] for item in state['listeners']],['loopback'])
                self.assertEqual(loopback.management['authorities'],['127.0.0.1:8765','127.0.0.1:18765'])

    def test_ethernet_listener_uses_selected_ip_interface_and_subnet(self):
        with tempfile.TemporaryDirectory() as tmp:
            access,ethernet,state,_=self.runtime_case(Path(tmp))
            ethernet.start.assert_called_once_with('192.168.10.2','eth0',port=8766,subnet='192.168.10.0/24',names=['pirate.local'])
            self.assertEqual(state['listeners'][1]['address'],'192.168.10.2')
            self.assertNotIn('password',json.dumps(state));access.firewall.install.assert_called_once()

    def test_ap_transaction_updates_firewall_without_restarting_lan_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            access,ethernet,state,_=self.runtime_case(Path(tmp),ap_change=True)
            ethernet.start.assert_called_once()
            self.assertEqual(access.firewall.install.call_count,2)
            self.assertEqual(access.firewall.install.call_args.args[0]['ap_interface'],'wlan1')
            self.assertTrue(any(item['scope']=='192.168.10.0/24' for item in state['listeners']))

    def test_missing_ipv4_or_changed_firewall_closes_direct_listener(self):
        for addresses,healthy in ((False,True),(True,False),('192.168.10.99',True)):
            with self.subTest(addresses=addresses,healthy=healthy),tempfile.TemporaryDirectory() as tmp:
                access,ethernet,state,_=self.runtime_case(Path(tmp),addresses=addresses,healthy=healthy)
                self.assertEqual([item['scope'] for item in state['listeners']],['loopback'])
                self.assertIsNone(ethernet.server);self.assertTrue(state['notes'])

    def test_unrelated_input_drop_prevents_claiming_access(self):
        firewall=EthernetFirewall()
        for policy,clear in (('drop',False),('accept',True)):
            rules={'nftables':[{'chain':{'family':'inet','table':'filter','name':'input','hook':'input','policy':policy}}]}
            with patch('gate_core.mvp.management_runtime.command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(rules))):
                self.assertEqual(firewall.other_input_clear(),clear)

    def test_foreign_firewall_never_overwritten(self):
        firewall=EthernetFirewall()
        with patch('gate_core.mvp.management_runtime.command',return_value=SimpleNamespace(returncode=0,stdout='{"nftables":[{"table":{"comment":"foreign"}}]}')),patch('gate_core.mvp.management_runtime.subprocess.run') as run:
            with self.assertRaises(ConnectionError):firewall.install({'management_owner':'a'*32})
            run.assert_not_called()


class UpgradeTests(unittest.TestCase):
    def old_install(self,root):
        (root/'etc/pirate').mkdir(parents=True,mode=0o700);(root/'opt/pirate').mkdir(parents=True)
        (root/'opt/pirate/VERSION').write_text('0.4.1-beta\n');(root/'opt/pirate/old-marker').write_text('old code')
        (root/'etc/os-release').write_text('ID=debian\nVERSION_ID=13\n')
        (root/'var/lib/dpkg').mkdir(parents=True);(root/'var/lib/dpkg/arch').write_text('arm64\n')
        config={'ap_interface':'wlan1','wan_interface':'eth0','subnet':'10.42.0.1/24','management_port':8766,
                'auth_file':'/etc/pirate/admin.json','tls_cert':'/etc/pirate/tls.crt','tls_key':'/etc/pirate/tls.key'}
        admin.atomic_json(root/'etc/pirate/deployment.json',config)
        admin.atomic_json(root/'etc/pirate/admin.json',admin.password_hash('admin','saved-password'))
        admin.atomic_json(root/'etc/pirate/installation.json',{'owner':'a'*32,'backup':'original-backup'})
        (root/'etc/pirate/tls.key').write_text('preserve key');(root/'etc/pirate/tls.crt').write_text('preserve cert')
        (root/'var/lib/pirate/runtime').mkdir(parents=True)
        (root/'var/lib/pirate/profiles.json').write_text('{"saved":"private-profile"}')
        (root/'var/lib/pirate/runtime/ap-state').write_text('saved AP configuration')
        return argparse.Namespace(image_root=str(root),ap_interface=None,wan_interface=None,manage_ap_interface=False,tunnel_port=[18765])

    def test_upgrade_preserves_settings_and_standalone_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args=self.old_install(root)
            auth=(root/'etc/pirate/admin.json').read_bytes()
            with redirect_stdout(io.StringIO()):install_pi.upgrade(args,root)
            self.assertEqual((root/'opt/pirate/VERSION').read_text().strip(),(install_pi.SOURCE/'VERSION').read_text().strip())
            self.assertEqual((root/'etc/pirate/admin.json').read_bytes(),auth)
            self.assertEqual((root/'etc/pirate/tls.key').read_text(),'preserve key')
            self.assertEqual((root/'var/lib/pirate/profiles.json').read_text(),'{"saved":"private-profile"}')
            config=json.loads((root/'etc/pirate/deployment.json').read_text())
            self.assertEqual(config['ap_interface'],'wlan1');self.assertEqual(config['tunnel_ports'],[18765,8765])
            backup=next((root/'var/backups/pirate').iterdir())
            # Runs copied recovery script outside source/install trees, without imports.
            result=subprocess.run([*json.loads(os.environ.get('PIRATE_TEST_PYTHON_PREFIX','[]')),os.sys.executable,'-B',str(backup/'restore.py'),'restore','--backup',str(backup),'--image-root',str(root)],cwd='/tmp',capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((root/'opt/pirate/VERSION').read_text().strip(),'0.4.1-beta')
            self.assertFalse((root/'etc/profile.d/pirate.sh').exists());self.assertEqual((root/'etc/pirate/admin.json').read_bytes(),auth)

    def test_upgrade_failure_automatically_restores_old_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args=self.old_install(root)
            (root/'opt/pirate/VERSION').write_text('0.5.6.2-beta\n')
            (root/'var/lib/pirate/runtime/ap').mkdir(mode=0o700)
            admin.atomic_json(root/'var/lib/pirate/runtime/ap/state.json',
                             {'confirmed':{'interface':'wlan1','ssid':'Saved Wi-Fi','password':'saved-wifi-secret'}})
            admin.atomic_json(root/'var/lib/pirate/runtime/confirmed-router.json',
                             {'enabled':True,'profile_id':'saved-profile','ap':{'interface':'wlan1','ssid':'Saved Wi-Fi','password':'saved-wifi-secret'},
                              'gateway':{'lan_interface':'wlan1','wan_interface':'eth0'}})
            saved={str(p.relative_to(root)):p.read_bytes() for d in ('etc/pirate','var/lib/pirate')
                   for p in (root/d).rglob('*') if p.is_file()}
            with patch.object(install_pi,'install_login',side_effect=OSError('test failure')),redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):install_pi.upgrade(args,root)
            self.assertEqual((root/'opt/pirate/VERSION').read_text().strip(),'0.5.6.2-beta')
            self.assertEqual((root/'opt/pirate/old-marker').read_text(),'old code')
            self.assertEqual((root/'var/lib/pirate/runtime/ap-state').read_text(),'saved AP configuration')
            for name,raw in saved.items():self.assertEqual((root/name).read_bytes(),raw)


if __name__=='__main__':unittest.main()
