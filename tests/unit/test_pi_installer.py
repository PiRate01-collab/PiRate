"""Focused installer and AP failure regressions; no network or root required."""
import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from tools import install_pi as installer
from gate_core.mvp.ap import AccessPoint, normalize
from gate_core.mvp.connections import Connections
from gate_core.mvp.proxy import ConnectionError


def args(**values):
    return argparse.Namespace(**dict(dict(ap_interface='wlan1',wan_interface='eth0',image_root=None,
        manage_ap_interface=False,subnet='10.42.0.1/24',admin_user='admin'),**values))


class InstallerTests(unittest.TestCase):
    def runtime_inspect(self,capabilities,ap='wlan1',missing=False):
        links=[{'ifname':'eth0','flags':['UP']}]
        if ap:links.append({'ifname':ap,'flags':[]})
        def run(*command,**kw):
            out='';rc=0
            if command[0] in ('apt-get','unshare'): raise AssertionError('inspect must be read-only')
            if command==('dpkg','--print-architecture'):out='arm64'
            elif command[:2]==('dpkg-query','-W'):out='install ok installed' if command[2]=='-f=${Status}' else '99.0'
            elif command==('ip','-j','link'):out=json.dumps(links)
            elif command[:5]==('ip','-j','-4','route','show'):out='[{"dev":"eth0"}]'
            elif command[:2]==('iw','dev'):rc=1 if not ap or command[2]=='eth0' else 0
            return subprocess.CompletedProcess(command,rc,out,'')
        with ExitStack() as stack:
            stack.enter_context(patch.object(installer,'os_release',return_value={'ID':'debian','VERSION_ID':'13'}))
            stack.enter_context(patch.object(installer.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(installer.platform,'machine',return_value='aarch64'))
            stack.enter_context(patch.object(installer.Path,'read_text',return_value='CapEff: 00201000'))
            stack.enter_context(patch.object(installer.Path,'is_char_device',return_value=True))
            stack.enter_context(patch.object(installer.shutil,'which',return_value=None if missing else '/usr/bin/tool'))
            stack.enter_context(patch.object(installer,'run',side_effect=run))
            stack.enter_context(patch('gate_core.mvp.ap.capabilities',side_effect=capabilities if isinstance(capabilities,Exception) else None,return_value=capabilities))
            warnings=stack.enter_context(redirect_stderr(io.StringIO()))
            result=installer.inspect(args(ap_interface=ap),Path('/'))
            return result,warnings.getvalue()

    def test_standalone_restore_keeps_ssh_guard_without_checkout(self):
        import shutil, sys
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/'backup';folder.mkdir()
            shutil.copy2(installer.__file__,folder/'restore.py')
            shutil.copy2(installer.SOURCE/'gate_core/mvp/management_guard.py',folder/'management_guard.py')
            code="""import runpy,sys
from types import SimpleNamespace
n=runpy.run_path(sys.argv[1]);guard=n['protect_ssh']
def run(*args):
    return SimpleNamespace(stdout='ESTAB 0 192.0.2.1:22 192.0.2.2:50000 users:sshd' if args[0]=='ss' else '[{"dev":"wlan0"}]')
guard.__globals__['run']=run
try:guard('wlan0')
except ValueError as exc:
    assert 'carries SSH' in str(exc)
else:raise AssertionError('SSH guard was bypassed')
assert 'gate_core' not in sys.modules
"""
            result=subprocess.run([sys.executable,'-I','-B','-c',code,str(folder/'restore.py')],cwd=tmp,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_unknown_ap_is_warning(self):
        result,warning=self.runtime_inspect({'ap_mode':None,'security':[],'channels':[]})
        self.assertIn('WARNING:',warning);self.assertTrue(result['warnings'])

    def test_reported_no_ap_is_warning(self):
        _,warning=self.runtime_inspect({'ap_mode':False,'security':[],'channels':[]})
        self.assertIn('WARNING:',warning)

    def test_channel_one_is_not_required(self):
        result,warning=self.runtime_inspect({'ap_mode':True,'security':['wpa2'],'channels':[6]})
        self.assertEqual(result['ap_capabilities']['channels'],[6]);self.assertEqual(warning,'')

    def test_inspection_exception_is_warning(self):
        _,warning=self.runtime_inspect(RuntimeError('driver unavailable'))
        self.assertIn('WARNING:',warning)

    def test_no_wifi_inspect(self):
        result,warning=self.runtime_inspect({},ap=None)
        self.assertEqual(result['wifi_interfaces'],[]);self.assertIn('No Wi-Fi adapter',warning)

    def test_missing_dependency_remains_fatal(self):
        with self.assertRaisesRegex(ValueError,'Missing packages'):
            self.runtime_inspect({},missing=True)

    def test_unsupported_os_remains_fatal(self):
        with patch.object(installer,'os_release',return_value={'ID':'other','VERSION_ID':'13'}):
            with self.assertRaisesRegex(ValueError,'Requires Debian'):installer.inspect(args(),Path('/'))

    def test_management_checks_with_no_ap(self):
        with patch.object(installer,'run',return_value=SimpleNamespace(returncode=1)),patch.object(installer,'protect_ssh') as ssh:
            installer.protect_management(args(ap_interface=None));ssh.assert_not_called()
        with patch.object(installer,'run',return_value=SimpleNamespace(returncode=0)):
            with self.assertRaisesRegex(ValueError,'Existing pirate_gateway'):installer.protect_management(args(ap_interface=None))

    def test_ssh_on_ap_still_rejected(self):
        responses=[SimpleNamespace(stdout='ESTAB 0 192.0.2.1:22 192.0.2.2:45000 users:sshd'),
                   SimpleNamespace(stdout='[{"dev":"wlan1"}]')]
        with patch.object(installer,'run',side_effect=responses):
            with self.assertRaisesRegex(ValueError,'carries SSH'):installer.protect_ssh('wlan1')

    def test_shared_guard_allows_distinct_wired_ssh(self):
        from gate_core.mvp.management_guard import protect_ssh
        responses=[SimpleNamespace(stdout='ESTAB 0 192.0.2.1:22 192.0.2.2:45000 users:sshd'),SimpleNamespace(stdout='[{"dev":"eth0"}]')]
        with patch('gate_core.mvp.management_guard.subprocess.run',side_effect=responses) as run:
            protect_ssh('wlan1')
        self.assertEqual(run.call_count,2)

    def test_shared_guard_rejects_ssh_and_does_not_skip_inspection_failure(self):
        from gate_core.mvp.management_guard import protect_ssh
        responses=[SimpleNamespace(stdout='ESTAB 0 192.0.2.1:22 192.0.2.2:45000 users:sshd'),SimpleNamespace(stdout='[{"dev":"wlan1"}]')]
        with patch('gate_core.mvp.management_guard.subprocess.run',side_effect=responses):
            with self.assertRaisesRegex(ValueError,'carries SSH'):protect_ssh('wlan1')
        with patch('gate_core.mvp.management_guard.subprocess.run',side_effect=subprocess.CalledProcessError(1,['ss'])):
            with self.assertRaises(subprocess.CalledProcessError):protect_ssh('wlan1')

    def test_target_symlink_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'etc').symlink_to('/etc',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'symlink'):installer.target(root,'etc/pirate')

    def test_no_ap_install_starts_web_service_without_network_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);calls=[]
            original_run=installer.run
            def run(*command,**kw):
                calls.append(command)
                if command[:2]==('openssl','req'):return original_run(*command,**kw)
                if command[:2]==('sysctl','-n'):return SimpleNamespace(stdout='0',returncode=0)
                # Existing unrelated DHCP service must not block proxy-only install.
                rc=0 if command==('systemctl','is-active','dnsmasq.service') else 1
                return SimpleNamespace(stdout='',returncode=rc)
            with patch.object(installer,'installation_banner'),patch.object(installer,'inspect',return_value={'warnings':['No Wi-Fi adapter']}),patch.object(installer,'run',side_effect=run),patch.object(installer.getpass,'getpass',return_value='test-admin-password'),redirect_stdout(io.StringIO()):
                installer.install(args(ap_interface=None),root)
            self.assertIn(('systemctl','start',*installer.UNITS),calls)
            self.assertFalse(any(command[0] in ('ip','iw','nmcli') or command[:2]==('sysctl','-w') for command in calls))
            self.assertFalse((root/'var/lib/pirate/runtime/router.json').exists())
            self.assertFalse((root/'etc/sysctl.d/90-pirate-ap.conf').exists())
            # Actual OpenSSL generated usable private credentials in the staged tree.
            self.assertIn('PRIVATE KEY',(root/'etc/pirate/tls.key').read_text())
            self.assertEqual((root/'etc/pirate/tls.key').stat().st_mode&0o777,0o600)

    def test_image_install_and_restore_without_wifi_and_with_unknown_wifi(self):
        for interface in (None,'wlan1'):
            with self.subTest(interface=interface),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'etc').mkdir();(root/'etc/os-release').write_text('ID=debian\nVERSION_ID=13\n')
                (root/'var/lib/dpkg').mkdir(parents=True);(root/'var/lib/dpkg/arch').write_text('arm64\n')
                (root/'opt/pirate').mkdir(parents=True);(root/'opt/pirate/original').write_text('original')
                (root/'opt/pirate/original').chmod(0o640)
                original_run=installer.run
                def run(*command,**kw):
                    if command[:2]==('openssl','req'):
                        for flag in ('-keyout','-out'):Path(command[command.index(flag)+1]).write_text('test certificate')
                        return SimpleNamespace(returncode=0)
                    return original_run(*command,**kw)
                options=args(ap_interface=interface,image_root=str(root))
                with patch.object(installer,'run',side_effect=run),patch.object(installer.getpass,'getpass',return_value='test-admin-password'),redirect_stdout(io.StringIO()):
                    installer.install(options,root)
                self.assertEqual((root/'var/lib/pirate/runtime/router.json').exists(),bool(interface))
                deployment=json.loads((root/'etc/pirate/deployment.json').read_text())
                self.assertEqual(deployment['ap_interface'],interface)
                auth=json.loads((root/'etc/pirate/admin.json').read_text())
                self.assertEqual(len(auth['scrypt']),64);self.assertNotIn('password',auth)
                self.assertEqual((root/'etc/pirate/admin.json').stat().st_mode&0o777,0o600)
                backup=next((root/'var/backups/pirate').iterdir())
                with redirect_stdout(io.StringIO()):installer.restore(root,backup,image=True)
                self.assertEqual((root/'opt/pirate/original').read_text(),'original')
                self.assertEqual((root/'opt/pirate/original').stat().st_mode&0o777,0o640)
                self.assertFalse((root/'etc/pirate').exists())

    def test_upgrade_from_0562_retains_settings_and_standalone_rollback(self):
        from tests.unit.test_management_access import UpgradeTests
        from gate_core.mvp import admin
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);options=UpgradeTests().old_install(root)
            (root/'opt/pirate/VERSION').write_text('0.5.6.2-beta\n')
            (root/'var/lib/pirate/runtime/ap').mkdir(mode=0o700)
            admin.atomic_json(root/'var/lib/pirate/runtime/ap/state.json',
                             {'confirmed':{'interface':'wlan1','ssid':'Saved Wi-Fi','password':'saved-wifi-secret'}})
            admin.atomic_json(root/'var/lib/pirate/runtime/confirmed-router.json',
                             {'enabled':True,'profile_id':'saved-profile','ap':{'interface':'wlan1','ssid':'Saved Wi-Fi','password':'saved-wifi-secret'},
                              'gateway':{'lan_interface':'wlan1','wan_interface':'eth0'}})
            paths=('etc/pirate/admin.json','etc/pirate/tls.key','etc/pirate/tls.crt',
                   'var/lib/pirate/profiles.json','var/lib/pirate/runtime/ap-state',
                   'var/lib/pirate/runtime/confirmed-router.json','var/lib/pirate/runtime/ap/state.json')
            saved={name:(root/name).read_bytes() for name in paths}
            with redirect_stdout(io.StringIO()):installer.upgrade(options,root)
            self.assertEqual((root/'opt/pirate/VERSION').read_text().strip(),(installer.SOURCE/'VERSION').read_text().strip())
            for name,raw in saved.items():self.assertEqual((root/name).read_bytes(),raw)
            backup=Path(json.loads((root/'etc/pirate/installation.json').read_text())['upgrade_backup'])
            result=subprocess.run([os.sys.executable,'-I','-B',str(backup/'restore.py'),'restore',
                                   '--backup',str(backup),'--image-root',str(root)],cwd='/tmp',capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((root/'opt/pirate/VERSION').read_text().strip(),'0.5.6.2-beta')
            for name,raw in saved.items():self.assertEqual((root/name).read_bytes(),raw)


class APTests(unittest.TestCase):
    def test_secure_configuration_validation_remains(self):
        for overrides in ({'security':'open'},{'password':'short'},{'channel':999},{'country':'??'}):
            with self.subTest(overrides=overrides),self.assertRaises(ConnectionError):
                normalize(dict({'password':'valid-password'},**overrides))

    def test_hostapd_failure_exposes_reason_without_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            ap=AccessPoint.__new__(AccessPoint);ap.directory=Path(tmp);ap.active={'password':'secret-value'}
            (ap.directory/'hostapd.log').write_text('password=secret-value\nnl80211: Driver does not support AP\nCould not select hw_mode and channel\n')
            error=str(ap.daemon_error('hostapd','startup failed'))
            self.assertIn('Driver does not support AP',error);self.assertNotIn('secret-value',error)

    def test_unknown_iw_reaches_secure_hostapd_and_failed_apply_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=Connections.__new__(Connections);app.directory=Path(tmp);app.lock=threading.RLock()
            app.pending=None;app.current=Mock();app.current.profile={'id':'previous','type':'http'}
            previous=app.current;app.previous=None;app.profiles=Mock();app.profiles.get.return_value={'id':'new','type':'http'}
            app.router=Mock();app.router.current=None;app.router.blocked_config=None
            app.router.dns_tcp.server_address=('127.0.0.1',12345)
            app.persist=Mock()
            app.ap=AccessPoint(app);ap=app.ap
            ap.launch=Mock(side_effect=ConnectionError('hostapd: nl80211: unsupported channel'))
            responses=SimpleNamespace(returncode=0,stderr='',stdout='[]');flags=[]
            def network(*command,**kw):
                if command[-1]=='up':flags[:]=['UP']
                elif command[-1]=='down':flags[:]=[]
                if command==('ip','-j','link','show','dev','wlan1'):return SimpleNamespace(stdout=json.dumps([{'flags':list(flags)}]))
                return responses
            with patch('gate_core.mvp.ap.permitted'),patch('gate_core.mvp.ap.binary',side_effect=lambda name:name),patch('gate_core.mvp.ap.network_command',side_effect=network),patch('gate_core.mvp.ap.capabilities',side_effect=AssertionError('iw must not gate Apply')):
                with self.assertRaisesRegex(ConnectionError,'selected Wi-Fi mode'):
                    app.connect('new',gateway_config={'lan_interface':'wlan1','wan_interface':'eth0'},ap_config={'interface':'wlan1','password':'valid-password'})
            ap.launch.assert_called_once();app.router.install.assert_called_once()
            self.assertEqual(app.router.install.call_args.args[0]['lan_interface'],'wlan1')
            app.router.rollback.assert_called_once();self.assertIs(app.current,previous)
            self.assertIsNone(ap.active);self.assertFalse(ap.pending)
            self.assertEqual(app.last_action,'APPLY_FAILED_PREVIOUS_PRESERVED')
            self.assertIn('unsupported channel',app.ap.failure['detail'])

    def test_real_launch_reports_driver_failure_and_keeps_secure_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=SimpleNamespace(directory=Path(tmp),router=Mock())
            app.router.dns_tcp.server_address=('127.0.0.1',12345)
            ap=AccessPoint(app);ap.active=normalize({'interface':'wlan1','password':'valid-password','security':'wpa3','channel':6})
            def spawn(name,command):
                process=Mock();process.poll.return_value=1 if name=='hostapd' else None
                ap.processes.append(process)
                ap.write(name+'.log','nl80211: Driver does not support AP' if name=='hostapd' else '')
                return process
            ap.spawn=Mock(side_effect=spawn)
            with patch('gate_core.mvp.ap.binary',side_effect=lambda name:name),patch('gate_core.mvp.ap.network_command',return_value=SimpleNamespace(returncode=0)):
                with patch('gate_core.mvp.wifi_performance.inspect_radio',return_value={'bands':{'2.4':{'ht':True,'ht40':False,'vht':False,'channels':[{'number':6,'flags':''}]}}}):
                    with self.assertRaisesRegex(ConnectionError,'Driver does not support AP'):ap.launch()
            config=(ap.directory/'hostapd.conf').read_text()
            for setting in ('rsn_pairwise=CCMP','wpa_key_mgmt=SAE','ieee80211w=2','sae_require_mfp=1','channel=6'):
                self.assertIn(setting,config)
            self.assertEqual(ap.spawn.call_args.args[0],'hostapd')

    def test_dhcp_configuration_failure_reports_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=SimpleNamespace(directory=Path(tmp),router=Mock())
            app.router.dns_tcp.server_address=('127.0.0.1',12345)
            ap=AccessPoint(app);ap.active=normalize({'password':'valid-password'})
            with patch('gate_core.mvp.ap.binary',side_effect=lambda name:name),patch('gate_core.mvp.ap.network_command',return_value=SimpleNamespace(returncode=1,stderr='dnsmasq: bad dhcp-range')):
                with patch('gate_core.mvp.wifi_performance.plans',return_value=[]):
                    with self.assertRaisesRegex(ConnectionError,'bad dhcp-range'):ap.launch()

    def test_previous_ap_configuration_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            ap=AccessPoint(SimpleNamespace(directory=Path(tmp)))
            prior=normalize({'password':'prior-password','channel':6})
            ap.previous=prior;ap.active=normalize({'password':'new-password','channel':11});ap.pending=True
            ap.owned={'interface':'wlan0','address':'10.42.0.1/24'}
            ap.launch=Mock()
            def network(*args,**kwargs):
                return SimpleNamespace(stdout='[{"flags":["UP"]}]' if 'link' in args else '[]')
            with patch('gate_core.mvp.ap.network_command',side_effect=network):
                ap.rollback()
            self.assertEqual(ap.active,prior);ap.launch.assert_called_once()
            self.assertFalse(ap.pending);self.assertEqual(ap.last_action,'ROLLED_BACK_CONTROL_VERIFIED')

    def test_webui_receives_actual_ap_error(self):
        from web.mvp_api import handle
        app=Mock();app.connect.side_effect=ConnectionError('hostapd: nl80211: unsupported channel')
        handler=Mock();handler.server.pirate_app=app;handler.read_json.return_value={'profile_id':'test','ap':{}}
        self.assertTrue(handle(handler,'POST','/api/mvp/connect'))
        self.assertEqual(handler.send_data.call_args.args,(400,{'error':'hostapd: nl80211: unsupported channel'}))

    def test_controller_and_proxy_start_without_wifi_inspection(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{},clear=False):
            os.environ.pop('PIRATE_DEPLOYMENT_CONFIG',None)
            with patch('gate_core.mvp.connections.Gateway') as gateway,patch('gate_core.mvp.connections.threading.Thread'),patch('gate_core.mvp.tunnels.recover_namespaces'),patch('gate_core.mvp.ap.capabilities',side_effect=AssertionError('Wi-Fi must not gate startup')):
                app=Connections(Mock(),Path(tmp),proxy_port=8088)
                try:
                    gateway.assert_called_once()
                    self.assertIsNone(app.router.blocked_config)
                    self.assertEqual(app.ap.public()['state'],'DISABLED')
                finally:app.close()

    def test_no_ap_deployment_public_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=SimpleNamespace(directory=Path(tmp))
            ap=AccessPoint(app);ap.management.config={'ap_interface':None}
            self.assertEqual(ap.public()['state'],'DISABLED');self.assertIsNone(ap.public()['config'])





class DependencyTests(unittest.TestCase):
    def test_command_mapping_and_package_status(self):
        def status(*cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, 'deinstall ok config-files' if cmd[-1]=='openvpn' else 'install ok installed', '')
        with patch.object(installer, 'run', side_effect=status), patch.object(installer.shutil, 'which', side_effect=lambda cmd, **kw: None if cmd=='openvpn' else '/usr/bin/'+cmd):
            self.assertEqual(installer.missing_dependencies(), (['openvpn'], ['openvpn -> openvpn']))
        for package, binary in [('wireguard-tools','wg'),('dnsmasq-base','dnsmasq'),('mount','mount'),('kmod','modprobe'),('ethtool','ethtool'),('conntrack','conntrack')]:
            self.assertIn(binary, installer.PACKAGES[package])

    def test_inspect_and_repeat_never_invoke_apt(self):
        for install, missing in [(False, (['openvpn'], ['openvpn -> openvpn'])), (True, ([], []))]:
            with patch.object(installer, 'missing_dependencies', return_value=missing), patch.object(installer.subprocess, 'run') as apt:
                if install:
                    installer.ensure_dependencies(True)
                else:
                    with self.assertRaisesRegex(ValueError, 'openvpn -> openvpn.*read-only'):
                        installer.ensure_dependencies()
                apt.assert_not_called()

    def test_installs_only_missing_and_rechecks(self):
        from contextlib import nullcontext
        with patch.object(installer, 'missing_dependencies', side_effect=[(['hostapd','openvpn'], ['openvpn -> openvpn']), ([], [])]) as missing, patch.object(installer, 'run', return_value=SimpleNamespace(stdout='')), patch.object(installer.shutil, 'which', return_value='/usr/bin/apt-get'), patch.object(installer, 'inhibit_package_services', side_effect=nullcontext) as policy, patch.object(installer.subprocess, 'run') as apt:
            installer.ensure_dependencies(True)
            self.assertEqual(missing.call_count, 2)
            self.assertEqual(apt.call_args_list[0].args[0], ['apt-get','--error-on=any','update'])
            command=apt.call_args_list[1].args[0]
            self.assertEqual(command[command.index('install')+1:], ['hostapd','openvpn'])
            self.assertIn('--no-upgrade',command); self.assertIn('--no-remove',command)
            self.assertEqual(apt.call_args.kwargs['env']['NEEDRESTART_MODE'], 'l')
            policy.assert_called_once()

    def test_apt_failure_and_incomplete_install_stop(self):
        from contextlib import nullcontext
        for fail_update in (True, False):
            with patch.object(installer, 'missing_dependencies', return_value=(['openvpn'], [])), patch.object(installer, 'run', return_value=SimpleNamespace(stdout='')), patch.object(installer.shutil, 'which', return_value='/usr/bin/apt-get'), patch.object(installer, 'inhibit_package_services', side_effect=nullcontext), patch.object(installer.subprocess, 'run', side_effect=subprocess.CalledProcessError(100,['apt-get']) if fail_update else None) as apt:
                with self.assertRaises(subprocess.CalledProcessError if fail_update else ValueError):
                    installer.ensure_dependencies(True)
                self.assertEqual(apt.call_count, 1 if fail_update else 2)

    def test_policy_restored_on_success_failure_and_existing_symlink(self):
        for original in ('absent','file','symlink'):
            for failure in (False,True):
                with self.subTest(original=original, failure=failure), tempfile.TemporaryDirectory() as folder:
                    policy=Path(folder)/'policy-rc.d'
                    other=Path(folder)/'other'; other.write_text('original'); other.chmod(0o750)
                    if original=='file': policy.write_bytes(other.read_bytes()); policy.chmod(0o750)
                    if original=='symlink': policy.symlink_to(other)
                    try:
                        with installer.inhibit_package_services(policy):
                            self.assertEqual(subprocess.run([str(policy)]).returncode,101)
                            if failure: raise RuntimeError('apt failed')
                    except RuntimeError: pass
                    self.assertEqual(policy.exists(),original!='absent')
                    if original!='absent':
                        self.assertEqual(policy.read_text(),'original')
                        self.assertEqual(policy.stat().st_mode&0o777,0o750)
                    self.assertEqual(policy.is_symlink(),original=='symlink')

    def test_failed_policy_restore_keeps_original_for_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            policy=Path(folder)/'policy-rc.d'; policy.write_text('original')
            replace=os.replace
            def fail_restore(source, destination):
                if Path(source).name=='original': raise OSError('restore failed')
                return replace(source,destination)
            with patch.object(installer.os,'replace',side_effect=fail_restore):
                with self.assertRaisesRegex(OSError,'restore failed'):
                    with installer.inhibit_package_services(policy): pass
            saved=list(Path(folder).glob('.pirate-apt-*/original'))
            self.assertEqual(len(saved),1); self.assertEqual(saved[0].read_text(),'original')

    def test_dependency_failure_precedes_configuration_or_service_changes(self):
        with patch.object(installer, 'inspect', side_effect=ValueError('dependency failed')) as inspect, patch.object(installer, 'backup') as backup, patch.object(installer, 'install_code') as code, patch.object(installer, 'run') as run:
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                with self.assertRaisesRegex(ValueError,'dependency failed'): installer.install(args(),root)
                (root/'etc/pirate').mkdir(parents=True); (root/'opt/pirate').mkdir(parents=True)
                (root/'etc/pirate/deployment.json').write_text('{"wan_interface":"eth0"}')
                (root/'etc/pirate/admin.json').write_text('{}')
                (root/'opt/pirate/VERSION').write_text('0.5.9-rc1')
                with patch.object(installer, 'access_options', side_effect=lambda a,c:c):
                    with self.assertRaisesRegex(ValueError,'dependency failed'): installer.upgrade(args(),root)
            for item in (backup,code,run): item.assert_not_called()
            self.assertTrue(all(c.kwargs['install_missing'] for c in inspect.call_args_list))

    def test_repeated_fresh_install_refuses_before_changes(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(installer,'inspect') as inspect:
            root=Path(folder); (root/'etc/pirate').mkdir(parents=True)
            (root/'etc/pirate/installation.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'use upgrade'): installer.install(args(),root)
            inspect.assert_not_called()




class AutomaticInstallerTests(unittest.TestCase):
    def options(self, **kw):
        return args(automatic=True, ap_interface=None, wan_interface=None,
                    country=None, ssid=None, tunnel_only=False,
                    management_interface=None, management_subnet=None,
                    management_address=None, tunnel_port=None, **kw)

    def test_fresh_upgrade_and_partial_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.assertEqual(installer.automatic_action(root),'install')
            for name in ('opt/pirate/VERSION','etc/pirate/deployment.json','etc/pirate/admin.json','etc/pirate/installation.json'):
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('{}')
            self.assertEqual(installer.automatic_action(root),'upgrade')
            (root/'etc/pirate/admin.json').unlink()
            with self.assertRaisesRegex(ValueError,'Incomplete'):installer.automatic_action(root)

    def detection(self, radios=('wlan0',), busy=False, ambiguous=False, ssh=False, nm_state='30 (disconnected)'):
        options=self.options()
        links=[dict(ifname='eth0',flags=['UP'])]+[dict(ifname=n,flags=['UP']) for n in radios]
        routes=[dict(dev='eth0',metric=100)]
        if ambiguous:links.append(dict(ifname='eth1',flags=['UP']));routes.append(dict(dev='eth1',metric=100))
        def run(*cmd,**kw):
            output='';code=0
            if cmd==('ip','-j','link'):output=json.dumps(links)
            elif cmd==('ip','-j','-4','route','show','default'):output=json.dumps(routes)
            elif cmd==('ip','-j','-4','route','get','1.1.1.1'):output='[{"dev":"eth0"}]'
            elif cmd==('ip','-j','addr'):output=json.dumps([dict(ifname='eth0',addr_info=[dict(family='inet',local='192.168.1.20',prefixlen=24)])])
            elif cmd==('iw','dev'):output=''.join(f'phy#{i}\n Interface {n}\n' for i,n in enumerate(radios))
            elif cmd[-1]=='link':output='Connected to abc' if busy else 'Not connected.'
            elif cmd[-1]=='info':output='type managed'
            elif cmd==('iw','reg','get'):output='global\ncountry 00: DFS-UNSET'
            elif cmd[:3]==('nmcli','-g','GENERAL.NM-MANAGED'):output='yes'
            elif cmd[:3]==('nmcli','-g','GENERAL.STATE'):output=nm_state
            else:raise AssertionError(cmd)
            return subprocess.CompletedProcess(cmd,code,output,'')
        with patch.object(installer,'run',side_effect=run),patch.object(installer.shutil,'which',return_value='/usr/bin/nmcli'),patch.object(installer,'protect_ssh',side_effect=ValueError('SSH') if ssh else None),patch.object(installer,'protect_management'),patch('gate_core.mvp.ap.capabilities',return_value=dict(ap_mode=True,security=['wpa2'],channels=[1])):
            installer.detect_bootstrap(options,dict(wifi_interfaces=list(radios)))
        return options

    def test_selects_idle_radio_and_scoped_nm_management(self):
        options=self.detection()
        self.assertEqual((options.wan_interface,options.ap_interface),('eth0','wlan0'))
        self.assertTrue(options.manage_ap_interface)
        self.assertEqual(options.country,'00')
        self.assertEqual(options.management_subnet,'192.168.1.0/24')

    def test_ambiguous_occupied_ssh_and_activating_devices_refused(self):
        for kw in (dict(ambiguous=True),dict(radios=('wlan0','wlan1')),dict(busy=True),dict(ssh=True),dict(nm_state='40 (connecting)')):
            with self.subTest(kw=kw),self.assertRaises(ValueError):self.detection(**kw)

    def test_installer_never_auto_confirms(self):
        self.assertFalse(hasattr(installer,'activate_bootstrap'))
        self.assertNotIn('ppp',installer.PACKAGES)
        self.assertNotIn('pptp-linux',installer.PACKAGES)

    def test_fresh_bootstrap_and_failure_restore_filesystem(self):
        for fail in (False,True):
            with self.subTest(fail=fail),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);options=self.options()
                original_run=installer.run
                original_restore=installer.restore
                def run(*cmd,**kw):
                    if cmd[:2]==('openssl','req'):return original_run(*cmd,**kw)
                    if cmd[:4]==('ip','-j','-4','addr'):return SimpleNamespace(stdout='[]',returncode=0)
                    return SimpleNamespace(stdout='0',returncode=1)
                def select(a,info):a.ap_interface='wlan0';a.wan_interface='eth0';a.country='00'
                with patch.object(installer,'inspect',return_value={}),patch.object(installer,'detect_bootstrap',side_effect=select),patch.object(installer,'protect_management'),patch.object(installer,'protect_ssh'),patch.object(installer,'run',side_effect=run),patch.object(installer,'installation_banner',side_effect=ValueError('failed bootstrap') if fail else None) as banner,patch.object(installer,'restore',side_effect=lambda r,d,image:original_restore(r,d,True)),patch.object(installer,'bootstrap_api',side_effect=AssertionError('No activation or confirmation')) as activate,redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()),patch.object(installer,'credentials',side_effect=AssertionError('No password prompt')):
                    if fail:
                        with self.assertRaisesRegex(ValueError,'failed bootstrap'):installer.install(options,root)
                        self.assertFalse((root/'etc/pirate').exists())
                        self.assertFalse((root/'opt/pirate').exists())
                    else:
                        installer.install(options,root)
                        auth=json.loads((root/'etc/pirate/admin.json').read_text())
                        self.assertTrue(auth['bootstrap_only'])
                        self.assertFalse((root/'etc/pirate/bootstrap-credentials.json').exists())
                        self.assertEqual(installer.automatic_action(root),'upgrade')
                        activate.assert_not_called()

    def test_world_country_does_not_guess_geography(self):
        from gate_core.mvp.ap import normalize
        self.assertEqual(normalize({'password':'synthetic-password','country':'00'})['country'],'00')

    def test_no_action_dispatches_fresh_and_upgrade_without_prompts(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(sys,'argv',['install_pi.py','--image-root',tmp]),patch.object(installer,'install') as install:
                self.assertEqual(installer.main(),0)
                self.assertTrue(install.call_args.args[0].automatic)
            for name in ('opt/pirate/VERSION','etc/pirate/deployment.json','etc/pirate/admin.json','etc/pirate/installation.json'):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')
            with patch.object(sys,'argv',['install_pi.py','--image-root',tmp]),patch.object(installer,'upgrade') as upgrade,patch.object(installer,'detect_bootstrap') as detect:
                self.assertEqual(installer.main(),0)
                upgrade.assert_called_once();detect.assert_not_called()

if __name__=='__main__':unittest.main()
