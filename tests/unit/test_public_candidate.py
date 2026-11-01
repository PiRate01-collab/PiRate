"""Focused public-candidate regressions using existing unit infrastructure."""
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock
from gate_core.mvp import support,preflight
from gate_core.mvp.profiles import Profiles
from gate_core.core import ProfileError
from tools import install_pi

class PublicCandidateTests(unittest.TestCase):
    def test_legacy_records_retained_but_inaccessible(self):
        with tempfile.TemporaryDirectory() as d:
            store=Profiles(Path(d)/'profiles.json')
            legacy={'id':'00000000-0000-4000-8000-000000000001','type':'pptp','password':'private','name':'old'}
            store.path.write_text(json.dumps([legacy]))
            p=store.create({'name':'Direct','type':'direct'})
            self.assertEqual(len(store.list()),1)
            with self.assertRaises(ProfileError):store.get(legacy['id'])
            with self.assertRaises(ProfileError):store.create({'name':'old','type':'pptp','server':'example.org','port':1723})
            store.update(p['id'],{'name':'Renamed','type':'direct'})
            store.delete(p['id'])
            self.assertEqual(json.loads(store.path.read_text()),[legacy])
            self.assertEqual(store.path.stat().st_mode&0o777,0o600)

    def test_latest_attempt_search_and_unknown_timestamp(self):
        with tempfile.TemporaryDirectory() as d:
            store=Profiles(Path(d)/'profiles.json');p=store.create({'name':'Proxy','type':'http','server':'example.org','port':8080})
            app=SimpleNamespace(directory=Path(d)/'runtime',profiles=store,current=None,previous=None,ap=None)
            svc=support.service(app)
            svc.events.add('http','old error','error',p,attempt_id='old')
            svc.events.add('http','new error password=hidden','error',p,attempt_id='new')
            with patch.object(support,'bounded_command',return_value={'exit':0,'limited':False,'output':''}):
                rows=svc.logs({'profile_id':p['id'],'search':'error'})
            self.assertEqual(rows['attempt_id'],'new');self.assertEqual(len(rows['entries']),1)
            self.assertNotIn('hidden',rows['entries'][0]['line']);self.assertIn('pirate[',rows['entries'][0]['line'])
            self.assertIn('--- -- --:--:--',support.log_line({'time':None,'message':'no timestamp'}))

    def test_worker_uses_production_request_and_closes_before_success(self):
        raw=json.dumps({'type':'http','server':'example.org','port':8080,'endpoint_ip':'1.1.1.1','username':'private','password':'secret'}).encode()
        backend=Mock();backend.request.return_value={'body':'8.8.8.8'}
        with patch('gate_core.mvp.proxy.ProxyBackend',return_value=backend),patch.object(preflight.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),patch('sys.stdout',new_callable=io.StringIO) as out:
            preflight.proxy_worker()
        self.assertTrue(json.loads(out.getvalue())['ok']);backend.stop.assert_called_once()
        backend.request.assert_called_once_with('https://api.ipify.org/')
        self.assertNotIn('secret',out.getvalue())

    def test_worker_rejects_non_ip_response_and_closes(self):
        raw=json.dumps({'type':'http','endpoint_ip':'1.1.1.1'}).encode();backend=Mock();backend.request.return_value={'body':'login required'}
        with patch('gate_core.mvp.proxy.ProxyBackend',return_value=backend),patch.object(preflight.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),patch('sys.stdout',new_callable=io.StringIO) as out:
            preflight.proxy_worker()
        self.assertFalse(json.loads(out.getvalue())['ok']);backend.stop.assert_called_once()

    def test_cancelled_worker_killed_and_reaped(self):
        cancel=threading.Event();cancel.set();process=Mock();process.poll.return_value=None
        with patch('subprocess.Popen',return_value=process):
            value=preflight.proxy_check({'type':'http'},'1.1.1.1',cancel,lambda:True)
        self.assertNotIn('ok',value);process.kill.assert_called_once();process.wait.assert_called_once()

    def test_short_installer_banner_actual_ssh_and_pending_setup(self):
        status={'listeners':[{'scope':'loopback','address':'127.0.0.1','port':8765}]}
        with patch('gate_core.mvp.admin.read_public',return_value=status),patch('gate_core.mvp.admin.live_status',return_value=True),patch('gate_core.mvp.admin.listeners',return_value={('127.0.0.1',8765),('0.0.0.0',22)}),patch('gate_core.mvp.admin.interfaces',return_value=[{'addr_info':[{'family':'inet','local':'192.0.2.2'}]}]),patch.dict(os.environ,{'SSH_CONNECTION':'192.0.2.1 12345 192.0.2.2 22','SUDO_USER':'owner'}),patch('sys.stdout',new_callable=io.StringIO) as out:
            install_pi.installation_banner(Path('/'),SimpleNamespace(image_root=None,action='install'),{'username':'admin','bootstrap_only':True})
        text=out.getvalue();self.assertIn('owner@192.0.2.2',text);self.assertIn('sudo pirate passwd',text)
        self.assertIn('Применить → Подтвердить',text);self.assertNotIn('Backup',text);self.assertNotIn('BLOCKED',text)

if __name__=='__main__':unittest.main()
