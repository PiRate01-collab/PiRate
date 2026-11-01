import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from gate_core.core import ProfileStore, ProfileError, snapshot

class StoreTests(unittest.TestCase):
    def test_create_list_delete_and_reject_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            store=ProfileStore(Path(d)/'profiles.json')
            p=store.create({'name':'Test','type':'openvpn','server':'vpn.example','port':1194,'dns_mode':'tunnel','notes':''})
            self.assertEqual(len(store.list()),1)
            self.assertEqual(store.list()[0]['state'],'saved_only')
            self.assertEqual((Path(d)/'profiles.json').stat().st_mode & 0o777,0o600)
            with self.assertRaises(ProfileError):
                store.create({'name':'Bad','type':'openvpn','password':'secret'})
            self.assertTrue(store.delete(p['id']))
            self.assertEqual(store.list(),[])
    def test_status(self):
        with patch('gate_core.core.command', return_value=None), patch('gate_core.core.get_conf', return_value={}):
            self.assertIn('services',snapshot())

if __name__=='__main__': unittest.main()
