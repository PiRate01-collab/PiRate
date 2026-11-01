"""HTTP handler tests use memory streams, never sockets or user profiles."""
import io
import json
import unittest
from email.message import Message
from unittest.mock import Mock, patch
from web import server


def handler(body=b'', headers=None):
    obj = object.__new__(server.Handler)
    obj.headers = Message()
    for key, value in (headers or {'Host': f'{server.HOST}:{server.PORT}'}).items():
        obj.headers[key] = value
    obj.rfile = io.BytesIO(body)
    obj.path = '/api/profiles'
    obj.send_data = Mock()
    return obj


class ApiTests(unittest.TestCase):
    def test_host_and_origin_all_methods_before_storage(self):
        with patch.object(server, 'STORE') as store, patch.object(server, 'snapshot') as snapshot:
            for method in ('GET', 'POST', 'PUT', 'DELETE'):
                for headers in ({}, {'Host': 'evil.example'}, {'Host': f'{server.HOST}:{server.PORT}', 'Origin': 'https://evil.example'}):
                    obj = handler(headers={'Host': 'evil.example'} if not headers else headers)
                    getattr(obj, 'do_' + method)()
                    self.assertEqual(obj.send_data.call_args.args[0], 403)
            store.list.assert_not_called()
            store.create.assert_not_called()
            snapshot.assert_not_called()

    def test_missing_duplicate_host_and_origin(self):
        obj = handler(); del obj.headers['Host']
        self.assertFalse(obj.request_allowed())
        obj = handler(); obj.headers['Host'] = 'evil.example'
        self.assertFalse(obj.request_allowed())
        obj = handler(); obj.headers['Origin'] = f'http://{server.HOST}:{server.PORT}'
        self.assertTrue(obj.request_allowed())
        obj.headers['Origin'] = 'https://evil.example'
        self.assertFalse(obj.request_allowed())

    def test_body_validation(self):
        for headers, body, status in [
            ({'Content-Type': 'text/plain', 'Content-Length': '2'}, b'{}', 415),
            ({'Content-Type': 'application/json'}, b'', 400),
            ({'Content-Type': 'application/json', 'Content-Length': '-1'}, b'', 400),
            ({'Content-Type': 'application/json', 'Content-Length': '4097'}, b'', 413),
            ({'Content-Type': 'application/json', 'Content-Length': '2'}, b'{', 400),
            ({'Content-Type': 'application/json', 'Content-Length': '2'}, b'\xff\xff', 400),
            ({'Content-Type': 'application/json', 'Content-Length': '2', 'Transfer-Encoding': 'chunked'}, b'{}', 400),
        ]:
            obj = handler(body, headers)
            with self.assertRaises(server.RequestError) as error: obj.read_json()
            self.assertEqual(error.exception.status, status)
        obj = handler(b'{}', {'Content-Type': 'application/json', 'Content-Length': '2'})
        self.assertEqual(obj.read_json(), {})
        obj.headers['Content-Length'] = '2'
        with self.assertRaises(server.RequestError): obj.read_json()

    def test_body_timeout_returns_408(self):
        obj = handler(headers={'Host': f'{server.HOST}:{server.PORT}', 'Content-Type': 'application/json', 'Content-Length': '2'})
        obj.rfile = Mock(); obj.rfile.read.side_effect = TimeoutError()
        obj.do_POST()
        self.assertEqual(obj.send_data.call_args.args[0], 408)

    def test_setup_sets_timeout(self):
        obj = handler(); obj.connection = Mock()
        with patch('http.server.BaseHTTPRequestHandler.setup'):
            obj.setup()
        obj.connection.settimeout.assert_called_once_with(server.REQUEST_TIMEOUT)

    def test_delete_reports_missing_and_corrupt_store(self):
        obj = handler(); obj.path += '/missing'
        with patch.object(server, 'STORE') as store:
            store.delete.return_value = False
            obj.do_DELETE()
            obj.send_data.assert_called_with(404, {'deleted': False})
            store.delete.side_effect = ValueError('private path')
            obj.do_DELETE()
            self.assertEqual(obj.send_data.call_args.args[0], 500)
            self.assertNotIn('private path', str(obj.send_data.call_args))

    def test_version_endpoint(self):
        obj = handler(); obj.path = '/api/version'; obj.do_GET()
        obj.send_data.assert_called_with(200, {'version': server.VERSION})
