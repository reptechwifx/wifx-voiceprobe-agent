"""Real loopback listeners and deterministic address-change notification tests."""
import http.client
import pathlib
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from network_lifecycle import NetworkMonitor, network_key
from localweb import LocalWebService, build_server, management_peer_allowed


def snapshot(address=None, gateway='192.168.0.1'):
    return {'interfaces': [{'name': 'eth0', 'up': True, 'addresses':
                            [{'address': address}] if address else []}],
            'primary_interface': 'eth0', 'gateway': gateway}


class NetworkLifecycleTest(unittest.TestCase):
    def test_network_transitions_notify_without_identity_or_configuration_writes(self):
        events = []
        samples = iter([snapshot(), snapshot('192.168.0.30'), snapshot('192.168.0.30'),
                        snapshot(), snapshot('172.30.155.200', '172.30.155.1'),
                        snapshot('172.30.155.200', '172.30.155.254')])
        monitor = NetworkMonitor(events.append, reader=lambda: next(samples))
        for _ in range(6):
            monitor.sample()
        self.assertEqual(events, [True, False, True, True])

    def test_loopback_link_local_and_down_interfaces_do_not_trigger_sip_recovery(self):
        for address in ('127.0.0.1', '::1', 'fe80::1', '169.254.1.1'):
            self.assertFalse(network_key(snapshot(address))[0])
        value = snapshot('172.30.155.200')
        value['interfaces'][0]['up'] = False
        self.assertFalse(network_key(value)[0])
        self.assertTrue(network_key(snapshot('2001:db8::2'))[0])

    def test_auto_acl_and_explicit_acl_are_enforced_even_for_tls(self):
        for peer in ('127.0.0.1', '192.168.0.3', '172.30.155.3', '::1', 'fd00::3'):
            self.assertTrue(management_peer_allowed({'bind': 'auto'}, peer))
        for peer in ('8.8.8.8', '2001:4860:4860::8888', '::ffff:8.8.8.8'):
            self.assertFalse(management_peer_allowed({'bind': 'auto', 'tls_cert': 'configured'}, peer))
        cfg = {'bind': 'auto', 'management_allowed_networks': ['172.30.155.0/24']}
        self.assertFalse(management_peer_allowed(cfg, '192.168.0.3'))
        self.assertTrue(management_peer_allowed(cfg, '172.30.155.3'))
        self.assertFalse(management_peer_allowed({'management_allowed_networks': []}, '127.0.0.1'))

    def agent(self, **values):
        return types.SimpleNamespace(cfg={'id': 'lab', 'bind': 'auto', 'port': 0,
                                         'allow_http': True, **values})

    def test_auto_listener_works_without_a_configured_address_and_requires_authentication(self):
        agent = self.agent()
        original = dict(agent.cfg)
        server = build_server(agent)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertEqual(server.server_address[0], '0.0.0.0')
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
            connection.request('GET', '/api/status')
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            connection.close()
            self.assertEqual(agent.cfg, original)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_invalid_acl_fails_closed(self):
        with self.assertRaises(ValueError):
            build_server(self.agent(management_allowed_networks=['invalid']))

    def test_stale_explicit_address_is_not_silently_widened(self):
        agent = self.agent(bind='192.0.2.240')
        service = LocalWebService(agent, retry_s=.01)
        thread = threading.Thread(target=service.run)
        thread.start()
        try:
            deadline = time.monotonic() + 2
            while service.status == 'starting' and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(service.status, 'unavailable')
            self.assertEqual(service.servers, {})
            self.assertEqual(agent.cfg['bind'], '192.0.2.240')
        finally:
            service.stop(); thread.join(3)
        self.assertFalse(thread.is_alive())

    def test_listener_recovers_after_real_port_contention(self):
        blocker = socket.socket()
        blocker.bind(('127.0.0.1', 0)); blocker.listen()
        port = blocker.getsockname()[1]
        service = LocalWebService(self.agent(bind='127.0.0.1', port=port), retry_s=.02)
        thread = threading.Thread(target=service.run)
        thread.start()
        try:
            deadline = time.monotonic() + 2
            while service.status == 'starting' and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(service.status, 'unavailable')
            blocker.close()
            deadline = time.monotonic() + 2
            while service.status != 'ready' and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(service.status, 'ready')
        finally:
            blocker.close(); service.stop(); thread.join(3)
        self.assertFalse(thread.is_alive())

    @unittest.skipUnless(socket.has_ipv6, 'IPv6 absent')
    def test_ipv6_listener_and_host_filter(self):
        try:
            server = build_server(self.agent(), bind='::1')
        except OSError as error:
            self.skipTest(str(error))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            connection = http.client.HTTPConnection('::1', server.server_port, timeout=2)
            connection.request('GET', '/login')
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read(); connection.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()
