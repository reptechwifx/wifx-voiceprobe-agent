"""Portable admission policy: real RSA proofs, fail-closed leases and read-only UI."""
import base64
import datetime
import hashlib
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from portable_runtime import (EphemeralIdentity, PortableError, PortableLease,
                              status_view, verify_provisioning)


class ProvisioningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = cls.key.public_key()
        cls.pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.key_id = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def payload(self):
        return {'schema': 'wifx-voiceprobe-portable-provisioning-v1',
                'invitation_id': '12345678-1234-4321-8123-123456789abc',
                'invitation_secret': 'A'*43, 'controller_url': 'https://controller.example',
                'name': 'Sonde LAB', 'organization': 'LAB', 'site': 'Essais',
                'expires_at': '2030-01-01T00:00:00Z', 'agent_version': '0.9-004', 'mode': 'ephemeral'}

    def envelope(self, payload=None):
        raw = json.dumps(self.payload() if payload is None else payload).encode()
        return {'payload': base64.b64encode(raw).decode(),
                'signature': base64.b64encode(self.key.sign(raw, padding.PKCS1v15(), hashes.SHA256())).decode(),
                'key_id': self.key_id}

    def verify(self, envelope):
        return verify_provisioning(json.dumps(envelope).encode(), {self.key_id: self.pem}, agent_version='0.9-004', now=1_800_000_000)

    def test_real_signature_verifies_and_preserves_invitation(self):
        self.assertEqual(self.payload(), self.verify(self.envelope()))

    def test_tampering_rejected(self):
        doc = self.envelope(); doc['payload'] = base64.b64encode(b'{}').decode()
        with self.assertRaises(PortableError): self.verify(doc)

    def test_unknown_and_mismatched_roots_rejected(self):
        doc = self.envelope(); doc['key_id'] = '0'*64
        with self.assertRaises(PortableError): self.verify(doc)
        with self.assertRaises(PortableError):
            verify_provisioning(json.dumps(doc).encode(), {'0'*64: self.pem}, agent_version='0.9-004')

    def test_signed_expired_wrong_version_invalid_secret_and_extra_fields_rejected(self):
        changes = [('expires_at', '2000-01-01T00:00:00Z'), ('expires_at', '2030-01-01T00:00:00'),
                   ('agent_version', 'other'), ('invitation_secret', 'short'), ('sip_password', 'forbidden'),
                   ('mode', 'persistent'), ('organization', None)]
        for name, value in changes:
            with self.subTest(name=name, value=value):
                payload = self.payload(); payload[name] = value
                with self.assertRaises(PortableError): self.verify(self.envelope(payload))

    def test_insecure_or_credential_bearing_controller_rejected(self):
        for url in ['http://controller.example', 'https://user:secret@controller.example',
                    'https://controller.example?secret=x', 'https://controller.example/path',
                    'https://controller.example:99999']:
            with self.subTest(url=url):
                payload = self.payload(); payload['controller_url'] = url
                with self.assertRaises(PortableError): self.verify(self.envelope(payload))

    def test_duplicate_json_and_oversized_document_rejected(self):
        with self.assertRaises(PortableError):
            verify_provisioning(b'{"payload":"x","payload":"y"}', {}, agent_version='0.9-004')
        with self.assertRaises(PortableError):
            verify_provisioning(b' '*65537, {}, agent_version='0.9-004')


class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.identity = EphemeralIdentity()
        self.challenge = {'challenge_id': '12345678-1234-4321-8123-123456789abc',
                          'nonce': 'a'*64, 'audience': 'https://controller.example'}
        self.result = {'id': self.identity.id, 'fingerprint': self.identity.fingerprint, 'state': 'pending'}
        self.cfg = {'controller_url': 'https://controller.example'}

    def response(self, value, status=200):
        return Mock(status_code=status, content=json.dumps(value).encode(), raise_for_status=Mock())

    def test_identity_matches_existing_rsa_challenge_contract_without_openssl_or_files(self):
        session = Mock()
        session.post.side_effect = [self.response(self.challenge), self.response(self.result)]
        payload = {'action': 'present', 'portable_invitation': {'id': 'test', 'secret': 'one-session-only'}}
        with patch('subprocess.run', side_effect=AssertionError('No external OpenSSL')):
            self.assertEqual(self.result, self.identity.exchange(self.cfg, payload, session=session))
        body = session.post.call_args.kwargs['json']
        raw = base64.b64decode(body['payload'])
        message = '\n'.join(['WIFX-VoiceProbe-Enrollment-v1', self.challenge['audience'], self.challenge['challenge_id'],
                             self.challenge['nonce'], self.identity.id, self.identity.fingerprint,
                             hashlib.sha256(raw).hexdigest()]).encode()
        public = serialization.load_der_public_key(base64.b64decode(self.identity.public_key))
        public.verify(base64.b64decode(body['signature']), message, padding.PKCS1v15(), hashes.SHA256())
        for call in session.post.call_args_list:
            self.assertFalse(call.kwargs['allow_redirects'])
            self.assertIs(call.kwargs['verify'], True)

    def test_cross_controller_challenge_and_redirect_do_not_send_proof(self):
        self.challenge['audience'] = 'https://other.example'
        session = Mock(); session.post.return_value = self.response(self.challenge)
        with self.assertRaises(PortableError): self.identity.exchange(self.cfg, {}, session=session)
        self.assertEqual(1, session.post.call_count)
        session = Mock(); session.post.return_value = self.response({}, 302)
        with self.assertRaises(PortableError): self.identity.exchange(self.cfg, {}, session=session)
        self.assertEqual(1, session.post.call_count)

    def test_other_identity_response_rejected_and_close_destroys_signer_reference(self):
        self.result['id'] = 'other'
        session = Mock(); session.post.side_effect = [self.response(self.challenge), self.response(self.result)]
        with self.assertRaises(PortableError): self.identity.exchange(self.cfg, {}, session=session)
        self.identity.close()
        with self.assertRaises(PortableError): self.identity.sign(b'any')


class LeaseTest(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.lease = PortableLease(clock=lambda: self.now)

    def grant(self, seconds=60):
        return self.lease.apply({'state': 'authorized', 'lease_seconds': seconds}, self.lease.begin_request())

    def test_pending_denies_then_server_grant_expires_using_monotonic_time(self):
        self.assertFalse(self.lease.allowed())
        self.assertTrue(self.grant())
        self.now += 59
        self.assertTrue(self.lease.allowed())
        with patch('time.time', return_value=0):
            self.now += 1
            self.assertFalse(self.lease.allowed())
        self.assertEqual('expired', self.lease.snapshot()['state'])

    def test_network_round_trip_counts_against_lease(self):
        request = self.lease.begin_request(); self.now += 61
        self.assertFalse(self.lease.apply({'state': 'authorized', 'lease_seconds': 60}, request))

    def test_out_of_order_and_duplicate_responses_cannot_renew(self):
        old = self.lease.begin_request(); new = self.lease.begin_request()
        self.lease.apply({'state': 'authorized', 'lease_seconds': 30}, new)
        self.now += 20
        self.assertFalse(self.lease.apply({'state': 'authorized', 'lease_seconds': 60}, old))
        self.assertFalse(self.lease.apply({'state': 'authorized', 'lease_seconds': 60}, new))
        self.assertEqual(10, self.lease.snapshot()['remaining_seconds'])

    def test_revocation_and_server_expiry_override_inflight_responses_permanently(self):
        for state in ('revoked', 'expired'):
            lease = PortableLease(clock=lambda: self.now)
            inflight = lease.begin_request()
            lease.deny(state)
            self.assertFalse(lease.apply({'state': 'authorized', 'lease_seconds': 60}, inflight))
            self.assertFalse(lease.allowed())

    def test_invalid_lease_never_grants_permission(self):
        for state, seconds in [('authorized', 61), ('authorized', float('nan')), ('authorized', True),
                               ('pending', 10), ('adopted', 60), ('authorized', -1), ('authorized', '60')]:
            with self.subTest(state=state, seconds=seconds):
                self.grant()
                with self.assertRaises(PortableError):
                    self.lease.apply({'state': state, 'lease_seconds': seconds}, self.lease.begin_request())
                self.assertFalse(self.lease.allowed())

    def test_full_authorization_duration_uses_server_time_minus_network_latency(self):
        request = self.lease.begin_request()
        self.now += 3
        value = {'state': 'authorized', 'lease_seconds': 60,
                 'server_time': '2026-10-15T12:00:00Z',
                 'authorization_expires_at': '2026-10-22T15:00:00Z'}
        with patch('time.time', return_value=1):
            self.assertTrue(self.lease.apply(value, request))
            self.assertEqual(7*86400+3*3600-3, self.lease.snapshot()['authorization_remaining_seconds'])
        self.assertEqual(57, self.lease.snapshot()['remaining_seconds'])
        # A displayed seven-day validity never extends the offline 60s lease.
        self.now += 58
        self.assertFalse(self.lease.allowed())
        self.assertEqual(0, self.lease.snapshot()['authorization_remaining_seconds'])

    def test_invalid_duration_metadata_is_unavailable_and_never_grants_authority(self):
        for expiry, server in [('bad', 'bad'), ('2026-10-22T15:00:00', '2026-10-15T12:00:00Z'),
                               ('2036-10-22T15:00:00Z', '2026-10-15T12:00:00Z'),
                               ('2026-10-10T12:00:00Z', '2026-10-15T12:00:00Z'), (None, 42)]:
            lease = PortableLease(clock=lambda: self.now)
            value = {'state': 'pending', 'lease_seconds': 0, 'authorization_expires_at': expiry, 'server_time': server}
            self.assertFalse(lease.apply(value, lease.begin_request()))
            self.assertFalse(lease.allowed())
            self.assertEqual(0, lease.snapshot()['authorization_remaining_seconds'])
            value.update(state='authorized', lease_seconds=60)
            self.assertTrue(lease.apply(value, lease.begin_request()))
            self.assertIsNone(lease.snapshot()['authorization_remaining_seconds'])
            self.now += 61
            self.assertFalse(lease.allowed())

    def test_authorization_duration_format_uses_days_hours_minutes_and_no_lease_value(self):
        from portable_gui import format_authorization_duration
        for value, expected in [(7*86400+3*3600, '7 j 3 h'), (3600+10*60, '1 h 10 min'),
                                (10*60+30, '10 min'), (45, '45 s'), (0, '0 s'),
                                (None, 'INDISPONIBLE'), (True, 'INDISPONIBLE')]:
            self.assertEqual(expected, format_authorization_duration(value))

    def test_client_view_is_allowlisted_even_if_backend_error_contains_credentials(self):
        snapshot = {'token': 'forbidden', 'identity_private_key': 'forbidden', 'controller_url': 'private',
                    'accounts': [{'password': 'forbidden', 'username': 'private', 'registration_code': 200, 'registration_active': True}],
                    'last_error': 'sip:private@example?password=forbidden', 'events': ['forbidden'], 'recent_runs': []}
        view = status_view(snapshot, {'state': 'authorized', 'remaining_seconds': 10})
        text = json.dumps(view)
        for word in ('forbidden', 'private', 'password', 'token', 'username', 'controller_url'):
            self.assertNotIn(word, text)
        self.assertEqual('OK', view['sip'])


class SharedEngineHooksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_configuration import main
        cls.main = main
        with patch.dict(sys.modules, {'main': main}):
            import portable_agent
        cls.portable = portable_agent

    def engine(self):
        import asyncio
        import queue
        import threading
        agent = self.main.Agent.__new__(self.main.Agent)
        agent.running = True; agent.poll_now = threading.Event()
        agent.communication = lambda: None
        async def wss():
            await asyncio.sleep(100)
        agent.wss = wss
        agent.calls = {}; agent.accounts = {}; agent.rejected = []
        agent.endpoint = Mock(); agent.db = Mock(); agent.maintenance = Mock()
        agent.inbox = queue.Queue(); agent.prepared = {}
        agent.management_export = Mock()
        return agent

    def test_portable_run_does_not_construct_server_install_signals_or_export_status(self):
        agent = self.engine()
        agent.before_iteration = agent.request_stop
        with patch.object(self.main, 'LocalWebService') as server, patch.object(self.main.signal, 'signal') as signals:
            agent.run(enable_web=False, install_signals=False, export_management=False)
        server.assert_not_called(); signals.assert_not_called(); agent.management_export.assert_not_called()
        agent.endpoint.libDestroy.assert_called_once(); agent.db.close.assert_called_once()

    def test_engine_error_also_releases_native_endpoint(self):
        agent = self.engine()
        agent.before_iteration = Mock(side_effect=RuntimeError('injected error'))
        with self.assertRaises(RuntimeError):
            agent.run(enable_web=False, install_signals=False, export_management=False)
        agent.endpoint.libDestroy.assert_called_once(); self.assertFalse(agent.running)

    def test_portable_rejects_local_writes_and_never_uses_disk_database(self):
        agent = self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        self.assertEqual(':memory:', agent.database_location())
        with self.assertRaises(PortableError): agent.update_local({'token': 'attempt'})
        agent.persist_config()  # Must not require any configuration path.

    def test_constructor_failure_releases_partial_native_endpoint_and_private_temp(self):
        observed = {}
        endpoint = Mock()
        endpoint.libDestroy.side_effect = RuntimeError("cleanup failure must not mask startup")
        identity = Mock(id="12345678-1234-4321-8123-123456789abc", public_key="public", fingerprint="f"*64)
        def failing_init(instance, *, config, data_directory):
            instance.endpoint = endpoint
            observed['temporary'] = Path(data_directory)
            raise ValueError("injected transport startup failure")
        provision = {'name': 'LAB', 'controller_url': 'https://controller.example', 'invitation_secret': 'A'*43}
        with patch.object(self.portable, 'EphemeralIdentity', return_value=identity), patch.object(self.main.Agent, '__init__', failing_init):
            with self.assertRaisesRegex(ValueError, 'injected transport startup failure'):
                self.portable.PortableAgent(provision)
        endpoint.libDestroy.assert_called_once()
        identity.close.assert_called_once()
        self.assertFalse(observed['temporary'].exists())

    def test_authenticated_denial_distinguishes_expiry_without_exposing_error_text(self):
        import queue
        for server_state, expected in [('expired', 'expired'), ('revoked', 'revoked'),
                                       ('untrusted arbitrary error text', 'revoked'), (None, 'revoked')]:
            with self.subTest(state=server_state):
                agent = self.portable.PortableAgent.__new__(self.portable.PortableAgent)
                agent.running = True; agent.cfg = {'controller_url': 'https://controller.example', 'token': 'T'*80, 'ca_file': True}
                agent.persistent = False
                agent.poll_now = threading.Event()
                agent.lease = PortableLease(); agent.inbox = queue.Queue()
                response = Mock(status_code=403, content=b'{}')
                response.json.return_value = {'portable_state': server_state, 'message': 'never displayed'}
                response.raise_for_status.side_effect = self.portable.requests.HTTPError()
                agent._http_session = Mock(return_value=Mock(request=Mock(return_value=response)))
                with self.assertRaises(self.portable.requests.HTTPError):
                    agent.api('GET', 'portable/lease')
                self.assertEqual(expected, agent.lease.snapshot()['state'])
                self.assertFalse(agent.lease.allowed())

    def test_revocation_keeps_native_accounts_alive_until_active_call_reports_finish(self):
        import time
        from types import SimpleNamespace
        agent = self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        agent.running = True; agent.lease = PortableLease(); agent.lease.deny()
        account = Mock(config={'password': 'synthetic-secret'})
        call = Mock()
        agent.accounts = {1: account}; agent.calls = {'active': call}
        agent.prepared = {'queued': {}}; agent.remote = {'accounts': []}; agent.remote_fingerprint = 'private-digest'
        agent.journal = SimpleNamespace(secrets=('synthetic-secret',))
        agent._display_sampled = time.monotonic()
        agent.revoke_configuration()
        self.assertFalse(agent.prepared)
        self.assertIsNone(agent.remote)
        account.shutdown.assert_not_called()
        agent.before_iteration()
        account.shutdown.assert_not_called()
        self.assertIn('password', account.config)
        # The shared SIP event loop has now completed report() and removed calls.
        agent.calls.clear()
        agent.before_iteration()
        account.shutdown.assert_called_once()
        self.assertEqual({}, agent.accounts)
        self.assertEqual({}, account.config)

    def test_stop_refuses_new_http_work_without_opening_a_transport(self):
        agent = self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        agent.running = False
        agent._http_session = Mock()
        with self.assertRaises(PortableError):
            agent.api('GET', 'commands')
        agent._http_session.assert_not_called()

    def test_expired_authorization_gates_incoming_outgoing_and_remote_configuration(self):
        agent = self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        agent.running = True; agent.lease = PortableLease()
        with patch.object(self.main.Agent, 'capacity', return_value=True) as shared_capacity:
            self.assertFalse(agent.capacity(Mock())); shared_capacity.assert_not_called()
            agent.lease.apply({'state': 'authorized', 'lease_seconds': 60}, agent.lease.begin_request())
            self.assertTrue(agent.capacity(Mock())); shared_capacity.assert_called_once()
        agent.lease.deny()
        with patch.object(self.main.Agent, 'apply_config') as apply:
            agent.apply_config({'accounts': [{'password': 'not-applied'}]})
        apply.assert_not_called()

class WebsocketRedirectTest(unittest.TestCase):
    def test_real_tls_redirect_cannot_forward_the_bearer_to_another_origin(self):
        import asyncio
        import http.server
        import ipaddress
        import ssl
        import tempfile
        import threading
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from portable_runtime import websocket_connector
        from websockets.exceptions import InvalidHandshake
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(key, hashes.SHA256()))
        requests_seen = [0, 0]
        class Target(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                requests_seen[1] += 1
                self.send_response(403); self.end_headers()
        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                requests_seen[0] += 1
                self.send_response(302)
                self.send_header('Location', 'wss://127.0.0.1:' + str(target.server_port) + '/forbidden')
                self.end_headers()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pem = root/'cert.pem'; private = root/'key.pem'
            pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            private.chmod(0o600)
            target = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
            source = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(pem, private)
            for server in (target, source):
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                async def connect():
                    ctx = ssl.create_default_context(cafile=str(pem))
                    async with websocket_connector()('wss://127.0.0.1:' + str(source.server_port) + '/ws',
                            ssl=ctx, extra_headers={'Authorization': 'Bearer synthetic-test-value'}, open_timeout=3):
                        self.fail('Redirect accepted')
                with self.assertRaises(InvalidHandshake): asyncio.run(connect())
                self.assertEqual([1, 0], requests_seen)
            finally:
                for server in (source, target): server.shutdown(); server.server_close()


if __name__ == '__main__':
    unittest.main()
