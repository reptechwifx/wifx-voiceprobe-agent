# SPDX-License-Identifier: GPL-3.0-or-later
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('bundle_audit', Path(__file__).resolve().parents[1] / 'windows/audit-bundle.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class WindowsBundleAuditTest(unittest.TestCase):
    def test_forbidden_paths_modules_and_personal_data_are_rejected(self):
        for name in ('gateway', 'agent.src.gateway', 'controller/app/example.php', 'app/Http/Controllers/AgentController.php', 'pip._internal', 'setuptools', 'setuptools/__init__.py', 'tools/swig.exe', 'admin.json', 'provisioning.json', 'WIFX-VoiceProbe.provision.json', 'identity.key'):
            with self.subTest(name=name):
                self.assertIsNotNone(audit.forbidden_reason(name))
        for name in ('portable_runtime', 'portable_agent', 'cryptography.hazmat.primitives.serialization', 'provisioning-public.pem', 'build-trust.json', 'numpy.libs/openblas.dll', 'numpy-2.5.4.dist-info/WHEEL'):
            with self.subTest(name=name):
                self.assertIsNone(audit.forbidden_reason(name))
        for name in ('../outside', '/outside', 'C:\\outside', '\\\\server\\share', 'normal/../../outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.normalize_name(name)

    def test_secret_matches_never_serialize_the_secret(self):
        secret = 'LAB-synthetic-credential-for-unit-test'
        scanner = audit.Scanner([secret])
        scanner.member('portable_runtime', secret.encode('utf-16-le'), 'pyz')
        scanner.member('data.bin', base64.b64encode(secret.encode()), 'x')
        self.assertEqual(2, len(scanner.issues))
        serialized = json.dumps({'issues': scanner.issues, 'members': scanner.members})
        self.assertNotIn(secret, serialized)
        self.assertIn('utf16le', serialized)
        self.assertIn('base64', serialized)

    def test_personal_home_paths_are_detected_without_person_specific_constants(self):
        cases = [b'/ho' + b'me/synthetic-user/work/', b'C:\\Users\\synthetic-user\\AppData', b'\\\\wsl.localhost\\Ubuntu\\home\\synthetic-user\\work']
        for raw in cases:
            scanner = audit.Scanner()
            scanner.member('runtime.py', raw, 'pyz')
            self.assertTrue(scanner.issues)
        scanner = audit.Scanner()
        scanner.member('runtime.py', b'/opt/voiceprobe/releases/', 'pyz')
        self.assertFalse(scanner.issues)

    def test_key_material_requires_explicit_exact_public_fixture_exception(self):
        pem = b'-----BEGIN ' + b'PRIVATE KEY-----\nZmFrZQ==\n-----END ' + b'PRIVATE KEY-----'
        digest = hashlib.sha256(pem).hexdigest()
        refused = audit.Scanner()
        refused.member('crypto.dll', pem, 'b')
        self.assertEqual('private_pem_material', refused.issues[0]['condition'])
        self.assertNotIn('ZmFrZQ==', json.dumps(refused.issues))
        wrong_exception = audit.Scanner(allowed_test_keys=['0' * 64])
        wrong_exception.member('crypto.dll', pem, 'b')
        self.assertTrue(wrong_exception.issues)
        permitted = audit.Scanner(allowed_test_keys=[digest])
        permitted.member('crypto.dll', pem, 'b')
        self.assertFalse(permitted.issues)
        self.assertTrue(permitted.pem_candidates[0]['allowed_public_upstream_fixture'])
        delimiters = audit.Scanner()
        delimiters.member('cryptography.serialization', b'-----BEGIN ' + b'OPENSSH PRIVATE KEY-----' + b'\0marshal-constant-separator\0' + b'-----END ' + b'OPENSSH PRIVATE KEY-----', 'pyz')
        self.assertFalse(delimiters.issues)
        self.assertEqual(1, delimiters.pem_format_markers[0]['begin_markers'])

    def test_nested_zip_is_scanned_and_escaping_zip_rejected(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr('app/routes/private.php', 'private controller source')
        scanner = audit.Scanner()
        scanner.member('base_library.zip', output.getvalue(), 'x')
        self.assertEqual(2, len(scanner.members))
        self.assertTrue(scanner.issues)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr('../outside', 'not extracted')
        with self.assertRaises(ValueError):
            audit.Scanner().member('bad.zip', output.getvalue(), 'x')
        # A self-extracting PE can contain ZIP footers without being a ZIP member.
        audit.Scanner().member('executable-outer', b'MZnonzip' + output.getvalue(), 'pe')

    def test_personal_signed_provisioning_is_detected_without_known_secret(self):
        invitation = {'invitation_secret': 'synthetic-private-fixture', 'name': 'LAB'}
        envelope = {'payload': base64.b64encode(json.dumps(invitation).encode()).decode(), 'signature': 'public-signature'}
        scanner = audit.Scanner()
        scanner.member('innocent-name.json', json.dumps(envelope).encode(), 'x')
        self.assertEqual('personal_provisioning_or_credentials', scanner.issues[0]['condition'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            path.write_text(json.dumps(envelope))
            self.assertEqual({'synthetic-private-fixture'}, audit.fixture_secrets(path))
        self.assertFalse(audit.personal_json(b'{"provisioning_public_key":"public.pem"}'))

    def test_execution_manifest_rejects_elevation_and_ambiguous_privileges(self):
        valid = '<assembly><requestedExecutionLevel level="asInvoker" uiAccess="false"/></assembly>'
        self.assertEqual('asInvoker', audit.validate_manifest(valid))
        for value in (valid.replace('asInvoker', 'requireAdministrator'), valid.replace('false', 'true'), '<assembly/>', valid.replace('</assembly>', '<requestedExecutionLevel level="asInvoker"/></assembly>')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit.validate_manifest(value)
