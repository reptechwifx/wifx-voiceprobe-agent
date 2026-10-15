"""Real key generation and password/bootstrap safety, isolated in temporary paths."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'agent/src'))
from credentials import generate_password, hash_password, verify_password
from identity import verify_identity, public_identity

spec = importlib.util.spec_from_file_location('configure_agent', ROOT / 'scripts/configure-agent.py')
configure = importlib.util.module_from_spec(spec); spec.loader.exec_module(configure)


class ProvisioningTest(unittest.TestCase):
    def test_passwords_are_unique_hashed_and_require_no_controller(self):
        values = [generate_password() for _ in range(20)]
        self.assertEqual(len(set(values)), 20)
        for password in values:
            self.assertGreaterEqual(len(password), 16)
            for pattern in ['[a-z]', '[A-Z]', '[0-9]']:
                self.assertRegex(password, pattern)
        encoded = hash_password(values[0])
        self.assertNotIn(values[0], encoded)
        self.assertTrue(verify_password(values[0], {'local_password_hash': encoded}))
        self.assertFalse(verify_password('wrong', {'local_password_hash': encoded}))
        self.assertTrue(verify_password('existing-lab-password', {'local_password': 'existing-lab-password'}))
        self.assertFalse(verify_password('', {}))
        with self.assertRaises(ValueError): hash_password('short')

    def test_preparation_is_offline_and_repeat_preserves_everything(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            self.assertTrue(configure.prepare(path))
            cfg = json.loads(path.read_text())
            self.assertEqual(cfg['controller_url'], '')
            self.assertEqual(cfg['port'], 18441)
            self.assertEqual(cfg['adoption_state'], 'unconfigured')
            self.assertNotIn('local_password', cfg)
            verify_identity(cfg)
            self.assertEqual(Path(cfg['identity_private_key']).stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            credentials = json.loads((path.parent / 'install-credentials.json').read_text())
            self.assertTrue(verify_password(credentials['password'], cfg))
            original = {p.name: p.read_bytes() for p in path.parent.iterdir() if p.is_file()}
            self.assertFalse(configure.prepare(path))
            self.assertEqual(original, {p.name:p.read_bytes() for p in path.parent.iterdir() if p.is_file()})
            Path(cfg['identity_private_key']).unlink()
            with self.assertRaises((ValueError, OSError)): verify_identity(cfg)
            self.assertFalse(configure.prepare(path))
            self.assertFalse(Path(cfg['identity_private_key']).exists())

    def test_identity_matches_openssl_and_signature_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json';configure.prepare(path);cfg=json.loads(path.read_text())
            public, fingerprint=public_identity(cfg['identity_private_key'])
            self.assertEqual(fingerprint,cfg['identity_fingerprint'])
            pem=subprocess.run(['openssl','pkey','-in',cfg['identity_private_key'],'-pubout'],capture_output=True,check=True).stdout
            pub=Path(directory)/'public.pem';pub.write_bytes(pem)
            signature=subprocess.run(['openssl','dgst','-sha256','-sign',cfg['identity_private_key']],input=b'bound enrollment payload',capture_output=True,check=True).stdout
            sig=Path(directory)/'signature.bin';sig.write_bytes(signature)
            result=subprocess.run(['openssl','dgst','-sha256','-verify',str(pub),'-signature',str(sig)],input=b'bound enrollment payload',capture_output=True)
            self.assertEqual(result.returncode,0)
            result=subprocess.run(['openssl','dgst','-sha256','-verify',str(pub),'-signature',str(sig)],input=b'changed payload',capture_output=True)
            self.assertNotEqual(result.returncode,0)
