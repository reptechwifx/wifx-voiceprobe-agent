"""Real per-user NCrypt and CryptProtectMemory tests, no elevation required.

Every native fixture uses fresh random instance UUIDs; cleanup never enumerates
or deletes unrelated keys. Windows-only tests are explicit skips elsewhere.
"""
import base64
import ctypes
import json
import os
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from portable_runtime import PortableError
from windows_identity import PersistentIdentity, REGISTRY_ROOT


@unittest.skipUnless(os.name=='nt','Windows NCrypt requis')
class WindowsIdentityTest(unittest.TestCase):
    def setUp(self):
        self.provision={'instance_id':str(uuid.uuid4()),'invitation_id':str(uuid.uuid4()),
                        'controller_url':'https://controller.example'}
        self.identity=None

    def tearDown(self):
        if self.identity and self.identity._key:
            self.identity.forget()

    def create(self):
        self.identity=PersistentIdentity(self.provision,allow_create=True)
        return self.identity

    def test_real_nonexportable_key_signs_and_reopens_unchanged(self):
        from cryptography.hazmat.primitives import serialization,hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        identity=self.create(); original=(identity.id,identity.fingerprint)
        message=b'Synthetic Windows NCrypt qualification'
        serialization.load_der_public_key(base64.b64decode(identity.public_key)).verify(identity.sign(message),message,padding.PKCS1v15(),hashes.SHA256())
        length=identity._cng.w.DWORD()
        status=identity._cng.dll.NCryptExportKey(identity._key,0,'RSAPRIVATEBLOB',None,None,0,ctypes.byref(length),0x40)
        self.assertNotEqual(0,status)
        identity.close(); self.identity=PersistentIdentity(self.provision,allow_create=False)
        self.assertEqual(original,(self.identity.id,self.identity.fingerprint)); self.assertFalse(self.identity.created)

    def test_missing_key_does_not_create_on_expired_invitation_or_reactivation(self):
        with self.assertRaises(PortableError): PersistentIdentity(self.provision,allow_create=False)
        import winreg
        with self.assertRaises(FileNotFoundError): winreg.OpenKey(winreg.HKEY_CURRENT_USER,REGISTRY_ROOT+'\\'+self.provision['instance_id'])

    def test_same_instance_concurrent_process_handle_is_refused(self):
        # Mutexes are recursive within one OS thread; use another thread.
        import threading
        self.create(); outcome=[]
        def open_again():
            try:
                other=PersistentIdentity(self.provision,allow_create=False)
                other.close(); outcome.append('unsafe')
            except PortableError: outcome.append('refused')
        worker=threading.Thread(target=open_again); worker.start(); worker.join(10)
        self.assertEqual(['refused'],outcome)

    def test_metadata_tamper_cannot_replace_or_delete_key(self):
        import winreg
        identity=self.create(); original=identity._read_metadata(); identity.close()
        keypath=REGISTRY_ROOT+'\\'+self.provision['instance_id']
        tampered=dict(original,fingerprint='0'*64)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,keypath,0,winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key,'Identity',0,winreg.REG_SZ,json.dumps(tampered))
        try:
            with self.assertRaises(PortableError): PersistentIdentity(self.provision,allow_create=True)
        finally:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,keypath,0,winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key,'Identity',0,winreg.REG_SZ,json.dumps(original))
            self.identity=PersistentIdentity(self.provision,allow_create=False)
        self.assertEqual(original['fingerprint'],self.identity.fingerprint)

    def test_agent_uuid_tamper_is_rejected_without_creating_new_identity(self):
        import winreg
        identity=self.create(); original=identity._read_metadata(); identity.close()
        keypath=REGISTRY_ROOT+'\\'+self.provision['instance_id']
        tampered=dict(original,id=str(uuid.uuid4()))
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,keypath,0,winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key,'Identity',0,winreg.REG_SZ,json.dumps(tampered))
        try:
            with self.assertRaises(PortableError): PersistentIdentity(self.provision,allow_create=True)
        finally:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,keypath,0,winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key,'Identity',0,winreg.REG_SZ,json.dumps(original))
            self.identity=PersistentIdentity(self.provision,allow_create=False)
        self.assertEqual(original['id'],self.identity.id)

    def test_signed_expected_identity_mismatch_refuses_existing_key(self):
        identity=self.create(); original=identity.id; identity.close()
        wrong=dict(self.provision,expected_agent_id=str(uuid.uuid4()),expected_fingerprint='0'*64)
        with self.assertRaises(PortableError): PersistentIdentity(wrong,allow_create=False)
        self.identity=PersistentIdentity(self.provision,allow_create=False); self.assertEqual(original,self.identity.id)

    def test_cleanup_removes_only_exact_instance(self):
        first=self.create(); other_provision=dict(self.provision,instance_id=str(uuid.uuid4()))
        other=PersistentIdentity(other_provision,allow_create=True)
        try:
            first.forget(); self.identity=None
            self.assertTrue(other.sign(b'still here'))
            with self.assertRaises(PortableError): PersistentIdentity(self.provision,allow_create=False)
        finally: other.forget()


@unittest.skipUnless(os.name=='nt','Windows CryptProtectMemory requis')
class WindowsMemoryTest(unittest.TestCase):
    def test_real_same_process_protection_mutable_borrow_and_zeroization(self):
        from portable_memory import ProtectedSecret
        raw=bytearray(b'SYNTHETIC_ONLY_NOT_A_REAL_PASSWORD')
        secret=ProtectedSecret(raw)
        try:
            self.assertTrue(secret._encrypted)
            self.assertNotIn(bytes(raw),ctypes.string_at(secret._pointer,secret._capacity))
            with secret.borrow() as borrowed:
                self.assertEqual(raw,borrowed)
                self.assertTrue(secret._encrypted)
                self.assertNotIn(bytes(raw),ctypes.string_at(secret._pointer,secret._capacity))
            self.assertEqual(bytearray(len(raw)),borrowed)
            self.assertTrue(secret._encrypted)
            self.assertNotIn(bytes(raw),ctypes.string_at(secret._pointer,secret._capacity))
            self.assertNotIn('SYNTHETIC',repr(secret))
        finally:
            secret.close(); raw[:]=b'\0'*len(raw)
        self.assertIsNone(secret._pointer)
        with self.assertRaises(PortableError):
            with secret.borrow(): pass

    def test_bearer_owned_slot_protected_and_dictionary_export_does_not_leak(self):
        from portable_memory import ProtectedSessionConfig
        config=ProtectedSessionConfig({'token':'SYNTHETIC_TOKEN_ONLY','id':'fixture'})
        first=config._bearer
        self.assertTrue(first._encrypted)
        self.assertEqual('SYNTHETIC_TOKEN_ONLY',config.get('token'))
        self.assertNotIn('SYNTHETIC',json.dumps(config))
        self.assertNotIn('SYNTHETIC',repr(config))
        config['token']='REPLACEMENT_FIXTURE'
        self.assertTrue(first._closed)
        current=config._bearer
        config.clear()
        self.assertTrue(current._closed); self.assertEqual({},config)

    def test_redaction_patterns_encrypted_and_only_sanitized_events_retained(self):
        from journal import EventJournal
        from portable_memory import ProtectedJournal
        old=EventJournal(secrets=('SYNTHETIC_REDACTION',))
        journal=ProtectedJournal(old)
        try:
            self.assertEqual((),old.secrets)
            self.assertTrue(journal._patterns[0]._encrypted)
            journal.record('fixture','SYNTHETIC_REDACTION value',password='SYNTHETIC_REDACTION')
            self.assertNotIn('SYNTHETIC_REDACTION',json.dumps(journal.snapshot()))
            self.assertNotIn('SYNTHETIC_REDACTION',str(journal.__dict__))
            previous=journal._patterns[0];journal.secrets=()
            self.assertTrue(previous._closed)
        finally: journal.secrets=()

    def test_exception_during_borrow_also_zeroes_copy(self):
        from portable_memory import ProtectedSecret
        secret=ProtectedSecret(b'SYNTHETIC')
        try:
            with self.assertRaisesRegex(RuntimeError,'fixture'):
                with secret.borrow() as borrowed: raise RuntimeError('fixture')
            self.assertEqual(bytearray(len(borrowed)),borrowed); self.assertTrue(secret._encrypted)
        finally: secret.close()


if __name__=='__main__':unittest.main()
