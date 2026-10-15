"""Host-independent structural and worker tests; real Windows launch is separate."""
import base64
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

WINDOWS = Path(__file__).resolve().parents[1] / 'windows'
sys.path.insert(0, str(WINDOWS))
import portable_package as package
spec = importlib.util.spec_from_file_location('personalizer', WINDOWS/'personalize-portable.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def template():
    raw = bytearray(512)
    raw[:2] = b'MZ'; struct.pack_into('<I', raw, 60, 64)
    raw[64:68] = b'PE\0\0'
    struct.pack_into('<HH', raw, 68, 0x8664, 1)
    struct.pack_into('<HH', raw, 84, 240, 2)
    struct.pack_into('<H', raw, 88, 0x20b)
    struct.pack_into('<H', raw, 156, 2)
    struct.pack_into('<I', raw, 196, 16)
    struct.pack_into('<II', raw, 344, 128, 384)
    # One bounded zero-size archive member, TOC padded to 16 bytes.
    toc = struct.pack('!IIIIBc', 32, 0, 0, 0, 0, b's') + b'entry\0'+b'\0'*8
    return bytes(raw)+toc+struct.pack('!8sIIII64s', package.COOKIE, len(toc)+88, 0, len(toc), 313, b'python313.dll')


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.original = template()
        self.envelope = b'{"key_id":"test","payload":"eA==","signature":"eA=="}'
        self.nonce = '1'*64
        self.personal = package.personalize(self.original, self.envelope, self.nonce)

    def test_roundtrip_exact_template_and_document(self):
        value = package.extract(self.personal)
        self.assertEqual(value['template_sha256'], hashlib.sha256(self.original).hexdigest())
        self.assertEqual(value['provisioning'], package.canonical(json.loads(self.envelope)))
        self.assertFalse(value['certificate_present'])

    def test_reject_truncation_trailing_injection_and_prefix_mutation(self):
        corrupt = bytearray(self.personal); corrupt[400] ^= 1
        for value in (self.personal[:-1], self.personal+b'evil', bytes(corrupt), self.personal+self.personal):
            with self.subTest(length=len(value)), self.assertRaises(package.PackageError):
                package.extract(value)

    def test_refuse_repersonalizing_or_signed_template(self):
        with self.assertRaises(package.PackageError):
            package.personalize(self.personal, self.envelope, self.nonce)
        signed = bytearray(self.original)
        struct.pack_into('<II', signed, 232, len(signed), 8)
        signed.extend(struct.pack('<IHH', 8, 0x200, 2))
        with self.assertRaises(package.PackageError):
            package.validate_template(bytes(signed))

    def test_signed_container_normalizes_only_authenticode_fields(self):
        signed = bytearray(self.personal)
        struct.pack_into('<I', signed, 152, 123456)
        struct.pack_into('<II', signed, 232, len(signed), 16)
        signed.extend(struct.pack('<IHH', 12, 0x200, 2)+b'test'+b'\0'*4)
        value = package.extract(bytes(signed))
        self.assertTrue(value['certificate_present'])
        self.assertEqual(value['template_sha256'], hashlib.sha256(self.original).hexdigest())
        signed[-1] = 1
        with self.assertRaises(package.PackageError):
            package.extract(bytes(signed))

    def test_duplicate_unknown_json_and_wrong_architecture(self):
        for raw in (b'{"x":1,"x":2}', b'[]'):
            with self.assertRaises(package.PackageError):
                package.document(raw)
        bad = bytearray(self.original); struct.pack_into('<H',bad,68,0x14c)
        with self.assertRaises(package.PackageError):
            package.validate_template(bytes(bad))


    def test_duplicate_archive_member_and_cookie_injection_refused(self):
        toc = self.original[512:-88]
        duplicate = self.original[:512]+toc+toc+struct.pack('!8sIIII64s', package.COOKIE, 2*len(toc)+88, 0, 2*len(toc), 313, b'python313.dll')
        with self.assertRaises(package.PackageError):
            package.validate_template(duplicate)
        injected = self.personal+struct.pack('!8sIIII64s', package.COOKIE, 88, 0, 0, 313, b'python313.dll')
        with self.assertRaises(package.PackageError):
            package.extract(injected)

    def test_unknown_or_duplicate_overlay_fields_are_refused(self):
        begin = len(self.original)+len(package.BEGIN)
        finish = self.personal.index(package.END, begin)
        body = self.personal[begin:finish]
        for mutated in (body[:-1]+b',"extra":0}', body[:-1]+b',"template_size":0}'):
            raw = self.original+package.BEGIN+mutated+package.END+('%016x'%len(mutated)).encode()+b'\n'
            raw += b'\0'*(-len(raw)%8)
            with self.assertRaises(package.PackageError):
                package.extract(raw)


class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.pem = cls.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.key_id = hashlib.sha256(cls.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = template(); self.digest = hashlib.sha256(self.binary).hexdigest()
        (self.root/'template.exe').write_bytes(self.binary); (self.root/'public.pem').write_bytes(self.pem)
        self.job = {'schema':'wifx-portable-artifact-job-v2','job_id':str(uuid.uuid4()),'package_nonce':'a'*64,
                    'template_id':'lab-test','template_sha256':self.digest,'mode':'lab'}
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp = lambda delta: (now+datetime.timedelta(days=delta)).isoformat()
        provision = {'schema':'wifx-voiceprobe-portable-provisioning-v2','invitation_id':str(uuid.uuid4()),
                     'invitation_secret':'X'*43,'controller_url':'https://localhost:19494','name':'LAB',
                     'organization':'LAB','site':'LAB','expires_at':stamp(1),'invitation_expires_at':stamp(1),
                     'agent_version':'0.9-004','mode':'persistent','instance_id':str(uuid.uuid4()),
                     'support_reference':'WSUP-1','client_name':'LAB','starts_at':stamp(-1),
                     'operational_expires_at':stamp(7),'expected_agent_id':None,'expected_fingerprint':None,
                     'artifact_template_sha256':self.digest,'package_nonce':self.job['package_nonce']}
        raw = package.canonical(provision)
        self.job['provisioning'] = {'key_id':self.key_id,'payload':base64.b64encode(raw).decode(),
            'signature':base64.b64encode(self.key.sign(raw,padding.PKCS1v15(),hashes.SHA256())).decode()}
        self.catalog = {'schema':'wifx-portable-template-catalog-v2','templates':{'lab-test':{
            'path':str(self.root/'template.exe'),'sha256':self.digest,'agent_version':'0.9-004','qualification':'lab',
            'provisioning_public_key_path':str(self.root/'public.pem'),'provisioning_key_sha256':self.key_id}}}

    def run_worker(self):
        for name, obj in [('job.json',self.job),('catalog.json',self.catalog)]:
            (self.root/name).write_bytes(package.canonical(obj))
        return worker.prepare(self.root/'job.json',self.root/'catalog.json',self.root/'output')

    def test_signed_job_creates_only_single_executable_and_safe_receipt(self):
        result=self.run_worker()
        self.assertEqual(result['status'],'VERIFIED_ARTIFACT')
        self.assertEqual({f.name for f in (self.root/'output').iterdir()},{'WIFX-VoiceProbe.exe','result.json'})
        self.assertNotIn('X'*43,json.dumps(result))
        self.assertEqual(result['artifact_sha256'],hashlib.sha256((self.root/'output/WIFX-VoiceProbe.exe').read_bytes()).hexdigest())
        with self.assertRaises(worker.WorkerError): self.run_worker()

    def test_production_unsigned_refused_before_output(self):
        self.job['mode']='production'
        with self.assertRaisesRegex(worker.WorkerError,'SIGNING_NOT_CONFIGURED'):self.run_worker()
        self.assertFalse((self.root/'output').exists())

    def test_nonce_template_and_signature_tampering_refused(self):
        self.job['package_nonce']='b'*64
        with self.assertRaises(worker.PortableError):self.run_worker()
        self.job['package_nonce']='a'*64
        self.job['provisioning']['signature']='eA=='
        with self.assertRaises(worker.PortableError):self.run_worker()
        self.assertFalse((self.root/'output').exists())

    def test_user_commands_and_paths_cannot_be_job_fields(self):
        self.job['command']='not-executed'
        with self.assertRaisesRegex(worker.WorkerError,'INVALID_JOB'):self.run_worker()
        self.assertFalse((self.root/'output').exists())

    def test_template_bytes_must_match_catalog(self):
        raw=bytearray(self.binary);raw[400]^=1;(self.root/'template.exe').write_bytes(raw)
        with self.assertRaisesRegex(worker.WorkerError,'TEMPLATE_DIGEST_MISMATCH'):self.run_worker()
        self.assertFalse((self.root/'output').exists())

    def test_catalog_cannot_inject_another_public_root_without_matching_signature(self):
        other = rsa.generate_private_key(public_exponent=65537,key_size=3072)
        (self.root/'public.pem').write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(worker.PortableError):self.run_worker()
        self.assertFalse((self.root/'output').exists())

    def test_modified_signed_document_cannot_be_accepted(self):
        raw=json.loads(base64.b64decode(self.job['provisioning']['payload']))
        raw['controller_url']='https://untrusted.invalid'
        self.job['provisioning']['payload']=base64.b64encode(package.canonical(raw)).decode()
        with self.assertRaises(worker.PortableError):self.run_worker()
        self.assertFalse((self.root/'output').exists())

    def test_entry_uses_the_same_signed_template_binding_for_cleanup(self):
        self.run_worker()
        (self.root/'provisioning-public.pem').write_bytes(self.pem)
        spec=importlib.util.spec_from_file_location('entry_binding',WINDOWS/'portable-entry.py')
        entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
        # This fixture deliberately represents a signed legacy 0.9-004 package.
        policy={'qualification':'lab','provisioning_key_sha256':self.key_id}
        with patch('version.VERSION','0.9-004'):
            provision=entry.load_integrated_provision(self.root,self.root/'output/WIFX-VoiceProbe.exe',policy)
        self.assertEqual(provision['artifact_template_sha256'],self.digest)
        self.assertEqual(provision['mode'],'persistent')
        policy['provisioning_key_sha256']='0'*64
        with self.assertRaises(worker.PortableError):
            entry.load_integrated_provision(self.root,self.root/'output/WIFX-VoiceProbe.exe',policy)


if __name__=='__main__':unittest.main()
