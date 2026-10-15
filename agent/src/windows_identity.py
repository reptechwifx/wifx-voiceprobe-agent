"""Per-user Windows CNG identity; no private key export or SIP persistence.

HKCU stores only identity metadata. Software KSP non-exportability is an API
policy, not a guarantee against an administrator/debugger controlling Windows.
"""
import base64
import ctypes
import hashlib
import json
import os
import struct
import threading
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from portable_runtime import EphemeralIdentity, PortableError, https_origin

REGISTRY_ROOT = r'Software\WIFX\VoiceProbe\PortableInstances'
PROVIDER = 'Microsoft Software Key Storage Provider'
PREFIX = 'WIFX.VoiceProbe.Portable.'
_OPEN_INSTANCES = set()
_OPEN_INSTANCES_LOCK = threading.Lock()


def canonical_uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
        return value
    except (ValueError, AttributeError):
        raise PortableError('Identifiant de sonde Windows invalide.') from None


class _CNG:
    def __init__(self):
        if os.name != 'nt':
            raise PortableError('Une identité Windows nécessite Windows x64.')
        from ctypes import wintypes as w
        self.w = w
        self.dll = ctypes.WinDLL('ncrypt', use_last_error=True)
        self.handle = ctypes.c_size_t
        specs = {
            'NCryptOpenStorageProvider': [ctypes.POINTER(self.handle), w.LPCWSTR, w.DWORD],
            'NCryptCreatePersistedKey': [self.handle, ctypes.POINTER(self.handle), w.LPCWSTR, w.LPCWSTR, w.DWORD, w.DWORD],
            'NCryptOpenKey': [self.handle, ctypes.POINTER(self.handle), w.LPCWSTR, w.DWORD, w.DWORD],
            'NCryptSetProperty': [self.handle, w.LPCWSTR, ctypes.c_void_p, w.DWORD, w.DWORD],
            'NCryptGetProperty': [self.handle, w.LPCWSTR, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD],
            'NCryptFinalizeKey': [self.handle, w.DWORD],
            'NCryptExportKey': [self.handle, self.handle, w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD],
            'NCryptSignHash': [self.handle, ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD],
            'NCryptDeleteKey': [self.handle, w.DWORD], 'NCryptFreeObject': [self.handle],
        }
        for name, args in specs.items():
            fn = getattr(self.dll, name); fn.argtypes = args; fn.restype = ctypes.c_long

    @staticmethod
    def check(code):
        if code:
            raise PortableError('Identité Windows indisponible ou incohérente ; aucune nouvelle identité créée.')

    def property(self, key, name):
        result = self.w.DWORD(); length = self.w.DWORD()
        self.check(self.dll.NCryptGetProperty(key, name, ctypes.byref(result), 4, ctypes.byref(length), 0x40))
        if length.value != 4:
            raise PortableError('Propriété de clé Windows invalide.')
        return result.value

    def set_dword(self, key, name, value):
        value = self.w.DWORD(value)
        self.check(self.dll.NCryptSetProperty(key, name, ctypes.byref(value), 4, 0))

    def export_public(self, key):
        length = self.w.DWORD()
        self.check(self.dll.NCryptExportKey(key, 0, 'RSAPUBLICBLOB', None, None, 0, ctypes.byref(length), 0x40))
        blob = ctypes.create_string_buffer(length.value)
        self.check(self.dll.NCryptExportKey(key, 0, 'RSAPUBLICBLOB', None, blob, len(blob), ctypes.byref(length), 0x40))
        raw = blob.raw[:length.value]
        magic, bits, exponent_size, modulus_size, prime1, prime2 = struct.unpack('<6I', raw[:24])
        if magic != 0x31415352 or bits != 3072 or modulus_size != 384 or prime1 or prime2 or len(raw) != 24+exponent_size+modulus_size:
            raise PortableError('Clé publique Windows incompatible.')
        exponent = int.from_bytes(raw[24:24+exponent_size], 'big')
        modulus = int.from_bytes(raw[24+exponent_size:], 'big')
        return rsa.RSAPublicNumbers(exponent, modulus).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class PersistentIdentity(EphemeralIdentity):
    """Only the exact signed instance may open/create/delete its per-user key.

    A named mutex prevents concurrent use of the same instance. Missing or
    inconsistent metadata/key fails closed: there is no automatic replacement.
    close() releases handles but deliberately preserves identity. forget() is
    explicit and verifies the metadata and public fingerprint before deletion.
    """
    def __init__(self, provision, *, allow_create):
        self.instance_id = canonical_uuid(provision['instance_id'])
        self.controller_url = https_origin(provision['controller_url'])
        self.invitation_id = canonical_uuid(provision['invitation_id'])
        self.key_name = PREFIX + self.instance_id
        self._cng = _CNG(); self._provider = self._cng.handle(); self._key = self._cng.handle()
        self._mutex = None
        self._owns_process_slot = False
        self._sign_lock = threading.RLock()
        self.created = False
        try:
            self._lock_instance()
            self._cng.check(self._cng.dll.NCryptOpenStorageProvider(ctypes.byref(self._provider), PROVIDER, 0))
            metadata = self._read_metadata()
            if metadata is None:
                if not allow_create or provision.get('expected_agent_id') or provision.get('expected_fingerprint'):
                    raise PortableError('Identité Windows attendue absente ; réactivation refusée.')
                self.id = str(uuid.uuid4())
                self.created = True
                self._cng.check(self._cng.dll.NCryptCreatePersistedKey(self._provider, ctypes.byref(self._key), 'RSA', self.key_name, 0, 0))
                try:
                    self._cng.set_dword(self._key, 'Length', 3072)
                    self._cng.set_dword(self._key, 'Export Policy', 0)
                    self._cng.set_dword(self._key, 'Key Usage', 2)  # NCRYPT_ALLOW_SIGNING_FLAG
                    self._cng.check(self._cng.dll.NCryptFinalizeKey(self._key, 0x40))
                    self._describe_key()
                    self._write_metadata()
                except BaseException:
                    # Only this freshly-created key is eligible for rollback.
                    if self._key:
                        self._cng.dll.NCryptDeleteKey(self._key, 0); self._key = self._cng.handle()
                    raise
            else:
                if set(metadata) != {'schema', 'instance_id', 'id', 'controller_url', 'key_name', 'fingerprint', 'proof'} or metadata['schema'] != 1 or metadata['instance_id'] != self.instance_id or metadata['controller_url'] != self.controller_url or metadata['key_name'] != self.key_name:
                    raise PortableError('Métadonnées de sonde Windows incohérentes.')
                self.id = canonical_uuid(metadata['id'])
                self._cng.check(self._cng.dll.NCryptOpenKey(self._provider, ctypes.byref(self._key), self.key_name, 0, 0x40))
                self._describe_key()
                if metadata['fingerprint'] != self.fingerprint:
                    raise PortableError('Empreinte de sonde Windows incohérente.')
                self._verify_metadata(metadata)
                self._metadata = metadata
            for field, actual in [('expected_agent_id', self.id), ('expected_fingerprint', self.fingerprint)]:
                if provision.get(field) is not None and provision[field] != actual:
                    raise PortableError('Cette réactivation est destinée à une autre sonde Windows.')
        except BaseException:
            self.close(); raise

    def _lock_instance(self):
        with _OPEN_INSTANCES_LOCK:
            if self.instance_id in _OPEN_INSTANCES:
                raise PortableError('Cette sonde Windows est déjà ouverte.')
            _OPEN_INSTANCES.add(self.instance_id)
            self._owns_process_slot = True
        from ctypes import wintypes as w
        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._kernel.CreateMutexW.argtypes = [ctypes.c_void_p, w.BOOL, w.LPCWSTR]; self._kernel.CreateMutexW.restype = w.HANDLE
        self._kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]; self._kernel.WaitForSingleObject.restype = w.DWORD
        self._kernel.ReleaseMutex.argtypes = [w.HANDLE]; self._kernel.CloseHandle.argtypes = [w.HANDLE]
        handle = self._kernel.CreateMutexW(None, False, 'Local\\' + self.key_name)
        if not handle:
            raise PortableError('Verrou de sonde Windows indisponible.')
        if self._kernel.WaitForSingleObject(handle, 0) not in (0, 0x80):
            self._kernel.CloseHandle(handle)
            raise PortableError('Cette sonde Windows est déjà ouverte.')
        self._mutex = handle

    def _read_metadata(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_ROOT+'\\'+self.instance_id, 0, winreg.KEY_READ) as key:
                value, kind = winreg.QueryValueEx(key, 'Identity')
            if kind != winreg.REG_SZ or len(value) > 4096:
                raise ValueError()
            result = json.loads(value)
            if not isinstance(result, dict): raise ValueError()
            return result
        except FileNotFoundError:
            return None
        except (ValueError, OSError):
            raise PortableError('Métadonnées de sonde Windows illisibles.') from None

    def _write_metadata(self):
        import winreg
        metadata = {'schema': 1, 'instance_id': self.instance_id, 'id': self.id, 'controller_url': self.controller_url, 'key_name': self.key_name, 'fingerprint': self.fingerprint}
        metadata['proof'] = base64.b64encode(self.sign(self._metadata_message(metadata))).decode('ascii')
        self._metadata = metadata
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, REGISTRY_ROOT+'\\'+self.instance_id, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, 'Identity', 0, winreg.REG_SZ, json.dumps(metadata, sort_keys=True))
            winreg.FlushKey(key)

    @staticmethod
    def _metadata_message(metadata):
        value = {key: item for key, item in metadata.items() if key != 'proof'}
        return b'WIFX-VoiceProbe-CNG-Metadata-v1\n' + json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

    def _verify_metadata(self, metadata):
        try:
            public = serialization.load_der_public_key(base64.b64decode(self.public_key, validate=True))
            proof = metadata['proof']
            if not isinstance(proof, str) or len(proof) != 512:
                raise ValueError()
            public.verify(base64.b64decode(proof, validate=True), self._metadata_message(metadata), padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError, TypeError, KeyError):
            raise PortableError('Intégrité des métadonnées de sonde Windows refusée.') from None

    def _describe_key(self):
        if self._cng.property(self._key, 'Export Policy') != 0 or self._cng.property(self._key, 'Length') != 3072 or self._cng.property(self._key, 'Key Usage') != 2:
            raise PortableError('La politique de protection de la clé Windows est refusée.')
        der = self._cng.export_public(self._key)
        self.public_key = base64.b64encode(der).decode('ascii'); self.fingerprint = hashlib.sha256(der).hexdigest()

    def sign(self, message):
        with self._sign_lock:
            if not self._key:
                raise PortableError('La sonde Windows est fermée.')
            class Padding(ctypes.Structure):
                _fields_ = [('pszAlgId', self._cng.w.LPCWSTR)]
            pad = Padding('SHA256'); digest = hashlib.sha256(message).digest(); size = self._cng.w.DWORD()
            self._cng.check(self._cng.dll.NCryptSignHash(self._key, ctypes.byref(pad), digest, len(digest), None, 0, ctypes.byref(size), 0x42))
            if size.value != 384:
                raise PortableError('Signature Windows incompatible.')
            output = ctypes.create_string_buffer(size.value)
            self._cng.check(self._cng.dll.NCryptSignHash(self._key, ctypes.byref(pad), digest, len(digest), output, len(output), ctypes.byref(size), 0x42))
            return output.raw[:size.value]
    

    def forget(self):
        """Delete this exact instance only; no enumeration or wildcard removal."""
        import winreg
        if not self._key or self._read_metadata() != self._metadata:
            raise PortableError('Nettoyage refusé : identité Windows incohérente.')
        if hashlib.sha256(self._cng.export_public(self._key)).hexdigest() != self.fingerprint:
            raise PortableError('Nettoyage refusé : clé Windows incohérente.')
        self._cng.check(self._cng.dll.NCryptDeleteKey(self._key, 0x40)); self._key = self._cng.handle()
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REGISTRY_ROOT+'\\'+self.instance_id)
        self.close()

    def close(self):
        with self._sign_lock:
            for name in ('_key', '_provider'):
                handle = getattr(self, name, None)
                if handle:
                    self._cng.dll.NCryptFreeObject(handle); setattr(self, name, self._cng.handle())
            if self._mutex:
                self._kernel.ReleaseMutex(self._mutex); self._kernel.CloseHandle(self._mutex); self._mutex = None
            if self._owns_process_slot:
                with _OPEN_INSTANCES_LOCK:
                    _OPEN_INSTANCES.discard(self.instance_id)
                self._owns_process_slot = False
