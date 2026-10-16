"""Security policy for the portable Agent; no SIP engine or local HTTP server.

Ephemeral identity and live admission/SIP credentials stay in process memory.
Persistent Windows identity uses non-exportable per-user CNG key storage; public
identity metadata lives in HKCU. CPython/native libraries cannot guarantee
forensic erasure of immutable objects, runtime copies or swap.
"""
import base64
import datetime
import hashlib
import json
import math
import re
import threading
import time
import uuid
from urllib.parse import urlsplit

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SCHEMA = 'wifx-voiceprobe-portable-provisioning-v1'
PERSISTENT_SCHEMA = 'wifx-voiceprobe-portable-provisioning-v2'
MAX_DOCUMENT = 65536


class PortableError(ValueError):
    """A diagnostic safe to show to a client without credentials."""


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise PortableError('Document de préparation ambigu.')
        result[name] = value
    return result


def _json(raw):
    try:
        if len(raw) > MAX_DOCUMENT:
            raise PortableError('Document de préparation trop volumineux.')
        result = json.loads(raw, object_pairs_hook=_object)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (UnicodeError, TypeError, json.JSONDecodeError, ValueError) as exc:
        raise PortableError('Document de préparation invalide.') from None


def _b64(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise PortableError('Encodage cryptographique invalide.') from None


def https_origin(value):
    if not isinstance(value, str) or len(value) > 300:
        raise PortableError('Adresse WIFX invalide.')
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise PortableError('Adresse WIFX invalide.') from None
    if (parts.scheme != 'https' or not parts.hostname or parts.username or
            parts.password or parts.query or parts.fragment or
            parts.path not in ('', '/') or (port is not None and not 1 <= port <= 65535)):
        raise PortableError('Une adresse HTTPS WIFX sans identifiants est requise.')
    return value.rstrip('/')


def verify_provisioning(document, trusted_keys, *, agent_version, now=None, expected_template_sha256=None, expected_package_nonce=None):
    """Verify against keys pinned in the EXE, never keys supplied by the package.

    ``trusted_keys`` maps SPKI SHA-256 fingerprints to public PEM bytes. The
    wall clock check is only an early rejection; the Controller enforces expiry.
    """
    envelope = _json(document)
    if set(envelope) != {'payload', 'signature', 'key_id'}:
        raise PortableError('Signature de préparation absente ou invalide.')
    key_id = envelope['key_id']
    if not isinstance(key_id, str) or key_id not in trusted_keys:
        raise PortableError('Clé de préparation WIFX inconnue.')
    try:
        key = serialization.load_pem_public_key(trusted_keys[key_id])
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
            raise ValueError()
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if hashlib.sha256(der).hexdigest() != key_id:
            raise ValueError()
        raw = _b64(envelope['payload'])
        key.verify(_b64(envelope['signature']), raw, padding.PKCS1v15(), hashes.SHA256())
    except (ValueError, TypeError, InvalidSignature):
        raise PortableError('La signature de préparation WIFX est refusée.') from None
    value = _json(raw)
    expected = {'schema', 'invitation_id', 'invitation_secret', 'controller_url', 'name',
                'organization', 'site', 'expires_at', 'agent_version', 'mode'}
    persistent = value.get('schema') == PERSISTENT_SCHEMA and value.get('mode') == 'persistent'
    if persistent:
        expected |= {'instance_id', 'support_reference', 'client_name', 'starts_at',
                     'operational_expires_at', 'invitation_expires_at', 'expected_agent_id',
                     'expected_fingerprint', 'artifact_template_sha256', 'package_nonce'}
    if set(value) != expected or not (persistent or value['schema'] == SCHEMA and value['mode'] == 'ephemeral'):
        raise PortableError('Format de préparation non pris en charge.')
    try:
        if str(uuid.UUID(value['invitation_id'])) != value['invitation_id']:
            raise ValueError()
        secret = value['invitation_secret']
        if not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', secret):
            raise ValueError()
        expires = datetime.datetime.fromisoformat(value['expires_at'].replace('Z', '+00:00'))
        if expires.tzinfo is None or (not persistent and expires.timestamp() <= (time.time() if now is None else now)):
            raise ValueError()
        if value['agent_version'] != agent_version:
            raise ValueError()
        for field in ('name', 'organization', 'site'):
            if not isinstance(value[field], str) or len(value[field]) > 200:
                raise ValueError()
        if not value['name'].strip():
            raise ValueError()
        if persistent:
            if str(uuid.UUID(value['instance_id'])) != value['instance_id']:
                raise ValueError()
            if not re.fullmatch(r'WSUP-[0-9]{1,7}', value['support_reference']):
                raise ValueError()
            if not isinstance(value['client_name'], str) or not 1 <= len(value['client_name']) <= 200:
                raise ValueError()
            if value['expires_at'] != value['invitation_expires_at']:
                raise ValueError()
            start, end = [datetime.datetime.fromisoformat(value[field].replace('Z', '+00:00'))
                          for field in ('starts_at', 'operational_expires_at')]
            if start.tzinfo is None or end.tzinfo is None or start >= end:
                raise ValueError()
            agent_id, fingerprint = value['expected_agent_id'], value['expected_fingerprint']
            if (agent_id is None) != (fingerprint is None):
                raise ValueError()
            if agent_id is not None and (str(uuid.UUID(agent_id)) != agent_id or not re.fullmatch('[0-9a-f]{64}', fingerprint)):
                raise ValueError()
            if any(not isinstance(value[field], str) or not re.fullmatch('[0-9a-f]{64}', value[field])
                   for field in ('artifact_template_sha256', 'package_nonce')):
                raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise PortableError('Préparation expirée, incompatible ou incomplète.') from None
    if persistent and (expected_template_sha256 is None or value['artifact_template_sha256'] != expected_template_sha256):
        raise PortableError('Le paquet Windows ne correspond pas au programme signé.')
    if persistent and expected_package_nonce is not None and value['package_nonce'] != expected_package_nonce:
        raise PortableError('Le paquet Windows ne correspond pas à sa préparation.')
    value['controller_url'] = https_origin(value['controller_url'])
    return value


class EphemeralIdentity:
    """Existing RSA-3072 enrollment proof with an unexported in-memory key."""
    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.id = str(uuid.uuid4())
        der = self._key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = base64.b64encode(der).decode('ascii')
        self.fingerprint = hashlib.sha256(der).hexdigest()

    def sign(self, message):
        if self._key is None:
            raise PortableError('La session de diagnostic est fermée.')
        return self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def close(self):
        self._key = None

    def exchange(self, cfg, payload, *, session=None):
        base = https_origin(cfg['controller_url']) + '/api/enrollment/identity/'
        transport = session or requests.Session()
        owns_session = session is None
        if owns_session:
            # Do not inherit an HTTP proxy or credentials from the environment.
            transport.trust_env = False
        options = {'verify': cfg.get('ca_file') or True, 'timeout': 10, 'allow_redirects': False}
        try:
            response = transport.post(base + 'challenge', json={'id': self.id, 'public_key': self.public_key}, **options)
            response.raise_for_status()
            if response.status_code != 200 or len(response.content) > MAX_DOCUMENT:
                raise PortableError('Réponse WIFX de préparation refusée.')
            challenge = _json(response.content)
            challenge_id = str(uuid.UUID(challenge['challenge_id']))
            nonce, audience = challenge['nonce'], challenge['audience']
            if (not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{64}', nonce) or
                    not isinstance(audience, str) or audience.rstrip('/') != cfg['controller_url'].rstrip('/')):
                raise PortableError('Défi WIFX invalide.')
            raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            message = '\n'.join(['WIFX-VoiceProbe-Enrollment-v1', audience, challenge_id, nonce,
                                 self.id, self.fingerprint, hashlib.sha256(raw).hexdigest()]).encode('utf-8')
            body = {'challenge_id': challenge_id, 'nonce': nonce, 'payload': base64.b64encode(raw).decode('ascii'),
                    'signature': base64.b64encode(self.sign(message)).decode('ascii')}
            response = transport.post(base + 'complete', json=body, **options)
            response.raise_for_status()
            if response.status_code != 200 or len(response.content) > MAX_DOCUMENT:
                raise PortableError('Réponse WIFX d’adoption refusée.')
            result = _json(response.content)
            if result.get('id') != self.id or result.get('fingerprint') != self.fingerprint:
                raise PortableError('La réponse WIFX ne correspond pas à cette sonde.')
            return result
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, PortableError):
                raise
            raise PortableError('Réponse WIFX d’adoption invalide.') from None
        finally:
            if owns_session:
                transport.close()


class PortableLease:
    """Fail closed: only an authenticated server response grants <=60 seconds.

    A monotonic deadline bounds offline work and a slow/replayed HTTP response
    cannot extend the original request's lease. No local clock grants authority.
    """
    def __init__(self, clock=time.monotonic, *, recoverable_expiry=False):
        self._recoverable_expiry = recoverable_expiry
        self._support_reference = None
        self._intervention_id = None
        self._clock = clock
        self._lock = threading.RLock()
        self._deadline = 0.0
        self._authorization_deadline = None
        self._state = 'pending'
        self._closed = False
        self._request_sequence = 0
        self._applied_sequence = 0

    def begin_request(self):
        with self._lock:
            self._request_sequence += 1
            return self._request_sequence, self._clock()

    def apply(self, value, request):
        sequence, started = request
        with self._lock:
            if self._closed or sequence <= self._applied_sequence:
                return False
            if not isinstance(value, dict):
                self._deadline = 0
                raise PortableError('Autorisation temporaire WIFX invalide.')
            state, seconds = value.get('state'), value.get('lease_seconds')
            if (state not in ('pending', 'authorized', 'expired', 'revoked') or
                    type(seconds) not in (int, float) or not math.isfinite(seconds) or
                    not 0 <= seconds <= 60 or (state != 'authorized' and seconds != 0)):
                self._deadline = 0
                raise PortableError('Autorisation temporaire WIFX invalide.')
            if sequence > self._request_sequence or started > self._clock():
                self._deadline = 0
                raise PortableError('Autorisation temporaire WIFX incohérente.')
            if self._recoverable_expiry:
                try:
                    intervention_id = value['intervention_id']
                    if (str(uuid.UUID(intervention_id)) != intervention_id or
                            not isinstance(value.get('support_reference'), str) or
                            not re.fullmatch(r'WSUP-[0-9]{1,7}', value['support_reference'])):
                        raise ValueError()
                except (KeyError, TypeError, ValueError, AttributeError):
                    self._deadline = 0
                    raise PortableError('Intervention WIFX invalide.') from None
                self._intervention_id = intervention_id
            self._applied_sequence = sequence
            # Display metadata never grants authority or extends the 60s lease.
            self._authorization_deadline = None
            try:
                expires_at, server_time = value['authorization_expires_at'], value['server_time']
                if not all(isinstance(x, str) and len(x) <= 64 for x in (expires_at, server_time)):
                    raise ValueError()
                expires_at = datetime.datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                server_time = datetime.datetime.fromisoformat(server_time.replace('Z', '+00:00'))
                if expires_at.tzinfo is None or server_time.tzinfo is None:
                    raise ValueError()
                duration = (expires_at - server_time).total_seconds()
                if not math.isfinite(duration) or not 0 <= duration <= 31*86400:
                    raise ValueError()
                self._authorization_deadline = started + duration
            except (KeyError, ValueError, TypeError, OverflowError):
                pass
            reference = value.get('support_reference')
            if isinstance(reference, str) and re.fullmatch(r'WSUP-[0-9]{1,7}', reference):
                self._support_reference = reference
            self._state = state
            self._deadline = started + seconds if state == 'authorized' else 0
            if state == 'revoked' or state == 'expired' and not self._recoverable_expiry:
                self._closed = True
            return self.allowed()

    def deny(self, state='revoked'):
        with self._lock:
            if self._closed and state != 'revoked':
                return
            self._state = state
            self._deadline = 0
            self._authorization_deadline = None
            self._closed = state == 'revoked' or not self._recoverable_expiry

    def allowed(self):
        with self._lock:
            return not self._closed and self._state == 'authorized' and self._clock() < self._deadline

    def snapshot(self):
        with self._lock:
            remaining = max(0, math.ceil(self._deadline - self._clock())) if self.allowed() else 0
            state = self._state
            if state == 'authorized' and not remaining:
                state = 'expired'
            authorization_remaining = (max(0, math.ceil(self._authorization_deadline-self._clock()))
                                       if self._authorization_deadline is not None else None)
            return {'state': state, 'remaining_seconds': remaining, 'support_reference': self._support_reference, 'intervention_id': self._intervention_id,
                    'authorization_remaining_seconds': authorization_remaining if self.allowed() else 0}


def status_view(snapshot, lease):
    """Allowlist the client display; never return accounts, URLs or diagnostics."""
    authorized = lease['state'] == 'authorized' and lease['remaining_seconds'] > 0
    accounts = snapshot.get('accounts', [])
    registered = sum(a.get('registration_code') == 200 and a.get('registration_active') is True for a in accounts)
    runs = snapshot.get('recent_runs', [])
    return {
        'version': str(snapshot.get('version', ''))[:64],
        'ticket_reference': lease.get('support_reference') if isinstance(lease.get('support_reference'), str) and re.fullmatch(r'WSUP-[0-9]{1,7}', lease['support_reference']) else '',
        'application': 'ACTIF' if snapshot.get('running', True) else 'ARRÊTÉ',
        'controller': 'CONNECTÉ' if snapshot.get('controller_connected') else 'EN ATTENTE',
        'adoption': {'pending': 'EN ATTENTE WIFX', 'authorized': 'ADOPTÉ PAR WIFX',
                     'expired': 'AUTORISATION EXPIRÉE', 'revoked': 'AUTORISATION RÉVOQUÉE'}.get(lease['state'], 'EN ATTENTE WIFX'),
        'sip': 'OK' if authorized and accounts and registered == len(accounts) else 'EN ATTENTE',
        'active_tests': int(snapshot.get('active_calls', 0)),
        'completed_tests': int(snapshot.get('completed_tests', len(runs))),
        'last_test': 'TERMINÉ' if runs else 'AUCUN',
        'remaining_seconds': int(lease['remaining_seconds']),
        'authorization_remaining_seconds': lease.get('authorization_remaining_seconds') if authorized else 0,
        # Raw Controller/PJSIP exceptions can contain endpoints or credentials.
        'error': portable_diagnostic(snapshot, lease),
        'current_metrics': {k: snapshot.get('current_metrics', {}).get(k) for k in ('jitter_ms', 'loss_percent', 'rms_dbfs', 'audio_gap_s')},
        'session_metrics': {k: snapshot.get('session_metrics', {}).get(k) for k in ('jitter_ms', 'loss_percent', 'rms_dbfs', 'audio_gap_s')},
    }


def protect_temporary_directory(path):
    """Restrict a session directory to its Windows user and SYSTEM before use."""
    import os
    if os.name != 'nt':
        os.chmod(path, 0o700)
        return
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    token = wintypes.HANDLE()
    buffer_size = wintypes.DWORD()
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    sid_string = wintypes.LPWSTR()
    descriptor = ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise OSError()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(buffer_size))
        token_user = ctypes.create_string_buffer(buffer_size.value)
        if not advapi.GetTokenInformation(token, 1, token_user, buffer_size, ctypes.byref(buffer_size)):
            raise OSError()
        sid = ctypes.cast(token_user, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)):
            raise OSError()
        sddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + sid_string.value + ')'
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise OSError()
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise OSError()
    except OSError:
        raise PortableError('Impossible de protéger le dossier temporaire de diagnostic.') from None
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_string:
            kernel.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def websocket_connector():
    """Refuse every HTTP redirect before a bearer can reach another origin."""
    from websockets.exceptions import InvalidHandshake
    from websockets.legacy.client import Connect
    class NoRedirectConnect(Connect):
        def handle_redirect(self, uri):
            raise InvalidHandshake("Redirection WSS refusée.")
    return NoRedirectConnect


def portable_diagnostic(snapshot, lease):
    """Evidence-based client wording; never guesses firewall or produces MOS.

    Deliberately accepts a small category enum, not raw requests/PJSIP text.
    Missing RTP does not prove a firewall, NAT or PBX cause.
    """
    state = lease.get('state')
    if state == 'revoked': return 'Autorisation révoquée par WIFX.'
    if state == 'expired': return 'Autorisation expirée ; renouvellement WIFX nécessaire.'
    category = snapshot.get('controller_error_category')
    if category == 'tls': return 'Certificat de connexion WIFX refusé.'
    if category == 'timeout': return 'Connexion WIFX : délai dépassé.'
    if category == 'network_dns': return 'Connexion WIFX : réseau ou DNS indisponible.'
    if category == 'http': return 'Connexion WIFX refusée ; contacter WIFX.'
    if category == 'enrollment_format_identity': return 'Identité ou préparation WIFX refusée.'
    accounts = snapshot.get('accounts', [])
    codes = [a.get('registration_code', 0) for a in accounts if isinstance(a, dict)]
    if any(isinstance(code, int) and code >= 400 for code in codes):
        return 'Enregistrement téléphonique refusé ; contacter WIFX.'
    if snapshot.get('last_error'): return 'Connexion WIFX indisponible.'
    return ''
