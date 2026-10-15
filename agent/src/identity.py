"""RSA-3072 identity and single-use, payload-bound HTTPS enrollment proof."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

import requests


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def public_identity(private_key):
    der = subprocess.run(['openssl', 'pkey', '-in', str(private_key), '-pubout', '-outform', 'DER'], check=True, capture_output=True).stdout
    return base64.b64encode(der).decode(), hashlib.sha256(der).hexdigest()


def create_identity(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    key = directory / 'identity.key'
    if not key.exists():
        fd, temporary = tempfile.mkstemp(prefix='.identity-', dir=directory)
        os.close(fd)
        try:
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', temporary], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Never replace a concurrently generated identity.
            os.link(temporary, key)
        finally:
            os.unlink(temporary)
    if key.is_symlink() or key.stat().st_mode & 0o077:
        raise ValueError('La clé privée doit rester un fichier privé 0600.')
    public, fingerprint = public_identity(key)
    return {'identity_private_key': str(key), 'identity_public_key': public, 'identity_fingerprint': fingerprint}


def verify_identity(cfg):
    key = Path(cfg['identity_private_key'])
    if not key.is_file() or key.is_symlink() or key.stat().st_mode & 0o077:
        raise ValueError('Identité privée absente ou permissions non sûres ; aucune régénération automatique.')
    public, fingerprint = public_identity(key)
    if public != cfg['identity_public_key'] or fingerprint != cfg['identity_fingerprint']:
        raise ValueError('Identité cryptographique incohérente.')


def exchange(cfg, payload):
    """No redirect may carry a signature or a final credential to another origin."""
    verify_identity(cfg)
    base = cfg['controller_url'].rstrip('/') + '/api/enrollment/identity/'
    options = {'verify': cfg.get('ca_file') or True, 'timeout': 10, 'allow_redirects': False}
    challenge_response = requests.post(base + 'challenge', json={'id': cfg['id'], 'public_key': cfg['identity_public_key']}, **options)
    challenge_response.raise_for_status()
    if challenge_response.status_code != 200:
        raise requests.RequestException('Controller enrollment endpoint must not redirect')
    challenge = challenge_response.json()
    uuid.UUID(challenge['challenge_id'])
    nonce = challenge['nonce']
    audience = challenge['audience']
    if not isinstance(nonce, str) or len(nonce) != 64 or not isinstance(audience, str) or len(audience) > 300:
        raise ValueError('Défi du Controller invalide.')
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    message = '\n'.join(['WIFX-VoiceProbe-Enrollment-v1', audience, challenge['challenge_id'], nonce, cfg['id'], cfg['identity_fingerprint'], hashlib.sha256(raw).hexdigest()]).encode()
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', cfg['identity_private_key']], input=message, check=True, capture_output=True).stdout
    response = requests.post(base + 'complete', json={'challenge_id': challenge['challenge_id'], 'nonce': nonce, 'payload': base64.b64encode(raw).decode(), 'signature': base64.b64encode(signature).decode()}, **options)
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.RequestException('Controller enrollment endpoint must not redirect')
    result = response.json()
    if result.get('id') != cfg['id'] or result.get('fingerprint') != cfg['identity_fingerprint']:
        raise ValueError('Identité retournée par le Controller incohérente.')
    return result
