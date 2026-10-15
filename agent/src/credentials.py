"""Local password hashing; legacy LAB credentials remain readable until changed."""
import hashlib
import hmac
import secrets
import string


def generate_password():
    alphabet = string.ascii_letters + string.digits
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(24))
        if any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value):
            return value


def hash_password(value):
    if not 16 <= len(value) <= 200:
        raise ValueError('Le mot de passe doit contenir 16 à 200 caractères.')
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return 'scrypt$16384$8$1$' + salt.hex() + '$' + digest.hex()


def verify_password(value, cfg):
    encoded = cfg.get('local_password_hash')
    if encoded:
        try:
            algorithm, n, r, p, salt, digest = encoded.split('$')
            if (algorithm, n, r, p) != ('scrypt', '16384', '8', '1') or len(salt) != 32 or len(digest) != 64:
                return False
            actual = hashlib.scrypt(value.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32)
            return hmac.compare_digest(actual, bytes.fromhex(digest))
        except (ValueError, TypeError):
            return False
    legacy = cfg.get('local_password')
    return bool(legacy) and hmac.compare_digest(value.encode(), str(legacy).encode())
