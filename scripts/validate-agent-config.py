#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import uuid
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent/src'))
from identity import verify_identity

try:
    p = Path(sys.argv[1])
    c = json.loads(p.read_text())
    uuid.UUID(c['id'])
    assert not p.stat().st_mode & 0o077
    if c.get('controller_url'):
        u = urlsplit(c['controller_url'])
        assert u.scheme == 'https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment
    if c.get('identity_private_key'):
        verify_identity(c)
    else:
        assert c.get('controller_url') and len(c['token']) >= 40
    assert c.get('local_password_hash', '').startswith('scrypt$') or len(c.get('local_password', '')) >= 12
    assert 1 <= int(c.get('max_calls', 4)) <= 128
    assert 1024 <= int(c.get('port', 18441)) <= 65535
    assert Path(c['ca_file']).is_file()
    if c.get('tls_cert'):
        assert Path(c['tls_cert']).is_file() and Path(c['tls_key']).is_file()
    else:
        assert c.get('allow_http') is True
except (OSError, ValueError, KeyError, AssertionError):
    raise SystemExit('Invalid protected agent configuration (values omitted)')
print('Agent configuration valid (secrets omitted).')
