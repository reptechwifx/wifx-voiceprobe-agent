"""Small in-memory operational journal; secrets never enter the public payload."""
import collections
import datetime
import re
import threading

SECRET = re.compile(r'password|passwd|secret|token|authorization|credential|tls_key|private_key', re.I)


def redact(value, secrets=()):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key = str(key)
            if key in ('token_configured', 'enrollment_configured'):
                result[key] = item if isinstance(item, bool) else '[masqué]'
            else:
                result[key] = '[masqué]' if SECRET.search(key) else redact(item, secrets)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        value = re.sub(r'(https?://|wss?://)[^/@\s]+:[^/@\s]+@', r'\1[masqué]@', value)
        value = re.sub(r'(?i)(bearer\s+)[^\s,;]+', r'\1[masqué]', value)
        value = re.sub(r'(?i)((?:password|passwd|secret|token|authorization)\s*[=:]\s*)[^\s,;]+', r'\1[masqué]', value)
        for secret in secrets:
            if secret:
                value = value.replace(str(secret), '[masqué]')
        return value[:4000]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)[:200]


class EventJournal:
    def __init__(self, limit=300, secrets=()):
        self.events = collections.deque(maxlen=limit)
        self.lock = threading.Lock()
        self.secrets = secrets

    def record(self, kind, message, level='info', **details):
        event = redact({'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'kind': kind, 'message': message, 'level': level if level in ('info', 'warning', 'error') else 'info', 'details': details}, self.secrets)
        with self.lock:
            self.events.append(event)

    def snapshot(self, limit=100):
        with self.lock:
            return list(self.events)[-min(limit, 300):][::-1] if limit > 0 else []
