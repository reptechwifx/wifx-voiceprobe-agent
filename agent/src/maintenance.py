"""Local update lease: gate new SIP work while allowing existing calls to finish."""
import json
import os
from pathlib import Path
import stat
import time


class Maintenance:
    def __init__(self, directory):
        self.request = Path(directory) / '.update-request.json'
        self.nonce = None
        self.paused = False

    def refresh(self):
        try:
            info = self.request.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid not in (0, os.getuid()):
                raise ValueError('Unsafe lease')
            if info.st_size > 4096:
                raise ValueError('Oversized lease')
            value = json.loads(self.request.read_text())
            deadline = value['expires']
            nonce = value['nonce']
            if (not isinstance(nonce, str) or len(nonce) != 64 or
                    type(deadline) not in (int, float) or not time.time() < deadline <= time.time() + 3600):
                raise ValueError('Expired/invalid lease')
            self.nonce, self.paused = nonce, True
        except (OSError, ValueError, KeyError, TypeError):
            self.nonce, self.paused = None, False
        return self.paused

    def status(self):
        return {'protocol': 1, 'paused': self.paused, 'nonce': self.nonce}
