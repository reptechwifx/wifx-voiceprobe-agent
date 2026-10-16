"""Typed local handoff; the unprivileged Agent never starts a shell or a root command."""
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
from identity import atomic_json


class RemoteUpdate:
    def __init__(self, directory):
        self.directory = Path(directory)

    def trusted(self, name):
        try:
            fd = os.open(self.directory / name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 8192:
                    return None
                return json.load(stream)
        except (OSError, ValueError):
            return None

    def capability(self):
        if os.name != 'posix':
            return {'protocol': 1, 'enabled': False}
        value = self.trusted('.remote-update-enabled.json')
        return {'protocol': 1, 'enabled': True, 'backend': value['backend']} if isinstance(value, dict) and value.get('protocol') == 1 and value.get('backend') in ('native', 'docker') else {'protocol': 1, 'enabled': False}

    def request(self, action):
        if not self.capability()['enabled'] or not isinstance(action, dict) or set(action) != {'kind', 'id', 'target_version'}:
            raise ValueError('REMOTE_UPDATE_UNAVAILABLE: Maintenance distante non préparée.')
        if action['kind'] != 'UPDATE_AGENT' or not isinstance(action['target_version'], str) or not re.fullmatch(r'0\.9-\d{3}', action['target_version']):
            raise ValueError('REMOTE_UPDATE_INVALID: Action de maintenance non reconnue.')
        uuid.UUID(action['id'])
        current = self.result()
        if current and current.get('id') == action['id']:
            return
        path = self.directory / '.remote-update-request.json'
        if path.exists():
            if json.loads(path.read_text()).get('id') != action['id']:
                raise ValueError('REMOTE_UPDATE_BUSY: Mise à jour déjà en attente.')
            return
        atomic_json(path, {'kind':'UPDATE_AGENT', 'id':action['id'], 'target_version':action['target_version'], 'created_at':time.time(), 'expires':time.time()+600})

    def result(self):
        value = self.trusted('.remote-update-result.json')
        if not isinstance(value, dict) or value.get('state') not in ('running', 'updater_verified', 'failed'):
            return None
        return {k:value[k] for k in ('id','state','target_version','installed_version','error_code','stage','updated_at') if k in value}
