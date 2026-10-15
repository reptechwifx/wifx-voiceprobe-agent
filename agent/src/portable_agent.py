"""Portable orchestration around the shared, unmodified SIP/RTP engines."""
import copy
import datetime
import os
import hashlib
import json
import tempfile
import threading
import time

import certifi
import requests

from main import Agent
from portable_runtime import (EphemeralIdentity, PortableError, PortableLease,
                              protect_temporary_directory, status_view)


class _NoMaintenanceFiles:
    def refresh(self):
        return False

    def status(self):
        return {'protocol': 1, 'paused': False, 'nonce': None}


class PortableAgent(Agent):
    """Must be constructed and run on the same SIP worker thread.

    The GUI runs on the Windows main thread and gets only display_status(). No
    local server, management status file, password or administrative endpoint
    is created. Temporary synthetic/received WAV files are deleted on exit.
    """
    def __init__(self, provision, *, ca_file=None):
        self.provision = copy.deepcopy(provision)
        self.persistent = provision.get('mode') == 'persistent'
        self._admission_secret = None
        if self.persistent:
            from windows_identity import PersistentIdentity
            expires = datetime.datetime.fromisoformat(provision['invitation_expires_at'].replace('Z', '+00:00'))
            self.identity = PersistentIdentity(provision, allow_create=expires.timestamp() > time.time())
        else:
            self.identity = EphemeralIdentity()
        self.lease = PortableLease(recoverable_expiry=self.persistent)
        self._display_lock = threading.Lock()
        self._display = status_view({}, self.lease.snapshot())
        self._temporary = None
        self._closed_session = False
        self.completed_tests = 0
        try:
            self._temporary = tempfile.TemporaryDirectory(prefix='WIFX-VoiceProbe-')
            protect_temporary_directory(self._temporary.name)
            if os.name == 'nt' and (not self.persistent or self.identity.created):
                from portable_memory import ProtectedSecret
                self._admission_secret = ProtectedSecret(self.provision.pop('invitation_secret').encode('ascii'))
            elif self.persistent:
                self.provision.pop('invitation_secret', None)
            self._sessions = []
            self._sessions_lock = threading.Lock()
            self._thread_session = threading.local()
            cfg = {
                'id': self.identity.id, 'name': provision['name'],
                'identity_public_key': self.identity.public_key,
                'identity_fingerprint': self.identity.fingerprint,
                'controller_url': provision['controller_url'],
                'wss_url': 'wss://' + provision['controller_url'].split('://', 1)[1] + '/ws',
                'ca_file': ca_file or certifi.where(), 'token': '',
                'installation_type': 'windows-portable', 'adoption_state': 'pending',
                'administrative': {}, 'max_calls': 4,
                # OS-assigned signaling port avoids 5060 conflicts on clients.
                'sip_port': 0, 'rtp_base_port': 24000,
            }
            super().__init__(config=cfg, data_directory=self._temporary.name)
            self.maintenance = _NoMaintenanceFiles()
            if os.name == 'nt':
                from portable_memory import ProtectedSessionConfig, ProtectedJournal
                self.cfg = ProtectedSessionConfig(self.cfg)
                self.journal = ProtectedJournal(self.journal)
        except BaseException:
            # A native transport failure can happen after libCreate/libInit.
            # Release it before deleting files, without masking the root error.
            endpoint = getattr(self, 'endpoint', None)
            if endpoint is not None:
                try:
                    endpoint.libDestroy()
                except Exception:
                    pass
            self.identity.close()
            getattr(self, 'cfg', {}).clear()
            journal = getattr(self, 'journal', None)
            if journal is not None:
                journal.secrets = ()
            if self._admission_secret is not None:
                self._admission_secret.close()
            if self._temporary is not None:
                self._temporary.cleanup()
            for session in getattr(self, '_sessions', []):
                session.close()
            raise

    def _http_session(self):
        if not hasattr(self._thread_session, 'http'):
            session = requests.Session()
            session.trust_env = False
            self._thread_session.http = session
            with self._sessions_lock:
                self._sessions.append(session)
        return self._thread_session.http

    def database_location(self):
        return ':memory:'

    def persist_config(self):
        # Neither admission tokens nor Controller/SIP credentials touch disk.
        return

    def update_local(self, values):
        raise PortableError('La configuration de cette sonde est administrée par WIFX.')

    def _invitation(self):
        result = {'id': self.provision['invitation_id']}
        if self._admission_secret is not None:
            with self._admission_secret.borrow() as secret:
                result['secret'] = secret.decode('ascii')
        elif 'invitation_secret' in self.provision:
            result['secret'] = self.provision['invitation_secret']
        return result

    def enrollment(self):
        request = self.lease.begin_request()
        payload = {'action': 'present', 'name': self.cfg['name'],
                   'administrative': {}, 'management_url': None,
                   'portable_invitation': self._invitation(),
                   'telemetry': {'version': self.snapshot_version(),
                                 'pjsip_version': self.pjsip_version,
                                 'os': self.os_description(), 'architecture': 'AMD64',
                                 'installation_type': 'windows-portable'}}
        if getattr(self, 'persistent', False):
            payload['instance_id'] = self.provision['instance_id']
        result = self.identity.exchange(self.cfg, payload, session=self._http_session())
        self.lease.apply(result.get('portable', {}), request)
        state = result.get('state')
        if state not in ('pending', 'adopted', 'rejected', 'revoked', 'expired'):
            raise PortableError('État d’adoption WIFX invalide.')
        if not self.running:
            return False
        token = result.get('token')
        if token:
            if state != 'adopted' or not isinstance(token, str) or not 40 <= len(token) <= 200:
                raise PortableError('Autorisation WIFX invalide.')
            self.cfg['token'] = token
            self.cfg['credential_ack_pending'] = True
        self.adoption_state = state
        self.cfg['adoption_state'] = state
        if state == 'adopted':
            self.cfg['metadata_authority'] = 'controller'
        if state in ('rejected', 'revoked', 'expired'):
            self.lease.deny('expired' if state == 'expired' else 'revoked')
        self.journal.secrets = self.safe_secrets() + tuple([self._invitation()['secret']] if 'secret' in self._invitation() else [])
        if state == 'adopted' and self.cfg.get('token') and self.cfg.get('credential_ack_pending'):
            ack = {'action': 'ack', 'token_hash': hashlib.sha256(self.cfg['token'].encode()).hexdigest(),
                   'portable_invitation': self._invitation()}
            if getattr(self, 'persistent', False):
                ack['instance_id'] = self.provision['instance_id']
            self.identity.exchange(self.cfg, ack, session=self._http_session())
            self.cfg.pop('credential_ack_pending', None)
        return state == 'adopted' and bool(self.cfg.get('token'))

    def api(self, method, path, **kwargs):
        if not self.running and path != 'portable/close':
            raise PortableError('La session de diagnostic est fermée.')
        response = self._http_session().request(
            method, self.cfg['controller_url'] + '/api/agent/' + path,
            headers={'Authorization': 'Bearer ' + self.cfg['token'], 'Accept': 'application/json'},
            verify=self.cfg['ca_file'], timeout=5, allow_redirects=False, **kwargs)
        if response.status_code in (401, 403):
            denied_state = 'revoked'
            try:
                body = response.json() if len(response.content) <= 65536 else {}
                if isinstance(body, dict) and body.get('portable_state') in ('pending', 'expired', 'revoked'):
                    denied_state = body['portable_state']
            except (ValueError, TypeError):
                pass
            self.lease.deny(denied_state)
            self.inbox.put(('revoked', None))
            response.raise_for_status()
        if 300 <= response.status_code < 400:
            raise PortableError('Redirection WIFX refusée.')
        return response

    def websocket_connector(self):
        from portable_runtime import websocket_connector
        return websocket_connector()

    def communication(self):
        # Shared communication uses self.api; renew independently of command
        # polling/long report uploads so no request implicitly grants authority.
        def renew():
            while self.running:
                if self.adoption_state == 'adopted' and self.cfg.get('token'):
                    request = self.lease.begin_request()
                    try:
                        response = self.api('GET', 'portable/lease')
                        response.raise_for_status()
                        self.lease.apply(response.json(), request)
                    except (requests.RequestException, ValueError, KeyError, OSError):
                        pass
                for _ in range(20):
                    if not self.running:
                        break
                    time.sleep(.1)
        worker = threading.Thread(target=renew, daemon=True)
        worker.start()
        try:
            super().communication()
        finally:
            worker.join(6)

    def execute(self, command):
        if getattr(self, 'persistent', False):
            snapshot = self.lease.snapshot()
            if (not self.lease.allowed() or not isinstance(command.get('payload'), dict) or
                    command['payload'].get('intervention_id') != snapshot.get('intervention_id')):
                raise PortableError('La commande ne correspond pas à l’intervention WIFX autorisée.')
        return super().execute(command)

    def capacity(self, account):
        # Incoming correlation and outgoing execute both call capacity().
        return self.running and self.lease.allowed() and super().capacity(account)

    def apply_config(self, config):
        if not self.running or not self.lease.allowed() or self.calls:
            return
        # Shared engine comparison uses JSON containing live SIP credentials.
        # Keep only a digest between polls; temporary JSON/PJSIP copies cannot
        # be reliably zeroed by CPython and are not claimed to be encrypted.
        fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode('utf-8')).hexdigest()
        if fingerprint == self.remote_fingerprint:
            return
        super().apply_config(config)
        self.remote_fingerprint = fingerprint

    def revoke_configuration(self):
        # Calls still need their account to finalize media/reporting. Their
        # credentials are discarded only after the SIP loop removes the calls.
        self.prepared.clear()
        for call in list(self.calls.values()):
            call.hangup_safe()
        self.remote = None
        self.remote_fingerprint = None

    def _clear_sensitive_configuration(self):
        self.remote = None
        self.remote_fingerprint = None
        for account in list(self.accounts.values()):
            account.shutdown()
            account.config.clear()
        self.accounts.clear()
        self.prepared.clear()
        self.journal.secrets = ()

    def pending_report(self, run_id, metrics):
        self.completed_tests += 1
        rtp = metrics.get('rtp') or {}
        received = (rtp.get('rx') or {}).get('packets') if isinstance(rtp, dict) else None
        audio = metrics.get('audio') or {}
        if metrics.get('established') and type(received) is int and received == 0:
            self._media_evidence = 'no_rtp'
        elif type(received) is int and received > 0 and isinstance(audio, dict) and isinstance(audio.get('interrupted_s'), (int, float)) and audio['interrupted_s'] > 0:
            self._media_evidence = 'degraded'
        else:
            self._media_evidence = None
        return super().pending_report(run_id, metrics)

    def before_iteration(self):
        current_intervention = self.lease.snapshot().get('intervention_id')
        previous = getattr(self, '_current_intervention', None)
        if previous is not None and previous != current_intervention:
            self.revoke_configuration()
        self._current_intervention = current_intervention
        if not self.lease.allowed():
            for call in list(self.calls.values()):
                call.hangup_safe()
            if not self.calls and self.accounts:
                self._clear_sensitive_configuration()
        if time.monotonic() - getattr(self, '_display_sampled', 0) > .5:
            # Expensive network/system measurements stay off the SIP thread.
            snapshot = {'version': self.snapshot_version(), 'running': self.running,
                        'controller_connected': self.controller_connected,
                        'accounts': [{'registration_code': a.registration_code,
                                      'registration_active': a.registration_active}
                                     for a in list(self.accounts.values())],
                        'active_calls': len(self.calls),
                        'completed_tests': self.completed_tests,
                        'recent_runs': self.recent_runs[:1], 'last_error': self.last_error,
                        'controller_error_category': getattr(self, 'controller_error_category', None),
                        'media_evidence': getattr(self, '_media_evidence', None)}
            lease_view = self.lease.snapshot()
            if lease_view.get('support_reference') is None:
                lease_view['support_reference'] = self.provision.get('support_reference')
            view = status_view(snapshot, lease_view)
            with self._display_lock:
                self._display = view
            self._display_sampled = time.monotonic()

    def snapshot_version(self):
        from version import VERSION
        return VERSION

    def display_status(self):
        with self._display_lock:
            return dict(self._display)

    def run(self):
        try:
            super().run(enable_web=False, install_signals=False, export_management=False)
        finally:
            # Calls and PJSIP are already stopped by the shared engine finally.
            if self.cfg.get('token'):
                try:
                    response = self.api('POST', 'portable/close')
                    response.close()
                except (requests.RequestException, PortableError):
                    pass
            self.lease.deny()
            self.identity.close()
            if self._admission_secret is not None:
                self._admission_secret.close()
            self.cfg.clear()
            self.provision.clear()
            self.remote = None
            self.remote_fingerprint = None
            self.journal.events.clear()
            self.journal.secrets = ()
            for session in self._sessions:
                session.close()
            self._temporary.cleanup()
            self._closed_session = True
