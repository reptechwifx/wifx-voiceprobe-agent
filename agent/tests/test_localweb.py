import http.client
import http.cookiejar
import urllib.request
import urllib.error
import json
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from localweb import build_server, COOKIE, Sessions
from journal import EventJournal, redact
from telemetry import system_snapshot, network_snapshot


class AgentStub:
    def __init__(self, directory):
        self.cfg = {'id': 'e3a4708e-75a5-433d-965b-4903d5a146bd', 'name': 'Lab Agent', 'local_password': 'existing-local-password', 'token': 'individual-secret-token', 'controller_url': 'https://controller.example', 'bind': '127.0.0.1', 'port': 0, 'allow_http': True, 'max_calls': 3}
        self.data = directory
        self.updates = []
        self.calls = False
        self.adoption_state = 'adopted'
        self.metadata_authority = 'local'
    def snapshot(self):
        return {'id': self.cfg['id'], 'name': self.cfg['name'], 'version': 'Bêta 0.9-001', 'adoption_state': self.adoption_state, 'metadata_authority': self.metadata_authority, 'token_configured': bool(self.cfg.get('token')), 'enrollment_configured': bool(self.cfg.get('enrollment_secret')), 'system': {}, 'network': {}, 'accounts': [{'password': 'sip-secret'}], 'last_error': 'token=individual-secret-token'}
    def update_local(self, values):
        if self.calls:
            raise RuntimeError('Calls active')
        self.updates.append(values)
        self.cfg.update(values)


class LocalWebTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.agent = AgentStub(self.temp.name)
        self.server = build_server(self.agent)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ''
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()
    def request(self, method, path, values=None, cookie=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        headers = {'Cookie': self.cookie} if cookie else {}
        body = None
        if values is not None:
            body = urlencode(values)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        data = response.read().decode()
        if response.getheader('Set-Cookie'):
            self.cookie = response.getheader('Set-Cookie').split(';')[0]
        result = response.status, dict(response.getheaders()), data
        conn.close()
        return result
    def login(self, password='existing-local-password'):
        _, _, body = self.request('GET', '/login')
        csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
        return self.request('POST', '/login', {'csrf': csrf, 'username': 'admin', 'password': password})
    def csrf(self):
        _, _, body = self.request('GET', '/')
        return re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    def test_graphical_login_preserves_password_and_rotates_session(self):
        status, _, body = self.request('GET', '/login')
        self.assertEqual(status, 200)
        self.assertIn('Interface locale de l’agent', body)
        anonymous_cookie = self.cookie
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        self.assertNotEqual(anonymous_cookie, self.cookie)
        self.assertTrue(headers['Set-Cookie'].startswith(self.server.cookie_name + '='))
        self.assertTrue(self.server.cookie_name.startswith(COOKIE + '_'))
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        status, _, body = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn('Appels en cours', body)
        self.assertIn('Diagnostic avancé', body)
        self.assertNotIn('existing-local-password', body)
    def test_unauthenticated_api_basic_rejected(self):
        self.assertEqual(self.request('GET', '/api/status', cookie=False)[0], 401)
        status, headers, _ = self.request('GET', '/', cookie=False)
        self.assertEqual(status, 303)
        self.assertNotIn('WWW-Authenticate', headers)
    def test_login_and_configuration_require_csrf(self):
        self.request('GET', '/login')
        self.assertEqual(self.request('POST', '/login', {'username':'admin','password':'existing-local-password'})[0], 403)
        self.login()
        self.assertEqual(self.request('POST', '/config', {'controller_url':'https://new.example'})[0], 403)
        self.assertFalse(self.agent.updates)
    def test_throttling_repeated_login_errors(self):
        for _ in range(5):
            self.assertEqual(self.login('wrong')[0], 401)
        status, headers, _ = self.login()
        self.assertEqual(status, 429)
        self.assertGreater(int(headers['Retry-After']), 0)
    def test_status_redacts_all_secrets(self):
        self.login()
        status, _, body = self.request('GET', '/api/status')
        self.assertEqual(status, 200)
        self.assertNotIn('sip-secret', body)
        self.assertNotIn('individual-secret-token', body)
        self.assertNotIn('existing-local-password', body)
        self.assertIn('Bêta 0.9-001', body)
        self.assertEqual(json.loads(body)['accounts'][0]['password'], '[masqué]')
    def test_status_keeps_exact_boolean_configuration_flags(self):
        self.login()
        status, _, body = self.request('GET', '/api/status')
        data = json.loads(body)
        self.assertIs(data['token_configured'], True)
        self.assertIs(data['enrollment_configured'], False)
        self.assertIs(data['local_configuration']['token_configured'], True)
        self.assertIs(data['local_configuration']['enrollment_configured'], False)
        self.assertNotIn(self.agent.cfg['token'], body)

    def test_revoked_central_metadata_remains_readonly(self):
        self.agent.adoption_state = 'rejected'
        self.agent.metadata_authority = 'controller'
        self.login()
        status, _, _ = self.request('POST', '/config', {'csrf':self.csrf(),'name':'Changed','organization':'Wrong'})
        self.assertEqual(status,303)
        self.assertEqual(self.agent.cfg['name'],'Lab Agent')
        self.assertNotIn('name',self.agent.updates[-1])
        self.assertNotIn('administrative',self.agent.updates[-1])

    def test_config_preserves_adopted_identity_metadata_and_existing_secrets(self):
        self.login()
        status, _, _ = self.request('POST', '/config', {'csrf':self.csrf(),'controller_url':'https://new.example','id':'different','name':'Renamed','organization':'Wrong','max_calls':'4','token':''})
        self.assertEqual(status, 303)
        self.assertEqual(self.agent.cfg['name'], 'Lab Agent')
        self.assertEqual(self.agent.cfg['token'], 'individual-secret-token')
        self.assertEqual(self.agent.cfg['max_calls'], 4)
        self.assertNotIn('id', self.agent.updates[-1])
        self.assertNotIn('administrative', self.agent.updates[-1])
    def test_pending_agent_can_prepare_metadata_without_changing_uuid(self):
        self.agent.adoption_state = 'pending'
        self.login()
        identity=self.agent.cfg['id']
        status, _, _ = self.request('POST', '/config', {'csrf':self.csrf(),'name':'Probe Client','organization':'Client SA','site':'Lausanne','id':'changed'})
        self.assertEqual(status,303)
        self.assertEqual(self.agent.cfg['id'],identity)
        self.assertEqual(self.agent.cfg['name'],'Probe Client')
        self.assertEqual(self.agent.cfg['administrative']['site'],'Lausanne')

    def test_configuration_rejects_unsafe_url_and_active_calls(self):
        self.login()
        for url in ('http://insecure.example','https://user:pass@example','https://example?token=secret'):
            self.assertEqual(self.request('POST', '/config', {'csrf':self.csrf(),'controller_url':url})[0], 422)
        self.agent.calls = True
        status, _, body = self.request('POST','/config',{'csrf':self.csrf(),'controller_url':'https://new.example'})
        self.assertEqual(status,422)
        self.assertIn('appel actif',body)
        self.assertFalse(self.agent.updates)
    def test_logout_and_password_change_invalidate_sessions(self):
        self.login()
        old_cookie=self.cookie
        self.assertEqual(self.request('POST','/password',{'csrf':self.csrf(),'current_password':'wrong','new_password':'new-long-password','confirm_password':'new-long-password'})[0],422)
        self.assertEqual(self.request('POST','/password',{'csrf':self.csrf(),'current_password':'existing-local-password','new_password':'new-long-password','confirm_password':'new-long-password'})[0],200)
        self.cookie=old_cookie
        self.assertEqual(self.request('GET','/api/status')[0],401)
        self.login('new-long-password')
        self.assertEqual(self.request('POST','/logout',{'csrf':self.csrf()})[0],303)
        self.assertEqual(self.request('GET','/api/status')[0],401)
    def test_tls_cookie_is_secure(self):
        cert=pathlib.Path(self.temp.name)/'cert.pem'; key=pathlib.Path(self.temp.name)/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-days','1'],check=True,capture_output=True)
        self.agent.cfg.update(tls_cert=str(cert),tls_key=str(key))
        server=build_server(self.agent)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            conn=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=ssl._create_unverified_context(),timeout=3)
            conn.request('GET','/login'); response=conn.getresponse(); response.read()
            self.assertIn('; Secure',response.getheader('Set-Cookie'))
            self.assertIn('max-age',response.getheader('Strict-Transport-Security'))
            conn.close()
        finally:
            server.shutdown();server.server_close();thread.join()
    def test_identity_cookie_names_isolate_same_hostname_ports(self):
        other = AgentStub(self.temp.name)
        other.cfg['id'] = '13cf4941-47cd-40cb-a411-9171e1345a2b'
        server = build_server(other)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def url(s, path): return 'http://127.0.0.1:' + str(s.server_port) + path
        def get(s, path):
            with opener.open(url(s, path), timeout=3) as response:
                return response.read().decode()
        def post(s, path, values):
            with opener.open(url(s, path), urlencode(values).encode(), timeout=3) as response:
                return response.read().decode()
        def login(s):
            csrf = re.search(r'name="csrf" value="([^"]+)"', get(s, '/login')).group(1)
            post(s, '/login', {'csrf':csrf, 'username':'admin', 'password':'existing-local-password'})
        try:
            self.assertNotEqual(self.server.cookie_name, server.cookie_name)
            login(self.server)
            login(server)
            self.assertEqual(json.loads(get(self.server, '/api/status'))['id'], self.agent.cfg['id'])
            self.assertEqual(json.loads(get(server, '/api/status'))['id'], other.cfg['id'])
            csrf = re.search(r'name="csrf" value="([^"]+)"', get(self.server, '/')).group(1)
            post(self.server, '/logout', {'csrf':csrf})
            with self.assertRaises(urllib.error.HTTPError) as error:
                get(self.server, '/api/status')
            self.assertEqual(error.exception.code,401)
            self.assertEqual(json.loads(get(server, '/api/status'))['id'],other.cfg['id'])
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_lan_http_requires_explicit_opt_in(self):
        self.agent.cfg['bind']='0.0.0.0'
        self.agent.cfg['allow_http']=False
        with self.assertRaises(RuntimeError): build_server(self.agent)
        self.agent.cfg['allow_http']=True
        server=build_server(self.agent)
        try:
            self.assertEqual(server.server_address[0], '0.0.0.0')
        finally:
            server.server_close()

    def test_http_rejects_untrusted_host_and_cross_origin(self):
        for headers in [{'Host':'untrusted.example'}, {'Origin':'http://untrusted.example'}]:
            conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
            conn.request('GET','/login',headers=headers)
            response=conn.getresponse();response.read()
            self.assertEqual(response.status,403)
            conn.close()

    def test_configuration_has_no_manual_enrollment_secrets(self):
        self.agent.adoption_state='unconfigured'
        self.login()
        status,_,body=self.request('GET','/')
        self.assertEqual(status,200)
        self.assertIn('Enregistrer et connecter',body)
        self.assertIn('18441',body)
        self.assertNotIn('name="token"',body)
        self.assertNotIn('name="enrollment_secret"',body)


class DiagnosticsTest(unittest.TestCase):
    def test_journal_bounds_redaction_and_chronology(self):
        journal=EventJournal(limit=2,secrets=('custom-sensitive-value',))
        journal.record('start','Started')
        journal.record('sip','password=hidden',password='hidden')
        journal.record('controller','custom-sensitive-value',level='error')
        events=journal.snapshot()
        self.assertEqual(len(events),2)
        self.assertEqual(events[0]['kind'],'controller')
        self.assertNotIn('custom-sensitive-value',json.dumps(events))
        self.assertNotIn('hidden',json.dumps(events))
        self.assertEqual(journal.snapshot(0),[])
    def test_only_exact_bool_flags_bypass_secret_key_redaction(self):
        data = redact({'token_configured':True,'enrollment_configured':False,'token':'secret','token_enabled':False,'enrollment_secret':False,'nested':{'token_configured':'secret','enrollment_configured':1}})
        self.assertIs(data['token_configured'],True)
        self.assertIs(data['enrollment_configured'],False)
        for key in ('token','token_enabled','enrollment_secret'):
            self.assertEqual(data[key],'[masqué]')
        self.assertEqual(data['nested']['token_configured'],'[masqué]')
        self.assertEqual(data['nested']['enrollment_configured'],'[masqué]')

    def test_redacts_nested_bearer_and_url_credentials(self):
        value=redact({'headers':{'Authorization':'Bearer ABC'},'message':'https://user:pass@host and Bearer ABC'})
        self.assertNotIn('ABC',str(value));self.assertNotIn('user:pass',str(value))
    def test_session_idle_and_absolute_expiration(self):
        sessions=Sessions()
        with patch('localweb.time.monotonic', return_value=0):
            idle=sessions.new(True)
            absolute=sessions.new(True)
        with patch('localweb.time.monotonic', return_value=1801):
            self.assertIsNone(sessions.get(idle))
        sessions.sessions[absolute]['last']=28000
        with patch('localweb.time.monotonic', return_value=28801):
            self.assertIsNone(sessions.get(absolute))

    def test_real_measurements_are_json_safe_and_scoped(self):
        data=system_snapshot(self.temp_dir())
        json.dumps(data)
        self.assertIn(data['scope'],('host','container'))
        self.assertGreater(data['disk']['total_bytes'],0)
        self.assertGreater(data['cpu']['available_cores'],0)
        network=network_snapshot({'controller_url':'https://local.example'})
        self.assertTrue(network['hostname'])
        self.assertIsNone(network['public_ip'])
        json.dumps(network)
    @staticmethod
    def temp_dir(): return tempfile.gettempdir()
    def test_container_cgroup_quota_and_memory_distinguished(self):
        values={'/proc/meminfo':'MemTotal: 8000000 kB\nMemAvailable: 4000000 kB','/proc/stat':'cpu 10 0 10 80 0 0 0 0','/sys/fs/cgroup/cpu.max':'50000 100000','/sys/fs/cgroup/cpuset.cpus.effective':'0-3','/sys/fs/cgroup/memory.max':'104857600','/sys/fs/cgroup/memory.current':'52428800','/sys/fs/cgroup/cpu.stat':'usage_usec 1000000','/proc/uptime':'30.0 1.0'}
        with patch('telemetry._read',side_effect=lambda p: values.get(str(p))),patch('telemetry.pathlib.Path.exists',return_value=True):
            data=system_snapshot()
        self.assertEqual(data['cpu']['available_cores'],0.5)
        self.assertEqual(data['memory']['total_bytes'],104857600)
        self.assertEqual(data['memory']['percent'],50)
        self.assertEqual(data['host']['memory']['total_bytes'],8192000000)

if __name__=='__main__':unittest.main()
