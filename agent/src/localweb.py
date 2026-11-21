"""Local administration UI, authenticated with existing admin credentials."""
import socket
import ipaddress
from credentials import verify_password
import hmac
import hashlib
import html
import json
import pathlib
import secrets
import ssl
import threading
import time
from collections import OrderedDict
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from journal import redact
from telemetry import system_snapshot, network_snapshot

WEB = pathlib.Path(__file__).resolve().parent.parent / 'web'
ADMIN_FIELDS = ('organization', 'owner', 'responsible', 'contact', 'internal_reference', 'description', 'notes', 'site', 'location', 'address', 'postal_code', 'city', 'canton', 'country', 'latitude', 'longitude')
COOKIE = 'voiceprobe_session'


def _secret_values(cfg):
    return tuple(str(v) for k, v in cfg.items() if any(x in k.lower() for x in ('password', 'secret', 'token')) and v)


class Sessions:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = OrderedDict()
        self.failures = OrderedDict()

    def new(self, authenticated=False):
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = {'csrf': secrets.token_urlsafe(32), 'authenticated': authenticated, 'created': now, 'last': now}
            while len(self.sessions) > 1000:
                self.sessions.popitem(last=False)
        return token

    def get(self, token):
        with self.lock:
            s = self.sessions.get(token)
            if s and time.monotonic() - s['last'] < 1800 and time.monotonic() - s['created'] < 28800:
                s['last'] = time.monotonic()
                return dict(s)
            self.sessions.pop(token, None)
        return None

    def delete(self, token):
        with self.lock:
            self.sessions.pop(token, None)

    def clear(self):
        with self.lock:
            self.sessions.clear()

    def retry_after(self, ip):
        now = time.monotonic()
        with self.lock:
            tries = [n for n in self.failures.get(ip, []) if now - n < 300]
            self.failures[ip] = tries
            self.failures.move_to_end(ip)
            while len(self.failures) > 1000:
                self.failures.popitem(last=False)
        return max(1, int(300 - (now - tries[0]))) if len(tries) >= 5 else 0

    def failed(self, ip):
        with self.lock:
            self.failures.setdefault(ip, []).append(time.monotonic())

    def succeeded(self, ip):
        with self.lock:
            self.failures.pop(ip, None)


DEFAULT_MANAGEMENT_NETWORKS = ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                               '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10')


def automatic_bind(cfg):
    return cfg.get('bind', 'auto') in ('auto', '', None)


def management_peer_allowed(cfg, peer):
    networks = cfg.get('management_allowed_networks')
    if networks is None and automatic_bind(cfg):
        networks = DEFAULT_MANAGEMENT_NETWORKS
    if networks is None:
        return True  # Preserve an existing explicit bind's policy.
    address = ipaddress.ip_address(peer.split('%', 1)[0])
    address = getattr(address, 'ipv4_mapped', None) or address
    return any(address in ipaddress.ip_network(net) for net in networks)


class IPv6HTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def build_server(agent, *, bind=None):
    cfg = agent.cfg
    networks = cfg.get('management_allowed_networks')
    if networks is not None:
        if not isinstance(networks, (list, tuple)) or len(networks) > 64:
            raise ValueError('Invalid management ACL')
        for network in networks:
            ipaddress.ip_network(network)  # Fail closed before opening any listener.
    cookie_name = COOKIE + '_' + hashlib.sha256(str(cfg['id']).encode()).hexdigest()[:16]
    use_tls = bool(cfg.get('tls_cert'))
    if not use_tls and not cfg.get('allow_http'):
        raise RuntimeError('HTTP local doit être explicitement autorisé.')
    sessions = Sessions()

    class Handler(BaseHTTPRequestHandler):
        server_version = 'VoiceProbe'
        def log_message(self, *args):
            pass

        def response(self, status, body=b'', content_type='text/html; charset=utf-8', location=None, cookie=None, retry=None):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'same-origin')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
            if use_tls:
                self.send_header('Strict-Transport-Security', 'max-age=31536000')
            if location:
                self.send_header('Location', location)
            if cookie is not None:
                value = cookie_name + '=' + cookie + '; Path=/; HttpOnly; SameSite=Strict' + ('; Secure' if use_tls else '')
                if not cookie:
                    value += '; Max-Age=0'
                self.send_header('Set-Cookie', value)
            if retry:
                self.send_header('Retry-After', str(retry))
            self.end_headers()
            self.wfile.write(body)

        def token(self):
            try:
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                return cookie[cookie_name].value if cookie_name in cookie else ''
            except Exception:
                return ''

        def session(self, required=True):
            token = self.token()
            session = sessions.get(token)
            if required and (not session or not session['authenticated']):
                if self.path.startswith('/api/'):
                    self.response(401, json.dumps({'error': 'Session expirée. Reconnectez-vous.'}), 'application/json')
                else:
                    self.response(303, location='/login')
                return None
            return session

        def page(self, path, replacements):
            body = (WEB / path).read_text()
            for key, value in replacements.items():
                body = body.replace('{{' + key + '}}', html.escape(str(value or ''), quote=True))
            return body

        def login_page(self, error='', status=200, retry=None):
            token = sessions.new()
            self.response(status, self.page('login.html', {'csrf': sessions.get(token)['csrf'], 'error': error}), cookie=token, retry=retry)

        def status_data(self):
            data = agent.snapshot()
            if 'system' not in data:
                data['system'] = system_snapshot(getattr(agent, 'data', None))
            if 'network' not in data:
                data['network'] = network_snapshot(agent.cfg)
            data['local_configuration'] = {k: agent.cfg.get(k, '') for k in ('controller_url', 'management_url', 'name', 'max_calls')}
            data['local_configuration']['administrative'] = agent.cfg.get('administrative', {})
            data['local_configuration']['token_configured'] = bool(agent.cfg.get('token'))
            data['local_configuration']['enrollment_configured'] = bool(agent.cfg.get('enrollment_secret'))
            data.setdefault('administrative', agent.cfg.get('administrative', {}))
            data.setdefault('adoption_state', 'adopted' if agent.cfg.get('token') else 'unconfigured')
            return redact(data, _secret_values(agent.cfg))

        def safe_request(self):
            if not management_peer_allowed(cfg, self.client_address[0]):
                self.response(403, 'Source hors du réseau de gestion autorisé.')
                return False
            if use_tls:
                return True
            if not ipaddress.ip_address(self.client_address[0]).is_private:
                self.response(403, 'Interface HTTP réservée au réseau local de gestion.')
                return False
            try:
                host = urlsplit('http://' + self.headers.get('Host', '')).hostname
                allowed = {socket.gethostname(), socket.getfqdn(), 'localhost', self.connection.getsockname()[0], cfg.get('bind'), urlsplit(cfg.get('management_url') or '').hostname}
                if not host or host not in allowed:
                    self.response(403, 'Adresse de gestion non autorisée.')
                    return False
                origin = self.headers.get('Origin')
                if origin and origin != 'http://' + self.headers.get('Host', ''):
                    self.response(403, 'Origine de formulaire non autorisée.')
                    return False
            except ValueError:
                self.response(400, 'Adresse invalide.')
                return False
            return True

        def do_GET(self):
            if not self.safe_request():
                return
            path = urlsplit(self.path).path
            if path in ('/assets/style.css', '/assets/app.js'):
                file = WEB / path.rsplit('/', 1)[1]
                self.response(200, file.read_bytes(), 'text/css; charset=utf-8' if path.endswith('css') else 'text/javascript; charset=utf-8')
                return
            if path == '/login':
                session = self.session(False)
                if session and session['authenticated']:
                    self.response(303, location='/')
                else:
                    self.login_page()
                return
            session = self.session()
            if not session:
                return
            if path == '/api/status':
                self.response(200, json.dumps(self.status_data(), ensure_ascii=False), 'application/json; charset=utf-8')
            elif path == '/':
                self.response(200, self.page('dashboard.html', {'csrf': session['csrf'], 'notice': parse_qs(urlsplit(self.path).query).get('notice', [''])[0]}))
            else:
                self.response(404, 'Page introuvable.')

        def form(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self.response(400, 'Requête invalide.')
                return None
            if length < 1 or length > 32768:
                self.response(413, 'Formulaire trop volumineux ou vide.')
                return None
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded':
                self.response(415, 'Format de formulaire invalide.')
                return None
            try:
                return {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode(), keep_blank_values=True, max_num_fields=50).items()}
            except (ValueError, UnicodeDecodeError):
                self.response(400, 'Formulaire invalide.')
                return None

        def do_POST(self):
            if not self.safe_request():
                return
            path = urlsplit(self.path).path
            session = self.session(path != '/login')
            if not session:
                if path == '/login':
                    self.login_page('Session de connexion expirée.', 403)
                return
            values = self.form()
            if values is None:
                return
            if not hmac.compare_digest(values.get('csrf', ''), session['csrf']):
                self.response(403, 'Session ou protection CSRF invalide. Rechargez la page.')
                return
            if path == '/login':
                retry = sessions.retry_after(self.client_address[0])
                if retry:
                    self.login_page('Trop de tentatives. Réessayez dans quelques minutes.', 429, retry)
                    return
                valid = hmac.compare_digest(values.get('username', '').encode(), b'admin') & verify_password(values.get('password', ''), agent.cfg)
                if not valid:
                    sessions.failed(self.client_address[0])
                    self.login_page('Identifiants invalides.', 401)
                    return
                sessions.succeeded(self.client_address[0])
                sessions.delete(self.token())
                self.response(303, location='/', cookie=sessions.new(True))
                return
            if path == '/logout':
                sessions.delete(self.token())
                self.response(303, location='/login', cookie='')
                return
            try:
                if path == '/password':
                    if not verify_password(values.get('current_password', ''), agent.cfg):
                        raise ValueError('Mot de passe actuel incorrect.')
                    new = values.get('new_password', '')
                    if len(new) < 16 or len(new) > 200 or new != values.get('confirm_password'):
                        raise ValueError('Le nouveau mot de passe doit contenir 16 à 200 caractères et être confirmé.')
                    agent.update_local({'local_password': new})
                    sessions.clear()
                    self.login_page('Mot de passe modifié. Reconnectez-vous.')
                    return
                if path != '/config':
                    self.response(404, 'Page introuvable.')
                    return
                changes = {}
                for k in ('controller_url', 'management_url', 'controller_ca'):
                    if values.get(k):
                        changes[k] = values[k].strip()
                if 'management_url' in values:
                    changes['management_url'] = values['management_url'].strip()
                if values.get('use_system_ca') == '1':
                    changes['use_system_ca'] = True
                if values.get('max_calls'):
                    maximum = int(values['max_calls'])
                    if not 1 <= maximum <= 128:
                        raise ValueError('Capacité autorisée : 1 à 128 appels.')
                    changes['max_calls'] = maximum
                status = self.status_data()
                centrally_managed = status.get('metadata_authority') == 'controller' or status.get('adoption_state') == 'adopted'
                if not centrally_managed:
                    if values.get('name'):
                        changes['name'] = values['name'].strip()[:100]
                    changes['administrative'] = {k: values.get(k, '')[:2000 if k in ('description', 'notes', 'location', 'contact') else 200] for k in ADMIN_FIELDS}
                if 'controller_url' in changes:
                    url = urlsplit(changes['controller_url'])
                    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
                        raise ValueError('Renseignez une adresse HTTPS du Controller sans identifiants ni paramètres.')
                if changes.get('management_url'):
                    url = urlsplit(changes['management_url'])
                    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
                        raise ValueError('L’adresse de gestion doit utiliser HTTP local ou HTTPS sans identifiants.')
                agent.update_local(changes)
                from urllib.parse import urlencode
                self.response(303, location='/?' + urlencode({'notice': 'Configuration enregistrée. Connexion au Controller en cours.'}) + '#configuration')
            except (ValueError, RuntimeError) as error:
                messages = {'Invalid individual token': 'Le token individuel doit contenir 40 à 200 caractères.', 'Invalid enrollment proof': 'La preuve d’enrôlement doit contenir 40 à 200 caractères.', 'Local password must contain at least 12 characters': 'Le mot de passe local doit contenir au moins 12 caractères.', 'Administrative metadata is managed by Controller after adoption': 'Après adoption, modifiez les informations administratives dans le Controller.'}
                message = messages.get(str(error), str(error)) if isinstance(error, ValueError) else 'Configuration indisponible pendant un appel actif. Réessayez après les appels.'
                self.response(422, self.page('error.html', {'error': redact(message, _secret_values(agent.cfg))}))

    address = bind if bind is not None else ('0.0.0.0' if automatic_bind(cfg) else cfg['bind'])
    server_type = IPv6HTTPServer if ':' in address else ThreadingHTTPServer
    server = server_type((address, cfg.get('port', 18441)), Handler)
    server.daemon_threads = True
    server.sessions = sessions
    server.cookie_name = cookie_name
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.load_cert_chain(cfg['tls_cert'], cfg['tls_key'])
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except Exception:
            server.server_close()
            raise
    return server


def serve(agent):
    build_server(agent).serve_forever()


class LocalWebService:
    """Retry unavailable listeners without stopping media or relaxing a bind/ACL."""
    def __init__(self, agent, retry_s=5):
        self.agent, self.retry_s = agent, retry_s
        self.stop_event = threading.Event()
        self.servers = {}
        self.status = 'starting'

    def run(self):
        try:
            while not self.stop_event.is_set():
                cfg = self.agent.cfg
                addresses = ['0.0.0.0'] if automatic_bind(cfg) else [cfg['bind']]
                if automatic_bind(cfg) and socket.has_ipv6:
                    addresses.append('::')
                for address in addresses:
                    if address in self.servers:
                        continue
                    try:
                        server = build_server(self.agent, bind=address)
                    except (OSError, RuntimeError, ValueError):
                        continue
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    self.servers[address] = (server, thread)
                    thread.start()
                self.status = ('ready' if len(self.servers) == len(addresses) else
                               'partial' if self.servers else 'unavailable')
                self.stop_event.wait(self.retry_s)
        finally:
            for server, thread in self.servers.values():
                server.shutdown()
                server.server_close()
                thread.join(2)
            self.servers.clear()
            self.status = 'stopped'

    def stop(self):
        self.stop_event.set()
