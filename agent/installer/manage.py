#!/usr/bin/env python3
"""Gestionnaire Agent autonome : HTTPS signé, releases, sauvegardes et reprise."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

INSTALLER_VERSION = '1.0.0'
MAX_ARTIFACT = 1024 * 1024 * 1024
MIN_FREE = 512 * 1024 * 1024

LEGACY_OBSERVER = '#!/usr/bin/env python3\n"""Read-only status adapter for a hash-qualified legacy Agent; SIP engine unchanged."""\nimport hashlib\nimport importlib.util\nimport os\nfrom pathlib import Path\nimport sys\nimport threading\nimport time\n\nsource=Path(sys.argv[1]).resolve()\nallowed=ALLOWED_HASHES\nif hashlib.sha256(source.read_bytes()).hexdigest() not in allowed:\n    raise SystemExit(\'Version historique non qualifiée ; démarrage refusé sans modifier les données.\')\nsys.path.insert(0,str(source.parent))\nspec=importlib.util.spec_from_file_location(\'qualified_legacy_agent\',source)\nmodule=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\noriginal_registration=module.ProbeAccount.onRegState\n\ndef observed_registration(account,parameter):\n    original_registration(account,parameter)\n    try:account._management_registration_active=bool(account.getInfo().regIsActive) and parameter.code==200\n    except module.pj.Error:account._management_registration_active=False\n\nmodule.ProbeAccount.onRegState=observed_registration\nagent=module.Agent()\n\ndef export():\n    while agent.running:\n        try:\n            status=agent.snapshot()\n            accounts={a.config[\'id\']:a for a in list(agent.accounts.values())}\n            for row in status.get(\'accounts\',[]):\n                row[\'registration_active\']=getattr(accounts.get(row[\'id\']),\'_management_registration_active\',False)\n            status.update({\'pid\':os.getpid(),\'sampled_at\':time.time(),\'prepared_calls\':len(agent.prepared),\'maintenance\':{\'protocol\':0,\'paused\':False,\'nonce\':None}})\n            module.atomic_json(agent.data/\'.management-status.json\',status)\n        except (OSError,ValueError):pass\n        time.sleep(1)\n\nthreading.Thread(target=export,daemon=True).start()\nagent.run()\n'
FREEZE_WATCHDOG = "import os,sys,time,signal\nfrom pathlib import Path\npid,expected,manager,owner_expected=sys.argv[1:]\ndef marker(pid):\n    try:return Path('/proc/'+pid+'/stat').read_text().rsplit(') ',1)[1].split()[19]\n    except (OSError,IndexError):return None\nwhile marker(pid)==expected:\n    if marker(manager)!=owner_expected:\n        try:os.kill(int(pid),signal.SIGCONT)\n        except ProcessLookupError:pass\n        break\n    time.sleep(.2)\n"

class Failure(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Failure(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def command(args, *, data=None, timeout=180, message='Commande locale refusée.'):
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(message) from None
    need(result.returncode == 0, message)
    return result.stdout


def safe_directory(path, create=False):
    path = Path(path)
    need(path.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)) and '..' not in path.parts,
         'Chemin absolu simple requis ; traversée de chemin refusée.')
    for parent in [*reversed(path.parents), path]:
        need(not parent.is_symlink(), 'Chemin symbolique refusé.')
    if create: path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def private_json(path):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size < 4 * 1024 * 1024,
         'Fichier privé absent, trop volumineux ou permissions non sûres.')
    return json.loads(path.read_text())


def https_url(value):
    parsed = urllib.parse.urlsplit(value)
    need(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
         and not parsed.query and not parsed.fragment and not any(c.isspace() for c in value),
         'URL HTTPS sans identifiants, paramètres ni fragment requise.')
    return value.rstrip('/')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise Failure('Redirection de distribution refusée ; utiliser son adresse HTTPS canonique.')


GITHUB_AGENT = 'reptechwifx/wifx-voiceprobe-agent'


def github_channel(value):
    return value in ('https://raw.githubusercontent.com/'+GITHUB_AGENT+'/main/channel/beta',
                     'https://raw.githubusercontent.com/'+GITHUB_AGENT+'/main/channel/stable')


def github_release(value):
    return bool(re.fullmatch(r'https://github\.com/'+GITHUB_AGENT+r'/releases/download/agent-[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value))


class GithubAssetRedirect(urllib.request.HTTPRedirectHandler):
    """No auth headers; only the official repository's asset CDN redirects."""
    max_redirections = 3
    max_repeats = 2

    def __init__(self, release_base):
        need(github_release(release_base), 'Source GitHub Release non autorisée.')
        self.release_base = release_base

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        target = urllib.parse.urlsplit(newurl)
        origins = ('release-assets.githubusercontent.com', 'objects.githubusercontent.com')
        allowed_start = (req.full_url.startswith(self.release_base+'/') and old.hostname == 'github.com'
                         and not old.query)
        allowed_cdn = old.hostname in origins and old.path.startswith('/github-production-release-asset')
        need((allowed_start or allowed_cdn) and code in (301,302,303,307,308)
             and target.scheme == 'https' and target.hostname in origins and target.port in (None,443)
             and not target.username and not target.password and not target.fragment
             and target.path.startswith('/github-production-release-asset')
             and not any(c.isspace() or c == '\\' for c in newurl),
             'Redirection GitHub hors périmètre refusée ; aucun artefact exécuté.')
        need(not any(k.lower() in ('authorization','cookie','proxy-authorization') for k,v in req.header_items()),
             'Authentification interdite pour les téléchargements publics.')
        return urllib.request.Request(newurl, headers={'Accept':'application/octet-stream'})


class Source:
    def __init__(self, base, public_key, ca=None):
        self.base = https_url(base)
        self.artifact_base = None
        self.artifact_opener = None
        self.key = Path(public_key)
        need(self.key.is_file() and not self.key.is_symlink(), 'Clé publique de distribution absente.')
        context = ssl.create_default_context()
        if ca: context.load_verify_locations(cafile=ca)
        self.context = context
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def download(self, name, destination, *, expected=None, size=None, maximum=MAX_ARTIFACT):
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', name), 'Nom d’artefact de distribution invalide.')
        if size is not None: need(type(size) is int and 0 < size <= maximum, 'Taille d’artefact non autorisée.')
        if expected is not None: need(re.fullmatch('[a-f0-9]{64}', expected), 'Empreinte d’artefact invalide.')
        destination = Path(destination)
        if expected and destination.is_file() and not destination.is_symlink() and digest(destination) == expected:
            return destination
        temporary = destination.with_name(destination.name + '.part-' + secrets.token_hex(6))
        try:
            h = hashlib.sha256(); total = 0
            catalog = name in ('release.json','release.sig')
            base = self.base if catalog or self.artifact_base is None else self.artifact_base
            opener = self.opener if catalog or self.artifact_opener is None else self.artifact_opener
            with opener.open(base + '/' + name, timeout=30) as response, temporary.open('xb') as stream:
                need(response.status == 200, 'Téléchargement HTTPS refusé.')
                while data := response.read(1024 * 1024):
                    total += len(data)
                    need(total <= (size if size is not None else maximum), 'Téléchargement trop volumineux.')
                    stream.write(data); h.update(data)
                stream.flush(); os.fsync(stream.fileno())
            need(size is None or total == size, 'Téléchargement incomplet ; aucune bascule effectuée.')
            need(expected is None or h.hexdigest() == expected, 'SHA-256 incorrect ; aucune bascule effectuée.')
            os.chmod(temporary, 0o600); os.replace(temporary, destination)
            return destination
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError, http.client.IncompleteRead):
            raise Failure('Distribution inaccessible, certificat TLS refusé ou téléchargement interrompu.') from None
        finally:
            temporary.unlink(missing_ok=True)

    def manifest(self, directory, minimum=0):
        path = self.download('release.json', Path(directory)/'release.json', maximum=256*1024)
        signature = self.download('release.sig', Path(directory)/'release.sig', maximum=4096)
        command(['openssl','dgst','-sha256','-verify',str(self.key),'-signature',str(signature),str(path)],
                message='Signature de manifeste invalide ; aucun artefact exécuté.')
        value = json.loads(path.read_text())
        need(type(value.get('schema')) is int and value['schema'] == 1 and type(value.get('installer_protocol')) is int and value['installer_protocol'] == 1, 'Contrat de distribution incompatible.')
        need(type(value.get('sequence')) is int and value['sequence'] >= minimum, 'Manifeste plus ancien que celui déjà accepté ; replay refusé.')
        need(type(value.get('expires')) is int and time.time() < value['expires'] <= time.time()+370*86400,
             'Manifeste expiré ou horloge système incorrecte.')
        need(re.fullmatch(r'\d+\.\d+-\d{3}', value.get('version','')) and
             value.get('release_id') == value.get('version','')+'-'+value.get('source_revision','')[:12] and
             re.fullmatch('[a-f0-9]{40}',value.get('source_revision','')), 'Version/révision de distribution invalide.')
        need(type(value.get('data_schema')) is int and value['data_schema'] == 1 and value.get('rollback_compatible') is True,
             'Migration locale non qualifiée ou rollback incompatible ; mise à jour refusée.')
        need(isinstance(value.get('compatible_from'),list) and all(isinstance(v,str) and re.fullmatch(r'\d+\.\d+-\d{3}',v) for v in value['compatible_from']), 'Transitions de version non qualifiées.')
        if value.get('artifact_source') is not None:
            need(github_channel(self.base) and github_release(value['artifact_source']), 'Canal ou artefacts GitHub hors périmètre ; distribution refusée.')
            self.artifact_base = value['artifact_source']
            self.artifact_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), GithubAssetRedirect(self.artifact_base), urllib.request.HTTPSHandler(context=self.context))
        return value


def same_release(left,right):
    # Catalog renewal may extend validity/increase sequence; artifacts stay immutable.
    return {k:v for k,v in left.items() if k not in ('expires','sequence')} == {k:v for k,v in right.items() if k not in ('expires','sequence')}


def extract(archive, directory, maximum):
    directory = Path(directory)
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        need(len(members) < 4096 and sum(m.size for m in members) <= maximum, 'Archive trop volumineuse.')
        names = set()
        for member in members:
            path = Path(member.name)
            need(member.name not in names and not path.is_absolute() and '..' not in path.parts
                 and (member.isfile() or member.isdir()), 'Archive contenant lien, chemin interdit ou doublon.')
            names.add(member.name)
        source.extractall(directory, **({'filter':'data'} if hasattr(tarfile,'data_filter') else {}))


def lan_address():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
            route.connect(('192.0.2.1',9)); address = route.getsockname()[0]
        ip = ipaddress.ip_address(address)
        if any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
            return address
    except OSError: pass
    return '127.0.0.1'


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


class Engine:
    def call(self, method, path, value=None, file=None):
        connection = UnixHTTP('localhost', timeout=600)
        headers = {}
        data = None
        if value is not None: data=json.dumps(value).encode();headers['Content-Type']='application/json'
        if file:
            headers.update({'Content-Type':'application/x-tar','Content-Length':str(Path(file).stat().st_size)})
            data = Path(file).open('rb')
        try:
            connection.request(method, '/v1.41'+path, body=data, headers=headers)
            response = connection.getresponse(); body=response.read(8*1024*1024+1)
            need(len(body)<=8*1024*1024, 'Réponse Docker trop volumineuse.')
            if response.status==404: return None
            need(200<=response.status<300, 'API Docker refusée (HTTP '+str(response.status)+') ; vérifier droits/capacités locales.')
            if not body: return {}
            if path.startswith('/images/load'):
                for line in body.splitlines():
                    event=json.loads(line);need(not event.get('error') and not event.get('errorDetail'),'Chargement de l’image Docker refusé.')
                return {}
            return json.loads(body)
        except (OSError,http.client.HTTPException):
            raise Failure('Docker local indisponible ou opération interrompue.') from None
        finally:
            if file and data: data.close()
            connection.close()


class Native:
    def __init__(self, manager):
        self.m=manager;self.unit='voiceprobe-agent'+('' if manager.args.instance=='default' else '-'+manager.args.instance)+'.service'
        self.unit_path=Path('/etc/systemd/system')/self.unit

    def status(self):
        r=subprocess.run(['systemctl','is-active','--quiet',self.unit],capture_output=True)
        return r.returncode==0

    def pid(self):
        return int(command(['systemctl','show','--property=MainPID','--value',self.unit]).strip() or 0)

    def freeze(self):
        pid=self.pid();need(pid>1,'PID Agent invalide.')
        cmd=Path('/proc/'+str(pid)+'/cmdline').read_bytes()
        need(b'agent/src/main.py' in cmd,'Le service cible ne correspond pas à l’Agent attendu.')
        marker=lambda p:Path('/proc/'+str(p)+'/stat').read_text().rsplit(') ',1)[1].split()[19]
        subprocess.Popen([sys.executable,'-c',FREEZE_WATCHDOG,str(pid),marker(pid),str(os.getpid()),marker(os.getpid())],
                         stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
        self.frozen_marker=(pid,marker(pid))
        os.kill(pid,signal.SIGSTOP);return pid

    def thaw(self, pid):
        try: actual=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(') ',1)[1].split()[19]
        except (OSError,IndexError):return
        expected=getattr(self,'frozen_marker',None)
        need(expected==(pid,actual),'PID historique différent ; reprise automatique refusée.')
        os.kill(pid,signal.SIGCONT)

    def stop(self):
        command(['systemctl','stop',self.unit],timeout=60,message='Arrêt contrôlé du seul Agent refusé.')

    def start(self, release):
        current=self.m.code/'current'; temporary=self.m.code/'current.new';temporary.unlink(missing_ok=True)
        temporary.symlink_to(release);os.replace(temporary,current)
        text='''[Unit]\nDescription=WIFX Voice Probe Agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser=voiceprobe\nGroup=voiceprobe\nWorkingDirectory=CODE/current\nEnvironment=PYTHONUNBUFFERED=1\nEnvironment=CONFIG_FILE=DATA/config.json\nExecStart=CODE/current/venv/bin/python CODE/current/agent/src/main.py\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=20\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths=DATA\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n'''.replace('CODE',str(self.m.code)).replace('DATA',str(self.m.data))
        self.unit_path.write_text(text);self.unit_path.chmod(0o644)
        command(['systemctl','daemon-reload']);command(['systemctl','enable',self.unit]);command(['systemctl','start',self.unit])

    def restore(self, previous):
        self.stop()
        target=self.m.code/'current.new';target.unlink(missing_ok=True);target.symlink_to(previous['release']);os.replace(target,self.m.code/'current')
        self.unit_path.write_text(previous['unit']);self.unit_path.chmod(0o644)
        command(['systemctl','daemon-reload'])
        if previous.get('was_running',True):command(['systemctl','start',self.unit])

    def capture(self):
        if not (self.m.code/'current').exists() and not self.unit_path.exists():return None
        need((self.m.code/'current').is_symlink() and self.unit_path.is_file(), 'Installation native existante non reconnue ; aucune réécriture du service.')
        need((self.m.code/'current').resolve().is_relative_to((self.m.code/'releases').resolve()),'Release native hors du répertoire Agent ; aucune modification.')
        return {'release':str((self.m.code/'current').resolve()),'unit':self.unit_path.read_text(),'was_running':self.status()}


class Container:
    def __init__(self, manager):
        self.m=manager;self.engine=Engine();self.name='voiceprobe-agent-'+manager.args.instance

    def inspect(self):
        item=self.engine.call('GET','/containers/'+self.name+'/json')
        if item:
            labels=item['Config'].get('Labels') or {}
            need(labels.get('net.wifx.project')=='voiceprobe-agent' and labels.get('net.wifx.instance')==self.m.args.instance,
                 'Conteneur homonyme appartenant à une installation inconnue ; aucune modification.')
            need(item['HostConfig'].get('NetworkMode')=='host' and not item['HostConfig'].get('Privileged')
                 and not item['HostConfig'].get('CapAdd') and not item['HostConfig'].get('PortBindings'),
                 'Mode réseau/privilèges Docker modifiés hors contrat ; aucune substitution.')
            need(all(v['Type']=='bind' and v['Destination']=='/var/lib/voiceprobe' or v['Type']=='tmpfs' and v['Destination']=='/tmp' for v in item['Mounts']),
                 'Montage Docker supplémentaire non qualifié ; aucune ressource étrangère modifiée.')
            need(any(v['Type']=='bind' and v['Source']==str(self.m.data) and v['Destination']=='/var/lib/voiceprobe' for v in item['Mounts']),
                 'Persistance Docker différente de l’instance ; aucune modification.')
        return item

    def status(self):
        item=self.inspect();return bool(item and item['State']['Running'])

    def freeze(self):
        item=self.inspect();need(item and item['State']['Running'],'Agent Docker inactif.')
        self.engine.call('POST','/containers/'+item['Id']+'/pause');return item['Id']

    def thaw(self, identifier):
        item=self.inspect()
        if item and item['Id']==identifier and item['State'].get('Paused'):
            self.engine.call('POST','/containers/'+identifier+'/unpause')

    def stop(self):
        item=self.inspect()
        if not item or not item['State']['Running']:return
        if item['State'].get('Paused'):
            # Kill a proven idle legacy process while frozen; prevent restart races.
            self.engine.call('POST','/containers/'+item['Id']+'/update',{'RestartPolicy':{'Name':'no'}})
            self.engine.call('POST','/containers/'+item['Id']+'/kill?signal=KILL')
        else:self.engine.call('POST','/containers/'+item['Id']+'/stop?t=20')
        for _ in range(30):
            if not self.status():return
            time.sleep(.2)
        raise Failure('Arrêt du conteneur Agent non confirmé.')

    def start(self, declaration, start=True):
        item=self.inspect()
        prior=declaration if declaration.get('config') else self.capture()
        if item:
            need(not item['State']['Running'],'Conteneur Agent encore actif ; remplacement refusé.')
            self.engine.call('DELETE','/containers/'+item['Id']+'?v=false&force=false')
        config={'Image':declaration['local_image_id'],'User':'1000:1000','Env':['CONFIG_FILE=/var/lib/voiceprobe/config.json'],
                'Labels':{'net.wifx.project':'voiceprobe-agent','net.wifx.instance':self.m.args.instance},
                'HostConfig':{'NetworkMode':'host','RestartPolicy':{'Name':'unless-stopped'},'Init':True,
                  'Binds':[str(self.m.data)+':/var/lib/voiceprobe:rw'],'SecurityOpt':['no-new-privileges:true'],'CapDrop':['ALL'],'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=16777216'},
                  'LogConfig':{'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}}}}
        if prior:
            config.update(prior.get('config',{}))
            config['Image']=declaration['local_image_id']
            config['Labels']={k:v for k,v in config['Labels'].items() if k not in ('org.opencontainers.image.version','org.opencontainers.image.revision')}
            config['HostConfig'].update(prior.get('host',{}))
        else:
            hostname=self.engine.call('GET','/info').get('Name','voiceprobe')
            config['Hostname']=(re.sub('[^A-Za-z0-9-]','-',hostname)+'-'+self.m.args.instance)[:63]
        if 'Healthcheck' not in config:
            check="""import json,os,time,urllib.request,ssl,sys
try:
 p='/var/lib/voiceprobe/';c=json.load(open(p+'config.json'));s=json.load(open(p+'.management-status.json'))
 assert time.time()-s['sampled_at']<15 and s['pjsip_version']=='2.16'
 h=c.get('bind','127.0.0.1');h='127.0.0.1' if h=='0.0.0.0' else h
 u=('https' if c.get('tls_cert') else 'http')+'://'+h+':'+str(c.get('port',18441))+'/login'
 context=ssl.create_default_context(cafile=c['tls_cert']) if c.get('tls_cert') else None
 r=urllib.request.urlopen(u,context=context,timeout=3);assert r.status==200
except Exception:
 print('Agent local/SIP non prêt ; consulter voiceprobe-agent diagnose sans secrets.');sys.exit(1)
"""
            config['Healthcheck']={'Test':['CMD','python3','-c',check],'Interval':15000000000,'Timeout':5000000000,'Retries':4,'StartPeriod':60000000000}
        result=self.engine.call('POST','/containers/create?name='+self.name,config)
        need(result and result.get('Id'),'Création du conteneur Agent refusée.')
        if start:self.engine.call('POST','/containers/'+result['Id']+'/start')

    def capture(self):
        item=self.inspect()
        if not item:return None
        keys=['Env','Cmd','Entrypoint','WorkingDir','User','Labels','Hostname','Healthcheck']
        host_keys=['Memory','MemorySwap','MemoryReservation','NanoCpus','CpuShares','CpuPeriod','CpuQuota','CpusetCpus','PidsLimit','RestartPolicy','LogConfig','ReadonlyRootfs','Init','SecurityOpt','CapDrop','Tmpfs']
        original_image=self.engine.call('GET','/images/'+item['Image']+'/json')
        need(original_image,'Image actuelle absente ; capture de configuration refusée.')
        defaults=set(original_image.get('Config',{}).get('Env') or [])
        item['Config']['Env']=[value for value in item['Config'].get('Env',[]) if value not in defaults]
        return {'local_image_id':item['Image'],'was_running':item['State']['Running'],
                'config':{k:item['Config'][k] for k in keys if k in item['Config']},
                'host':{k:item['HostConfig'][k] for k in host_keys if k in item['HostConfig']}}

    def restore(self, previous):
        self.stop();self.start(previous,start=previous.get('was_running',True))


class Manager:
    def __init__(self,args):
        self.args=args;self.stage='initialisation';self.password=None;self.frozen=None;self.previous=None
        need(os.geteuid()==0,'Exécuter avec sudo ou le compte SSH autorisé root.')
        need(platform.machine() in ('x86_64','amd64'),'Architecture non qualifiée : AMD64 requis ; aucune compilation automatique.')
        need(re.fullmatch('[a-z][a-z0-9-]{0,31}',args.instance),'Nom d’instance invalide.')
        if args.backend=='native':
            need(args.instance=='default','Instances natives multiples non qualifiées ; utiliser les instances Docker distinctes.')
            self.code=Path('/opt/voiceprobe') if args.instance=='default' else Path('/opt/voiceprobe/instances')/args.instance
            self.data=Path('/var/lib/voiceprobe') if args.instance=='default' else Path('/var/lib/voiceprobe/instances')/args.instance
        else:
            base=safe_directory(args.data_root)
            need('voiceprobe' in base.parts or any('voiceprobe' in p for p in base.parts),'Répertoire Docker dédié à Voice Probe requis.')
            self.code=base/'instances'/args.instance/'management';self.data=base/'instances'/args.instance/'data'
        safe_directory(self.code);safe_directory(self.data)
        self.settings_path=self.code/'management.json';self.state_path=self.code/'update-state.json';self.settings={}
        if self.settings_path.exists():
            self.settings=private_json(self.settings_path)
            need(self.settings.get('backend')==args.backend and self.settings.get('instance')==args.instance,'État d’une autre installation/instance ; aucune modification.')
        self.backend=Native(self) if args.backend=='native' else Container(self)
        self.cfg=self.data/'config.json'

    def progress(self,number,message):
        self.stage=message;print('['+str(number)+'/7] '+message+'.',flush=True)

    def source(self):
        base=self.args.source or self.settings.get('source')
        key=self.args.key or self.settings.get('public_key')
        need(base and key,'Source officielle non provisionnée : préciser une source HTTPS et sa clé publique de confiance. Aucun téléchargement GitLab privé implicite.')
        if self.settings.get('public_key') and self.args.key:
            before=command(['openssl','pkey','-pubin','-in',self.settings['public_key'],'-outform','DER'],message='Clé de confiance installée illisible.')
            after=command(['openssl','pkey','-pubin','-in',str(key),'-outform','DER'],message='Clé de confiance proposée illisible.')
            need(before==after,'Changement de clé de signature refusé ; rotation de confiance à qualifier explicitement.')
        return Source(base,key,self.args.ca_file or self.settings.get('distribution_ca'))

    def platform_key(self):
        info=platform.freedesktop_os_release();version='.'.join(map(str,sys.version_info[:2]));abi=sys.implementation.cache_tag
        allowed={('ubuntu','24.04','3.12'): 'ubuntu-24.04-amd64-cp312',('debian','12','3.11'):'debian-12-amd64-cp311'}
        key=allowed.get((info.get('ID'),info.get('VERSION_ID'),version))
        need(key,'OS/version Python non qualifiés : Ubuntu24.04/Python3.12 ou Debian12/Python3.11 AMD64 requis. Aucun fallback source/ARM64.')
        need(Path('/run/systemd/system').is_dir() and shutil.which('systemctl'),'systemd natif actif requis ; choisir le mode Docker sur DSM.')
        return key

    def free_space(self,required):
        base=self.code
        while not base.exists():base=base.parent
        need(shutil.disk_usage(base).free>=required+MIN_FREE,'Espace disque insuffisant pour préparer, sauvegarder et conserver le rollback.')
        base=self.data
        while not base.exists():base=base.parent
        need(shutil.disk_usage(base).free>=MIN_FREE,'Espace de persistance insuffisant ; conserver les données et libérer de l’espace.')

    def read_status(self,fresh=True):
        try:
            result=private_json(self.data/'.management-status.json')
            if fresh:need(time.time()-result.get('sampled_at',0)<8,'Statut Agent périmé.')
            return result
        except (OSError,ValueError,Failure):return None

    def version_at(self,release):
        for candidate in [Path(release)/'agent/VERSION',Path(release)/'VERSION']:
            if candidate.is_file():return candidate.read_text().strip()
        return 'inconnue'

    def persistent_proof(self):
        cfg=private_json(self.cfg)
        key=Path(cfg.get('identity_private_key',''))
        if self.args.backend=='docker' and str(key)=='/var/lib/voiceprobe/identity.key':key=self.data/'identity.key'
        need(key.is_file() and not key.is_symlink(),'Identité existante absente ; aucune régénération autorisée.')
        return {'id':cfg['id'],'identity_key_sha256':digest(key),'identity_fingerprint':cfg.get('identity_fingerprint'),
                'local_password_hash':cfg.get('local_password_hash'),'local_password_sha256':hashlib.sha256(str(cfg.get('local_password','')).encode()).hexdigest(),
                'controller_url':cfg.get('controller_url'),'token_sha256':hashlib.sha256(str(cfg.get('token','')).encode()).hexdigest(),'port':cfg.get('port'),
                'sip_port':cfg.get('sip_port',5060),'rtp_base_port':cfg.get('rtp_base_port',4000)}

    def data_path(self,value):
        if value and self.args.backend=='docker':
            path=Path(value)
            if path.is_relative_to('/var/lib/voiceprobe'):
                return str(self.data/path.relative_to('/var/lib/voiceprobe'))
        return value

    def expected_accounts(self):
        if not self.cfg.exists():return 0
        cfg=private_json(self.cfg)
        if not cfg.get('token') or cfg.get('adoption_state')!='adopted':return 0
        context=ssl.create_default_context(cafile=self.data_path(cfg.get('ca_file')))
        request=urllib.request.Request(https_url(cfg['controller_url'])+'/api/agent/config',headers={'Authorization':'Bearer '+cfg['token'],'Accept':'application/json'})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=context))
        try:
            with opener.open(request,timeout=15) as response:data=json.loads(response.read(4*1024*1024))
            need(data.get('id')==cfg['id'],'Le Controller retourne une autre identité.')
            return len(data.get('accounts',[]))
        except (OSError,urllib.error.URLError,ValueError):
            raise Failure('Controller indisponible ou authentification refusée avant mise à jour ; Agent existant conservé.') from None

    def idle_database(self):
        path=self.data/'state.sqlite'
        need(path.is_file() and not path.is_symlink(),'État local inconnu : absence de preuve d’inactivité ; arrêt refusé.')
        try:
            with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=2) as connection:
                count=connection.execute('SELECT count(*) FROM active').fetchone()[0]
            return count==0
        except sqlite3.Error:
            raise Failure('État SQLite illisible ; aucun arrêt de la sonde.') from None

    def drain(self,release):
        if not self.backend.status():return
        status=self.read_status()
        if not status or (status.get('maintenance') or {}).get('protocol')!=1:
            need(not self.args.scheduled,'Agent historique sans drainage : mise à jour planifiée reportée.')
            need(self.previous and self.args.backend=='native','Agent Docker historique sans protocole de maintenance : transition non qualifiée, mise à jour refusée.')
            main=Path(self.previous['release'])/'agent/src/main.py'
            need(main.is_file() and digest(main) in release.get('legacy_main_sha256',[]),
                 'Agent historique non reconnu : aucune preuve de sécurité pour arrêter ses appels.')
            need(self.idle_database(),'Appels historiques actifs : mise à jour reportée, Agent conservé.')
            self.frozen=self.backend.freeze()
            if not self.idle_database():
                self.backend.thaw(self.frozen);self.frozen=None
                raise Failure('Un appel vient de démarrer ; mise à jour reportée sans bascule.')
            print('Agent003 reconnu et figé à vide ; aucun drainage de campagne Controller revendiqué.',flush=True)
            return
        nonce=secrets.token_hex(32)
        request=self.data/'.update-request.json';atomic(request,{'nonce':nonce,'expires':time.time()+self.args.drain_timeout+180})
        owner=self.cfg.stat();os.chown(request,owner.st_uid,owner.st_gid)
        deadline=time.monotonic()+self.args.drain_timeout
        while time.monotonic()<deadline:
            status=self.read_status()
            if (status and status.get('maintenance',{}).get('nonce')==nonce and
                    status['maintenance'].get('paused') is True and status.get('active_calls')==0 and status.get('prepared_calls')==0):
                return
            time.sleep(.25)
        request.unlink(missing_ok=True)
        raise Failure('Fin des appels non confirmée dans le délai ; mise à jour reportée et tests locaux réautorisés.')

    def backup(self):
        directory=self.code/'backups'/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4))
        directory.mkdir(parents=True,mode=0o700)
        # Agent is stopped: SQLite and persistent configuration cannot race this copy.
        archive=directory/'persistent.tar.gz'
        with tarfile.open(archive,'w:gz') as target:
            for path in sorted(self.data.rglob('*')):
                need(not path.is_symlink(),'Lien symbolique inattendu dans les données ; sauvegarde refusée.')
                if path.is_file() and path.name not in ('.update-request.json','.management-status.json'):
                    target.add(path,arcname=str(path.relative_to(self.data)),recursive=False)
        archive.chmod(0o600)
        atomic(directory/'checksums.json',{'persistent.tar.gz':digest(archive)})
        atomic(directory/'previous.json',self.previous or {})
        self.verify_backup(directory)
        return directory

    def verify_backup(self,directory):
        directory=Path(directory);checks=private_json(directory/'checksums.json')
        need(set(checks)=={'persistent.tar.gz'} and digest(directory/'persistent.tar.gz')==checks['persistent.tar.gz'],
             'Sauvegarde corrompue ; aucune reprise ou restauration automatique.')
        with tempfile.TemporaryDirectory(prefix='voiceprobe-backup-') as folder:
            extract(directory/'persistent.tar.gz',folder,4*1024*1024*1024)
            cfg=Path(folder)/'config.json';need(cfg.is_file(),'Configuration absente de la sauvegarde.')
            db=Path(folder)/'state.sqlite'
            if db.exists():
                with sqlite3.connect(str(db)) as connection:need(connection.execute('PRAGMA quick_check').fetchone()[0]=='ok','Sauvegarde SQLite non intègre.')

    def dependencies(self,runtime):
        allowed={'python3','python3-venv','python3-requests','python3-websockets','python3-numpy','ca-certificates','openssl','iproute2','libssl3','libssl3t64','libopus0','libasound2','libasound2t64','libstdc++6','libgcc-s1','libgfortran5','libquadmath0'}
        packages=runtime.get('dependencies',[])
        need(isinstance(packages,list) and packages and all(p in allowed for p in packages),'Dépendances non qualifiées ; aucun paquet arbitraire installé.')
        installed=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status}\n',*packages],capture_output=True,text=True)
        if installed.returncode or installed.stdout.splitlines()!=['installed']*len(packages):
            command(['apt-get','update'],timeout=300,message='Index apt indisponible ; installation Agent non basculée.')
            command(['apt-get','install','-y','--no-install-recommends',*packages],timeout=600,message='Installation des dépendances binaires refusée ; aucune compilation source.')
        try:pwd.getpwnam('voiceprobe')
        except KeyError:command(['useradd','--system','--home-dir','/var/lib/voiceprobe','--shell','/usr/sbin/nologin','voiceprobe'])

    def legacy_metadata(self,manifest):
        root=Path(self.previous['release']);main=root/'agent/src/main.py'
        need(main.is_file() and digest(main) in manifest.get('legacy_main_sha256',[]),
             'Code historique003 non reconnu ; aucune adaptation ou bascule.')
        build=(root/'agent/BUILD_ID').read_text().strip()
        need(re.fullmatch('[a-f0-9]{40}',build),'Révision historique non identifiée ; transition non qualifiée.')
        unit=self.previous['unit']
        expected='ExecStart='+str(self.code/'venv/bin/python')+' '+str(self.code/'current/agent/src/main.py')
        need(expected in unit.splitlines(),'Service historique différent du contrat qualifié ; aucune substitution.')
        directory=self.code/'admin';directory.mkdir(exist_ok=True,mode=0o755);directory.chmod(0o755)
        observer=directory/'legacy-run.py'
        observer.write_text(LEGACY_OBSERVER.replace('ALLOWED_HASHES',repr(manifest['legacy_main_sha256'])));observer.chmod(0o755)
        self.previous['unit_original']=unit
        self.previous['unit']=unit.replace(expected,'ExecStart='+str(self.code/'venv/bin/python')+' '+str(observer)+' '+str(self.code/'current/agent/src/main.py'))
        return {'version':'0.9-003','source_revision':build,'release_id':'0.9-003-'+build[:12],
                'data_schema':1,'rollback_compatible':True,'legacy_main_sha256':manifest['legacy_main_sha256']}

    def prepare_native(self,manifest,app,runtime_file,runtime):
        release=self.code/'releases'/manifest['release_id']
        if release.exists():
            need((release/'qualified-release.json').is_file() and same_release(private_json(release/'qualified-release.json'),manifest),'Release existante incohérente ; aucun écrasement.')
            self.runtime_test(release/'venv/bin/python')
            return release
        self.dependencies(runtime)
        (self.code/'releases').mkdir(parents=True,exist_ok=True,mode=0o755)
        (self.code/'releases').chmod(0o755)
        with tempfile.TemporaryDirectory(prefix='.stage-',dir=self.code/'releases') as temporary:
            stage=Path(temporary);stage.chmod(0o755)
            extract(app,stage,32*1024*1024)
            need((stage/'agent/src/main.py').is_file() and (stage/'agent/VERSION').read_text().strip()==manifest['version'],
                 'Archive Agent non conforme.')
            command(['python3','-m','venv',str(stage/'venv')],message='Création de l’environnement Python isolé refusée.')
            with tempfile.TemporaryDirectory(prefix='voiceprobe-runtime-') as binary_dir:
                extract(runtime_file,binary_dir,128*1024*1024)
                binary=Path(binary_dir)/'pjsip';info=json.loads((binary/'binary.json').read_text())
                need(info.get('platform')==self.platform_key() and info.get('pjsip_version')=='2.16' and info.get('python')=='.'.join(map(str,sys.version_info[:2]))
                     and info.get('soabi')==sysconfig.get_config_var('SOABI') and info.get('glibc')==platform.libc_ver()[1],
                     'Binaire PJSUA2 incompatible avec la plateforme ou l’ABI Python.')
                wheels=binary/'wheels'
                need(wheels.is_dir() and (binary/'requirements.lock').is_file(),'Dépendances Python binaires qualifiées absentes ; aucune compilation.')
                command([str(stage/'venv/bin/python'),'-m','pip','--isolated','install','--no-compile','--no-index','--only-binary',':all:','--require-hashes','--find-links',str(wheels),'-r',str(binary/'requirements.lock')],timeout=180,message='Installation hors ligne des dépendances Python binaires refusée.')
                site=Path(command([str(stage/'venv/bin/python'),'-c','import sysconfig; print(sysconfig.get_path("purelib"))']).decode().strip())
                modules=[p for p in binary.iterdir() if p.name=='pjsua2.py' or p.name.startswith('_pjsua2') and p.suffix=='.so']
                need(len(modules)==2,'Bindings PJSUA2 manquants ou ambigus.')
                for module in modules:shutil.copy2(module,site/module.name)
                shutil.copy2(binary/'binary.json',stage/'pjsip-binary.json')
            self.runtime_test(stage/'venv/bin/python')
            for path in [stage,*stage.rglob('*')]:
                if not path.is_symlink():
                    path.chmod(0o755 if path.is_dir() or path.stat().st_mode&0o111 else 0o644)
            atomic(stage/'qualified-release.json',manifest)
            shutil.move(str(stage),release)
        return release

    def runtime_test(self,python):
        command([str(python),'-c',
          'import requests,websockets,numpy,pjsua2 as p,sys; from pathlib import Path; assert Path(p.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()); e=p.Endpoint(); e.libCreate(); c=p.EpConfig(); c.logConfig.level=0; c.logConfig.consoleLevel=0; e.libInit(c); e.libStart(); e.audDevManager().setNullDev(); assert e.libVersion().full=="2.16"; assert all(any(x.codecId.startswith(k) for x in e.codecEnum2()) for k in ("G722/","PCMA/","PCMU/")); e.libDestroy()'],
          timeout=30,message='Import/initialisation SIP ou codecs du binaire PJSUA2 refusés ; aucune compilation sur la cible.')

    def prepare_docker(self,manifest,archive):
        declaration=manifest['docker'];engine=self.backend.engine
        info=engine.call('GET','/info');need(info and info.get('OSType')=='linux' and info.get('Architecture') in ('x86_64','amd64'),
                                                'Moteur Docker Linux AMD64 requis.')
        image=engine.call('GET','/images/'+urllib.parse.quote(declaration['reference'],safe='')+'/json')
        if image is None:
            # Refuse archives that could load another project or a second image.
            with tarfile.open(archive,'r:gz') as source:
                entry=source.extractfile('manifest.json');need(entry,'Manifeste Docker absent.')
                entries=json.load(entry)
                need(len(entries)==1 and entries[0].get('RepoTags')==[declaration['reference']],
                     'Archive Docker contenant une image étrangère ou des tags inattendus.')
            engine.call('POST','/images/load?quiet=true',file=archive)
            image=engine.call('GET','/images/'+urllib.parse.quote(declaration['reference'],safe='')+'/json')
        need(image and image.get('Id') in declaration['image_ids'] and image.get('Architecture')=='amd64' and image.get('Os')=='linux'
             and image.get('RootFS',{}).get('Layers')==declaration['rootfs_diff_ids'], 'Image Docker différente de la distribution signée.')
        labels=image.get('Config',{}).get('Labels') or {}
        need(labels.get('net.wifx.project')=='voiceprobe-agent' and labels.get('org.opencontainers.image.version')==manifest['version']
             and labels.get('org.opencontainers.image.revision')==manifest['source_revision'], 'Identité/version de l’image Agent non conforme.')
        return {'local_image_id':image['Id']}

    def available_rtp_base(self):
        # New installations only: avoid system services such as mDNS5353/LLMNR5355.
        # Existing installations retain their precise RTP configuration.
        for base in range(20000,60001,4000):
            available=True
            for port in range(base,base+3180):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                    try:probe.bind(('0.0.0.0',port))
                    except OSError:available=False;break
            if available:return base
        raise Failure('Aucune plage RTP libre détectée ; aucune modification des services existants.')

    def configure_new(self,release,manifest):
        if self.cfg.exists():
            if not self.args.reset_initial_password:return False
            state=private_json(self.state_path) if self.state_path.exists() else {}
            need(self.args.action=='install' and not self.settings and not self.backend.status()
                 and state.get('phase') in ('failed_initial','recovered_initial') and state.get('initial_install') is True
                 and state.get('previous') is None,
                 'Réinitialisation initiale réservée à une installation jamais validée et arrêtée ; aucune modification des accès existants.')
            need(not self.args.non_interactive,'Utiliser reset-password avec un fichier privé pour une réinitialisation non interactive.')
            try:
                with open('/dev/tty','w'):pass
            except OSError:raise Failure('Terminal requis pour remettre le nouveau mot de passe initial.') from None
            password=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789') for _ in range(28))
            cfg=private_json(self.cfg);owner=self.cfg.stat();salt=secrets.token_bytes(16)
            h=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
            cfg['local_password_hash']='scrypt$16384$8$1$'+salt.hex()+'$'+h.hex();cfg.pop('local_password',None)
            atomic(self.cfg,cfg);os.chown(self.cfg,owner.st_uid,owner.st_gid)
            self.password=password
            return True
        need(not self.args.non_interactive or self.args.password_file,'Mode non interactif : fournir un fichier privé --password-file ; aucun mot de passe généré ne sera journalisé.')
        if self.args.password_file:
            path=Path(self.args.password_file);private=path.lstat()
            need(stat.S_ISREG(private.st_mode) and not private.st_mode & 0o077,'Fichier de mot de passe non privé.')
            password=path.read_text().rstrip('\r\n')
        else:
            need(os.path.exists('/dev/tty'),'Terminal interactif requis pour afficher les identifiants initiaux.')
            try:
                with open('/dev/tty','w'):pass
            except OSError:raise Failure('Aucun terminal interactif pour remettre les identifiants ; utiliser --non-interactive --password-file.') from None
            password=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789') for _ in range(28))
        need(16<=len(password)<=200,'Mot de passe de16à200 caractères requis.')
        controller=https_url(self.args.controller or 'https://vp.wifx.net')
        bind=self.args.bind or lan_address()
        address=ipaddress.ip_address(bind)
        need(address.version==4 and (address.is_private or address.is_loopback) and not address.is_unspecified,
             'Écoute administrative limitée à une IPv4 privée/loopback ; 0.0.0.0 et IPv6 publique refusés pour une nouvelle installation.')
        ports={'port':self.args.port,'sip_port':self.args.sip_port,'rtp_base_port':self.args.rtp_base_port or self.available_rtp_base()}
        need(1024<=ports['port']<=65535 and 1024<=ports['sip_port']<=65535 and 1024<=ports['rtp_base_port']<=62000,
             'Ports Agent hors limites.')
        for typ,port in [(socket.SOCK_STREAM,ports['port']),(socket.SOCK_STREAM,ports['sip_port']),(socket.SOCK_DGRAM,ports['sip_port'])]:
            with socket.socket(socket.AF_INET,typ) as check:
                try:check.bind((bind if port==ports['port'] else '0.0.0.0',port))
                except OSError:raise Failure('Port HTTP/SIP occupé ; aucune ressource existante arrêtée. Choisir des ports distincts.') from None
        for port in range(ports['rtp_base_port'],ports['rtp_base_port']+3180):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as check:
                try:check.bind(('0.0.0.0',port))
                except OSError:raise Failure('Plage RTP occupée ; choisir --rtp-base-port sans modifier les autres services.') from None
        safe_directory(self.data,create=True)
        helper=Path(release)/'scripts/configure-agent.py' if self.args.backend=='native' else Path('/opt/voiceprobe/scripts/configure-agent.py')
        python=str(Path(release)/'venv/bin/python') if self.args.backend=='native' else sys.executable
        settings={'controller_url':controller,'wss_url':'wss://'+urllib.parse.urlsplit(controller).netloc+'/ws','bind':bind,**ports,
                  'name':self.args.name or (self.backend.engine.call('GET','/info').get('Name','Voice Probe') if self.args.backend=='docker' else socket.gethostname()),'installation_type':'native' if self.args.backend=='native' else 'container'}
        ca=self.args.controller_ca or '/etc/ssl/certs/ca-certificates.crt'
        if self.args.controller_ca:
            target=self.data/'controller-ca.pem';shutil.copyfile(ca,target);target.chmod(0o600)
            ca=str(target) if self.args.backend=='native' else '/var/lib/voiceprobe/controller-ca.pem'
        settings['ca_file']=ca
        program='''import importlib.util,json,sys
from pathlib import Path
s=importlib.util.spec_from_file_location("configure",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
x=json.load(sys.stdin);p=Path(sys.argv[2]);m.prepare(p,x.pop("password"),retain_credentials=False)
c=json.loads(p.read_text());c.update(x["config"])
if x["docker"]:c["identity_private_key"]="/var/lib/voiceprobe/identity.key"
m.atomic_json(p,c)
'''
        command([python,'-c',program,str(helper),str(self.cfg)],data=json.dumps({'password':password,'config':settings,'docker':self.args.backend=='docker'}).encode(),
                message='Préparation de l’identité locale refusée ; aucune clé existante remplacée.')
        if self.args.backend=='native':owner=pwd.getpwnam('voiceprobe');uid,gid=owner.pw_uid,owner.pw_gid
        else:uid=gid=1000
        for path in [self.data,*self.data.rglob('*')]:
            need(not path.is_symlink(),'Lien inattendu dans les données neuves.')
            os.chown(path,uid,gid)
        self.password=password
        return True

    def verify(self,manifest,expected_accounts=0,timeout=None,minimum_sample=0):
        deadline=time.monotonic()+(timeout or self.args.timeout)
        previous_cfg=private_json(self.cfg);adopted=previous_cfg.get('adoption_state')=='adopted'
        while time.monotonic()<deadline:
            status=self.read_status()
            if (self.backend.status() and status and status.get('sampled_at',0)>=minimum_sample and status.get('version')==manifest['version'] and status.get('build_id')==manifest['source_revision']
                and status.get('pjsip_version')=='2.16' and status.get('controller_connected') is True and
                (not adopted or status.get('wss_connected') is True) and
                len([a for a in status.get('accounts',[]) if a.get('registration_code')==200 and a.get('registration_active') is True])>=expected_accounts):
                try:
                    host=previous_cfg.get('bind','127.0.0.1');scheme='https' if previous_cfg.get('tls_cert') else 'http'
                    connection=http.client.HTTPSConnection(host,previous_cfg.get('port',18441),context=ssl.create_default_context(cafile=self.data_path(previous_cfg['tls_cert'])),timeout=3) if scheme=='https' else http.client.HTTPConnection(host,previous_cfg.get('port',18441),timeout=3)
                    connection.request('GET','/login');response=connection.getresponse();response.read();connection.close()
                    if response.status==200:return status
                except (OSError,ssl.SSLError):pass
            time.sleep(1)
        details=[]
        if status:
            details.append('service '+('actif' if self.backend.status() else 'inactif'))
            details.append('Controller connecté='+str(status.get('controller_connected') is True))
            code=status.get('controller_http_status')
            if type(code) is int and 100<=code<=599:details.append('Controller HTTP'+str(code))
            category=status.get('controller_error_category')
            if category in {'http','tls','timeout','network_dns','enrollment_format_identity'}:details.append('cause='+category)
        raise Failure('Vérification après démarrage échouée : service/interface, version, Controller HTTPS/WSS ou comptes SIP non conformes. '+', '.join(details))

    def retire_legacy_credentials(self):
        path=self.data/'install-credentials.json'
        if not path.exists():return
        value=private_json(path)
        need(set(value)<= {'username','password','note'} and value.get('username')=='admin'
             and isinstance(value.get('password'),str) and private_json(self.cfg).get('local_password_hash'),
             'Ancien fichier d’identifiants inconnu ; retrait automatique refusé.')
        path.unlink()
        print('Ancien fichier de remise des identifiants retiré ; hash et accès administrateur conservés, sauvegarde privée disponible.')

    def install_command(self, manager_source=None):
        directory=self.code/'admin';directory.mkdir(exist_ok=True,mode=0o755)
        destination=directory/'manage.py';temporary=directory/'manage.py.new';shutil.copyfile(manager_source or __file__,temporary);temporary.chmod(0o755);os.replace(temporary,destination)
        if self.args.backend=='native':
            path=Path('/usr/local/bin/voiceprobe-agent')
            script='''#!/bin/sh
# WIFX Voice Probe native management
voiceprobe_strict=0
for voiceprobe_arg in "$@"; do [ "$voiceprobe_arg" != --strict ] || voiceprobe_strict=1; done
if python3 MANAGER --strict --backend native "$@"; then exit 0; else voiceprobe_code=$?; fi
printf 'ÉCHEC CONTRÔLÉ : commande Agent non vérifiée ; session conservée.\\nVOICEPROBE_AGENT_RESULT=CONTROLLED_FAILURE\\n' >&2
[ "$voiceprobe_strict" -eq 0 ] || exit "$voiceprobe_code"
exit 0
'''.replace('MANAGER',shlex.quote(str(destination)))
            alias=Path('/usr/local/bin/voiceprobe-agent-native')
            need(not alias.is_symlink() and (not alias.exists() or
                 alias.is_file() and '--backend native' in alias.read_text() and str(destination) in alias.read_text()),
                 'Commande voiceprobe-agent-native homonyme inconnue ; aucune substitution.')
            alias.write_text(script);alias.chmod(0o755)
            own_native=path.is_file() and not path.is_symlink() and '--backend native' in path.read_text() and str(destination) in path.read_text()
            if not path.exists() and not path.is_symlink() or own_native:
                path.write_text(script);path.chmod(0o755);self.launcher='voiceprobe-agent'
            else:
                self.launcher='voiceprobe-agent-native'
                print('Commande existante conservée ; gestion native : sudo voiceprobe-agent-native.')
        # Docker/DSM host shim is installed by the verified POSIX bootstrap.

    def save_settings(self,source,manifest):
        key=self.code/'signing-public.pem'
        if source.key.resolve()!=key.resolve():shutil.copyfile(source.key,key)
        key.chmod(0o644)
        ca=self.args.ca_file or self.settings.get('distribution_ca')
        if ca:
            target=self.code/'distribution-ca.pem'
            if Path(ca).resolve()!=target.resolve():shutil.copyfile(ca,target)
            target.chmod(0o644);ca=str(target)
        self.settings.update({'schema':1,'backend':self.args.backend,'instance':self.args.instance,'source':source.base,
                'public_key':str(key),'distribution_ca':ca,'sequence':manifest['sequence'],'release':manifest,
                'last_update':dt.datetime.now(dt.timezone.utc).isoformat()})
        atomic(self.settings_path,self.settings)

    def update(self):
        self.progress(1,'Vérification du système et de l’installation')
        platform_key=self.platform_key() if self.args.backend=='native' else None
        source=self.source()
        with tempfile.TemporaryDirectory(prefix='voiceprobe-download-') as folder:
            folder=Path(folder);manifest=source.manifest(folder,self.settings.get('sequence',0))
            self.progress(2,'Architecture et manifeste signé vérifiés')
            installed=self.settings.get('release',{})
            if installed.get('release_id')==manifest['release_id']:
                need(same_release(installed,manifest),'Contenu différent sous un identifiant de release immuable ; publication refusée.')
                if self.backend.status():
                    self.verify(manifest,self.expected_accounts())
                    if self.args.check:
                        print('CONTRÔLE OK : installation courante vérifiée ; aucun changement.')
                        return 'CHECK_OK'
                    self.settings.update({'sequence':manifest['sequence'],'release':manifest});atomic(self.settings_path,self.settings)
                    print('DÉJÀ INSTALLÉ : contrôles effectués, aucun artefact téléchargé, identité et comptes conservés.')
                    return 'VERIFIED_SUCCESS'
            if self.args.backend=='native':
                runtime=manifest.get('runtimes',{}).get(platform_key)
                need(runtime,'Aucun binaire PJSUA2 qualifié pour cette plateforme ; arrêt sans compilation.')
                wanted=[manifest['agent'],runtime]
            else:wanted=[manifest['docker']]
            if manifest.get('manager'):wanted.append(manifest['manager'])
            total=sum(v['bytes'] for v in wanted)
            persistent=sum(p.stat().st_size for p in self.data.rglob('*') if p.is_file() and not p.is_symlink()) if self.data.exists() else 0
            self.free_space(total*4+int(persistent*1.1))
            need(shutil.disk_usage(tempfile.gettempdir()).free>=total+MIN_FREE,'Espace temporaire insuffisant pour le téléchargement vérifié.')
            artifacts=[]
            for value in wanted:
                artifacts.append(source.download(value['name'],folder/value['name'],expected=value['sha256'],size=value['bytes']))
            self.progress(3,'Artefacts téléchargés et intégrité vérifiée')
            if self.args.check:
                print('CONTRÔLE OK : distribution compatible vérifiée ; aucune installation, dépendance, image ou donnée modifiée.')
                return 'CHECK_OK'
            safe_directory(self.code,create=True)
            if self.args.backend=='native':self.code.chmod(0o755)
            self.previous=self.backend.capture()
            prior_state=private_json(self.state_path) if self.state_path.exists() else {}
            initial_recovery=not self.settings and prior_state.get('initial_install') is True
            if initial_recovery and self.previous and not self.previous.get('was_running',True):self.previous=None
            if initial_recovery and prior_state.get('initial_generated') and not self.args.reset_initial_password:
                raise Failure('Identifiants initiaux non remis après interruption ; relancer install --reset-initial-password pour générer un nouvel accès en mémoire, sans changer l’identité.')
            original=self.persistent_proof() if self.cfg.exists() else None
            expected=self.expected_accounts()
            if self.previous:
                version=self.version_at(self.previous['release']) if self.args.backend=='native' else (self.read_status() or {}).get('version','inconnue')
                need(version in manifest.get('compatible_from',[]),'Transition de version non qualifiée ; installation existante conservée.')
            current=self.settings.get('release',{})
            if self.previous and self.args.backend=='native' and version=='0.9-003' and not current:
                current=self.legacy_metadata(manifest)
            if current.get('release_id')==manifest['release_id'] and self.backend.status():
                self.verify(manifest,expected);print('DÉJÀ INSTALLÉ : contrôles effectués, identité et comptes conservés.')
                return 'VERIFIED_SUCCESS'
            prepared=self.prepare_native(manifest,artifacts[0],artifacts[1],runtime) if self.args.backend=='native' else self.prepare_docker(manifest,artifacts[0])
            self.progress(4,'Nouvelle version préparée sans compilation')
            created=self.configure_new(prepared if self.args.backend=='native' else '',manifest)
            if self.args.reset_initial_password and original:
                reset_proof=self.persistent_proof()
                original['local_password_hash']=reset_proof['local_password_hash'];original['local_password_sha256']=reset_proof['local_password_sha256']
            backup=None
            state={'phase':'prepared','settings_before':json.loads(json.dumps(self.settings)),'target':manifest,'prepared':str(prepared) if self.args.backend=='native' else prepared,'previous':self.previous,'original':original,'expected_accounts':expected,'initial_install':original is None or initial_recovery,'initial_generated':bool(created and not self.args.password_file) or bool(prior_state.get('initial_generated'))}
            atomic(self.state_path,state)
            try:
                self.drain(manifest)
                if self.backend.status():self.backend.stop()
                self.frozen=None
                state['phase']='stopped';atomic(self.state_path,state)
                backup=self.backup();state.update({'phase':'backed_up','backup':str(backup)});atomic(self.state_path,state)
                self.progress(5,'Sauvegarde vérifiée et appels terminés')
                started_after=time.time();self.backend.start(prepared);state['phase']='started';atomic(self.state_path,state)
                self.progress(6,'Seul l’Agent concerné a démarré')
                status=self.verify(manifest,expected,minimum_sample=started_after)
                if original:need(self.persistent_proof()==original,'Identité, adoption, mots de passe ou ports modifiés ; reprise suspendue.')
                self.settings['previous']={'backend':self.previous,'release':current,'backup':str(backup)} if self.previous and self.previous.get('was_running',True) else None
                self.retire_legacy_credentials()
                self.install_command(artifacts[-1] if manifest.get('manager') else None);self.save_settings(source,manifest)
                state['phase']='success';atomic(self.state_path,state)
                self.progress(7,'Interface et connexion Controller vérifiées')
                self.summary(manifest,status,created)
                return 'VERIFIED_SUCCESS'
            except BaseException:
                if self.frozen:
                    self.backend.thaw(self.frozen);self.frozen=None
                (self.data/'.update-request.json').unlink(missing_ok=True)
                if state['phase'] in ('stopped','backed_up','started') and self.previous:
                    if backup:self.verify_backup(backup)
                    self.backend.restore(self.previous);state['phase']='rolled_back';atomic(self.state_path,state)
                    need(self.backend.status()==self.previous.get('was_running',True),'Échec de reprise de l’état précédent ; données et sauvegarde conservées.')
                    if current and self.previous.get('was_running',True):self.verify(current,expected)
                    if original:need(self.persistent_proof()==original,'Données persistantes modifiées ; aucune restauration destructive automatique.')
                    print('RETOUR À LA VERSION PRÉCÉDENTE : état de service initial rétabli, données et sauvegarde conservées.')
                elif not self.previous and state['phase']=='started':
                    self.backend.stop();state['phase']='failed_initial';atomic(self.state_path,state)
                raise
            finally:
                (self.data/'.update-request.json').unlink(missing_ok=True)
                self.password=None

    def summary(self,manifest,status,created):
        cfg=private_json(self.cfg);scheme='https' if cfg.get('tls_cert') else 'http'
        print('\nWIFX Voice Probe Agent\n'+('Installation terminée.' if created else 'Mise à jour vérifiée.'))
        print('Version : '+manifest['version']+'\nÉtat : ACTIF\nController : '+cfg['controller_url'])
        if getattr(self,'launcher',None):print('Gestion : sudo '+self.launcher)
        print('Interface : '+scheme+'://'+cfg.get('bind','127.0.0.1')+':'+str(cfg.get('port',18441)))
        if created and self.password and not self.args.non_interactive:
            with open('/dev/tty','w') as terminal:
                terminal.write('\nUtilisateur : admin\nMot de passe : '+self.password+'\nConservez ces identifiants ; ce mot de passe ne sera pas réaffiché.\n');terminal.flush()
        elif created:print('Utilisateur : admin ; mot de passe fourni par le fichier privé opérateur.')
        print('Identité : '+str(status.get('id'))+' ; comptes enregistrés : '+str(sum(bool(a.get('registration_active')) for a in status.get('accounts',[]))))

    def report_status(self):
        status=self.read_status();running=self.backend.status()
        if status is None:
            print('État : '+('ACTIF, télémétrie privée absente/périmée (Agent historique)' if running else 'INACTIF'))
            if self.cfg.exists():print('Identité : '+str(private_json(self.cfg).get('id')))
            return 'STATUS_OK'
        fields={'version':'Version Agent','pjsip_version':'Version PJSIP','os':'Système','architecture':'Architecture','id':'Identité','controller_connected':'Controller connecté','wss_connected':'WSS connecté','active_calls':'Appels actifs','last_error':'Dernière erreur'}
        for key,label in fields.items():print(label+' : '+str(status.get(key)))
        accounts=status.get('accounts',[])
        print('Service : '+('ACTIF' if running else 'INACTIF')+'\nComptes SIP : '+str(len(accounts))+' ; enregistrés : '+str(sum(a.get('registration_active') is True and a.get('registration_code')==200 for a in accounts)))
        cfg=private_json(self.cfg);print('Interface : '+('https' if cfg.get('tls_cert') else 'http')+'://'+cfg.get('bind','127.0.0.1')+':'+str(cfg.get('port',18441)))
        print('Dernière mise à jour : '+str(self.settings.get('last_update','historique/non gérée')))
        if self.args.action=='diagnose':
            print('Stockage disponible : '+str(shutil.disk_usage(self.data).free)+' octets ; protocole maintenance : '+str(status.get('maintenance',{}).get('protocol','absent')))
            if self.settings.get('previous'):self.verify_backup(self.settings['previous']['backup']);print('Dernière sauvegarde : INTÈGRE')
        return 'STATUS_OK'

    def rollback(self):
        previous=self.settings.get('previous');need(previous and previous.get('backend'),'Aucune version précédente qualifiée disponible.')
        need(previous.get('release',{}).get('data_schema')==1 and self.settings['release'].get('rollback_compatible') is True,
             'Retour de schéma non qualifié ; aucune restauration destructive.')
        self.verify_backup(previous['backup']);self.previous=self.backend.capture();proof=self.persistent_proof()
        current=self.settings['release'];expected=self.expected_accounts()
        state={'phase':'prepared','settings_before':json.loads(json.dumps(self.settings)),'previous':self.previous,'target':previous['release'],'operation':'rollback'}
        atomic(self.state_path,state)
        try:
            self.drain(current);self.backend.stop();self.frozen=None
            state['phase']='stopped';atomic(self.state_path,state)
            backup=self.backup();state.update({'phase':'backed_up','backup':str(backup)});atomic(self.state_path,state)
            started=time.time();self.backend.restore(previous['backend']);state['phase']='started';atomic(self.state_path,state)
            self.verify(previous['release'],expected,minimum_sample=started)
            need(self.persistent_proof()==proof,'Données modifiées pendant le rollback ; reprise suspendue.')
            self.settings['release']=previous['release'];self.settings['previous']=None
            self.settings['last_update']=dt.datetime.now(dt.timezone.utc).isoformat();atomic(self.settings_path,self.settings)
            state['phase']='rollback_success';atomic(self.state_path,state)
        except BaseException:
            if self.frozen:self.backend.thaw(self.frozen);self.frozen=None
            if state['phase'] in ('stopped','backed_up','started'):
                self.backend.restore(self.previous);self.verify(current,expected)
                state['phase']='rollback_failed_current_restored';atomic(self.state_path,state)
            raise
        finally:(self.data/'.update-request.json').unlink(missing_ok=True)
        print('ROLLBACK VÉRIFIÉ : binaires précédents actifs ; identité, configuration et historique conservés.')
        return 'VERIFIED_SUCCESS'

    def recover(self):
        if not self.state_path.exists():return
        state=private_json(self.state_path)
        if state.get('phase') in ('prepared','stopped','backed_up','started'):
            if not state.get('previous'):
                if self.backend.status():self.backend.stop()
                if 'settings_before' in state:
                    self.settings=state['settings_before']
                    if self.settings:atomic(self.settings_path,self.settings)
                    else:self.settings_path.unlink(missing_ok=True)
                state['phase']='recovered_initial';atomic(self.state_path,state)
                print('Installation initiale interrompue : identité conservée ; le mot de passe initial non remis devra être réinitialisé explicitement.')
                return
            if state.get('backup'):self.verify_backup(state['backup'])
            if state.get('phase')=='prepared' and state['previous'].get('was_running',True):
                if not self.backend.status():self.backend.restore(state['previous'])
            if state.get('phase') in ('stopped','backed_up','started'):
                if state.get('operation')=='configure' and state.get('backup'):
                    self.backend.stop()
                    owner=self.cfg.stat()
                    with tarfile.open(Path(state['backup'])/'persistent.tar.gz') as archive:
                        old_config=json.load(archive.extractfile('config.json'))
                    atomic(self.cfg,old_config);os.chown(self.cfg,owner.st_uid,owner.st_gid)
                restarted_after=time.time()
                self.backend.restore(state['previous'])
                if 'settings_before' in state:
                    self.settings=state['settings_before']
                    if self.settings:atomic(self.settings_path,self.settings)
                    else:self.settings_path.unlink(missing_ok=True)
                prior_release=self.settings.get('release')
                if prior_release and state['previous'].get('was_running',True):
                    # systemctl start returns before the Agent publishes its first status.
                    # Never classify this startup interval as an unknown legacy Agent.
                    self.verify(prior_release,state.get('expected_accounts',0),minimum_sample=restarted_after)
                state['phase']='recovered_previous';atomic(self.state_path,state)
                print('Interruption détectée : version précédente vérifiée avant nouvelle tentative.')
            (self.data/'.update-request.json').unlink(missing_ok=True)

    def configuration(self, reset_password=False):
        need(self.settings.get('release') and self.cfg.exists(),'Instance gérée requise ; effectuer d’abord l’installation/reprise qualifiée.')
        old=private_json(self.cfg);updated=json.loads(json.dumps(old));password=None
        if reset_password:
            if self.args.password_file:
                p=Path(self.args.password_file);info=p.lstat()
                need(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,'Fichier de mot de passe privé requis.')
                password=p.read_text().rstrip('\r\n')
            else:
                need(not self.args.non_interactive,'Réinitialisation non interactive : fournir --password-file.')
                try:
                    with open('/dev/tty','w'):pass
                except OSError:raise Failure('Terminal interactif requis pour remettre le nouveau mot de passe.') from None
                password=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789') for _ in range(28))
            need(16<=len(password)<=200,'Mot de passe de16à200 caractères requis.')
            import hashlib
            salt=secrets.token_bytes(16);h=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
            updated['local_password_hash']='scrypt$16384$8$1$'+salt.hex()+'$'+h.hex();updated.pop('local_password',None)
        else:
            need(any(x is not None for x in [self.args.controller,self.args.name,self.args.bind]) or bool({'--port','--sip-port','--rtp-base-port'}&self.args.provided),
                 'Préciser --name, --controller, --bind ou les ports à modifier.')
            if self.args.name is not None:updated['name']=self.args.name
            if self.args.controller and https_url(self.args.controller)!=old.get('controller_url'):
                url=https_url(self.args.controller);updated.update({'controller_url':url,'wss_url':'wss://'+urllib.parse.urlsplit(url).netloc+'/ws','token':'','adoption_state':'unconfigured'})
                updated.pop('credential_ack_pending',None);updated.pop('metadata_authority',None)
            if self.args.bind:
                ip=ipaddress.ip_address(self.args.bind)
                need(ip.version==4 and not ip.is_unspecified and (ip.is_private or ip.is_loopback),'Adresse administrative privée IPv4 ou loopback requise.')
                updated['bind']=str(ip)
            for option,key in [('--port','port'),('--sip-port','sip_port'),('--rtp-base-port','rtp_base_port')]:
                if option in self.args.provided:
                    value=getattr(self.args,key);need(value and 1024<=value<=(62000 if key=='rtp_base_port' else 65535),'Port hors limites.');updated[key]=value
        self.previous=self.backend.capture();need(self.previous,'Service Agent existant requis.')
        expected=self.expected_accounts() if updated.get('controller_url')==old.get('controller_url') else 0
        state={'phase':'prepared','previous':self.previous,'settings_before':json.loads(json.dumps(self.settings)),'operation':'configure'}
        atomic(self.state_path,state);owner=self.cfg.stat()
        try:
            self.drain(self.settings['release']);self.backend.stop();self.frozen=None
            state['phase']='stopped';atomic(self.state_path,state)
            backup=self.backup();state.update({'phase':'backed_up','backup':str(backup)});atomic(self.state_path,state)
            atomic(self.cfg,updated);os.chown(self.cfg,owner.st_uid,owner.st_gid)
            started=time.time();self.backend.start(self.previous['release'] if self.args.backend=='native' else self.previous)
            state['phase']='started';atomic(self.state_path,state)
            self.verify(self.settings['release'],expected,minimum_sample=started)
            state['phase']='configuration_success';atomic(self.state_path,state)
        except BaseException:
            if self.frozen:self.backend.thaw(self.frozen);self.frozen=None
            if state['phase'] in ('stopped','backed_up','started'):
                self.backend.stop();atomic(self.cfg,old);os.chown(self.cfg,owner.st_uid,owner.st_gid);self.backend.restore(self.previous)
                self.verify(self.settings['release'],self.expected_accounts())
                state['phase']='configuration_failed_previous_restored';atomic(self.state_path,state)
            raise
        finally:(self.data/'.update-request.json').unlink(missing_ok=True)
        if password and not self.args.non_interactive:
            with open('/dev/tty','w') as terminal:terminal.write('Utilisateur : admin\nNouveau mot de passe : '+password+'\n');terminal.flush()
        print(('Mot de passe réinitialisé' if reset_password else 'Configuration appliquée')+' ; identité conservée, sauvegarde privée vérifiée.')
        return 'VERIFIED_SUCCESS'

    def schedule(self, enable):
        need(self.settings.get('release'),'Installation gérée requise avant de planifier les mises à jour.')
        need(re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]',self.args.at),'Heure UTC au format HH:MM requise.')
        name='voiceprobe-agent-update'+('' if self.args.instance=='default' else '-'+self.args.instance)
        if self.args.backend=='native':
            timer=Path('/etc/systemd/system')/(name+'.timer');service=Path('/etc/systemd/system')/(name+'.service')
            if enable:
                for unit in (timer,service):
                    need(not unit.is_symlink() and (not unit.exists() or unit.is_file() and 'WIFX Voice Probe' in unit.read_text()),'Unité de planification homonyme inconnue ; aucune substitution.')
                service.write_text('[Unit]\nDescription=WIFX Voice Probe scheduled Agent update\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/voiceprobe-agent-native update --strict --scheduled --instance '+self.args.instance+'\n')
                timer.write_text('[Unit]\nDescription=WIFX Voice Probe Agent update timer\n[Timer]\nOnCalendar=*-*-* '+self.args.at+':00 UTC\nPersistent=false\n[Install]\nWantedBy=timers.target\n')
                service.chmod(0o644);timer.chmod(0o644);command(['systemctl','daemon-reload']);command(['systemctl','enable','--now',name+'.timer'])
            elif timer.exists():
                need('WIFX Voice Probe' in timer.read_text(),'Timer homonyme inconnu ; aucune modification.')
                command(['systemctl','disable','--now',name+'.timer'])
        else:
            engine=self.backend.engine;container='voiceprobe-agent-updater-'+self.args.instance
            current=engine.call('GET','/containers/'+container+'/json')
            if current:
                labels=current['Config'].get('Labels') or {}
                need(labels.get('net.wifx.project')=='voiceprobe-agent-updater' and labels.get('net.wifx.instance')==self.args.instance,
                     'Planificateur homonyme étranger ; aucune modification.')
                if current['State']['Running']:engine.call('POST','/containers/'+current['Id']+'/stop?t=30')
                engine.call('DELETE','/containers/'+current['Id']+'?v=false&force=false')
            if enable:
                declaration=self.settings['release']['docker'];image=engine.call('GET','/images/'+urllib.parse.quote(declaration['reference'],safe='')+'/json')
                need(image and image['Id'] in declaration['image_ids'],'Image de gestion locale manquante ; aucun pull implicite.')
                root=str(safe_directory(self.args.data_root));config={'Image':image['Id'],'User':'0:0','Entrypoint':['python3'],
                  'Cmd':[str(self.code/'admin/manage.py'),'watch','--strict','--backend','docker','--data-root',root,'--instance',self.args.instance,'--at',self.args.at],
                  'Labels':{'net.wifx.project':'voiceprobe-agent-updater','net.wifx.instance':self.args.instance},
                  'HostConfig':{'NetworkMode':'host','RestartPolicy':{'Name':'unless-stopped'},'Binds':['/var/run/docker.sock:/var/run/docker.sock:rw',root+':'+root+':rw',root+':/var/lib/voiceprobe:rw'],
                    'SecurityOpt':['no-new-privileges:true'],'LogConfig':{'Type':'json-file','Config':{'max-size':'5m','max-file':'3'}}}}
                result=engine.call('POST','/containers/create?name='+container,config);engine.call('POST','/containers/'+result['Id']+'/start')
        atomic(self.code/'schedule.json',{'enabled':enable,'at_utc':self.args.at})
        print('Mises à jour planifiées '+('ACTIVÉES à '+self.args.at+' UTC' if enable else 'DÉSACTIVÉES')+' ; aucun autre service modifié.')
        return 'STATUS_OK'

    def watch(self):
        need(self.args.backend=='docker' and self.settings.get('release'),'Planificateur Docker réservé aux instances déjà installées.')
        while True:
            try:plan=private_json(self.code/'schedule.json')
            except OSError:time.sleep(10);continue
            if not plan.get('enabled'):return 'STATUS_OK'
            now=dt.datetime.now(dt.timezone.utc);day=now.strftime('%Y-%m-%d')
            if now.strftime('%H:%M')==plan['at_utc'] and plan.get('last_day')!=day:
                plan['last_day']=day;atomic(self.code/'schedule.json',plan)
                result=subprocess.run([sys.executable,str(self.code/'admin/manage.py'),'update','--strict','--scheduled','--backend','docker','--instance',self.args.instance,'--data-root',self.args.data_root])
                print('Résultat mise à jour planifiée : '+str(result.returncode),flush=True)
            time.sleep(15)

    def execute(self):
        if self.args.action=='watch':return self.watch()
        if self.args.action in ('status','diagnose'):return self.report_status()
        if self.args.action=='version':
            status=self.read_status() or {}
            print('Installateur : '+INSTALLER_VERSION+'\nAgent : '+str(status.get('version','indisponible'))+'\nPJSIP : '+str(status.get('pjsip_version','indisponible')))
            return 'STATUS_OK'
        if self.args.check:return self.update()
        safe_directory(self.code,create=True)
        if self.args.backend=='native':self.code.chmod(0o755)
        with (self.code/'management.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Failure('Autre opération Agent en cours ; aucune action concurrente.') from None
            if self.args.action=='enable-schedule':return self.schedule(True)
            if self.args.action=='disable-schedule':return self.schedule(False)
            if self.args.action in ('configure','reset-password'):
                self.recover();return self.configuration(self.args.action=='reset-password')
            if self.args.action=='rollback':
                self.recover();return self.rollback()
            if not self.args.check:self.recover()
            return self.update()


class Parser(argparse.ArgumentParser):
    def error(self,message):raise Failure('Arguments invalides ; utiliser voiceprobe-agent help. Valeurs omises.')


def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv);strict='--strict' in args
    parser=Parser(description=__doc__)
    parser.add_argument('action',choices=['install','update','status','diagnose','rollback','version','help','configure','reset-password','enable-schedule','disable-schedule','watch'],nargs='?',default='help')
    parser.add_argument('--backend',choices=['native','docker'],default='native')
    parser.add_argument('--instance',default='default');parser.add_argument('--data-root',default='/var/lib/voiceprobe-agent')
    parser.add_argument('--strict',action='store_true');parser.add_argument('--check',action='store_true')
    parser.add_argument('--source');parser.add_argument('--key');parser.add_argument('--ca-file');parser.add_argument('--controller-ca')
    parser.add_argument('--controller');parser.add_argument('--name');parser.add_argument('--bind')
    parser.add_argument('--port',type=int,default=18441);parser.add_argument('--sip-port',type=int,default=5060);parser.add_argument('--rtp-base-port',type=int)
    parser.add_argument('--timeout',type=int,default=90);parser.add_argument('--drain-timeout',type=int,default=330)
    parser.add_argument('--reset-initial-password',action='store_true')
    parser.add_argument('--at',default='02:00')
    parser.add_argument('--scheduled',action='store_true');parser.add_argument('--non-interactive',action='store_true');parser.add_argument('--password-file')
    manager=None
    try:
        parsed=parser.parse_args(args)
        parsed.provided={v.split('=',1)[0] for v in args if v.startswith('--')}
        if parsed.action=='help':parser.print_help();return 0
        need(5<=parsed.timeout<=600 and 1<=parsed.drain_timeout<=900,'Délais hors limites.')
        os.umask(0o077);manager=Manager(parsed);result=manager.execute()
        print('VOICEPROBE_AGENT_RESULT='+result)
        return 0
    except (KeyboardInterrupt,EOFError):message='Interruption contrôlée ; relancer la même commande pour reprendre.'
    except Failure as error:message=str(error)
    except Exception as error:
        import traceback
        frames=traceback.extract_tb(error.__traceback__)
        frame=next((x.name for x in reversed(frames) if Path(x.filename).name=='manage.py'),'execute')
        code='VP-LOCAL-'+type(error).__name__+'-'+re.sub('[^A-Za-z0-9_]','',frame)
        message='Échec local contrôlé ; fichiers, droits, état ou contrat non conforme. Repère : '+code+'. Valeurs sensibles omises.'
    print('ÉCHEC CONTRÔLÉ — étape : '+(manager.stage if manager else 'préparation')+'\n'+message,file=sys.stderr)
    print('VOICEPROBE_AGENT_RESULT=CONTROLLED_FAILURE',file=sys.stderr)
    return 1 if strict else 0


if __name__=='__main__':sys.exit(main())
