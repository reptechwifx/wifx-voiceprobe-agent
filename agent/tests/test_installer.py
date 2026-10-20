"""Signed Agent delivery and interruption safety. No production/real Docker access."""
import copy
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import tarfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('agent_manager',ROOT/'agent/installer/manage.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class CryptographicDistribution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        cls.key=cls.root/'key';cls.pub=cls.root/'pub';cls.cert=cls.root/'cert'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-keyout',str(cls.key),'-out',str(cls.cert)],check=True,capture_output=True)
        cls.pub.write_bytes(subprocess.check_output(['openssl','pkey','-in',str(cls.key),'-pubout'],stderr=subprocess.DEVNULL))
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                cls.requests.append(self.path)
                if self.path=='/redirect':self.send_response(302);self.send_header('Location',cls.url+'/payload');self.end_headers();return
                path=cls.root/self.path.lstrip('/')
                if not path.is_file():self.send_error(404);return
                body=path.read_bytes();self.send_response(200)
                self.send_header('Content-Length',str(len(body)+10 if cls.truncate else len(body)));self.end_headers();self.wfile.write(body)
                if cls.truncate:self.close_connection=True
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cls.cert,cls.key);cls.server.socket=ctx.wrap_socket(cls.server.socket,server_side=True)
        cls.url='https://127.0.0.1:'+str(cls.server.server_port);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()

    def setUp(self):
        type(self).truncate=False;type(self).requests=[]
        self.source=m.Source(self.url,self.pub,self.cert)
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup);self.out=Path(self.folder.name)
        self.manifest={'schema':1,'installer_protocol':1,'version':'0.9-004','source_revision':'a'*40,'release_id':'0.9-004-'+'a'*12,'sequence':2,'expires':int(time.time())+3600,'data_schema':1,'rollback_compatible':True,'compatible_from':['0.9-003','0.9-004']}
        self.publish()

    def publish(self):
        (self.root/'release.json').write_text(json.dumps(self.manifest))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.key),'-out',str(self.root/'release.sig'),str(self.root/'release.json')],check=True,capture_output=True)

    def test_signed_catalog_and_exact_payload(self):
        self.assertEqual(self.manifest,self.source.manifest(self.out,minimum=2))
        data=b'qualified binary';(self.root/'payload').write_bytes(data)
        path=self.source.download('payload',self.out/'artifact',expected=hashlib.sha256(data).hexdigest(),size=len(data))
        self.assertEqual(data,path.read_bytes());self.assertEqual(0o600,path.stat().st_mode&0o777)

    def manager_catalog(self, **changes):
        raw=b'# signed management fixture\n'
        digest=hashlib.sha256(raw).hexdigest()
        values={'schema':'1','sequence':'3','expires':str(int(time.time())+3600),
                'manager':'agent-manager-'+digest[:12]+'.py','manager_sha256':digest,
                'manager_bytes':str(len(raw)),'source_revision':'a'*40,'artifact_source':''}
        values.update(changes)
        (self.root/values['manager']).write_bytes(raw)
        path=self.root/'manager.manifest';path.write_text(''.join(k+'='+v+'\n' for k,v in values.items()))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.key),'-out',str(self.root/'manager.sig'),str(path)],check=True,capture_output=True)
        return values

    def test_manager_is_signed_bounded_and_independent_of_application_catalog(self):
        values=self.manager_catalog()
        manifest=self.source.manager_manifest(self.out,minimum=3)
        self.assertEqual(values['manager_sha256'],manifest['manager_sha256'])
        manager=m.Manager.__new__(m.Manager);manager.code=self.out
        qualified=manager.refresh_manager(self.source,self.out,install=False)
        self.assertEqual(values['manager_sha256'],m.digest(qualified))
        self.assertFalse((self.out/'manager-state.json').exists())
        self.assertEqual([], [p for p in self.requests if p.endswith('/release.json')])
        (self.root/values['manager']).write_bytes(b'corrupted manager')
        qualified.unlink()
        with self.assertRaises(m.Failure):manager.refresh_manager(self.source,self.out,install=False)

    def test_manager_signature_replay_expiry_duplicate_and_origin_are_rejected_before_execution(self):
        for changes in ({'sequence':'1'},{'expires':'1'},{'schema':'2'},
                        {'artifact_source':'https://other.invalid/manager'}, {'manager_bytes':'1048577'}):
            self.manager_catalog(**changes)
            with self.assertRaises(m.Failure):self.source.manager_manifest(self.out,minimum=2)
        self.manager_catalog();(self.root/'manager.sig').write_bytes(b'invalid')
        with self.assertRaisesRegex(m.Failure,'Signature'):self.source.manager_manifest(self.out)
        self.manager_catalog()
        path=self.root/'manager.manifest'
        path.write_bytes(path.read_bytes()+b'schema=1\n')
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.key),'-out',str(self.root/'manager.sig'),str(path)],check=True,capture_output=True)
        with self.assertRaises(m.Failure):self.source.manager_manifest(self.out)

    def test_verified_manager_handoff_precedes_the_old_platform_and_dependency_logic(self):
        raw=b'''class Failure(Exception): pass
class Manager:
    def __init__(self, args):
        self.stage = 'new signed manager ran first'
        self.settings = {'handoff_verified': True}
    def update(self):
        return 'CHECK_OK'
'''
        digest=hashlib.sha256(raw).hexdigest()
        self.manager_catalog(manager='agent-manager-'+digest[:12]+'.py',manager_sha256=digest,manager_bytes=str(len(raw)))
        (self.root/('agent-manager-'+digest[:12]+'.py')).write_bytes(raw)
        manager=m.Manager.__new__(m.Manager);manager.code=self.out;manager.settings={}
        manager.args=types.SimpleNamespace(check=True,backend='native')
        manager.source=lambda:self.source
        manager.platform_key=lambda:(_ for _ in ()).throw(AssertionError('Old platform/dependency logic must not run'))
        self.assertEqual('CHECK_OK',manager.update())
        self.assertTrue(manager.settings['handoff_verified'])
        self.assertFalse((self.out/'manager-state.json').exists())

    def test_invalid_signature_replay_expiry_and_unqualified_schema(self):
        for changes in ({'sequence':0},{'expires':int(time.time())-1},{'data_schema':2},{'rollback_compatible':False},{'source_revision':'unknown'},{'installer_protocol':2}):
            with self.subTest(changes=changes):
                before=copy.deepcopy(self.manifest);self.manifest.update(changes);self.publish()
                with self.assertRaises(m.Failure):self.source.manifest(self.out,minimum=1)
                self.manifest=before
        self.publish();(self.root/'release.sig').write_bytes(b'bad signature')
        with self.assertRaisesRegex(m.Failure,'Signature'):self.source.manifest(self.out)

    def test_corruption_incomplete_size_and_temporary_cleanup(self):
        data=b'original payload';(self.root/'payload').write_bytes(data)
        for expected,size in [('0'*64,len(data)),(hashlib.sha256(data).hexdigest(),len(data)+1),(None,2)]:
            with self.assertRaises(m.Failure):self.source.download('payload',self.out/'artifact',expected=expected,size=size)
            self.assertEqual([],list(self.out.glob('*.part-*')));self.assertFalse((self.out/'artifact').exists())
        type(self).truncate=True
        with self.assertRaises(m.Failure):self.source.download('payload',self.out/'artifact',size=len(data)+10)
        self.assertEqual([],list(self.out.glob('*.part-*')))

    def test_tls_verification_redirects_and_cross_origin_names(self):
        with self.assertRaises(m.Failure):m.Source(self.url,self.pub).download('payload',self.out/'p')
        with self.assertRaisesRegex(m.Failure,'Redirection'):self.source.download('redirect',self.out/'p')
        for name in ['../secret','https://evil.invalid/secret','/payload','payload?token=secret','payload#fragment']:
            with self.assertRaises(m.Failure):self.source.download(name,self.out/'p')
        for url in ['http://localhost','https://user:secret@localhost','https://localhost/?token=secret']:
            with self.assertRaises(m.Failure):m.Source(url,self.pub)

    def test_signed_artifact_source_requires_the_official_channel_after_signature_verification(self):
        release='https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0'
        self.manifest['artifact_source']=release;self.publish()
        with self.assertRaisesRegex(m.Failure,'hors périmètre'):self.source.manifest(self.out)
        self.assertIsNone(self.source.artifact_base)
        self.source.base='https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/beta'
        def copied(name,destination,**kwargs):
            shutil.copyfile(self.root/name,destination);return destination
        with patch.object(self.source,'download',side_effect=copied):
            self.assertEqual(release,self.source.manifest(self.out)['artifact_source'])
            self.assertEqual(release,self.source.artifact_base)
            self.manifest['artifact_source']='https://github.com/other/repo/releases/download/agent-x';self.publish()
            with self.assertRaises(m.Failure):self.source.manifest(self.out)
        self.source.artifact_base=None;(self.root/'release.sig').write_bytes(b'bad signature')
        with patch.object(self.source,'download',side_effect=copied):
            with self.assertRaisesRegex(m.Failure,'Signature'):self.source.manifest(self.out)
        self.assertIsNone(self.source.artifact_base)

    def test_known_download_is_revalidated_before_reuse(self):
        data=b'known';(self.root/'payload').write_bytes(data);dest=self.out/'p';expected=hashlib.sha256(data).hexdigest()
        self.source.download('payload',dest,expected=expected,size=len(data));count=len(self.requests)
        self.source.download('payload',dest,expected=expected,size=len(data));self.assertEqual(count,len(self.requests))
        dest.write_bytes(b'tampered');self.source.download('payload',dest,expected=expected,size=len(data));self.assertEqual(data,dest.read_bytes())


class GithubPublicTransport(unittest.TestCase):
    def test_only_official_channels_and_release_paths_are_accepted(self):
        self.assertTrue(m.github_channel('https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/beta'))
        self.assertTrue(m.github_release('https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0'))
        for url in ['https://github.com/other/repo/releases/download/agent-x','https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-x/extra','https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-x?token=secret','http://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-x']:
            self.assertFalse(m.github_release(url))

    def test_github_asset_redirect_is_exact_tls_only_and_unauthenticated(self):
        base='https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-x'
        handler=m.GithubAssetRedirect(base)
        request=m.urllib.request.Request(base+'/payload.tar.gz')
        target='https://release-assets.githubusercontent.com/github-production-release-asset/123/file?signature=ephemeral'
        result=handler.redirect_request(request,None,302,'',{},target)
        self.assertEqual(target,result.full_url);self.assertEqual({'Accept':'application/octet-stream'},dict(result.header_items()))
        request.add_header('Authorization','Bearer never-forward')
        with self.assertRaises(m.Failure):handler.redirect_request(request,None,302,'',{},target)

    def test_github_redirect_rejects_unknown_origins_credentials_ports_and_downgrade(self):
        base='https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-x';handler=m.GithubAssetRedirect(base)
        for target in ['http://release-assets.githubusercontent.com/github-production-release-asset/file','https://evil.invalid/file','https://127.0.0.1/file','https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/file','https://user:secret@release-assets.githubusercontent.com/github-production-release-asset/file','https://release-assets.githubusercontent.com:444/github-production-release-asset/file','https://release-assets.githubusercontent.com/unrelated/file']:
            with self.assertRaises(m.Failure):handler.redirect_request(m.urllib.request.Request(base+'/payload'),None,302,'',{},target)
        with self.assertRaises(m.Failure):handler.redirect_request(m.urllib.request.Request('https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/beta/release.json'),None,302,'',{},'https://release-assets.githubusercontent.com/github-production-release-asset/file')


class LocalSafety(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def archive(self,name,kind=tarfile.REGTYPE):
        path=self.root/'test.tar.gz'
        with tarfile.open(path,'w:gz') as archive:
            info=tarfile.TarInfo(name);info.type=kind
            if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):info.linkname='/etc/passwd'
            info.size=0;archive.addfile(info,io.BytesIO())
        return path

    def test_archive_traversal_devices_links_and_size_refused(self):
        for name,kind in [('../outside',tarfile.REGTYPE),('/outside',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('link',tarfile.LNKTYPE),('device',tarfile.CHRTYPE)]:
            with self.subTest(name=name,kind=kind):
                with self.assertRaises(m.Failure):m.extract(self.archive(name,kind),self.root/'out',1000)
        with tarfile.open(self.root/'test.tar.gz','w:gz') as a:
            info=tarfile.TarInfo('big');info.size=100;a.addfile(info,io.BytesIO(b'x'*100))
        with self.assertRaises(m.Failure):m.extract(self.root/'test.tar.gz',self.root/'out',10)

    def test_atomic_private_state_and_symbolic_parents(self):
        path=self.root/'state.json';m.atomic(path,{'phase':'prepared'});self.assertEqual(0o600,path.stat().st_mode&0o777)
        self.assertEqual({'phase':'prepared'},m.private_json(path))
        path.chmod(0o644)
        with self.assertRaises(m.Failure):m.private_json(path)
        link=self.root/'link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(m.Failure):m.safe_directory(link/'child')

    def test_foreign_docker_resources_are_never_modified(self):
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='test'),data=self.root/'data')
        container=m.Container(manager);calls=[]
        foreign={'Config':{'Labels':{'net.wifx.project':'other-project'}},'HostConfig':{'NetworkMode':'host'},'Mounts':[]}
        container.engine=types.SimpleNamespace(call=lambda method,path,value=None: calls.append((method,path)) or foreign)
        with self.assertRaisesRegex(m.Failure,'inconnue'):container.stop()
        self.assertTrue(all(method=='GET' for method,path in calls))
        foreign['Config']['Labels']={'net.wifx.project':'voiceprobe-agent','net.wifx.instance':'test'}
        with self.assertRaisesRegex(m.Failure,'Persistance'):container.stop()
        self.assertTrue(all(method=='GET' for method,path in calls))

    def test_docker_024_network_capability_and_legacy_rollback(self):
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='test'),data=self.root/'data')
        container=m.Container(manager);created=[]
        container.inspect=lambda:None
        container.capture=lambda:{'host':{'SecurityOpt':['no-new-privileges:true','seccomp=default'],
                                            'CapDrop':['ALL'],'CapAdd':[]}}
        container.engine=types.SimpleNamespace(call=lambda method,path,value=None:
            created.append(value) or {'Id':'test-container'} if method=='POST' else {'Name':'lab'})
        container.start({'local_image_id':'sha256:new','network_diagnostics':True},start=False)
        host=created[-1]['HostConfig']
        self.assertEqual(['ALL'],host['CapDrop'])
        self.assertEqual(['NET_RAW'],host['CapAdd'])
        self.assertEqual(['seccomp=default','no-new-privileges:false'],host['SecurityOpt'])
        created.clear()
        container.start({'local_image_id':'sha256:old','network_diagnostics':False},start=False)
        legacy=created[-1]['HostConfig']
        self.assertEqual([],legacy['CapAdd'])
        self.assertEqual(['no-new-privileges:true','seccomp=default'],legacy['SecurityOpt'])

    def manager(self):
        manager=m.Manager.__new__(m.Manager);manager.code=self.root/'code';manager.code.mkdir();manager.data=self.root/'data';manager.data.mkdir()
        manager.cfg=manager.data/'config.json';m.atomic(manager.cfg,{'id':'test-id','local_password_hash':'known-hash'})
        manager.settings={};manager.state_path=manager.code/'update-state.json';manager.settings_path=manager.code/'management.json';manager.frozen=None;manager.previous={'release':str(self.root/'old')}
        manager.args=types.SimpleNamespace(scheduled=False,drain_timeout=1,backend='native')
        manager.backend=types.SimpleNamespace(status=lambda:True)
        with sqlite3.connect(manager.data/'state.sqlite') as con:con.execute('CREATE TABLE active(run_id TEXT PRIMARY KEY)')
        return manager

    def test_backup_is_real_integrity_checked_and_rejects_corruption(self):
        manager=self.manager();directory=manager.backup();manager.verify_backup(directory)
        with (directory/'persistent.tar.gz').open('ab') as output:output.write(b'corrupt')
        with self.assertRaisesRegex(m.Failure,'corrompue'):manager.verify_backup(directory)

    def test_legacy_active_call_refused_without_freezing_or_stopping(self):
        manager=self.manager();old=Path(manager.previous['release'])/'agent/src';old.mkdir(parents=True);(old/'main.py').write_text('known source')
        expected=hashlib.sha256(b'known source').hexdigest();events=[]
        manager.backend.freeze=lambda:events.append('freeze')
        with sqlite3.connect(manager.data/'state.sqlite') as con:con.execute("INSERT INTO active VALUES ('active-call')")
        with self.assertRaisesRegex(m.Failure,'actifs'):manager.drain({'legacy_main_sha256':[expected]})
        self.assertEqual([],events)

    def test_legacy_race_resumes_process_without_any_stop(self):
        manager=self.manager();old=Path(manager.previous['release'])/'agent/src';old.mkdir(parents=True);(old/'main.py').write_text('known source')
        def freeze():
            with sqlite3.connect(manager.data/'state.sqlite') as con:con.execute("INSERT INTO active VALUES ('new-call')")
            return 123
        resumed=[];manager.backend.freeze=freeze;manager.backend.thaw=resumed.append
        with self.assertRaisesRegex(m.Failure,'vient de démarrer'):manager.drain({'legacy_main_sha256':[hashlib.sha256(b'known source').hexdigest()]})
        self.assertEqual([123],resumed);self.assertIsNone(manager.frozen)

    def test_unknown_legacy_or_scheduled_legacy_always_refused(self):
        manager=self.manager();old=Path(manager.previous['release'])/'agent/src';old.mkdir(parents=True);(old/'main.py').write_text('unknown')
        with self.assertRaisesRegex(m.Failure,'non reconnu'):manager.drain({'legacy_main_sha256':[]})
        manager.args.scheduled=True
        with self.assertRaisesRegex(m.Failure,'reportée'):manager.drain({})

    def test_modern_drain_waits_for_nonce_and_completed_calls(self):
        manager=self.manager();m.atomic(manager.data/'.management-status.json',{'sampled_at':time.time(),'maintenance':{'protocol':1},'active_calls':1})
        def agent():
            deadline=time.time()+2
            while time.time()<deadline:
                try:
                    request=m.private_json(manager.data/'.update-request.json')
                    m.atomic(manager.data/'.management-status.json',{'sampled_at':time.time(),'maintenance':{'protocol':1,'paused':True,'nonce':request['nonce']},'active_calls':0,'prepared_calls':0});return
                except (OSError,ValueError):time.sleep(.01)
        thread=threading.Thread(target=agent);thread.start();manager.drain({});thread.join()
        self.assertTrue((manager.data/'.update-request.json').exists())

    def test_modern_timeout_removes_lease_and_preserves_service(self):
        manager=self.manager();m.atomic(manager.data/'.management-status.json',{'sampled_at':time.time(),'maintenance':{'protocol':1},'active_calls':1})
        with self.assertRaisesRegex(m.Failure,'délai'):manager.drain({})
        self.assertFalse((manager.data/'.update-request.json').exists())

    def test_password_reset_is_explicit_and_never_persisted_in_plaintext(self):
        manager=self.manager();manager.args=types.SimpleNamespace(reset_initial_password=True,action='install',non_interactive=False,backend='native')
        manager.backend.status=lambda:False
        m.atomic(manager.state_path,{'phase':'failed_initial','original':None,'previous':None,'initial_install':True})
        original_open=open
        def tty(path,*args,**kwargs):return io.StringIO() if path=='/dev/tty' else original_open(path,*args,**kwargs)
        with patch('builtins.open',side_effect=tty):self.assertTrue(manager.configure_new('',{}))
        self.assertEqual(28,len(manager.password))
        self.assertNotIn(manager.password,manager.cfg.read_text())
        self.assertEqual('test-id',m.private_json(manager.cfg)['id'])
        for path in manager.code.rglob('*'):
            if path.is_file():self.assertNotIn(manager.password.encode(),path.read_bytes())
        manager.settings={'release':{}}
        with self.assertRaisesRegex(m.Failure,'jamais validée'):manager.configure_new('',{})


class MaintenanceLease(unittest.TestCase):
    def test_invalid_permissions_expiry_symlink_and_live_lease(self):
        spec=importlib.util.spec_from_file_location('lease',ROOT/'agent/src/maintenance.py');lease=importlib.util.module_from_spec(spec);spec.loader.exec_module(lease)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'.update-request.json';maintenance=lease.Maintenance(d)
            self.assertFalse(maintenance.refresh());m.atomic(path,{'nonce':'a'*64,'expires':time.time()+60});self.assertTrue(maintenance.refresh())
            path.chmod(0o644);self.assertFalse(maintenance.refresh());m.atomic(path,{'nonce':'a'*64,'expires':time.time()-1});self.assertFalse(maintenance.refresh())
            m.atomic(path,{'nonce':'a'*64,'expires':time.time()+60000});self.assertFalse(maintenance.refresh())
            path.unlink();target=Path(d)/'other';m.atomic(target,{'nonce':'a'*64,'expires':time.time()+60});path.symlink_to(target);self.assertFalse(maintenance.refresh())


if __name__=='__main__':unittest.main()


class RuntimeAndRecovery(unittest.TestCase):
    def test_docker_private_ca_is_resolved_in_the_selected_persistence_only(self):
        manager=object.__new__(m.Manager);manager.args=types.SimpleNamespace(backend='docker');manager.data=Path('/srv/voiceprobe/instances/office/data')
        self.assertEqual('/srv/voiceprobe/instances/office/data/controller-ca.pem',manager.data_path('/var/lib/voiceprobe/controller-ca.pem'))
        self.assertEqual('/etc/ssl/certs/ca-certificates.crt',manager.data_path('/etc/ssl/certs/ca-certificates.crt'))
        manager.args.backend='native'
        self.assertEqual('/var/lib/voiceprobe/controller-ca.pem',manager.data_path('/var/lib/voiceprobe/controller-ca.pem'))

    def test_docker_new_image_inherits_its_runtime_defaults_and_preserves_operator_overrides(self):
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='office'),data=Path('/srv/voiceprobe/office'))
        backend=m.Container(manager) if hasattr(m,'Container') else m.Docker(manager)
        item={'Image':'sha256:old','State':{'Running':True},'Config':{'Env':['PATH=/old-venv/bin:/usr/bin','PYTHONPATH=/old','CONFIG_FILE=/var/lib/voiceprobe/config.json','SITE=office'],'Labels':{'net.wifx.project':'voiceprobe-agent','net.wifx.instance':'office'}},'HostConfig':{}}
        backend.inspect=lambda:item
        backend.engine=types.SimpleNamespace(call=lambda *args:{'Config':{'Env':['PATH=/old-venv/bin:/usr/bin','PYTHONPATH=/old']}})
        captured=backend.capture()
        self.assertEqual(['CONFIG_FILE=/var/lib/voiceprobe/config.json','SITE=office'],captured['config']['Env'])
        self.assertEqual('sha256:old',captured['local_image_id'])

    def test_restore_handles_an_already_stopped_docker_container(self):
        backend=object.__new__(m.Container)
        backend.inspect=lambda:{'Id':'own-stopped-container','State':{'Running':False}}
        calls=[]
        backend.engine=types.SimpleNamespace(call=lambda *args:calls.append(args))
        started=[];backend.start=lambda declaration,start=True:started.append((declaration,start))
        previous={'local_image_id':'verified-prior-image','was_running':True}
        backend.restore(previous)
        self.assertEqual([],calls)  # Docker returns HTTP304 if stop is repeated.
        self.assertEqual([(previous,True)],started)

    def test_native_thaw_refuses_a_reused_pid(self):
        native=object.__new__(m.Native);native.frozen_marker=(os.getpid(),'not-the-real-start-time')
        with patch.object(m.os,'kill') as kill:
            with self.assertRaisesRegex(m.Failure,'PID historique'):native.thaw(os.getpid())
            kill.assert_not_called()

    def test_legacy_watchdog_resumes_the_process_when_the_manager_is_killed(self):
        import signal,sys
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'agent/src/main.py';source.parent.mkdir(parents=True);source.write_text('import time\nwhile True:time.sleep(.1)\n')
            child=subprocess.Popen([sys.executable,str(source)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            owner=None
            try:
                while not Path('/proc/'+str(child.pid)+'/cmdline').read_bytes():time.sleep(.01)
                owner_code="import importlib.util,types,sys,time;from pathlib import Path;s=importlib.util.spec_from_file_location('m',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);n=object.__new__(m.Native);n.pid=lambda:int(sys.argv[2]);n.freeze();Path(sys.argv[3]).touch();time.sleep(30)"
                ready=root/'ready';owner=subprocess.Popen([sys.executable,'-c',owner_code,str(ROOT/'agent/installer/manage.py'),str(child.pid),str(ready)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                until=time.monotonic()+5
                while not ready.exists() and time.monotonic()<until:time.sleep(.02)
                self.assertTrue(ready.exists())
                self.assertEqual('T',Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(') ',1)[1].split()[0])
                owner.kill();owner.wait(timeout=3)
                until=time.monotonic()+3
                while time.monotonic()<until:
                    state=Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(') ',1)[1].split()[0]
                    if state!='T':break
                    time.sleep(.02)
                self.assertNotEqual('T',state)
            finally:
                if owner and owner.poll() is None:owner.kill();owner.wait()
                child.send_signal(signal.SIGCONT);child.terminate();child.wait(timeout=3)


class JournalConsistency(unittest.TestCase):
    def test_interruption_after_settings_commit_restores_the_prior_catalog(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);manager=object.__new__(m.Manager);manager.data=root/'data';manager.data.mkdir()
            manager.settings_path=root/'settings.json';manager.state_path=root/'operation.json';manager.args=types.SimpleNamespace(backend='native')
            old={'release':{'release_id':'prior'},'sequence':2};manager.settings={'release':{'release_id':'target'},'sequence':3}
            m.atomic(manager.settings_path,manager.settings)
            m.atomic(manager.state_path,{'phase':'started','previous':{'release':'prior-directory'},'settings_before':old})
            restored=[];manager.backend=types.SimpleNamespace(restore=restored.append)
            verified=[]
            manager.verify=lambda release,expected,minimum_sample:verified.append((release,expected,minimum_sample))
            before=time.time();manager.recover()
            self.assertEqual([{'release':'prior-directory'}],restored)
            self.assertEqual(old,m.private_json(manager.settings_path));self.assertEqual(old,manager.settings)
            self.assertEqual(1,len(verified));self.assertEqual((old['release'],0),verified[0][:2]);self.assertGreaterEqual(verified[0][2],before)
            self.assertEqual('recovered_previous',m.private_json(manager.state_path)['phase'])

    def test_incomplete_first_install_does_not_keep_a_committed_success_catalog(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);manager=object.__new__(m.Manager);manager.data=root/'data';manager.data.mkdir()
            manager.settings_path=root/'settings.json';manager.state_path=root/'operation.json';manager.settings={'release':{'release_id':'unverified'}}
            m.atomic(manager.settings_path,manager.settings);m.atomic(manager.state_path,{'phase':'started','previous':None,'settings_before':{},'initial_install':True})
            stopped=[];manager.backend=types.SimpleNamespace(status=lambda:True,stop=lambda:stopped.append(True))
            manager.recover()
            self.assertEqual([True],stopped);self.assertFalse(manager.settings_path.exists());self.assertEqual({},manager.settings)
            self.assertEqual('recovered_initial',m.private_json(manager.state_path)['phase'])


class SecretDiagnostics(unittest.TestCase):
    def test_unexpected_error_does_not_disclose_exception_message(self):
        import contextlib
        manager=types.SimpleNamespace(stage='qualification',execute=lambda:(_ for _ in ()).throw(OSError('password=private-sip-password token=private-token')))
        output=io.StringIO()
        with patch.object(m,'Manager',return_value=manager),contextlib.redirect_stderr(output):
            result=m.main(['status','--strict'])
        self.assertEqual(1,result);self.assertIn('CONTROLLED_FAILURE',output.getvalue());self.assertIn('VP-LOCAL-OSError',output.getvalue())
        self.assertNotIn('private-sip-password',output.getvalue());self.assertNotIn('private-token',output.getvalue())

    def test_only_the_known_legacy_credentials_file_is_retired(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=object.__new__(m.Manager);manager.data=Path(folder);manager.cfg=manager.data/'config.json'
            m.atomic(manager.cfg,{'local_password_hash':'unchanged-hash'});secret=manager.data/'install-credentials.json'
            m.atomic(secret,{'username':'admin','password':'legacy-private-password','note':'old installer'})
            manager.retire_legacy_credentials();self.assertFalse(secret.exists());self.assertEqual('unchanged-hash',m.private_json(manager.cfg)['local_password_hash'])
            m.atomic(secret,{'unknown':True})
            with self.assertRaises(m.Failure):manager.retire_legacy_credentials()
            self.assertTrue(secret.exists())


class LauncherCoexistence(unittest.TestCase):
    def test_native_keeps_an_existing_foreign_command_and_installs_its_own_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'bin').mkdir();code=root/'code';code.mkdir();source=root/'manager-source.py';source.write_text('# verified fixture manager\n')
            command=root/'bin/voiceprobe-agent';command.write_text('# another project command\n');original=command.read_bytes()
            manager=object.__new__(m.Manager);manager.code=code;manager.args=types.SimpleNamespace(backend='native')
            def mapped(value):
                return root/'bin'/Path(value).name if str(value).startswith('/usr/local/bin/') else Path(value)
            with patch.object(m,'Path',side_effect=mapped):manager.install_command(source)
            self.assertEqual(original,command.read_bytes());self.assertTrue((root/'bin/voiceprobe-agent-native').is_file())
            self.assertEqual('voiceprobe-agent-native',manager.launcher)

    def test_specific_native_alias_is_never_overwritten_when_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'bin').mkdir();code=root/'code';code.mkdir();source=root/'source.py';source.write_text('# fixture\n')
            alias=root/'bin/voiceprobe-agent-native';alias.write_text('# foreign\n')
            manager=object.__new__(m.Manager);manager.code=code;manager.args=types.SimpleNamespace(backend='native')
            with patch.object(m,'Path',side_effect=lambda value:root/'bin'/Path(value).name):
                with self.assertRaises(m.Failure):manager.install_command(source)
            self.assertEqual('# foreign\n',alias.read_text())


class IncomingRollbackCompatibility(unittest.TestCase):
    def test_legacy_binary_is_not_started_with_an_autonomous_report_still_pending(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=m.Manager.__new__(m.Manager);manager.data=Path(folder)
            with sqlite3.connect(manager.data/'state.sqlite') as db:
                db.execute('CREATE TABLE reports(run_id TEXT,payload TEXT)')
                db.execute('INSERT INTO reports VALUES (?,?)',('synthetic',json.dumps({'incoming':{'correlation':'unrecognized'}})))
            with self.assertRaisesRegex(m.Failure,'Rapports entrants non synchronisés'):
                manager.assert_legacy_rollback_reports({'version':'0.9-004'})
            with sqlite3.connect(manager.data/'state.sqlite') as db:db.execute('DELETE FROM reports')
            manager.assert_legacy_rollback_reports({'version':'0.9-004'})
