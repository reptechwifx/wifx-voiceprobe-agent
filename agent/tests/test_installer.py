"""Signed Agent delivery and interruption safety. No production/real Docker access."""
import copy
import errno
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
import struct
import ssl
import subprocess
import sys
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

    def test_qualified_dependencies_wait_for_dpkg_without_installing_arbitrary_packages(self):
        manager=m.Manager.__new__(m.Manager)
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stdout='')) as queried,patch.object(m,'command') as executed,patch.object(m.pwd,'getpwnam'):
            with self.assertRaises(m.Failure):manager.dependencies({'dependencies':['unqualified-package']})
            queried.assert_not_called();executed.assert_not_called()
            manager.dependencies({'dependencies':['traceroute']})
            args=executed.call_args_list[-1]
            self.assertEqual(['apt-get','-o','DPkg::Lock::Timeout=300','install','-y','--no-install-recommends','traceroute'],args.args[0])
            self.assertEqual(600,args.kwargs['timeout'])

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
        for replace_running_file in (False,True):
            with self.subTest(replace_running_file=replace_running_file):
                running=self.out/'installed-manager.py';running.write_bytes(b'# original running manager\n')
                manager=m.Manager.__new__(m.Manager);manager.code=self.out;manager.settings={}
                manager.args=types.SimpleNamespace(check=not replace_running_file,backend='native')
                manager.source=lambda:self.source
                manager.platform_key=lambda:(_ for _ in ()).throw(AssertionError('Old platform/dependency logic must not run'))
                def refresh(source,folder,install=True):
                    qualified=m.Manager.refresh_manager(manager,source,folder,install=False)
                    if replace_running_file:running.write_bytes(qualified.read_bytes())
                    return qualified
                manager.refresh_manager=refresh
                with patch.object(m,'__file__',str(running)):
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
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='test'),data=self.root/'data',code=self.root/'code')
        container=m.Container(manager);calls=[]
        foreign={'Config':{'Labels':{'net.wifx.project':'other-project'}},'HostConfig':{'NetworkMode':'host'},'Mounts':[]}
        container.engine=types.SimpleNamespace(call=lambda method,path,value=None: calls.append((method,path)) or foreign)
        with self.assertRaisesRegex(m.Failure,'inconnue'):container.stop()
        self.assertTrue(all(method=='GET' for method,path in calls))
        foreign['Config']['Labels']={'net.wifx.project':'voiceprobe-agent','net.wifx.instance':'test'}
        with self.assertRaisesRegex(m.Failure,'Persistance'):container.stop()
        self.assertTrue(all(method=='GET' for method,path in calls))

    def test_docker_024_network_capability_and_legacy_rollback(self):
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='test'),data=self.root/'data',code=self.root/'code')
        container=m.Container(manager);created=[]
        container.inspect=lambda:None
        container.capture=lambda:{'host':{'SecurityOpt':['no-new-privileges:true','seccomp=default'],
                                            'CapDrop':['ALL'],'CapAdd':[]}}
        container.engine=types.SimpleNamespace(call=lambda method,path,value=None:
            created.append(value) or {'Id':'test-container'} if method=='POST' else {'Name':'lab'})
        container.start_network=lambda image:None
        container.remove_network=lambda:None
        container.start({'local_image_id':'sha256:new','network_diagnostics':True},start=False)
        host=created[-1]['HostConfig']
        self.assertEqual(['ALL'],host['CapDrop'])
        self.assertEqual([],host['CapAdd'])
        self.assertEqual('1000:1000',created[-1]['User'])
        self.assertTrue(host['ReadonlyRootfs'])
        self.assertEqual(['seccomp=default','no-new-privileges:true'],host['SecurityOpt'])
        created.clear()
        container.start({'local_image_id':'sha256:old','network_diagnostics':False},start=False)
        legacy=created[-1]['HostConfig']
        self.assertEqual([],legacy['CapAdd'])
        self.assertEqual(['no-new-privileges:true','seccomp=default'],legacy['SecurityOpt'])

    def test_network_profile_is_required_for_027_and_preserves_024(self):
        self.assertTrue(m.network_diagnostics('0.9-025'))
        self.assertTrue(m.network_diagnostics('0.9-024'))
        self.assertFalse(m.network_diagnostics('0.9-021'))
        self.assertTrue(m.docker_network_diagnostics('0.9-027'))
        self.assertTrue(m.network_diagnostics('0.9-027'))

    def test_docker_verification_requires_effective_diagnostics_not_only_cap_add(self):
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='test'),data=self.root/'data',code=self.root/'code',settings={})
        container=m.Container(manager)
        item={'Id':'agent-id','Config':{'User':'1000:1000'},'HostConfig':{'ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':['NET_RAW'],'SecurityOpt':['no-new-privileges:false']}}
        container.inspect=lambda:item
        identifier='a'*64;calls=[]
        profile=[True]
        container.network_profile_matches=lambda:profile[0]
        proof={'profile':m.DOCKER_NETWORK_PROFILE,'uid':1000,'agent_no_new_privileges':True,'worker_no_new_privileges':True,'no_new_privileges_source':'prctl','loopback':{method:{'passed':True,'effective':[8192]} for method in ('udp','icmp')}}
        raw=json.dumps(proof).encode();frame=bytes([1,0,0,0])+len(raw).to_bytes(4,'big')+raw
        exit_code=[1];rootless=[False]
        def api(method,path,value=None,raw=False):
            calls.append((method,path,value))
            if path=='/info':return {'SecurityOptions':['name=rootless'] if rootless[0] else []}
            if path.endswith('/exec'):return {'Id':identifier}
            if path.endswith('/start'):return frame
            return {'ExitCode':exit_code[0],'Running':False}
        container.engine=types.SimpleNamespace(call=api)
        with self.assertRaisesRegex(m.Failure,'non vérifiés'):container.verify_network_profile()
        self.assertNotIn('network_profile_verified',manager.settings)
        exit_code[0]=0
        self.assertEqual(proof,container.verify_network_profile())
        self.assertEqual('1000:1000',calls[-3][2]['User'])
        rootless[0]=True
        with self.assertRaisesRegex(m.Failure,'rootless'):container.verify_network_profile()
        rootless[0]=False
        self.assertNotIn('network_profile_verified',manager.settings)
        profile[0]=False
        with self.assertRaisesRegex(m.Failure,'non conforme'):container.verify_network_profile()
        self.assertEqual(['/opt/voiceprobe-network/bin/traceroute','--vp-verify'],next(value['Cmd'] for method,path,value in calls if path.endswith('/exec')))

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
            manager.verify=lambda release,expected,minimum_sample,**options:verified.append((release,expected,minimum_sample))
            before=time.time();manager.recover()
            self.assertEqual([{'release':'prior-directory'}],restored)
            self.assertEqual(old,m.private_json(manager.settings_path));self.assertEqual(old,manager.settings)
            self.assertEqual(1,len(verified));self.assertEqual((old['release'],0),verified[0][:2]);self.assertGreaterEqual(verified[0][2],before)
            self.assertEqual('recovered_previous',m.private_json(manager.state_path)['phase'])

    def test_incomplete_first_install_does_not_keep_a_committed_success_catalog(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);manager=object.__new__(m.Manager);manager.data=root/'data';manager.data.mkdir()
            manager.settings_path=root/'settings.json';manager.state_path=root/'operation.json';manager.settings={'release':{'release_id':'unverified'}};manager.args=types.SimpleNamespace(backend='native')
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


class NetworkRollbackCompatibility(unittest.TestCase):
    def test_legacy_rollback_preserves_current_network_security_before_any_stop(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=object.__new__(m.Manager)
            manager.cfg=Path(folder)/'config.json'
            for cfg in ({'bind':'auto'}, {'bind':'0.0.0.0','management_allowed_networks':[]},
                        {'bind':'127.0.0.1','management_allowed_networks':['127.0.0.0/8']}):
                m.atomic(manager.cfg,cfg)
                with self.assertRaises(m.Failure):manager.assert_rollback_network_compatibility({'version':'0.9-027'})
                self.assertEqual(cfg,json.loads(manager.cfg.read_text()))
                manager.assert_rollback_network_compatibility({'version':'0.9-028'})
            m.atomic(manager.cfg,{'bind':'127.0.0.1'})
            manager.assert_rollback_network_compatibility({'version':'0.9-027'})


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


class DockerDiagnosticPermissions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'bin';self.path.mkdir()
        original=os.fstat
        def root_info(fd):
            info=original(fd)
            return types.SimpleNamespace(**{k:getattr(info,k) for k in ('st_mode','st_nlink','st_dev','st_ino')},st_uid=0,st_gid=0)
        self.owner=patch.object(m.os,'fstat',side_effect=root_info);self.owner.start();self.addCleanup(self.owner.stop)

    def test_real_inherited_posix_acl_and_777_normalize_before_check(self):
        acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,7,who) for tag,who in ((1,0xffffffff),(2,1001),(4,0xffffffff),(16,0xffffffff),(32,0xffffffff)))
        os.setxattr(self.path,'system.posix_acl_default',acl)
        child=self.path/'child';child.mkdir();child.chmod(0o777)
        self.assertIn('system.posix_acl_access',os.listxattr(child))
        with patch.object(m.os,'fchown'):
            proof=m.diagnostic_permissions(child,0o755,normalize=True)
        self.assertEqual('0o755',proof['mode']);self.assertEqual([],os.listxattr(child))
        self.assertIn('system.posix_acl_default',os.listxattr(self.path))

    def test_parent_acl_is_never_modified(self):
        with patch.object(m.os,'fchmod') as chmod,patch.object(m.os,'removexattr') as remove,patch.object(m.os,'getxattr',side_effect=OSError(errno.ENODATA,'absent')):
            m.diagnostic_permissions(self.path,0o755,parent=True)
        chmod.assert_not_called();remove.assert_not_called()

    def test_residual_or_unreadable_acl_refuses_success(self):
        for name,value in (('system.syno_acl_self',b'\x01\x00entry'),('user.unknown_acl',b'unknown')):
            with self.subTest(name=name),patch.object(m.os,'listxattr',return_value=[name]),patch.object(m.os,'getxattr',return_value=value):
                with self.assertRaisesRegex(m.Failure,'ACL résiduelle'):m.diagnostic_permissions(self.path,0o755)
        with patch.object(m.os,'listxattr',side_effect=PermissionError(errno.EACCES,'denied')):
            with self.assertRaisesRegex(m.Failure,'contrôle des permissions/ACL impossible'):m.diagnostic_permissions(self.path,0o755)

    def test_virtual_synology_acl_is_queried_even_when_not_listed(self):
        def attr(fd,name):
            if name=='system.syno_acl_self':return b'\x01\x00grant'
            raise OSError(errno.ENODATA,'absent')
        with patch.object(m.os,'listxattr',return_value=[]),patch.object(m.os,'getxattr',side_effect=attr):
            with self.assertRaisesRegex(m.Failure,'ACL résiduelle'):m.diagnostic_permissions(self.path,0o755)

    def test_empty_synology_native_header_and_unknown_layout(self):
        def attr(value):
            def get(fd,name):
                if name=='system.syno_acl_self':return value
                raise OSError(errno.ENODATA,'absent')
            return get
        for value in (b'',b'\x01\x00\x00\x00'):
            with patch.object(m.os,'getxattr',side_effect=attr(value)):
                m.diagnostic_permissions(self.path,0o755)
        for value in (b'\x01\x00',b'\x02\x00\x00\x00'):
            with patch.object(m.os,'getxattr',side_effect=attr(value)),self.assertRaises(m.Failure):
                m.diagnostic_permissions(self.path,0o755)

    def test_failed_chmod_foreign_owner_symlink_and_hardlink_refused(self):
        self.path.chmod(0o777)
        with patch.object(m.os,'fchown'),patch.object(m.os,'fchmod'):
            with self.assertRaisesRegex(m.Failure,'POSIX non conformes'):m.diagnostic_permissions(self.path,0o755,normalize=True)
        self.owner.stop()
        with self.assertRaisesRegex(m.Failure,'propriétaire root'):m.diagnostic_permissions(self.path,0o755)
        link=self.path.parent/'link';link.symlink_to(self.path,target_is_directory=True)
        with self.assertRaisesRegex(m.Failure,'symbolique'):m.diagnostic_permissions(link,0o755)
        program=self.path/'program';program.touch();os.link(program,self.path/'alias')
        self.owner.start()
        with self.assertRaisesRegex(m.Failure,'objet dédié'):m.diagnostic_permissions(program,0o755,directory=False)


class DockerNetworkWorker(unittest.TestCase):
    def setUp(self):
        self.worker={'__name__':'qualified_worker'}
        exec(compile(m.DOCKER_NETWORK_PROGRAM,'signed-network-worker','exec'),self.worker)

    def test_legacy_proc_without_no_new_privs_uses_kernel_api(self):
        original=Path.read_text
        def legacy(path,*args,**kwargs):
            data=original(path,*args,**kwargs)
            return '\n'.join(line for line in data.splitlines() if not line.startswith('NoNewPrivs:'))
        for kernel in ('3.10.108','4.4.302+'):
            with self.subTest(proc_layout=kernel),patch.object(Path,'read_text',legacy):
                self.assertIn('CapEff',self.worker['process_state']())
                self.assertIsInstance(self.worker['no_new_privileges'](),bool)
        # Verify true in a fresh child without changing this test process.
        code=m.DOCKER_NETWORK_PROGRAM.split("if __name__=='__main__':")[0]
        result=subprocess.run([sys.executable,'-c',code+"\nassert ctypes.CDLL(None).prctl(38,1,0,0,0)==0;assert no_new_privileges() is True"],capture_output=True,text=True)
        self.assertEqual(0,result.returncode,result.stderr)
        with patch.object(self.worker['ctypes'],'CDLL',return_value=types.SimpleNamespace(prctl=lambda *args:-1)):
            with self.assertRaises(OSError):self.worker['no_new_privileges']()

    def test_worker_refuses_unbounded_or_arbitrary_commands(self):
        request={'operation':'trace','method':'udp','peer':'127.0.0.1','queries':10,'hops':20,'wait':.5,'sport':65001}
        with patch.object(self.worker['subprocess'],'Popen') as spawn:
            for update in ({'method':'shell'},{'peer':'127.0.0.1;id'},{'peer':'224.0.0.1'},{'queries':11},{'hops':21},{'wait':60},{'sport':22},{'command':'id'}):
                with self.subTest(update=update),self.assertRaises(ValueError):self.worker['trace']({**request,**update})
            spawn.assert_not_called()

    def test_worker_profile_refuses_extra_capabilities_or_disabled_protection(self):
        manager=types.SimpleNamespace(args=types.SimpleNamespace(instance='test'))
        backend=m.Container(manager)
        item={'Image':'signed-image','Config':{'User':'0:1000','Entrypoint':['/usr/bin/python3'],'Cmd':['/opt/voiceprobe-network/bin/traceroute','--serve'],'Labels':{'net.wifx.network-code':'hash'}},'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'NetworkMode':'host','CapDrop':['ALL'],'CapAdd':['CAP_NET_RAW'],'SecurityOpt':['no-new-privileges:true'],'Tmpfs':{'/var/lib/voiceprobe':'ro,nosuid,nodev,noexec,size=4096'}}}
        self.assertTrue(backend.network_worker_matches(item,'signed-image','hash'))
        for change in ({'CapAdd':['NET_RAW','NET_ADMIN']},{'Privileged':True},{'SecurityOpt':['no-new-privileges:false']},{'ReadonlyRootfs':False},{'Tmpfs':{}}):
            with self.subTest(change=change):
                altered=json.loads(json.dumps(item));altered['HostConfig'].update(change)
                self.assertFalse(backend.network_worker_matches(altered,'signed-image','hash'))


class AutomaticBindHealthcheck(unittest.TestCase):
    def test_real_loopback_healthcheck_resolves_automatic_bind_and_rejects_stale_status(self):
        spec=importlib.util.spec_from_file_location('healthcheck',Path(__file__).resolve().parents[1]/'installer/healthcheck.py')
        health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200 if self.path=='/login' else 404);self.end_headers()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'config.json';status=path.parent/'.management-status.json'
                from unittest.mock import patch
                with patch.dict(os.environ,{'CONFIG_FILE':str(path)}):
                    for bind in ['auto','0.0.0.0','127.0.0.1']:
                        path.write_text(json.dumps({'bind':bind,'port':server.server_port}))
                        status.write_text(json.dumps({'sampled_at':time.time(),'pjsip_version':'2.16'}))
                        self.assertEqual(0,health.main())
                    status.write_text(json.dumps({'sampled_at':0,'pjsip_version':'2.16'}))
                    self.assertEqual(1,health.main())
        finally:
            server.shutdown();server.server_close();thread.join()
