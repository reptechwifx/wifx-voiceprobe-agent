import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from remote_update import RemoteUpdate
spec=importlib.util.spec_from_file_location('remote_manager_test',Path(__file__).resolve().parents[1]/'installer/manage.py');manage=importlib.util.module_from_spec(spec);spec.loader.exec_module(manage)


class TypedHandoffTest(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.root=Path(self.folder.name);self.remote=RemoteUpdate(self.root)
        self.action={'kind':'UPDATE_AGENT','id':str(uuid.uuid4()),'target_version':'0.9-008'}
    def tearDown(self):self.folder.cleanup()

    def test_not_provisioned_means_no_handoff_and_no_shell(self):
        self.assertFalse(self.remote.capability()['enabled'])
        with self.assertRaises(ValueError):self.remote.request(self.action)
        self.assertFalse((self.root/'.remote-update-request.json').exists())

    def test_request_accepts_only_typed_id_and_version_and_is_idempotent(self):
        with patch.object(self.remote,'capability',return_value={'enabled':True}),patch.object(self.remote,'result',return_value=None):
            for body in [self.action|{'command':'touch /tmp/unsafe'}, self.action|{'source':'https://other.invalid'},self.action|{'kind':'SHELL'},self.action|{'target_version':'latest'},self.action|{'id':'../../path'}]:
                with self.subTest(body=list(body)),self.assertRaises((ValueError,TypeError)):
                    self.remote.request(body)
            self.remote.request(self.action);first=(self.root/'.remote-update-request.json').read_bytes();self.remote.request(self.action)
            self.assertEqual(first,(self.root/'.remote-update-request.json').read_bytes())
            self.assertEqual(0o600,(self.root/'.remote-update-request.json').stat().st_mode&0o777)
            with self.assertRaises(ValueError):self.remote.request(self.action|{'id':str(uuid.uuid4())})

    def test_symbolic_results_and_writable_or_unprivileged_markers_are_not_trusted(self):
        marker=self.root/'.remote-update-enabled.json';marker.write_text('{"protocol":1,"backend":"native"}');marker.chmod(0o666)
        self.assertFalse(self.remote.capability()['enabled']);marker.unlink()
        target=self.root/'foreign';target.write_text('{"protocol":1,"backend":"native"}');marker.symlink_to(target)
        self.assertFalse(self.remote.capability()['enabled'])


class OfficialUpdaterRelayTest(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.root=Path(self.folder.name);self.manager=manage.Manager.__new__(manage.Manager)
        self.manager.code=self.root/'management';self.manager.code.mkdir();self.manager.data=self.root/'data';self.manager.data.mkdir();self.manager.stage='Préparation';self.manager.args=types.SimpleNamespace()
        self.manager.recover=Mock();self.manager.update=Mock(return_value='VERIFIED_SUCCESS');self.manager.read_status=Mock(return_value={'version':'0.9-008'})
        self.request={'kind':'UPDATE_AGENT','id':str(uuid.uuid4()),'target_version':'0.9-008','created_at':time.time(),'expires':time.time()+300}
    def tearDown(self):self.folder.cleanup()
    def save(self,body=None):manage.atomic(self.manager.data/'.remote-update-request.json',body or self.request)

    def test_official_updater_is_the_only_action_and_replay_does_not_reinstall(self):
        self.save();self.assertEqual('VERIFIED_SUCCESS',self.manager.remote_apply());self.manager.update.assert_called_once();self.assertEqual('0.9-008',self.manager.args.requested_version)
        result=json.loads((self.manager.data/'.remote-update-result.json').read_text());self.assertEqual('updater_verified',result['state']);self.assertEqual('0.9-008',result['installed_version'])
        self.save();self.assertEqual('STATUS_OK',self.manager.remote_apply());self.manager.update.assert_called_once()
        with patch('subprocess.run',side_effect=AssertionError('No generic command execution')):
            self.save(self.request|{'command':'anything'})
            with self.assertRaises(manage.Failure):self.manager.remote_apply()
        self.manager.update.assert_called_once()

    def test_invalid_request_never_starts_updater_and_failed_verification_never_succeeds(self):
        for change in [{'expires':0},{'target_version':'../../bin/sh'},{'kind':'RUN'}]:
            self.save(self.request|change)
            with self.assertRaises(manage.Failure):self.manager.remote_apply()
            self.manager.update.assert_not_called()
        self.request['id']=str(uuid.uuid4())
        self.save();self.manager.read_status.return_value={'version':'0.9-007'}
        with self.assertRaises(manage.Failure):self.manager.remote_apply()
        self.assertEqual('failed',json.loads((self.manager.data/'.remote-update-result.json').read_text())['state'])

    def test_docker_relay_has_a_fixed_updater_command_and_no_agent_healthcheck(self):
        self.manager.settings={'release':{'version':'0.9-008'}}
        self.manager.cfg=self.manager.data/'config.json';self.manager.cfg.write_text('{}')
        self.manager.settings_path=self.manager.code/'management.json';self.manager.settings_path.write_text('{}')
        self.manager.args=types.SimpleNamespace(backend='docker',instance='lab008',data_root=str(self.root))
        engine=Mock();engine.call.side_effect=[None,{'Id':'lab-relay'},None]
        self.manager.backend=types.SimpleNamespace(engine=engine,capture=lambda:{'local_image_id':'sha256:fixture'})
        real_stat=Path.stat
        def root_stat(path,*args,**kwargs):
            value=real_stat(path,*args,**kwargs)
            return types.SimpleNamespace(st_uid=0,st_mode=value.st_mode)
        with patch.object(Path,'stat',root_stat):
            self.assertEqual('STATUS_OK',self.manager.remote_enable())
        config=engine.call.call_args_list[1].args[2]
        self.assertEqual({'Test':['NONE']},config['Healthcheck'])
        self.assertEqual(['python3'],config['Entrypoint'])
        self.assertEqual('remote-watch',config['Cmd'][1])
        self.assertNotIn('sh',config['Entrypoint'])
        self.assertEqual('voiceprobe-agent-remote-updater',config['Labels']['net.wifx.project'])

    def test_resume_uses_root_journal_and_preserves_same_operation(self):
        self.save();self.manager.remote_result(self.request,'running');self.save(self.request|{'expires':time.time()-1000})
        self.assertEqual('VERIFIED_SUCCESS',self.manager.remote_apply());self.manager.recover.assert_called_once();self.manager.update.assert_called_once()


if __name__=='__main__':unittest.main()
