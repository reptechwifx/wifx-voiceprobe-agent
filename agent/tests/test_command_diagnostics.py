"""Refusals must report their observed cause, never guess a saturated capacity."""
import copy
import json
import sqlite3
import threading
import types
import unittest
from unittest.mock import Mock, patch
from test_configuration import main


class CommandDiagnosticTest(unittest.TestCase):
    def setUp(self):
        self.a = main.Agent.__new__(main.Agent)
        self.a.db = sqlite3.connect(':memory:')
        self.a.db.execute('CREATE TABLE commands(id TEXT PRIMARY KEY,ok INTEGER,error TEXT,acked INTEGER DEFAULT 0)')
        self.a.lock = threading.Lock()
        self.a.cfg = {'max_calls':4,'max_load_per_cpu':1.5}
        self.a.calls = {}; self.a.prepared = {}; self.a.remote = {'mode':'bidirectional','max_calls':10}
        self.a.maintenance = types.SimpleNamespace(refresh=lambda:False)
        self.a.load_average = lambda:0
        self.a.journal = main.EventJournal()
        self.account = types.SimpleNamespace(config={'id':1,'server':'pbx.test','max_calls':20,'max_duration_s':300,'call_mode':'bidirectional','codecs':['PCMU/8000'],'destination_policy':'account-public-v1','public_calls_enabled':False}, registration_code=200, registration_active=True)
        self.a.accounts = {1:self.account}
        self.command = {'id':'cmd','kind':'prepare','payload':{'run_id':'run','account_id':1,'duration_s':5,'audio_profile':'tone-1000','destination':'100','server':'pbx.test'}}

    def rejected(self, expected):
        self.a.execute(self.command)
        ok, error = self.a.db.execute('SELECT ok,error FROM commands').fetchone()
        self.assertFalse(ok); self.assertTrue(error.startswith(expected), error)
        self.assertNotIn('configuration, registration, or capacity',error)

    def test_missing_account_and_registration_are_distinct(self):
        self.a.accounts.clear();self.rejected('ACCOUNT_NOT_CONFIGURED:')
        self.a.db.execute('DELETE FROM commands');self.a.accounts[1]=self.account;self.account.registration_active=False
        self.rejected('ACCOUNT_NOT_REGISTERED:')

    def test_idle_local_four_controller_ten_account_twenty_accepts_prepare(self):
        self.a.execute(self.command)
        self.assertEqual((1,None),self.a.db.execute('SELECT ok,error FROM commands').fetchone())
        self.assertIn('run',self.a.prepared)

    def test_real_local_capacity_separate_from_account_capacity(self):
        self.a.calls={str(i):types.SimpleNamespace(account=object(), finished=False) for i in range(4)}
        self.rejected('AGENT_CAPACITY_EXHAUSTED:')
        self.a.db.execute('DELETE FROM commands');self.a.calls={'one':types.SimpleNamespace(account=self.account, finished=False)};self.account.config['max_calls']=1
        self.rejected('ACCOUNT_CAPACITY_EXHAUSTED:')

    def test_maintenance_and_cpu_are_never_presented_as_capacity(self):
        self.a.maintenance.refresh=lambda:True;self.rejected('MAINTENANCE_ACTIVE:')
        self.a.db.execute('DELETE FROM commands');self.a.maintenance.refresh=lambda:False;self.a.load_average=lambda:100000
        self.rejected('CPU_LOAD_EXCEEDED:')

    def test_profile_duration_codec_and_direction_are_distinct(self):
        cases=[('audio_profile','pink','AUDIO_PROFILE_UNSUPPORTED:'),('duration_s',0,'DURATION_INVALID:'),('preferred_codec','G722/16000','CODEC_UNSUPPORTED:')]
        for key,value,error in cases:
            with self.subTest(key=key):
                self.a.db.execute('DELETE FROM commands');old=copy.deepcopy(self.command['payload']);self.command['payload'][key]=value;self.rejected(error);self.command['payload']=old
        self.a.db.execute('DELETE FROM commands');self.account.config['call_mode']='caller';self.rejected('INCOMING_DISABLED:')
        self.a.db.execute('DELETE FROM commands');self.account.config['call_mode']='receiver';self.command['kind']='call';self.rejected('OUTGOING_DISABLED:')

    def test_destination_legacy_server_and_public_denials_are_distinct(self):
        self.command['kind']='call'
        self.command['payload']['server']='wrong.test';self.rejected('SIP_SERVER_MISMATCH:')
        self.a.db.execute('DELETE FROM commands');self.command['payload']['server']='pbx.test';self.account.config.pop('destination_policy');self.rejected('LEGACY_DESTINATION_DENIED:')
        self.a.db.execute('DELETE FROM commands');self.account.config['destination_policy']='account-public-v1';self.command['payload']['destination']='+41225550123';self.rejected('PUBLIC_CALLS_DISABLED:')

    def test_jitter_profile_requires_qualified_binding_and_preserves_requested_parameters(self):
        self.command['payload']['jitter_profile'] = {'mode': 'fixed', 'initial_ms': 40, 'min_prefetch_ms': 40,
            'max_prefetch_ms': 40, 'capacity_ms': 200, 'discard_algorithm': 0}
        self.a.pjsip_version = '2.17'
        self.rejected('JITTER_PROFILE_UNSUPPORTED:')
        self.assertNotIn('run', self.a.prepared)
        self.a.db.execute('DELETE FROM commands')
        self.a.pjsip_version = '2.16'
        with patch.object(main, 'jitter_profiles_supported', return_value=True):
            self.a.execute(self.command)
        self.assertEqual((1, None), self.a.db.execute('SELECT ok,error FROM commands').fetchone())
        self.assertEqual(self.a.prepared['run']['jitter_profile'], self.command['payload']['jitter_profile'])


if __name__ == '__main__':
    unittest.main()
