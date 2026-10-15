import copy
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest

from test_configuration import main
from credentials import hash_password, verify_password
from journal import EventJournal


class LocalConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'config.json'
        self.agent=main.Agent.__new__(main.Agent)
        self.agent.path=self.path;self.agent.cfg={'id':'00000000-0000-4000-8000-000000000001','name':'Initial','token':'local-test-token','local_password':'existing-legacy-password','controller_url':'https://old.example','administrative':{},'max_calls':4}
        self.agent.config_lock=threading.RLock();self.agent.calls={};self.agent.adoption_state='unconfigured';self.agent.connection_generation=0;self.agent.remote=None;self.agent.inbox=queue.Queue();self.agent.journal=EventJournal();self.agent.poll_now=threading.Event();self.agent.controller_connected=False;self.agent.wss_connected=False
        self.agent.persist_config()
    def tearDown(self):self.temp.cleanup()

    def test_invalid_update_does_not_remove_existing_password_or_overwrite_configuration(self):
        before=copy.deepcopy(self.agent.cfg);disk=self.path.read_bytes()
        with self.assertRaises(ValueError):self.agent.update_local({'local_password':'NewIndividualPassword123','max_calls':0})
        self.assertEqual(self.agent.cfg,before);self.assertEqual(self.path.read_bytes(),disk)
        self.agent.update_local({'local_password':'NewIndividualPassword123'})
        self.assertNotIn('local_password',self.agent.cfg)
        self.assertTrue(verify_password('NewIndividualPassword123',self.agent.cfg))
        self.assertNotIn('NewIndividualPassword123',self.path.read_text())

    def test_invalid_url_does_not_replace_existing_ca(self):
        directory=Path(self.temp.name);cert=directory/'new.crt';key=directory/'new.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=Temporary-Unit-Test'],check=True,capture_output=True)
        tls=directory/'tls';tls.mkdir();existing=tls/'controller-ca.crt';existing.write_text('existing-public-ca')
        self.agent.cfg['ca_file']=str(existing);self.agent.persist_config();before=self.path.read_bytes()
        with self.assertRaises(ValueError):self.agent.update_local({'controller_ca':cert.read_text(),'controller_url':'http://unsafe.example'})
        self.assertEqual(existing.read_text(),'existing-public-ca');self.assertEqual(self.path.read_bytes(),before)

    def test_blank_coordinates_can_clear_values_and_invalid_coordinates_do_not_persist(self):
        self.agent.update_local({'administrative':{'latitude':'','longitude':'','site':'Prepared'}})
        self.assertIsNone(self.agent.cfg['administrative']['latitude']);self.assertIsNone(self.agent.cfg['administrative']['longitude'])
        before=self.path.read_bytes()
        with self.assertRaises(ValueError):self.agent.update_local({'administrative':{'latitude':'91'}})
        self.assertEqual(self.path.read_bytes(),before)
