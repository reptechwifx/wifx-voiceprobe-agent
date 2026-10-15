import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from incoming import correlate, reception_status, outgoing_allowed
class IncomingTest(unittest.TestCase):
 def setUp(self):
  self.id='00000000-0000-4000-8000-000000000004';self.prepared={self.id:{'account_id':1,'expires':45,'expected_user':'+41225550111','correlation_mode':'window'}};self.msg='From: <sip:+41225550111@pbx.example>\r\nCall-ID: rewritten\r\n'
 def test_no_header_never_guesses_a_run_from_caller_or_time_window(self):
  self.assertIsNone(correlate(self.prepared,1,self.msg,'10.0.0.2',['10.0.0.2'],0))
  for account,message,source,now in [(2,self.msg,'10.0.0.2',0),(1,self.msg.replace('111','112'),'10.0.0.2',0),(1,self.msg,'10.0.0.3',0),(1,self.msg,'10.0.0.2',46)]:self.assertIsNone(correlate(self.prepared,account,message,source,['10.0.0.2'],now))
  self.prepared['second']=self.prepared[self.id].copy();self.assertIsNone(correlate(self.prepared,1,self.msg,'10.0.0.2',['10.0.0.2'],0))
 def test_header_preserves_existing_protocol_and_wrong_header_never_falls_back(self):
  self.prepared[self.id]['correlation_mode']='header';self.assertIsNone(correlate(self.prepared,1,self.msg,'10.0.0.2',['10.0.0.2'],0))
  self.assertEqual(self.id,correlate(self.prepared,1,self.msg+'X-VoiceProbe-Test: '+self.id+'\r\n','10.0.0.3',[],0))
  self.prepared[self.id]['correlation_mode']='window';self.assertIsNone(correlate(self.prepared,1,self.msg+'X-VoiceProbe-Test: 00000000-0000-4000-8000-000000000005\r\n','10.0.0.2',['10.0.0.2'],0))

class AutomaticIncomingPolicyTest(unittest.TestCase):
 def test_unprepared_rewritten_call_is_admitted_without_header_or_caller_rules(self):
  self.assertEqual(180,reception_status({'call_mode':'bidirectional'},'bidirectional','192.0.2.1',{'192.0.2.1'},True))
  self.assertIsNone(correlate({},1,'From: <sip:101@pbx>\r\nCall-ID: rewritten\r\n','192.0.2.1',{'192.0.2.1'},0))
 def test_only_configured_infrastructure_direction_and_capacity_gate_admission(self):
  self.assertEqual(405,reception_status({'call_mode':'caller'},'bidirectional','192.0.2.1',{'192.0.2.1'},True))
  self.assertEqual(403,reception_status({},'bidirectional','192.0.2.2',{'192.0.2.1'},True))
  self.assertEqual(486,reception_status({},'bidirectional','192.0.2.1',{'192.0.2.1'},False))
 def test_simplified_outgoing_ignores_old_lists_and_preserves_public_boolean(self):
  c={'server':'pbx.test','destination_policy':'account-public-v1','allowed_destinations':[],'public_calls_enabled':False}
  for address in ['100','*777','sip:100@pbx.test']:
   self.assertTrue(outgoing_allowed(c,{'server':'pbx.test','destination':address}))
  for address in ['+41225550111','0041225550111','0791234567','sip:test@other.test']:
   self.assertFalse(outgoing_allowed(c,{'server':'pbx.test','destination':address}))
   self.assertTrue(outgoing_allowed(c|{'public_calls_enabled':True},{'server':'pbx.test','destination':address}))
  self.assertTrue(outgoing_allowed(c,{'server':'pbx.test','destination':'1234567890','destination_public':False}))
  self.assertFalse(outgoing_allowed(c|{'call_mode':'receiver'},{'server':'pbx.test','destination':'100'}))
