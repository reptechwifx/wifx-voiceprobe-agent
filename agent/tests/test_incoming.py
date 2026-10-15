import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from incoming import correlate
class IncomingTest(unittest.TestCase):
 def setUp(self):
  self.id='00000000-0000-4000-8000-000000000004';self.prepared={self.id:{'account_id':1,'expires':45,'expected_user':'+41225550111','correlation_mode':'window'}};self.msg='From: <sip:+41225550111@pbx.example>\r\nCall-ID: rewritten\r\n'
 def test_public_window_requires_trusted_pbx_exact_caller_and_unique_preparation(self):
  self.assertEqual(self.id,correlate(self.prepared,1,self.msg,'10.0.0.2',['10.0.0.2'],0))
  for account,message,source,now in [(2,self.msg,'10.0.0.2',0),(1,self.msg.replace('111','112'),'10.0.0.2',0),(1,self.msg,'10.0.0.3',0),(1,self.msg,'10.0.0.2',46)]:self.assertIsNone(correlate(self.prepared,account,message,source,['10.0.0.2'],now))
  self.prepared['second']=self.prepared[self.id].copy();self.assertIsNone(correlate(self.prepared,1,self.msg,'10.0.0.2',['10.0.0.2'],0))
 def test_header_preserves_existing_protocol_and_wrong_header_never_falls_back(self):
  self.prepared[self.id]['correlation_mode']='header';self.assertIsNone(correlate(self.prepared,1,self.msg,'10.0.0.2',['10.0.0.2'],0))
  self.assertEqual(self.id,correlate(self.prepared,1,self.msg+'X-VoiceProbe-Test: '+self.id+'\r\n','10.0.0.3',[],0))
  self.prepared[self.id]['correlation_mode']='window';self.assertIsNone(correlate(self.prepared,1,self.msg+'X-VoiceProbe-Test: 00000000-0000-4000-8000-000000000005\r\n','10.0.0.2',['10.0.0.2'],0))
