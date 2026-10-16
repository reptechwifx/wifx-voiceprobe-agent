"""Differential coverage: central capacity and numeric-only Windows aggregates."""
import sys,unittest,types,math
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from session_metrics import SessionMetrics,active_metrics
from portable_gui import metric_text
from portable_runtime import portable_diagnostic
from test_configuration import main

class Quality009Test(unittest.TestCase):
 def test_central_ten_ignores_local_four_account_one_and_cpu_while_preserving_maintenance(self):
  a=main.Agent.__new__(main.Agent);a.cfg={'max_calls':4};a.remote={'capacity_protocol':2,'max_calls':10};a.maintenance=types.SimpleNamespace(refresh=lambda:False);a.load_average=lambda:100000
  account=types.SimpleNamespace(config={'max_calls':1});a.calls={str(i):types.SimpleNamespace(account=account) for i in range(9)}
  self.assertEqual(10,a.applied_capacity());self.assertIsNone(a.capacity_reason(account));a.calls['tenth']=types.SimpleNamespace(account=account);self.assertIn('AGENT_CAPACITY',a.capacity_reason(account));a.maintenance.refresh=lambda:True;self.assertIn('MAINTENANCE',a.capacity_reason(account))
 def test_legacy_controller_keeps_known_compatibility_behavior(self):
  a=main.Agent.__new__(main.Agent);a.cfg={'max_calls':4};a.remote={'max_calls':10};self.assertEqual(4,a.applied_capacity())
 def test_packet_weighting_and_audio_power_preserve_unknowns(self):
  s=SessionMetrics();self.assertIsNone(s.snapshot()['loss_percent']);s.add({'rtp':{'rx':{'packets':900,'loss':100,'jitter_ms_mean':10}},'audio':{'analyzed_s':1,'rms_dbfs':-10,'interrupted_s':.2}});s.add({'rtp':{'rx':{'packets':100,'loss':0,'jitter_ms_mean':20}},'audio':{'analyzed_s':3,'rms_dbfs':-20,'interrupted_s':0}})
  r=s.snapshot();self.assertEqual(2,r['tests']);self.assertAlmostEqual(100*100/1100,r['loss_percent']);self.assertEqual(11,r['jitter_ms']);self.assertAlmostEqual(10*math.log10(.13/4),r['rms_dbfs']);self.assertEqual(.1,r['audio_gap_s']);s.add({'audio':None});self.assertEqual(r['loss_percent'],s.snapshot()['loss_percent'])
 def test_live_values_do_not_fabricate_audio_and_client_has_no_quality_judgment(self):
  c=types.SimpleNamespace(established=True,finished=False,stats={'rx':{'packets':100,'loss':1,'jitter_ms_mean':8}});r=active_metrics([c]);self.assertEqual(8,r['jitter_ms']);self.assertIsNone(r['rms_dbfs']);self.assertEqual('—',metric_text(None,'ms'));self.assertEqual('8,00 ms',metric_text(8,'ms'));self.assertEqual('—',metric_text('secret','ms'));self.assertEqual('',portable_diagnostic({'media_evidence':'degraded'}, {'state':'authorized'}))
