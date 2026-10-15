import pathlib,tempfile,sys,unittest,wave
import numpy as np
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from audio import reference,analyze_echo,observe_audio
class EchoAudioTest(unittest.TestCase):
 def test_round_trip_alignment_survives_codec_bandwidth_and_gain(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);src=root/'reference.wav';out=root/'received.wav';reference(src,seconds=5,rate=16000,envelope=True)
   with wave.open(str(src),'rb') as w: x=np.frombuffer(w.readframes(w.getnframes()),dtype='<i2')[::2]
   y=np.concatenate([np.zeros(9600,dtype='<i2'),(x*.75).astype('<i2')])
   with wave.open(str(out),'wb') as w:w.setparams((1,2,8000,0,'NONE',''));w.writeframes(y.tobytes())
   result=analyze_echo(out,src);self.assertEqual(1200,result['echo_delay_ms']);self.assertGreater(result['alignment_confidence'],.95);self.assertEqual(0,result['interrupted_s']);self.assertGreater(result['tone_ratio_mean'],.95);self.assertIsNone(result['direction_attribution'])
 def test_unknown_reference_never_invents_delay(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);src=root/'reference.wav';out=root/'received.wav';reference(src,seconds=3,rate=8000,envelope=True)
   with wave.open(str(out),'wb') as w:w.setparams((1,2,8000,0,'NONE',''));w.writeframes(np.zeros(24000,dtype='<i2').tobytes())
   self.assertIsNone(analyze_echo(out,src)['echo_delay_ms']);local=observe_audio(out);self.assertFalse(local['reference_available']);self.assertNotIn('interrupted_s',local);self.assertNotIn('tone_ratio_mean',local)
 def test_a_real_gap_is_retained_after_alignment(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);src=root/'reference.wav';out=root/'received.wav';reference(src,seconds=4,rate=8000,envelope=True)
   with wave.open(str(src),'rb') as w:x=np.frombuffer(w.readframes(w.getnframes()),dtype='<i2').copy()
   x[16000:18400]=0
   with wave.open(str(out),'wb') as w:w.setparams((1,2,8000,0,'NONE',''));w.writeframes(x.tobytes())
   self.assertLessEqual(abs(.3-analyze_echo(out,src)['interrupted_s']),.021)
