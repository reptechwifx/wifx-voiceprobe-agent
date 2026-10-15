import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from sdp import constrain_audio

class SdpCodecsTest(unittest.TestCase):
    SDP='v=0\r\nm=audio 4000 RTP/AVP 9 8 0 101\r\na=rtpmap:9 G722/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n'
    def test_g722_rtp_clock_maps_to_16khz_audio_capability(self):
        result=constrain_audio(self.SDP,['G722/16000'])
        self.assertIn('m=audio 4000 RTP/AVP 9\r\n',result)
        self.assertIn('a=rtpmap:9 G722/8000',result)
        self.assertNotIn('a=rtpmap:8',result)
        self.assertNotIn('a=fmtp:101',result)
    def test_explicit_codec_constrains_call_even_when_global_g722_priority_is_highest(self):
        for preferred,payload in [('G722/16000','9'),('PCMA/8000','8'),('PCMU/8000','0')]:
            result=constrain_audio(self.SDP,['G722/16000','PCMA/8000','PCMU/8000'],preferred)
            self.assertIn('m=audio 4000 RTP/AVP '+payload+'\r\n',result)
    def test_pjsip_16000_rtpmap_variant_is_normalized(self):
        self.assertIn('RTP/AVP 9\r\n',constrain_audio(self.SDP.replace('G722/8000','G722/16000/1'),['G722/16000']))

    def test_account_preference_orders_the_offer_without_inventing_negotiated_codec(self):
        offered="v=0\r\nm=audio 4000 RTP/AVP 9 0 8\r\na=rtpmap:9 G722/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
        result=constrain_audio(offered,['PCMA/8000','PCMU/8000','G722/16000'])
        self.assertIn('m=audio 4000 RTP/AVP 8 0 9',result)

if __name__=='__main__':unittest.main()
