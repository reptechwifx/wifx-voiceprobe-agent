import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from rtp_quality import ReceiverQuality, percentile


class ReceiverPrecisionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.driver = pathlib.Path(cls.temp.name) / 'observer'
        subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-O2', str(ROOT / 'tests/fixtures/rtp-observer-driver.c'), '-lm', '-o', str(cls.driver)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def observe(self, data):
        result = subprocess.run([str(self.driver)], input=data, text=True, capture_output=True, check=True)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_reference_transit_dataset_exact_mean_and_bounded_p95(self):
        rows=self.observe('p 1 9000 1000 123\np 2 9160 1030 123\np 3 9320 1045 123\np 4 9480 1080 123\nf 1 4\ns 1081\n')
        q=ReceiverQuality();q.add(rows[0]);timing=q.snapshot('PCMA/8000')['timing'];h=timing['histogram']
        self.assertEqual(h['count'],4);self.assertEqual(h['sum_ms']/4-h['min_ms'],8.75)
        self.assertEqual(h['max_ms']-h['min_ms'],20);self.assertLessEqual(abs(percentile(q.histogram,q.count,.25)-20),.25)
        self.assertEqual(q.snapshot('PCMA/8000')['playout']['profile'],'pjsip-wsola')

    def test_timestamp_sequence_wrap_reorder_duplicate_and_late_exclusion(self):
        ts=0xffffff60
        packets=[(65534,ts,1000),(65535,(ts+160)&0xffffffff,1020),(1,(ts+480)&0xffffffff,1060),(0,(ts+320)&0xffffffff,1070),(1,(ts+480)&0xffffffff,1071)]
        text=''.join(f'p {s} {t} {a} 9\n' for s,t,a in packets)+'s 1080\n'
        o=self.observe(text)[0];self.assertTrue(o['valid']);self.assertEqual(o['samples'],4);self.assertEqual(o['duplicates'],1);self.assertEqual(o['reordered'],1);self.assertEqual(o['max_ms'],30)
        self.assertEqual(o['min_ms'],0)

    def test_loss_runs_span_intervals_without_double_counting(self):
        rows=self.observe('s 0\np 1 100 1000 1\nf 0 10\nf 1 20\nf 0 3\ns 2000\nf 0 2\nf 1 10\nf 0 1\np 51 8100 2010 1\ns 3000\n')
        self.assertEqual(rows[0],{'pending':3});a,b=rows[1:];self.assertEqual((a['received'],a['lost'],a['loss_runs']),(20,3,1));self.assertEqual((b['received'],b['lost'],b['loss_runs']),(10,3,1))
        self.assertEqual((b['total_received'],b['total_lost'],b['total_loss_runs']),(30,6,2))
        self.assertEqual(a['distribution_protocol'], 2)
        self.assertEqual((a['interval_loss_runs'], b['interval_loss_runs']), (1, 2))
        self.assertFalse(a['interval_starts_lost']);self.assertTrue(a['interval_ends_lost'])
        self.assertTrue(b['interval_starts_lost']);self.assertTrue(b['interval_ends_lost'])
        q=ReceiverQuality();q.add(a);q.add(b);snapshot=q.snapshot('PCMU')
        self.assertEqual(len(snapshot['intervals']),2)
        self.assertEqual(snapshot['playout']['loss_runs'],2)
        self.assertEqual(snapshot['intervals'][1]['playout']['loss_runs'],2)
        self.assertEqual(snapshot['intervals'][1]['playout']['distribution_protocol'],2)

    def test_codec_or_decoder_format_change_invalidates_mos_without_changing_pdv(self):
        rows=self.observe('p 1 100 1000 1\np 2 260 1020 1\nf 1 100\ns 2000\np 3 420 1040 1\nf 1 100\ns 3000\n')
        q=ReceiverQuality().add(rows[0], 'G722/16000').add(rows[1], 'PCMA/8000')
        snapshot=q.snapshot('PCMA/8000')
        self.assertFalse(snapshot['playout']['valid'])
        self.assertFalse(snapshot['playout']['format_stable'])
        self.assertTrue(snapshot['timing']['clock_stable'])
        self.assertEqual(snapshot['playout']['observed_codecs'], ['G722/16000','PCMA/8000'])

    def test_old_protocol_stays_accepted_without_inventing_interval_boundaries(self):
        row=self.observe('p 1 100 1000 1\np 2 260 1020 1\nf 1 100\nf 0 2\ns 3000\n')[0]
        for key in ['distribution_protocol','interval_loss_runs','interval_starts_lost','interval_ends_lost']:
            row.pop(key)
        snapshot=ReceiverQuality().add(row).snapshot('PCMA')
        self.assertEqual(snapshot['playout']['distribution_protocol'],1)
        self.assertIsNone(snapshot['intervals'][0]['playout']['starts_lost'])

    def test_ssrc_restart_and_extreme_transit_are_explicitly_invalid(self):
        for text in ['p 1 100 1000 1\np 2 260 1020 2\ns 1100\n','p 1 100 1000 1\np 2 260 4020 1\ns 4100\n']:
            q=ReceiverQuality();q.add(self.observe(text)[0]);self.assertFalse(q.snapshot()['timing']['clock_stable'])

    def test_negative_transit_and_interval_reference_retains_whole_call_minimum(self):
        q=ReceiverQuality()
        for o in self.observe('p 1 100 1000 1\np 2 260 1030 1\ns 1040\np 3 420 1035 1\np 4 580 1060 1\ns 1080\n'):q.add(o)
        snapshot=q.snapshot('PCMA');self.assertEqual(snapshot['timing']['histogram']['min_ms'],-5)
        self.assertEqual(snapshot['intervals'][0]['timing']['reference_min_ms'],-5)
        self.assertEqual(snapshot['intervals'][1]['timing']['reference_min_ms'],-5)

    def test_storage_is_bounded_for_a_ten_minute_call(self):
        q=ReceiverQuality()
        for i in range(300):
            o=self.observe(f'p 1 100 1000 1\np 2 260 1020 1\ns {3000+i*2000}\n')[0]
            o['elapsed_ms']=(i+1)*2000;q.add(o)
        self.assertEqual(q.count,600);self.assertEqual(len(q.histogram),1);self.assertEqual(len(q.intervals),300)
        self.assertLess(len(json.dumps(q.snapshot('G722'))),320000)

    def test_dtmf_decoder_erasures_remain_raw_but_audio_phase_uses_later_counters(self):
        rows = self.observe('p 1 100 1000 1\np 2 260 1020 1\nf 1 200\nf 0 300\ns 10000\n'
                            'p 3 420 11000 1\np 4 580 11020 1\nf 1 200\ns 12000\n')
        q = ReceiverQuality().add(rows[0], 'PCMA/8000')
        q.begin_audio_phase()
        q.add(rows[1], 'PCMA/8000')
        result = q.snapshot('PCMA/8000')
        self.assertEqual(result['playout']['lost'], 300)
        self.assertEqual(result['audio_phase']['playout']['lost'], 0)
        self.assertEqual(result['audio_phase']['playout']['received'], 200)
        self.assertEqual([i['phase'] for i in result['intervals']], ['identification', 'audio'])

    def test_network_sequence_gaps_are_corrected_by_late_packets(self):
        rows = self.observe('p 1 100 1000 7\np 2 260 1020 7\ns 2000\n'
                            'p 4 580 3020 7\ns 3030\n'
                            'p 3 420 5000 7\np 3 420 5001 7\ns 5010\n')
        q = ReceiverQuality()
        for row in rows:
            q.add(row, 'PCMA/8000')
        network = q.snapshot('PCMA/8000')['network_timeline']
        self.assertEqual((network['received_unique'], network['missing_final'], network['expected']), (4, 0, 4))
        self.assertEqual([(p['offset_s'], p['missing_final']) for p in network['intervals']], [(0, 0), (2, 0), (4, 0)])
        self.assertEqual((network['intervals'][2]['gap_recovered'], network['intervals'][2]['duplicates']), (1, 1))

    def test_network_loss_and_local_buffer_interruption_are_separate_observations(self):
        lost_packet = self.observe('p 1 100 1000 7\np 2 260 1020 7\np 4 580 1060 7\nf 1 200\ns 1070\n')[0]
        network = ReceiverQuality().add(lost_packet, 'PCMA/8000').snapshot('PCMA/8000')['network_timeline']
        self.assertEqual((network['received_unique'], network['missing_final'], network['expected']), (3, 1, 4))
        self.assertEqual(network['intervals'][0]['audio_missing'], 1)
        self.assertEqual(lost_packet['total_lost'], 0)

        local_interruption = self.observe('p 1 100 1000 7\np 2 260 1020 7\np 3 420 1040 7\n'
                                          'f 1 100\nf 3 20\nf 1 80\ns 1060\n')[0]
        result = ReceiverQuality().add(local_interruption, 'PCMA/8000').snapshot('PCMA/8000')
        self.assertEqual(result['network_timeline']['missing_final'], 0)
        self.assertEqual((result['playout']['lost'], result['playout']['empty']), (20, 20))

    def test_network_burst_dtmf_segments_and_playout_states(self):
        rows = self.observe('p 10 100 1000 7\ne 11 260 1020 7\ne 12 260 1040 7\np 13 420 1060 7\n'
                            'p 23 2020 1260 7\nf 1 100\nf 0 18\nf 3 10\nf 2 10\ns 1300\n'
                            'p 1 100 1500 8\ns 1600\n')
        q = ReceiverQuality()
        for row in rows:
            q.add(row, 'PCMA/8000')
        result = q.snapshot('PCMA/8000')
        network = result['network_timeline']
        self.assertEqual((network['received_unique'], network['missing_final'], network['expected']), (6, 9, 15))
        self.assertEqual((network['intervals'][0]['audio_missing'], network['intervals'][0]['other_missing'], network['intervals'][0]['mixed_missing']), (9, 0, 0))
        self.assertEqual(len(network['segments']), 2)
        self.assertEqual((result['playout']['missing'], result['playout']['empty'], result['playout']['prefetch']), (18, 10, 10))
        self.assertEqual(result['playout']['lost'], 38)

if __name__=='__main__':unittest.main()
