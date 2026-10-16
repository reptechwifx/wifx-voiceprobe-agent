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
        rows=self.observe('s 0\np 1 100 1000 1\nf 2 10\nf 1 20\nf 2 3\ns 2000\nf 2 2\nf 1 10\nf 2 1\np 51 8100 2010 1\ns 3000\n')
        self.assertEqual(rows[0],{'pending':3});a,b=rows[1:];self.assertEqual((a['received'],a['lost'],a['loss_runs']),(20,3,1));self.assertEqual((b['received'],b['lost'],b['loss_runs']),(10,3,1))
        self.assertEqual((b['total_received'],b['total_lost'],b['total_loss_runs']),(30,6,2))
        q=ReceiverQuality();q.add(a);q.add(b);self.assertEqual(len(q.snapshot('PCMU')['intervals']),2)

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
        self.assertLess(len(json.dumps(q.snapshot('G722'))),250000)

if __name__=='__main__':unittest.main()
