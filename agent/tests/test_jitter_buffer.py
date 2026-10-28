import pathlib
import sys
import types
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from jitter_buffer import JitterBufferHistory, configuration, FIELDS


class JitterBufferTest(unittest.TestCase):
    def state(self, **values):
        return types.SimpleNamespace(**{attribute: values.get(attribute, 0) for attribute in FIELDS.values()})

    def test_native_values_and_unavailable_values_are_not_inferred(self):
        collector = JitterBufferHistory(); collector.started = 0
        value = collector.observe(self.state(size=4, prefetch=2, empty=12, lost=3, discard=7), None, now=0)
        self.assertEqual(value['state']['occupancy_frames'], 4)
        self.assertEqual(value['empty'], 12)
        self.assertIsNone(value['configuration']['current_delay_ms'])
        self.assertIsNone(value['configuration']['mode'])
        self.assertIsNone(value['configuration']['overflow_events'])
        self.assertIsNone(value['clock']['utc_uncertainty_ms'])
        self.assertIsNone(collector.observe(None, None, now=1))

    def test_sampling_deltas_and_counter_discontinuity(self):
        collector = JitterBufferHistory(); collector.started = 0
        first = collector.observe(self.state(size=2, lost=3), None, now=0)
        self.assertIs(first, collector.observe(self.state(size=100), None, now=.1))
        value = collector.observe(self.state(size=4, lost=5), None, now=1)
        self.assertEqual(value['samples'][-1]['delta']['lost'], 2)
        self.assertEqual(value['occupancy_sampled']['mean_frames'], 3)
        value = collector.observe(self.state(size=3, lost=1), None, now=2)
        self.assertTrue(value['samples'][-1]['counter_discontinuity'])
        self.assertIsNone(value['samples'][-1]['delta']['lost'])
        self.assertEqual(value['samples'][-1]['segment'], 1)

    def test_bounded_history_retains_total_sample_count(self):
        collector = JitterBufferHistory(); collector.started = 0
        for n in range(700):
            value = collector.observe(self.state(size=n % 4), None, now=n)
        self.assertEqual(len(value['samples']), 601)
        self.assertEqual(value['sample_count'], 700)
        self.assertTrue(value['truncated'])

    def test_rational_frame_duration_and_tx_packetization_are_distinct(self):
        info = types.SimpleNamespace(jbInit=-1, jbMax=500, codecName='test', audCodecParam=types.SimpleNamespace(
            info=types.SimpleNamespace(frameLen=15, frameLenDenum=2, encFrameLen=10, encFrameLenDenum=1),
            setting=types.SimpleNamespace(frmPerPkt=2)))
        result = configuration(info)
        self.assertEqual(result['frame_ms'], 7.5)
        self.assertEqual(result['tx_ptime_ms'], 20)
        self.assertIsNone(result['rx_ptime_ms'])
        self.assertIsNone(result['stream_parameters']['initial_ms'])
        self.assertEqual(result['stream_parameters']['capacity_ms'], 500)

    def test_rtp_and_buffer_counters_share_a_local_sample_without_being_added(self):
        history = JitterBufferHistory(); history.started = 0
        history.observe(self.state(lost=2), None, rx={'packets': 100, 'loss': 1}, now=0)
        result = history.observe(self.state(lost=5), None, rx={'packets': 145, 'loss': 3, 'reordered': 2}, now=1)
        point = result['samples'][-1]
        self.assertEqual(point['delta']['lost'], 3)
        self.assertEqual(point['rtp_delta']['loss'], 2)
        self.assertEqual(point['rtp_delta']['packets'], 45)
        self.assertIsNone(point['playout'])
        history.new_stream()
        result = history.observe(self.state(lost=0), None, rx={'packets': 10, 'loss': 0}, now=2)
        self.assertIsNone(result['samples'][-1]['rtp_delta']['packets'])
