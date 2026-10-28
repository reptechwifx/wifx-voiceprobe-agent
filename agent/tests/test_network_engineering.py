import pathlib
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import network_diagnostics as n


class NetworkEngineeringTest(unittest.TestCase):
    def test_quantiles_include_short_latency_spikes_and_separate_timeouts(self):
        values = [1, 2, 2, 4, 90]
        result = n.rtt_statistics(values, 2, n.SETTINGS)
        self.assertEqual(result['rtt_median_ms'], 2)
        self.assertEqual(result['rtt_p95_ms'], 90)
        self.assertEqual(result['rtt_p99_ms'], 90)
        self.assertEqual(result['sample_count'], 5)
        self.assertEqual(result['above_warning'], 1)
        self.assertEqual(result['above_critical'], 0)
        self.assertEqual(result['timeouts'], 2)
        self.assertIsNone(n.rtt_statistics([], 10, n.SETTINGS)['rtt_p99_ms'])

    def test_short_timeout_is_independent_of_threshold_and_deadline(self):
        settings = dict(n.SETTINGS, probe_timeout_ms=20, warning_ms=10, critical_ms=15)
        output = types.SimpleNamespace(returncode=0, stdout='1 127.0.0.1  12.0 ms  *', stderr='')
        with patch.object(n.shutil, 'which', return_value='/usr/bin/traceroute'), patch.object(n.subprocess, 'run', return_value=output) as run:
            result = n._run('udp', '127.0.0.1', settings=settings)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index('-w') + 1], '0.02,0,0')
        self.assertEqual(run.call_args.kwargs['timeout'], 16)
        self.assertEqual(result['hops'][0]['above_warning'], 1)
        self.assertEqual(result['hops'][0]['above_critical'], 0)
        self.assertEqual(result['parameters']['probe_timeout_ms'], 20)
        self.assertEqual(result['parameters']['max_probes'], 200)

    def test_partial_measurements_survive_global_timeout(self):
        error = subprocess.TimeoutExpired(['traceroute'], 16, output=b'1 127.0.0.1  12.0 ms  *\n')
        with patch.object(n.shutil, 'which', return_value='/usr/bin/traceroute'), patch.object(n.subprocess, 'run', side_effect=error):
            result = n._run('icmp', '127.0.0.1', settings=n.SETTINGS)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['hops'][0]['responses'], 1)
        self.assertEqual(result['hops'][0]['timeouts'], 1)

    def test_settings_reject_unbounded_or_ambiguous_values(self):
        for key, value in [('probe_timeout_ms', 19), ('probes_per_hop', 11), ('max_hops', True), ('profile', 'unknown'), ('udp_enabled', 1)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                n.validate_settings(dict(n.SETTINGS, **{key: value}))
        with self.assertRaises(ValueError):
            n.validate_settings(dict(n.SETTINGS, warning_ms=100))
