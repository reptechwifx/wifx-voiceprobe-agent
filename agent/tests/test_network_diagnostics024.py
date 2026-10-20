"""Targeted boundaries for the 0.9-024 network probe adapter."""

import pathlib
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import network_diagnostics as network


class NetworkDiagnosticsTest(unittest.TestCase):
    def test_windows_keeps_default_socket_qos(self):
        transport = types.SimpleNamespace()
        binding = types.SimpleNamespace(pj_qos_params=lambda: self.fail("Windows requested QoS"))
        with patch.object(network.os, "name", "nt"):
            network.set_dscp(transport, binding, network.MEDIA_DSCP)
        self.assertFalse(hasattr(transport, "qosParams"))

    def test_only_observed_numeric_unicast_peer_is_accepted(self):
        self.assertEqual(network.observed_peer("192.0.2.10:4000"), "192.0.2.10")
        self.assertEqual(network.observed_peer("[2001:db8::10]:4000"), "2001:db8::10")
        for value in ("sip.example:5060", "192.0.2.0/24", "224.0.0.1:4000", "255.255.255.255:4000", "240.0.0.1:4000", "0.0.0.0:4000", "fe80::1", "192.0.2.10:0"):
            self.assertIsNone(network.observed_peer(value))
        with self.assertRaises(ValueError):
            network.start("udp", "192.0.2.0/24")

    def test_traceroute_uses_bounded_arguments_and_dscp_octet(self):
        output = "traceroute to 192.0.2.10 (192.0.2.10), 20 hops max, 100 byte packets\n 1  192.0.2.1  1.0 ms  2.0 ms  3.0 ms  4.0 ms  5.0 ms  *  *  *  *  *\n"
        completed = type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()
        with patch.object(network.shutil, "which", return_value="/usr/bin/traceroute"), patch.object(network.subprocess, "run", return_value=completed) as runner:
            result = network._run("udp", "192.0.2.10")
        args = runner.call_args.args[0]
        self.assertEqual(args[args.index("-t") + 1], "184")
        self.assertEqual(args[args.index("-p") + 1], "65000")
        self.assertIn("--sport=65001", args)
        self.assertEqual(args[-1], "100")
        self.assertEqual(runner.call_args.kwargs["timeout"], 16)
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(result["hops"][0]["responses"], 5)
        self.assertEqual(result["hops"][0]["rtt_avg_ms"], 3)

    def test_missing_tool_is_explicit_and_does_not_affect_media(self):
        with patch.object(network.shutil, "which", return_value=None):
            result = network._run("udp", "192.0.2.10")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "traceroute_absent")
        self.assertEqual(result["hops"], [])

    def test_icmp_permission_denied_is_explicit(self):
        completed = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "socket: Operation not permitted"})()
        with patch.object(network.shutil, "which", return_value="/usr/bin/traceroute"), patch.object(network.subprocess, "run", return_value=completed):
            result = network._run("icmp", "127.0.0.1")
        self.assertEqual(result["reason"], "icmp_permission_denied")

    def test_file_capability_exec_refusal_is_explicit(self):
        with patch.object(network.shutil, "which", return_value="/usr/bin/traceroute"), patch.object(network.subprocess, "run", side_effect=PermissionError(1, "Operation not permitted")):
            self.assertEqual(network._run("icmp", "127.0.0.1")["reason"], "icmp_permission_denied")
            self.assertEqual(network._run("udp", "127.0.0.1")["reason"], "udp_permission_denied")

    def test_empty_traceroute_report_is_unavailable_even_when_tool_exits_zero(self):
        completed = type("Result", (), {"returncode": 0, "stdout": "traceroute to 127.0.0.1 (127.0.0.1), 20 hops max, 100 byte packets\n", "stderr": ""})()
        with patch.object(network.shutil, "which", return_value="/usr/bin/traceroute"), patch.object(network.subprocess, "run", return_value=completed):
            result = network._run("udp", "127.0.0.1")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "no_hops_returned")

    def test_real_lab_ipv6_and_unanswered_hops_are_parsed_as_responses_not_loss(self):
        output = "traceroute to ::1 (::1), 20 hops max, 100 byte packets\n 1  *  *  *  *  *  *  *  *  *  *\n 2  ::1  0.049 ms  0.004 ms  0.002 ms  0.002 ms  0.002 ms  0.003 ms  0.002 ms  0.003 ms  0.003 ms  0.002 ms\n"
        hops = network._parse_report(output)
        self.assertEqual(hops[0]["responses"], 0)
        self.assertIsNone(hops[0]["address"])
        self.assertEqual(hops[1]["address"], "::1")
        self.assertEqual(hops[1]["responses"], 10)


if __name__ == "__main__":
    unittest.main()
