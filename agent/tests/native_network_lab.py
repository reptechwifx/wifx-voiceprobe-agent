"""Actual Linux address replacement and Agent startup in a private net namespace.

Address replacement exercises the kernel events caused by DHCP, but this is NOT
an actual DHCP server/client lease test. No host link/route may be modified.
"""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

assert os.stat('/proc/self/ns/net').st_ino != int(os.environ['VP_LAB_PARENT_NETNS']), 'Private network namespace required'
root = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.environ['VOICEPROBE_PJSUA2_SDK'])
sys.path.insert(0, str(root / 'agent/src'))
import main


def ip(*args):
    subprocess.run(['ip', *args], check=True, capture_output=True, timeout=3)


def reachable(host):
    connection = http.client.HTTPConnection(host, 18441, timeout=2)
    try:
        connection.request('GET', '/login')
        response = connection.getresponse(); response.read()
        return response.status == 200
    finally:
        connection.close()


ip('link', 'set', 'lo', 'up')
ip('link', 'add', 'vp-test', 'type', 'dummy')
ip('link', 'set', 'vp-test', 'up')
with tempfile.TemporaryDirectory() as folder:
    cfg_path = Path(folder) / 'config.json'
    spec = importlib.util.spec_from_file_location('prepare', root / 'scripts/configure-agent.py')
    configure = importlib.util.module_from_spec(spec); spec.loader.exec_module(configure)
    configure.prepare(cfg_path, 'isolated-lab-password-only', retain_credentials=False)
    os.environ['CONFIG_FILE'] = str(cfg_path)
    agent = main.Agent()
    identity_before = hashlib.sha256((Path(folder) / 'identity.key').read_bytes()).hexdigest()
    config_before = cfg_path.read_bytes()
    observations = []; failures = []

    def movement():
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    if reachable('127.0.0.1'):
                        break
                except OSError:
                    time.sleep(.1)
            assert reachable('127.0.0.1')
            observations.append('boot_without_non_loopback_ip')
            ip('addr', 'add', '192.168.0.30/24', 'dev', 'vp-test')
            time.sleep(3)
            assert reachable('192.168.0.30')
            observations.append('network_192.168.0.30')
            ip('addr', 'del', '192.168.0.30/24', 'dev', 'vp-test')
            time.sleep(3)
            assert reachable('127.0.0.1')
            observations.append('disconnected_management_loopback_survives')
            ip('addr', 'add', '172.30.155.200/24', 'dev', 'vp-test')
            time.sleep(4)
            assert reachable('172.30.155.200')
            observations.append('network_172.30.155.200')
            ip('addr', 'del', '172.30.155.200/24', 'dev', 'vp-test')
            ip('addr', 'add', '172.30.155.201/24', 'dev', 'vp-test')
            time.sleep(4)
            assert reachable('172.30.155.201')
            observations.append('address_renewal_172.30.155.201')
            assert cfg_path.read_bytes() == config_before
            assert hashlib.sha256((Path(folder) / 'identity.key').read_bytes()).hexdigest() == identity_before
            observations.append('identity_and_configuration_unchanged')
        except BaseException as error:
            failures.append(type(error).__name__ + ': ' + str(error))
        finally:
            agent.request_stop()

    worker = threading.Thread(target=movement)
    worker.start()
    agent.run(install_signals=False, export_management=False)
    worker.join(5)
    assert not worker.is_alive() and not failures, failures
    print('VP_LAB_RESULT ' + json.dumps({'scope': 'real Linux namespace and real Agent/PJSUA2; no DHCP daemon or Controller', 'observations': observations}), flush=True)

# Real packaged traceroute, loopback only, inside the same private namespace.
from network_diagnostics import SETTINGS, _run
network_results = []
for timeout_ms in (20, 30, 50, 100):
    for method in ('udp', 'icmp'):
        settings = dict(SETTINGS, probes_per_hop=3, max_hops=1, probe_timeout_ms=timeout_ms,
                        warning_ms=10, critical_ms=50, deadline_s=2)
        result = _run(method, '127.0.0.1', settings=settings)
        assert result['status'] == 'complete', result
        assert result['hops'][0]['sample_count'] == 3, result
        assert result['hops'][0]['rtt_max_ms'] is not None, result
        network_results.append({'method': method, 'timeout_ms': timeout_ms, 'hop': result['hops'][0]})
subprocess.run(['tc','qdisc','replace','dev','lo','root','netem','delay','15ms'],check=True,capture_output=True)
try:
    settings = dict(SETTINGS, probes_per_hop=3, max_hops=1, probe_timeout_ms=100,
                    warning_ms=10, critical_ms=80, deadline_s=2)
    result = _run('icmp', '127.0.0.1', settings=settings)
    assert result['status'] == 'complete' and result['hops'][0]['above_warning'] == 3, result
    assert result['hops'][0]['timeouts'] == 0, result
    network_results.append({'case': 'actual_netem_latency_below_timeout_above_threshold', 'hop': result['hops'][0]})
finally:
    subprocess.run(['tc','qdisc','del','dev','lo','root'],check=True,capture_output=True)
print('VP_LAB_RESULT ' + json.dumps({'scope': 'real traceroute ICMP/UDP in private namespace', 'results': network_results}),flush=True)
