"""Bounded, best-effort diagnostics of an observed RTP peer.

Linux traceroute uses separate probes; Windows uses the native ICMP API.
Neither adapter writes to a media transport.
"""

import datetime
import ipaddress
import os
import math
import statistics
import time
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


MEDIA_DSCP = 46
SIP_DSCP = 40
INITIAL_METHOD = "icmp" if os.name == "nt" else "udp"
PROBE_DSCP = 0 if os.name == "nt" else MEDIA_DSCP
MAX_HOPS = 20
PROBES_PER_HOP = 10
PROBE_BYTES = 100  # traceroute packet_len: includes IP and transport headers.
DIAGNOSTIC_PORT = 65000
LOCAL_PORTS = (65001, 65002)
TIMEOUT_SECONDS = 16
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vp-network")
_SLOTS = threading.BoundedSemaphore(2)
_PORT_LOCK = threading.Lock()
_USED_PORTS = set()
_LAST_STARTED = {}
SETTINGS = {'icmp_enabled': True, 'udp_enabled': True, 'probes_per_hop': 10, 'max_hops': 20,
            'probe_timeout_ms': 500, 'interval_ms': 20, 'warning_ms': 30, 'critical_ms': 100,
            'deadline_s': 16, 'udp_port': 65000, 'profile': 'standard', 'min_interval_s': 60}
LIMITS = {'probes_per_hop': (1, 10), 'max_hops': (1, 20), 'probe_timeout_ms': (20, 2000),
          'interval_ms': (10, 1000), 'warning_ms': (1, 10000), 'critical_ms': (1, 10000),
          'deadline_s': (1, 20), 'udp_port': (1024, 65535), 'min_interval_s': (10, 3600)}


def validate_settings(values):
    if not isinstance(values, dict) or set(values) != set(SETTINGS):
        raise ValueError('Incomplete network diagnostic settings')
    for name, (minimum, maximum) in LIMITS.items():
        if type(values[name]) is not int or not minimum <= values[name] <= maximum:
            raise ValueError('Invalid network diagnostic setting: ' + name)
    if any(type(values[name]) is not bool for name in ('icmp_enabled', 'udp_enabled')):
        raise ValueError('Invalid network diagnostic activation')
    if values['profile'] not in ('standard', 'deep') or values['warning_ms'] >= values['critical_ms']:
        raise ValueError('Invalid network diagnostic profile or thresholds')
    return dict(values)


def rtt_statistics(times, missed, settings):
    ordered = sorted(times)
    count = len(ordered)
    return {'sample_count': count, 'timeouts': missed, 'rtt_samples_ms': times,
            'rtt_median_ms': statistics.median(ordered) if count else None,
            'rtt_p95_ms': ordered[math.ceil(.95 * count) - 1] if count else None,
            'rtt_p99_ms': ordered[math.ceil(.99 * count) - 1] if count else None,
            'above_warning': sum(value > settings['warning_ms'] for value in times),
            'above_critical': sum(value > settings['critical_ms'] for value in times),
            'no_response_percent': 100 * missed / (count + missed) if count + missed else None}



def observed_peer(address):
    """Accept only a numeric, unicast address reported by the live media socket."""
    if not isinstance(address, str):
        return None
    match = re.fullmatch(r"\[([^]]+)\]:(\d{1,5})|([^:]+):(\d{1,5})", address)
    if not match:
        return None
    host = match.group(1) or match.group(3)
    port = int(match.group(2) or match.group(4))
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if (not 1 <= port <= 65535 or ip.is_unspecified or ip.is_multicast or ip.is_link_local
            or (ip.is_reserved and not ip.is_loopback)):
        return None
    return str(ip)


def unavailable(reason, method="udp", peer=None, settings=None):
    result = {"method": method, "status": "unavailable", "reason": reason,
            "peer": peer, "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "parameters": {"probes_per_hop": PROBES_PER_HOP, "max_hops": MAX_HOPS,
                           "packet_bytes": PROBE_BYTES, "packet_size_scope": "IP packet including transport header",
                           "dscp": PROBE_DSCP, "timeout_s": TIMEOUT_SECONDS}, "hops": []}
    if settings is not None:
        settings = validate_settings(settings)
        result['parameters'].update(settings)
        result['parameters'].update(protocol=2, timeout_s=settings['deadline_s'],
                                    percentile_method='nearest-rank', max_probes=settings['max_hops'] * settings['probes_per_hop'])
    return result


def _parse_report(output, settings=None):
    """Parse the bounded numeric output of Linux traceroute 2.1.x."""
    hops = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match:
            continue
        ttl = int(match.group(1))
        if not 1 <= ttl <= MAX_HOPS or len(hops) >= MAX_HOPS:
            continue
        body = match.group(2)
        times = [float(value) for value in re.findall(r"(?<!\S)(\d+(?:\.\d+)?)\s+ms\b", body)]
        missed = len(re.findall(r"(?<!\S)\*(?!\S)", body))
        sent = len(times) + missed
        if not 1 <= sent <= PROBES_PER_HOP:
            continue
        address = None
        for token in body.split():
            try:
                address = str(ipaddress.ip_address(token.strip("()")))
                break
            except ValueError:
                pass
        hops.append({"ttl": ttl, "address": address, "sent": sent, "responses": len(times),
                     "rtt_min_ms": round(min(times), 3) if times else None,
                     "rtt_avg_ms": round(sum(times) / len(times), 3) if times else None,
                     "rtt_max_ms": round(max(times), 3) if times else None,
                     "status": "responded" if times else "no_response"})
        if settings is not None:
            hops[-1].update(rtt_statistics(times, missed, settings))
    return hops


def _run(method, peer, local_port=65001, settings=None):
    result = unavailable("pending", method, peer, settings)
    if os.name == "nt":
        if method != "icmp":
            result.update(status="unavailable", reason="udp_requires_admin_on_windows")
            return result
        try:
            from windows_icmp_diagnostics import run as run_windows_icmp
            return run_windows_icmp(peer, result, max_hops=MAX_HOPS,
                                    probes_per_hop=PROBES_PER_HOP,
                                    timeout_s=TIMEOUT_SECONDS, packet_bytes=PROBE_BYTES)
        except PermissionError:
            result.update(status="unavailable", reason="icmp_permission_denied")
        except (OSError, ValueError, AttributeError):
            result.update(status="unavailable", reason="icmp_api_unavailable")
        return result
    # Native releases carry a private capability-scoped copy. Docker images use
    # the packaged system binary, which is likewise capability-scoped.
    private_binary = Path(__file__).resolve().parents[2] / "bin" / "traceroute"
    binary = str(private_binary) if private_binary.is_file() else shutil.which("traceroute")
    if binary is None:
        result.update(status="unavailable", reason="traceroute_absent")
        return result
    parameters = settings or SETTINGS
    arguments = [binary, "-n", "-q", str(parameters['probes_per_hop']), "-m", str(parameters['max_hops']), "-N", "1",
                 "-t", str(MEDIA_DSCP << 2)]
    if method == "udp":
        arguments.extend(["-U", "--sport=" + str(local_port), "-p", str(parameters['udp_port'])])
    else:
        arguments.append("-I")
    if settings is not None:
        # Disable adaptive timeout multipliers; report the exact requested wait.
        arguments.extend(['-z', str(settings['interval_ms'] / 1000)])
    wait = str(parameters['probe_timeout_ms'] / 1000) + ',0,0' if settings is not None else '0.5'
    arguments.extend(["-w", wait, peer, str(PROBE_BYTES)])
    try:
        process = subprocess.run(arguments, capture_output=True, text=True, timeout=parameters['deadline_s'],
                                 check=False, shell=False, env={**os.environ, 'LC_ALL': 'C'})
        if process.returncode:
            reason = ("icmp_permission_denied" if method == "icmp" and
                      ("Operation not permitted" in process.stderr or "not enough privileges" in process.stderr)
                      else "traceroute_failed")
            result.update(status="unavailable", reason=reason)
            return result
        hops = _parse_report(process.stdout, settings)
        if not hops:
            result.update(status="unavailable", reason="no_hops_returned")
            return result
        result.update(status="complete", reason=None, hops=hops)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ''
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        hops = _parse_report(output, settings) if settings is not None else []
        result.update(status="partial" if hops else "unavailable", reason="timeout", hops=hops)
    except PermissionError:
        result.update(status="unavailable", reason="icmp_permission_denied" if method == "icmp" else "udp_permission_denied")
    except (OSError, UnicodeError, ValueError) as error:
        result.update(status="unavailable", reason=type(error).__name__)
    return result


def start(method, peer, settings=None):
    if method not in ("udp", "icmp") or observed_peer(f"[{peer}]:1" if ":" in peer else f"{peer}:1") != peer:
        raise ValueError("Diagnostics require an observed numeric RTP peer")
    if settings is not None:
        settings = validate_settings(settings)
        if not settings[method + '_enabled']:
            return None
    if not _SLOTS.acquire(blocking=False):
        return None
    with _PORT_LOCK:
        if settings is not None and time.monotonic() - _LAST_STARTED.get(method, -float('inf')) < settings['min_interval_s']:
            _SLOTS.release()
            return None
        _LAST_STARTED[method] = time.monotonic()
        local_port = next(port for port in LOCAL_PORTS if port not in _USED_PORTS)
        _USED_PORTS.add(local_port)

    def task():
        try:
            return _run(method, peer, local_port, settings)
        finally:
            with _PORT_LOCK:
                _USED_PORTS.remove(local_port)
            _SLOTS.release()

    return _POOL.submit(task)


def set_dscp(transport, binding, value):
    """Request exact PJSIP DSCP on Linux; keep Windows socket defaults."""
    if os.name == "nt":
        return
    params = binding.pj_qos_params()
    params.flags = binding.PJ_QOS_PARAM_HAS_DSCP
    params.dscp_val = value
    transport.qosParams = params
