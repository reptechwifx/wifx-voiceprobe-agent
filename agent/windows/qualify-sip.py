#!/usr/bin/env python3
"""Qualification SIP/RTP Windows réelle sur PBX LAB loopback exclusivement."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import gc
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module-dir', type=Path, required=True)
    parser.add_argument('--private-fixture', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'win32' or platform.machine().upper() != 'AMD64':
        raise ValueError('Cette qualification exige Windows AMD64 réel.')
    fixture = json.loads(args.private_fixture.read_text())
    if set(fixture) != {'9701', '9702', '9703', '9704'} or not all(isinstance(value, str) and len(value) >= 16 for value in fixture.values()):
        raise ValueError('Fixture PBX LAB dédiée requise.')
    sys.path.insert(0, str(args.module_dir.resolve()))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    result = {'platform': platform.platform(), 'python': platform.python_version(), 'source_engine': 'main.Agent + ProbeAccount + ProbeCall + audio.analyze_echo', 'lab_only': True, 'pbx': '127.0.0.1:5068', 'public_or_production_calls': 0, 'registrations': [], 'calls': [], 'peak_established_calls': 0, 'passed': False}
    dll_directory = os.add_dll_directory(str(args.module_dir.resolve()))
    import main as engine

    class LabAgent(engine.Agent):
        def database_location(self):
            return ':memory:'

        def persist_config(self):
            pass

        def pending_report(self, run_id, metrics):
            metrics.pop('events', None)
            if metrics.get('audio'):
                metrics['audio'].pop('timeline', None)
            self.reports[run_id] = metrics

    with tempfile.TemporaryDirectory(prefix='WIFX-VoiceProbe-SIP-LAB-') as temporary:
        identity = str(uuid.uuid4())
        agent = LabAgent({'id': identity, 'name': 'Windows SIP LAB', 'max_calls': 8, 'sip_port': 0, 'rtp_base_port': 48000, 'max_load_per_cpu': 10000}, temporary)
        agent.reports = {}
        accounts = []
        for number, transport in (('9703', 'udp'), ('9704', 'tcp')):
            accounts.append({'id': int(number), 'username': number, 'auth_username': number, 'server': '127.0.0.1:5068', 'registrar': 'sip:127.0.0.1:5068', 'transport': transport, 'password': fixture[number], 'codecs': ['G722/16000', 'PCMA/8000', 'PCMU/8000'], 'max_calls': 4, 'max_duration_s': 20, 'allowed_destinations': ['*777']})
        try:
            agent.apply_config({'id': identity, 'name': 'Windows SIP LAB', 'mode': 'bidirectional', 'max_calls': 8, 'accounts': accounts})
            result['pjsip'] = agent.pjsip_version

            def tick():
                agent.endpoint.libHandleEvents(10)
                active = sum(call.established and not call.finished for call in agent.calls.values())
                result['peak_established_calls'] = max(active, result['peak_established_calls'])
                for run_id, call in list(agent.calls.items()):
                    call.sample()
                    if call.started and time.monotonic() - call.started >= call.duration:
                        call.hangup_safe()
                    if time.monotonic() - call.created > call.duration + 12:
                        call.hangup_safe()
                    if call.finished and call.report():
                        del agent.calls[run_id]
                call = None

            def wait(predicate, seconds):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    tick()
                    if predicate():
                        return True
                return False

            if not wait(lambda: all(account.registration_active for account in agent.accounts.values()), 20):
                result['registrations'] = [{'transport': account.config['transport'], 'code': account.registration_code, 'active': account.registration_active} for account in agent.accounts.values()]
                raise ValueError('REGISTER LAB UDP/TCP non confirmé.')
            result['registrations'] = [{'transport': account.config['transport'], 'code': account.registration_code, 'active': account.registration_active} for account in agent.accounts.values()]

            def launch(number, codec, duration=7):
                run_id = str(uuid.uuid4())
                agent.execute({'id': str(uuid.uuid4()), 'kind': 'call', 'payload': {'run_id': run_id, 'account_id': int(number), 'audio_profile': 'tone-1000', 'duration_s': duration, 'scenario_type': 'echo', 'destination': '*777', 'server': '127.0.0.1:5068', 'preferred_codec': codec}})
                if run_id not in agent.calls:
                    raise ValueError('Commande SIP LAB refusée.')
                return run_id

            def collect(run_id, transport, codec, concurrent=False):
                if run_id not in agent.reports:
                    raise ValueError('Résultat appel LAB absent après délai.')
                metrics = agent.reports[run_id]
                rtp = metrics.get('rtp') or {}
                audio = metrics.get('audio') or {}
                success = bool(metrics.get('established') and (rtp.get('codec') or '').startswith(codec.split('/')[0] + '/') and (rtp.get('rx') or {}).get('packets', 0) > 100 and (rtp.get('tx') or {}).get('packets', 0) > 100 and (audio.get('tone_ratio_mean') or 0) > .80 and (audio.get('alignment_confidence') or 0) > .50 and audio.get('echo_delay_ms') is not None)
                item = {'transport': transport, 'requested_codec': codec, 'simultaneous': concurrent, 'passed': success, 'metrics': metrics}
                result['calls'].append(item)
                return success

            for number, transport in (('9703', 'udp'), ('9704', 'tcp')):
                for codec in ('G722/16000', 'PCMA/8000', 'PCMU/8000'):
                    run_id = launch(number, codec)
                    wait(lambda: run_id in agent.reports, 24)
                    collect(run_id, transport, codec)
            simultaneous = [(launch('9703', 'G722/16000', 8), 'udp', 'G722/16000'), (launch('9704', 'PCMA/8000', 8), 'tcp', 'PCMA/8000')]
            wait(lambda: all(run_id in agent.reports for run_id, _, _ in simultaneous), 25)
            for run_id, transport, codec in simultaneous:
                collect(run_id, transport, codec, True)
            result['passed'] = all(item['passed'] for item in result['calls']) and result['peak_established_calls'] >= 2
        except Exception as error:
            result['error_type'] = type(error).__name__
            # A neutral error avoids serializing a native SIP/config exception.
            result['error'] = 'Qualification LAB incomplète ; consulter les contrôles structurés.'
        finally:
            for call in agent.calls.values():
                call.hangup_safe()
            call = None
            for _ in range(30):
                agent.endpoint.libHandleEvents(10)
            for account in agent.accounts.values():
                account.shutdown()
            account = None
            agent.calls.clear()
            agent.accounts.clear()
            agent.remote = None
            accounts.clear()
            fixture.clear()
            gc.collect()
            agent.endpoint.libDestroy()
            agent.db.close()
            result['clean_shutdown'] = True
    dll_directory.close()
    args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': result['passed'], 'registrations': result['registrations'], 'calls': [{'transport': item['transport'], 'codec': item['requested_codec'], 'passed': item['passed'], 'simultaneous': item['simultaneous']} for item in result['calls']], 'peak_established_calls': result['peak_established_calls'], 'clean_shutdown': result.get('clean_shutdown')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError):
        raise SystemExit('Qualification SIP Windows refusée : environnement ou fixture LAB invalide.')
