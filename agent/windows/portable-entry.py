"""Entry point for the universal Windows portable executable (GPL-3.0-or-later)."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading


def resources():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))


def self_test():
    """No invitation, credential, network traffic or local HTTP listener."""
    import platform
    import pjsua2 as pj
    import cryptography
    import numpy
    endpoint = pj.Endpoint()
    endpoint.libCreate()
    try:
        config = pj.EpConfig()
        config.uaConfig.threadCnt = 0
        config.uaConfig.mainThreadOnly = True
        config.logConfig.level = config.logConfig.consoleLevel = 0
        endpoint.libInit(config)
        endpoint.libStart()
        endpoint.audDevManager().setNullDev()
        codecs = [codec.codecId for codec in endpoint.codecEnum2()]
        if endpoint.libVersion().full != '2.16' or not all(any(c.startswith(p) for c in codecs) for p in ('G722/', 'PCMA/', 'PCMU/')):
            raise RuntimeError('Moteur SIP ou codecs incompatibles.')
        return {'result': 'VERIFIED_SUCCESS', 'platform': platform.system(),
                'architecture': platform.machine(), 'python': platform.python_version(),
                'pjsip': endpoint.libVersion().full, 'numpy': numpy.__version__,
                'cryptography': cryptography.__version__, 'codecs': codecs,
                'audio': 'null-device', 'local_administration': False}
    finally:
        endpoint.libDestroy()


def main():
    parser = argparse.ArgumentParser(description='WIFX Voice Probe — sonde portable')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--gui-smoke', type=int, metavar='SECONDS', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = resources()
    policy = json.loads((root / 'build-trust.json').read_text(encoding='utf-8'))
    if args.self_test:
        result = self_test()
        # Windowed EXEs have no stdout; this mode is primarily for the console QA build.
        if sys.stdout is not None:
            print(json.dumps(result, ensure_ascii=False))
        return 0
    if args.gui_smoke is not None and (policy['qualification'] != 'lab' or not 1 <= args.gui_smoke <= 60):
        parser.error('Mode réservé à la qualification LAB.')
    from portable_gui import run_window
    from portable_runtime import PortableError, verify_provisioning
    from version import VERSION
    completed = threading.Event()
    state_lock = threading.Lock()
    state = {'application': 'DÉMARRAGE', 'controller': 'EN ATTENTE', 'adoption': 'EN ATTENTE',
             'sip': 'INACTIF', 'active_tests': 0, 'completed_tests': 0, 'version': VERSION,
             'authorization_remaining_seconds': None, 'error': None}
    holder = {}
    stopping = threading.Event()

    def status():
        with state_lock:
            agent = holder.get('agent')
            return dict(state) if state['application'] == 'ERREUR' or not agent else agent.display_status()

    def stop():
        stopping.set()
        with state_lock:
            if holder.get('agent'):
                holder['agent'].request_stop()

    def work():
        try:
            if args.gui_smoke:
                with state_lock:
                    state['application'] = 'ACTIF'
                stopping.wait(args.gui_smoke + 10)
                return
            pem = (root / 'provisioning-public.pem').read_bytes()
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_pem_public_key(pem)
            der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            fingerprint = hashlib.sha256(der).hexdigest()
            if fingerprint != policy['provisioning_key_sha256']:
                raise PortableError('Racine de préparation incohérente.')
            location = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
            document = location / 'WIFX-VoiceProbe.provision.json'
            if document.is_symlink() or document.stat().st_size > 65536:
                raise PortableError('Paquet de préparation invalide.')
            provision = verify_provisioning(document.read_bytes(), {fingerprint: pem}, agent_version=VERSION)
            from portable_agent import PortableAgent
            ca = root / 'lab-ca.crt'
            agent = PortableAgent(provision, ca_file=str(ca) if policy['qualification'] == 'lab' and ca.is_file() else None)
            with state_lock:
                holder['agent'] = agent
            if stopping.is_set():
                agent.request_stop()
            agent.run()
        except PortableError as error:
            with state_lock:
                state.update(application='ERREUR', error=str(error))
        except Exception:
            # Never disclose request URLs, invitation secrets, native exceptions or config.
            with state_lock:
                state.update(application='ERREUR', error='Démarrage impossible. Contactez votre technicien WIFX.')
        finally:
            completed.set()

    thread = threading.Thread(target=work, name='VoiceProbe-SIP', daemon=False)
    thread.start()
    try:
        run_window(status, stop, completed, smoke_seconds=args.gui_smoke, lab=policy['qualification'] == 'lab')
    finally:
        stop()
        thread.join()
    return 1 if state['application'] == 'ERREUR' else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        if '--self-test' in sys.argv:
            if sys.stdout is not None:
                print(json.dumps({'result': 'CONTROLLED_FAILURE', 'error': 'Contrôle Windows embarqué refusé.'}))
        else:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, 'La sonde ne peut pas démarrer. Contactez votre technicien WIFX.',
                                            'WIFX Voice Probe — erreur de démarrage', 0x10)
        raise SystemExit(1) from None
