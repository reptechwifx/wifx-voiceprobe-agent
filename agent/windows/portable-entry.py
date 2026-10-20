"""Entry point for the universal Windows portable executable (GPL-3.0-or-later)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
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


def load_integrated_provision(root, executable, policy):
    """Same signed package binding for startup and explicit identity cleanup."""
    from cryptography.hazmat.primitives import serialization
    from portable_package import extract, read_regular
    from portable_runtime import PortableError, verify_provisioning
    from version import VERSION
    pem = (root / 'provisioning-public.pem').read_bytes()
    key = serialization.load_pem_public_key(pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(der).hexdigest()
    if fingerprint != policy['provisioning_key_sha256']:
        raise PortableError('Racine de préparation incohérente.')
    if policy['qualification'] != 'lab':
        raise PortableError('Signature Windows de production non qualifiée.')
    embedded = extract(read_regular(executable))
    return verify_provisioning(embedded['provisioning'], {fingerprint: pem}, agent_version=VERSION,
                               expected_template_sha256=embedded['template_sha256'],
                               expected_package_nonce=embedded['package_nonce'])


def relocate_persistent(provision, executable):
    """Start only the verified per-user copy, before any SIP/RTP socket exists."""
    if os.name != 'nt' or provision.get('mode') != 'persistent':
        return False
    from windows_autostart import stage
    try:
        stable = stage(provision['instance_id'], executable)
    except PermissionError:
        from portable_runtime import PortableError
        raise PortableError('Fermez la sonde Voice Probe avant d’installer sa mise à jour.') from None
    if os.path.samefile(stable, executable):
        return False
    subprocess.Popen([str(stable)], cwd=str(stable.parent), close_fds=True)
    return True


def forget_identity(provision, ask, notify, *, identity_factory=None):
    """Forget one verified instance after explicit confirmation; no SIP/network."""
    from portable_runtime import PortableError
    if provision.get('mode') != 'persistent':
        raise PortableError('Ce paquet ne possède pas une identité Windows persistante.')
    if not ask('Supprimer l’identité de cette sonde ?',
               'Cette action supprime uniquement l’identité locale de cette sonde WIFX.\n'
               'Une nouvelle autorisation WIFX sera nécessaire pour la réutiliser.\n'
               'Les autres sondes ne seront pas modifiées.\n\nVoulez-vous continuer ?'):
        return 2  # Cancellation is never reported as successful deletion.
    if identity_factory is None:
        from windows_identity import PersistentIdentity
        identity_factory = PersistentIdentity
    identity = identity_factory(provision, allow_create=False)
    try:
        if os.name == 'nt':
            from windows_autostart import remove
            remove(provision['instance_id'])
        identity.forget()
    finally:
        identity.close()
    notify('Identité supprimée', 'L’identité locale de cette sonde a été supprimée. Vous pouvez supprimer cet EXE.')
    return 0


def native_forget_dialogs():
    import ctypes
    from ctypes import wintypes as w
    user = ctypes.WinDLL('user32', use_last_error=True)
    user.MessageBoxW.argtypes = [w.HWND, w.LPCWSTR, w.LPCWSTR, w.UINT]
    user.MessageBoxW.restype = ctypes.c_int
    def ask(title, message):
        # MB_DEFBUTTON2 makes NO the default, including keyboard Enter.
        return user.MessageBoxW(None, message, title, 4 | 0x30 | 0x100) == 6
    def notify(title, message):
        user.MessageBoxW(None, message, title, 0x40)
    return ask, notify


def main():
    parser = argparse.ArgumentParser(description='WIFX Voice Probe — sonde portable')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--self-test', action='store_true')
    actions.add_argument('--forget-identity', action='store_true', help='Supprimer explicitement l’identité locale de cette sonde, après confirmation.')
    actions.add_argument('--gui-smoke', type=int, metavar='SECONDS', help=argparse.SUPPRESS)
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
    if args.forget_identity:
        from portable_runtime import PortableError
        from portable_package import PackageError
        ask, notify = native_forget_dialogs()
        try:
            if not getattr(sys, 'frozen', False):
                raise PortableError('Le nettoyage exige le paquet Windows vérifié.')
            provision = load_integrated_provision(root, Path(sys.executable), policy)
            return forget_identity(provision, ask, notify)
        except (PortableError, PackageError) as error:
            notify('Suppression refusée', str(error))
            return 1
    prepared_provision = None
    bootstrap_error = None
    if os.name == 'nt' and getattr(sys, 'frozen', False) and not args.gui_smoke:
        try:
            prepared_provision = load_integrated_provision(root, Path(sys.executable), policy)
            if relocate_persistent(prepared_provision, sys.executable):
                return 0
        except PortableError as error:
            bootstrap_error = str(error)
        except Exception:
            bootstrap_error = 'Démarrage impossible. Contactez votre technicien WIFX.'
    from portable_gui import run_window
    from portable_runtime import PortableError
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
            if not getattr(sys, 'frozen', False):
                raise PortableError('Utilisez le paquet Windows préparé par votre technicien WIFX.')
            if bootstrap_error:
                raise PortableError(bootstrap_error)
            provision = prepared_provision or load_integrated_provision(root, Path(sys.executable), policy)
            from portable_agent import PortableAgent
            ca = root / 'lab-ca.crt'
            agent = PortableAgent(provision, ca_file=str(ca) if policy['qualification'] == 'lab' and ca.is_file() and provision['controller_url'] == policy.get('controller_url') else None)
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
