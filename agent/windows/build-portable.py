#!/usr/bin/env python3
"""Constructeur Windows local ; aucune installation système ni politique modifiée."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile

from pjsip_contract import validate_binding


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--trust', type=Path, required=True)
    p.add_argument('--wheels', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--console', action='store_true')
    p.add_argument('--expected-provisioning-spki-sha256')
    args = p.parse_args()
    if sys.platform != 'win32' or struct.calcsize('P') != 8 or sys.version_info[:2] != (3, 13):
        raise ValueError('Python Windows 3.13 x64 requis ; aucun remplacement de l’ABI.')
    if args.output.exists():
        raise ValueError('Destination existante refusée.')
    root = Path(__file__).resolve().parents[2]
    binding = validate_binding(args.sdk, root)
    policy = json.loads((args.trust/'build-trust.json').read_text(encoding='utf-8'))
    if policy['qualification'] != 'lab':
        raise ValueError('Seuls les candidats LAB sont construits ici ; qualification client distincte.')
    env = dict(os.environ, VOICEPROBE_WINDOWS_SDK=str(args.sdk.resolve()),
               VOICEPROBE_WINDOWS_TRUST=str(args.trust.resolve()),
               VOICEPROBE_WINDOWS_CONSOLE='1' if args.console else '0')
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--find-links', str(args.wheels.resolve()),
                    '--require-hashes', '--only-binary=:all:', '--disable-pip-version-check',
                    '-r', str(root/'agent/windows/requirements-build.lock')], check=True)
    from cryptography.hazmat.primitives import serialization
    public = serialization.load_pem_public_key((args.trust / policy['provisioning_public_key']).read_bytes())
    spki = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    if spki != policy['provisioning_key_sha256'] or (args.expected_provisioning_spki_sha256 and spki != args.expected_provisioning_spki_sha256):
        raise ValueError('Racine de provisioning différente de celle du worker qualifié ; construction arrêtée.')
    def source_manifest():
        sources = sorted((root/'agent/src').glob('*.py')) + sorted((root/'agent/windows').rglob('*')) + [root/'agent/VERSION']
        sources = [f for f in sources if f.is_file() and f.name != 'gateway.py' and '__pycache__' not in f.parts]
        return {f.relative_to(root).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest() for f in sources}
    source_hashes = source_manifest()
    with tempfile.TemporaryDirectory(prefix='voiceprobe-build-') as work:
        subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                        '--distpath', str(args.output.resolve()), '--workpath', work,
                        str(root/'agent/windows/portable.spec')], env=env, check=True)
    if source_manifest() != source_hashes:
        raise ValueError('Sources modifiées pendant la construction ; candidat non qualifiable.')
    if validate_binding(args.sdk, root) != binding:
        raise ValueError('SDK PJSIP modifié pendant la construction ; candidat non qualifiable.')
    receipt = {'trust': {'provisioning_spki_sha256': spki, 'lab_controller_url': policy['controller_url']}, 'pjsip_binding': binding, 'source_sha256': source_hashes, 'qualification': 'LAB_UNSIGNED_NOT_FOR_CLIENTS', 'python': platform.python_version(), 'agent_version': (root/'agent/windows/release/VERSION').read_text().strip(), 'portable_version': (root/'agent/windows/VERSION').read_text().strip(), 'artifacts': []}
    for f in sorted(args.output.glob('*.exe')):
        receipt['artifacts'].append({'file': f.name, 'bytes': f.stat().st_size,
                                    'sha256': hashlib.sha256(f.read_bytes()).hexdigest()})
    if len(receipt['artifacts']) != 1:
        raise ValueError('EXE final absent ou ambigu.')
    (args.output/'build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
