#!/usr/bin/env python3
"""Paquet Windows LAB signé, liste fermée ; aucune publication ni clé dans le ZIP."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_archive_entry(archive, name, data):
    item = zipfile.ZipInfo(name, date_time=(2026, 10, 15, 0, 0, 0))
    item.create_system = 3
    item.external_attr = 0o100644 << 16
    archive.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)


def package(args):
    if args.output.exists():
        raise ValueError('Destination immuable déjà présente.')
    proof = json.loads(args.audit.read_text(encoding='utf-8'))
    receipt_path = getattr(args, 'build_receipt', None)
    portable_version = '0.1.0-lab'
    if receipt_path is not None:
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ValueError('Reçu de construction régulier requis.')
        receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
        if not isinstance(receipt, dict):
            raise ValueError('Structure du reçu LAB invalide.')
        portable_version = receipt.get('portable_version')
        artifacts = receipt.get('artifacts')
        if (receipt.get('qualification') != 'LAB_UNSIGNED_NOT_FOR_CLIENTS'
                or not isinstance(portable_version, str) or len(portable_version) > 64
                or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-lab', portable_version)
                or not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict)
                or artifacts[0].get('file') != args.exe.name
                or artifacts[0].get('sha256') != sha(args.exe)
                or artifacts[0].get('bytes') != args.exe.stat().st_size):
            raise ValueError('Reçu LAB/version incompatible avec le binaire audité.')
    if not isinstance(proof, dict) or proof.get('passed') is not True or proof.get('issues') != [] or proof.get('executable_sha256') != sha(args.exe):
        raise ValueError('Audit complet du binaire correspondant requis.')
    if not isinstance(proof.get('trust'), dict) or proof['trust'].get('qualification') != 'lab':
        raise ValueError('Ce constructeur est réservé aux candidats LAB.')
    if args.sign_key.is_symlink() or not args.sign_key.is_file() or stat.S_IMODE(args.sign_key.stat().st_mode) != 0o600:
        raise ValueError('Clé de signature LAB privée 0600 requise.')
    for directory in (args.sdk, args.notices, args.sources, args.third_party_sources):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Répertoire régulier requis : SDK, licences et sources correspondantes.')
    files = {'WIFX-VoiceProbe.exe': args.exe, 'qualification/bundle-audit.json': args.audit}
    if receipt_path is not None:
        files['qualification/build-receipt.json'] = receipt_path
    for name in ['_pjsua2.pyd', 'pjsua2.py', 'libwinpthread-1.dll', 'binary.json', 'COPYING.pjsip', 'COPYING.mingw-w64', 'COPYING.gcc-runtime']:
        files['sdk/'+name] = args.sdk/name
    for directory, prefix in [(args.notices, 'licenses'), (args.sources, 'agent-sources'), (args.third_party_sources, 'third-party-sources')]:
        count = 0
        for path in sorted(directory.rglob('*')):
            if path.is_symlink():
                raise ValueError('Lien refusé dans les sources/notices.')
            if path.is_file():
                relative = path.relative_to(directory)
                if any(part.casefold() in ('.git', 'controller', '__pycache__') for part in relative.parts) or path.name.casefold() == 'gateway.py':
                    raise ValueError('Frontière Agent publique violée.')
                files[prefix+'/'+relative.as_posix()] = path
                count += 1
        if not count:
            raise ValueError('Répertoire de licences ou sources correspondantes vide.')
    if not files.get('agent-sources/LICENSE'):
        raise ValueError('Sources Agent publiques avec licence requises.')
    names = set()
    for name, path in files.items():
        archive_path = PurePosixPath(name)
        if (not path.is_file() or path.is_symlink() or archive_path.is_absolute()
                or any(part in ('', '.', '..') for part in archive_path.parts)
                or any(ord(character) < 32 or character in '\\:<>"|?*' for character in name)
                or name.casefold() in names):
            raise ValueError('Fichier régulier manquant ou chemin refusé.')
        names.add(name.casefold())
        if re.search(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{24,}-----END ', path.read_bytes()):
            raise ValueError('Matériel de clé privée refusé.')
    agent_version = proof.get('agent_version', '0.9-004')
    if not isinstance(agent_version, str) or not re.fullmatch(r'\d+\.\d+-\d{3}', agent_version):
        raise ValueError('Version Agent absente ou invalide dans l’audit qualifié.')
    args.output.mkdir(mode=0o700, parents=True)
    manifest = {'schema': 'wifx-windows-lab-distribution-v1', 'qualification': 'LAB_UNSIGNED_NOT_FOR_CLIENTS',
                'agent_version': agent_version, 'portable_version': portable_version, 'architecture': 'AMD64',
                'python': '3.13.16', 'pjsip': '2.16', 'authenticode': False,
                'files': {name: {'sha256': sha(path), 'bytes': path.stat().st_size} for name, path in sorted(files.items())}}
    mf = args.output/'manifest.json';mf.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)+'\n')
    pub = args.output/'manifest-public.pem'
    subprocess.run(['openssl', 'pkey', '-in', str(args.sign_key), '-pubout', '-out', str(pub)], check=True, capture_output=True)
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(args.sign_key), '-out', str(args.output/'manifest.sig'), str(mf)], check=True, capture_output=True)
    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(pub), '-signature', str(args.output/'manifest.sig'), str(mf)], check=True, capture_output=True)
    bundle = args.output/('WIFX-VoiceProbe-Windows-x64-'+portable_version.removesuffix('-lab')+'-LAB.zip')
    disclaimer = 'VERSION LAB NON SIGNÉE AUTHENTICODE — NON DESTINÉE AUX CLIENTS.\nCe ZIP universel ne contient aucune invitation ni compte SIP.\nUne invitation privée signée du Controller LAB est nécessaire.\nLa clé de manifeste est une racine LAB locale, distincte de la racine de production Linux.\n'
    if receipt_path is not None:
        disclaimer += 'Ce candidat est un modèle universel LAB. Le worker autorisé doit intégrer une invitation signée avant tout lancement de diagnostic. Aucun fichier JSON externe ne personnalise ce modèle.\n'
    with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, path in sorted(files.items()):
            write_archive_entry(archive, name, path.read_bytes())
        for name in ('manifest.json', 'manifest.sig', 'manifest-public.pem'):
            write_archive_entry(archive, name, (args.output/name).read_bytes())
        write_archive_entry(archive, 'LAB-LISEZ-MOI.txt', disclaimer.encode('utf-8'))
    (args.output/'SHA256SUMS').write_text(''.join(sha(path)+'  '+path.name+'\n' for path in (bundle, mf, args.output/'manifest.sig', pub)))
    print(json.dumps({'result': 'VERIFIED_LAB_PACKAGE', 'archive': str(bundle), 'sha256': sha(bundle), 'files': len(files), 'authenticode': False, 'client_ready': False}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'audit', 'sdk', 'notices', 'sources', 'sign-key', 'third-party-sources', 'output'):
        p.add_argument('--'+name, required=True, type=Path)
    p.add_argument('--build-receipt', type=Path, help='Reçu du constructeur Windows, version LAB et SHA exact du modèle.')
    try:
        package(p.parse_args())
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('ÉCHEC CONTRÔLÉ : paquet LAB refusé ; aucun succès client annoncé.') from None
