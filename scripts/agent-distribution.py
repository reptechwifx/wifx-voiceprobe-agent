#!/usr/bin/env python3
"""Build and verify source-only Agent archives. An out-of-band SHA anchors downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ['install-agent.sh', 'install-agent-from-source.sh', 'update-agent.sh', 'uninstall-agent.sh', 'configure-agent.py', 'validate-agent-config.py', 'build-pjsip.sh', 'instrument-pjsip.py', 'reset-agent-password.py', 'installation-info.py', 'agent-distribution.py']


def members(root):
    paths = [root / 'VERSION', root / 'infrastructure/agent/voiceprobe-agent.service'] + [root / 'scripts' / name for name in SCRIPTS]
    paths += [p for part in ['src', 'web', 'installer'] for p in (root / 'agent' / part).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc' and p.name != 'gateway.py']
    result = {str(p.relative_to(root)): p.read_bytes() for p in paths}
    result['agent/VERSION'] = (root / 'agent/VERSION').read_bytes()
    result['VERSION'] = result['agent/VERSION']
    for name in ['agent/LICENSE','agent/NOTICE.md']:
        if (root/name).is_file():result[name]=(root/name).read_bytes()
    if 'agent/LICENSE' in result:result['LICENSE']=result['agent/LICENSE']
    return result


def pack(output, allow_dirty=False):
    version = (ROOT / 'agent/VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+-\d{3}', version):
        raise ValueError('Version identifiée requise.')
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))
    if dirty and not allow_dirty:
        raise ValueError('Commiter les sources avant de préparer une archive de distribution.')
    data = members(ROOT)
    build = sha + ('-development' if dirty else '')
    data['agent/BUILD_ID'] = (build + '\n').encode()
    manifest = {'version': version, 'git_commit': sha, 'development': dirty, 'files': {p: hashlib.sha256(v).hexdigest() for p, v in sorted(data.items())}}
    data['release-manifest.json'] = json.dumps(manifest, indent=2).encode()
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    import io
    with tarfile.open(output, 'w:gz') as archive:
        for name, content in sorted(data.items()):
            info = tarfile.TarInfo('voiceprobe-agent-' + version + '/' + name)
            info.size = len(content)
            info.mode = 0o755 if name.startswith('scripts/') and name.endswith('.sh') else 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(checksum + '  ' + output.name + '\n')
    print(json.dumps({'version': version, 'git_commit': sha, 'development': dirty, 'archive': str(output), 'sha256': checksum}))


def validate(root, expected=None):
    root = Path(root)
    version = (root / 'VERSION').read_text().strip()
    if expected and version != expected:
        raise ValueError('Version différente de la version attendue.')
    manifest_path = root / 'release-manifest.json'
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text())
        if version != manifest['version']:
            raise ValueError('Manifest/version incohérents.')
        if len(manifest['files']) > 1024:
            raise ValueError('Manifest trop volumineux.')
        for name, digest in manifest['files'].items():
            path = root / name
            if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('Source altérée : ' + name)
        expected_paths = set(manifest['files']) | {'release-manifest.json'}
        actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
        if actual != expected_paths:
            raise ValueError('Fichier inattendu ou manquant dans la distribution.')
    elif not (root / '.git').exists():
        raise ValueError('Utiliser des sources Git contrôlées ou une archive avec manifest vérifié.')
    print('Sources identifiées et vérifiées : Bêta ' + version)


def extract(archive, destination, checksum):
    archive, destination = Path(archive), Path(destination)
    if not re.fullmatch('[a-fA-F0-9]{64}', checksum) or hashlib.sha256(archive.read_bytes()).hexdigest() != checksum.lower():
        raise ValueError('SHA-256 de l’archive incorrect ; installation bloquée.')
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    seen = set()
    with tarfile.open(archive) as source:
        entries = source.getmembers()
        if len(entries) > 1024 or sum(m.size for m in entries) > 100_000_000:
            raise ValueError('Archive trop volumineuse.')
        prefix = None
        for item in entries:
            p = Path(item.name)
            if p.is_absolute() or '..' in p.parts or len(p.parts) < 2 or not item.isfile() or item.name in seen:
                raise ValueError('Entrée d’archive non sûre.')
            if prefix is None:
                prefix = p.parts[0]
            if p.parts[0] != prefix or not re.fullmatch(r'voiceprobe-agent-\d+\.\d+-\d{3}', prefix):
                raise ValueError('Racine d’archive invalide.')
            seen.add(item.name)
        for item in entries:
            path = destination / item.name
            path.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(item) as stream:
                path.write_bytes(stream.read())
            path.chmod(0o755 if item.mode & 0o111 else 0o644)
    validate(destination / prefix)
    print(destination / prefix)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('pack'); p.add_argument('output'); p.add_argument('--allow-dirty', action='store_true')
    p = commands.add_parser('validate'); p.add_argument('root'); p.add_argument('--version')
    p = commands.add_parser('extract'); p.add_argument('archive'); p.add_argument('destination'); p.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'pack':
            pack(args.output, args.allow_dirty)
        elif args.command == 'validate':
            validate(args.root, args.version)
        else:
            extract(args.archive, args.destination, args.sha256)
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        raise SystemExit(str(error))
