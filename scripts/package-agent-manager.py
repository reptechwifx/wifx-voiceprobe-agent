#!/usr/bin/env python3
"""Package only the signed root manager, reusing an unchanged Agent release."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import shlex
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def write_catalog(output, manager, revision, sequence, expires, artifact_source, signing_key):
    raw = manager.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    name = 'agent-manager-' + digest[:12] + '.py'
    if (output / name).resolve() != manager.resolve():
        shutil.copy2(manager, output / name)
    values = {'schema': 1, 'sequence': sequence, 'expires': expires, 'manager': name,
              'manager_sha256': digest, 'manager_bytes': len(raw),
              'source_revision': revision, 'artifact_source': artifact_source or ''}
    manifest = output / 'manager.manifest'
    manifest.write_text(''.join(str(k) + '=' + str(v) + '\n' for k, v in values.items()))
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(signing_key),
                    '-out', str(output / 'manager.sig'), str(manifest)], check=True)


def package(args):
    if args.output.exists():
        raise ValueError('Destination existante refusée.')
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)
    if dirty and not args.lab_development:
        raise ValueError('Sources propres et commitées requises.')
    spec = importlib.util.spec_from_file_location('manager', ROOT / 'agent/installer/manage.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.https_url(args.source)
    if args.artifact_source and not (module.github_channel(args.source) and module.github_release(args.artifact_source)):
        raise ValueError('Canal ou Release GitHub hors périmètre.')
    args.output.mkdir(parents=True, mode=0o700)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    write_catalog(args.output, ROOT / 'agent/installer/manage.py', revision, args.sequence,
                  int(time.time()) + 90 * 86400, args.artifact_source, args.signing_key)
    public = subprocess.check_output(['openssl', 'pkey', '-in', str(args.signing_key), '-pubout'], text=True).strip()
    (args.output / 'signing-public.pem').write_text(public + '\n')
    for name in ('bootstrap.manifest', 'bootstrap.sig'):
        shutil.copy2(args.application_release / name, args.output / name)
    # Verify the retained application bootstrap before generating the new entry point.
    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(args.output / 'signing-public.pem'),
                    '-signature', str(args.output / 'bootstrap.sig'), str(args.output / 'bootstrap.manifest')], check=True)
    bootstrap = (ROOT / 'agent/installer/bootstrap.sh.in').read_text().replace(
        '@SOURCE_SHELL@', shlex.quote(args.source.rstrip('/'))).replace('@PUBLIC_KEY@', public)
    (args.output / 'install.sh').write_text(bootstrap)
    files = sorted(args.output.iterdir())
    (args.output / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in files))
    print(args.output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--application-release', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--artifact-source')
    parser.add_argument('--signing-key', type=Path, required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--lab-development', action='store_true')
    args = parser.parse_args()
    from storage_maintenance import guard
    guard(0.1)
    package(args)
