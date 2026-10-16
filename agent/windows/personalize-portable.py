#!/usr/bin/env python3
"""Isolated fixed-contract packaging worker. SPDX-License-Identifier: GPL-3.0-or-later.

Only the dedicated signing worker receives a signed provisioning document.
This process needs public verification material, never a private signing key.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from portable_package import PackageError, canonical, document, extract, personalize, read_regular, validate_template
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from portable_runtime import PortableError, verify_provisioning


class WorkerError(ValueError):
    pass


def prepare(job_path, catalog_path, output):
    job = document(read_regular(job_path), 131072)
    expected = {'schema', 'job_id', 'package_nonce', 'template_id', 'template_sha256', 'provisioning', 'mode'}
    if set(job) != expected or job['schema'] != 'wifx-portable-artifact-job-v2':
        raise WorkerError('INVALID_JOB')
    try:
        if str(uuid.UUID(job['job_id'])) != job['job_id']:
            raise ValueError()
        if any(not isinstance(job[k], str) or re.fullmatch('[0-9a-f]{64}', job[k]) is None for k in ('package_nonce', 'template_sha256')):
            raise ValueError()
        if not isinstance(job['template_id'], str) or re.fullmatch('[a-z0-9][a-z0-9.-]{2,79}', job['template_id']) is None:
            raise ValueError()
    except (ValueError, TypeError):
        raise WorkerError('INVALID_JOB') from None
    if job['mode'] == 'production':
        raise WorkerError('SIGNING_NOT_CONFIGURED')
    if job['mode'] != 'lab':
        raise WorkerError('INVALID_MODE')
    if catalog_path.is_symlink() or os.name != 'nt' and catalog_path.stat().st_mode & 0o022:
        raise WorkerError('UNSAFE_CATALOG')
    catalog = document(read_regular(catalog_path), 131072)
    if set(catalog) != {'schema', 'templates'} or catalog['schema'] != 'wifx-portable-template-catalog-v2' or not isinstance(catalog['templates'], dict):
        raise WorkerError('INVALID_CATALOG')
    item = catalog['templates'].get(job['template_id'])
    if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'agent_version', 'qualification', 'provisioning_public_key_path', 'provisioning_key_sha256'}:
        raise WorkerError('UNKNOWN_TEMPLATE')
    if item['qualification'] != 'lab' or item['agent_version'] not in ('0.9-004', '0.9-007', '0.9-008', '0.9-009') or item['sha256'] != job['template_sha256']:
        raise WorkerError('INCOMPATIBLE_TEMPLATE')
    template_path, public_path = Path(item['path']), Path(item['provisioning_public_key_path'])
    if not template_path.is_absolute() or not public_path.is_absolute():
        raise WorkerError('UNSAFE_CATALOG')
    template = read_regular(template_path)
    if validate_template(template) != item['sha256']:
        raise WorkerError('TEMPLATE_DIGEST_MISMATCH')
    envelope = canonical(job['provisioning'])
    provision = verify_provisioning(envelope, {item['provisioning_key_sha256']: read_regular(public_path)},
                                    agent_version=item['agent_version'], expected_template_sha256=item['sha256'],
                                    expected_package_nonce=job['package_nonce'])
    if provision['schema'] != 'wifx-voiceprobe-portable-provisioning-v2':
        raise WorkerError('PROVISIONING_V2_REQUIRED')
    artifact = personalize(template, envelope, job['package_nonce'])
    checked = extract(artifact)
    if checked['template_sha256'] != item['sha256'] or checked['certificate_present']:
        raise WorkerError('ARTIFACT_CHECK_FAILED')
    if output.exists() or output.is_symlink():
        raise WorkerError('OUTPUT_EXISTS')
    output.mkdir(mode=0o700, parents=False)
    result = {'schema': 'wifx-portable-artifact-result-v2', 'job_id': job['job_id'],
              'package_nonce': job['package_nonce'], 'template_id': job['template_id'],
              'template_sha256': job['template_sha256'], 'artifact_filename': 'WIFX-VoiceProbe.exe',
              'artifact_sha256': hashlib.sha256(artifact).hexdigest(), 'artifact_bytes': len(artifact),
              'status': 'VERIFIED_ARTIFACT', 'qualification': 'lab', 'authenticode': 'NOT_SIGNED_LAB'}
    try:
        for name, data in [('WIFX-VoiceProbe.exe', artifact), ('result.json', canonical(result)+b'\n')]:
            temporary = output / (name+'.partial')
            with temporary.open('xb') as handle:
                os.chmod(temporary, 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(output/name)
    except Exception:
        for name in ('WIFX-VoiceProbe.exe', 'WIFX-VoiceProbe.exe.partial', 'result.json', 'result.json.partial'):
            (output/name).unlink(missing_ok=True)
        output.rmdir()
        raise WorkerError('OUTPUT_WRITE_FAILED') from None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.job, args.catalog, args.output)
    except WorkerError as error:
        result = {'schema': 'wifx-portable-artifact-result-v2', 'status': 'CONTROLLED_FAILURE', 'error_code': str(error)}
    except (PackageError, PortableError):
        result = {'schema': 'wifx-portable-artifact-result-v2', 'status': 'CONTROLLED_FAILURE', 'error_code': 'PACKAGE_VERIFICATION_FAILED'}
    except Exception:
        result = {'schema': 'wifx-portable-artifact-result-v2', 'status': 'CONTROLLED_FAILURE', 'error_code': 'PACKAGING_FAILED'}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result['status'] == 'VERIFIED_ARTIFACT' else 1


if __name__ == '__main__':
    raise SystemExit(main())
