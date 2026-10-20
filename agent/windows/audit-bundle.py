#!/usr/bin/env python3
"""Audit statique complet d'un EXE PyInstaller, sans exécuter son code embarqué."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

PRIVATE_BEGIN = re.compile(rb'-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----')
# Require real ASCII PEM armor, not two independent serialization delimiters in
# a marshaled code object's constant table. Every complete candidate is refused.
PRIVATE_PEM = re.compile(rb'-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\r?\n(?:[ -~]*\r?\n)*?-----END \1-----')
SECRET_FIELD = re.compile(r'password|passwd|secret|token|private.?key|credential', re.I)
PRIVATE_HOME = re.compile(rb'/hom[e]/[^/\x00\r\n ]+/|[A-Za-z]:\\User[s]\\[^\\\x00\r\n]+\\|\\+wsl[.]localhost\\+[^\\\x00\r\n]+\\+hom[e]\\+[^\\\x00\r\n]+\\+', re.I)
# These literals are upstream wheel build paths or examples, verified in the
# pinned NumPy/cryptography wheels. Keep rejecting every other private path.
UPSTREAM_PATHS = {
    'numpy.__config__': (b'C:\\Users\\runneradmin\\AppData\\Local\\Temp\\build-env-',),
    'numpy.lib._datasource': (b'/home/guido/', b'/home/user/'),
    'cryptography/hazmat/bindings/_rust.pyd': (b'C:\\Users\\runneradmin\\.cargo\\registry\\src\\',),
}
FORBIDDEN_COMPONENTS = {'controller', 'gateway', 'gateway.py', 'gateway.pyc', 'artisan', 'laravel', 'pip', 'ensurepip', 'setuptools', '_distutils_hack', 'distutils', 'pyinstaller', '_pyinstaller_hooks_contrib', 'wheel'}
FORBIDDEN_FILES = {'admin.json', 'accounts-private.json', 'config.json', '.env', 'provisioning.json', 'provisioning.sig', 'voiceprobe-provisioning.json', 'voiceprobe-provisioning.sig', 'swig.exe', 'gcc.exe', 'g++.exe', 'make.exe', 'cmake.exe', 'cl.exe', 'msbuild.exe'}
MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def normalize_name(name):
    value = str(name).replace('\\', '/')
    path = PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or ':' in value or '\x00' in value:
        raise ValueError('Chemin embarqué interdit.')
    return value


def forbidden_reason(name):
    value = normalize_name(name).lower()
    if value.endswith('.dist-info/wheel'):
        return None  # Package metadata, not the wheel build package.
    components = set(value.split('/')) | set(value.replace('/', '.').split('.'))
    if components & FORBIDDEN_COMPONENTS:
        return 'controller_or_build_tool'
    if value.rsplit('/', 1)[-1] in FORBIDDEN_FILES or value.endswith(('.provision.json', '.provisioning.json')):
        return 'personal_configuration_or_build_tool'
    if value.endswith('.php') or value.rsplit('/', 1)[-1] in {'composer.json', 'composer.lock', 'artisan'}:
        return 'controller_source'
    if value.rsplit('/', 1)[-1].endswith(('.pfx', '.p12', '.key')):
        return 'private_key_container'
    return None


def fixture_secrets(path):
    raw = Path(path).read_bytes()
    found = set()

    def walk(value, key=''):
        if isinstance(value, dict):
            for field, child in value.items():
                walk(child, str(field))
        elif isinstance(value, list):
            for child in value:
                walk(child, key)
        elif isinstance(value, str):
            if (SECRET_FIELD.search(key) or key.isdecimal()) and len(value) >= 12:
                found.add(value)
            if key == 'payload':
                try:
                    walk(json.loads(base64.b64decode(value, validate=True)))
                except (ValueError, UnicodeError):
                    pass
    try:
        walk(json.loads(raw))
    except (ValueError, UnicodeError):
        text = raw.decode('utf-8').strip()
        if len(text) >= 12:
            found.add(text)
    return found


def personal_json(raw):
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in {'password', 'sip_password', 'invitation_secret', 'enrollment_secret', 'identity_private_key', 'token'}:
                    return True
                if key == 'payload' and isinstance(child, str):
                    try:
                        if walk(json.loads(base64.b64decode(child, validate=True))):
                            return True
                    except (ValueError, UnicodeError):
                        pass
                if walk(child):
                    return True
        if isinstance(value, list):
            return any(walk(child) for child in value)
        return False
    try:
        return walk(json.loads(raw))
    except (ValueError, UnicodeError):
        return False


class Scanner:
    def __init__(self, secrets=(), allowed_test_keys=()):
        self.members = []
        self.issues = []
        self.pem_candidates = []
        self.pem_format_markers = []
        self.allowed = set(allowed_test_keys)
        self.total = 0
        self.needles = []
        for index, value in enumerate(sorted(set(secrets))):
            for encoding, raw in (('utf8', value.encode()), ('utf16le', value.encode('utf-16-le')), ('base64', base64.b64encode(value.encode()))):
                self.needles.append((index, encoding, raw))

    def member(self, name, raw, kind, depth=0):
        name = normalize_name(name)
        reason = forbidden_reason(name)
        if reason:
            self.issues.append({'member': name, 'condition': reason})
        raw = raw or b''
        self.total += len(raw)
        if len(raw) > MAX_MEMBER or self.total > MAX_TOTAL or depth > 3:
            raise ValueError('Archive embarquée trop volumineuse ou imbriquée.')
        self.members.append({'name': name, 'kind': kind, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        if raw.lstrip()[:1] in (b'{', b'[') and personal_json(raw):
            self.issues.append({'member': name, 'condition': 'personal_provisioning_or_credentials'})
        markers = list(PRIVATE_BEGIN.finditer(raw))
        if markers:
            self.pem_format_markers.append({"member": name, "begin_markers": len(markers)})
        for match in PRIVATE_PEM.finditer(raw):
            digest = hashlib.sha256(match.group()).hexdigest()
            allowed = digest in self.allowed
            item = {'member': name, 'sha256': digest, 'allowed_public_upstream_fixture': allowed}
            self.pem_candidates.append(item)
            if not allowed:
                self.issues.append({'member': name, 'condition': 'private_pem_material', 'sha256': digest})
        for index, encoding, needle in self.needles:
            if needle in raw:
                self.issues.append({'member': name, 'condition': 'private_fixture_value', 'secret_index': index, 'encoding': encoding})
        allowed_paths = UPSTREAM_PATHS.get(name, ())
        def private_path_found(data):
            return any(not any(data[match.start():].startswith(prefix) for prefix in allowed_paths)
                       for match in PRIVATE_HOME.finditer(data))
        if private_path_found(raw) or private_path_found(raw.replace(b'\0', b'')):
            self.issues.append({'member': name, 'condition': 'private_development_path'})
        if name.lower().endswith('.zip') or raw.startswith(b'PK\x03\x04'):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for entry in archive.infolist():
                    normalize_name(entry.filename)
                    if entry.file_size > MAX_MEMBER:
                        raise ValueError('Membre ZIP embarqué trop volumineux.')
                    if not entry.is_dir():
                        self.member(name + '/' + entry.filename, archive.read(entry), 'zip', depth + 1)


def validate_manifest(xml):
    root = ET.fromstring(xml)
    levels = [element for element in root.iter() if element.tag.rsplit('}', 1)[-1] == 'requestedExecutionLevel']
    if len(levels) != 1 or levels[0].attrib.get('level') != 'asInvoker' or levels[0].attrib.get('uiAccess', 'false').lower() != 'false':
        raise ValueError('Le manifeste doit imposer asInvoker sans uiAccess.')
    return 'asInvoker'


def pe_check(raw, *, executable=False):
    import pefile
    pe = pefile.PE(data=raw, fast_load=False)
    try:
        if pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError('Binaire PE AMD64 requis.')
        result = {'machine': 'AMD64'}
        if executable:
            manifests = []
            directory = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            for resource in directory.entries if directory else ():
                if resource.id == 24:
                    for entry in resource.directory.entries:
                        for language in entry.directory.entries:
                            data = language.data.struct
                            manifests.append(pe.get_data(data.OffsetToData, data.Size))
            if len(manifests) != 1:
                raise ValueError('Manifeste Windows unique requis.')
            result['requested_execution_level'] = validate_manifest(manifests[0])
        return result
    finally:
        pe.close()


def validate_trust(key_pem, policy_raw, *, expected_fingerprint=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from urllib.parse import urlsplit
    if PRIVATE_PEM.search(key_pem):
        raise ValueError('La racine de confiance doit être publique uniquement.')
    key = serialization.load_pem_public_key(key_pem)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError('Racine publique RSA3072 minimum requise.')
    digest = hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    policy = json.loads(policy_raw)
    origin = urlsplit(policy.get('controller_url', ''))
    if (policy.get('qualification') not in ('lab', 'production') or origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path not in ('', '/') or policy.get('provisioning_public_key') != 'provisioning-public.pem' or policy.get('provisioning_key_sha256') != digest):
        raise ValueError('Politique de confiance incohérente.')
    if expected_fingerprint and digest != expected_fingerprint:
        raise ValueError('La racine publique embarquée diffère de celle attendue.')
    if policy['qualification'] == 'production' and policy.get('tls_ca') == 'lab-ca.crt':
        raise ValueError('Autorité TLS LAB interdite pour une distribution production.')
    return {'qualification': policy['qualification'], 'public_key_spki_sha256': digest, 'rsa_bits': key.key_size, 'controller_url': policy['controller_url']}


def validate_archive_toc(archive, content):
    cookie_start = archive._end_offset - archive._COOKIE_LENGTH
    _, _, offset, length, _, _ = struct.unpack(archive._COOKIE_FORMAT, content[cookie_start:archive._end_offset])
    toc = content[archive._start_offset + offset:archive._start_offset + offset + length]
    cursor = 0
    seen = set()
    while cursor < len(toc):
        size, _, _, unpacked, _, kind = struct.unpack(archive._TOC_ENTRY_FORMAT, toc[cursor:cursor + archive._TOC_ENTRY_LENGTH])
        if size <= archive._TOC_ENTRY_LENGTH or cursor + size > len(toc) or unpacked > MAX_MEMBER:
            raise ValueError('Table des membres PyInstaller invalide.')
        name = toc[cursor + archive._TOC_ENTRY_LENGTH:cursor + size].rstrip(b'\0').decode('utf-8')
        if kind != b'o':
            normalize_name(name)
            if name in seen:
                raise ValueError('Membre PyInstaller dupliqué : audit incomplet refusé.')
            seen.add(name)
        cursor += size
    if cursor != len(toc):
        raise ValueError('Table des membres PyInstaller tronquée.')


def audit(executable, *, secrets=(), allowed_test_keys=(), expected_version='0.9-004', expected_fingerprint=None):
    from PyInstaller.archive.readers import CArchiveReader
    content = Path(executable).read_bytes()
    pe = pe_check(content, executable=True)
    scanner = Scanner(secrets, allowed_test_keys)
    scanner.member('executable-outer', content, 'pe')
    archive = CArchiveReader(str(executable))
    validate_archive_toc(archive, content)
    for index, option in enumerate(archive.options):
        scanner.member('runtime-option-' + str(index), option.encode(), 'option')
    special = {}
    modules = set()
    archive_kinds = {}
    for name, entry in sorted(archive.toc.items()):
        kind = entry[-1]
        archive_kinds[kind] = archive_kinds.get(kind, 0) + 1
        if kind not in {'b', 'x', 's', 'm', 'M', 'z', 'Z'}:
            scanner.issues.append({'member': normalize_name(name), 'condition': 'unexpected_archive_entry_type', 'kind': kind})
        raw = archive.extract(name)
        scanner.member(name, raw, kind)
        if name in ('VERSION', 'provisioning-public.pem', 'build-trust.json'):
            special[name] = raw
        if name.lower().endswith(('.dll', '.pyd', '.exe')):
            pe_check(raw)
        if kind == 'z':
            embedded = archive.open_embedded_archive(name)
            for module in sorted(embedded.toc):
                modules.add(module)
                scanner.member(module, embedded.extract(module, raw=True), 'pyz')
    if special.get('VERSION', b'').decode().strip() != expected_version:
        scanner.issues.append({'condition': 'missing_or_wrong_agent_version'})
    expected = {'main', 'portable_agent', 'portable_runtime', 'portable_gui', 'pjsua2', 'version'}
    if expected - modules:
        scanner.issues.append({'condition': 'required_agent_module_missing', 'modules': sorted(expected - modules)})
    if not {'_pjsua2.pyd', 'python313.dll'}.issubset(archive.toc):
        scanner.issues.append({'condition': 'required_native_runtime_missing'})
    trust = validate_trust(special.get('provisioning-public.pem', b''), special.get('build-trust.json', b'{}'), expected_fingerprint=expected_fingerprint)
    report = {'schema': 'wifx-portable-bundle-audit-v1', 'executable_sha256': hashlib.sha256(content).hexdigest(), 'executable_bytes': len(content), 'agent_version': expected_version, 'pe': pe, 'trust': trust, 'carchive_members': len(archive.toc), 'carchive_options': len(archive.options), 'pyz_modules': len(modules), 'archive_kinds': archive_kinds, 'inspected_members': len(scanner.members), 'inspected_unpacked_bytes': scanner.total, 'private_fixture_values_checked': len(set(secrets)), 'private_pem_candidates': scanner.pem_candidates, 'private_pem_format_markers': scanner.pem_format_markers, 'issues': scanner.issues, 'members': scanner.members, 'passed': not scanner.issues, 'authenticode_verified': False, 'executes_embedded_code': False}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--version', default='0.9-004')
    parser.add_argument('--expected-trust-sha256')
    parser.add_argument('--secret-file', type=Path, action='append', default=[])
    parser.add_argument('--allow-public-test-key-sha256', action='append', default=[])
    args = parser.parse_args()
    secrets = set()
    for path in args.secret_file:
        secrets.update(fixture_secrets(path))
    try:
        # UNC access can make hundreds of random archive reads very slow. Copy
        # this EXE alone into an automatically removed private user temp folder.
        with tempfile.TemporaryDirectory(prefix='WIFX-VoiceProbe-Audit-') as directory:
            copied = Path(directory) / 'candidate.exe'
            shutil.copyfile(args.exe, copied)
            report = audit(copied, secrets=secrets, allowed_test_keys=args.allow_public_test_key_sha256, expected_version=args.version, expected_fingerprint=args.expected_trust_sha256)
            if hashlib.sha256(args.exe.read_bytes()).hexdigest() != report['executable_sha256']:
                raise ValueError('Le fichier source a changé pendant son audit.')
            report['source_copy_hash_verified'] = True
        report['temporary_executable_copy_removed'] = True
    except Exception as error:
        report = {'schema': 'wifx-portable-bundle-audit-v1', 'passed': False, 'audit_incomplete': True, 'error_type': type(error).__name__}
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('passed', 'executable_sha256', 'carchive_members', 'pyz_modules', 'inspected_members', 'issues', 'private_pem_candidates', 'audit_incomplete', 'error_type') if key in report}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
