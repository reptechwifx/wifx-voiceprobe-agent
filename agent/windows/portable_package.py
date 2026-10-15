"""Bounded personalized PE overlay. SPDX-License-Identifier: GPL-3.0-or-later.

The signed provisioning binds the SHA-256 of the exact unsigned template.
Authenticode, when provisioned, must be applied AFTER personalization. Certificate
presence is structural information, never a claim of trusted signature validity.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import struct

COOKIE = b'MEI\x0c\x0b\x0a\x0b\x0e'
BEGIN = b'\nWIFX-PORTABLE-PROVISIONING-V2\n'
END = b'\nWIFX-PORTABLE-END-V2:'
MAX_EXE = 128 * 1024 * 1024
MAX_FRAME = 196608
HEX = re.compile(r'[0-9a-f]{64}')


class PackageError(ValueError):
    """Safe operator error; never contains provisioning values."""


def _fail():
    raise PackageError('Structure du paquet Windows refusée.')


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            _fail()
        obj[key] = value
    return obj


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def document(raw, limit=MAX_FRAME):
    try:
        if not isinstance(raw, bytes) or len(raw) > limit:
            _fail()
        value = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(value, dict):
            _fail()
        return value
    except (UnicodeError, ValueError, TypeError):
        _fail()


def read_regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= MAX_EXE:
        _fail()
    raw = path.read_bytes()
    if len(raw) > MAX_EXE:
        _fail()
    return raw


def pe_layout(raw):
    try:
        if len(raw) < 256 or len(raw) > MAX_EXE or raw[:2] != b'MZ':
            _fail()
        pe = struct.unpack_from('<I', raw, 60)[0]
        if pe < 64 or raw[pe:pe+4] != b'PE\0\0':
            _fail()
        machine, count = struct.unpack_from('<HH', raw, pe+4)
        optional_size, flags = struct.unpack_from('<HH', raw, pe+20)
        opt = pe+24
        if machine != 0x8664 or not 1 <= count <= 96 or optional_size < 240 or flags & 0x2000 or not flags & 2:
            _fail()
        if struct.unpack_from('<H', raw, opt)[0] != 0x20b or struct.unpack_from('<H', raw, opt+68)[0] not in (2, 3):
            _fail()
        if struct.unpack_from('<I', raw, opt+108)[0] != 16:
            _fail()
        checksum_offset = opt+64
        security_offset = opt+112+4*8
        cert_start, cert_size = struct.unpack_from('<II', raw, security_offset)
        sections = opt+optional_size
        raw_end = sections+40*count
        spans = []
        for index in range(count):
            size, offset = struct.unpack_from('<II', raw, sections+index*40+16)
            if size:
                if offset < sections+40*count or offset+size > len(raw):
                    _fail()
                spans.append((offset, offset+size))
                raw_end = max(raw_end, offset+size)
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            _fail()
        if bool(cert_start) != bool(cert_size):
            _fail()
        if cert_size:
            if cert_start % 8 or cert_start < raw_end or cert_start+cert_size != len(raw) or cert_size > 8*1024*1024:
                _fail()
            length, revision, kind = struct.unpack_from('<IHH', raw, cert_start)
            if length < 8 or (length+7)//8*8 != cert_size or revision != 0x200 or kind != 2:
                _fail()
            if any(raw[cert_start+length:]):
                _fail()
        return {'checksum_offset': checksum_offset, 'security_offset': security_offset,
                'section_end': raw_end, 'payload_end': cert_start if cert_size else len(raw),
                'certificate_present': bool(cert_size)}
    except (IndexError, struct.error):
        _fail()


def validate_template(raw):
    """Check the pinned unsigned PyInstaller CP313 archive without executing it."""
    layout = pe_layout(raw)
    if layout['certificate_present'] or raw[-88:-80] != COOKIE:
        _fail()
    magic, size, toc, toc_size, pyver, dll = struct.unpack('!8sIIII64s', raw[-88:])
    start = len(raw)-size
    if start < layout['section_end'] or toc+toc_size != size-88 or pyver != 313 or dll.rstrip(b'\0') != b'python313.dll':
        _fail()
    table = raw[start+toc:start+toc+toc_size]
    cursor = 0
    names = set()
    while cursor < len(table):
        try:
            entry_size, offset, compressed, original, flag, kind = struct.unpack_from('!IIIIBc', table, cursor)
            if entry_size < 19 or entry_size % 16 or cursor+entry_size > len(table) or flag not in (0, 1):
                _fail()
            name_raw = table[cursor+18:cursor+entry_size]
            name = name_raw.split(b'\0', 1)[0]
            if not name or b'\0' not in name_raw or any(name_raw[len(name):]) or offset+compressed > toc or original > MAX_EXE:
                _fail()
            text = name.decode('utf-8')
            if text.startswith(('/', '\\')) or '..' in text.replace('\\', '/').split('/') or (text in names and kind != b'o'):
                _fail()
            if kind != b'o':
                names.add(text)
            cursor += entry_size
        except (UnicodeError, struct.error):
            _fail()
    if cursor != len(table) or not names:
        _fail()
    return hashlib.sha256(raw).hexdigest()


def personalize(template, envelope, package_nonce):
    digest = validate_template(template)
    if not isinstance(package_nonce, str) or HEX.fullmatch(package_nonce) is None:
        _fail()
    outer = document(envelope, 65536)
    if set(outer) != {'payload', 'signature', 'key_id'}:
        _fail()
    envelope = canonical(outer)
    layout = pe_layout(template)
    body = canonical({'schema': 'wifx-portable-exe-overlay-v2', 'template_size': len(template),
                      'template_sha256': digest,
                      'template_checksum': struct.unpack_from('<I', template, layout['checksum_offset'])[0],
                      'package_nonce': package_nonce, 'provisioning_b64': base64.b64encode(envelope).decode('ascii'),
                      'provisioning_sha256': hashlib.sha256(envelope).hexdigest()})
    if len(body) > MAX_FRAME:
        _fail()
    result = template+BEGIN+body+END+('%016x' % len(body)).encode('ascii')+b'\n'
    result += b'\0'*(-len(result) % 8)
    if len(result) > MAX_EXE or COOKIE in result[len(template):]:
        _fail()
    extract(result)
    return result


def extract(raw):
    layout = pe_layout(raw)
    end = layout['payload_end']
    # Only canonical 8-byte alignment padding may follow the fixed footer.
    for padding in range(8):
        finish = end-padding
        footer_start = finish-len(END)-17
        if footer_start < 0 or raw[footer_start:footer_start+len(END)] != END:
            continue
        tail = raw[footer_start+len(END):finish]
        if len(tail) != 17 or tail[-1:] != b'\n' or not re.fullmatch(b'[0-9a-f]{16}\n', tail):
            _fail()
        length = int(tail[:16], 16)
        body_start = footer_start-length
        begin = body_start-len(BEGIN)
        if not 1 <= length <= MAX_FRAME or begin < layout['section_end'] or raw[begin:body_start] != BEGIN or any(raw[finish:end]) or end % 8:
            _fail()
        body = raw[body_start:footer_start]
        meta = document(body)
        expected = {'schema', 'template_size', 'template_sha256', 'template_checksum', 'package_nonce', 'provisioning_b64', 'provisioning_sha256'}
        if set(meta) != expected or canonical(meta) != body or meta['schema'] != 'wifx-portable-exe-overlay-v2' or type(meta['template_size']) is not int or meta['template_size'] != begin:
            _fail()
        if type(meta['template_checksum']) is not int or not 0 <= meta['template_checksum'] < 2**32 or any(not isinstance(meta[k], str) or HEX.fullmatch(meta[k]) is None for k in ('template_sha256', 'package_nonce', 'provisioning_sha256')):
            _fail()
        try:
            envelope = base64.b64decode(meta['provisioning_b64'], validate=True)
        except (ValueError, TypeError):
            _fail()
        if len(envelope) > 65536 or hashlib.sha256(envelope).hexdigest() != meta['provisioning_sha256']:
            _fail()
        template = bytearray(raw[:begin])
        # Authenticode changes these two fields only. Their ORIGINAL values are
        # recovered so the signed provisioning still pins the exact template.
        struct.pack_into('<I', template, layout['checksum_offset'], meta['template_checksum'])
        struct.pack_into('<II', template, layout['security_offset'], 0, 0)
        digest = validate_template(bytes(template))
        if digest != meta['template_sha256']:
            _fail()
        return {'provisioning': envelope, 'template_sha256': digest,
                'package_nonce': meta['package_nonce'], 'certificate_present': layout['certificate_present']}
    _fail()
