# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import struct
import sys
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'windows/build-pjsip-windows.py'
sys.path.insert(0, str(TOOL.parent))
spec = importlib.util.spec_from_file_location('windows_pjsip_builder', TOOL)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
from pjsip_contract import validate_binding


class WindowsBuilderTest(unittest.TestCase):
    def test_portable_sdk_rejects_stale_native_observer_and_missing_exports(self):
        project = TOOL.parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = {'rtp_observer_protocol': 2, 'rtp_playout_distribution_protocol': 2,
                        'rtcp_arithmetic': 'vp-rtcp-safe-v1'}
            for name, source in [('observer_sha256', 'agent/installer/rtp-observer.h'),
                                 ('rtcp_arithmetic_sha256', 'agent/installer/rtcp-safe.h'),
                                 ('rtcp_patch_sha256', 'scripts/instrument-pjsip.py')]:
                metadata[name] = hashlib.sha256((project / source).read_bytes()).hexdigest()
            (root / 'binary.json').write_text(json.dumps(metadata))
            (root / 'pjsua2.py').write_text('class Call:\n    def getVoiceProbeStats(self, index): pass\n')
            binary = b'Call_getVoiceProbeStats\0vp-rtcp-safe-v1\0rtp-sequence-observer-v1\0'
            (root / '_pjsua2.pyd').write_bytes(binary)
            self.assertEqual(validate_binding(root, project)['binding_sha256'], hashlib.sha256(binary).hexdigest())
            for marker in (b'Call_getVoiceProbeStats', b'vp-rtcp-safe-v1', b'rtp-sequence-observer-v1'):
                (root / '_pjsua2.pyd').write_bytes(binary.replace(marker, b''))
                with self.subTest(marker=marker), self.assertRaises(ValueError):
                    validate_binding(root, project)
            (root / '_pjsua2.pyd').write_bytes(binary)
            (root / 'pjsua2.py').write_text('class Call: pass\n')
            with self.assertRaises(ValueError):
                validate_binding(root, project)
            (root / 'pjsua2.py').write_text('class Call:\n    def getVoiceProbeStats(self, index): pass\n')
            metadata['observer_sha256'] = '0' * 64
            (root / 'binary.json').write_text(json.dumps(metadata))
            with self.assertRaises(ValueError):
                validate_binding(root, project)

    def test_dependencies_require_exact_windows_python_abi_and_architecture(self):
        header = 'file format pei-x86-64\nDLL Name: python313.dll\nDLL Name: libwinpthread-1.dll\nDLL Name: KERNEL32.dll\n'
        self.assertEqual(len(builder.validate_dependencies(header)), 3)
        runtime_header = 'file format pei-x86-64\nDLL Name: KERNEL32.dll\nDLL Name: msvcrt.dll\n'
        self.assertEqual(len(builder.validate_dependencies(runtime_header, runtime=True)), 2)
        with self.assertRaises(ValueError):
            builder.validate_dependencies(runtime_header + 'DLL Name: unexpected.dll\n', runtime=True)
        for bad in (header.replace('python313.dll', 'python312.dll'),
                    header.replace('pei-x86-64', 'pei-i386'),
                    header + 'DLL Name: unknown-vendor.dll\n',
                    header.replace('DLL Name: libwinpthread-1.dll\n', '')):
            with self.subTest(header=bad), self.assertRaises(ValueError):
                builder.validate_dependencies(bad)

    def test_sdk_rejects_wrong_python_headers_and_pe_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'include').mkdir()
            (root / 'libs').mkdir()
            (root / 'include/Python.h').write_text('/* sdk */')
            (root / 'libs/python313.lib').write_bytes(b'import library')
            valid_headers = '#define PY_MAJOR_VERSION 3\n#define PY_MINOR_VERSION 13\n'
            (root / 'include/patchlevel.h').write_text(valid_headers)
            pe = bytearray(128)
            pe[:2] = b'MZ'
            struct.pack_into('<I', pe, 0x3c, 64)
            pe[64:68] = b'PE\0\0'
            struct.pack_into('<H', pe, 68, 0x8664)
            (root / 'python313.dll').write_bytes(pe)
            builder.validate_sdk(root)
            (root / 'include/patchlevel.h').write_text(valid_headers.replace('13', '12'))
            with self.assertRaises(ValueError):
                builder.validate_sdk(root)
            (root / 'include/patchlevel.h').write_text(valid_headers)
            struct.pack_into('<H', pe, 68, 0x14c)
            (root / 'python313.dll').write_bytes(pe)
            with self.assertRaises(ValueError):
                builder.validate_sdk(root)
            struct.pack_into('<I', pe, 0x3c, 999999)
            (root / 'python313.dll').write_bytes(pe)
            with self.assertRaises(ValueError):
                builder.validate_sdk(root)

    def test_source_archive_rejects_escaping_links_and_special_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, kind in [('pjproject-2.16/../../escape', tarfile.REGTYPE),
                               ('/pjproject-2.16/file', tarfile.REGTYPE),
                               ('other-source/file', tarfile.REGTYPE),
                               ('pjproject-2.16/link', tarfile.SYMTYPE),
                               ('pjproject-2.16/device', tarfile.CHRTYPE)]:
                archive = root / 'source.tar.gz'
                with tarfile.open(archive, 'w:gz') as output:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    output.addfile(member, io.BytesIO())
                with self.subTest(name=name), self.assertRaises(ValueError):
                    builder.safe_extract(archive, root / 'output')
                self.assertFalse((root / 'escape').exists())
            with tarfile.open(root / 'source.tar.gz', 'w:gz') as output:
                member = tarfile.TarInfo('pjproject-2.16/COPYING')
                member.size = 7
                output.addfile(member, io.BytesIO(b'license'))
            builder.safe_extract(root / 'source.tar.gz', root / 'valid')
            self.assertEqual((root / 'valid/pjproject-2.16/COPYING').read_bytes(), b'license')
