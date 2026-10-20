"""Platform gates affected by the Debian 13 ARM64 port; no media simulation."""
import importlib.util
import io
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('arm64_manager', ROOT/'agent/installer/manage.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class NativePlatform(unittest.TestCase):
    def detect(self, cpu='aarch64', userspace='arm64', machine=183,
               os_name='debian', os_version='13', python=(3, 13), bits=64):
        header = bytearray(20)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = machine.to_bytes(2, 'little')
        def path(value):
            if value == '/proc/self/exe':
                return types.SimpleNamespace(open=lambda *_: io.BytesIO(header))
            if value == '/run/systemd/system':
                return types.SimpleNamespace(is_dir=lambda: True)
            return Path(value)
        runtime = types.SimpleNamespace(version_info=python, maxsize=2**(bits-1)-1,
                                        implementation=types.SimpleNamespace(cache_tag='cpython-'+''.join(map(str, python))))
        with patch.object(m, 'Path', side_effect=path), patch.object(m, 'sys', runtime), \
             patch.object(m.platform, 'machine', return_value=cpu), \
             patch.object(m.platform, 'freedesktop_os_release', return_value={'ID': os_name, 'VERSION_ID': os_version}), \
             patch.object(m, 'command', return_value=(userspace+'\n').encode()), \
             patch.object(m.shutil, 'which', return_value='/usr/bin/systemctl'):
            return m.Manager.platform_key(object())

    def test_debian13_arm64_python313_is_selected(self):
        self.assertEqual('debian-13-arm64-cp313', self.detect())

    def test_kernel_userspace_python_and_os_must_match(self):
        for values in ({'userspace':'armhf'}, {'bits':32}, {'machine':62},
                       {'cpu':'armv7l'}, {'python':(3,12)}, {'os_version':'12'},
                       {'os_name':'ubuntu','os_version':'24.04'}):
            with self.subTest(values=values), self.assertRaises(m.Failure):
                self.detect(**values)

    def test_existing_amd64_targets_are_retained(self):
        self.assertEqual('debian-12-amd64-cp311', self.detect(cpu='x86_64', userspace='amd64', machine=62, os_version='12', python=(3,11)))
        self.assertEqual('ubuntu-24.04-amd64-cp312', self.detect(cpu='x86_64', userspace='amd64', machine=62, os_name='ubuntu', os_version='24.04', python=(3,12)))

    def test_network_profile_applies_to026(self):
        self.assertTrue(m.network_diagnostics('0.9-026'))


if __name__ == '__main__':
    unittest.main()
