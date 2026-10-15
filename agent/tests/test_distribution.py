import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('agent_distribution', ROOT / 'scripts/agent-distribution.py')
distribution = importlib.util.module_from_spec(spec); spec.loader.exec_module(distribution)


class DistributionTest(unittest.TestCase):
    def archive(self, path, name, content=b'content', link=False):
        with tarfile.open(path, 'w:gz') as archive:
            info=tarfile.TarInfo(name);info.size=len(content)
            if link:info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';info.size=0
            archive.addfile(info,None if link else io.BytesIO(content))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_agent_only_source_members_exclude_controller_gateway(self):
        members=distribution.members(ROOT)
        self.assertNotIn('agent/src/gateway.py',members)
        self.assertFalse(any(name.startswith('controller/') for name in members))
        self.assertEqual((ROOT/'agent/VERSION').read_bytes(),members['VERSION'])
        self.assertIn('agent/installer/manage.py',members)

    def test_archive_integrity_and_path_traversal_are_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'source.tar.gz'
            checksum=self.archive(archive,'voiceprobe-agent-0.9-002/../../outside')
            with self.assertRaises(ValueError):distribution.extract(archive,root/'out',checksum)
            self.assertFalse((root/'outside').exists())
            checksum=self.archive(archive,'voiceprobe-agent-0.9-002/link',link=True)
            with self.assertRaises(ValueError):distribution.extract(archive,root/'out',checksum)
            with self.assertRaises(ValueError):distribution.extract(archive,root/'out','0'*64)

    def test_manifest_detects_tampering_unexpected_files_and_wrong_version(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'VERSION').write_text('0.9-002\n')
            (root/'release-manifest.json').write_text(json.dumps({'version':'0.9-002','files':{'VERSION':hashlib.sha256((root/'VERSION').read_bytes()).hexdigest()}}))
            distribution.validate(root,'0.9-002')
            with self.assertRaises(ValueError):distribution.validate(root,'0.9-001')
            (root/'unexpected').write_text('unknown')
            with self.assertRaises(ValueError):distribution.validate(root)
            (root/'unexpected').unlink();(root/'VERSION').write_text('0.9-002\nchanged')
            with self.assertRaises(ValueError):distribution.validate(root)
