"""Execute the real portable PJSUA2 lifecycle on Windows, without SIP accounts.

A local-only refused Controller connection exercises network failure and close.
Supply the qualified PJSUA2 SDK on PYTHONPATH before running this test.
"""
import os
from pathlib import Path
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


@unittest.skipUnless(os.name == 'nt', 'Moteur natif Windows requis')
class PortableNativeWindowsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import pjsua2
            import psutil
        except ImportError:
            raise unittest.SkipTest('SDK PJSUA2 Windows qualifié absent de PYTHONPATH') from None

    def test_memory_credentials_no_admin_listener_clean_sip_shutdown_and_temp_cleanup(self):
        import psutil
        from portable_agent import PortableAgent
        # Synthetic invitation. No real Controller or PBX connection is possible.
        provision = {'name': 'Windows lifecycle LAB', 'controller_url': 'https://127.0.0.1:9',
                     'invitation_id': '12345678-1234-4321-8123-123456789abc', 'invitation_secret': 'A'*43}
        agent = PortableAgent(provision)
        directory = agent.data
        try:
            self.assertEqual(['echo-reference.wav', 'tone-1000.wav'], sorted(p.name for p in directory.iterdir()))
            self.assertNotIn('identity_private_key', agent.cfg)
            self.assertEqual(':memory:', agent.database_location())
            self.assertFalse(any(c.laddr and c.laddr.port == 18441 for c in psutil.Process().net_connections()))
            self.assertTrue(all(any(codec.startswith(prefix) for codec in agent.supported_codecs)
                                for prefix in ('G722/', 'PCMA/', 'PCMU/')))
            timer = threading.Timer(1.0, agent.request_stop)
            timer.start()
            try:
                agent.run()
            finally:
                timer.join(10)
            self.assertTrue(agent._closed_session)
            self.assertIsNone(agent.identity._key)
            self.assertEqual({}, agent.cfg)
            self.assertEqual({}, agent.provision)
            self.assertFalse(directory.exists())
        finally:
            if not agent._closed_session:
                agent.request_stop()
                agent.endpoint.libDestroy()
                agent.identity.close()
                agent._temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
