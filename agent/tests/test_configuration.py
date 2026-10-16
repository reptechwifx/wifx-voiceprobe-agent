"""Regression: administrative/identical saves must keep established SIP accounts."""

import copy, importlib.util, pathlib, sys, tempfile, threading, types, unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class NativeAccount:
    def __init__(self):
        self.created = []
        self.modified = []
        self.stopped = 0

    def create(self, cfg):
        self.created.append(cfg)
        self.registration_code = 200

    def modify(self, cfg):
        self.modified.append(cfg)
        self.registration_code = 200

    def shutdown(self):
        self.stopped += 1


class NativeConfiguration:
    def __init__(self):
        self.regConfig = types.SimpleNamespace()
        self.sipConfig = types.SimpleNamespace(authCreds=[], proxies=[])
        self.mediaConfig = types.SimpleNamespace(
            transportConfig=types.SimpleNamespace()
        )


class Route:
    def connect(self, *args):
        pass

    def getsockname(self):
        return ("192.0.2.10", 5060)

    def close(self):
        pass


sdk = types.SimpleNamespace(
    Account=NativeAccount,
    Call=object,
    AccountConfig=NativeConfiguration,
    AuthCredInfo=lambda *args: args,
    PJSUA_INVALID_ID=-1,
    Error=RuntimeError,
)
with patch.dict(sys.modules, {"pjsua2": sdk, "websockets": types.SimpleNamespace()}):
    spec = importlib.util.spec_from_file_location(
        "probe_configuration_test", ROOT / "src/main.py"
    )
    main = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main)


class ConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = main.Agent.__new__(main.Agent)
        self.a.cfg = {
            "id": "00000000-0000-4000-8000-000000000001",
            "name": "Initial",
            "token": "local-test-token",
            "local_password": "local-test-password",
        }
        self.a.path = pathlib.Path(self.tmp.name) / "config.json"
        self.a.config_lock = threading.RLock()
        self.a.accounts = {}
        self.a.calls = {}
        self.a.remote = None
        self.a.remote_fingerprint = None
        self.a.journal = main.EventJournal()
        self.a.endpoint = types.SimpleNamespace(
            codecEnum2=lambda: [], codecSetPriority=lambda *a: None
        )
        self.config = {
            "id": self.a.cfg["id"],
            "name": "Initial",
            "mode": "bidirectional",
            "max_calls": 4,
            "administrative": {"site": "Lausanne"},
            "metadata_revision": 1,
            "accounts": [
                {
                    "id": 1,
                    "name": "LAB",
                    "username": "7001",
                    "server": "pbx.example",
                    "registrar": "sip:pbx.example",
                    "auth_username": "7001",
                    "password": "sip-test-secret",
                    "transport": "udp",
                    "codecs": ["PCMU/8000"],
                    "allowed_destinations": ["7002"],
                    "max_calls": 4,
                }
            ],
        }
        self.route = patch.object(main.socket, "socket", return_value=Route())
        self.route.start()
        self.a.apply_config(copy.deepcopy(self.config))
        self.original = self.a.accounts[1]

    def tearDown(self):
        self.route.stop()
        self.tmp.cleanup()

    def test_admin_codec_and_control_changes_keep_native_registration(self):
        new = copy.deepcopy(self.config)
        new["name"] = "Central name"
        new["administrative"]["site"] = "Genève"
        new["metadata_revision"] = 2
        new["accounts"][0]["codecs"] = ["G722/16000", "PCMU/8000"]
        new["accounts"][0]["max_calls"] = 2
        new["accounts"][0]["allowed_destinations"] = ["7002", "7004"]
        self.a.apply_config(new)
        self.assertIs(self.original, self.a.accounts[1])
        self.assertEqual(len(self.original.created), 1)
        self.assertEqual(len(self.original.modified), 0)
        self.assertEqual(self.original.stopped, 0)
        self.assertEqual(self.original.registration_code, 200)
        self.assertEqual(self.a.cfg["administrative"]["site"], "Genève")
        self.assertEqual(self.original.config["max_calls"], 2)

    def test_sip_auth_change_modifies_the_existing_account(self):
        new = copy.deepcopy(self.config)
        new["accounts"][0]["password"] = "changed-test-secret"
        self.a.apply_config(new)
        self.assertIs(self.original, self.a.accounts[1])
        self.assertEqual(len(self.original.modified), 1)
        self.assertEqual(len(self.original.created), 1)
        self.assertEqual(self.original.stopped, 0)

    def test_active_call_defers_sip_changes_without_teardown(self):
        self.a.calls = {"active-run": object()}
        new = copy.deepcopy(self.config)
        new["accounts"][0]["password"] = "changed-test-secret"
        self.a.apply_config(new)
        self.assertEqual(self.original.stopped, 0)
        self.assertEqual(len(self.original.modified), 0)
        self.a.calls.clear()
        self.a.apply_config(new)
        self.assertEqual(len(self.original.modified), 1)

    def test_freed_media_slot_does_not_collide_with_retained_account(self):
        new = copy.deepcopy(self.config)
        second = copy.deepcopy(new["accounts"][0])
        second.update(id=3, username="7003", auth_username="7003")
        new["accounts"].append(second)
        self.a.apply_config(new)
        kept = self.a.accounts[3]
        new["accounts"].pop(0)
        third = copy.deepcopy(second)
        third.update(id=5, username="7005", auth_username="7005")
        new["accounts"].append(third)
        self.a.apply_config(new)
        self.assertIs(kept, self.a.accounts[3])
        self.assertNotEqual(self.a.accounts[3].rtp_slot, self.a.accounts[5].rtp_slot)
        self.assertEqual(self.original.stopped, 1)

    def test_configuration_ack_is_published_only_after_application_on_the_sip_thread(self):
        self.a.configuration_applied_revision = "a" * 64
        self.a.calls = {"existing": object()}
        new = copy.deepcopy(self.config)
        new["configuration_revision"] = "b" * 64
        new["accounts"][0]["max_duration_s"] = 20
        self.a.apply_config(new)
        self.assertEqual("a" * 64, self.a.configuration_applied_revision)
        self.a.calls.clear()
        self.a.apply_config(new)
        self.assertEqual("b" * 64, self.a.configuration_applied_revision)

    def test_revocation_keeps_account_alive_until_call_report_has_finished(self):
        call = types.SimpleNamespace(hangup_safe=lambda: None, account=self.original)
        self.a.calls = {"existing": call}
        self.a.prepared = {}
        self.a.rejected = []
        self.a.revoke_configuration()
        self.assertEqual(0, self.original.stopped)
        self.assertIn(1, self.a.accounts)
        self.a.calls.clear()
        self.a.retire_revoked_accounts()
        self.assertEqual(1, self.original.stopped)
        self.assertEqual({}, self.a.accounts)


if __name__ == "__main__":
    unittest.main()
