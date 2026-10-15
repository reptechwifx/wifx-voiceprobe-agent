import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from test_configuration import main
class RegistrationTest(unittest.TestCase):
    def test_deregistration_keeps_response_200_but_reports_inactive_and_state_change(self):
        account=main.ProbeAccount.__new__(main.ProbeAccount)
        account.registration_code=200;account.registration_active=True;account.registration_changed_at="before"
        account.config={"username":"test-only"};account.agent=SimpleNamespace(journal=Mock());account.getInfo=lambda:SimpleNamespace(regIsActive=False,regStatusText="OK")
        account.onRegState(SimpleNamespace(code=200))
        self.assertEqual(200,account.registration_code);self.assertFalse(account.registration_active);self.assertNotEqual("before",account.registration_changed_at)
        self.assertEqual("warning",account.agent.journal.record.call_args.kwargs["level"])
