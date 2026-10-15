"""Client presentation boundaries, without a Windows desktop or network."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from portable_gui import badge_tone, client_notice, ticket_title, tray_tooltip


class PortablePresentationTest(unittest.TestCase):
    def test_ticket_caption_accepts_seven_digits_and_never_an_arbitrary_path(self):
        for reference in ('WSUP-24238', 'WSUP-123456', 'WSUP-1234567', 'WSUP-1'):
            self.assertEqual('Intervention '+reference, ticket_title({'ticket_reference': reference}))
        for reference in ('WSUP-12345678', '../secret', 'WSUP-42.exe', 'WSUP-42\npassword', None):
            self.assertEqual('Intervention WIFX', ticket_title({'ticket_reference': reference}))

    def test_expiration_message_takes_precedence_over_stale_active_call_display(self):
        title, text, tone = client_notice({'adoption': 'AUTORISATION EXPIRÉE', 'active_tests': 1})
        self.assertIn('EXPIRÉE', title)
        self.assertIn('plus de tests', text)
        self.assertIn('technicien WIFX', text)
        self.assertEqual('bad', tone)

    def test_ready_and_active_messages_explain_background_diagnostics(self):
        ready = {'adoption': 'ADOPTÉ PAR WIFX', 'controller': 'CONNECTÉ', 'active_tests': 0}
        self.assertEqual('SONDE PRÊTE', client_notice(ready)[0])
        ready['active_tests'] = 2
        self.assertEqual('DIAGNOSTIC EN COURS', client_notice(ready)[0])
        self.assertIn('ordinateur normalement', client_notice(ready)[1])

    def test_status_tooltip_has_no_sensitive_fields_and_distinguishes_revocation(self):
        view = {'controller': 'CONNECTÉ', 'active_tests': 1, 'adoption': 'ADOPTÉ PAR WIFX',
                'password': 'not-for-display', 'private_key': 'not-for-display'}
        tip = tray_tooltip(view)
        self.assertIn('Diagnostic actif', tip)
        self.assertNotIn('not-for-display', tip)
        view['adoption'] = 'AUTORISATION RÉVOQUÉE'
        self.assertIn('Autorisation révoquée', tray_tooltip(view))
        self.assertNotIn('Diagnostic actif', tray_tooltip(view))

    def test_connectivity_failure_is_never_a_green_quality_badge(self):
        self.assertEqual('bad', badge_tone('Appel établi, mais aucun média reçu.'))
        self.assertEqual('warning', badge_tone('En attente de tests'))
        self.assertNotEqual('good', badge_tone('INCONNU'))


if __name__ == '__main__':
    unittest.main()
