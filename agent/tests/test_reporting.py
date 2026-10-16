import json
import pathlib
import sqlite3
import sys
import threading
import unittest
from unittest.mock import Mock
import requests
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from reporting import recovery_report, ReportOutbox


class RecoveryTest(unittest.TestCase):
    def test_new_crash_metadata_preserves_account_and_legacy_unknown_stays_unknown(self):
        incoming = {'observed_at': '2026-10-16T00:00:00Z', 'correlation': 'unrecognized'}
        legacy = recovery_report(incoming)
        self.assertEqual(incoming, legacy['incoming'])
        self.assertNotIn('account_id', legacy['sip'])
        new = recovery_report({'incoming': incoming, 'account_id': 3})
        self.assertEqual(3, new['sip']['account_id'])
        for body in (legacy, new, recovery_report()):
            self.assertFalse(body['established'])
            self.assertEqual({}, body['rtp'])
            self.assertNotIn('call_id', body['sip'])
            self.assertNotIn('codec', body['sip'])
        self.assertNotIn('incoming', recovery_report())


class OutboxTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute('CREATE TABLE reports(run_id TEXT PRIMARY KEY,payload TEXT)')
        self.now = 1000
        self.lock = threading.Lock()
        self.outbox = ReportOutbox(self.db, self.lock, clock=lambda:self.now)

    def response(self, status=200, errors=None):
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps({'errors': errors or {}}).encode()
        return response

    def insert(self, rid, body=None):
        payload = json.dumps(recovery_report() if body is None else body)
        self.db.execute('INSERT INTO reports VALUES (?,?)', (rid, payload)); self.db.commit()
        return payload

    def test_permanent_failure_keeps_payload_and_does_not_block_following_reports(self):
        first = self.insert('first', recovery_report({'observed_at': '2026-10-16T00:00:00Z'}))
        second = self.insert('second')
        api = Mock(side_effect=[self.response(422, {'sip.account_id': ['SECRET value'], 'token': ['secret']}), self.response()])
        self.assertFalse(self.outbox.deliver('first', first, api))
        self.assertTrue(self.outbox.deliver('second', second, api))
        self.assertEqual([('first', first)], self.db.execute('SELECT * FROM reports').fetchall())
        status = self.outbox.snapshot()
        self.assertEqual(['sip.account_id'], status['errors'][0]['fields'])
        self.assertEqual('incoming/first/report', status['errors'][0]['endpoint'])
        self.assertNotIn('SECRET', json.dumps(status))
        self.assertNotIn('secret', json.dumps(status))
        self.assertFalse(self.outbox.deliver('first', first, api))
        self.assertEqual(2, api.call_count)
        # Reopen on the same durable database: retry delay and payload survive.
        resumed = ReportOutbox(self.db, self.lock, clock=lambda:self.now)
        self.now += 301
        self.assertTrue(resumed.deliver('first', first, Mock(return_value=self.response())))
        self.assertEqual(0, resumed.snapshot()['pending'])

    def test_authentication_and_transient_failures_propagate_without_losing_data(self):
        payload = self.insert('run')
        for status in (401, 429, 408, 503):
            with self.subTest(status=status), self.assertRaises(requests.HTTPError):
                self.outbox.deliver('run', payload, Mock(return_value=self.response(status)))
        self.assertEqual(1, self.outbox.snapshot()['pending'])

    def test_corrupt_local_report_is_preserved_without_hiding_valid_reports(self):
        self.db.execute('INSERT INTO reports VALUES (?,?)', ('bad', '{'))
        api = Mock()
        self.assertFalse(self.outbox.deliver('bad', '{', api)); api.assert_not_called()
        payload = self.insert('good')
        self.assertTrue(self.outbox.deliver('good', payload, Mock(return_value=self.response())))
        self.assertEqual('invalid_local_json', self.outbox.snapshot()['errors'][0]['state'])


if __name__ == '__main__':
    unittest.main()
