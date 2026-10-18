import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dtmf_identity import (NUMERIC_DISCOVERY_REQUEST, NUMERIC_DISCOVERY_REPLY,
                           FrameReceiver, NumericFrameReceiver, decode_numeric, frame, numeric_frame)


class NumericDtmfIdentity021Test(unittest.TestCase):
    def test_stripped_v1_feature_prefix_is_not_a_valid_frame(self):
        clock = [0.0]
        old = FrameReceiver(clock=lambda: clock[0], expected_kind="1")
        old.start()
        encoded = frame("1", "3964603446")
        self.assertTrue(encoded.startswith("*1"))
        for digit in encoded[2:]:
            self.assertIsNone(old.feed(digit))
            clock[0] += 0.1
        numeric = NumericFrameReceiver(clock=lambda: clock[0], expected_kind="1")
        numeric.start()
        result = None
        for digit in NUMERIC_DISCOVERY_REQUEST + numeric_frame("1", "3964603446"):
            result = numeric.feed(digit) or result
            clock[0] += 0.1
        self.assertEqual(result, ("1", "3964603446"))

    def test_only_digits_are_transmitted_and_checksum_rejects_corruption(self):
        for token in ("0000000000", "9876543210", "9999999999"):
            for kind in ("1", "2"):
                encoded = numeric_frame(kind, token)
                self.assertEqual(len(encoded), 14)
                self.assertTrue(encoded.isdecimal())
                self.assertEqual(decode_numeric(encoded), (kind, token))
                damaged = encoded[:12] + ("00" if encoded[12:] != "00" else "99")
                self.assertIsNone(decode_numeric(damaged))
        self.assertTrue(NUMERIC_DISCOVERY_REQUEST.isdecimal())
        self.assertTrue(NUMERIC_DISCOVERY_REPLY.isdecimal())

    def test_repeated_discovery_and_sliding_frame_resynchronization(self):
        clock = [0.0]
        receiver = NumericFrameReceiver(clock=lambda: clock[0], expected_kind="1")
        receiver.start()
        for sequence in ("99" + NUMERIC_DISCOVERY_REQUEST[:2], NUMERIC_DISCOVERY_REQUEST):
            result = None
            for digit in sequence:
                result = receiver.feed(digit)
                clock[0] += 0.1
        self.assertEqual(result, ("discovery", NUMERIC_DISCOVERY_REQUEST))
        result = None
        for digit in "7" + numeric_frame("1", "1234567890"):
            result = receiver.feed(digit)
            clock[0] += 0.1
        self.assertEqual(result, ("1", "1234567890"))
        self.assertGreater(receiver.invalid, 0)

    def test_timeout_and_wrong_kind(self):
        clock = [0.0]
        receiver = NumericFrameReceiver(clock=lambda: clock[0], expected_kind="2")
        receiver.start()
        for digit in NUMERIC_DISCOVERY_REPLY:
            receiver.feed(digit)
        for digit in numeric_frame("1", "1234567890"):
            self.assertIsNone(receiver.feed(digit))
        clock[0] = 10.01
        for digit in numeric_frame("2", "1234567890"):
            self.assertIsNone(receiver.feed(digit))

    def test_repeated_init_can_request_a_replacement_ack_without_splitting_identifier(self):
        receiver = NumericFrameReceiver(expected_kind="1")
        receiver.start()
        for _ in range(2):
            result = None
            for digit in NUMERIC_DISCOVERY_REQUEST:
                result = receiver.feed(digit)
            self.assertEqual(result, ("discovery", NUMERIC_DISCOVERY_REQUEST))
        result = None
        for digit in numeric_frame("1", "0017048300"):
            result = receiver.feed(digit)
        self.assertEqual(result, ("1", "0017048300"))


if __name__ == "__main__":
    unittest.main()
