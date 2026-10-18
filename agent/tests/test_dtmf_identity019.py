import pathlib
import sys
import tempfile
import unittest
import wave

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from audio import analyze, reference
from dtmf_identity import DISCOVERY_REPLY, DISCOVERY_REQUEST, FrameReceiver, checksum, decode, frame


class DtmfIdentity019Test(unittest.TestCase):
    def test_frame_round_trip_and_corruption(self):
        for token in ("0000000000", "9876543210", "9999999999"):
            encoded = frame("1", token)
            self.assertEqual(len(encoded), 15)
            self.assertEqual(decode(encoded), ("1", token))
            self.assertIsNone(decode(encoded[:-3] + "00#") if encoded[-3:-1] != "00" else decode(encoded[:-3] + "99#"))
            self.assertEqual(frame("2", token)[1], "2")
        self.assertEqual(checksum("19876543210"), frame("1", "9876543210")[-3:-1])
        self.assertIsNone(decode("*300000000000#"))
        self.assertIsNone(decode("*10000000000#"))

    def test_completed_digits_only_and_timeout(self):
        clock = [0.0]
        receiver = FrameReceiver(clock=lambda: clock[0], expected_kind="1")
        receiver.start()
        incoming = frame("1", "1234567890")
        for digit in incoming[:-1]:
            self.assertIsNone(receiver.feed(digit))
            clock[0] += 0.15
        self.assertEqual(receiver.feed("#"), ("1", "1234567890"))
        self.assertIsNone(receiver.feed("#"))
        late = FrameReceiver(clock=lambda: clock[0])
        late.start()
        clock[0] += 10.1
        for digit in incoming:
            self.assertIsNone(late.feed(digit))

    def test_short_discovery_does_not_consume_the_full_identification_frame(self):
        clock = [0.0]
        receiver = FrameReceiver(clock=lambda: clock[0], expected_kind="1")
        receiver.start()
        for control in (DISCOVERY_REQUEST, DISCOVERY_REPLY):
            result = None
            for digit in control:
                result = receiver.feed(digit)
                clock[0] += 0.16
            self.assertEqual(result, ("discovery", control))
            self.assertIsNone(receiver.result)
        result = None
        for digit in frame("1", "1234567890"):
            result = receiver.feed(digit)
            clock[0] += 0.16
        self.assertEqual(result, ("1", "1234567890"))

    def test_audio_reference_starts_after_identification_window(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "tone.wav"
            reference(path, 12, 8000)
            with wave.open(str(path), "rb") as source:
                data = np.frombuffer(source.readframes(source.getnframes()), dtype="<i2").copy()
            data[:80000] = 0
            with wave.open(str(path), "wb") as target:
                target.setparams((1, 2, 8000, 0, "NONE", ""))
                target.writeframes(data.tobytes())
            result = analyze(path, start_s=10)
            self.assertEqual(result["interrupted_s"], 0)
            self.assertGreater(result["tone_ratio_mean"], 0.99)
            self.assertGreaterEqual(result["timeline"][0]["offset_s"], 10.25)


if __name__ == "__main__":
    unittest.main()
