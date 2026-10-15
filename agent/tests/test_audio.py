import unittest, tempfile, pathlib, sys, wave, json
import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from audio import reference, analyze


class AudioTest(unittest.TestCase):
    def test_reference_survives_phase_and_mulaw_quantization(self):
        import audioop

        with tempfile.TemporaryDirectory() as directory:
            p = pathlib.Path(directory) / "reference.wav"
            reference(p, 3)
            with wave.open(str(p), "rb") as w:
                data = w.readframes(w.getnframes())
                rate = w.getframerate()
            shifted = audioop.ulaw2lin(audioop.lin2ulaw(data, 2), 2)[94:]
            with wave.open(str(p), "wb") as w:
                w.setparams((1, 2, rate, 0, "NONE", ""))
                w.writeframes(shifted)
            result = analyze(p)
            json.dumps(result)
            self.assertGreater(result["tone_ratio_mean"], 0.98)
            self.assertEqual(result["interrupted_s"], 0)
            self.assertAlmostEqual(result["rms_dbfs"], -15, delta=0.4)

    def test_audio_gap_is_timed_without_counting_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            p = pathlib.Path(directory) / "gap.wav"
            reference(p, 3)
            with wave.open(str(p), "rb") as w:
                data = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").copy()
            data[:1600] = 0
            data[8000:10400] = 0
            with wave.open(str(p), "wb") as w:
                w.setparams((1, 2, 8000, 0, "NONE", ""))
                w.writeframes(data.tobytes())
            result = analyze(p)
            self.assertEqual(len(result["interruptions"]), 1)
            self.assertAlmostEqual(result["interrupted_s"], 0.3, delta=0.021)
            self.assertAlmostEqual(
                result["interruptions"][0]["start_s"], 1, delta=0.021
            )

    def test_wrong_tone_is_not_reported_as_the_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            p = pathlib.Path(directory) / "wrong.wav"
            x = (np.sin(2 * np.pi * 500 * np.arange(16000) / 8000) * 8192).astype("<i2")
            with wave.open(str(p), "wb") as w:
                w.setparams((1, 2, 8000, 0, "NONE", ""))
                w.writeframes(x.tobytes())
            result = analyze(p)
            self.assertLess(result["tone_ratio_mean"], 0.01)
            self.assertGreater(result["interrupted_s"], 1)


if __name__ == "__main__":
    unittest.main()
