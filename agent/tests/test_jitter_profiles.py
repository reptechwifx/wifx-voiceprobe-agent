import pathlib
import sys
import types
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from jitter_profiles import apply_profile, validate_profile, verify_readback, FIELDS


class JitterProfilesTest(unittest.TestCase):
    def profile(self, **overrides):
        return {'mode': 'fixed', 'initial_ms': 40, 'min_prefetch_ms': 40,
                'max_prefetch_ms': 40, 'capacity_ms': 200, 'discard_algorithm': 0, **overrides}

    def test_fixed_requires_exact_state_equivalence_and_native_version(self):
        with self.assertRaises(ValueError):
            validate_profile(self.profile(discard_algorithm=2))
        with self.assertRaises(ValueError):
            validate_profile(self.profile(min_prefetch_ms=20))
        with self.assertRaises(ValueError):
            apply_profile(None, self.profile(), '2.17')

    def test_parameters_are_written_before_stream_creation_and_read_back(self):
        info = types.SimpleNamespace(**{field: -1 for field in FIELDS.values()},
                                     audCodecParam=types.SimpleNamespace(info=types.SimpleNamespace(frameLen=10)))
        application = apply_profile(info, self.profile(), '2.16')
        self.assertEqual(info.jbInit, 40)
        self.assertEqual(info.jbDiscardAlgo, 0)
        state = {'min_prefetch_frames': 4, 'max_prefetch_frames': 4, 'prefetch_frames': 4}
        self.assertTrue(verify_readback(application, state, info)['readback_verified'])
        state['prefetch_frames'] = 5
        self.assertFalse(verify_readback(application, state, info)['readback_verified'])

    def test_non_integral_frames_are_rejected_without_any_mutation(self):
        info = types.SimpleNamespace(**{field: -1 for field in FIELDS.values()},
                                     audCodecParam=types.SimpleNamespace(info=types.SimpleNamespace(frameLen=30)))
        with self.assertRaises(ValueError):
            apply_profile(info, self.profile(), '2.16')
        self.assertEqual(info.jbInit, -1)
