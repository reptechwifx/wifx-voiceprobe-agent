"""Apply profiles at stream creation through the pinned PJSUA2 2.16 API.

Fixed mode is the exact state transformation of pjmedia_jbuf_set_fixed in 2.16:
init=min=max=prefetch and discard NONE. No delay is simulated. Do not enable on
other native versions without verifying their stream/jbuf implementations.
"""
from jitter_buffer import configuration

FIELDS = {'initial_ms': 'jbInit', 'min_prefetch_ms': 'jbMinPre',
          'max_prefetch_ms': 'jbMaxPre', 'capacity_ms': 'jbMax',
          'discard_algorithm': 'jbDiscardAlgo'}


def validate_profile(profile):
    if not isinstance(profile, dict) or set(profile) != {'mode', *FIELDS}:
        raise ValueError('JITTER_PROFILE_INVALID: Complete profile required')
    if profile['mode'] not in ('fixed', 'adaptive'):
        raise ValueError('JITTER_PROFILE_INVALID: Unsupported mode')
    for key in FIELDS:
        lower, upper = (0, 2) if key == 'discard_algorithm' else (1, 1000)
        if type(profile[key]) is not int or not lower <= profile[key] <= upper:
            raise ValueError('JITTER_PROFILE_INVALID: Parameter out of bounds')
    if not profile['min_prefetch_ms'] <= profile['initial_ms'] <= profile['max_prefetch_ms'] <= profile['capacity_ms']:
        raise ValueError('JITTER_PROFILE_INVALID: Invalid prefetch/capacity ordering')
    if profile['mode'] == 'fixed' and (len({profile[k] for k in ('initial_ms', 'min_prefetch_ms', 'max_prefetch_ms')}) != 1 or profile['discard_algorithm'] != 0):
        raise ValueError('JITTER_PROFILE_INVALID: Fixed requires equal prefetch and discard NONE')
    return dict(profile)


def supported(version, call_type):
    return version == '2.16' and hasattr(call_type, 'onStreamPreCreate')


def apply_profile(info, profile, version):
    profile = validate_profile(profile)
    if version != '2.16':
        raise ValueError('JITTER_PROFILE_UNSUPPORTED: PJSIP version not qualified')
    frame_ms = configuration(info)['frame_ms']
    if not frame_ms or any(abs(profile[key] / frame_ms - round(profile[key] / frame_ms)) > 1e-7
                           for key in FIELDS if key != 'discard_algorithm'):
        raise ValueError('JITTER_PROFILE_INCOMPATIBLE: Values must be whole codec frames')
    for key, attribute in FIELDS.items():
        if not hasattr(info, attribute):
            raise ValueError('JITTER_PROFILE_UNSUPPORTED: Binding field unavailable')
    for key, attribute in FIELDS.items():
        setattr(info, attribute, profile[key])
    return {'requested': profile, 'creation_applied': dict(profile), 'frame_ms': frame_ms,
            'implementation': 'pjsip-2.16-fixed-state-equivalence-v1' if profile['mode'] == 'fixed' else 'pjsua2-stream-precreate-adaptive-v1',
            'readback_verified': False}


def verify_readback(application, state, info):
    if not application:
        return None
    requested = application['creation_applied']
    frame = application['frame_ms']
    checks = [state.get('min_prefetch_frames') == requested['min_prefetch_ms'] / frame,
              state.get('max_prefetch_frames') == requested['max_prefetch_ms'] / frame,
              getattr(info, 'jbDiscardAlgo', None) == requested['discard_algorithm']]
    if requested['mode'] == 'fixed':
        checks.append(state.get('prefetch_frames') == requested['initial_ms'] / frame)
    return {**application, 'readback_verified': all(checks),
            'readback_scope': 'min/max prefetch, discard algorithm; current prefetch for fixed; capacity unavailable'}
