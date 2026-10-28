"""Versioned, bounded snapshots of actual PJSUA2 receiver jitter-buffer state.

No RTP jitter, RTT or packet-loss statistic is used to fabricate buffer state.
"""
import datetime
import math
import time

FIELDS = {
    'frame_bytes': 'frameSize', 'min_prefetch_frames': 'minPrefetch',
    'max_prefetch_frames': 'maxPrefetch', 'prefetch_frames': 'prefetch',
    'occupancy_frames': 'size', 'burst_frames': 'burst', 'avg_burst_frames': 'avgBurst',
    'delay_mean_ms': 'avgDelayMsec', 'delay_min_ms': 'minDelayMsec',
    'delay_max_ms': 'maxDelayMsec', 'delay_stddev_ms': 'devDelayMsec',
    'lost': 'lost', 'discarded': 'discard', 'empty': 'empty',
}
COUNTERS = ('lost', 'discarded', 'empty')
CONFIG = {'initial_ms': 'jbInit', 'min_prefetch_ms': 'jbMinPre',
          'max_prefetch_ms': 'jbMaxPre', 'capacity_ms': 'jbMax',
          'discard_algorithm': 'jbDiscardAlgo'}
UNAVAILABLE = ('mode', 'capacity_frames', 'current_delay_ms', 'overflow_events',
               'late_packets', 'plc_operations', 'decoder_errors', 'reset_events',
               'rx_ptime_ms', 'delay_sample_count')


def number(obj, name):
    value = getattr(obj, name, None)
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def configuration(info):
    codec = getattr(info, 'audCodecParam', None)
    codec_info = getattr(codec, 'info', None)
    frame = number(codec_info, 'frameLen')
    denominator = number(codec_info, 'frameLenDenum')
    frame_ms = frame / (denominator or 1) if frame else None
    encoder = number(codec_info, 'encFrameLen')
    encoder_denominator = number(codec_info, 'encFrameLenDenum')
    encoder_ms = encoder / (encoder_denominator or 1) if encoder else frame_ms
    per_packet = number(getattr(codec, 'setting', None), 'frmPerPkt')
    return {'source': 'Call.getStreamInfo',
            'stream_parameters': {key: number(info, attribute) for key, attribute in CONFIG.items()},
            'stream_parameters_scope': 'creation parameters; defaults/rounding may differ from live state',
            'codec': getattr(info, 'codecName', None), 'frame_ms': frame_ms,
            'tx_ptime_ms': encoder_ms * per_packet if encoder_ms and per_packet else None,
            **{key: None for key in UNAVAILABLE}}


class JitterBufferHistory:
    INTERVAL_S = 1.0
    LIMIT = 601

    def __init__(self):
        self.started = time.monotonic()
        self.last_at = None
        self.previous = None
        self.previous_rtp = None
        self.segment = 0
        self.samples = []
        self.total = 0
        self.occupancy_count = 0
        self.occupancy_sum = 0
        self.occupancy_min = None
        self.occupancy_max = None
        self.last = None

    def new_stream(self):
        self.segment += 1
        self.previous = None
        self.previous_rtp = None
        self.last_at = None

    def observe(self, stat, info, *, rx=None, now=None, utc=None):
        now = time.monotonic() if now is None else now
        if self.last_at is not None and now - self.last_at < self.INTERVAL_S:
            return self.last
        state = {key: number(stat, attribute) for key, attribute in FIELDS.items()}
        if not any(value is not None for value in state.values()):
            return None
        decrease = self.previous is not None and any(
            state[key] is not None and self.previous[key] is not None and state[key] < self.previous[key]
            for key in COUNTERS)
        if decrease:
            self.new_stream()  # Counter discontinuity, not proof of a native reset event.
        delta = {key: state[key] - self.previous[key]
                 if self.previous is not None and state[key] is not None and self.previous[key] is not None
                 else None for key in COUNTERS}
        sample = {'offset_s': round(now - self.started, 3),
                  'utc': utc or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'segment': self.segment, 'counter_discontinuity': decrease,
                  'state': state, 'delta': delta}
        rx = rx or {}
        rtp = {key: value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
               for key in ('packets', 'loss', 'reordered', 'duplicates', 'jitter_ms_mean', 'jitter_ms_max')
               for value in (rx.get(key),)}
        sample['rtp_rx'] = rtp
        sample['rtp_delta'] = {key: value - self.previous_rtp[key]
                               if self.previous_rtp and value is not None and self.previous_rtp[key] is not None and value >= self.previous_rtp[key]
                               else None for key, value in rtp.items() if key in ('packets', 'loss', 'reordered', 'duplicates')}
        playout = rx.get('playout', {})
        sample['playout'] = {key: playout.get(key) for key in ('empty', 'prefetch', 'missing')} if playout.get('valid') is True and playout.get('source') == 'pjmedia-jbuf-output-v1' else None
        self.previous_rtp = rtp
        self.total += 1
        if len(self.samples) < self.LIMIT:
            self.samples.append(sample)
        size = state['occupancy_frames']
        if size is not None:
            self.occupancy_count += 1
            self.occupancy_sum += size
            self.occupancy_min = size if self.occupancy_min is None else min(self.occupancy_min, size)
            self.occupancy_max = size if self.occupancy_max is None else max(self.occupancy_max, size)
        self.last_at, self.previous = now, state
        self.last = {'protocol': 1, 'source': 'Call.getStreamStat.jbuf', 'scope': 'local_receiver',
                     **{key: state[key] for key in COUNTERS},
                     'configuration': configuration(info), 'state': state,
                     'sample_interval_s': self.INTERVAL_S, 'samples': self.samples,
                     'sample_count': self.total, 'truncated': self.total > self.LIMIT,
                     'clock': {'reference': 'monotonic_since_call_creation', 'utc_uncertainty_ms': None},
                     'occupancy_sampled': {'count': self.occupancy_count, 'min_frames': self.occupancy_min,
                                          'max_frames': self.occupancy_max,
                                          'mean_frames': self.occupancy_sum / self.occupancy_count if self.occupancy_count else None}}
        return self.last
