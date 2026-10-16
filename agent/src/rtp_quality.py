"""Bounded receiver observations. No RTP payload, guessed delay or PLC profile."""
import math

METHOD = 'vp-relative-transit-min-v1'
MAX_INTERVALS = 320


def percentile(histogram, count, resolution):
    if not count:
        return None
    rank = math.ceil(.95 * count)
    cumulative = 0
    for index, number in sorted(histogram.items()):
        cumulative += number
        if cumulative >= rank:
            return (index + 1) * resolution
    return None


class ReceiverQuality:
    def __init__(self):
        self.histogram = {}
        self.count = 0
        self.sum = 0.0
        self.minimum = self.maximum = None
        self.ssrc = None
        self.valid = True
        self.end_ms = 0.0
        self.intervals = []
        self.latest = None
        self.last = None

    def add(self, observation):
        if observation.get('protocol') != 1:
            raise ValueError('Unsupported receiver observation')
        count = observation['samples']
        bins = observation['bins']
        if not isinstance(count, int) or not 0 <= count <= 1_000_000 or len(bins) > 16001:
            raise ValueError('Invalid receiver histogram')
        histogram = {}
        for index, number in bins:
            if not isinstance(index, int) or not -8000 <= index <= 8000 or not isinstance(number, int) or number <= 0 or index in histogram:
                raise ValueError('Invalid receiver bin')
            histogram[index] = number
        if sum(histogram.values()) != count or observation['resolution_ms'] != .25:
            raise ValueError('Invalid receiver sample count')
        for name in ['min_ms', 'max_ms', 'sum_ms', 'jitter_sum_ms', 'elapsed_ms', 'packetization_ms', 'frame_ms']:
            if isinstance(observation[name], bool) or not isinstance(observation[name], (int, float)) or not math.isfinite(observation[name]):
                raise ValueError('Non-finite receiver statistic')
        for name in ['received', 'lost', 'loss_runs', 'total_received', 'total_lost', 'total_loss_runs', 'duplicates', 'reordered', 'excluded', 'overflow']:
            if type(observation[name]) is not int or not 0 <= observation[name] <= 1_000_000:
                raise ValueError('Invalid receiver counter')
        if count and (observation['min_ms'] > observation['max_ms'] or not observation['min_ms'] * count - .001 <= observation['sum_ms'] <= observation['max_ms'] * count + .001):
            raise ValueError('Inconsistent receiver moments')
        end = observation['elapsed_ms']
        if not math.isfinite(end) or end < self.end_ms or len(self.intervals) >= MAX_INTERVALS:
            self.valid = False
        if self.ssrc is not None and observation['ssrc'] != self.ssrc:
            self.valid = False
        self.ssrc = observation['ssrc']
        self.valid = self.valid and observation['valid'] and not observation['overflow']
        if count:
            self.minimum = observation['min_ms'] if self.minimum is None else min(self.minimum, observation['min_ms'])
            self.maximum = observation['max_ms'] if self.maximum is None else max(self.maximum, observation['max_ms'])
            self.count += count
            self.sum += observation['sum_ms']
            for index, number in histogram.items():
                self.histogram[index] = self.histogram.get(index, 0) + number
        if len(self.intervals) < MAX_INTERVALS and end > self.end_ms:
            self.intervals.append({'offset_s': round(self.end_ms / 1000, 3), 'duration_s': round((end - self.end_ms) / 1000, 3),
                'count': count, 'min_ms': observation['min_ms'] if count else None, 'max_ms': observation['max_ms'] if count else None,
                'sum_ms': observation['sum_ms'], 'p95_transit_ms': percentile(histogram, count, .25),
                'jitter_ms_mean': observation['jitter_sum_ms'] / count if count else None,
                'received': observation['received'], 'lost': observation['lost'], 'loss_runs': observation['loss_runs'],
                'valid': bool(observation['valid'])})
        self.end_ms = end
        self.last = observation
        return self

    def playout(self, codec, received, lost, runs):
        observation = self.last
        name = codec.upper().split('/')[0]
        # PJSIP's default G.711 PLC is WSOLA, not the G.711 Appendix I profile.
        profile = ('pjsip-wsola' if observation['plc_enabled'] else 'g711-no-plc') if name in ('PCMA', 'PCMU') else 'codec-profile-unqualified'
        probability = lost / (received + lost) if received + lost else 0
        burst = (lost / runs) * (1 - probability) if runs and lost else (1.0 if lost == 0 else None)
        return {'valid': bool(self.valid and self.count >= 2), 'profile': profile, 'packetization_ms': observation['packetization_ms'], 'frame_ms': observation['frame_ms'],
                'unit': 'decoder-frame', 'received': received, 'lost': lost, 'loss_runs': runs, 'burst_ratio': burst,
                'warmup': 'Initial prefetch excluded until first normal decoded frame', 'source': 'pjmedia-jbuf-output-v1'}

    def snapshot(self, codec=''):
        if not self.last:
            return {}
        result = {'timing': {'method': 'rtp-arrival-v1', 'representation': 'transit-histogram-v1',
            'clock_stable': bool(self.valid), 'ssrc': self.ssrc,
            'clock_reference': 'PJSIP monotonic timestamp / nominal 8000 Hz RTP clock; no clock-drift correction or absolute delay',
            'histogram': {'resolution_ms': .25, 'count': self.count, 'min_ms': self.minimum, 'max_ms': self.maximum,
                          'sum_ms': self.sum, 'bins': sorted(self.histogram.items())},
            'duplicates': self.last['duplicates'], 'reordered': self.last['reordered'], 'excluded': self.last['excluded'],
            'out_of_range': self.last['overflow'], 'observed_s': round(self.end_ms / 1000, 3)},
            'playout': self.playout(codec, self.last['total_received'], self.last['total_lost'], self.last['total_loss_runs']), 'intervals': []}
        for interval in self.intervals:
            summary = {key: interval[key] for key in ['count', 'min_ms', 'max_ms', 'sum_ms', 'p95_transit_ms']}
            result['intervals'].append({'offset_s': interval['offset_s'], 'duration_s': interval['duration_s'],
                'timing': {'method': 'rtp-arrival-v1', 'representation': 'transit-summary-v1', 'clock_stable': bool(self.valid and interval['valid']),
                           'ssrc': self.ssrc, 'reference_min_ms': self.minimum, 'resolution_ms': .25, 'summary': summary},
                'playout': self.playout(codec, interval['received'], interval['lost'], interval['loss_runs']), 'jitter_ms_mean': interval['jitter_ms_mean']})
        return result
