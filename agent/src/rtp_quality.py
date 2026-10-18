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


def annotate_pjsip_jitter(stats):
    """Keep original global statistics and expose failures without saturation."""
    provenance = stats.get('rx', {}).get('pjsip_jitter', {})
    if provenance.get('method') != 'vp-rtcp-safe-v1':
        return
    for direction in ('rx', 'tx'):
        stream = stats.get(direction)
        if not isinstance(stream, dict):
            continue
        flags = provenance.get(direction + '_invalid_flags')
        if type(flags) is not int or flags < 0:
            flags = 1
        previous = stream.get('jitter_calculation', {})
        raw_mean = stream.get('jitter_ms_mean')
        raw_max = stream.get('jitter_ms_max')
        if flags and raw_mean is None and previous.get('method') == provenance['method']:
            raw_mean, raw_max = previous.get('raw_mean_ms'), previous.get('raw_max_ms')
        stream['jitter_calculation'] = {
            'method': provenance['method'], 'valid': flags == 0, 'invalid_flags': flags,
            'raw_mean_ms': raw_mean, 'raw_max_ms': raw_max,
            'reason': 'Clock discontinuity or statistic outside its numeric domain' if flags else None,
        }
        if flags:
            stream['jitter_ms_mean'] = stream['jitter_ms_max'] = None


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
        self.codecs = set()
        self.format_stable = True
        self.last = None
        self.audio_baseline = None
        self.audio_interval_index = None

    def begin_audio_phase(self):
        """Snapshot decoder counters after identification; retain full-call observations."""
        if self.audio_baseline is not None:
            return
        if self.last is None:
            self.audio_baseline = (0, 0, 0, 0.0)
        else:
            self.audio_baseline = (self.last['total_received'], self.last['total_lost'],
                                   self.last['total_loss_runs'], self.end_ms)
        self.audio_interval_index = len(self.intervals)

    def add(self, observation, codec=None):
        if observation.get('protocol') != 1:
            raise ValueError('Unsupported receiver observation')
        if codec:
            if len(self.codecs) < 4:
                self.codecs.add(codec.upper())
            if len(self.codecs) > 1:
                self.format_stable = False
        if self.last and any(observation.get(key) != self.last.get(key) for key in ('frame_ms', 'plc_enabled')):
            self.format_stable = False
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
        distribution = observation.get('distribution_protocol', 1)
        if distribution not in (1, 2):
            raise ValueError('Unsupported playout distribution')
        if distribution == 2:
            local_runs = observation.get('interval_loss_runs')
            if type(local_runs) is not int or not 0 <= local_runs <= observation['lost'] or any(type(observation.get(k)) is not bool for k in ('interval_starts_lost', 'interval_ends_lost')):
                raise ValueError('Invalid interval loss boundaries')
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
                'received': observation['received'], 'lost': observation['lost'], 'loss_runs': observation.get('interval_loss_runs', observation['loss_runs']),
                'distribution_protocol': distribution, 'starts_lost': observation.get('interval_starts_lost'), 'ends_lost': observation.get('interval_ends_lost'),
                'valid': bool(observation['valid'])})
        self.end_ms = end
        self.last = observation
        return self

    def playout(self, codec, received, lost, runs, distribution=None):
        observation = self.last
        name = codec.upper().split('/')[0]
        # PJSIP's default G.711 PLC is WSOLA, not the G.711 Appendix I profile.
        profile = ('pjsip-wsola' if observation['plc_enabled'] else 'g711-no-plc') if name in ('PCMA', 'PCMU') else 'codec-profile-unqualified'
        probability = lost / (received + lost) if received + lost else 0
        burst = (lost / runs) * (1 - probability) if runs and lost else (1.0 if lost == 0 else None)
        return {'valid': bool(self.valid and self.format_stable and self.count >= 2), 'format_stable': self.format_stable, 'observed_codecs': sorted(self.codecs), 'profile': profile, 'packetization_ms': observation['packetization_ms'], 'frame_ms': observation['frame_ms'],
                'distribution_protocol': distribution or observation.get('distribution_protocol', 1), 'unit': 'decoder-frame', 'received': received, 'lost': lost, 'loss_runs': runs, 'burst_ratio': burst,
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
        if self.audio_baseline is not None:
            received, lost, runs, start_ms = self.audio_baseline
            deltas = (self.last['total_received'] - received, self.last['total_lost'] - lost,
                      self.last['total_loss_runs'] - runs)
            audio = self.playout(codec, *[max(0, value) for value in deltas])
            audio['valid'] = bool(audio['valid'] and all(value >= 0 for value in deltas)
                                  and deltas[0] + deltas[1] > 0 and deltas[2] <= deltas[1])
            result['audio_phase'] = {'method': 'decoder-counter-baseline-v1',
                                     'start_observed_s': round(start_ms / 1000, 3),
                                     'playout': audio}
        if self.last.get('pjsip_jitter', {}).get('method') == 'vp-rtcp-safe-v1':
            result['pjsip_jitter'] = dict(self.last['pjsip_jitter'])
        for index, interval in enumerate(self.intervals):
            summary = {key: interval[key] for key in ['count', 'min_ms', 'max_ms', 'sum_ms', 'p95_transit_ms']}
            result['intervals'].append({'offset_s': interval['offset_s'], 'duration_s': interval['duration_s'],
                'phase': 'audio' if self.audio_interval_index is not None and index >= self.audio_interval_index else 'identification' if self.audio_baseline is not None else 'full_call',
                'timing': {'method': 'rtp-arrival-v1', 'representation': 'transit-summary-v1', 'clock_stable': bool(self.valid and interval['valid']),
                           'ssrc': self.ssrc, 'reference_min_ms': self.minimum, 'resolution_ms': .25, 'summary': summary},
                'playout': dict(self.playout(codec, interval['received'], interval['lost'], interval['loss_runs'], interval['distribution_protocol']), starts_lost=interval['starts_lost'], ends_lost=interval['ends_lost']), 'jitter_ms_mean': interval['jitter_ms_mean']})
        return result
