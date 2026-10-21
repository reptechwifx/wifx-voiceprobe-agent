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
        self.network_buckets = {}
        self.network_meta = None

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
        if observation.get('protocol') not in (1, 2):
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
        states = observation.get('playout_states')
        if states is not None:
            if states.get('protocol') != 1 or any(type(states.get(k)) is not int or states[k] < 0 or states[k] > 1_000_000 for k in
                ('missing', 'empty', 'prefetch', 'total_missing', 'total_empty', 'total_prefetch')):
                raise ValueError('Invalid playout states')
            if states['missing'] + states['empty'] + states['prefetch'] != observation['lost']:
                raise ValueError('Inconsistent playout states')
        network = observation.get('network')
        if network is not None:
            if network.get('protocol') != 1 or network.get('method') != 'rtp-sequence-observer-v1' or network.get('bucket_s') != 2 or type(network.get('valid')) is not bool:
                raise ValueError('Unsupported network observation')
            origin = network.get('origin_delta_ms')
            if isinstance(origin, bool) or not isinstance(origin, (int, float)) or not math.isfinite(origin) or abs(origin) > 605000:
                raise ValueError('Invalid network origin')
            changes = network.get('changes')
            segments = network.get('segments')
            if not isinstance(changes, list) or len(changes) > MAX_INTERVALS or not isinstance(segments, list) or len(segments) > 16:
                raise ValueError('Invalid network bounds')
            for row in changes:
                if not isinstance(row, list) or len(row) != 12 or any(type(v) is not int or v < 0 or v > 1_000_000 for v in row) or row[0] >= MAX_INTERVALS:
                    raise ValueError('Invalid network bucket')
                if row[2] + row[3] != row[1] or row[5] + row[6] + row[7] != row[4]:
                    raise ValueError('Inconsistent network bucket')
            for segment in segments:
                if not isinstance(segment, dict) or any(k not in segment for k in ('id', 'ssrc', 'start_s', 'end_s', 'first_seq', 'last_seq')):
                    raise ValueError('Invalid network segment')
            self.network_meta = {k: network[k] for k in ('protocol', 'method', 'bucket_s', 'valid', 'out_of_window', 'origin_delta_ms', 'segments')}
            for row in changes:
                self.network_buckets[row[0]] = row
        end = observation['elapsed_ms']
        if not math.isfinite(end) or end < self.end_ms or len(self.intervals) >= MAX_INTERVALS:
            self.valid = False
        if self.ssrc is not None and observation['ssrc'] != self.ssrc:
            self.valid = False
        self.ssrc = observation['ssrc']
        local_timing_valid = bool(observation['valid'] and not observation['overflow'])
        self.valid = self.valid and local_timing_valid
        local_format_stable = not self.last or all(observation.get(key) == self.last.get(key) for key in ('frame_ms', 'plc_enabled', 'packetization_ms'))
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
                'valid': local_timing_valid, 'ssrc': observation['ssrc'], 'codec': codec,
                'format_stable': local_format_stable, 'packetization_ms': observation['packetization_ms'],
                'frame_ms': observation['frame_ms'], 'plc_enabled': observation['plc_enabled'],
                'playout_states': states})
        self.end_ms = end
        self.last = observation
        return self

    def playout(self, codec, received, lost, runs, distribution=None, observation=None, format_stable=None):
        observation = observation or self.last
        name = codec.upper().split('/')[0]
        # PJSIP's default G.711 PLC is WSOLA, not the G.711 Appendix I profile.
        profile = ('pjsip-wsola' if observation['plc_enabled'] else 'g711-no-plc') if name in ('PCMA', 'PCMU') else 'codec-profile-unqualified'
        probability = lost / (received + lost) if received + lost else 0
        burst = (lost / runs) * (1 - probability) if runs and lost else (1.0 if lost == 0 else None)
        stable = self.format_stable if format_stable is None else format_stable
        return {'valid': bool(stable and received + lost > 0), 'format_stable': stable, 'observed_codecs': sorted(self.codecs), 'profile': profile, 'packetization_ms': observation['packetization_ms'], 'frame_ms': observation['frame_ms'],
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
        if self.last.get('playout_states'):
            result['playout'].update({k: self.last['playout_states']['total_' + k] for k in ('missing', 'empty', 'prefetch')})
            result['playout']['state_protocol'] = 1
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
            local = {'packetization_ms': interval['packetization_ms'], 'frame_ms': interval['frame_ms'], 'plc_enabled': interval['plc_enabled'], 'distribution_protocol': interval['distribution_protocol']}
            playout = self.playout(interval['codec'] or codec, interval['received'], interval['lost'], interval['loss_runs'],
                                   interval['distribution_protocol'], local, interval['format_stable'])
            playout.update(starts_lost=interval['starts_lost'], ends_lost=interval['ends_lost'])
            if interval['playout_states']:
                playout.update({k: interval['playout_states'][k] for k in ('missing', 'empty', 'prefetch')})
                playout['state_protocol'] = 1
            result['intervals'].append({'offset_s': interval['offset_s'], 'duration_s': interval['duration_s'],
                'phase': 'audio' if self.audio_interval_index is not None and index >= self.audio_interval_index else 'identification' if self.audio_baseline is not None else 'full_call',
                'timing': {'method': 'rtp-arrival-v1', 'representation': 'transit-summary-v1', 'clock_stable': interval['valid'],
                           'ssrc': interval['ssrc'], 'reference_min_ms': self.minimum, 'resolution_ms': .25, 'summary': summary},
                'playout': playout, 'jitter_ms_mean': interval['jitter_ms_mean']})
        if self.network_meta:
            rows = list(self.network_buckets.values())
            result['network_timeline'] = {**self.network_meta,
                'scope': 'RTP reçu, tous payload types ; pertes attribuées au paquet révélant le trou de séquence',
                'audio_start_observed_s': round(self.audio_baseline[3] / 1000, 3) if self.audio_baseline else None,
                'received_unique': sum(row[1] for row in rows), 'missing_final': sum(row[4] for row in rows),
                'expected': sum(row[1] + row[4] for row in rows),
                'intervals': [{'offset_s': round(row[0] * 2 + self.network_meta['origin_delta_ms'] / 1000, 3),
                    'duration_s': 2, 'received_unique': row[1], 'audio_received': row[2], 'other_received': row[3],
                    'missing_final': row[4], 'audio_missing': row[5], 'other_missing': row[6], 'mixed_missing': row[7],
                    'gap_recovered': row[8], 'reordered': row[9], 'duplicates': row[10], 'segment': row[11]}
                    for row in sorted(rows)]}
        return result
