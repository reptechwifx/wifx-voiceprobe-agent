"""Numeric-only session display: packet-weighted RTP and time-weighted audio power."""
import math


def number(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


class SessionMetrics:
    def __init__(self):
        self.tests = 0
        self.received = self.lost = self.jitter_weight = self.jitter_sum = 0
        self.packet_samples = self.audio_weight = self.power_sum = self.gap_count = self.gap_sum = 0

    def add(self, metrics):
        self.tests += 1
        rx = (metrics.get('rtp') or {}).get('rx') or {}
        packets, loss = number(rx.get('packets')), number(rx.get('loss'))
        if packets is not None and loss is not None and packets >= 0 and loss >= 0:
            self.received += packets
            self.lost += loss
            self.packet_samples += 1
        jitter = number(rx.get('jitter_ms_mean'))
        if packets is not None and packets > 0 and jitter is not None and jitter >= 0:
            self.jitter_sum += jitter * packets
            self.jitter_weight += packets
        audio = metrics.get('audio') or {}
        level, seconds = number(audio.get('rms_dbfs')), number(audio.get('analyzed_s'))
        if level is not None and -300 <= level <= 20 and seconds is not None and seconds > 0:
            self.power_sum += 10 ** (level / 10) * seconds
            self.audio_weight += seconds
        gaps = number(audio.get('interrupted_s'))
        if gaps is not None and gaps >= 0:
            self.gap_sum += gaps
            self.gap_count += 1

    def snapshot(self):
        total = self.received + self.lost
        return {'tests': self.tests, 'jitter_ms': self.jitter_sum / self.jitter_weight if self.jitter_weight else None,
                'loss_percent': 100 * self.lost / total if self.packet_samples and total > 0 else None,
                'rms_dbfs': 10 * math.log10(self.power_sum / self.audio_weight) if self.audio_weight and self.power_sum else None,
                'audio_gap_s': self.gap_sum / self.gap_count if self.gap_count else None}


def active_metrics(calls):
    accumulator = SessionMetrics()
    for call in calls:
        if call.established and not call.finished:
            accumulator.add({'rtp': call.stats})
    return accumulator.snapshot()
