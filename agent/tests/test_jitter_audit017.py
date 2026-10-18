"""Independent RFC 3550 oracle against the shipped C receiver, not its Python port.

PCAP timestamps are generated from known arrivals. Playout events are injected;
they do not qualify PLC audibility or the real PJSIP jitter buffer.
"""
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_pdv_audit import ROOT, packets, save_pcap


def oracle(rows):
    # Exact rational convolution of transit differences, independent of the C
    # recurrence and histogram. Timestamps in these fixtures do not wrap.
    transits = [Fraction(str(p['arrival_ms'])) - Fraction(p['timestamp'], 8) for p in rows]
    differences = [abs(b-a) for a, b in zip(transits, transits[1:])]
    return [0.0] + [float(sum((d * Fraction(15, 16)**(n-i) / 16
                              for i, d in enumerate(differences[:n+1])), Fraction()))
                    for n in range(len(differences))]


class JitterAudit017Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.driver = Path(cls.temp.name)/'observer'
        subprocess.run(['gcc', '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(ROOT/'agent/tests/fixtures/rtp-observer-driver.c'), '-lm', '-o', str(cls.driver)], check=True)
        cls.evidence = Path(os.environ['VP_JITTER_EVIDENCE']) if os.environ.get('VP_JITTER_EVIDENCE') else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.results = []

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        if cls.evidence:
            (cls.evidence/'matrix.json').write_text(json.dumps(cls.results, indent=2)+'\n')

    def test_independent_rfc3550_convolution(self):
        cases = {
            'regular_pcma': packets(120),
            'stable_low_jitter': packets(120, delay=lambda i:(i%5)*.1),
            'increasing_jitter': packets(120, delay=lambda i:(i%2)*i*2),
            'isolated_high_delay': packets(120, delay=lambda i:900 if i==50 else 0),
            'persistent_real_delay': packets(120, delay=lambda i:1000 if i>=50 else 0),
            'timestamp_discontinuity': packets(120, timestamp=lambda i:160*i+(8000 if i>=50 else 0)),
            'clock_drift': packets(120, timestamp=lambda i:161*i),
            'network_loss': [p for i,p in enumerate(packets(120)) if i%11],
            'reordering': packets(120, delay=lambda i:30 if i%11==0 else 0),
            'short_one_packet': packets(1),
            'short_two_packets': packets(2, delay=lambda i:i*.25),
            'late_first_packet': packets(120, delay=lambda i:1000),
            'late_last_packet': packets(120, delay=lambda i:1000 if i==119 else 0),
            'jitter_without_network_loss': packets(120, delay=lambda i:600 if i%2 else 0),
            'burst_network_loss': [p for i,p in enumerate(packets(120)) if not 30<=i<50],
            'zero_rtp_timestamp': packets(120, timestamp=lambda i:160*i-90000),
            'pcmu_same_rtp_clock': packets(120, delay=lambda i:(i%7)*.2),
            'g722_8000_rtp_clock': packets(120, delay=lambda i:(i%3)*.5),
        }
        for name, rows in cases.items():
            with self.subTest(name=name):
                rows = sorted(rows, key=lambda p:p['arrival_ms'])
                commands = ''.join(f"p {p['seq']} {p['timestamp']} {p['arrival_ms']:.6f} {p['ssrc']}\nj\n" for p in rows)
                output = subprocess.run([str(self.driver)], input=commands, text=True, capture_output=True, check=True)
                observed = [json.loads(line)['jitter_ms'] for line in output.stdout.splitlines()]
                expected = oracle(rows)
                error = max(abs(a-b) for a,b in zip(observed,expected))
                self.assertLess(error, 1e-7)
                result = {'case':name,'samples':len(rows),'maximum_ms':max(observed),
                          'mean_ms':sum(observed)/len(observed),'oracle_max_error_ms':error,
                          'qualified_quantity':'RFC3550 interarrival jitter; network attribution not established'}
                self.results.append(result)
                if self.evidence:
                    save_pcap(self.evidence/(name+'.pcap'), rows)

    def test_intervals_preserve_recurrence_and_weighted_population(self):
        rows = packets(120, delay=lambda i:(i%5)*.1)
        commands = ''
        for i,p in enumerate(rows):
            commands += f"p {p['seq']} {p['timestamp']} {p['arrival_ms']:.6f} {p['ssrc']}\n"
            if i in (1,25,70,119):
                commands += f"s {p['arrival_ms']+.001:.6f}\n"
        output = subprocess.run([str(self.driver)],input=commands,text=True,capture_output=True,check=True)
        snapshots = list(map(json.loads,output.stdout.splitlines()))
        n = sum(s['samples'] for s in snapshots)
        mean = sum(s['jitter_sum_ms'] for s in snapshots)/n
        self.assertEqual(n,len(rows))
        self.assertAlmostEqual(mean,sum(oracle(rows))/n,places=7)
        self.assertNotAlmostEqual(mean,sum(s['jitter_sum_ms']/s['samples'] for s in snapshots)/len(snapshots),places=3)
        self.results.append({'case':'unequal_windows','samples':n,'weighted_mean_ms':mean})

    def test_pjsip_pinned_clock_conversion_overflow(self):
        source = ROOT/'var/controller-beta012-lab/pjproject-2.16/pjmedia/src/pjmedia/rtcp.c'
        if not source.exists():
            self.skipTest('Pinned PJSIP source required for forensic reproduction')
        code = source.read_text()
        expression = 'ts.u64 = ts.u64 * sess->clock_rate / sess->ts_freq.u64;'
        self.assertIn(expression, code)
        # Compile the actual source expression; compare to arbitrary precision
        # integer arithmetic. This qualifies the overflow finding, not the
        # unavailable production incident or all of PJSIP.
        c = Path(self.temp.name)/'clock.c'
        c.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                     'int main(void){struct {uint64_t u64;} ts; '
                     'struct S {uint32_t clock_rate; struct {uint64_t u64;} ts_freq;} s={8000,{1000000000}},*sess=&s; '
                     'unsigned long long value; while(scanf("%llu",&value)==1){ts.u64=value; '
                     +expression+' printf("%llu\\n",(unsigned long long)ts.u64);}return 0;}')
        executable = Path(self.temp.name)/'clock'
        subprocess.run(['gcc','-Wall','-Wextra','-Werror',str(c),'-o',str(executable)],check=True)
        boundary = (1<<64)//8000
        inputs = [boundary-20_000_000, boundary+20_000_000]
        output = subprocess.run([str(executable)],input='\n'.join(map(str,inputs)),text=True,capture_output=True,check=True)
        actual = list(map(int,output.stdout.splitlines()))
        expected = [x*8000//1_000_000_000 for x in inputs]
        self.assertEqual(expected[1]-expected[0],320)
        self.assertNotEqual(actual[1]-actual[0],320)
        self.results.append({'case':'pjsip_clock_multiplication_overflow',
                             'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                             'uptime_days':boundary/1e9/86400,'actual_ticks':actual,
                             'expected_ticks':expected,'production_incident_attribution':'unproven'})

        # Execute the pinned jitter update and both integer conversions as C.
        # The synthetic stream crosses the 64-bit clock multiplication boundary.
        a = code.index('            d = transit - sess->transit;')
        b = code.index('            pj_math_stat_update(&sess->stat.rx.jitter, jitter);',a)
        update = code[a:b]
        c.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                     'int main(void){struct {uint64_t u64;} ts; '
                     'struct S {uint32_t clock_rate; struct {uint64_t u64;} ts_freq; int32_t transit; uint32_t jitter;} s={8000,{1000000000},0,0},*sess=&s; '
                     'unsigned long long value; unsigned rtp_ts,i=0; '
                     'while(scanf("%llu %u",&value,&rtp_ts)==2){ts.u64=value; '
                     +expression+' uint32_t arrival=(uint32_t)ts.u64; int32_t transit=(int32_t)(arrival-rtp_ts); '
                     'if(i++>=25){int32_t d;uint32_t jitter;'+update+
                     'printf("%u\\n",jitter);}sess->transit=transit;}return 0;}')
        subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(c),'-o',str(executable)],check=True)
        streams = {}
        for name, origin in [('control',10_000_000_000),('overflow',boundary-10_000_000_000)]:
            values = [(origin+i*20_000_000+(500_000 if i%2 else 0),90000+i*160) for i in range(3001)]
            output = subprocess.run([str(executable)],input='\n'.join(f'{a} {t}' for a,t in values),text=True,capture_output=True,check=True)
            values = [int(v)/1000 for v in output.stdout.splitlines()]
            streams[name] = {'mean_ms':sum(values)/len(values),'maximum_ms':max(values),'samples':len(values)}
        self.assertLess(streams['control']['maximum_ms'],1)
        self.assertEqual(streams['overflow']['maximum_ms'],519013)
        self.results.append({'case':'pjsip_peak_519013_reproduction','synthetic':True,'streams':streams,
                             'incident_attribution':'Compatible numeric signature; production uptime and raw packet timestamps unavailable'})
