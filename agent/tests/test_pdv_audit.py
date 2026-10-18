"""Audit the shipped observer against known emission/arrival times, without SIP.

PASS here means the finding is reproducible, not that PDV is qualified. The
separate qualification verdict compares the receiver with the network oracle.
Playout inputs are injected output events, never claimed to simulate PJSIP's JB.
"""
import csv
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'agent/src'))
from rtp_quality import ReceiverQuality


def packets(count=500, delay=None, timestamp=None, ssrc=None):
    return [dict(seq=i + 1000, timestamp=(90000 + (timestamp(i) if timestamp else 160*i)) & 0xffffffff,
                 emission_ms=20*i, arrival_ms=1000+20*i+(delay(i) if delay else 0),
                 ssrc=ssrc(i) if ssrc else 77) for i in range(count)]


def empirical_p95(values):
    """Exact order statistic over unbinned ground-truth network delays."""
    values = sorted(values)
    return values[(95*len(values)+99)//100-1] - values[0]


def save_pcap(path, rows):
    """Deterministic Ethernet/IP/UDP/PCMA trace, for external Wireshark replay."""
    def checksum(data):
        words = sum(struct.unpack('!10H', data))
        words = (words >> 16) + (words & 65535)
        return (~((words >> 16) + words)) & 65535
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for row in rows:
            rtp = struct.pack('!BBHII', 0x80, 8, row['seq'] & 65535, row['timestamp'], row['ssrc']) + bytes([0xd5])*row.get('payload_bytes',160)
            udp = struct.pack('!HHHH', 20000, 20002, len(rtp)+8, 0) + rtp
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp)+20, 0, 0, 64, 17, 0, bytes([192,0,2,1]), bytes([192,0,2,2]))
            ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
            frame = bytes.fromhex('0200000000020200000000010800') + ip + udp
            at = round(row['arrival_ms']*1000)
            f.write(struct.pack('<IIII', at//1000000, at%1000000, len(frame), len(frame)))
            f.write(frame)


class PdvAuditTest(unittest.TestCase):
    results = []

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.driver = Path(cls.temp.name) / 'observer'
        subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(ROOT/'agent/tests/fixtures/rtp-observer-driver.c'), '-lm', '-o', str(cls.driver)], check=True)
        cls.evidence = Path(os.environ['VP_PDV_EVIDENCE']) if os.environ.get('VP_PDV_EVIDENCE') else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        if cls.evidence:
            (cls.evidence/'matrix.json').write_text(json.dumps(cls.results, indent=2)+'\n')

    def observe(self, text):
        p = subprocess.run([str(self.driver)], input=text, text=True, capture_output=True, check=True)
        return [json.loads(line) for line in p.stdout.splitlines()]

    def evaluate(self, name, rows, explanation, playout='', invalid=False, failure=False, playout_failure=False):
        rows = sorted(rows, key=lambda p: p['arrival_ms'])
        commands = []
        for i, p in enumerate(rows):
            commands.append(f"p {p['seq']} {p['timestamp']} {p['arrival_ms']:.6f} {p['ssrc']}\nj\n")
            if (i+1) % 100 == 0 and i+1 < len(rows):
                commands.append(f"s {p['arrival_ms']:.6f}\n")
        commands.append(playout + f"s {rows[-1]['arrival_ms']+.001:.6f}\n")
        observations = self.observe(''.join(commands))
        quality = ReceiverQuality()
        jitter = []
        for o in observations:
            if 'jitter_ms' in o:
                jitter.append(o['jitter_ms'])
            else:
                quality.add(o, 'PCMA/8000')
        snapshot = quality.snapshot('PCMA/8000')
        metrics = {'established':True, 'rtp':{'codec':'PCMA/8000','rtp_clock_hz':8000,'rx':snapshot}}
        # The retained forensic function is identical to the pre-withdrawal PDV.
        php = "require 'controller/app/Support/VoipEstimate.php'; $m=json_decode(stream_get_contents(STDIN),true); $f=method_exists(App\\Support\\VoipEstimate::class,'diagnosticPdv')?'diagnosticPdv':'pdv'; echo json_encode(App\\Support\\VoipEstimate::$f($m));"
        pdv = json.loads(subprocess.run(['php','-r',php],input=json.dumps(metrics),cwd=ROOT,text=True,capture_output=True,check=True).stdout)
        # The oracle knows actual emission times, independent of RTP timestamps.
        unique = {(p['ssrc'],p['seq']):p for p in reversed(rows)}
        expected = empirical_p95([p['arrival_ms']-p['emission_ms'] for p in unique.values()])
        observed = pdv['p95_ms']
        error = None if observed is None else observed-expected
        if invalid:
            self.assertIsNone(observed)
            self.assertFalse(snapshot['timing']['clock_stable'])
        elif failure:
            self.assertTrue(snapshot['timing']['clock_stable'])
            self.assertGreater(abs(error), .251)
        else:
            self.assertIsNotNone(observed)
            self.assertLessEqual(abs(error), .251)
        result = {'case':name,'expected_network_p95_ms':expected,'legacy_p95_ms':observed,
                  'error_ms':error,'clock_marked_stable':snapshot['timing']['clock_stable'],
                  'jitter_max_ms':max(jitter),'jitter_final_ms':jitter[-1],
                  'accepted_samples':snapshot['timing']['histogram']['count'],
                  'playout_lost':snapshot['playout']['lost'], 'qualification_verdict':'FAIL' if failure or playout_failure else 'PASS',
                  'explanation':explanation}
        self.results.append(result)
        if self.evidence:
            (self.evidence/(name+'.json')).write_text(json.dumps({'result':result,'metrics':metrics,'legacy_pdv':pdv},indent=2)+'\n')
            save_pcap(self.evidence/(name+'.pcap'),rows)
            with (self.evidence/(name+'.csv')).open('w') as f:
                writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        return result, snapshot

    def test_01_regular(self):
        self.evaluate('01_regular',packets(),'Regular PCMA, known constant network delay.')

    def test_02_small_jitter(self):
        self.evaluate('02_small_jitter',packets(delay=lambda i:(i%5)*.1),'Network P95 0.4 ms; histogram error bounded by 0.25 ms.')

    def test_03_transient_delay(self):
        r,_=self.evaluate('03_transient_delay',packets(delay=lambda i:1000 if i==100 else 0),'One packet delayed 1 s then normal; less than 5% affected, P95 zero, maximum retained.')
        self.assertGreater(r['jitter_max_ms'],60)

    def test_04_persistent_delay(self):
        self.evaluate('04_persistent_delay',packets(delay=lambda i:1000 if i>=51 else 0),'Real persistent 1 s network delay preserved; no rebasing.')
        r,s=self.evaluate('04b_persistent_1060',packets(delay=lambda i:1060 if i>=51 else 0),'Incident-amplitude variant; real persistent delay preserved; no rebasing.')
        self.assertEqual(r['legacy_p95_ms'],1060)
        self.assertAlmostEqual(r['jitter_max_ms'],66.25)
        self.assertLess(r['jitter_final_ms'],.001)
        self.assertEqual(s['intervals'][-1]['timing']['summary']['min_ms'],1060)

    def test_05_timestamp_forward(self):
        self.evaluate('05_timestamp_forward',packets(timestamp=lambda i:160*i+(8000 if i>=51 else 0)),'Clock discontinuity on a perfect network accepted; earlier 10.2% now lie 1000 ms above minimum.',failure=True)

    def test_06_timestamp_backward(self):
        self.evaluate('06_timestamp_backward',packets(timestamp=lambda i:160*i-(8000 if i>=51 else 0)),'Backward RTP clock step of 1 s accepted on a perfect network.',failure=True)
        r,_=self.evaluate('06b_timestamp_backward_1060',packets(timestamp=lambda i:160*i-(8480 if i>=51 else 0)),'Backward RTP clock step alone creates the 1060 ms plateau and 66.25 ms jitter maximum.',failure=True)
        self.assertEqual(r['legacy_p95_ms'],1060)
        self.assertAlmostEqual(r['jitter_max_ms'],66.25)

    def test_07_ssrc_change(self):
        self.evaluate('07_ssrc_change',packets(ssrc=lambda i:77 if i<100 else 88),'SSRC change reaching the observer latches invalid; no stream mixing.',invalid=True)

    def test_08_reordering(self):
        r,s=self.evaluate('08_reordering',packets(delay=lambda i:30 if i%10==0 else 0),'Packets delayed 30 ms overtake one another; known physical P95 30 ms.')
        self.assertGreater(s['timing']['reordered'],0)

    def test_09_duplicates(self):
        rows=packets();rows.extend(dict(p,arrival_ms=p['arrival_ms']+1) for p in rows[::10])
        _,s=self.evaluate('09_duplicates',rows,'Duplicate copies excluded; one original observation per SSRC/sequence.')
        self.assertEqual(s['timing']['duplicates'],50)

    def test_10_network_loss(self):
        _,s=self.evaluate('10_network_loss',[p for i,p in enumerate(packets()) if i%10!=5],'50 packets omitted; PDV covers delivered packets only. Playout events injected separately.',playout='f 1 900\nf 2 100\n')
        self.assertEqual(s['timing']['histogram']['count'],450)
        self.assertEqual(s['playout']['lost'],100)

    def test_11_late_playout(self):
        _,s=self.evaluate('11_late_playout',packets(delay=lambda i:100 if 100<=i<102 else 0),'All network packets arrive; synthetic deadline trace has four unavailable decoder frames.',playout='f 1 200\nf 2 4\nf 1 796\n')
        self.assertEqual(s['playout']['lost'],4)

    def test_12_abrupt_stop(self):
        _,s=self.evaluate('12_abrupt_stop',packets(100),'Receiver continues requesting 1 s after last RTP: 100 missing frames retained.',playout='f 1 200\nf 2 100\n')
        self.assertEqual(s['playout']['lost'],100)

    def test_13_normal_end(self):
        self.evaluate('13_normal_end',packets(100),'Stopping playout with RTP yields no loss.',playout='f 1 200\n')
        _,s=self.evaluate('13b_end_tail_ambiguous',packets(100),'Identical observer input for a hangup tail and an outage: no SIP lifecycle input; false terminal loss cannot be identified.',playout='f 1 200\nf 2 26\n',playout_failure=True)
        self.assertEqual(s['playout']['lost'],26)

    def test_14_startup(self):
        _,s=self.evaluate('14_startup',packets(100),'Prefetch before first normal frame excluded; six missing frames after start preserved.',playout='f 2 20\nf 1 100\nf 2 6\nf 1 94\n')
        self.assertEqual(s['playout']['lost'],6)

    def test_15_clock_drift(self):
        self.evaluate('15_clock_drift',packets(timestamp=lambda i:160*i+(4*i//25)),'1000 ppm RTP clock drift on constant-delay network accepted as stable.',failure=True)

    def test_16_simultaneous_streams(self):
        for stream in [77,88]:
            self.evaluate(f'16_separate_stream_{stream}',packets(ssrc=lambda i:stream),'Independent observer instance per media stream; same concurrent clock, no cross-state.')
        mixed=packets(ssrc=lambda i:77 if i%2==0 else 88)
        self.evaluate('16b_mixed_ssrc',mixed,'If both SSRCs reach one media stream, timing invalidated.',invalid=True)

    def test_17_initial_reference(self):
        self.evaluate('17_bad_first_timestamp',packets(timestamp=lambda i:160*i+(8000 if i==0 else 0)),'First timestamp inconsistent with later packets; permanent false transit offset accepted.',failure=True)

    def test_18_wrap(self):
        rows=packets()
        for i,p in enumerate(rows):p.update(seq=(65500+i)&65535,timestamp=(0xffffff00+160*i)&0xffffffff)
        self.evaluate('18_wrap',rows,'Ordinary 16-bit sequence / 32-bit timestamp rollover preserves zero transit.')

    def test_19_actual_incident(self):
        incident=json.loads((ROOT/'agent/tests/fixtures/pdv-incident-20261017.json').read_text())
        h=incident['histogram'];expanded=[b*.25 for b,n in h['bins'] for _ in range(n)]
        self.assertEqual(len(expanded),2535)
        rank=(95*len(expanded)+99)//100-1
        lower=sorted(expanded)[rank]-h['min_ms'];upper=lower+.25
        self.assertEqual(round(upper,3),1060.094)
        self.assertEqual(round(h['sum_ms']/h['count']-h['min_ms'],3),1026.260)
        intervals=[dict(zip(incident['interval_columns'],r)) for r in incident['intervals']]
        self.assertEqual(sum(r['count'] for r in intervals),2535)
        self.assertAlmostEqual(sum(r['sum_ms'] for r in intervals),h['sum_ms'],places=5)
        self.assertEqual(sum(r['lost'] for r in intervals),32)
        self.assertEqual(sum(r['received'] for r in intervals),5068)
        self.assertEqual(sum(r['loss_runs'] for r in intervals),3)
        p=incident['playout'];burst=p['lost']/p['loss_runs']*(1-p['lost']/(p['received']+p['lost']))
        self.assertAlmostEqual(burst,10.599738562091503)
        self.assertEqual(intervals[-2]['received'],56)
        self.results.append({'case':'19_incident','qualification_verdict':'FAIL','p95_lower_ms':lower,'p95_upper_ms':upper,'burst_ratio':burst,
                             'explanation':'Arithmetic matches supplied histogram. No send/arrival packet trace to identify causal transit change; counts and timing reveal different observation endpoints.'})

    def test_20_interval_scope(self):
        _,s=self.evaluate('20_interval_scope',packets(delay=lambda i:10 if i<100 else 0),
                          'First interval at 0 relative transit; final call minimum -10 ms. Later interval P95 uses local samples, never the cumulative percentile.')
        first,last=s['intervals'][0]['timing'],s['intervals'][-1]['timing']
        self.assertEqual(first['reference_min_ms'],-10)
        self.assertEqual(last['reference_min_ms'],-10)
        self.assertEqual(first['summary']['p95_transit_ms'],.25)
        self.assertEqual(last['summary']['p95_transit_ms'],-9.75)

    def test_21_variable_packetization(self):
        rows=packets()
        for i,p in enumerate(rows):
            emission=20*min(i,100)+40*max(0,i-100)
            p.update(emission_ms=emission,arrival_ms=1000+emission,timestamp=90000+8*emission,payload_bytes=160 if i<100 else 320)
        _,s=self.evaluate('21_variable_packetization',rows,'20 to 40 ms packets with matching timestamps: zero transit variation, variable packetization metadata.')
        self.assertEqual(s['playout']['packetization_ms'],0)

    def test_22_far_reordering_exclusion(self):
        self.evaluate('22_far_reordering_exclusion',packets(delay=lambda i:1500 if i%10==0 else 0),
                      'Beyond the 64-sequence observer window, delayed packets are excluded without invalidation; survivor quantile understates known network variation.',failure=True)


if __name__=='__main__':unittest.main()
