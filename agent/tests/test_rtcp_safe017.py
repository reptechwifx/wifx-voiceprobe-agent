"""Exact integer oracles for the compiled production RTCP arithmetic patch."""
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RtcpSafe017Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get('VP_STORAGE_SCRATCH'))
        cls.path = Path(cls.temp.name)
        source = cls.path/'arithmetic.c'
        source.write_text(r'''
#include <stdio.h>
#include "rtcp-safe.h"
int main(void) {
 char op; unsigned long long a,b; unsigned c,out;
 while(scanf(" %c %llu %llu %u",&op,&a,&b,&c)==4) {
  if(op=='c') printf("%u\n",vp_rtcp_clock(a,b,c));
  if(op=='d') printf("%lld\n",(long long)vp_rtcp_delta((uint32_t)a,(uint32_t)b));
  if(op=='j') printf("%llu\n",(unsigned long long)vp_rtcp_jitter_step(a,(int64_t)b));
  if(op=='u') {out=0;int valid=vp_rtcp_usec((uint32_t)a,c,&out);printf("%d %u\n",valid,out);}
 }
 return 0;
}
''')
        cls.binary = cls.path/'arithmetic'
        subprocess.run(['gcc','-std=c99','-O2','-Wall','-Wextra','-Werror',
                        '-fsanitize=undefined,float-cast-overflow','-fno-sanitize-recover=all',
                        '-I'+str(ROOT/'agent/installer'),str(source),'-o',str(cls.binary)],check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def calculate(self, lines):
        return subprocess.run([str(self.binary)],input='\n'.join(lines)+'\n',text=True,
                              capture_output=True,check=True).stdout.splitlines()

    def test_clock_conversion_at_full_uint64_limits(self):
        rng = random.Random(17017)
        limit = (1<<64)-1
        values = [(t,f,r) for f in [1,1000,1_000_000,10_000_000,1_000_000_000,limit//2,limit]
                  for t in [0,1,limit//8000-1,limit//8000,limit//8000+1,limit-1,limit]
                  for r in [1,8000,16000,48000,(1<<32)-1]]
        values += [(rng.randrange(1<<64),rng.randrange(1,1<<64),rng.randrange(1,1<<32)) for _ in range(1000)]
        actual = self.calculate([f'c {t} {f} {r}' for t,f,r in values])
        self.assertEqual(list(map(int,actual)),[(t*r//f)&0xffffffff for t,f,r in values])

    def test_rtp_wrap_and_signed_half_range_have_defined_arithmetic(self):
        values = [(0,0xffffffff),(0xffffffff,0),(0x80000000,0),(0,0x80000000),
                  (0x80000000,0x7fffffff),(0x7fffffff,0x80000000)]
        expected = [((a-b+(1<<31))%(1<<32))-(1<<31) for a,b in values]
        self.assertEqual(list(map(int,self.calculate([f'd {a} {b} 0' for a,b in values]))),expected)

    def test_scaled_jitter_survives_uint32_limit_without_capping(self):
        values = [(j,d) for j in [0,(1<<32)-8,(1<<32)-1,16*(1<<31)] for d in [0,1,(1<<31)-1]]
        self.assertEqual(list(map(int,self.calculate([f'j {j} {d} 0' for j,d in values]))),
                         [j-((j+8)//16)+d for j,d in values])

    def test_microseconds_are_exact_or_explicitly_unrepresentable(self):
        values = [(n,r) for n in [0,1,4293,4294,4295,8000,800000,17179869,17179870,(1<<32)-1]
                  for r in [0,8000,16000,48000]]
        expected = []
        for n,r in values:
            v=n*1_000_000//r if r else (1<<31)
            expected.append(f'1 {v}' if v <= (1<<31)-1 else '0 0')
        self.assertEqual(self.calculate([f'u {n} 0 {r}' for n,r in values]),expected)

    def test_patch_applies_only_to_pinned_source_and_math_variance_stays_finite(self):
        archive = Path(os.environ.get('VP_PJSIP_ARCHIVE', ROOT/'var/quality017-lab/pjproject-2.16.tar.gz'))
        if not archive.exists():
            self.skipTest('Pinned PJSIP archive required')
        import hashlib
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),'3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb')
        with tarfile.open(archive) as a:
            a.extractall(self.path,filter='data')
        root=self.path/'pjproject-2.16'
        spec=importlib.util.spec_from_file_location('instrument',ROOT/'scripts/instrument-pjsip.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.instrument(root,ROOT/'agent/installer/rtp-observer.h')
        self.assertNotIn('ts.u64 = ts.u64 * sess->clock_rate', (root/'pjmedia/src/pjmedia/rtcp.c').read_text())
        with self.assertRaises(ValueError): module.correct_rtcp(root,ROOT/'agent/installer/rtcp-safe.h')
        # Compile the patched real pj_math_stat implementation with only its
        # platform typedefs supplied, exercising the former narrowing cast.
        text=(root/'pjlib/include/pj/math.h').read_text()
        a=text.index('typedef struct pj_math_stat');b=text.index('/** @} */',a)
        source=self.path/'statistics.c'
        source.write_text('#include <stdio.h>\n#include <string.h>\n#include <math.h>\n#define PJ_HAS_FLOATING_POINT 1\n#define PJ_INLINE(t) static t\n#define pj_bzero(p,n) memset(p,0,n)\ntypedef double pj_highprec_t;\n'+text[a:b]+r'''
int main(void) {
 pj_math_stat s;pj_math_stat_init(&s);pj_math_stat_set_stddev(&s,0);pj_math_stat_init(&s);
 pj_math_stat_update(&s,0);pj_math_stat_update(&s,2000000);pj_math_stat_update(&s,1000000);
 printf("%d %d %d %u\n",s.mean,s.min,s.max,pj_math_stat_get_stddev(&s));
 pj_math_stat_init(&s);pj_math_stat_update(&s,2147483647);pj_math_stat_update(&s,2147483647);
 printf("%d %u %u\n",s.mean,pj_math_stat_get_stddev(&s),pj_isqrt(4));
 return 0;
}
''')
        binary=self.path/'statistics'
        subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror','-fsanitize=undefined,float-cast-overflow',
                        '-fno-sanitize-recover=all',str(source),'-lm','-o',str(binary)],check=True)
        result=subprocess.check_output([str(binary)],text=True).splitlines()
        self.assertEqual(result,['1000000 0 2000000 816496','2147483647 0 2'])

    def test_receiver_clock_regression_and_frequency_change_are_unqualified(self):
        binary=self.path/'observer'
        subprocess.run(['gcc','-std=c99','-O2','-Wall','-Wextra','-Werror',
                        str(ROOT/'agent/tests/fixtures/rtp-observer-driver.c'),'-lm','-o',str(binary)],check=True)
        for commands in ['p 1 9000 1000 123\np 2 9160 1020 123\np 3 9320 1010 123\ns 1040\n',
                         'p 1 9000 1000 123\nc 1000000000\np 2 9160 1020 123\ns 1040\n',
                         'p 1 9000 1000 123\np 2 9160 1020 123\ns 1010\n']:
            observation=json.loads(subprocess.check_output([str(binary)],input=commands,text=True))
            self.assertFalse(observation['valid'])
            self.assertLess(observation['elapsed_ms'],1000)

    def test_invalid_global_statistics_keep_provenance_and_no_operational_value(self):
        import sys
        sys.path.insert(0,str(ROOT/'agent/src'))
        from rtp_quality import annotate_pjsip_jitter
        stats={'rx':{'jitter_ms_mean':6134.609,'jitter_ms_max':519013,
                     'pjsip_jitter':{'method':'vp-rtcp-safe-v1','rx_invalid_flags':4,'tx_invalid_flags':0}},
               'tx':{'jitter_ms_mean':.25,'jitter_ms_max':.375}}
        annotate_pjsip_jitter(stats);annotate_pjsip_jitter(stats)
        self.assertIsNone(stats['rx']['jitter_ms_mean'])
        self.assertEqual(stats['rx']['jitter_calculation']['raw_max_ms'],519013)
        self.assertFalse(stats['rx']['jitter_calculation']['valid'])
        self.assertEqual(stats['tx']['jitter_ms_mean'],.25)
        real={'rx':{'jitter_ms_mean':500,'jitter_ms_max':1000,'pjsip_jitter':{
            'method':'vp-rtcp-safe-v1','rx_invalid_flags':0,'tx_invalid_flags':0}}}
        annotate_pjsip_jitter(real)
        self.assertEqual(real['rx']['jitter_ms_mean'],500)
