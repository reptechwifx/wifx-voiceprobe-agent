#!/usr/bin/env python3
"""Apply additive receiver observation to the pinned PJSIP 2.16 source only."""
import hashlib
from pathlib import Path
import sys


def replace(root, name, old, new, count=1):
    p=root/name;s=p.read_text()
    if s.count(old)!=count:raise ValueError('Pinned PJSIP source context differs: '+name)
    p.write_text(s.replace(old,new))


def correct_rtcp(root, header):
    """Patch exact 2.16 contexts; binary ABI changes require complete rebuilding."""
    replace(root, 'pjmedia/src/pjmedia/rtcp.c', '#include <pjmedia/rtcp.h>', '#include <pjmedia/rtcp.h>\n#include "voiceprobe_rtcp_safe.h"')
    replace(root, 'pjmedia/include/pjmedia/rtcp.h', '    pj_int32_t              transit;', '    pj_uint32_t             transit;')
    replace(root, 'pjmedia/include/pjmedia/rtcp.h', '    pj_uint32_t             jitter;', '''    pj_uint64_t             jitter;
    pj_uint64_t             voiceprobe_last_clock;
    unsigned                voiceprobe_clock_rate;
    unsigned                voiceprobe_clock_seen;
    unsigned                voiceprobe_transit_valid;
    unsigned                voiceprobe_jitter_invalid;
    unsigned                voiceprobe_tx_jitter_invalid;''')
    replace(root, 'pjmedia/src/pjmedia/rtcp.c', '    sess->transit = 0;', '    sess->transit = 0;\n    sess->voiceprobe_transit_valid = 0;')
    replace(root, 'pjmedia/src/pjmedia/rtcp.c', '    pj_int32_t transit;', '    pj_uint32_t transit;')
    replace(root, 'pjmedia/src/pjmedia/rtcp.c', '''        pj_get_timestamp(&ts);
        ts.u64 = ts.u64 * sess->clock_rate / sess->ts_freq.u64;
        arrival = ts.u32.lo;''', '''        pj_timestamp frequency;
        if (pj_get_timestamp(&ts) != PJ_SUCCESS ||
            pj_get_timestamp_freq(&frequency) != PJ_SUCCESS ||
            !frequency.u64 || !sess->clock_rate) {
            sess->voiceprobe_jitter_invalid |= 1;
            goto voiceprobe_rx_end;
        }
        if (frequency.u64 != sess->ts_freq.u64)
            sess->voiceprobe_jitter_invalid |= 2;
        if (sess->voiceprobe_clock_seen) {
            if (ts.u64 < sess->voiceprobe_last_clock)
                sess->voiceprobe_jitter_invalid |= 4;
            if (sess->clock_rate != sess->voiceprobe_clock_rate)
                sess->voiceprobe_jitter_invalid |= 8;
        }
        sess->voiceprobe_clock_seen = 1;
        sess->voiceprobe_clock_rate = sess->clock_rate;
        sess->voiceprobe_last_clock = ts.u64;
        if (sess->voiceprobe_jitter_invalid) goto voiceprobe_rx_end;
        arrival = vp_rtcp_clock(ts.u64, frequency.u64, sess->clock_rate);''')
    replace(root, 'pjmedia/src/pjmedia/rtcp.c', 'if (sess->transit == 0 ||', 'if (!sess->voiceprobe_transit_valid ||')
    replace(root, 'pjmedia/src/pjmedia/rtcp.c', '            sess->transit = transit;', '            sess->transit = transit;\n            sess->voiceprobe_transit_valid = 1;', count=2)
    p = root/'pjmedia/src/pjmedia/rtcp.c'; s = p.read_text()
    a = s.index('            pj_int32_t d;'); b = s.index('\n\n#if defined(PJMEDIA_RTCP_STAT_HAS_RAW_JITTER)', a)
    s = s[:a] + '''            pj_int64_t signed_delta = vp_rtcp_delta(transit, sess->transit);
            pj_int64_t d = signed_delta < 0 ? -signed_delta : signed_delta;
            pj_uint32_t jitter;
            if (signed_delta == -INT64_C(2147483648)) {
                sess->voiceprobe_jitter_invalid |= 32;
                goto voiceprobe_rx_end;
            }
            sess->jitter = vp_rtcp_jitter_step(sess->jitter, signed_delta);
            if (!vp_rtcp_usec((pj_uint32_t)(sess->jitter >> 4), sess->clock_rate, &jitter)) {
                sess->voiceprobe_jitter_invalid |= 16;
                goto voiceprobe_rx_end;
            }
            pj_math_stat_update(&sess->stat.rx.jitter, (int)jitter);
            PJ_UNUSED_ARG(d);''' + s[b:]
    a = s.index('                /* Convert raw jitter unit'); b = s.index('\n            }\n#endif', a)
    s = s[:a] + '''                if (vp_rtcp_usec((pj_uint32_t)d, sess->clock_rate, &raw_jitter))
                    pj_math_stat_update(&sess->stat.rx_raw_jitter, (int)raw_jitter);
                else sess->voiceprobe_jitter_invalid |= 16;''' + s[b:]
    a = s.index('                pj_int32_t ipdv;'); b = s.index('\n            }\n#endif', a)
    s = s[:a] + '''                pj_uint32_t magnitude;
                if (vp_rtcp_usec((pj_uint32_t)d, sess->clock_rate, &magnitude)) {
                    pj_int32_t ipdv = signed_delta < 0 ? -(pj_int32_t)magnitude : (pj_int32_t)magnitude;
                    pj_math_stat_update(&sess->stat.rx_ipdv, ipdv);
                } else sess->voiceprobe_jitter_invalid |= 16;''' + s[b:]
    a = s.index('    /* Calculate jitter in usec, avoiding overflows */'); b = s.index('\n    /* Can only calculate if LSR', a)
    s = s[:a] + '''    if (vp_rtcp_usec(jitter_samp, sess->clock_rate, &jitter))
        pj_math_stat_update(&sess->stat.tx.jitter, (int)jitter);
    else sess->voiceprobe_tx_jitter_invalid |= 16;
''' + s[b:]
    s = s.replace('    /* Update timestamp of last RX RTP packet */', 'voiceprobe_rx_end:\n    /* Update timestamp of last RX RTP packet */')
    p.write_text(s)
    # The original variance path casts a squared microsecond delta to int.
    # Preserve the statistic instead of overflowing at ~46 ms delta.
    replace(root, 'pjlib/include/pj/math.h', '#include <pj/string.h>', '#include <pj/string.h>\n#include <math.h>')
    replace(root, 'pjlib/include/pj/math.h', 'float            fmean_;', 'double           fmean_;')
    replace(root, 'pjlib/include/pj/math.h', 'float            delta;', 'double           delta;')
    replace(root, 'pjlib/include/pj/math.h', 'delta = (float)val - stat->fmean_;', 'delta = (double)val - stat->fmean_;')
    replace(root, 'pjlib/include/pj/math.h', 'delta/(float)stat->n', 'delta/(double)stat->n')
    replace(root, 'pjlib/include/pj/math.h', 'stat->m2_ += (int)(delta * ((float)val-stat->fmean_));', 'stat->m2_ += (pj_highprec_t)delta * ((pj_highprec_t)val-stat->fmean_);')
    replace(root, 'pjlib/include/pj/math.h', 'return (pj_isqrt((unsigned)(stat->m2_/stat->n)));', '#if PJ_HAS_FLOATING_POINT\n    return (unsigned)sqrt(stat->m2_ > 0 ? stat->m2_/stat->n : 0);\n#else\n    return (pj_isqrt((unsigned)(stat->m2_/stat->n)));\n#endif')
    (root/'pjmedia/src/pjmedia/voiceprobe_rtcp_safe.h').write_bytes(header.read_bytes())
    (root/'voiceprobe-rtcp-patch.sha256').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'\n')
    (root/'voiceprobe-rtcp-safe.sha256').write_text(hashlib.sha256(header.read_bytes()).hexdigest()+'\n')


def instrument(root, header):
    correct_rtcp(root, header.with_name("rtcp-safe.h"))
    replace(root,'pjmedia/include/pjmedia/stream_common.h','    pj_mutex_t              *jb_mutex;', '    void                    *voiceprobe_quality; /* additive observer */\n    pj_mutex_t              *jb_mutex;')
    p=root/'pjmedia/src/pjmedia/stream.c';s=p.read_text();end=s.index('\n};',s.index('struct pjmedia_stream\n'))+3;s=s[:end]+'\n#include "voiceprobe_quality.h"\n'+s[end:];p.write_text(s)
    replace(root,'pjmedia/src/pjmedia/stream.c','    /* Create and initialize codec: */','    c_strm->voiceprobe_quality = PJ_POOL_ZALLOC_T(pool, vp_observer);\n\n    /* Create and initialize codec: */')
    old='                                &frame_type, &bit_info, &rtp_ts, NULL);'
    new=old+'\n        vp_playout(c_strm, frame_type, frame_type == PJMEDIA_JB_NORMAL_FRAME || frame_type == PJMEDIA_JB_MISSING_FRAME ? 1 : (samples_required-samples_count+samples_per_frame-1)/samples_per_frame);'
    # Only the linear PCM path is used by the supported codecs.
    p=root/'pjmedia/src/pjmedia/stream.c';s=p.read_text();assert old in s;s=s.replace(old,new,1);p.write_text(s)
    replace(root,'pjmedia/src/pjmedia/stream_imp_common.c','    pj_bool_t pkt_discarded = PJ_FALSE;','    pj_bool_t pkt_discarded = PJ_FALSE;\n#ifdef AUDIO_STREAM\n    pj_timestamp vp_arrival;\n    pj_get_timestamp(&vp_arrival);\n#endif')
    replace(root,'pjmedia/src/pjmedia/stream_imp_common.c','    /* Pass it to specific stream for further processing. */','''#ifdef AUDIO_STREAM
    vp_rx(c_strm, hdr, &vp_arrival);
#endif
    /* Pass it to specific stream for further processing. */''')
    declaration='PJ_DECL(pj_status_t) pjmedia_stream_voiceprobe(pjmedia_stream *stream, char *buffer, pj_size_t capacity);\n'
    replace(root,'pjmedia/include/pjmedia/stream.h','PJ_END_DECL',declaration+'\nPJ_END_DECL')
    declaration='PJ_DECL(pj_status_t) pjsua_call_voiceprobe(pjsua_call_id call_id, unsigned med_idx, char *buffer, pj_size_t capacity);\n'
    replace(root,'pjsip/include/pjsua-lib/pjsua.h','PJ_END_DECL',declaration+'\nPJ_END_DECL')
    p=root/'pjsip/src/pjsua-lib/pjsua_call.c';s=p.read_text();a=s.index('PJ_DEF(pj_status_t) pjsua_call_get_stream_stat(');b=s.index('\n}',s.index('\non_return:',a))+2
    new='''PJ_DEF(pj_status_t) pjsua_call_voiceprobe(pjsua_call_id call_id, unsigned med_idx, char *buffer, pj_size_t capacity)
{
    pj_status_t status = PJ_EINVAL;
    PJ_ASSERT_RETURN(call_id >= 0 && call_id < (int)pjsua_var.ua_cfg.max_calls && buffer, PJ_EINVAL);
    PJSUA_LOCK();
    if (med_idx < pjsua_var.calls[call_id].med_cnt) {
        pjsua_call_media *media = &pjsua_var.calls[call_id].media[med_idx];
        if (media->type == PJMEDIA_TYPE_AUDIO && media->strm.a.stream)
            status = pjmedia_stream_voiceprobe(media->strm.a.stream, buffer, capacity);
    }
    PJSUA_UNLOCK();
    return status;
}
'''
    s=s[:b]+'\n'+new+s[b:];p.write_text(s)
    replace(root,'pjsip/include/pjsua2/call.hpp','    StreamStat getStreamStat(unsigned med_idx) const PJSUA2_THROW(Error);','    StreamStat getStreamStat(unsigned med_idx) const PJSUA2_THROW(Error);\n    string getVoiceProbeStats(unsigned med_idx) const PJSUA2_THROW(Error);')
    replace(root,'pjsip/src/pjsua2/call.cpp','StreamStat Call::getStreamStat(unsigned med_idx) const PJSUA2_THROW(Error)','''string Call::getVoiceProbeStats(unsigned med_idx) const PJSUA2_THROW(Error)
{
    std::vector<char> buffer(524288);
    PJSUA2_CHECK_EXPR(pjsua_call_voiceprobe(id, med_idx, &buffer[0], buffer.size()));
    return string(&buffer[0]);
}

StreamStat Call::getStreamStat(unsigned med_idx) const PJSUA2_THROW(Error)''')
    (root/'pjmedia/src/pjmedia/voiceprobe_quality.h').write_bytes(header.read_bytes())
    (root/'voiceprobe-observer.sha256').write_text(hashlib.sha256(header.read_bytes()).hexdigest()+'\n')


if __name__=='__main__':instrument(Path(sys.argv[1]),Path(sys.argv[2]))
