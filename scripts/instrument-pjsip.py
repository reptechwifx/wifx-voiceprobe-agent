#!/usr/bin/env python3
"""Apply additive receiver observation to the pinned PJSIP 2.16 source only."""
import hashlib
from pathlib import Path
import sys


def replace(root, name, old, new, count=1):
    p=root/name;s=p.read_text()
    if s.count(old)!=count:raise ValueError('Pinned PJSIP source context differs: '+name)
    p.write_text(s.replace(old,new))


def instrument(root, header):
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
