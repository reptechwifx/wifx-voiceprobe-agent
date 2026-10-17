/* SPDX-License-Identifier: GPL-3.0-or-later
 * Voice Probe read-only PJSIP 2.16 receiver observation. No payload retained.
 * Included only by the audio stream translation unit. Protected by jb_mutex.
 */
#include <math.h>
#include <stdio.h>
#include <stdarg.h>
#define VP_BINS 16001
#define VP_ORIGIN 8000
#define VP_BIN_MS 0.25

typedef struct vp_observer {
    pj_uint32_t bins[VP_BINS];
    pj_uint64_t samples, received, lost, loss_runs, duplicates, reordered;
    pj_uint64_t delta_received, delta_lost, delta_runs, overflow, excluded;
    pj_uint64_t seen;
    pj_uint32_t ssrc, last_ts;
    pj_uint16_t last_seq;
    pj_int64_t extended_ts, first_ts;
    pj_timestamp first_arrival, frequency;
    double minimum, maximum, sum, jitter, jitter_sum, last_transit, elapsed_ms;
    unsigned initialized, playback_started, previous_lost, valid, has_transit;
    unsigned delta_started, delta_starts_lost; pj_uint64_t delta_local_runs;
    double packet_ms; unsigned variable_packet_ms;
} vp_observer;

static void vp_rx(pjmedia_stream_common *base, const pjmedia_rtp_hdr *hdr,
                  const pj_timestamp *arrival)
{
    vp_observer *v = (vp_observer*)base->voiceprobe_quality;
    pj_uint32_t ts = pj_ntohl(hdr->ts), ssrc = pj_ntohl(hdr->ssrc);
    pj_uint16_t seq = pj_ntohs(hdr->seq);
    pj_int16_t sequence_delta = 0;
    pj_int32_t timestamp_delta;
    pj_int64_t extended;
    double transit, elapsed;
    int index;
    if (!v || hdr->pt != base->si->rx_pt) return;
    pj_mutex_lock(base->jb_mutex);
    if (!v->initialized) {
        if (pj_get_timestamp_freq(&v->frequency) != PJ_SUCCESS || !v->frequency.u64) {
            pj_mutex_unlock(base->jb_mutex); return;
        }
        v->initialized = 1; v->valid = 1; v->ssrc = ssrc;
        v->first_arrival = *arrival; v->last_ts = ts; v->first_ts = ts;
        v->extended_ts = ts; v->last_seq = seq; v->seen = 1;
        extended = ts;
    } else {
        sequence_delta = (pj_int16_t)(seq - v->last_seq);
        if (ssrc != v->ssrc || arrival->u64 < v->first_arrival.u64) {
            v->valid = 0; ++v->excluded; pj_mutex_unlock(base->jb_mutex); return;
        }
        if (sequence_delta <= 0) {
            unsigned distance = (unsigned)(-sequence_delta);
            if (distance >= 64) { ++v->excluded; pj_mutex_unlock(base->jb_mutex); return; }
            if (v->seen & ((pj_uint64_t)1 << distance)) {
                ++v->duplicates; pj_mutex_unlock(base->jb_mutex); return;
            }
            v->seen |= (pj_uint64_t)1 << distance; ++v->reordered;
        } else {
            v->seen = sequence_delta >= 64 ? 1 : (v->seen << sequence_delta) | 1;
            v->last_seq = seq;
        }
        timestamp_delta = (pj_int32_t)(ts - v->last_ts);
        if (timestamp_delta > 80000 || timestamp_delta < -80000) {
            v->valid = 0; ++v->excluded; pj_mutex_unlock(base->jb_mutex); return;
        }
        extended = v->extended_ts + timestamp_delta;
        if (sequence_delta == 1 && timestamp_delta > 0) {
            double packet_ms = (double)timestamp_delta/8.0;
            if (!v->packet_ms) v->packet_ms = packet_ms;
            else if (v->packet_ms != packet_ms) v->variable_packet_ms = 1;
        }
        if (timestamp_delta > 0) { v->last_ts = ts; v->extended_ts = extended; }
    }
    /* All supported codecs use the 8 kHz RTP clock (including G.722). */
    elapsed = 1000.0 * (double)(arrival->u64-v->first_arrival.u64) / (double)v->frequency.u64;
    transit = elapsed - 1000.0 * (double)(extended-v->first_ts) / 8000.0;
    v->elapsed_ms = elapsed;
    index = (int)floor(transit / VP_BIN_MS) + VP_ORIGIN;
    if (index < 0 || index >= VP_BINS || elapsed > 605000.0) {
        ++v->overflow; v->valid = 0; pj_mutex_unlock(base->jb_mutex); return;
    }
    if (!v->samples) { v->minimum = v->maximum = transit; }
    else {
        if (transit < v->minimum) v->minimum = transit;
        if (transit > v->maximum) v->maximum = transit;
    }
    if (v->has_transit) v->jitter += (fabs(transit-v->last_transit)-v->jitter)/16.0;
    v->has_transit = 1;
    v->last_transit = transit; v->jitter_sum += v->jitter;
    ++v->bins[index]; ++v->samples; v->sum += transit;
    pj_mutex_unlock(base->jb_mutex);
}

static void vp_playout(pjmedia_stream_common *base, char type, unsigned frames)
{
    vp_observer *v = (vp_observer*)base->voiceprobe_quality;
    unsigned i;
    /* Called with the existing jitter-buffer mutex held. */
    if (!v) return;
    if (type == PJMEDIA_JB_NORMAL_FRAME) v->playback_started = 1;
    if (!v->playback_started) return; /* exclude initial prefetch only */
    for (i=0; i<frames; ++i) {
        if (type != PJMEDIA_JB_NORMAL_FRAME && (!v->previous_lost || !v->delta_started)) ++v->delta_local_runs;
        if (!v->delta_started) { v->delta_starts_lost = type != PJMEDIA_JB_NORMAL_FRAME; v->delta_started = 1; }
        if (type == PJMEDIA_JB_NORMAL_FRAME) {
            ++v->received; ++v->delta_received; v->previous_lost = 0;
        } else {
            ++v->lost; ++v->delta_lost;
            if (!v->previous_lost) { ++v->loss_runs; ++v->delta_runs; }
            v->previous_lost = 1;
        }
    }
}

static int vp_append(char *buffer, pj_size_t capacity, pj_size_t *used,
                     const char *format, ...)
{
    int count; va_list args;
    if (*used >= capacity) return 0;
    va_start(args, format); count = vsnprintf(buffer+*used, capacity-*used, format, args); va_end(args);
    if (count < 0 || (pj_size_t)count >= capacity-*used) return 0;
    *used += count; return 1;
}

PJ_DEF(pj_status_t) pjmedia_stream_voiceprobe(pjmedia_stream *stream, char *buffer,
                                             pj_size_t capacity)
{
    pjmedia_stream_common *base = &stream->base;
    vp_observer *v = (vp_observer*)base->voiceprobe_quality;
    pj_size_t used = 0; unsigned i, comma = 0; pj_timestamp now;
    if (!v) return PJ_ENOTSUP;
    pj_mutex_lock(base->jb_mutex);
    if (!v->initialized) { pj_mutex_unlock(base->jb_mutex); return PJ_EPENDING; }
    pj_get_timestamp(&now);
    if (v->initialized) v->elapsed_ms = 1000.0*(double)(now.u64-v->first_arrival.u64)/(double)v->frequency.u64;
#define VP_OUT(...) do { if (!vp_append(buffer,capacity,&used,__VA_ARGS__)) { pj_mutex_unlock(base->jb_mutex); return PJ_ETOOSMALL; } } while (0)
    VP_OUT("{\"distribution_protocol\":2,\"interval_loss_runs\":%llu,\"interval_starts_lost\":%s,\"interval_ends_lost\":%s,\"protocol\":1,\"valid\":%s,\"ssrc\":\"%u\",\"elapsed_ms\":%.6f,\"samples\":%llu,\"min_ms\":%.6f,\"max_ms\":%.6f,\"sum_ms\":%.6f,\"jitter_sum_ms\":%.6f,\"resolution_ms\":0.25,\"received\":%llu,\"lost\":%llu,\"loss_runs\":%llu,\"total_received\":%llu,\"total_lost\":%llu,\"total_loss_runs\":%llu,\"duplicates\":%llu,\"reordered\":%llu,\"excluded\":%llu,\"overflow\":%llu,\"packetization_ms\":%.6f,\"frame_ms\":%.6f,\"plc_enabled\":%s,\"bins\":[",
      (unsigned long long)v->delta_local_runs, v->delta_starts_lost ? "true":"false", v->previous_lost ? "true":"false",
      v->initialized && v->valid ? "true":"false",v->ssrc,v->elapsed_ms,
      (unsigned long long)v->samples,v->minimum,v->maximum,v->sum,v->jitter_sum,
      (unsigned long long)v->delta_received,(unsigned long long)v->delta_lost,(unsigned long long)v->delta_runs,
      (unsigned long long)v->received,(unsigned long long)v->lost,(unsigned long long)v->loss_runs,
      (unsigned long long)v->duplicates,(unsigned long long)v->reordered,(unsigned long long)v->excluded,(unsigned long long)v->overflow,
      v->variable_packet_ms ? 0.0 : v->packet_ms, (double)stream->dec_ptime/stream->dec_ptime_denum,stream->codec_param.setting.plc?"true":"false");
    for (i=0;i<VP_BINS;++i) if (v->bins[i]) { VP_OUT("%s[%d,%u]",comma?",":"",(int)i-VP_ORIGIN,v->bins[i]);comma=1; }
    VP_OUT("]}");
    pj_bzero(v->bins,sizeof(v->bins));v->samples=0;v->sum=0;v->jitter_sum=0;
    v->delta_received=v->delta_lost=v->delta_runs=v->delta_local_runs=0; v->delta_started=v->delta_starts_lost=0;
    pj_mutex_unlock(base->jb_mutex);
#undef VP_OUT
    return PJ_SUCCESS;
}
