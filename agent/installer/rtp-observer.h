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
#define VP_NET_BUCKETS 320
#define VP_NET_SEQ_SPACE 65536
#define VP_NET_SEGMENTS 16

typedef struct vp_network_bucket {
    pj_uint32_t received, audio, other, missing, audio_missing, other_missing;
    pj_uint32_t mixed_missing, gap_recovered, reordered, duplicates;
    unsigned dirty, segment;
} vp_network_bucket;

typedef struct vp_network_segment {
    pj_uint32_t ssrc;
    pj_uint16_t first_seq, last_seq;
    double start_ms, end_ms;
} vp_network_segment;

typedef struct vp_observer {
    pj_uint32_t bins[VP_BINS];
    pj_uint64_t samples, received, lost, loss_runs, duplicates, reordered;
    pj_uint64_t delta_received, delta_lost, delta_runs, overflow, excluded;
    pj_uint64_t seen;
    pj_uint32_t ssrc, last_ts;
    pj_uint16_t last_seq;
    pj_int64_t extended_ts, first_ts;
    pj_timestamp first_arrival, last_arrival, frequency;
    double minimum, maximum, sum, jitter, jitter_sum, last_transit, elapsed_ms;
    unsigned initialized, playback_started, previous_lost, valid, has_transit;
    unsigned delta_started, delta_starts_lost; pj_uint64_t delta_local_runs;
    pj_uint64_t state_missing, state_empty, state_prefetch;
    pj_uint64_t delta_missing, delta_empty, delta_prefetch;
    double packet_ms; unsigned variable_packet_ms;
    pj_uint8_t net_seen[VP_NET_SEQ_SPACE/8], net_gap_kind[VP_NET_SEQ_SPACE];
    pj_uint16_t net_gap_bucket[VP_NET_SEQ_SPACE];
    vp_network_bucket net_buckets[VP_NET_BUCKETS];
    vp_network_segment net_segments[VP_NET_SEGMENTS];
    pj_timestamp net_first_arrival, net_last_arrival;
    pj_uint32_t net_ssrc, net_high_index;
    pj_uint16_t net_base_seq;
    unsigned net_segment_count, net_last_pt, net_valid, net_out_of_window;
} vp_observer;

/* Sequence space is shared by audio and telephone-event RTP. Missing slots
 * are assigned to the time at which a later packet reveals the gap. A late
 * unique packet corrects that bucket even when it arrives in another one. */
static void vp_network_rx(vp_observer *v, const pjmedia_rtp_hdr *hdr,
                          const pj_timestamp *arrival, pj_uint64_t frequency,
                          unsigned audio_pt)
{
    pj_uint32_t ssrc = pj_ntohl(hdr->ssrc);
    pj_uint16_t seq = pj_ntohs(hdr->seq);
    pj_int16_t delta;
    pj_uint32_t index, i;
    unsigned bucket, kind;
    double elapsed;
    vp_network_bucket *b;
    if (!v->net_segment_count) {
        v->net_first_arrival = *arrival;
        v->net_last_arrival = *arrival;
        v->net_valid = 1;
    }
    if (arrival->u64 < v->net_last_arrival.u64 || !frequency) {
        v->net_valid = 0;
        return;
    }
    elapsed = 1000.0 * (double)(arrival->u64 - v->net_first_arrival.u64) /
              (double)frequency;
    bucket = (unsigned)(elapsed / 2000.0);
    if (bucket >= VP_NET_BUCKETS) {
        v->net_valid = 0;
        return;
    }
    v->net_last_arrival = *arrival;
    b = &v->net_buckets[bucket];
    if (v->net_segment_count) {
        delta = (pj_int16_t)(seq - (pj_uint16_t)(v->net_base_seq + v->net_high_index));
    } else {
        delta = 0;
    }
    if (!v->net_segment_count || ssrc != v->net_ssrc || delta > 3000 ||
        (delta > 0 && v->net_high_index + (unsigned)delta >= VP_NET_SEQ_SPACE)) {
        if (v->net_segment_count >= VP_NET_SEGMENTS) {
            v->net_valid = 0;
            return;
        }
        if (v->net_segment_count && ssrc == v->net_ssrc)
            ++v->net_out_of_window; /* probable source restart or capacity */
        pj_bzero(v->net_seen, sizeof(v->net_seen));
        pj_bzero(v->net_gap_bucket, sizeof(v->net_gap_bucket));
        pj_bzero(v->net_gap_kind, sizeof(v->net_gap_kind));
        v->net_base_seq = seq;
        v->net_high_index = 0;
        v->net_ssrc = ssrc;
        v->net_last_pt = hdr->pt;
        v->net_segments[v->net_segment_count].ssrc = ssrc;
        v->net_segments[v->net_segment_count].first_seq = seq;
        v->net_segments[v->net_segment_count].last_seq = seq;
        v->net_segments[v->net_segment_count].start_ms = elapsed;
        v->net_segments[v->net_segment_count].end_ms = elapsed;
        ++v->net_segment_count;
        delta = 0;
    }
    if (b->segment && b->segment != v->net_segment_count) b->segment = 0;
    else if (!b->received && !b->missing && !b->duplicates) b->segment = v->net_segment_count;
    if (delta < 0 && (pj_uint32_t)(-delta) > v->net_high_index) {
        ++v->net_out_of_window;
        b->dirty = 1;
        return;
    }
    if (delta > 0) {
        kind = (v->net_last_pt == hdr->pt) ?
               (hdr->pt == audio_pt ? 1 : 2) : 3;
        for (i = v->net_high_index + 1; i < v->net_high_index + (unsigned)delta; ++i) {
            ++b->missing;
            if (kind == 1) ++b->audio_missing;
            else if (kind == 2) ++b->other_missing;
            else ++b->mixed_missing;
            v->net_gap_bucket[i] = (pj_uint16_t)(bucket + 1);
            v->net_gap_kind[i] = (pj_uint8_t)kind;
        }
        v->net_high_index += (unsigned)delta;
    }
    index = v->net_high_index + delta * (delta < 0);
    if (v->net_seen[index/8] & (1u << (index%8))) {
        ++b->duplicates;
    } else {
        v->net_seen[index/8] |= (pj_uint8_t)(1u << (index%8));
        ++b->received;
        if (hdr->pt == audio_pt) ++b->audio;
        else ++b->other;
        if (delta < 0) {
            unsigned gap = v->net_gap_bucket[index];
            ++b->reordered;
            if (gap) {
                vp_network_bucket *earlier = &v->net_buckets[gap-1];
                ++b->gap_recovered;
                if (earlier->missing) --earlier->missing;
                if (v->net_gap_kind[index] == 1 && earlier->audio_missing)
                    --earlier->audio_missing;
                else if (v->net_gap_kind[index] == 2 && earlier->other_missing)
                    --earlier->other_missing;
                else if (v->net_gap_kind[index] == 3 && earlier->mixed_missing)
                    --earlier->mixed_missing;
                earlier->dirty = 1;
                v->net_gap_bucket[index] = 0;
            }
        }
    }
    if (delta > 0) {
        v->net_last_pt = hdr->pt;
        v->net_segments[v->net_segment_count-1].last_seq = seq;
    }
    v->net_segments[v->net_segment_count-1].end_ms = elapsed;
    b->dirty = 1;
}

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
    int index; pj_timestamp frequency;
    if (!v) return;
    pj_mutex_lock(base->jb_mutex);
    if (pj_get_timestamp_freq(&frequency) != PJ_SUCCESS || !frequency.u64) {
        v->valid = 0; ++v->excluded; pj_mutex_unlock(base->jb_mutex); return;
    }
    vp_network_rx(v, hdr, arrival, frequency.u64, base->si->rx_pt);
    if (hdr->pt != base->si->rx_pt) {
        pj_mutex_unlock(base->jb_mutex); return;
    }
    if (v->initialized && (frequency.u64 != v->frequency.u64 || arrival->u64 < v->last_arrival.u64)) {
        v->valid = 0; ++v->excluded; pj_mutex_unlock(base->jb_mutex); return;
    }
    v->last_arrival = *arrival;
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
            if (type == PJMEDIA_JB_MISSING_FRAME) {
                ++v->state_missing; ++v->delta_missing;
            } else if (type == PJMEDIA_JB_ZERO_EMPTY_FRAME) {
                ++v->state_empty; ++v->delta_empty;
            } else if (type == PJMEDIA_JB_ZERO_PREFETCH_FRAME) {
                ++v->state_prefetch; ++v->delta_prefetch;
            }
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
    pj_size_t used = 0; unsigned i, comma = 0; pj_timestamp now, frequency;
    if (!v) return PJ_ENOTSUP;
    pj_mutex_lock(base->jb_mutex);
    if (!v->initialized) { pj_mutex_unlock(base->jb_mutex); return PJ_EPENDING; }
    if (pj_get_timestamp(&now) != PJ_SUCCESS || pj_get_timestamp_freq(&frequency) != PJ_SUCCESS ||
        frequency.u64 != v->frequency.u64 || now.u64 < v->last_arrival.u64) v->valid = 0;
    else if (v->initialized) v->elapsed_ms = 1000.0*(double)(now.u64-v->first_arrival.u64)/(double)v->frequency.u64;
#define VP_OUT(...) do { if (!vp_append(buffer,capacity,&used,__VA_ARGS__)) { pj_mutex_unlock(base->jb_mutex); return PJ_ETOOSMALL; } } while (0)
    VP_OUT("{\"distribution_protocol\":2,\"interval_loss_runs\":%llu,\"interval_starts_lost\":%s,\"interval_ends_lost\":%s,\"protocol\":2,\"valid\":%s,\"ssrc\":\"%u\",\"elapsed_ms\":%.6f,\"samples\":%llu,\"min_ms\":%.6f,\"max_ms\":%.6f,\"sum_ms\":%.6f,\"jitter_sum_ms\":%.6f,\"resolution_ms\":0.25,\"received\":%llu,\"lost\":%llu,\"loss_runs\":%llu,\"total_received\":%llu,\"total_lost\":%llu,\"total_loss_runs\":%llu,\"duplicates\":%llu,\"reordered\":%llu,\"excluded\":%llu,\"overflow\":%llu,\"packetization_ms\":%.6f,\"frame_ms\":%.6f,\"plc_enabled\":%s,\"bins\":[",
      (unsigned long long)v->delta_local_runs, v->delta_starts_lost ? "true":"false", v->previous_lost ? "true":"false",
      v->initialized && v->valid ? "true":"false",v->ssrc,v->elapsed_ms,
      (unsigned long long)v->samples,v->minimum,v->maximum,v->sum,v->jitter_sum,
      (unsigned long long)v->delta_received,(unsigned long long)v->delta_lost,(unsigned long long)v->delta_runs,
      (unsigned long long)v->received,(unsigned long long)v->lost,(unsigned long long)v->loss_runs,
      (unsigned long long)v->duplicates,(unsigned long long)v->reordered,(unsigned long long)v->excluded,(unsigned long long)v->overflow,
      v->variable_packet_ms ? 0.0 : v->packet_ms, (double)stream->dec_ptime/stream->dec_ptime_denum,stream->codec_param.setting.plc?"true":"false");
    for (i=0;i<VP_BINS;++i) if (v->bins[i]) { VP_OUT("%s[%d,%u]",comma?",":"",(int)i-VP_ORIGIN,v->bins[i]);comma=1; }
    VP_OUT("],\"pjsip_jitter\":{\"method\":\"vp-rtcp-safe-v1\",\"rx_invalid_flags\":%u,\"tx_invalid_flags\":%u,\"samples\":%d},",
        base->rtcp.voiceprobe_jitter_invalid, base->rtcp.voiceprobe_tx_jitter_invalid, base->rtcp.stat.rx.jitter.n);
    VP_OUT("\"playout_states\":{\"protocol\":1,\"missing\":%llu,\"empty\":%llu,\"prefetch\":%llu,\"total_missing\":%llu,\"total_empty\":%llu,\"total_prefetch\":%llu},",
        (unsigned long long)v->delta_missing, (unsigned long long)v->delta_empty,
        (unsigned long long)v->delta_prefetch, (unsigned long long)v->state_missing,
        (unsigned long long)v->state_empty, (unsigned long long)v->state_prefetch);
    VP_OUT("\"network\":{\"protocol\":1,\"method\":\"rtp-sequence-observer-v1\",\"bucket_s\":2,\"valid\":%s,\"out_of_window\":%u,\"origin_delta_ms\":%.6f,\"segments\":[",
        v->net_valid ? "true":"false", v->net_out_of_window,
        v->net_first_arrival.u64 >= v->first_arrival.u64 ?
          1000.0*(double)(v->net_first_arrival.u64-v->first_arrival.u64)/(double)v->frequency.u64 :
          -1000.0*(double)(v->first_arrival.u64-v->net_first_arrival.u64)/(double)v->frequency.u64);
    for (i=0; i<v->net_segment_count; ++i) {
        vp_network_segment *seg = &v->net_segments[i];
        VP_OUT("%s{\"id\":%u,\"ssrc\":\"%u\",\"start_s\":%.3f,\"end_s\":%.3f,\"first_seq\":%u,\"last_seq\":%u}",
            i?",":"", i+1, seg->ssrc, seg->start_ms/1000.0, seg->end_ms/1000.0,
            seg->first_seq, seg->last_seq);
    }
    VP_OUT("],\"changes\":["); comma = 0;
    for (i=0; i<VP_NET_BUCKETS; ++i) {
        vp_network_bucket *b = &v->net_buckets[i];
        if (!b->dirty) continue;
        VP_OUT("%s[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]", comma?",":"",
            i,b->received,b->audio,b->other,b->missing,b->audio_missing,
            b->other_missing,b->mixed_missing,b->gap_recovered,b->reordered,b->duplicates,b->segment);
        comma = 1;
    }
    VP_OUT("]}}");
    pj_bzero(v->bins,sizeof(v->bins));v->samples=0;v->sum=0;v->jitter_sum=0;
    v->delta_received=v->delta_lost=v->delta_runs=v->delta_local_runs=0; v->delta_started=v->delta_starts_lost=0;
    v->delta_missing=v->delta_empty=v->delta_prefetch=0;
    for (i=0; i<VP_NET_BUCKETS; ++i) v->net_buckets[i].dirty=0;
    pj_mutex_unlock(base->jb_mutex);
#undef VP_OUT
    return PJ_SUCCESS;
}
