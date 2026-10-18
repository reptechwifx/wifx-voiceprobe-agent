/* SPDX-License-Identifier: GPL-3.0-or-later
 * Exact integer arithmetic for the pinned PJSIP 2.16 RTCP receiver.
 * RTP timestamps are modulo 2^32; statistics in pj_math_stat are signed int.
 */
#ifndef VOICEPROBE_RTCP_SAFE_H
#define VOICEPROBE_RTCP_SAFE_H
#include <stdint.h>
#include <limits.h>

static uint32_t vp_rtcp_clock(uint64_t ticks, uint64_t frequency, uint32_t rate)
{
    uint64_t remainder = ticks % frequency, accumulator = 0;
    uint32_t fraction = 0;
    uint32_t whole = (uint32_t)(ticks / frequency) * rate;
    int bit;
    if (!rate) return 0;
    if (remainder <= UINT64_MAX / rate)
        return whole + (uint32_t)(remainder * rate / frequency);
    /* Binary long division for unusual frequencies. Neither addition can
     * overflow: subtraction is used whenever the sum reaches the divisor. */
    for (bit = 31; bit >= 0; --bit) {
        fraction *= 2;
        if (accumulator >= frequency - accumulator) {
            accumulator -= frequency - accumulator;
            ++fraction;
        } else accumulator += accumulator;
        if ((rate >> bit) & 1) {
            if (accumulator >= frequency - remainder) {
                accumulator -= frequency - remainder;
                ++fraction;
            } else accumulator += remainder;
        }
    }
    return whole + fraction;
}

static int64_t vp_rtcp_delta(uint32_t current, uint32_t previous)
{
    uint32_t delta = current - previous;
    return delta <= INT32_MAX ? (int64_t)delta : (int64_t)delta - INT64_C(4294967296);
}

static uint64_t vp_rtcp_jitter_step(uint64_t scaled, int64_t delta)
{
    uint64_t magnitude = (uint64_t)(delta < 0 ? -delta : delta);
    return scaled - ((scaled + 8) >> 4) + magnitude;
}

static int vp_rtcp_usec(uint32_t samples, uint32_t rate, uint32_t *usec)
{
    uint64_t value;
    if (!rate) return 0;
    value = (uint64_t)samples * UINT64_C(1000000) / rate;
    if (value > INT_MAX) return 0; /* Explicit invalidity, never saturation. */
    *usec = (uint32_t)value;
    return 1;
}
#endif
