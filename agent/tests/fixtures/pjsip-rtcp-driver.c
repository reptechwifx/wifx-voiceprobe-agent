/* Drive the actual linked PJSIP RTCP receiver with deterministic clock readings.
 * --wrap affects only this test executable; production binaries are unmodified.
 */
#include <pjlib.h>
#include <pjmedia/rtcp.h>
#include <stdio.h>
#include <stdint.h>
static pj_uint64_t test_ticks, test_frequency = 1000000000;
pj_status_t __wrap_pj_get_timestamp(pj_timestamp *value)
{ value->u64 = test_ticks; return PJ_SUCCESS; }
pj_status_t __wrap_pj_get_timestamp_freq(pj_timestamp *value)
{ value->u64 = test_frequency; return PJ_SUCCESS; }
int main(void)
{
    pjmedia_rtcp_session session;
    char op;
    unsigned rate, seq, timestamp;
    unsigned long long ticks, frequency;
    pj_init();
    pj_log_set_level(0);
    while (scanf(" %c", &op) == 1) {
        if (op == 'i') {
            if (scanf("%u %llu %llu", &rate, &ticks, &frequency) != 3) return 2;
            test_ticks = ticks; test_frequency = frequency;
            pjmedia_rtcp_init(&session, "rtcp-safe-017", rate, 160, 1);
        } else if (op == 'p') {
            if (scanf("%llu %u %u %llu %u", &ticks, &timestamp, &seq, &frequency, &rate) != 5) return 2;
            test_ticks = ticks; test_frequency = frequency; session.clock_rate = rate;
            pjmedia_rtcp_rx_rtp(&session, seq, timestamp, 160);
            printf("{\"samples\":%d,\"mean_us\":%d,\"max_us\":%d,\"last_us\":%d,\"mean_precise_us\":%.15g,\"invalid_flags\":%u,\"scaled\":%llu,\"transit\":%u}\n",
                session.stat.rx.jitter.n, session.stat.rx.jitter.mean,
                session.stat.rx.jitter.max, session.stat.rx.jitter.last,
                session.stat.rx.jitter.fmean_, session.voiceprobe_jitter_invalid,
                (unsigned long long)session.jitter, session.transit);
        }
    }
    pj_shutdown();
    return 0;
}
