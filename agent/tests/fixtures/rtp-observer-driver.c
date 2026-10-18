/* Exact observer algorithm with deterministic receiver clocks; no SIP simulation. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <assert.h>
typedef uint32_t pj_uint32_t;typedef uint64_t pj_uint64_t;typedef uint16_t pj_uint16_t;
typedef int16_t pj_int16_t;typedef int32_t pj_int32_t;typedef int64_t pj_int64_t;
typedef struct {uint64_t u64;} pj_timestamp;typedef size_t pj_size_t;typedef int pj_status_t;
#define PJ_SUCCESS 0
#define PJ_ENOTSUP 1
#define PJ_ETOOSMALL 2
#define PJ_EPENDING 3
#define PJ_DEF(x) x
#define PJMEDIA_JB_NORMAL_FRAME 1
#define PJMEDIA_JB_MISSING_FRAME 2
#define pj_bzero(p,n) memset(p,0,n)
#define pj_ntohl ntohl
#define pj_ntohs ntohs
static uint64_t now_us, frequency_hz=1000000;
static int pj_get_timestamp_freq(pj_timestamp *t){t->u64=frequency_hz;return 0;}
static int pj_get_timestamp(pj_timestamp *t){t->u64=now_us;return 0;}
static void pj_mutex_lock(void *m){(void)m;}
static void pj_mutex_unlock(void *m){(void)m;}
typedef struct {unsigned pt;uint32_t ts,ssrc;uint16_t seq;} pjmedia_rtp_hdr;
typedef struct {struct {unsigned voiceprobe_jitter_invalid,voiceprobe_tx_jitter_invalid;struct {struct {struct {int n;} jitter;} rx;} stat;} rtcp; void *voiceprobe_quality,*jb_mutex;struct {unsigned rx_pt;} *si;} pjmedia_stream_common;
typedef struct {pjmedia_stream_common base;unsigned dec_ptime,dec_ptime_denum;struct {struct {unsigned plc;} setting;} codec_param;} pjmedia_stream;
#include "../../installer/rtp-observer.h"
int main(void){
 vp_observer observer={0};pjmedia_stream stream={0};char buffer[524288],command;unsigned seq,ts,ssrc,type,frames;double arrival;
 stream.base.voiceprobe_quality=&observer;stream.base.si=calloc(1,sizeof(*stream.base.si));stream.base.si->rx_pt=8;stream.dec_ptime=10;stream.dec_ptime_denum=1;stream.codec_param.setting.plc=1;
 while(scanf(" %c",&command)==1){
  if(command=='p'){
   assert(scanf("%u %u %lf %u",&seq,&ts,&arrival,&ssrc)==4);now_us=(uint64_t)(arrival*1000+.5);pj_timestamp at={now_us};pjmedia_rtp_hdr hdr={8,htonl(ts),htonl(ssrc),htons((uint16_t)seq)};vp_rx(&stream.base,&hdr,&at);
  }else if(command=='c') {unsigned long long hz;assert(scanf("%llu",&hz)==1);frequency_hz=hz;}else if(command=='j') {printf("{\"jitter_ms\":%.9f,\"last_transit_ms\":%.9f}\n",observer.jitter,observer.last_transit);}
  else if(command=='f') {assert(scanf("%u %u",&type,&frames)==2);vp_playout(&stream.base,(char)type,frames);}
  else if(command=='s') {assert(scanf("%lf",&arrival)==1);now_us=(uint64_t)(arrival*1000+.5);int status=pjmedia_stream_voiceprobe(&stream,buffer,sizeof(buffer));if(status==0)puts(buffer);else printf("{\"pending\":%d}\n",status);}
 }
 free(stream.base.si);return 0;
}
