"""Real PJSUA2 loopback media LAB, no PBX/Controller or production addresses.

Run in an isolated network namespace for netem. A single endpoint hosts two
independent accounts/calls and real RTP transports. This is not hardware proof.
"""
import gc
import json
import os
from pathlib import Path
import sys
import resource
import subprocess
import tempfile
import time

sys.path.insert(0, os.environ['VOICEPROBE_PJSUA2_SDK'])
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import pjsua2 as pj
from jitter_buffer import JitterBufferHistory
from jitter_profiles import apply_profile, verify_readback


def run(profile=None):
    impairment = os.environ.get('VP_LAB_NETEM', '')
    if impairment:
        assert os.stat('/proc/self/ns/net').st_ino != int(os.environ['VP_LAB_PARENT_NETNS']), 'Private namespace required'
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    netem = {'jitter': ['delay', '20ms', '10ms', 'distribution', 'normal'],
             'spike': ['delay', '180ms'], 'loss': ['loss', '2%'],
             'burst': ['loss', 'gemodel', '3%', '30%', '95%', '0.1%'],
             'reorder': ['delay', '40ms', 'reorder', '25%', '50%', 'gap', '5'],
             'late': ['delay', '150ms', '50ms']}
    def impair(arguments):
        subprocess.run(['tc', 'qdisc', 'replace', 'dev', 'lo', 'root', 'netem', *arguments], check=True, capture_output=True)

    cpu_started = time.process_time()
    wall_started = time.monotonic()
    endpoint = pj.Endpoint()
    endpoint.libCreate()
    config = pj.EpConfig()
    config.uaConfig.threadCnt = 0
    config.uaConfig.mainThreadOnly = True
    config.logConfig.level = 0
    config.logConfig.consoleLevel = 0
    config.medConfig.noVad = True
    endpoint.libInit(config)
    transport = pj.TransportConfig(); transport.port = 0; transport.boundAddress = '127.0.0.1'
    tid = endpoint.transportCreate(pj.PJSIP_TRANSPORT_UDP, transport)
    endpoint.libStart(); endpoint.audDevManager().setNullDev()
    address = endpoint.transportGetInfo(tid).localAddress
    for codec in endpoint.codecEnum2():
        endpoint.codecSetPriority(codec.codecId, 255 if codec.codecId.startswith(os.environ.get('VP_LAB_CODEC', 'PCMU/8000')) else 0)
    calls = []

    class Call(pj.Call):
        def __init__(self, account, call_id=pj.PJSUA_INVALID_ID):
            super().__init__(account, call_id)
            self.history = JitterBufferHistory()
            self.received_packets = 0
            self.rtp_loss = 0
            self.rtp_jitter_ms = None
            self.observer = None
            self.active = False
            self.finished = False
            self.stats = None
            self.audio = None
            self.application = None

        def onStreamPreCreate(self, prm):
            info = prm.streamInfo
            if info.type != pj.PJMEDIA_TYPE_AUDIO:
                return
            if profile:
                self.application = apply_profile(info, profile, endpoint.libVersion().full)

        def onCallState(self, prm):
            info = self.getInfo()
            print('VP_LAB_STATE ' + json.dumps({'state': info.stateText, 'status': info.lastStatusCode}), flush=True)
            self.finished = info.state == pj.PJSIP_INV_STATE_DISCONNECTED

        def onCallMediaState(self, prm):
            info = self.getInfo()  # Keep SWIG owner alive while reading its media vector.
            for media in info.media:
                print('VP_LAB_MEDIA ' + json.dumps({'type': media.type, 'status': media.status, 'index': media.index}), flush=True)
                if media.type == pj.PJMEDIA_TYPE_AUDIO and media.status == pj.PJSUA_CALL_MEDIA_ACTIVE:
                    self.audio = self.getAudioMedia(media.index)
                    self.audio.startTransmit(endpoint.audDevManager().getPlaybackDevMedia())
                    endpoint.audDevManager().getCaptureDevMedia().startTransmit(self.audio)
                    self.active = True

    class Account(pj.Account):
        def onIncomingCall(self, prm):
            incoming = Call(self, prm.callId); calls.append(incoming)
            # Answer after returning from the native incoming callback.

    receiver = Account(); sender = Account()
    for account, name in ((receiver, 'receiver'), (sender, 'sender')):
        cfg = pj.AccountConfig(); cfg.idUri = 'sip:' + name + '@' + address
        cfg.mediaConfig.transportConfig.boundAddress = '127.0.0.1'
        cfg.mediaConfig.transportConfig.port = 0
        account.create(cfg)
    outgoing = Call(sender); calls.append(outgoing)
    op = pj.CallOpParam(True); op.opt.audioCount = 1; op.opt.videoCount = 0; op.opt.textCount = 0
    outgoing.makeCall('sip:receiver@' + address, op)
    answered = False
    began = time.monotonic()
    end = began + (12 if impairment else 7)
    applied = cleared = False
    failure = None
    result = None
    try:
        while time.monotonic() < end:
            endpoint.libHandleEvents(10)
            if impairment and not applied and time.monotonic() - began > 2:
                impair(netem[impairment]); applied = True
            if impairment == 'spike' and applied and not cleared and time.monotonic() - began > 2.3:
                impair(['delay', '0ms']); cleared = True
            if len(calls) == 2 and not answered:
                op = pj.CallOpParam(); op.statusCode = 200; calls[1].answer(op); answered = True
            for call in calls:
                if call.active and not call.finished:
                    try:
                        native = call.getStreamStat(0)
                        info = call.getStreamInfo(0)
                        call.stats = call.history.observe(native.jbuf, info)
                        call.received_packets = native.rtcp.rxStat.pkt
                        call.rtp_loss = native.rtcp.rxStat.loss
                        call.observer = json.loads(call.getVoiceProbeStats(0))
                        call.rtp_jitter_ms = native.rtcp.rxStat.jitterUsec.mean / 1000
                        if call.application:
                            call.stats['profile_application'] = verify_readback(call.application, call.stats['state'], info)
                    except pj.Error as error:
                        if getattr(call, 'last_native_error', None) != error.status:
                            print('VP_LAB_PENDING ' + error.info(), flush=True)
                            call.last_native_error = error.status
        results = [{'received_packets': call.received_packets, 'rtp_loss': call.rtp_loss, 'rtp_jitter_ms': call.rtp_jitter_ms, 'jitter_buffer': call.stats, 'playout': (call.observer or {}).get('playout_states')} for call in calls]
        assert len(results) == 2 and all(item['received_packets'] > 50 for item in results), results
        assert all(item['jitter_buffer']['sample_count'] >= 4 for item in results)
        assert all(item['jitter_buffer']['state']['occupancy_frames'] is not None for item in results)
        if profile:
            assert all(item['jitter_buffer'].get('profile_application', {}).get('readback_verified') for item in results), results
        result = {'process_cpu_s': time.process_time() - cpu_started, 'wall_s': time.monotonic() - wall_started, 'max_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, 'impairment': impairment or None, 'requested_profile': profile, 'pjsip': endpoint.libVersion().full, 'platform': sys.platform,
                'scope': 'real localhost RTP; two receivers; not physical ARM64 qualification', 'receivers': results}
    except BaseException as error:
        # Do not retain a traceback containing native Call objects past libDestroy.
        failure = type(error).__name__ + ': ' + (error.info() if isinstance(error, pj.Error) else str(error))
    finally:
        if impairment:
            impair(['delay', '0ms'])
        for call in calls:
            if not call.finished:
                call.hangup(pj.CallOpParam())
        for _ in range(30):
            endpoint.libHandleEvents(10)
        for account in (receiver, sender):
            account.shutdown()
        calls.clear(); outgoing = call = receiver = sender = account = incoming = None
        gc.collect(); endpoint.libDestroy()
    if failure:
        raise AssertionError(failure)
    return result


if __name__ == '__main__':
    profile = None
    if len(sys.argv) > 1:
        mode, initial = sys.argv[1], int(sys.argv[2])
        profile = {'mode': mode, 'initial_ms': initial, 'min_prefetch_ms': initial if mode == 'fixed' else 20,
                   'max_prefetch_ms': initial if mode == 'fixed' else 120, 'capacity_ms': 200,
                   'discard_algorithm': 0 if mode == 'fixed' else 2}
    print('VP_LAB_RESULT ' + json.dumps(run(profile)), flush=True)
