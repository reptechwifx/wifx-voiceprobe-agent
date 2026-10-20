"""PJSUA2 real SIP/RTP probe. SIP callbacks stay on one event loop thread."""

import asyncio, gc, json, os, pathlib, platform, queue, re, signal, socket, sqlite3, ssl, threading, time, uuid
import requests, websockets, pjsua2 as pj
from audio import reference, analyze, analyze_echo, observe_audio
from incoming import correlate, trusted_pbx_addresses, reception_status, outgoing_allowed
from reporting import recovery_report, ReportOutbox
from remote_update import RemoteUpdate
from sdp import constrain_audio
from localweb import build_server
from version import VERSION, DISPLAY_VERSION, BUILD_ID
from identity import exchange, verify_identity, atomic_json
from maintenance import Maintenance
from credentials import hash_password
from journal import EventJournal, redact
from telemetry import system_snapshot, network_snapshot
from rtp_quality import ReceiverQuality, annotate_pjsip_jitter
from network_diagnostics import (INITIAL_METHOD, MEDIA_DSCP, SIP_DSCP, observed_peer,
    set_dscp, start as start_network_diagnostic, unavailable as network_unavailable)
from dtmf_identity import (FrameReceiver, NumericFrameReceiver, IDENTIFICATION_SECONDS, DTMF_DURATION_MS,
    NUMERIC_DTMF_DURATION_MS,
    DISCOVERY_REQUEST, DISCOVERY_REPLY, NUMERIC_DISCOVERY_REQUEST, NUMERIC_DISCOVERY_REPLY,
    MAX_DISCOVERY_ATTEMPTS, DISCOVERY_RETRY_SECONDS, decode as decode_dtmf,
    decode_numeric, frame as dtmf_frame, numeric_frame)

ADMIN_FIELDS = (
    "organization",
    "owner",
    "responsible",
    "internal_reference",
    "description",
    "notes",
    "site",
    "location",
    "address",
    "postal_code",
    "city",
    "canton",
    "country",
    "latitude",
    "longitude",
    "contact",
)


def utc():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class ProbeCall(pj.Call):
    def __init__(self, account, run_id, duration, call_id=pj.PJSUA_INVALID_ID):
        super().__init__(account, call_id)
        self.account = account
        self.agent = account.agent
        self.run_id = run_id
        self.duration = duration
        self.created = time.monotonic()
        self.incoming = None
        self.answer_at = None
        self.pending_response = None
        self.audio_profile = account.config.get("audio_profile", "tone-1000")
        self.destination = None
        self.started = None
        self.finished = False
        self.established = False
        self.player = None
        self.recorder = None
        self.media = None
        self.stats = {}
        self.receiver_quality = ReceiverQuality()
        self.last_quality_sample = 0.0
        self.codec = None
        self.events = []
        self.preferred = None
        self.scenario_type = "probe"
        self.call_id = None
        self.last_code = 0
        self.reason = ""
        self.closing_at = None
        self.ended = None
        self.recording = self.agent.data / (run_id + ".wav")
        self.dtmf_frame = None
        self.dtmf_discovery = False
        self.dtmf_discovery_sent = False
        self.dtmf_discovery_received = False
        self.dtmf_discovery_reply_pending = False
        self.dtmf_discovery_reply_sent = False
        self.dtmf_discovery_reply_attempts = 0
        self.dtmf_discovery_received_count = 0
        self.dtmf_next_reply_at = 0.0
        self.dtmf_receiver = FrameReceiver()
        self.dtmf_numeric_receiver = NumericFrameReceiver()
        self.dtmf_protocol = None
        self.dtmf_started_at = None
        self.dtmf_discovery_attempts = 0
        self.dtmf_next_discovery_at = 0.0
        self.dtmf_event_ids = set()
        self.dtmf_sent = False
        self.dtmf_ack_sent = False
        self.dtmf_received = False
        self.dtmf_controller_confirmed = False
        self.dtmf_status = "not_requested"
        self.dtmf_method = None
        self.dtmf_received_method = None
        self.dtmf_completed_at = None
        self.is_incoming = False
        self.dtmf_expected = False
        self.audio_phase_started = False
        self.rtp_audio_baseline = None
        self.audio_phase_offset_s = None
        self.network_peer = None
        self.network_jobs = {}
        self.network_results = {}
        self.network_started = set()
        self.network_phases = {}
        self.audio_report = None
        self.audio_report_analyzed = False

    def onCallState(self, prm):
        info = self.getInfo()
        self.call_id = info.callIdString
        self.last_code = info.lastStatusCode
        if info.state == pj.PJSIP_INV_STATE_CONFIRMED:
            self.started = self.started or time.monotonic()
            if self.dtmf_receiver.started is None:
                self.dtmf_receiver.start()
                self.dtmf_numeric_receiver.start()
            self.established = True
            self.events.append({"kind": "confirmed", "at": utc()})
            self.agent.journal.record(
                "call",
                "Appel établi",
                run_id=self.run_id,
                account=self.account.config["username"],
            )
        if info.state == pj.PJSIP_INV_STATE_DISCONNECTED:
            self.reason = info.lastReason
            self.finished = True
            self.ended = time.monotonic()
            self.agent.journal.record(
                "call", "Appel terminé", run_id=self.run_id, sip_code=self.last_code
            )
            self.events.append(
                {"kind": "disconnected", "at": utc(), "sip_code": self.last_code}
            )

    def onCallSdpCreated(self, prm):
        prm.sdp.wholeSdp = constrain_audio(
            prm.sdp.wholeSdp, self.account.config["codecs"], self.preferred
        )

    def onCallMediaState(self, prm):
        try:
            if self.media is not None:
                return
            self.media = self.getAudioMedia(-1)
            if self.started and self.dtmf_started_at is None:
                self.dtmf_started_at = time.monotonic()
                self.dtmf_receiver.start()
                self.dtmf_numeric_receiver.start()
            if self.audio_profile == "echo":
                self.media.startTransmit(self.media)
            else:
                self.player = pj.AudioMediaPlayer()
                self.player.createPlayer(str(self.agent.echo_tone if self.scenario_type == "echo" else self.agent.tone))
            self.recorder = pj.AudioMediaRecorder()
            self.recorder.createRecorder(str(self.recording))
            if self.player is not None:
                self.player.startTransmit(self.media)
            self.media.startTransmit(self.recorder)
        except pj.Error:
            self.events.append({"kind": "media_not_ready", "at": utc()})

    def onDtmfDigit(self, prm):
        method = ("rtp_telephone_event" if prm.method == pj.PJSUA_DTMF_METHOD_RFC2833 else
                  "sip_info" if prm.method == pj.PJSUA_DTMF_METHOD_SIP_INFO else None)
        if method != "sip_info":
            return
        self._receive_dtmf_digit(prm.digit, method)

    def onDtmfEvent(self, prm):
        if prm.method != pj.PJSUA_DTMF_METHOD_RFC2833:
            return
        # RFC 4733 updates and repeated end packets share an event timestamp.
        # Distinct consecutive identical digits have distinct timestamps.
        key = (prm.timestamp, prm.digit)
        if key in self.dtmf_event_ids or len(self.dtmf_event_ids) >= 64:
            return
        self.dtmf_event_ids.add(key)
        self._receive_dtmf_digit(prm.digit, "rtp_telephone_event")

    def _receive_dtmf_digit(self, digit, method):
        if self.is_incoming:
            self.dtmf_expected = True
        if self.dtmf_protocol == 2:
            result = self.dtmf_numeric_receiver.feed(digit)
        elif self.dtmf_protocol == 1:
            result = self.dtmf_receiver.feed(digit)
        else:
            result = self.dtmf_numeric_receiver.feed(digit) or self.dtmf_receiver.feed(digit)
        if result is None:
            return
        kind, code = result
        if kind == "discovery":
            if self.is_incoming and not self.dtmf_received and code in (DISCOVERY_REQUEST, NUMERIC_DISCOVERY_REQUEST):
                self.dtmf_protocol = 2 if code == NUMERIC_DISCOVERY_REQUEST else 1
                self.dtmf_discovery_received_count += 1
                if not self.dtmf_discovery_reply_sent or (self.dtmf_protocol == 2 and self.dtmf_discovery_received_count >= 3):
                    self.dtmf_discovery_reply_pending = True
                self.dtmf_status = "discovery_received"
            elif not self.is_incoming and self.dtmf_discovery and code in (DISCOVERY_REPLY, NUMERIC_DISCOVERY_REPLY):
                self.dtmf_discovery_received = True
                self.dtmf_status = "discovery_confirmed"
            return
        if self.is_incoming and self.dtmf_protocol is None:
            self.dtmf_protocol = 1
        if (kind == "1" and self.is_incoming) or (kind == "2" and not self.is_incoming and self.dtmf_frame is not None):
            self.dtmf_received = True
            self.dtmf_received_method = method
            self.dtmf_status = "received_pending_server"
            encoded = numeric_frame(kind, code) if self.dtmf_protocol == 2 else dtmf_frame(kind, code)
            self.agent.dtmf_observations.put({"local_call_id": self.run_id,
                "account_id": self.account.config["id"], "frame": encoded,
                "method": method, "deadline": (self.dtmf_started_at or self.started or time.monotonic()) + IDENTIFICATION_SECONDS})
            self.agent.poll_now.set()

    def send_dtmf(self, digits):
        if not self.started or self.finished or time.monotonic() - (self.dtmf_started_at or self.started) >= IDENTIFICATION_SECONDS:
            self.dtmf_status = "timeout"
            return False
        try:
            parameters = pj.CallSendDtmfParam()
            parameters.method = pj.PJSUA_DTMF_METHOD_RFC2833
            parameters.duration = NUMERIC_DTMF_DURATION_MS if self.dtmf_protocol == 2 else DTMF_DURATION_MS
            parameters.digits = digits
            self.sendDtmf(parameters)
            self.dtmf_method = "rtp_telephone_event"
            return True
        except pj.Error as error:
            self.dtmf_status = "transport_unavailable"
            self.events.append({"kind": "dtmf_send_failed", "at": utc(), "status": getattr(error, "status", None)})
            return False

    def identification_tick(self):
        if not self.started or self.finished:
            return
        if self.media is not None and self.dtmf_started_at is None:
            self.dtmf_started_at = time.monotonic()
            if not (self.dtmf_receiver.digits_seen or self.dtmf_numeric_receiver.digits_seen):
                self.dtmf_receiver.start()
                self.dtmf_numeric_receiver.start()
        elapsed = time.monotonic() - (self.dtmf_started_at or self.started)
        if (self.dtmf_discovery_reply_pending and self.media is not None
                and self.dtmf_discovery_reply_attempts < (2 if self.dtmf_protocol == 2 else 1)
                and elapsed >= self.dtmf_next_reply_at and elapsed < IDENTIFICATION_SECONDS):
            reply = NUMERIC_DISCOVERY_REPLY if self.dtmf_protocol == 2 else DISCOVERY_REPLY
            if self.send_dtmf(reply):
                self.dtmf_discovery_reply_sent = True
                self.dtmf_discovery_reply_attempts += 1
                self.dtmf_next_reply_at = elapsed + DISCOVERY_RETRY_SECONDS
                self.dtmf_discovery_reply_pending = False
                self.dtmf_status = "discovery_reply_sent"
        if (self.dtmf_frame and self.dtmf_discovery and self.media is not None and
                not self.dtmf_discovery_received and not self.dtmf_sent and elapsed < IDENTIFICATION_SECONDS):
            repeat = self.dtmf_protocol == 2
            if (self.dtmf_discovery_attempts < (MAX_DISCOVERY_ATTEMPTS if repeat else 1)
                    and elapsed >= self.dtmf_next_discovery_at and (not repeat or elapsed <= 3.5)):
                request = NUMERIC_DISCOVERY_REQUEST if repeat else DISCOVERY_REQUEST
                if self.send_dtmf(request):
                    self.dtmf_discovery_sent = True
                    self.dtmf_discovery_attempts += 1
                    self.dtmf_next_discovery_at = elapsed + DISCOVERY_RETRY_SECONDS
                    self.dtmf_status = "discovery_sent"
        if self.dtmf_frame and (not self.dtmf_discovery or self.dtmf_discovery_received) and self.media is not None and not self.dtmf_sent and elapsed < IDENTIFICATION_SECONDS:
            self.dtmf_sent = self.send_dtmf(self.dtmf_frame)
            if self.dtmf_sent:
                self.dtmf_status = "a_to_b_sent"
        if elapsed >= IDENTIFICATION_SECONDS and self.dtmf_discovery_sent and not self.dtmf_discovery_received and self.dtmf_status == "discovery_sent":
            self.dtmf_status = "remote_unverified"
        if elapsed >= IDENTIFICATION_SECONDS and self.dtmf_status in ("a_to_b_sent", "received_pending_server", "ack_sent"):
            self.dtmf_status = "timeout"
        if elapsed >= IDENTIFICATION_SECONDS and self.dtmf_expected and self.dtmf_status == "not_requested":
            self.dtmf_status = ("invalid_frame" if self.dtmf_receiver.invalid else
                                "incomplete" if self.dtmf_receiver.digits_seen else "not_received")
        audio_boundary = IDENTIFICATION_SECONDS
        if self.dtmf_protocol == 2 and self.dtmf_controller_confirmed and self.dtmf_completed_at:
            audio_boundary = min(IDENTIFICATION_SECONDS,
                                 self.dtmf_completed_at - (self.dtmf_started_at or self.started) + 0.3)
        if (self.dtmf_frame or self.dtmf_expected) and not self.audio_phase_started and elapsed >= audio_boundary:
            # Drain the native observer at the phase boundary. DTMF can suppress
            # regular audio RTP, so its decoder erasures must remain diagnostic only.
            self.collect_receiver_quality(force=True)
            rx = self.stats.get("rx", {})
            if self.dtmf_protocol == 2 and all(isinstance(rx.get(key), int) and rx[key] >= 0 for key in ("packets", "loss")):
                self.rtp_audio_baseline = {key: rx[key] for key in ("packets", "loss")}
            self.audio_phase_offset_s = round(elapsed, 3)
            self.receiver_quality.begin_audio_phase()
            self.audio_phase_started = True

    def sample(self):
        if not self.established or self.finished:
            return
        try:
            stat = self.getStreamStat(0)
            info = self.getStreamInfo(0)
            self.codec = info.codecName + "/" + str(info.codecClockRate)

            def stream(s):
                return {
                    "packets": s.pkt,
                    "bytes": s.bytes,
                    "loss": s.loss,
                    "duplicates": s.dup,
                    "reordered": s.reorder,
                    "discarded": s.discard,
                    "jitter_ms_mean": (
                        s.jitterUsec.mean / 1000 if s.jitterUsec.n else None
                    ),
                    "jitter_ms_max": (
                        s.jitterUsec.max / 1000 if s.jitterUsec.n else None
                    ),
                    "loss_period_ms_max": s.lossPeriodUsec.max / 1000,
                }

            self.stats = {
                "rx": stream(stat.rtcp.rxStat),
                "tx": stream(stat.rtcp.txStat),
                "rtt_ms_mean": (
                    stat.rtcp.rttUsec.mean / 1000 if stat.rtcp.rttUsec.n else None
                ),
                "remote_rtp": info.remoteRtpAddress,
                "remote_rtcp": info.remoteRtcpAddress,
                "codec": self.codec,
                "audio_clock_hz": info.codecClockRate,
                "rtp_clock_hz": (
                    8000 if info.codecName.upper() == "G722" else info.codecClockRate
                ),
                "rx_payload_type": getattr(info, "rxPt", None),
                "tx_payload_type": getattr(info, "txPt", None),
                "jitter_buffer": {
                    "lost": stat.jbuf.lost,
                    "discarded": stat.jbuf.discard,
                    "empty": stat.jbuf.empty,
                },
                "rtp_interruptions": None,
                "network_loss_bursts": None,
            }
        except (pj.Error, AttributeError):
            # Some jitter-buffer fields differ by PJSIP release; preserve RTCP data.
            try:
                stat = self.getStreamStat(0)
                info = self.getStreamInfo(0)
                self.codec = info.codecName + "/" + str(info.codecClockRate)
                self.stats = {
                    "rx": stream(stat.rtcp.rxStat),
                    "tx": stream(stat.rtcp.txStat),
                    "rtt_ms_mean": (
                        stat.rtcp.rttUsec.mean / 1000 if stat.rtcp.rttUsec.n else None
                    ),
                    "remote_rtp": info.remoteRtpAddress,
                    "remote_rtcp": info.remoteRtcpAddress,
                    "codec": self.codec,
                    "audio_clock_hz": info.codecClockRate,
                    "rtp_clock_hz": (
                        8000
                        if info.codecName.upper() == "G722"
                        else info.codecClockRate
                    ),
                    "rx_payload_type": getattr(info, "rxPt", None),
                    "tx_payload_type": getattr(info, "txPt", None),
                    "jitter_buffer": None,
                    "rtp_interruptions": None,
                    "network_loss_bursts": None,
                }
            except Exception:
                pass

        self.collect_receiver_quality()
        if self.receiver_quality.latest:
            self.stats.setdefault('rx', {}).update(self.receiver_quality.latest)

        annotate_pjsip_jitter(self.stats)
        rx = self.stats.get("rx", {})
        if self.rtp_audio_baseline and all(isinstance(rx.get(key), int) and rx[key] >= self.rtp_audio_baseline[key] for key in ("packets", "loss")):
            received = rx["packets"] - self.rtp_audio_baseline["packets"]
            lost = rx["loss"] - self.rtp_audio_baseline["loss"]
            rx["audio_phase_rtp"] = {"method": "rtcp-receiver-counter-delta-v1", "start_s": self.audio_phase_offset_s,
                                     "received": received, "lost": lost, "valid": received + lost > 0}
        tx=self.stats.get("tx")
        if tx:
            feedback=tx.get("jitter_ms_mean") is not None or self.stats.get("rtt_ms_mean") is not None
            self.stats["remote_rtcp_feedback_available"]=feedback
            if not feedback: tx["loss"]=None
            for unavailable in ("duplicates","reordered","discarded","loss_period_ms_max"): tx[unavailable]=None

        try:
            transport = self.getMedTransportInfo(0)
            for field, attribute in (
                ("local_rtp", "localRtpName"),
                ("local_rtcp", "localRtcpName"),
                ("observed_rtp_source", "srcRtpName"),
                ("observed_rtcp_source", "srcRtcpName"),
            ):
                address = getattr(transport, attribute)
                self.stats[field] = (
                    address if address not in ("", "0.0.0.0:0", "[::]:0") else None
                )
        except pj.Error:
            pass

    def diagnostics_tick(self):
        if not self.started or self.finished:
            return
        elapsed = time.monotonic() - (self.dtmf_started_at or self.started)
        peer = observed_peer(self.stats.get("observed_rtp_source"))
        if peer and not self.network_peer:
            self.network_peer = peer
        if not self.network_peer:
            return
        # Discovery consumes the first ten seconds of a v2 call. Probe only
        # after that interval, on a separate diagnostic port and worker thread.
        initial_key = "icmp_initial" if INITIAL_METHOD == "icmp" else "udp"
        if (initial_key not in self.network_started
                and (self.audio_phase_started or elapsed >= IDENTIFICATION_SECONDS)):
            if INITIAL_METHOD == "icmp":
                self._start_network_diagnostic("icmp", slot=initial_key)
            else:
                self._start_network_diagnostic("udp")
        no_dtmf = not (self.dtmf_frame or self.dtmf_expected)
        if "icmp" not in self.network_started and (self.audio_phase_started or no_dtmf and elapsed >= IDENTIFICATION_SECONDS):
            rx = self.stats.get("rx", {})
            phase = rx if no_dtmf else (rx.get("audio_phase_rtp") or {})
            received, lost = phase.get("received"), phase.get("lost")
            if no_dtmf:
                received, lost = rx.get("packets"), rx.get("loss")
            valid = (phase.get("valid") is True if not no_dtmf else
                     type(received) is int and type(lost) is int)
            # Use the same received/lost RTP population graded by MediaQuality.
            # Decoder erasures alone are not an RTP loss classification.
            if (valid and type(received) is int and type(lost) is int
                    and received >= 0 and lost >= 0 and received + lost >= 100
                    and 100 * lost / (received + lost) > 1):
                self._start_network_diagnostic("icmp")

    def _start_network_diagnostic(self, method, phase="during_call", slot=None):
        key = slot or method
        self.network_started.add(key)
        self.network_phases[key] = phase
        try:
            job = start_network_diagnostic(method, self.network_peer)
            if job is None:
                self.network_results[key] = network_unavailable("agent_probe_limit", method, self.network_peer)
            else:
                self.network_jobs[key] = job
        except (OSError, ValueError):
            self.network_results[key] = network_unavailable("probe_start_failed", method, self.network_peer)

    def completed_network_diagnostics(self):
        for method, job in list(self.network_jobs.items()):
            if not job.done():
                return None
            try:
                self.network_results[method] = job.result()
            except Exception:
                self.network_results[method] = network_unavailable("probe_failed", method, self.network_peer)
            del self.network_jobs[method]
        initial_key = "icmp_initial" if INITIAL_METHOD == "icmp" else "udp"
        if initial_key not in self.network_results:
            self.network_results[initial_key] = network_unavailable(
                "call_too_short" if self.network_peer else "rtp_peer_not_observed", INITIAL_METHOD, self.network_peer)
        return [dict(self.network_results[name], phase=self.network_phases.get(name, "during_call"))
                for name in (initial_key, "icmp") if name in self.network_results]

    def collect_receiver_quality(self, force=False):
        if not hasattr(self, 'getVoiceProbeStats'):
            return
        current = time.monotonic()
        if not force and current - self.last_quality_sample < 2.0:
            return
        self.last_quality_sample = current
        try:
            observation = json.loads(self.getVoiceProbeStats(0))
            self.receiver_quality.add(observation, self.codec)
            self.receiver_quality.latest = self.receiver_quality.snapshot(self.codec or '')
            self.stats.setdefault('rx', {}).update(self.receiver_quality.latest)
        except pj.Error:
            return
        except (ValueError, KeyError, TypeError):
            self.receiver_quality.valid = False
            if self.receiver_quality.last:
                self.receiver_quality.latest = self.receiver_quality.snapshot(self.codec or '')
                self.stats.setdefault('rx', {}).update(self.receiver_quality.latest)

    def onStreamDestroyed(self, prm):
        self.collect_receiver_quality(force=True)
        if self.receiver_quality.latest:
            self.stats.setdefault('rx', {}).update(self.receiver_quality.latest)

    def hangup_safe(self):
        self.collect_receiver_quality(force=True)
        try:
            self.hangup(pj.CallOpParam())
        except pj.Error:
            self.finished = True

    def report(self):
        if self.closing_at is None:
            self.closing_at = time.monotonic()
            self.player = None
            self.recorder = None
            gc.collect()
            return False
        if time.monotonic() - self.closing_at < 0.3:
            return False
        annotate_pjsip_jitter(self.stats)
        elapsed = max(
            0, (self.ended or time.monotonic()) - (self.started or time.monotonic())
        )
        if self.player is not None:
            try:
                self.player.stopTransmit(self.media)
            except pj.Error:
                pass
        if self.recorder is not None:
            try:
                self.media.stopTransmit(self.recorder)
            except pj.Error:
                pass
        self.player = None
        self.recorder = None
        gc.collect()
        if not self.audio_report_analyzed:
            try:
                if self.recording.exists():
                    audio_start = (self.audio_phase_offset_s or IDENTIFICATION_SECONDS) if (self.dtmf_frame or self.dtmf_expected) else 0
                    if audio_start and elapsed <= audio_start + 0.5:
                        self.events.append({"kind": "audio_phase_unavailable", "at": utc()})
                    else:
                        self.audio_report = (analyze_echo(self.recording, self.agent.echo_tone) if self.scenario_type == "echo" else observe_audio(self.recording) if self.scenario_type == "destination" else analyze(self.recording, start_s=audio_start))
            except Exception as error:
                self.events.append(
                    {
                        "kind": "recording_analysis_failed",
                        "at": utc(),
                        "error": type(error).__name__ + ": " + str(error)[:160],
                    }
                )
            self.audio_report_analyzed = True
            audio = self.audio_report or {}
            analyzed, interrupted = audio.get("analyzed_s"), audio.get("interrupted_s")
            if (self.network_peer and "icmp" not in self.network_started and self.incoming is None
                    and audio.get("reference_available", True) is True
                    and isinstance(analyzed, (int, float)) and isinstance(interrupted, (int, float))
                    and analyzed > 0 and interrupted >= 0
                    and (interrupted > 1 or 100 * interrupted / analyzed > 3)):
                self._start_network_diagnostic("icmp", phase="after_call")
        network_diagnostics = self.completed_network_diagnostics()
        if network_diagnostics is None:
            return False
        audio = self.audio_report
        metrics = {
            "established": self.established,
            "duration_s": round(elapsed, 3),
            "sip": {
                "call_id": self.call_id,
                "last_code": self.last_code,
                "setup_s": round(self.started - self.created, 3) if self.started else None,
                "reason": self.reason,
                "account_id": self.account.config["id"],
                "local_uri": self.account.getInfo().uri,
                "codec": self.codec,
            },
            "rtp": self.stats,
            "network_diagnostics": network_diagnostics,
            "qos": ({"packet_capture_verified": False} if os.name == "nt" else
                    {"rtp_dscp_requested": MEDIA_DSCP, "rtcp_dscp_requested": MEDIA_DSCP,
                     "sip_dscp_requested": SIP_DSCP, "packet_capture_verified": False}),
            "audio": audio,
            "events": self.events,
            "dtmf": {"protocol": self.dtmf_protocol, "status": self.dtmf_status,
                     "discovery_sent": self.dtmf_discovery_sent if self.dtmf_frame else None,
                     "discovery_attempts": self.dtmf_discovery_attempts if self.dtmf_frame else None,
                     "discovery_received": self.dtmf_discovery_received if self.dtmf_frame else None,
                     "discovery_reply_sent": self.dtmf_discovery_reply_sent if not self.dtmf_frame else None,
                     "discovery_reply_attempts": self.dtmf_discovery_reply_attempts if not self.dtmf_frame else None,
                     "discovery_received_count": self.dtmf_discovery_received_count if not self.dtmf_frame else None,
                     "a_to_b_sent": self.dtmf_sent if self.dtmf_frame else None,
                     "a_to_b_received": self.dtmf_received if not self.dtmf_frame else None,
                     "b_to_a_sent": self.dtmf_ack_sent if not self.dtmf_frame else None,
                     "b_to_a_received": self.dtmf_received if self.dtmf_frame else None,
                     "controller_confirmed": self.dtmf_controller_confirmed,
                     "send_method": self.dtmf_method, "receive_method": self.dtmf_received_method,
                     "received_digits": self.dtmf_receiver.digits_seen + self.dtmf_numeric_receiver.digits_seen,
                     "invalid_frames": self.dtmf_receiver.invalid + self.dtmf_numeric_receiver.invalid,
                     "identification_duration_s": round(self.dtmf_completed_at - (self.dtmf_started_at or self.started), 3) if self.dtmf_completed_at and self.started else None,
                     "audio_start_s": (self.audio_phase_offset_s or IDENTIFICATION_SECONDS) if (self.dtmf_frame or self.dtmf_expected) else 0},
        }
        self.agent.journal.record(
            "audio",
            "Mesure audio terminée" if audio else "Mesure audio indisponible",
            level="info" if audio else "warning",
            run_id=self.run_id,
            codec=self.codec,
            sample_rate=(audio or {}).get("sample_rate"),
            interruptions_s=(audio or {}).get("interrupted_s"),
        )
        if self.incoming is not None:
            metrics["incoming"] = self.incoming
            if metrics.get("audio") is not None:
                metrics["audio"]["reference_available"] = False
                metrics["audio"]["scope"] = "local_incoming"
        self.agent.pending_report(self.run_id, metrics)
        if audio is not None and self.recording.exists():
            self.recording.unlink()
        return True


class ProbeAccount(pj.Account):
    def __init__(self, agent, config, rtp_slot=0):
        super().__init__()
        self.rtp_slot = rtp_slot
        self.agent = agent
        self.config = config
        self.registration_code = 0
        self.registration_active = False
        self.registration_text = "Non enregistré"
        self.trusted_sources = set().union(*(trusted_pbx_addresses(config[k]) for k in ("server", "registrar", "proxy") if config.get(k)))
        self.registered_at = None
        self.registration_changed_at = utc()

    def onRegState(self, prm):
        info = self.getInfo()
        active = bool(info.regIsActive) and prm.code == 200
        if self.registration_code != prm.code or self.registration_active != active:
            self.registration_changed_at = utc()
            self.agent.journal.record(
                "registration",
                "État enregistrement SIP modifié",
                level="info" if active else "warning",
                account=self.config["username"],
                code=prm.code,
            )
        self.registration_code = prm.code
        self.registration_text = str(info.regStatusText)
        self.registration_active = active
        if self.registration_active:
            self.registered_at = utc()
            self.trusted_sources = set().union(*(trusted_pbx_addresses(self.config[k]) for k in ("server", "registrar", "proxy") if self.config.get(k)))

    def onIncomingCall(self, prm):
        message = prm.rdata.wholeMsg
        source = str(prm.rdata.srcAddress).rsplit(":",1)[0].strip("[]")
        matched = correlate(self.agent.prepared, self.config["id"], message, source, self.trusted_sources)
        run_id = matched or str(uuid.uuid4())
        prep = self.agent.prepared.get(matched)
        call = ProbeCall(self, run_id, min(prep["duration_s"] if prep else self.config.get("max_duration_s", 300), self.config.get("max_duration_s", 300)), prm.callId)
        call.is_incoming = True
        call.dtmf_receiver.expected_kind = "1"
        call.dtmf_numeric_receiver.expected_kind = "1"
        call.dtmf_expected = any(value.get("account_id") == self.config["id"] and
                                 value.get("dtmf_protocol") in (1, 2) and
                                 value.get("expires", 0) > time.monotonic()
                                 for value in self.agent.prepared.values())
        call.preferred = prep.get("preferred_codec") if prep else None
        call.destination = self.config["username"]
        op = pj.CallOpParam()
        op.statusCode = reception_status(self.config, (self.agent.remote or {}).get("mode", "standby"), source, self.trusted_sources, self.agent.capacity(self))
        if op.statusCode == 180:
            if not matched:
                call.incoming = {"observed_at": utc(), "correlation": "unrecognized", "source": source}
                with self.agent.lock:
                    self.agent.db.execute("INSERT INTO incoming_active VALUES (?,?)", (run_id, json.dumps({"incoming": call.incoming, "account_id": self.config["id"]})))
                    self.agent.db.commit()
            self.agent.calls[run_id] = call
            self.agent.prepared.pop(matched, None)
            self.agent.store_active(run_id)
            call.answer_at = time.monotonic() + 1.0
        else:
            self.agent.rejected.append(call)
        # PJSUA2 2.16 releases incoming_data after this callback. A final
        # response here may release it first inside PJSUA and abort on return.
        call.pending_response = op.statusCode



class Agent:
    def __init__(self, config=None, data_directory=None):
        self.config_lock = threading.RLock()
        self.path = pathlib.Path(
            os.getenv("CONFIG_FILE", "/var/lib/voiceprobe/config.json")
        )
        self.cfg = dict(config) if config is not None else json.loads(self.path.read_text())
        if self.cfg.get("identity_private_key"):
            verify_identity(self.cfg)
        self.connection_generation = 0
        self.journal = EventJournal(
            secrets=tuple(
                str(self.cfg[k])
                for k in ("token", "local_password", "enrollment_secret")
                if self.cfg.get(k)
            )
        )
        self.journal.record("lifecycle", "Agent démarré", version=VERSION)
        self.recent_runs = []
        self.adoption_state = self.cfg.get(
            "adoption_state",
            "adopted" if self.cfg.get("token") and not self.cfg.get("enrollment_secret") else "unconfigured",
        )
        self.controller_version = None
        uuid.UUID(self.cfg["id"])
        self.data = pathlib.Path(data_directory) if data_directory is not None else self.path.parent
        self.data.mkdir(exist_ok=True)
        self.maintenance = Maintenance(self.data)
        self.remote_update = RemoteUpdate(self.data)
        self.tone = self.data / "tone-1000.wav"
        reference(self.tone, seconds=310, rate=16000)
        self.echo_tone = self.data / "echo-reference.wav"
        reference(self.echo_tone, seconds=310, rate=16000, envelope=True)
        self.db = sqlite3.connect(
            self.database_location(), check_same_thread=False
        )
        self.lock = threading.Lock()
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,ok INTEGER,error TEXT,acked INTEGER DEFAULT 0);CREATE TABLE IF NOT EXISTS reports(run_id TEXT PRIMARY KEY,payload TEXT);CREATE TABLE IF NOT EXISTS active(run_id TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS local_runs(run_id TEXT PRIMARY KEY,payload TEXT);CREATE TABLE IF NOT EXISTS incoming_active(run_id TEXT PRIMARY KEY,payload TEXT);"
        )
        self.db.execute("UPDATE commands SET acked=0 WHERE acked=2")
        self.db.commit()
        self.recent_runs = [
            json.loads(r[0])
            for r in self.db.execute(
                "SELECT payload FROM local_runs ORDER BY rowid DESC LIMIT 20"
            ).fetchall()
        ]
        if (self.data / "state.sqlite").exists():
            os.chmod(self.data / "state.sqlite", 0o600)
        for row in self.db.execute("SELECT run_id FROM active").fetchall():
            incoming_row = self.db.execute("SELECT payload FROM incoming_active WHERE run_id=?", (row[0],)).fetchone()
            self.pending_report(
                row[0],
                recovery_report(json.loads(incoming_row[0]) if incoming_row else None),
            )
        self.report_outbox = ReportOutbox(self.db, self.lock)
        self.inbox = queue.Queue()
        self.dtmf_observations = queue.Queue()
        self.dtmf_status_queries = queue.Queue()
        self.accounts = {}
        self.calls = {}
        self.prepared = {}
        self.rejected = []
        self.remote = None
        self.remote_fingerprint = None
        self.running = True
        self.last_controller = None
        self.last_error = None
        self.controller_connected = False
        self.wss_connected = False
        self.poll_now = threading.Event()
        self.endpoint = pj.Endpoint()
        self.endpoint.libCreate()
        c = pj.EpConfig()
        c.uaConfig.threadCnt = 0
        c.uaConfig.mainThreadOnly = True
        c.uaConfig.maxCalls = 128
        c.logConfig.level = 0
        c.logConfig.consoleLevel = 0
        c.medConfig.clockRate = 16000
        c.medConfig.sndClockRate = 16000
        c.medConfig.ecTailLen = 0
        c.medConfig.noVad = True
        self.endpoint.libInit(c)
        for transport in (pj.PJSIP_TRANSPORT_UDP, pj.PJSIP_TRANSPORT_TCP):
            tc = pj.TransportConfig()
            tc.port = int(self.cfg.get("sip_port", 5060))
            set_dscp(tc, pj, SIP_DSCP)
            self.endpoint.transportCreate(transport, tc)
        self.endpoint.libStart()
        self.endpoint.audDevManager().setNullDev()
        self.process_started = time.time()
        self.started_at = utc()
        self.pjsip_version = self.endpoint.libVersion().full
        self.supported_codecs = [x.codecId for x in self.endpoint.codecEnum2()]

    def database_location(self):
        return str(self.data / "state.sqlite")

    def distribution_platform(self):
        if platform.system() != "Linux":
            return None
        info = platform.freedesktop_os_release()
        import sys
        return {("ubuntu", "24.04", (3, 12)): "ubuntu-24.04-amd64-cp312", ("debian", "12", (3, 11)): "debian-12-amd64-cp311"}.get((info.get("ID"), info.get("VERSION_ID"), sys.version_info[:2]))

    def os_description(self):
        if platform.system() == "Linux":
            return platform.freedesktop_os_release().get("PRETTY_NAME", platform.platform())
        return platform.platform()

    def load_average(self):
        try:
            return os.getloadavg()[0]
        except (AttributeError, OSError):
            return None

    def before_iteration(self):
        """Optional platform admission policy, executed on the SIP thread."""

    def request_stop(self):
        self.running = False
        self.poll_now.set()

    def safe_secrets(self):
        local = tuple(
            str(self.cfg[k])
            for k in ("token", "local_password", "enrollment_secret")
            if self.cfg.get(k)
        )
        sip = tuple(
            a["password"]
            for a in (getattr(self, "remote", None) or {}).get("accounts", [])
            if a.get("password")
        )
        return local + sip

    def persist_config(self):
        with self.config_lock:
            if self.path.exists() and json.loads(self.path.read_text()) == self.cfg:
                return
            atomic_json(self.path, self.cfg)

    def update_local(self, values):
        with self.config_lock:
            return self._update_local(dict(values))

    def _update_local(self, values):
        if self.calls:
            raise RuntimeError("Calls active")
        allowed = {
            "controller_url",
            "controller_ca",
            "use_system_ca",
            "name",
            "token",
            "enrollment_secret",
            "administrative",
            "max_calls",
            "management_url",
            "local_password",
        }
        if not set(values).issubset(allowed):
            raise ValueError("Unsupported local setting; UUID is immutable")
        if (
            self.adoption_state == "adopted"
            or self.cfg.get("metadata_authority") == "controller"
        ) and ({"name", "administrative"} & set(values)):
            raise ValueError(
                "Administrative metadata is managed by Controller after adoption"
            )
        if values.pop("use_system_ca", False):
            values["ca_file"] = "/etc/ssl/certs/ca-certificates.crt"
        certificate = values.pop("controller_ca", "")
        if certificate:
            if len(certificate) > 12000 or "PRIVATE KEY" in certificate:
                raise ValueError("Fournir uniquement un certificat CA public PEM.")
            try:
                ssl.create_default_context(cadata=certificate)
            except ssl.SSLError:
                raise ValueError("Certificat CA public invalide.")
        if "controller_url" in values:
            from urllib.parse import urlparse

            u = urlparse(values["controller_url"])
            if (
                u.scheme != "https"
                or not u.hostname
                or u.username
                or u.password
                or u.query
                or u.fragment
            ):
                raise ValueError("HTTPS URL required")
            values["controller_url"] = values["controller_url"].rstrip("/")
            values["wss_url"] = "wss://" + u.netloc + u.path.rstrip("/") + "/ws"
        if "token" in values and not 40 <= len(values["token"]) <= 200:
            raise ValueError("Invalid individual token")
        if (
            "enrollment_secret" in values
            and not 40 <= len(values["enrollment_secret"]) <= 200
        ):
            raise ValueError("Invalid enrollment proof")
        if "local_password" in values:
            values["local_password_hash"] = hash_password(values.pop("local_password"))
        if "max_calls" in values and not 1 <= int(values["max_calls"]) <= 128:
            raise ValueError("Invalid call capacity")
        if "administrative" in values:
            values["administrative"] = {
                k: (None if v == "" else v) for k, v in values["administrative"].items() if k in ADMIN_FIELDS
            }
        for field, limit in (("latitude", 90), ("longitude", 180)):
            coordinate = values.get("administrative", {}).get(field)
            if coordinate is not None and not -limit <= float(coordinate) <= limit:
                raise ValueError("Coordonnées géographiques invalides.")
        reconnect = bool({"controller_url", "ca_file", "token", "enrollment_secret"} & set(values)) or bool(certificate)
        if self.cfg.get("identity_private_key") and values.get("controller_url") and values["controller_url"] != self.cfg.get("controller_url"):
            self.cfg["token"] = ""
            self.cfg["adoption_state"] = "unconfigured"
            self.cfg.pop("metadata_authority", None)
            self.adoption_state = "unconfigured"
        if reconnect:
            self.connection_generation = getattr(self, "connection_generation", 0) + 1
        if certificate:
            directory = self.path.parent / "tls"
            directory.mkdir(mode=0o700, exist_ok=True)
            directory.chmod(0o700)
            target = directory / "controller-ca.crt"
            temporary = directory / ".controller-ca.tmp"
            temporary.write_text(certificate)
            temporary.chmod(0o600)
            temporary.replace(target)
            values["ca_file"] = str(target)
        if "local_password_hash" in values:
            self.cfg.pop("local_password", None)
        self.cfg.update(values)
        self.journal.secrets = self.safe_secrets()
        self.persist_config()
        if reconnect:
            self.controller_connected = False
            self.wss_connected = False
            self.last_error = None
            self.inbox.put(("revoked", None))
            if values.get("enrollment_secret"):
                self.adoption_state = "unconfigured"
            self.journal.record(
                "controller", "Configuration enregistrée; reconnexion demandée"
            )
        self.poll_now.set()

    def snapshot(self):
        system = system_snapshot(self.data)
        network = network_snapshot(self.cfg)
        remote = self.remote or {}
        administrative = remote.get(
            "administrative", self.cfg.get("administrative", {})
        )
        result = {
            "id": self.cfg["id"],
            "name": self.cfg["name"],
            "hostname": socket.gethostname(),
            "version": VERSION,
            "display_version": DISPLAY_VERSION,
            "build_id": BUILD_ID,
            "pjsip_version": self.pjsip_version,
            "identity_fingerprint": self.cfg.get("identity_fingerprint"),
            "connection_state": self.connection_state(),
            "controller_version": self.controller_version,
            "started_at": self.started_at,
            "uptime_s": round(time.time() - self.process_started),
            "installation_type": self.cfg.get("installation_type")
            or (
                "container"
                if pathlib.Path("/.dockerenv").exists()
                else "systemd" if os.getenv("INVOCATION_ID") else "native"
            ),
            "capabilities": {
                "pjsip_version": self.pjsip_version,
                "supported_codecs": self.supported_codecs,
                "audio_profiles": ["tone-1000"],
                "scenario_types": ["probe", "destination", "echo"],
                "correlation_modes": ["header", "window"],
                "automatic_incoming": True,
                "dtmf_identification": {"protocol": 2, "protocols": [1, 2], "methods": ["rtp_telephone_event"], "window_s": 10, "discovery": True},
                "media_quality": {"protocol": 1, "supported_playout_distributions": [1, 2], "receiver_timing": hasattr(pj.Call, "getVoiceProbeStats"), "playout_observer": hasattr(pj.Call, "getVoiceProbeStats"), "interval_s": 2, "pdv_resolution_ms": .25},
                "configuration_ack_protocol": 1,
                "remote_update": self.remote_update.capability() if hasattr(self,"remote_update") else {"protocol":1,"enabled":False},
                "distribution_platform": self.distribution_platform(),
                "destination_policy": "account-public-v1",
                "max_calls": self.applied_capacity(),
                "capacity_protocol": 2,
                "media_clock": 16000,
                "process_call_ceiling": 128,
                "cpu_count": os.cpu_count(),
            },
            "os": self.os_description(),
            "architecture": platform.machine(),
            "local_ip": network.get("primary_address")
            or next(
                (
                    a["address"]
                    for i in network.get("interfaces", [])
                    for a in i.get("addresses", [])
                    if a.get("family") in ("IPv4", "inet")
                    and a["address"] != "127.0.0.1"
                ),
                None,
            ),
            "system": system,
            "network": network | {"public_ip": remote.get("public_ip_observed")},
            "load": self.load_average(),
            "memory": system.get("memory"),
            "temperature_c": system.get("temperature_c"),
            "controller_connected": self.controller_connected,
            "controller_error_category": getattr(self,"controller_error_category",None),
            "controller_http_status": getattr(self,"controller_http_status",None),
            "controller_last_endpoint": getattr(self,"controller_last_endpoint",None),
            "report_delivery": self.report_outbox.snapshot() if hasattr(self,"report_outbox") else None,
            "wss_connected": self.wss_connected,
            "last_controller": self.last_controller,
            "last_error": self.last_error,
            "management_url": self.cfg.get("management_url"),
            "controller_url": self.cfg["controller_url"],
            "adoption_state": self.adoption_state,
            "administrative": administrative,
            "metadata_revision": remote.get("metadata_revision"),
            "metadata_authority": (
                "controller"
                if self.adoption_state == "adopted"
                or self.cfg.get("metadata_authority") == "controller"
                else "local"
            ),
            "max_calls": self.applied_capacity(),
            "local_max_calls": self.cfg["max_calls"],
            "controller_max_calls": remote.get("max_calls"),
            "maintenance": self.maintenance.status(),
            "active_calls": sum(not call.finished for call in self.calls.values()),
            "calls": list(self.calls),
            "call_details": [
                {
                    "run_id": c.run_id,
                    "account_username": c.account.config["username"],
                    "destination": c.destination,
                    "codec": c.codec,
                    "duration_s": round(time.monotonic() - (c.started or c.created), 1),
                    "state": "established" if c.established else "connecting",
                }
                for c in list(self.calls.values()) if not c.finished
            ],
            "accounts": [
                {
                    k: a.config.get(k)
                    for k in (
                        "id",
                        "name",
                        "username",
                        "server",
                        "registrar",
                        "proxy",
                        "transport",
                        "codecs",
                    )
                }
                | {
                    "registration_code": a.registration_code,
                    "registration_active": a.registration_active,
                    "registration_text": a.registration_text,
                    "registered_at": a.registered_at,
                    "registration_changed_at": a.registration_changed_at,
                }
                for a in list(self.accounts.values())
            ],
            "recent_runs": self.recent_runs[:20],
            "events": self.journal.snapshot(limit=200),
        }
        return redact(result, self.safe_secrets())

    def applied_capacity(self):
        remote = self.remote or {}
        if remote.get("capacity_protocol") == 2:
            return int(remote["max_calls"])
        return min(remote.get("max_calls", self.cfg["max_calls"]), self.cfg["max_calls"])

    def capacity_reason(self, account):
        if self.maintenance.refresh():
            return "MAINTENANCE_ACTIVE: Maintenance active."
        central = (self.remote or {}).get("capacity_protocol") == 2
        if not central and (self.load_average() or 0) >= max(1, os.cpu_count() or 1) * self.cfg.get("max_load_per_cpu", 1.5):
            return "CPU_LOAD_EXCEEDED: Charge CPU excessive."
        if sum(not call.finished for call in self.calls.values()) >= self.applied_capacity():
            return "AGENT_CAPACITY_EXHAUSTED: Capacité simultanée de la sonde atteinte."
        if not central and sum(c.account is account and not c.finished for c in self.calls.values()) >= account.config["max_calls"]:
            return "ACCOUNT_CAPACITY_EXHAUSTED: Capacité simultanée du compte SIP atteinte."
        return None

    def capacity(self, account):
        return self.capacity_reason(account) is None

    def pending_report(self, run_id, metrics):
        self.recent_runs.insert(
            0,
            {
                "run_id": run_id,
                "at": utc(),
                "established": metrics["established"],
                "duration_s": metrics["duration_s"],
                "sip": metrics.get("sip"),
                "audio": {
                    k: v
                    for k, v in (metrics.get("audio") or {}).items()
                    if k not in ("timeline", "interruptions")
                },
            },
        )
        del self.recent_runs[20:]
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO local_runs VALUES (?,?)",
                (run_id, json.dumps(self.recent_runs[0])),
            )
            self.db.execute(
                "DELETE FROM local_runs WHERE rowid NOT IN (SELECT rowid FROM local_runs ORDER BY rowid DESC LIMIT 50)"
            )
            self.db.execute(
                "INSERT OR IGNORE INTO reports VALUES (?,?)",
                (run_id, json.dumps(metrics)),
            )
            self.db.execute("DELETE FROM active WHERE run_id=?", (run_id,))
            self.db.execute("DELETE FROM incoming_active WHERE run_id=?", (run_id,))
            self.db.commit()

    def respond_incoming(self):
        """Run SIP responses on the event thread after native callbacks unwind."""
        for call in [*self.calls.values(), *self.rejected]:
            status = call.pending_response
            if status is None:
                continue
            call.pending_response = None
            if call.finished:
                continue
            op = pj.CallOpParam()
            op.statusCode = status
            try:
                call.answer(op)
            except pj.Error:
                call.hangup_safe()

    def store_active(self, run_id):
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO active VALUES (?)", (run_id,))
            self.db.commit()

    def retire_revoked_accounts(self):
        if not getattr(self, "accounts_revoked", False) or self.calls or any(not c.finished for c in self.rejected):
            return
        for account in self.accounts.values():
            account.shutdown()
        self.accounts.clear()
        self.accounts_revoked = False

    def revoke_configuration(self):
        self.accounts_revoked = True
        self.prepared.clear()
        for call in list(self.calls.values()):
            call.hangup_safe()
        self.remote = None
        self.remote_fingerprint = None
        self.retire_revoked_accounts()

    def apply_config(self, config):
        fingerprint = json.dumps(config, sort_keys=True)
        if fingerprint == self.remote_fingerprint:
            self.configuration_applied_revision = config.get("configuration_revision")
            return
        if self.calls:
            return
        if config["id"] != self.cfg["id"]:
            raise ValueError("Controller identity mismatch")
        self.retire_revoked_accounts()
        if config.get("capacity_protocol") == 2:
            if type(config.get("max_calls")) is not int or not 1 <= config["max_calls"] <= 128:
                raise ValueError("Capacité Controller invalide : moteur limité à 128 appels.")
            self.cfg["max_calls"] = config["max_calls"]
        self.remote = config
        self.journal.secrets = self.safe_secrets()
        self.cfg["name"] = config["name"]
        self.cfg["administrative"] = config.get("administrative", {})
        self.cfg["adoption_state"] = "adopted"
        self.cfg["metadata_authority"] = "controller"
        self.adoption_state = "adopted"
        self.controller_version = config.get("controller_version")
        self.persist_config()
        self.journal.record(
            "controller",
            "Configuration centrale appliquée",
            revision=config.get("metadata_revision"),
        )
        protocol_keys = (
            "username",
            "server",
            "registrar",
            "proxy",
            "auth_username",
            "password",
            "transport",
        )
        desired_ids = {x["id"] for x in config["accounts"]}
        for account_id in set(self.accounts) - desired_ids:
            self.accounts.pop(account_id).shutdown()
        used_slots = {a.rtp_slot for a in self.accounts.values()}
        for x in config["accounts"]:
            existing = self.accounts.get(x["id"])
            if existing and all(
                existing.config.get(k) == x.get(k) for k in protocol_keys
            ):
                existing.config = x
                continue
            slot = (
                existing.rtp_slot
                if existing
                else next((i for i in range(32) if i not in used_slots), None)
            )
            if slot is None:
                raise ValueError("Compiled SIP account capacity exceeded")
            used_slots.add(slot)
            ac = pj.AccountConfig()
            ac.idUri = "sip:" + x["username"] + "@" + x["server"]
            ac.regConfig.registrarUri = x["registrar"]
            ac.regConfig.retryIntervalSec = 5
            ac.regConfig.firstRetryIntervalSec = 1
            ac.regConfig.timeoutSec = 60
            ac.sipConfig.authCreds.append(
                pj.AuthCredInfo("digest", "*", x["auth_username"], 0, x["password"])
            )
            if x.get("proxy"):
                ac.sipConfig.proxies.append(x["proxy"])
            route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            route.connect((x["server"].split(":")[0], 5060))
            sip_ip = route.getsockname()[0]
            route.close()
            ac.mediaConfig.transportConfig.boundAddress = sip_ip
            ac.mediaConfig.transportConfig.publicAddress = sip_ip
            ac.mediaConfig.transportConfig.port = int(self.cfg.get("rtp_base_port", 4000)) + slot * 100
            ac.mediaConfig.transportConfig.portRange = 80
            set_dscp(ac.mediaConfig.transportConfig, pj, MEDIA_DSCP)
            ac.sipConfig.transportId = pj.PJSUA_INVALID_ID
            if x["transport"] == "tcp":
                ac.regConfig.registrarUri += "" if ";transport=tcp" in ac.regConfig.registrarUri else ";transport=tcp"
            elif x["transport"] != "udp":
                raise ValueError("Transport unsupported")
            if existing:
                existing.registration_code = 0
                existing.registration_active = False
                existing.modify(ac)
                existing.config = x
                existing.trusted_sources = trusted_pbx_addresses(x["server"])
                self.journal.record(
                    "registration", "Paramètres SIP modifiés", account=x["username"]
                )
            else:
                a = ProbeAccount(self, x, slot)
                a.create(ac)
                self.accounts[x["id"]] = a
        allowed = set(c for x in config["accounts"] for c in x["codecs"])
        for codec in self.endpoint.codecEnum2():
            self.endpoint.codecSetPriority(
                codec.codecId,
                (
                    (
                        240
                        if codec.codecId.startswith("G722/")
                        else 220 if codec.codecId.startswith("PCMA/") else 200
                    )
                    if any(codec.codecId.startswith(c) for c in allowed)
                    else 0
                ),
            )

        self.remote_fingerprint = fingerprint
        self.configuration_applied_revision = config.get("configuration_revision")

    def execute(self, command):
        cid = command["id"]
        payload = command["payload"]
        rid = payload["run_id"]
        with self.lock:
            if self.db.execute("SELECT id FROM commands WHERE id=?", (cid,)).fetchone():
                return
            self.db.execute(
                "INSERT INTO commands(id,ok,error,acked) VALUES (?,0,?,2)",
                (cid, "Interrupted before command completion"),
            )
            self.db.commit()
        ok = True
        error = None
        try:
            if command["kind"] == "cancel":
                if rid in self.calls:
                    self.calls[rid].hangup_safe()
                self.prepared.pop(rid, None)
            else:
                account = self.accounts.get(payload["account_id"])
                if not account:
                    raise ValueError("ACCOUNT_NOT_CONFIGURED: Compte SIP absent de la configuration locale.")
                if account.registration_code != 200 or not account.registration_active:
                    raise ValueError("ACCOUNT_NOT_REGISTERED: Compte SIP non enregistré.")
                if not self.capacity(account):
                    raise ValueError(self.capacity_reason(account) or "AUTHORIZATION_REQUIRED: Autorisation de la sonde absente ou expirée.")
                mode = (self.remote or {}).get("mode", "standby")
                if payload.get("audio_profile") != "tone-1000":
                    raise ValueError("AUDIO_PROFILE_UNSUPPORTED: Profil audio incompatible.")
                duration = payload.get("duration_s")
                if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not 1 <= duration <= min(300, account.config.get("max_duration_s", 300)):
                    raise ValueError("DURATION_INVALID: Durée invalide ou supérieure à la limite du compte SIP.")
                if payload.get("preferred_codec") and payload["preferred_codec"] not in account.config.get("codecs", []):
                    raise ValueError("CODEC_UNSUPPORTED: Codec absent de la configuration du compte SIP.")
                if command["kind"] == "prepare":
                    if mode not in ("receiver", "bidirectional") or account.config.get("call_mode") == "caller":
                        raise ValueError("INCOMING_DISABLED: Réception désactivée sur cette sonde ou ce compte SIP.")
                    self.prepared[rid] = payload | {"expires": time.monotonic() + 45}
                elif command["kind"] == "call":
                    if mode not in ("caller", "bidirectional") or account.config.get("call_mode") == "receiver":
                        raise ValueError("OUTGOING_DISABLED: Appels sortants désactivés sur cette sonde ou ce compte SIP.")
                    if payload.get("server") != account.config["server"]:
                        raise ValueError("SIP_SERVER_MISMATCH: Serveur SIP différent de la configuration locale.")
                    if not outgoing_allowed(account.config, payload):
                        if account.config.get("destination_policy") != "account-public-v1":
                            raise ValueError("LEGACY_DESTINATION_DENIED: Destination refusée par l’ancienne politique de la sonde ; mise à jour nécessaire.")
                        raise ValueError("PUBLIC_CALLS_DISABLED: Destination publique non autorisée par le compte SIP.")
                    if rid in self.calls:
                        raise ValueError("Duplicate execution")
                    call = ProbeCall(account, rid, payload["duration_s"])
                    identification = payload.get("dtmf")
                    if identification is not None:
                        protocol = identification.get("protocol") if isinstance(identification, dict) else None
                        decoder = decode_numeric if protocol == 2 else decode_dtmf if protocol == 1 else None
                        if not decoder or not decoder(identification.get("frame")) or decoder(identification["frame"])[0] != "1":
                            raise ValueError("DTMF_PROTOCOL_INVALID: Trame d'identification invalide.")
                        call.dtmf_protocol = protocol
                        call.dtmf_frame = identification["frame"]
                        call.dtmf_discovery = protocol == 2 or identification.get("discovery") is True
                        call.dtmf_receiver.expected_kind = "2"
                        call.dtmf_numeric_receiver.expected_kind = "2"
                        call.dtmf_status = "waiting_media"
                    call.preferred = payload.get("preferred_codec")
                    call.scenario_type = payload.get("scenario_type", "probe")
                    if call.scenario_type not in ("probe", "destination", "echo"):
                        raise ValueError("Unsupported scenario type")
                    call.destination = payload["destination"]
                    self.journal.record(
                        "call",
                        "Appel demandé",
                        run_id=rid,
                        account=account.config["username"],
                        destination=call.destination,
                    )
                    self.calls[rid] = call
                    self.store_active(rid)
                    op = pj.CallOpParam(True)
                    op.opt.audioCount = 1
                    op.opt.videoCount = 0
                    header = pj.SipHeader()
                    header.hName = "X-VoiceProbe-Test"
                    header.hValue = rid
                    op.txOption.headers.append(header)
                    dest = payload["destination"] if payload["destination"].startswith("sip:") else "sip:" + payload["destination"] + "@" + account.config["server"]
                    if not re.fullmatch(r"sip:[A-Za-z0-9_.!~*'()%+\-#]+@[A-Za-z0-9.\-]+(?::[0-9]{1,5})?", dest):
                        raise ValueError("Invalid SIP destination")
                    if account.config["transport"] == "tcp":
                        dest += ";transport=tcp"
                    call.makeCall(dest, op)
                else:
                    raise ValueError("Unknown command")
        except (ValueError, pj.Error) as rejected:
            ok = False
            error = str(rejected)[:200] if isinstance(rejected, ValueError) else "PJSIP_ERROR: Erreur du moteur SIP : code " + str(getattr(rejected, "status", "inconnu"))
            self.last_error = error
            self.journal.record("call", error, level="error", run_id=rid)
        with self.lock:
            self.db.execute(
                "UPDATE commands SET ok=?,error=?,acked=0 WHERE id=?", (int(ok), error, cid)
            )
            self.db.commit()

    def api(self, method, path, **kwargs):
        self.controller_last_endpoint = method + " /api/agent/" + path
        return requests.request(
            method,
            self.cfg["controller_url"] + "/api/agent/" + path,
            headers={
                "Authorization": "Bearer " + self.cfg["token"],
                "Accept": "application/json",
            },
            verify=self.cfg["ca_file"],
            timeout=5,
            **kwargs
        )

    def connection_state(self):
        if not self.cfg.get("controller_url"):
            return "unconfigured"
        if self.adoption_state in ("rejected", "revoked"):
            return self.adoption_state
        if self.controller_connected and self.adoption_state == "adopted":
            return "connected"
        if self.adoption_state == "pending" and self.controller_connected:
            return "pending"
        return "error" if self.last_error else "connecting"

    def identity_enrollment(self):
        with self.config_lock:
            cfg = json.loads(json.dumps(self.cfg))
            generation = self.connection_generation
        network = network_snapshot(cfg)
        addresses = [a["address"] for i in network.get("interfaces", []) for a in i.get("addresses", []) if a.get("address") and a.get("scope") != "host"][:16]
        result = exchange(cfg, {"action": "present", "name": cfg["name"], "administrative": cfg.get("administrative", {}), "management_url": cfg.get("management_url") or None, "telemetry": {"version": VERSION, "build_id": BUILD_ID, "pjsip_version": self.pjsip_version, "hostname": socket.gethostname(), "os": self.os_description(), "architecture": platform.machine(), "local_ip": network.get("primary_address"), "local_addresses": addresses, "installation_type": cfg.get("installation_type", "native")}})
        state = result["state"]
        with self.config_lock:
            if generation != self.connection_generation:
                return False
            if state != self.adoption_state:
                self.journal.record("adoption", "État admission modifié", state=state)
            if result.get("token"):
                if state != "adopted" or not 40 <= len(result["token"]) <= 200:
                    raise ValueError("Authentification définitive invalide")
                self.cfg["token"] = result["token"]
                self.cfg["credential_ack_pending"] = True
            self.adoption_state = state
            self.cfg["adoption_state"] = state
            if state == "adopted":
                self.cfg["metadata_authority"] = "controller"
            self.journal.secrets = self.safe_secrets()
            self.persist_config()
            current = json.loads(json.dumps(self.cfg))
        if state == "adopted" and current.get("credential_ack_pending"):
            import hashlib
            exchange(current, {"action": "ack", "token_hash": hashlib.sha256(current["token"].encode()).hexdigest()})
            with self.config_lock:
                if generation == self.connection_generation:
                    self.cfg.pop("credential_ack_pending", None)
                    self.persist_config()
        return state == "adopted" and bool(current.get("token"))

    def enrollment(self):
        if self.cfg.get("identity_private_key"):
            return self.identity_enrollment()
        url = self.cfg["controller_url"] + "/api/enrollment/"
        headers = {
            "Authorization": "Bearer " + self.cfg["token"],
            "Accept": "application/json",
        }
        r = requests.get(
            url + "status", headers=headers, verify=self.cfg["ca_file"], timeout=5
        )
        if r.status_code == 401 and self.cfg.get("enrollment_secret"):
            r = requests.post(
                url + "present",
                json={
                    "id": self.cfg["id"],
                    "token": self.cfg["token"],
                    "proof": self.cfg["enrollment_secret"],
                    "name": self.cfg["name"],
                    "administrative": self.cfg.get("administrative", {}),
                    "telemetry": {
                        "version": VERSION,
                        "hostname": socket.gethostname(),
                        "os": self.os_description(),
                        "architecture": platform.machine(),
                        "installation_type": (
                            "container"
                            if pathlib.Path("/.dockerenv").exists()
                            else "native"
                        ),
                    },
                },
                verify=self.cfg["ca_file"],
                timeout=5,
            )
        r.raise_for_status()
        state = r.json()["state"]
        if state != self.adoption_state:
            self.journal.record("adoption", "État admission modifié", state=state)
        self.adoption_state = state
        self.cfg["adoption_state"] = state
        if state == "adopted":
            self.cfg.pop("enrollment_secret", None)
        self.persist_config()
        return state == "adopted"

    def communication(self):
        cycle = 0
        while self.running:
            if not self.cfg.get("controller_url"):
                self.controller_connected = False
                self.last_error = None
                self.poll_now.wait(2)
                self.poll_now.clear()
                continue
            generation = self.connection_generation
            try:
                if self.adoption_state != "adopted" or self.cfg.get("enrollment_secret") or not self.cfg.get("token") or self.cfg.get("credential_ack_pending"):
                    if not self.enrollment():
                        self.controller_connected = True
                        self.last_controller = utc()
                        self.last_error = None
                        self.controller_error_category = None
                        self.controller_http_status = None
                        self.poll_now.wait(6)
                        self.poll_now.clear()
                        continue
                for _ in range(min(self.dtmf_observations.qsize(), 16)):
                    observation = self.dtmf_observations.get_nowait()
                    if time.monotonic() > observation["deadline"]:
                        self.inbox.put(("dtmf_result", (observation["local_call_id"], {"accepted": False, "error": "timeout"})))
                        continue
                    try:
                        response = self.api("POST", "dtmf/observe", json={key: observation[key] for key in ("local_call_id", "account_id", "frame", "method")})
                        if response.status_code in (408, 429) or response.status_code >= 500:
                            self.dtmf_observations.put(observation)
                            continue
                        if response.status_code >= 400:
                            result = {"accepted": False, "error": "http_" + str(response.status_code)}
                        else:
                            result = response.json()
                        self.inbox.put(("dtmf_result", (observation["local_call_id"], result)))
                    except (requests.RequestException, ValueError):
                        self.dtmf_observations.put(observation)
                for _ in range(min(self.dtmf_status_queries.qsize(), 16)):
                    query = self.dtmf_status_queries.get_nowait()
                    if time.monotonic() > query["deadline"]:
                        continue
                    try:
                        response = self.api("GET", "dtmf/status/" + query["local_call_id"])
                        if response.ok and response.json().get("confirmed") is True:
                            self.inbox.put(("dtmf_status", query["local_call_id"]))
                        elif response.ok or response.status_code in (408, 429) or response.status_code >= 500:
                            self.dtmf_status_queries.put(query)
                    except (requests.RequestException, ValueError):
                        self.dtmf_status_queries.put(query)
                if cycle % 5 == 0:
                    response = self.api("GET", "config")
                    response.raise_for_status()
                    self.inbox.put(("config", (generation, response.json())))
                r = self.api("POST", "heartbeat", json={"telemetry": self.snapshot()})
                r.raise_for_status()
                if not self.controller_connected:
                    self.journal.record("controller", "Connexion HTTPS rétablie")
                self.controller_connected = True
                self.last_controller = utc()
                self.last_error = None
                self.controller_error_category = None
                self.controller_http_status = None
                with self.lock:
                    acks = self.db.execute(
                        "SELECT id,ok,error FROM commands WHERE acked=0"
                    ).fetchall()
                    reports = self.db.execute(
                        "SELECT run_id,payload FROM reports"
                    ).fetchall()
                for cid, ok, error in acks:
                    r = self.api(
                        "POST",
                        "commands/" + cid + "/ack",
                        json={"ok": bool(ok), "error": error},
                    )
                    r.raise_for_status()
                    with self.lock:
                        self.db.execute(
                            "UPDATE commands SET acked=1 WHERE id=?", (cid,)
                        )
                        self.db.commit()
                if (self.remote or {}).get("maintenance_protocol") == 1 and self.remote_update.capability()["enabled"]:
                    maintenance = self.api("GET", "maintenance")
                    maintenance.raise_for_status()
                    action = maintenance.json().get("action")
                    if action:
                        try:
                            self.remote_update.request(action)
                        except (ValueError, OSError):
                            if isinstance(action, dict) and isinstance(action.get("id"), str) and re.fullmatch(r"[a-f0-9-]{36}", action["id"]):
                                failure = self.api("POST", "maintenance/" + action["id"], json={"id": action["id"], "state": "failed", "target_version": action.get("target_version"), "error_code": "LOCAL_HANDOFF_REJECTED", "stage": "Relais local indisponible ou requête refusée."})
                                failure.raise_for_status()
                    result = self.remote_update.result()
                    if result:
                        acknowledgement = self.api("POST", "maintenance/" + result["id"], json=result)
                        acknowledgement.raise_for_status()
                revision = getattr(self, "configuration_applied_revision", None)
                if revision and revision != getattr(self, "configuration_ack_sent", None):
                    response = self.api("POST", "configuration/ack", json={"revision": revision})
                    if response.status_code == 409:
                        fresh = self.api("GET", "config")
                        fresh.raise_for_status()
                        self.inbox.put(("config", (generation, fresh.json())))
                    else:
                        response.raise_for_status()
                        self.configuration_ack_sent = revision
                if not self.maintenance.refresh():
                    r = self.api("GET", "commands")
                    r.raise_for_status()
                    batch = r.json()
                    if batch.get("configuration_required"):
                        fresh = self.api("GET", "config")
                        fresh.raise_for_status()
                        self.inbox.put(("config", (generation, fresh.json())))
                    for c in batch["commands"]:
                        self.inbox.put(("command", (generation, c)))
                for rid, payload in reports:
                    self.report_outbox.deliver(rid, payload, self.api)
            except (requests.RequestException, ValueError, KeyError, OSError) as e:
                if self.controller_connected:
                    self.journal.record(
                        "controller", "Connexion HTTPS interrompue", level="warning"
                    )
                self.controller_connected = False
                response = getattr(e, "response", None)
                self.controller_http_status = response.status_code if response is not None else None
                self.controller_error_category = (
                    "http" if response is not None else
                    "tls" if isinstance(e,requests.exceptions.SSLError) else
                    "timeout" if isinstance(e,requests.exceptions.Timeout) else
                    "network_dns" if isinstance(e,requests.exceptions.ConnectionError) else
                    "enrollment_format_identity"
                )
                labels = {"tls":"certificat TLS refusé","timeout":"délai dépassé",
                          "network_dns":"réseau ou DNS indisponible",
                          "enrollment_format_identity":"réponse d’enrôlement/identité non conforme"}
                self.last_error = "Controller : " + (
                    "requête refusée (HTTP " + str(self.controller_http_status) + ")"
                    if self.controller_error_category == "http" else labels[self.controller_error_category]
                )
                if (
                    getattr(e, "response", None) is not None
                    and e.response.status_code == 401
                ):
                    self.inbox.put(("revoked", None))
                    try:
                        self.enrollment()
                    except (requests.RequestException, ValueError, KeyError, OSError):
                        pass
            cycle += 1
            self.poll_now.wait(2)
            self.poll_now.clear()

    def websocket_connector(self):
        from websockets.legacy.client import connect
        return connect

    async def wss(self):
        while self.running:
            if self.adoption_state != "adopted" or not self.cfg.get("controller_url") or not self.cfg.get("token"):
                await asyncio.sleep(5)
                continue
            try:
                connection_identity = (
                    self.cfg["wss_url"],
                    self.cfg["token"],
                    self.cfg["ca_file"],
                )
                ctx = ssl.create_default_context(cafile=self.cfg["ca_file"])
                async with self.websocket_connector()(
                    self.cfg["wss_url"],
                    extra_headers={"Authorization": "Bearer " + self.cfg["token"]},
                    ssl=ctx,
                    ping_interval=15,
                    ping_timeout=15,
                ) as ws:
                    self.wss_connected = True
                    self.journal.record("controller", "Connexion WSS établie")
                    async for message in ws:
                        if connection_identity != (
                            self.cfg["wss_url"],
                            self.cfg["token"],
                            self.cfg["ca_file"],
                        ):
                            break
                        if json.loads(message).get("type") == "poll":
                            self.poll_now.set()
            except Exception:
                if self.wss_connected:
                    self.journal.record(
                        "controller", "Connexion WSS interrompue", level="warning"
                    )
                self.wss_connected = False
                await asyncio.sleep(5)

    def management_export(self):
        while self.running:
            barrier = getattr(self, "management_barrier", None)
            if barrier:
                try:
                    status = self.snapshot()
                    status.update(barrier)
                    atomic_json(self.data / '.management-status.json', status)
                except (OSError, ValueError):
                    pass
            time.sleep(1)

    def apply_dtmf_result(self, local_call_id, result):
        call = self.calls.get(local_call_id)
        if not call or call.finished:
            return
        if not result.get("accepted"):
            call.dtmf_status = result.get("error", "validation_failed")
            return
        if call.is_incoming:
            reply = result.get("reply_frame")
            decoder = decode_numeric if call.dtmf_protocol == 2 else decode_dtmf
            if reply and decoder(reply) and decoder(reply)[0] == "2" and not call.dtmf_ack_sent:
                call.dtmf_ack_sent = call.send_dtmf(reply)
                call.dtmf_status = "ack_sent" if call.dtmf_ack_sent else call.dtmf_status
                if call.dtmf_ack_sent:
                    call.dtmf_completed_at = time.monotonic()
                    self.dtmf_status_queries.put({"local_call_id": local_call_id, "deadline": (call.dtmf_started_at or call.started) + IDENTIFICATION_SECONDS})
                    self.poll_now.set()
        else:
            call.dtmf_controller_confirmed = result.get("confirmed") is True
            call.dtmf_status = "confirmed" if call.dtmf_controller_confirmed else "validation_failed"
            if call.dtmf_controller_confirmed:
                call.dtmf_completed_at = time.monotonic()

    def apply_dtmf_status(self, local_call_id):
        call = self.calls.get(local_call_id)
        if call and call.is_incoming and not call.finished:
            call.dtmf_controller_confirmed = True
            call.dtmf_status = "confirmed"
            call.dtmf_completed_at = time.monotonic()

    def run(self, *, enable_web=True, install_signals=True, export_management=True):
        # Portable mode never constructs the administrative HTTP server.
        web_server = build_server(self) if enable_web else None
        threads = [threading.Thread(target=self.communication, daemon=True)]
        wss_ready = threading.Event()
        wss_state = {}

        def run_wss():
            async def execute_wss():
                wss_state["loop"] = asyncio.get_running_loop()
                wss_state["task"] = asyncio.current_task()
                wss_ready.set()
                try:
                    await self.wss()
                except asyncio.CancelledError:
                    pass
            asyncio.run(execute_wss())

        threads.append(threading.Thread(target=run_wss, daemon=True))
        if web_server:
            threads.append(threading.Thread(target=web_server.serve_forever, daemon=True))
        if export_management:
            threads.append(threading.Thread(target=self.management_export, daemon=True))
        for thread in threads:
            thread.start()
        if install_signals:
            signal.signal(signal.SIGTERM, lambda *args: self.request_stop())
            signal.signal(signal.SIGINT, lambda *args: self.request_stop())
        try:
            last_sample = 0
            last_management = 0
            while self.running:
                self.before_iteration()
                if not self.running:
                    break
                self.maintenance.refresh()
                self.endpoint.libHandleEvents(10)
                try:
                    kind, value = self.inbox.get_nowait()
                    if kind == "config":
                        if value[0] == self.connection_generation:
                            self.apply_config(value[1])
                    elif kind == "revoked":
                        self.revoke_configuration()
                    elif kind == "command" and value[0] == self.connection_generation:
                        self.execute(value[1])
                    elif kind == "dtmf_result":
                        self.apply_dtmf_result(*value)
                    elif kind == "dtmf_status":
                        self.apply_dtmf_status(value)
                except queue.Empty:
                    pass
                except (pj.Error, ValueError):
                    self.last_error = "SIP configuration could not be applied"
                    self.remote_fingerprint = None
                now = time.monotonic()
                self.respond_incoming()
                for rid, call in list(self.calls.items()):
                    call.identification_tick()
                    if call.answer_at is not None and now >= call.answer_at and not call.finished:
                        call.answer_at = None
                        op = pj.CallOpParam()
                        op.statusCode = 200
                        if self.running and self.remote is not None:
                            call.answer(op)
                        else:
                            call.hangup_safe()
                    if now - last_sample > 0.1:
                        call.sample()
                    call.diagnostics_tick()
                    if (
                        call.started and now - call.started >= call.duration
                    ) or now - call.created > call.duration + 30:
                        call.hangup_safe()
                    if call.finished and call.report():
                        del self.calls[rid]
                call = None
                self.rejected = [c for c in self.rejected if not c.finished]
                self.retire_revoked_accounts()
                self.prepared = {
                    k: v for k, v in self.prepared.items() if v["expires"] > now
                }
                if now - last_sample > 0.1:
                    last_sample = now
                if now - last_management > .2:
                    # Only this SIP event loop acknowledges the maintenance barrier.
                    # Expensive system/network measurements and disk I/O stay off it.
                    self.management_barrier = {"pid": os.getpid(), "sampled_at": time.time(),
                        "prepared_calls": len(self.prepared), "active_calls": sum(not c.finished for c in self.calls.values()),
                        "maintenance": self.maintenance.status()}
                    last_management = now
        finally:
            self.request_stop()
            if wss_ready.wait(1):
                try:
                    wss_state["loop"].call_soon_threadsafe(wss_state["task"].cancel)
                except RuntimeError:
                    pass
            for call in self.calls.values():
                call.hangup_safe()
            for _ in range(20):
                self.endpoint.libHandleEvents(10)
            for a in self.accounts.values():
                a.shutdown()
            self.calls.clear()
            self.accounts.clear()
            self.rejected.clear()
            call = None
            a = None
            gc.collect()
            if web_server:
                web_server.shutdown()
                web_server.server_close()
            # Enrollment may have two bounded ten-second requests in flight.
            deadline = time.monotonic() + 25
            for thread in threads:
                thread.join(max(0, deadline - time.monotonic()))
            self.endpoint.libDestroy()
            if all(not thread.is_alive() for thread in threads):
                self.db.close()


if __name__ == "__main__":
    Agent().run()
