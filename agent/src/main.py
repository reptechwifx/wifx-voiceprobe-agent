"""PJSUA2 real SIP/RTP probe. SIP callbacks stay on one event loop thread."""

import asyncio, gc, json, os, pathlib, platform, queue, re, signal, socket, sqlite3, ssl, threading, time, uuid
import requests, websockets, pjsua2 as pj
from audio import reference, analyze, analyze_echo, observe_audio
from incoming import correlate, trusted_pbx_addresses
from sdp import constrain_audio
from localweb import build_server
from version import VERSION, DISPLAY_VERSION, BUILD_ID
from identity import exchange, verify_identity, atomic_json
from maintenance import Maintenance
from credentials import hash_password
from journal import EventJournal, redact
from telemetry import system_snapshot, network_snapshot

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
        self.destination = None
        self.started = None
        self.finished = False
        self.established = False
        self.player = None
        self.recorder = None
        self.media = None
        self.stats = {}
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

    def onCallState(self, prm):
        info = self.getInfo()
        self.call_id = info.callIdString
        self.last_code = info.lastStatusCode
        if info.state == pj.PJSIP_INV_STATE_CONFIRMED:
            self.started = self.started or time.monotonic()
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
            if self.player is not None:
                return
            self.media = self.getAudioMedia(-1)
            self.player = pj.AudioMediaPlayer()
            self.player.createPlayer(str(self.agent.echo_tone if self.scenario_type == "echo" else self.agent.tone))
            self.recorder = pj.AudioMediaRecorder()
            self.recorder.createRecorder(str(self.recording))
            self.player.startTransmit(self.media)
            self.media.startTransmit(self.recorder)
        except pj.Error:
            self.events.append({"kind": "media_not_ready", "at": utc()})

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

    def hangup_safe(self):
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
        audio = None
        try:
            if self.recording.exists():
                audio = (analyze_echo(self.recording, self.agent.echo_tone) if self.scenario_type == "echo" else observe_audio(self.recording) if self.scenario_type == "destination" else analyze(self.recording))
        except Exception as error:
            self.events.append(
                {
                    "kind": "recording_analysis_failed",
                    "at": utc(),
                    "error": type(error).__name__ + ": " + str(error)[:160],
                }
            )
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
            "audio": audio,
            "events": self.events,
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
        self.trusted_sources = trusted_pbx_addresses(config["server"])
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

    def onIncomingCall(self, prm):
        message = prm.rdata.wholeMsg
        source = str(prm.rdata.srcAddress).rsplit(":",1)[0].strip("[]")
        run_id = correlate(self.agent.prepared, self.config["id"], message, source, self.trusted_sources) or ""
        prep = self.agent.prepared.get(run_id)
        call = ProbeCall(self, run_id, prep["duration_s"] if prep else 1, prm.callId)
        call.preferred = prep.get("preferred_codec") if prep else None
        call.destination = self.config["username"]
        authorized = bool(prep)
        op = pj.CallOpParam()
        op.statusCode = 200 if authorized and self.agent.capacity(self) else 403
        if op.statusCode == 200:
            self.agent.calls[run_id] = call
            self.agent.prepared.pop(run_id, None)
            self.agent.store_active(run_id)
        else:
            self.agent.rejected.append(call)
        call.answer(op)


class Agent:
    def __init__(self):
        self.config_lock = threading.RLock()
        self.path = pathlib.Path(
            os.getenv("CONFIG_FILE", "/var/lib/voiceprobe/config.json")
        )
        self.cfg = json.loads(self.path.read_text())
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
        self.data = self.path.parent
        self.data.mkdir(exist_ok=True)
        self.maintenance = Maintenance(self.data)
        self.tone = self.data / "tone-1000.wav"
        reference(self.tone, seconds=310, rate=16000)
        self.echo_tone = self.data / "echo-reference.wav"
        reference(self.echo_tone, seconds=310, rate=16000, envelope=True)
        self.db = sqlite3.connect(
            str(self.data / "state.sqlite"), check_same_thread=False
        )
        self.lock = threading.Lock()
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,ok INTEGER,error TEXT,acked INTEGER DEFAULT 0);CREATE TABLE IF NOT EXISTS reports(run_id TEXT PRIMARY KEY,payload TEXT);CREATE TABLE IF NOT EXISTS active(run_id TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS local_runs(run_id TEXT PRIMARY KEY,payload TEXT);"
        )
        self.db.commit()
        self.recent_runs = [
            json.loads(r[0])
            for r in self.db.execute(
                "SELECT payload FROM local_runs ORDER BY rowid DESC LIMIT 20"
            ).fetchall()
        ]
        os.chmod(self.data / "state.sqlite", 0o600)
        for row in self.db.execute("SELECT run_id FROM active").fetchall():
            self.pending_report(
                row[0],
                {
                    "established": False,
                    "duration_s": 0,
                    "sip": {"reason": "Agent restarted during execution"},
                    "rtp": {},
                    "audio": None,
                    "events": [{"kind": "process_restart", "at": utc()}],
                },
            )
        self.inbox = queue.Queue()
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
            self.endpoint.transportCreate(transport, tc)
        self.endpoint.libStart()
        self.endpoint.audDevManager().setNullDev()
        self.process_started = time.time()
        self.started_at = utc()
        self.pjsip_version = self.endpoint.libVersion().full
        self.supported_codecs = [x.codecId for x in self.endpoint.codecEnum2()]

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
                "max_calls": self.cfg["max_calls"],
                "media_clock": 16000,
                "process_call_ceiling": 128,
                "cpu_count": os.cpu_count(),
            },
            "os": platform.freedesktop_os_release().get("PRETTY_NAME", platform.platform()),
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
            "load": os.getloadavg()[0],
            "memory": system.get("memory"),
            "temperature_c": system.get("temperature_c"),
            "controller_connected": self.controller_connected,
            "controller_error_category": getattr(self,"controller_error_category",None),
            "controller_http_status": getattr(self,"controller_http_status",None),
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
            "max_calls": min(remote.get("max_calls", self.cfg["max_calls"]), self.cfg["max_calls"]),
            "local_max_calls": self.cfg["max_calls"],
            "controller_max_calls": remote.get("max_calls"),
            "maintenance": self.maintenance.status(),
            "active_calls": len(self.calls),
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
                for c in list(self.calls.values())
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

    def capacity(self, account):
        return (
            not self.maintenance.refresh()
            and os.getloadavg()[0]
            < max(1, os.cpu_count() or 1) * self.cfg.get("max_load_per_cpu", 1.5)
            and len(self.calls)
            < min((self.remote or {}).get("max_calls", self.cfg["max_calls"]), self.cfg["max_calls"])
            and sum(c.account is account for c in self.calls.values())
            < account.config["max_calls"]
        )

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
            self.db.commit()

    def store_active(self, run_id):
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO active VALUES (?)", (run_id,))
            self.db.commit()

    def apply_config(self, config):
        fingerprint = json.dumps(config, sort_keys=True)
        if fingerprint == self.remote_fingerprint or self.calls:
            return
        if config["id"] != self.cfg["id"]:
            raise ValueError("Controller identity mismatch")
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

    def execute(self, command):
        cid = command["id"]
        payload = command["payload"]
        rid = payload["run_id"]
        with self.lock:
            if self.db.execute("SELECT id FROM commands WHERE id=?", (cid,)).fetchone():
                return
            self.db.execute(
                "INSERT INTO commands(id,ok,error) VALUES (?,0,?)",
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
                if not account or account.registration_code != 200 or not account.registration_active:
                    raise ValueError("SIP account not registered")
                if not self.capacity(account):
                    raise ValueError("Capacity exhausted")
                mode = (self.remote or {}).get("mode", "standby")
                if (
                    payload.get("audio_profile") != "tone-1000"
                    or not 1 <= payload["duration_s"] <= min(300, account.config.get("max_duration_s",300))
                ):
                    raise ValueError("Unsupported profile or duration")
                if command["kind"] == "prepare":
                    if mode not in ("receiver", "bidirectional"):
                        raise ValueError("Receiver mode disabled")
                    self.prepared[rid] = payload | {"expires": time.monotonic() + 45}
                elif command["kind"] == "call":
                    if mode not in ("caller", "bidirectional"):
                        raise ValueError("Caller mode disabled")
                    if (
                        payload["destination"]
                        not in account.config["allowed_destinations"]
                        or payload["server"] != account.config["server"]
                    ):
                        raise ValueError("Destination prohibited")
                    if rid in self.calls:
                        raise ValueError("Duplicate execution")
                    call = ProbeCall(account, rid, payload["duration_s"])
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
        except (ValueError, pj.Error):
            ok = False
            error = "Command rejected: configuration, registration, or capacity"
            self.last_error = error
            self.journal.record("call", error, level="error", run_id=rid)
        with self.lock:
            self.db.execute(
                "UPDATE commands SET ok=?,error=? WHERE id=?", (int(ok), error, cid)
            )
            self.db.commit()

    def api(self, method, path, **kwargs):
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
        result = exchange(cfg, {"action": "present", "name": cfg["name"], "administrative": cfg.get("administrative", {}), "management_url": cfg.get("management_url") or None, "telemetry": {"version": VERSION, "build_id": BUILD_ID, "pjsip_version": self.pjsip_version, "hostname": socket.gethostname(), "os": platform.freedesktop_os_release().get("PRETTY_NAME", platform.platform()), "architecture": platform.machine(), "local_ip": network.get("primary_address"), "local_addresses": addresses, "installation_type": cfg.get("installation_type", "native")}})
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
                        "os": platform.freedesktop_os_release().get("PRETTY_NAME", platform.platform()),
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
                if not self.maintenance.refresh():
                    r = self.api("GET", "commands")
                    r.raise_for_status()
                    for c in r.json()["commands"]:
                        self.inbox.put(("command", (generation, c)))
                for rid, payload in reports:
                    r = self.api(
                        "POST", "runs/" + rid + "/report", json=json.loads(payload)
                    )
                    r.raise_for_status()
                    with self.lock:
                        self.db.execute("DELETE FROM reports WHERE run_id=?", (rid,))
                        self.db.commit()
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

    async def wss(self):
        from websockets.legacy.client import connect
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
                async with connect(
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

    def run(self):
        web_server = build_server(self)
        threading.Thread(target=self.communication, daemon=True).start()
        threading.Thread(target=lambda: asyncio.run(self.wss()), daemon=True).start()
        threading.Thread(target=web_server.serve_forever, daemon=True).start()
        threading.Thread(target=self.management_export, daemon=True).start()
        signal.signal(signal.SIGTERM, lambda *args: setattr(self, "running", False))
        signal.signal(signal.SIGINT, lambda *args: setattr(self, "running", False))
        last_sample = 0
        last_management = 0
        while self.running:
            self.maintenance.refresh()
            self.endpoint.libHandleEvents(10)
            try:
                kind, value = self.inbox.get_nowait()
                if kind == "config":
                    if value[0] == self.connection_generation:
                        self.apply_config(value[1])
                elif kind == "revoked":
                    for call in self.calls.values():
                        call.hangup_safe()
                    for a in self.accounts.values():
                        a.shutdown()
                    self.accounts.clear()
                    self.prepared.clear()
                    self.remote = None
                    self.remote_fingerprint = None
                elif kind == "command" and value[0] == self.connection_generation:
                    self.execute(value[1])
            except queue.Empty:
                pass
            except (pj.Error, ValueError):
                self.last_error = "SIP configuration could not be applied"
                self.remote_fingerprint = None
            now = time.monotonic()
            for rid, call in list(self.calls.items()):
                if now - last_sample > 0.1:
                    call.sample()
                if (
                    call.started and now - call.started >= call.duration
                ) or now - call.created > call.duration + 30:
                    call.hangup_safe()
                if call.finished and call.report():
                    del self.calls[rid]
            call = None
            self.rejected = [c for c in self.rejected if not c.finished]
            self.prepared = {
                k: v for k, v in self.prepared.items() if v["expires"] > now
            }
            if now - last_sample > 0.1:
                last_sample = now
            if now - last_management > .2:
                # Only this SIP event loop acknowledges the maintenance barrier.
                # Expensive system/network measurements and disk I/O stay off it.
                self.management_barrier = {"pid": os.getpid(), "sampled_at": time.time(),
                    "prepared_calls": len(self.prepared), "active_calls": len(self.calls),
                    "maintenance": self.maintenance.status()}
                last_management = now
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
        web_server.shutdown()
        web_server.server_close()
        self.endpoint.libDestroy()


if __name__ == "__main__":
    Agent().run()
