"""Deterministic reference and phase-independent decoded PCM measurements."""

import wave
import numpy as np


def reference(path, seconds=1, rate=8000, envelope=False):
    t = np.arange(int(rate * seconds)) / rate
    amplitude = np.ones(len(t))
    if envelope:
        # Known 20 ms amplitude markers distinguish echo delay from tone phase.
        markers = np.random.default_rng(904).choice([0.8, 1.2], int(seconds / .02) + 1)
        amplitude = markers[np.minimum((t / .02).astype(int), len(markers) - 1)]
    pcm = (np.sin(2 * np.pi * 1000 * t) * 8192 * amplitude).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setparams((1, 2, rate, 0, "NONE", "not compressed"))
        w.writeframes(pcm.tobytes())


def analyze(path, start_s=0):
    with wave.open(str(path), "rb") as w:
        rate = w.getframerate()
        x = (
            np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(float)
            / 32768
        )
    # Ignore media startup and hangup transients, independent of reference phase.
    trim = int(rate * 0.25)
    offset_start = max(0.0, float(start_s)) + 0.25
    first_sample = int(rate * offset_start)
    x = x[first_sample:-trim] if len(x) > first_sample + trim else np.array([])
    n = int(rate * 0.02)
    frames = []
    gaps = []
    start = None
    for i in range(0, len(x) - n + 1, n):
        v = x[i : i + n]
        t = np.arange(n) / rate
        sine = np.sin(2 * np.pi * 1000 * t)
        cosine = np.cos(2 * np.pi * 1000 * t)
        fit = 2 * np.mean(v * sine) * sine + 2 * np.mean(v * cosine) * cosine
        rms = float(np.sqrt(np.mean(v * v)))
        residual = float(np.sqrt(np.mean((v - fit) ** 2)))
        ratio = float(np.mean(fit * fit) / (np.mean(v * v) + 1e-15))
        missing = rms < 0.005 or ratio < 0.5
        offset = round(offset_start + i / rate, 3)
        frames.append(
            {
                "offset_s": offset,
                "rms_dbfs": round(20 * np.log10(max(rms, 1e-8)), 2),
                "tone_ratio": round(ratio, 4),
                "missing": missing,
                "level_anomaly": bool(
                    not missing and abs(20 * np.log10(max(rms, 1e-8)) + 15) > 6
                ),
            }
        )
        if missing and start is None:
            start = offset
        if not missing and start is not None:
            gaps.append({"start_s": start, "duration_s": round(offset - start, 3)})
            start = None
    if start is not None:
        gaps.append(
            {"start_s": start, "duration_s": round(offset_start + len(x) / rate - start, 3)}
        )
    level = float(np.sqrt(np.mean(x * x))) if len(x) else 0
    return {
        "profile": "tone-1000",
        "sample_rate": rate,
        "analyzed_s": round(len(x) / rate, 3),
        "rms_dbfs": round(20 * np.log10(max(level, 1e-8)), 2),
        "reference_level_dbfs": -15,
        "level_error_db": round(float(20 * np.log10(max(level, 1e-8)) + 15), 2),
        "level_dbfs_min": min((f["rms_dbfs"] for f in frames), default=None),
        "level_dbfs_max": max((f["rms_dbfs"] for f in frames), default=None),
        "level_dbfs_std": (
            round(float(np.std([f["rms_dbfs"] for f in frames])), 3) if frames else None
        ),
        "level_anomaly_s": round(sum(0.02 for f in frames if f["level_anomaly"]), 3),
        "tone_ratio_mean": (
            round(float(np.mean([f["tone_ratio"] for f in frames])), 4)
            if frames
            else None
        ),
        "interruptions": gaps,
        "interrupted_s": round(sum(g["duration_s"] for g in gaps), 3),
        "timeline": frames,
        "method": "20 ms RMS + phase independent 1 kHz sine/cosine fit; 250 ms edge trim" + (f"; first {start_s:g} s reserved for DTMF" if start_s else ""),
        "perceptual_mos": None,
    }


def observe_audio(path):
    """Local signal energy only: an uncontrolled receiver supplies no reference."""
    with wave.open(str(path), "rb") as w:
        rate = w.getframerate()
        x = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(float) / 32768
    rms = float(np.sqrt(np.mean(x*x))) if len(x) else 0
    return {"sample_rate": rate, "analyzed_s": round(len(x)/rate,3), "rms_dbfs": round(20*np.log10(max(rms,1e-8)),2), "reference_available": False, "remote_received_quality": None, "method": "Énergie PCM observée localement ; référence distante indisponible", "perceptual_mos": None}


def analyze_echo(path, reference_path, max_delay_s=3):
    """Round trip amplitude alignment, 20 ms bins; never infer a direction."""
    def envelope(p):
        with wave.open(str(p), "rb") as w:
            rate=w.getframerate()
            x=np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(float)/32768
        n=round(rate*.02)
        return np.sqrt(np.mean(x[:len(x)//n*n].reshape(-1,n)**2,axis=1))
    received, emitted=envelope(path), envelope(reference_path)
    best=(-1,None)
    for delay in range(int(max_delay_s/.02)+1):
        size=min(len(received)-delay,len(emitted))
        if size<50: continue
        a,b=received[delay+10:delay+size-10],emitted[10:size-10]
        if np.std(a)<1e-5: continue
        correlation=float(np.corrcoef(a,b)[0,1])
        if np.isfinite(correlation) and correlation>best[0]: best=(correlation,delay)
    result=analyze(path)
    result.update({"scope":"round_trip", "direction_attribution":None, "echo_delay_ms":best[1]*20 if best[0]>=.5 else None, "alignment_confidence":round(max(0,best[0]),4), "delay_resolution_ms":20, "delay_search_max_ms":max_delay_s*1000, "method":"Écho aller-retour : corrélation des marqueurs d’amplitude déterministes, trames 20 ms ; délai inclut PBX et buffers média", "reference_available":True})
    # Startup before the aligned signal is not an interruption.
    if best[0]>=.5:
        start=max(.25,best[1]*.02+.25)
        frames=[f for f in result['timeline'] if f['offset_s']>=start]
        gaps=[]; opened=None
        for f in frames:
            if f['missing'] and opened is None: opened=f['offset_s']
            if not f['missing'] and opened is not None:
                gaps.append({'start_s':opened,'duration_s':round(f['offset_s']-opened,3)});opened=None
        if opened is not None and frames: gaps.append({'start_s':opened,'duration_s':round(frames[-1]['offset_s']+.02-opened,3)})
        levels=np.array([f['rms_dbfs'] for f in frames])
        rms=float(np.sqrt(np.mean(10**(levels/10)))) if len(levels) else None
        result.update({'timeline':frames,'interruptions':gaps,'interrupted_s':round(sum(g['duration_s'] for g in gaps),3), 'analyzed_s':round(len(frames)*.02,3), 'tone_ratio_mean':round(float(np.mean([f['tone_ratio'] for f in frames])),4) if frames else None, 'rms_dbfs':round(20*np.log10(max(rms,1e-8)),2) if rms is not None else None, 'level_error_db':round(20*np.log10(max(rms,1e-8))+15,2) if rms is not None else None, 'level_dbfs_min':min(levels) if len(levels) else None, 'level_dbfs_max':max(levels) if len(levels) else None, 'level_dbfs_std':round(float(np.std(levels)),3) if len(levels) else None, 'level_anomaly_s':round(sum(.02 for f in frames if f['level_anomaly']),3)})
    return result
