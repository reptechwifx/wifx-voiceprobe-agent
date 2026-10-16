"""Durable reports: unknown crash data stays unknown; one rejection never blocks others."""
import datetime
import json
import re
import time


def recovery_report(saved=None):
    metrics = {"established": False, "duration_s": 0,
               "sip": {"reason": "Agent restarted during execution"},
               "rtp": {}, "audio": None,
               "events": [{"kind": "process_restart", "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}]}
    if saved is not None:
        # Existing 007 databases stored only incoming metadata. Never guess its account.
        metrics["incoming"] = saved.get("incoming", saved)
        if "incoming" in saved and saved.get("account_id") is not None:
            metrics["sip"]["account_id"] = saved["account_id"]
    return metrics


class ReportOutbox:
    def __init__(self, db, lock, clock=time.time):
        self.db, self.lock, self.clock = db, lock, clock
        with lock:
            db.execute("CREATE TABLE IF NOT EXISTS report_delivery(run_id TEXT PRIMARY KEY,endpoint TEXT,http_status INTEGER,fields TEXT,attempts INTEGER NOT NULL DEFAULT 0,next_attempt REAL NOT NULL DEFAULT 0,state TEXT,updated_at REAL)")
            db.commit()

    def record(self, rid, path, status, fields, state, delay=0):
        with self.lock:
            self.db.execute("INSERT INTO report_delivery VALUES (?,?,?,?,1,?,?,?) ON CONFLICT(run_id) DO UPDATE SET endpoint=excluded.endpoint,http_status=excluded.http_status,fields=excluded.fields,attempts=report_delivery.attempts+1,next_attempt=excluded.next_attempt,state=excluded.state,updated_at=excluded.updated_at", (rid, path, status, json.dumps(fields), self.clock()+delay, state, self.clock()))
            self.db.commit()

    def deliver(self, rid, payload, api):
        with self.lock:
            row = self.db.execute("SELECT next_attempt FROM report_delivery WHERE run_id=?", (rid,)).fetchone()
        if row and row[0] > self.clock():
            return False
        path = None
        try:
            body = json.loads(payload)
            if not isinstance(body, dict):
                raise ValueError()
            path = ("incoming/" if "incoming" in body else "runs/") + rid + "/report"
        except (ValueError, TypeError):
            self.record(rid, path, None, [], "invalid_local_json", 300)
            return False
        response = api("POST", path, json=body)
        if 400 <= response.status_code < 500 and response.status_code not in (401, 429, 408):
            fields = []
            try:
                errors = response.json().get("errors", {})
                allowed = {"established", "sip", "duration_s", "rtp", "audio", "events", "incoming"}
                fields = sorted(k for k in errors if isinstance(k, str) and len(k) <= 100 and k.split('.')[0] in allowed and re.fullmatch(r'[a-zA-Z0-9_.]+', k))[:30]
            except (ValueError, AttributeError, TypeError):
                pass
            # Store only field names, never validation messages or reflected payloads/secrets.
            self.record(rid, path, response.status_code, fields, "rejected_recoverable", 300)
            return False
        response.raise_for_status()
        self.record(rid, path, response.status_code, [], "accepted")
        with self.lock:
            self.db.execute("DELETE FROM reports WHERE run_id=?", (rid,))
            self.db.commit()
        return True

    def snapshot(self):
        with self.lock:
            rows = self.db.execute("SELECT d.run_id,d.endpoint,d.http_status,d.fields,d.attempts,d.state,d.updated_at FROM report_delivery d JOIN reports r ON r.run_id=d.run_id ORDER BY d.updated_at DESC LIMIT 20").fetchall()
            count = self.db.execute("SELECT count(*) FROM reports").fetchone()[0]
        return {"pending": count, "errors": [{"run_id": r[0], "endpoint": r[1], "http_status": r[2], "fields": json.loads(r[3]), "attempts": r[4], "state": r[5], "updated_at": r[6]} for r in rows]}
