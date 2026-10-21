#!/usr/bin/env python3
"""
Honeypot Log Shipper - Cowrie -> n8n
Tails cowrie.json, aggregates events BY SESSION, and when a session closes
(or after an idle timeout) emits ONE structured alert containing:
  - source IP / country hint field, session id, duration
  - credentials attempted (username/password pairs)
  - commands entered (the attacker's session - core intel)
  - file downloads: URLs + SHA256 (C2 / payload-staging indicators)
  - direct-tcp / port-forward attempts if present

Design: local file FIRST (honeypot-sessions.json - no session is lost if
n8n is down), then webhook POST with retry/backoff. Stdlib + requests only.
"""
import json, os, time, logging, threading
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("honeypot-shipper")

COWRIE_LOG = Path(os.getenv("COWRIE_LOG", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"))
WEBHOOK_URL = os.getenv("WEBHOOK_URL") or (
    Path("/opt/honeypot-shipper/.webhook_url").read_text().strip()
    if Path("/opt/honeypot-shipper/.webhook_url").exists() else ""
)
OUT_FILE = Path(os.getenv("OUT_FILE", "/var/log/honeypot-lab/honeypot-sessions.json"))
OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
IDLE_FLUSH_SEC = int(os.getenv("IDLE_FLUSH_SEC", "120"))
MAX_COMMANDS, MAX_CREDS = 200, 50

sessions = {}
lock = threading.Lock()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def new_session(sid, src_ip):
    return {
        "session_id": sid, "source_ip": src_ip, "started_at": now_iso(),
        "last_seen": time.time(), "commands": [], "credentials_tried": [],
        "downloads": [], "login_attempts": 0, "login_success": False,
        "client_version": None, "event_ids": set(),
    }

def emit(s):
    alert = {
        "timestamp": now_iso(),
        "alert_type": "honeypot_session",
        "source_component": "cowrie-honeypot-v1",
        "session_id": s["session_id"],
        "source_ip": s["source_ip"],
        "severity": "high" if s["downloads"] else "medium" if s["commands"] else "low",
        "host": os.getenv("HOSTNAME", "honeypot-lab-ec2"),
        "instance_id": os.getenv("INSTANCE_ID", "unknown"),
        "event": {
            "started_at": s["started_at"],
            "commands": s["commands"][:MAX_COMMANDS],
            "command_count": len(s["commands"]),
            "credentials_tried": s["credentials_tried"][:MAX_CREDS],
            "login_attempts": s["login_attempts"],
            "login_success": s["login_success"],
            "downloads": s["downloads"],  # [{url, sha256, outfile}] = C2 indicators
            "client_version": s["client_version"],
        },
        # Pre-tag the obvious patterns; the LLM in n8n does the real ATT&CK mapping
        "hints": {
            "has_download": bool(s["downloads"]),
            "has_discovery": any(c.split()[:1] and c.split()[0] in
                                 ("cat", "whoami", "uname", "id", "ls", "ps", "ifconfig", "ip")
                                 for c in s["commands"] if c),
            "has_execution": any("./" in c or "chmod +x" in c or "sh " in c or "bash " in c
                                 for c in s["commands"]),
        },
    }
    with OUT_FILE.open("a") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    log.warning(f"SESSION {s['session_id']} ip={s['source_ip']} cmds={len(s['commands'])} downloads={len(s['downloads'])}")
    if not WEBHOOK_URL or not requests:
        log.info("No webhook configured, session saved locally only")
        return
    for attempt in range(3):
        try:
            r = requests.post(WEBHOOK_URL, json=alert, timeout=4)
            if r.status_code < 300:
                return
            log.error(f"Webhook {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log.error(f"Webhook failed attempt {attempt+1}: {e}")
        time.sleep(1 * (attempt + 1))

def handle(ev):
    sid = ev.get("session") or ev.get("session_id") or "unknown"
    src = ev.get("src_ip", "unknown")
    eid = ev.get("eventid", "")
    with lock:
        s = sessions.setdefault(sid, new_session(sid, src))
        s["last_seen"] = time.time()
        s["event_ids"].add(eid)

        if eid == "cowrie.client.version":
            s["client_version"] = ev.get("version")
        elif eid in ("cowrie.login.attempt", "cowrie.login.failed", "cowrie.login.success"):
            s["login_attempts"] += 1
            cred = {"username": ev.get("username"), "password": ev.get("password")}
            if cred not in s["credentials_tried"]:
                s["credentials_tried"].append(cred)
            if eid == "cowrie.login.success":
                s["login_success"] = True
        elif eid == "cowrie.command.input":
            cmd = (ev.get("input") or "").strip()
            if cmd:
                s["commands"].append(cmd)
        elif eid == "cowrie.session.file_download":
            # C2 / payload staging indicator - URL + hash, NEVER fetch/execute it here
            s["downloads"].append({
                "url": ev.get("url"), "sha256": ev.get("shasum"),
                "outfile": ev.get("outfile"),
            })
        elif eid in ("cowrie.session.closed", "cowrie.client.disconnect"):
            emit(s)
            sessions.pop(sid, None)

def idle_flusher():
    while True:
        time.sleep(15)
        now = time.time()
        with lock:
            stale = [sid for sid, s in sessions.items() if now - s["last_seen"] > IDLE_FLUSH_SEC]
        for sid in stale:
            with lock:
                s = sessions.pop(sid, None)
            if s and (s["commands"] or s["login_attempts"]):
                emit(s)

def tail():
    while not COWRIE_LOG.exists():
        log.info(f"Waiting for {COWRIE_LOG}")
        time.sleep(3)
    with COWRIE_LOG.open(errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            try:
                handle(json.loads(line))
            except Exception as e:
                log.error(f"parse error: {e}")

if __name__ == "__main__":
    log.info(f"Shipper starting log={COWRIE_LOG} webhook={'set' if WEBHOOK_URL else 'NOT SET'}")
    threading.Thread(target=idle_flusher, daemon=True).start()
    tail()
