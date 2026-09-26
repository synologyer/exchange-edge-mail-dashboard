#!/usr/bin/env python3
import csv
import base64
import hashlib
import json
import os
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    import paramiko
except ImportError:
    paramiko = None

SFTP_HOST = os.getenv("EDGE_HOST", "").strip()
SFTP_PORT = int(os.getenv("EDGE_PORT", "22"))
SFTP_USER = os.getenv("EDGE_USERNAME", "").strip()
SFTP_PASSWORD = os.getenv("EDGE_PASSWORD", "")
SFTP_PASSWORD_FILE = os.getenv("EDGE_PASSWORD_FILE", "").strip()
SFTP_ROOT = os.getenv("EDGE_LOG_PATH", "/C:/Program Files/Microsoft/Exchange Server/V15/TransportRoles/Logs").rstrip("/")
SFTP_FINGERPRINT = os.getenv("EDGE_HOST_KEY_SHA256", "").strip().removeprefix("SHA256:")
SFTP_SYNC_SECONDS = int(os.getenv("SFTP_SYNC_SECONDS", "60"))
LOG_ROOT = Path("/tmp/edge-logs" if SFTP_HOST else os.getenv("LOG_ROOT", "/logs"))
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "").strip().lower().lstrip("@")
TRUSTED_EXCHANGE_IP = os.getenv("TRUSTED_EXCHANGE_IP", "").strip()
PORT = int(os.getenv("PORT", "8080"))
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "60"))
STATIC_ROOT = Path(__file__).parent / "static"
MAX_ROWS = int(os.getenv("MAX_ROWS", "10000"))

_cache = {}
_cache_lock = threading.Lock()
_sftp_lock = threading.Lock()
_last_sftp_sync = 0.0


def secret_password():
    if SFTP_PASSWORD_FILE:
        return Path(SFTP_PASSWORD_FILE).read_text(encoding="utf-8").strip()
    return SFTP_PASSWORD


def verify_host_key(key):
    if not SFTP_FINGERPRINT:
        return
    actual = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    if actual != SFTP_FINGERPRINT.rstrip("="):
        raise RuntimeError(f"Edge SSH host key mismatch: expected SHA256:{SFTP_FINGERPRINT}, got SHA256:{actual}")


def sync_sftp_logs(force=False):
    global _last_sftp_sync
    if not SFTP_HOST:
        return
    if paramiko is None:
        raise RuntimeError("SFTP support is unavailable in this image")
    with _sftp_lock:
        now = time.time()
        if not force and now - _last_sftp_sync < SFTP_SYNC_SECONDS:
            return
        if not SFTP_USER or not secret_password():
            raise RuntimeError("EDGE_USERNAME and EDGE_PASSWORD/EDGE_PASSWORD_FILE are required")
        transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        try:
            transport.start_client(timeout=15)
            verify_host_key(transport.get_remote_server_key())
            transport.auth_password(SFTP_USER, secret_password())
            sftp = paramiko.SFTPClient.from_transport(transport)
            cutoff = now - (32 * 86400)

            def walk(remote_dir, is_root=False):
                try:
                    entries = sftp.listdir_attr(remote_dir)
                except OSError as exc:
                    if is_root:
                        raise RuntimeError(
                            f"Cannot read EDGE_LOG_PATH '{SFTP_ROOT}': {exc}. "
                            "Check the Windows OpenSSH path and NTFS read permission."
                        ) from exc
                    return
                for entry in entries:
                    remote = remote_dir + "/" + entry.filename
                    mode = entry.st_mode
                    if mode & 0o170000 == 0o040000:
                        yield from walk(remote)
                    elif entry.filename.lower().endswith(".log") and entry.st_mtime >= cutoff:
                        normalized = remote.lower().replace("\\", "/")
                        if not any(h in normalized for h in ("messagetracking", "agentlog", "protocollog/smtpreceive")):
                            continue
                        relative = remote[len(SFTP_ROOT):].lstrip("/")
                        local = LOG_ROOT / Path(relative)
                        local.parent.mkdir(parents=True, exist_ok=True)
                        if local.exists() and local.stat().st_size == entry.st_size and int(local.stat().st_mtime) == entry.st_mtime:
                            continue
                        temp = local.with_suffix(local.suffix + ".part")
                        sftp.get(remote, str(temp))
                        os.utime(temp, (entry.st_atime, entry.st_mtime))
                        temp.replace(local)

            list(walk(SFTP_ROOT, is_root=True))
            _last_sftp_sync = now
        finally:
            transport.close()


def parse_time(value):
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def text(value):
    return str(value or "").strip().strip("{}").replace(";", ", ")


def correlation_key(row):
    for name in ("network-message-id", "message-id", "internal-message-id"):
        value = text(row.get(name))
        if value:
            return f"{name}|{value}"
    return ""


def message_key(row, stamp, prefix):
    key = correlation_key(row)
    if key:
        return f"{prefix}|{key}"
    return f"{prefix}|{stamp.isoformat()}|{row.get('sender-address','')}|{row.get('recipient-address','')}"


def log_files(hint, cutoff):
    if not LOG_ROOT.is_dir():
        return []
    result = []
    normalized = hint.lower().replace("\\", "/")
    for path in LOG_ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() != ".log":
            continue
        if normalized not in str(path.parent).lower().replace("\\", "/"):
            continue
        try:
            if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) >= cutoff - timedelta(days=1):
                result.append(path)
        except OSError:
            pass
    return sorted(set(result))


def read_rows(files, cutoff):
    for path in files:
        headers = None
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                for raw in handle:
                    if raw.startswith("#Fields:"):
                        headers = [part.strip() for part in raw[8:].strip().split(",")]
                        continue
                    if not headers or not raw.strip() or raw.startswith("#"):
                        continue
                    try:
                        values = next(csv.reader([raw]))
                        row = dict(zip(headers, values))
                        stamp = parse_time(row.get("date-time") or row.get("Timestamp"))
                        if stamp and stamp >= cutoff:
                            yield row, stamp, str(path)
                    except (csv.Error, ValueError):
                        continue
        except (OSError, PermissionError):
            continue


def item(stamp, kind, sender="", recipients="", remote_ip="", subject="", status="", reason="", source=""):
    return {
        "time": stamp.isoformat(), "type": kind, "sender": text(sender),
        "recipients": text(recipients), "remoteIp": text(remote_ip),
        "subject": text(subject), "status": text(status), "reason": text(reason), "source": source,
    }


def build_dashboard(days):
    if not COMPANY_DOMAIN or not TRUSTED_EXCHANGE_IP:
        raise RuntimeError("COMPANY_DOMAIN and TRUSTED_EXCHANGE_IP are required")
    sync_sftp_logs()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    tracking = log_files("MessageTracking", cutoff)
    trusted = set()
    for row, stamp, _ in read_rows(tracking, cutoff):
        if (row.get("event-id", "").upper() == "RECEIVE"
                and row.get("directionality", "").lower() == "originating"
                and text(row.get("client-ip")).strip("[]") == TRUSTED_EXCHANGE_IP):
            key = correlation_key(row)
            if key:
                trusted.add(key)

    records, seen = [], defaultdict(set)
    domain_re = re.compile(r"@(?:[^@]+\.)?" + re.escape(COMPANY_DOMAIN) + r"$", re.I)
    send_event = lambda event, connector: event == "SEND" or (event == "SENDEXTERNAL" and re.search(r"\bto\s+internet\b", connector, re.I))

    for row, stamp, _ in read_rows(tracking, cutoff):
        event = row.get("event-id", "").upper()
        direction = row.get("directionality", "").lower()
        sender = text(row.get("sender-address")).lower()
        connector = text(row.get("connector-id"))
        trusted_out = correlation_key(row) in trusted
        system_sender = not sender or sender == "<>" or sender.startswith("postmaster@") or sender.startswith("microsoftexchange")
        kind = None
        if event == "RECEIVE" and direction == "incoming":
            kind = "收件"
        elif direction == "originating" and trusted_out and send_event(event, connector):
            if system_sender:
                kind = "系统退信"
            elif domain_re.search(sender):
                kind = "发件"
            else:
                kind = "异常发件人"
        elif event == "FAIL" and direction == "originating" and trusted_out:
            if system_sender:
                kind = "系统退信失败"
            elif domain_re.search(sender):
                kind = "外发失败"
            else:
                kind = "异常发件人失败"
        if not kind:
            continue
        key = message_key(row, stamp, kind)
        if key in seen[kind]:
            continue
        seen[kind].add(key)
        records.append(item(
            stamp, kind, row.get("sender-address"), row.get("recipient-address"),
            row.get("client-ip") if direction == "incoming" else row.get("server-ip"),
            row.get("message-subject"), event, row.get("recipient-status"), "MessageTracking"
        ))

    agent_files = log_files("AgentLog", cutoff)
    agent_responses = set()
    reject_seen = set()
    for row, stamp, _ in read_rows(agent_files, cutoff):
        action = text(row.get("Action"))
        response = text(row.get("SmtpResponse") or row.get("smtp-response"))
        if not (re.search(r"Reject|Delete|Quarantine", action, re.I) or re.match(r"^[45]\d\d", response)):
            continue
        session = text(row.get("SessionId") or row.get("session-id"))
        normalized = re.sub(r"\s+", " ", response).lower()
        if session and normalized:
            agent_responses.add((session, normalized))
        recipient = row.get("Recipient") or row.get("Recipients")
        key = ("agent", session, stamp.replace(microsecond=0).isoformat(), response, text(recipient))
        if key in reject_seen:
            continue
        reject_seen.add(key)
        reason = " ".join(filter(None, (text(row.get("Reason")), text(row.get("ReasonData")))))
        sender = row.get("P1FromAddress") or row.get("P2FromAddresses")
        records.append(item(stamp, "拒收", sender, recipient,
                            row.get("RemoteEndpoint") or row.get("remote-endpoint"),
                            "", response or action, reason, "AgentLog"))

    protocol_files = log_files("ProtocolLog/SmtpReceive", cutoff)
    sessions = {}
    for row, stamp, _ in read_rows(protocol_files, cutoff):
        event, data = text(row.get("event")), text(row.get("data"))
        session = text(row.get("session-id"))
        if session and event == "<":
            state = sessions.setdefault(session, {"sender": "", "recipient": ""})
            match = re.match(r"^\s*MAIL\s+FROM\s*:\s*<([^>]*)>", data, re.I)
            if match:
                state.update(sender=match.group(1), recipient="")
            match = re.match(r"^\s*RCPT\s+TO\s*:\s*<([^>]*)>", data, re.I)
            if match:
                state["recipient"] = match.group(1)
            continue
        if event != ">" or not re.match(r"^[45]\d\d(?:[ -]|$)", data):
            continue
        normalized = re.sub(r"\s+", " ", data).lower()
        if (session, normalized) in agent_responses:
            continue
        key = ("smtp", session, stamp.replace(microsecond=0).isoformat(), data)
        if key in reject_seen:
            continue
        reject_seen.add(key)
        state = sessions.get(session, {})
        records.append(item(stamp, "拒收", state.get("sender"), state.get("recipient"),
                            row.get("remote-endpoint"), "", data, row.get("context"), "SmtpReceive"))

    records.sort(key=lambda row: row["time"], reverse=True)
    if len(records) > MAX_ROWS:
        records = records[:MAX_ROWS]
    counts = {
        "inbound": sum(r["type"] == "收件" for r in records),
        "outbound": sum(r["type"] == "发件" for r in records),
        "rejected": sum(r["type"] == "拒收" for r in records),
        "failed": sum(r["type"] == "外发失败" for r in records),
        "systemNdr": sum(r["type"].startswith("系统退信") for r in records),
        "anomaly": sum(r["type"].startswith("异常发件人") for r in records),
    }
    daily = []
    local_now = datetime.now().astimezone()
    for offset in range(days - 1, -1, -1):
        day = (local_now - timedelta(days=offset)).date()
        subset = [r for r in records if datetime.fromisoformat(r["time"]).astimezone().date() == day]
        daily.append({"date": day.isoformat(), "inbound": sum(r["type"] == "收件" for r in subset),
                      "outbound": sum(r["type"] == "发件" for r in subset),
                      "rejected": sum(r["type"] == "拒收" for r in subset)})
    return {"generatedAt": datetime.now(timezone.utc).isoformat(), "days": days,
            "config": {"domain": COMPANY_DOMAIN, "trustedIp": TRUSTED_EXCHANGE_IP, "logRoot": str(LOG_ROOT)},
            "files": {"tracking": len(tracking), "agent": len(agent_files), "protocol": len(protocol_files)},
            "trustedMessages": len(trusted), "counts": counts, "daily": daily, "items": records}


def dashboard(days):
    now = time.time()
    with _cache_lock:
        cached = _cache.get(days)
        if cached and now - cached[0] < CACHE_SECONDS:
            return cached[1]
    result = build_dashboard(days)
    with _cache_lock:
        _cache[days] = (now, result)
    return result


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            try:
                sync_sftp_logs()
                ok = LOG_ROOT.is_dir()
                return self.send_json({"status": "ok" if ok else "error", "logRootExists": ok, "mode": "sftp" if SFTP_HOST else "mount"})
            except Exception as exc:
                return self.send_json({"status": "error", "error": str(exc), "mode": "sftp"}, 503)
        if parsed.path == "/api/dashboard":
            try:
                days = int(parse_qs(parsed.query).get("days", ["1"])[0])
                if days not in (1, 7, 30):
                    raise ValueError
                return self.send_json(dashboard(days))
            except ValueError:
                return self.send_json({"error": "days must be 1, 7 or 30"}, 400)
            except Exception as exc:
                return self.send_json({"error": str(exc)}, 500)
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"Exchange Edge dashboard listening on 0.0.0.0:{PORT}; logs={LOG_ROOT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
