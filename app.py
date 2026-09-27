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

SFTP_SYNC_SECONDS = int(os.getenv("SFTP_SYNC_SECONDS", "60"))
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "").strip().lower().lstrip("@")
TRUSTED_EXCHANGE_IP = os.getenv("TRUSTED_EXCHANGE_IP", "").strip()
TRUSTED_EXCHANGE_IPS = {ip.strip() for ip in os.getenv("TRUSTED_EXCHANGE_IPS", TRUSTED_EXCHANGE_IP).split(",") if ip.strip()}
PORT = int(os.getenv("PORT", "8080"))
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "60"))
STATIC_ROOT = Path(__file__).parent / "static"
MAX_ROWS = int(os.getenv("MAX_ROWS", "10000"))

_cache = {}
_cache_lock = threading.Lock()
_sftp_locks = defaultdict(threading.Lock)
_sync_state = defaultdict(lambda: {"lastSuccess": 0.0, "lastError": ""})


def edge_nodes():
    names = [name.strip() for name in os.getenv("EDGE_NODES", "").split(",") if name.strip()]
    nodes = []
    if names:
        for name in names:
            prefix = re.sub(r"[^A-Za-z0-9]", "_", name).upper()
            host = os.getenv(f"{prefix}_HOST", "").strip()
            nodes.append({
                "name": name, "host": host, "port": int(os.getenv(f"{prefix}_PORT", "22")),
                "user": os.getenv(f"{prefix}_USERNAME", "").strip(),
                "password": os.getenv(f"{prefix}_PASSWORD", ""),
                "passwordFile": os.getenv(f"{prefix}_PASSWORD_FILE", "").strip(),
                "root": os.getenv(f"{prefix}_LOG_PATH", "/C:/Program Files/Microsoft/Exchange Server/V15/TransportRoles/Logs").rstrip("/"),
                "fingerprint": os.getenv(f"{prefix}_HOST_KEY_SHA256", "").strip().removeprefix("SHA256:"),
                "localRoot": Path("/tmp/edge-logs") / name,
            })
    else:
        host = os.getenv("EDGE_HOST", "").strip()
        nodes.append({
            "name": os.getenv("EDGE_NAME", "mx").strip() or "mx", "host": host,
            "port": int(os.getenv("EDGE_PORT", "22")), "user": os.getenv("EDGE_USERNAME", "").strip(),
            "password": os.getenv("EDGE_PASSWORD", ""), "passwordFile": os.getenv("EDGE_PASSWORD_FILE", "").strip(),
            "root": os.getenv("EDGE_LOG_PATH", "/C:/Program Files/Microsoft/Exchange Server/V15/TransportRoles/Logs").rstrip("/"),
            "fingerprint": os.getenv("EDGE_HOST_KEY_SHA256", "").strip().removeprefix("SHA256:"),
            "localRoot": Path("/tmp/edge-logs" if host else os.getenv("LOG_ROOT", "/logs")),
        })
    return nodes


EDGE_NODES = edge_nodes()
LOG_ROOTS = [node["localRoot"] for node in EDGE_NODES]


def secret_password(node):
    if node["passwordFile"]:
        return Path(node["passwordFile"]).read_text(encoding="utf-8").strip()
    return node["password"]


def verify_host_key(key, expected):
    if not expected:
        return
    actual = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    if actual != expected.rstrip("="):
        raise RuntimeError(f"Edge SSH host key mismatch: expected SHA256:{expected}, got SHA256:{actual}")


def sync_sftp_node(node, force=False):
    if not node["host"]:
        return
    if paramiko is None:
        raise RuntimeError("SFTP support is unavailable in this image")
    state = _sync_state[node["name"]]
    with _sftp_locks[node["name"]]:
        now = time.time()
        if not force and now - state["lastSuccess"] < SFTP_SYNC_SECONDS:
            return
        if not node["user"] or not secret_password(node):
            raise RuntimeError(f"{node['name']}: username and password/password file are required")
        transport = paramiko.Transport((node["host"], node["port"]))
        try:
            transport.start_client(timeout=15)
            verify_host_key(transport.get_remote_server_key(), node["fingerprint"])
            transport.auth_password(node["user"], secret_password(node))
            sftp = paramiko.SFTPClient.from_transport(transport)
            cutoff = now - (32 * 86400)

            def walk(remote_dir, is_root=False):
                try:
                    entries = sftp.listdir_attr(remote_dir)
                except OSError as exc:
                    if is_root:
                        raise RuntimeError(
                            f"{node['name']}: cannot read log path '{node['root']}': {exc}. "
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
                        relative = remote[len(node["root"]):].lstrip("/")
                        local = node["localRoot"] / Path(relative)
                        local.parent.mkdir(parents=True, exist_ok=True)
                        if local.exists() and local.stat().st_size == entry.st_size and int(local.stat().st_mtime) == entry.st_mtime:
                            continue
                        temp = local.with_suffix(local.suffix + ".part")
                        sftp.get(remote, str(temp))
                        os.utime(temp, (entry.st_atime, entry.st_mtime))
                        temp.replace(local)

            list(walk(node["root"], is_root=True))
            state.update(lastSuccess=now, lastError="")
        except Exception as exc:
            state["lastError"] = str(exc)
            raise
        finally:
            transport.close()


def sync_sftp_logs(force=False):
    errors = []
    for node in EDGE_NODES:
        try:
            sync_sftp_node(node, force)
        except Exception as exc:
            errors.append(str(exc))
    if errors and len(errors) == len([node for node in EDGE_NODES if node["host"]]):
        raise RuntimeError("; ".join(errors))


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
    result = []
    normalized = hint.lower().replace("\\", "/")
    for root in LOG_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
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


def node_for_path(path):
    resolved = path.resolve()
    for node in EDGE_NODES:
        try:
            resolved.relative_to(node["localRoot"].resolve())
            return node["name"]
        except ValueError:
            continue
    return EDGE_NODES[0]["name"] if EDGE_NODES else "mx"


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


def endpoint_ip(value):
    value = text(value).strip("[]")
    if value.startswith("[") and "]:" in value:
        return value[1:value.rfind("]")]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def rejection_category(status, reason=""):
    value = f"{text(status)} {text(reason)}".lower()
    if re.search(r"5\.1\.1|recipientnotfound|user unknown|unknown recipient|resolver\.adr\.recipnotfound", value):
        return "不存在的收件人"
    if re.search(r"spam|content filter|scl|malware|phish", value):
        return "垃圾邮件或内容过滤"
    if re.search(r"spf|dkim|dmarc", value):
        return "身份验证策略"
    if re.search(r"blocklist|blacklist|rbl|dnsbl", value):
        return "IP 黑名单"
    if re.search(r"relay|unable to relay|not permitted", value):
        return "中继限制"
    if re.match(r"\s*4\d\d", value):
        return "临时失败"
    return "其他拒收"


def item(stamp, kind, sender="", recipients="", remote_ip="", subject="", status="", reason="", source="", category="", connector="", node=""):
    return {
        "time": stamp.isoformat(), "type": kind, "sender": text(sender),
        "recipients": text(recipients), "remoteIp": text(remote_ip),
        "subject": text(subject), "status": text(status), "reason": text(reason), "source": source,
        "category": text(category), "connector": text(connector), "node": text(node),
    }


def build_dashboard(days):
    if not COMPANY_DOMAIN or not TRUSTED_EXCHANGE_IPS:
        raise RuntimeError("COMPANY_DOMAIN and TRUSTED_EXCHANGE_IP/TRUSTED_EXCHANGE_IPS are required")
    sync_sftp_logs()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    tracking = log_files("MessageTracking", cutoff)
    trusted = set()
    for row, stamp, _ in read_rows(tracking, cutoff):
        if (row.get("event-id", "").upper() == "RECEIVE"
                and row.get("directionality", "").lower() == "originating"
                and endpoint_ip(row.get("client-ip")) in TRUSTED_EXCHANGE_IPS):
            key = correlation_key(row)
            if key:
                trusted.add(key)

    records, seen = [], defaultdict(dict)
    domain_re = re.compile(r"@(?:[^@]+\.)?" + re.escape(COMPANY_DOMAIN) + r"$", re.I)
    is_company_sender = lambda sender: bool(domain_re.search(text(sender).lower()))
    send_event = lambda event, connector: event == "SEND" or (event == "SENDEXTERNAL" and re.search(r"\bto\s+internet\b", connector, re.I))

    for row, stamp, source_path in read_rows(tracking, cutoff):
        event = row.get("event-id", "").upper()
        direction = row.get("directionality", "").lower()
        sender = text(row.get("sender-address")).lower()
        connector = text(row.get("connector-id"))
        trusted_out = correlation_key(row) in trusted
        system_sender = not sender or sender == "<>" or sender.startswith("postmaster@") or sender.startswith("microsoftexchange")
        kind = None
        if event == "RECEIVE" and direction == "incoming":
            remote_ip = endpoint_ip(row.get("client-ip"))
            kind = "匿名冒充公司域" if is_company_sender(sender) and remote_ip not in TRUSTED_EXCHANGE_IPS else "收件"
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
        categories = {
            "收件": "正常外部来信",
            "发件": "可信 Mail 正常外发",
            "外发失败": "公司邮件外发失败",
            "系统退信": "系统自动退信",
            "系统退信失败": "系统退信发送失败",
            "异常发件人": "可信 Mail 提交了非公司域发件地址",
            "异常发件人失败": "异常发件地址外发失败",
            "匿名冒充公司域": "外部连接冒充公司域发件人",
        }
        key = message_key(row, stamp, kind)
        node_name = node_for_path(Path(source_path))
        if key in seen[kind]:
            existing = seen[kind][key]
            nodes = [part.strip() for part in existing["node"].split(",") if part.strip()]
            if node_name not in nodes:
                existing["node"] = ", ".join(nodes + [node_name])
            continue
        record = item(
            stamp, kind, row.get("sender-address"), row.get("recipient-address"),
            row.get("client-ip") if direction == "incoming" else row.get("server-ip"),
            row.get("message-subject"), event, row.get("recipient-status"), "MessageTracking",
            categories.get(kind, ""), connector, node_name
        )
        seen[kind][key] = record
        records.append(record)

    agent_files = log_files("AgentLog", cutoff)
    agent_responses = set()
    reject_seen = set()
    for row, stamp, source_path in read_rows(agent_files, cutoff):
        node_name = node_for_path(Path(source_path))
        action = text(row.get("Action"))
        response = text(row.get("SmtpResponse") or row.get("smtp-response"))
        if not (re.search(r"Reject|Delete|Quarantine", action, re.I) or re.match(r"^[45]\d\d", response)):
            continue
        session = text(row.get("SessionId") or row.get("session-id"))
        normalized = re.sub(r"\s+", " ", response).lower()
        if session and normalized:
            agent_responses.add((node_name, session, normalized))
        recipient = row.get("Recipient") or row.get("Recipients")
        key = ("agent", session, stamp.replace(microsecond=0).isoformat(), response, text(recipient))
        if key in reject_seen:
            continue
        reject_seen.add(key)
        reason = " ".join(filter(None, (text(row.get("Reason")), text(row.get("ReasonData")))))
        sender = row.get("P1FromAddress") or row.get("P2FromAddresses")
        remote = row.get("RemoteEndpoint") or row.get("remote-endpoint")
        kind = "匿名冒充公司域（已拒收）" if is_company_sender(sender) and endpoint_ip(remote) not in TRUSTED_EXCHANGE_IPS else "拒收"
        category = "外部连接冒充公司域发件人" if kind.startswith("匿名冒充") else rejection_category(response or action, reason)
        records.append(item(stamp, kind, sender, recipient, remote,
                            "", response or action, reason, "AgentLog", category,
                            row.get("Agent"), node_name))

    protocol_files = log_files("ProtocolLog/SmtpReceive", cutoff)
    sessions = {}
    for row, stamp, source_path in read_rows(protocol_files, cutoff):
        node_name = node_for_path(Path(source_path))
        event, data = text(row.get("event")), text(row.get("data"))
        session = text(row.get("session-id"))
        session_key = (node_name, session)
        if session and event == "<":
            state = sessions.setdefault(session_key, {"sender": "", "recipient": ""})
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
        if (node_name, session, normalized) in agent_responses:
            continue
        key = ("smtp", session, stamp.replace(microsecond=0).isoformat(), data)
        if key in reject_seen:
            continue
        reject_seen.add(key)
        state = sessions.get(session_key, {})
        sender = state.get("sender")
        remote = row.get("remote-endpoint")
        kind = "匿名冒充公司域（已拒收）" if is_company_sender(sender) and endpoint_ip(remote) not in TRUSTED_EXCHANGE_IPS else "拒收"
        category = "外部连接冒充公司域发件人" if kind.startswith("匿名冒充") else rejection_category(data, row.get("context"))
        records.append(item(stamp, kind, sender, state.get("recipient"),
                            remote, "", data, row.get("context"), "SmtpReceive", category,
                            row.get("connector-id"), node_name))

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
        "spoofed": sum(r["type"].startswith("匿名冒充公司域") for r in records),
    }
    daily = []
    local_now = datetime.now().astimezone()
    for offset in range(days - 1, -1, -1):
        day = (local_now - timedelta(days=offset)).date()
        subset = [r for r in records if datetime.fromisoformat(r["time"]).astimezone().date() == day]
        daily.append({"date": day.isoformat(), "inbound": sum(r["type"] == "收件" for r in subset),
                      "outbound": sum(r["type"] == "发件" for r in subset),
                      "rejected": sum(r["type"] == "拒收" for r in subset),
                      "spoofed": sum(r["type"].startswith("匿名冒充公司域") for r in subset)})
    hourly = []
    if days == 1:
        local_now = datetime.now().astimezone().replace(minute=0, second=0, microsecond=0)
        for offset in range(23, -1, -1):
            start = local_now - timedelta(hours=offset)
            end = start + timedelta(hours=1)
            subset = [r for r in records if start <= datetime.fromisoformat(r["time"]).astimezone() < end]
            hourly.append({"time": start.isoformat(), "label": start.strftime("%H:00"),
                           "inbound": sum(r["type"] == "收件" for r in subset),
                           "outbound": sum(r["type"] == "发件" for r in subset),
                           "rejected": sum(r["type"] == "拒收" for r in subset),
                           "spoofed": sum(r["type"].startswith("匿名冒充公司域") for r in subset)})
    newest_record = records[0]["time"] if records else ""
    node_status = []
    for node in EDGE_NODES:
        state = _sync_state[node["name"]]
        node_status.append({"name": node["name"], "host": node["host"],
                            "mode": "sftp" if node["host"] else "mount",
                            "online": (bool(state["lastSuccess"]) if node["host"] else node["localRoot"].is_dir()) and not state["lastError"],
                            "lastSuccess": datetime.fromtimestamp(state["lastSuccess"], timezone.utc).isoformat() if state["lastSuccess"] else "",
                            "lastError": state["lastError"]})
    last_success = max((state["lastSuccess"] for state in _sync_state.values()), default=0)
    return {"generatedAt": datetime.now(timezone.utc).isoformat(), "days": days,
            "config": {"domain": COMPANY_DOMAIN, "trustedIps": sorted(TRUSTED_EXCHANGE_IPS),
                       "nodes": [node["name"] for node in EDGE_NODES]},
            "files": {"tracking": len(tracking), "agent": len(agent_files), "protocol": len(protocol_files)},
            "trustedMessages": len(trusted), "counts": counts, "daily": daily, "hourly": hourly,
            "sync": {"mode": "sftp" if any(node["host"] for node in EDGE_NODES) else "mount",
                     "lastSuccess": datetime.fromtimestamp(last_success, timezone.utc).isoformat() if last_success else "",
                     "newestRecord": newest_record, "intervalSeconds": SFTP_SYNC_SECONDS,
                     "nodes": node_status},
            "items": records}


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

    def end_headers(self):
        if not self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            try:
                sync_sftp_logs()
                states = [{"name": node["name"], "logRootExists": node["localRoot"].is_dir(),
                           "online": (bool(_sync_state[node["name"]]["lastSuccess"]) if node["host"] else node["localRoot"].is_dir()) and not _sync_state[node["name"]]["lastError"],
                           "error": _sync_state[node["name"]]["lastError"]} for node in EDGE_NODES]
                ok = any(state["online"] for state in states)
                return self.send_json({"status": "ok" if ok else "error", "nodes": states,
                                       "mode": "sftp" if any(node["host"] for node in EDGE_NODES) else "mount"}, 200 if ok else 503)
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
    print(f"Exchange Edge dashboard listening on 0.0.0.0:{PORT}; nodes={','.join(node['name'] for node in EDGE_NODES)}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
