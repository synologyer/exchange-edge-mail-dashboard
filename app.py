#!/usr/bin/env python3
import csv
import base64
import hashlib
import json
import os
import re
import sqlite3
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
BACKGROUND_INDEX_SECONDS = int(os.getenv("BACKGROUND_INDEX_SECONDS", "30"))
SFTP_HISTORY_DAYS = int(os.getenv("SFTP_HISTORY_DAYS", "0"))
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "").strip().lower().lstrip("@")
TRUSTED_EXCHANGE_IP = os.getenv("TRUSTED_EXCHANGE_IP", "").strip()
TRUSTED_EXCHANGE_IPS = {ip.strip() for ip in os.getenv("TRUSTED_EXCHANGE_IPS", TRUSTED_EXCHANGE_IP).split(",") if ip.strip()}
PORT = int(os.getenv("PORT", "8080"))
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "60"))
STATIC_ROOT = Path(__file__).parent / "static"
MAX_ROWS = int(os.getenv("MAX_ROWS", "10000"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "/data/dashboard.db"))
PARSER_VERSION = "2"
ANALYZER_VERSION = "4"

_cache = {}
_cache_lock = threading.Lock()
_build_lock = threading.Lock()
_db_lock = threading.Lock()
_sftp_locks = defaultdict(threading.Lock)
_sync_state = defaultdict(lambda: {"lastSuccess": 0.0, "lastError": ""})
_index_state = {"running": False, "lastSuccess": "", "lastError": "", "files": 0, "changed": 0}


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
            cutoff = now - (SFTP_HISTORY_DAYS * 86400) if SFTP_HISTORY_DAYS > 0 else 0

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
                    elif entry.filename.lower().endswith(".log") and (not cutoff or entry.st_mtime >= cutoff):
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


def database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS log_files (
            path TEXT PRIMARY KEY,
            signature TEXT NOT NULL,
            row_count INTEGER NOT NULL,
            indexed_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS log_rows (
            path TEXT NOT NULL,
            stamp TEXT NOT NULL,
            payload TEXT NOT NULL
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_log_rows_stamp ON log_rows(stamp)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_log_rows_path ON log_rows(path)")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS dashboard_snapshots (
            days INTEGER PRIMARY KEY,
            payload TEXT NOT NULL,
            generated_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS mail_events (
            days INTEGER NOT NULL,
            position INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY(days, position)
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_mail_events_type ON mail_events(days,event_type,position)")
    return connection


def parse_log_file(path):
    parsed, headers = [], None
    line_number = 0
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for raw in handle:
            if raw.startswith("#Fields:"):
                headers = [part.strip() for part in raw[8:].strip().split(",")]
                continue
            if not raw.strip() or raw.startswith("#"):
                continue
            line_number += 1
            if not headers:
                parsed.append(("", json.dumps({"_line": line_number, "_raw": raw.rstrip("\r\n"),
                                                  "_parseError": "日志缺少 #Fields 字段定义"}, ensure_ascii=False)))
                continue
            try:
                values = next(csv.reader([raw]))
                row = dict(zip(headers, values))
                stamp = parse_time(row.get("date-time") or row.get("Timestamp"))
                row["_line"] = line_number
                if len(values) != len(headers):
                    row["_parseError"] = f"字段数量不一致：应为 {len(headers)}，实际为 {len(values)}"
                parsed.append((stamp.isoformat() if stamp else "", json.dumps(row, ensure_ascii=False)))
            except (csv.Error, ValueError) as exc:
                parsed.append(("", json.dumps({"_line": line_number, "_raw": raw.rstrip("\r\n"),
                                                  "_parseError": str(exc)}, ensure_ascii=False)))
    return parsed


def index_log_files(files):
    changed = 0
    with _db_lock:
        with database() as connection:
            for path in files:
                try:
                    stat = path.stat()
                    signature = f"v{PARSER_VERSION}:{stat.st_mtime_ns}:{stat.st_size}"
                    current = connection.execute("SELECT signature FROM log_files WHERE path=?", (str(path),)).fetchone()
                    if current and current[0] == signature:
                        continue
                    parsed = parse_log_file(path)
                    connection.execute("DELETE FROM log_rows WHERE path=?", (str(path),))
                    connection.executemany("INSERT INTO log_rows(path,stamp,payload) VALUES(?,?,?)",
                                           ((str(path), stamp, payload) for stamp, payload in parsed))
                    connection.execute("""
                        INSERT INTO log_files(path,signature,row_count,indexed_at) VALUES(?,?,?,?)
                        ON CONFLICT(path) DO UPDATE SET signature=excluded.signature,
                        row_count=excluded.row_count,indexed_at=excluded.indexed_at
                    """, (str(path), signature, len(parsed), datetime.now(timezone.utc).isoformat()))
                    changed += 1
                except (OSError, PermissionError):
                    continue
    return changed


def all_log_files():
    cutoff = datetime(1970, 1, 1, tzinfo=timezone.utc)
    files = []
    for hint in ("MessageTracking", "AgentLog", "ProtocolLog/SmtpReceive"):
        files.extend(log_files(hint, cutoff))
    return sorted(set(files))


def background_index_once():
    _index_state.update(running=True, lastError="")
    try:
        sync_sftp_logs()
        files = all_log_files()
        changed = index_log_files(files)
        expected_config = {"domain": COMPANY_DOMAIN, "trustedIps": sorted(TRUSTED_EXCHANGE_IPS),
                           "nodes": [node["name"] for node in EDGE_NODES],
                           "analyzerVersion": ANALYZER_VERSION}
        with _db_lock:
            with database() as connection:
                saved_snapshots = connection.execute("SELECT days,payload FROM dashboard_snapshots").fetchall()
        snapshot_days = set()
        for days, payload in saved_snapshots:
            try:
                if json.loads(payload).get("config") == expected_config:
                    snapshot_days.add(days)
            except json.JSONDecodeError:
                pass
        if changed or snapshot_days != {1, 7, 30}:
            snapshots = {days: analyze_dashboard(days) for days in (1, 7, 30)}
            with _db_lock:
                with database() as connection:
                    now_text = datetime.now(timezone.utc).isoformat()
                    for days, payload in snapshots.items():
                        events = payload.pop("items", [])
                        connection.execute("DELETE FROM mail_events WHERE days=?", (days,))
                        connection.executemany(
                            "INSERT INTO mail_events(days,position,event_type,payload) VALUES(?,?,?,?)",
                            ((days, position, event["type"], json.dumps(event, ensure_ascii=False))
                             for position, event in enumerate(events)),
                        )
                        payload["totalEvents"] = len(events)
                        connection.execute(
                            "INSERT INTO dashboard_snapshots(days,payload,generated_at) VALUES(?,?,?) "
                            "ON CONFLICT(days) DO UPDATE SET payload=excluded.payload,generated_at=excluded.generated_at",
                            (days, json.dumps(payload, ensure_ascii=False), now_text),
                        )
            with _cache_lock:
                _cache.clear()
        _index_state.update(lastSuccess=datetime.now(timezone.utc).isoformat(),
                            files=len(files), changed=changed)
    except Exception as exc:
        _index_state["lastError"] = str(exc)
    finally:
        _index_state["running"] = False


def background_index_loop():
    while True:
        background_index_once()
        time.sleep(max(5, BACKGROUND_INDEX_SECONDS))


def node_for_path(path):
    resolved = path.resolve()
    for node in EDGE_NODES:
        try:
            resolved.relative_to(node["localRoot"].resolve())
            return node["name"]
        except ValueError:
            continue
    return EDGE_NODES[0]["name"] if EDGE_NODES else "mx"


def read_rows(hint, cutoff):
    pattern = f"%{hint.lower().replace('\\', '/')}%"
    with database() as connection:
        stored = connection.execute(
            "SELECT payload,stamp,path FROM log_rows "
            "WHERE stamp>=? AND lower(replace(path, '\\', '/')) LIKE ? ORDER BY stamp",
            (cutoff.isoformat(), pattern),
        ).fetchall()
    for payload, stamp_text, source_path in stored:
        try:
            yield json.loads(payload), datetime.fromisoformat(stamp_text), source_path
        except (json.JSONDecodeError, ValueError):
            continue


def classify_raw_log(source, event, pick, parse_error):
    if parse_error:
        return "解析异常", "无法解析的原始日志行", "需要检查", "warn"
    event_upper = event.upper()
    direction = text(pick("directionality")).lower()
    connector = text(pick("connector-id", "connector"))
    agent = text(pick("agent", "source-context"))
    action = text(pick("action"))
    reason = text(pick("reason", "recipient-status", "smtp-response", "smtpresponse", "data", "context"))
    response = " ".join((reason, text(pick("smtp-response", "smtpresponse")),
                         text(pick("source-context", "sourcecontext", "context")))).lower()
    recipient_missing = is_missing_recipient(response)
    rejected = action.lower().startswith("reject") or re.match(r"^[45]\d\d", response.strip())
    if recipient_missing:
        return "无效邮箱投递", "收件人不存在，已被 Edge 拒绝", "已成功拦截", "ok"
    if rejected or (event_upper == "FAIL" and "recipient filter agent" in agent.lower()):
        return "已有邮箱邮件被拒", rejection_category(response, reason), "已拦截", "ok"
    inbound_handoff = (event_upper == "SENDEXTERNAL" and direction == "incoming"
                       and "edgesync" in connector.lower() and "inbound" in connector.lower())
    if inbound_handoff and ("250 2." in response or "queued mail for delivery" in response):
        return "收件", "外部来信已转交内部 Mail 服务器", "已接收并进入投递队列", "ok"
    if event_upper == "RECEIVE" and direction == "incoming":
        return "收件", "外部来信已由 Edge 接收", "已接收", "ok"
    if event_upper in ("SEND", "SENDEXTERNAL") and direction == "originating":
        return "发件", "公司邮件正常外发", "已发送", "ok"
    if event_upper == "FAIL":
        return "传输失败", "邮件传输失败", "失败", "bad"
    if source == "AgentLog" and action:
        return "代理处理", f"{agent or '传输代理'}：{action}", "已处理", "ok"
    return event or "其他日志", "原始日志记录", "仅供审计", "neutral"


def raw_log_page(days, page=1, page_size=500):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    page = max(1, page)
    page_size = min(500, max(50, page_size))
    offset = (page - 1) * page_size
    with database() as connection:
        dated = connection.execute("SELECT count(*) FROM log_rows WHERE stamp>=?",
                                   (cutoff.isoformat(),)).fetchone()[0]
        failed = connection.execute("SELECT count(*) FROM log_rows WHERE stamp=''", ()).fetchone()[0]
        total = dated + failed
        rows = connection.execute(
            "SELECT rowid,payload,stamp,path FROM log_rows WHERE stamp>=? ORDER BY stamp DESC LIMIT ? OFFSET ?",
            (cutoff.isoformat(), page_size, offset),
        ).fetchall() if offset < dated else []
        if len(rows) < page_size and offset + len(rows) >= dated:
            failed_offset = max(0, offset - dated)
            rows.extend(connection.execute(
                "SELECT rowid,payload,stamp,path FROM log_rows WHERE stamp='' ORDER BY path LIMIT ? OFFSET ?",
                (page_size - len(rows), failed_offset),
            ).fetchall())
    items = []
    for raw_id, payload, stamp_text, source_path in rows:
        try:
            row = json.loads(payload)
        except json.JSONDecodeError:
            row = {"_raw": payload, "_parseError": "数据库记录不是有效 JSON"}
        normalized = {str(key).lower(): value for key, value in row.items()}
        pick = lambda *names: next((normalized[name.lower()] for name in names
                                    if normalized.get(name.lower()) not in (None, "")), "")
        path_lower = source_path.lower().replace("\\", "/")
        source = "MessageTracking" if "messagetracking" in path_lower else (
            "AgentLog" if "agentlog" in path_lower else "SmtpReceive")
        event = text(pick("event-id", "event", "action", "agent"))
        parse_error = text(pick("_parseError"))
        kind, category, result_text, result_class = classify_raw_log(source, event, pick, parse_error)
        items.append(item(
            parse_time(stamp_text) if stamp_text else datetime(1970, 1, 1, tzinfo=timezone.utc),
            kind,
            pick("sender-address", "p1-from-address", "p2-from-address", "mail-from"),
            pick("recipient-address", "recipient", "recipients", "rcpt-to"),
            endpoint_ip(pick("client-ip", "remote-endpoint", "ip-address")),
            pick("message-subject", "subject"), event,
            parse_error or pick("recipient-status", "smtp-response", "smtpresponse", "reason", "data", "context", "_raw"),
            source, category,
            pick("connector-id", "connector", "agent"), node_for_path(Path(source_path)),
        ))
        items[-1]["resultText"] = result_text
        items[-1]["resultClass"] = result_class
        items[-1]["rawIds"] = [raw_id]
    items = merge_rejection_records(items)
    return {"days": days, "page": page, "pageSize": page_size, "total": total,
            "parseErrors": failed, "items": items}


def raw_log_details(raw_ids):
    ids = sorted({int(value) for value in raw_ids if str(value).isdigit()})[:10]
    if not ids:
        raise ValueError("at least one valid log id is required")
    placeholders = ",".join("?" for _ in ids)
    with database() as connection:
        rows = connection.execute(
            f"SELECT rowid,payload,path FROM log_rows WHERE rowid IN ({placeholders})", ids
        ).fetchall()
    result = []
    for raw_id, payload, path in rows:
        try:
            raw = json.loads(payload)
        except json.JSONDecodeError:
            raw = {"_raw": payload, "_parseError": "数据库记录不是有效 JSON"}
        result.append({"id": raw_id, "source": path, "fields": raw})
    return {"items": result}


def smtp_response_key(record):
    value = f"{record.get('status', '')} {record.get('reason', '')}".lower()
    match = re.search(r"\b([45]\d\d(?:[ .-]\d+){0,2})\b", value)
    return re.sub(r"\s+", " ", match.group(1).replace("-", ".")) if match else ""


def merge_rejection_records(records):
    """Merge AgentLog and SMTP protocol views of one rejection for display only."""
    rejection_types = {"已有邮箱邮件被拒", "无效邮箱投递"}
    merged, candidates = [], {}
    for record in records:
        if record.get("type") not in rejection_types or record.get("source") not in {"AgentLog", "SmtpReceive"}:
            merged.append(record)
            continue
        stamp = text(record.get("time"))[:19]
        key = (record.get("node"), stamp, smtp_response_key(record))
        previous = candidates.get(key) if key[2] else None
        if previous and previous.get("source") != record.get("source"):
            for field in ("sender", "recipients", "remoteIp", "subject", "status", "reason", "connector"):
                if not previous.get(field) and record.get(field):
                    previous[field] = record[field]
            previous["rawIds"] = sorted(set(previous.get("rawIds", []) + record.get("rawIds", [])))
            if record.get("type") == "无效邮箱投递":
                previous.update(type=record["type"], category=record["category"],
                                resultText=record.get("resultText", "已成功拦截"),
                                resultClass=record.get("resultClass", "ok"))
            previous["source"] = "AgentLog + SmtpReceive"
            continue
        candidates[key] = record
        merged.append(record)
    return merged


def event_page(days, page=1, page_size=200, event_filter=""):
    page = max(1, page)
    page_size = min(500, max(50, page_size))
    filters = {
        "收件": ("event_type=?", ("收件",)), "发件": ("event_type=?", ("发件",)),
        "拒收": ("event_type IN (?,?)", ("已有邮箱邮件被拒", "无效邮箱投递")),
        "valid-rejected": ("event_type=?", ("已有邮箱邮件被拒",)),
        "invalid-recipient": ("event_type=?", ("无效邮箱投递",)),
        "外发失败": ("event_type=?", ("外发失败",)),
        "spoofed": ("event_type LIKE ?", ("匿名冒充公司域%",)),
        "system": ("event_type LIKE ?", ("系统退信%",)),
        "anomaly": ("event_type LIKE ?", ("异常发件人%",)),
    }
    clause, args = filters.get(event_filter, ("1=1", ()))
    with database() as connection:
        total = connection.execute(f"SELECT count(*) FROM mail_events WHERE days=? AND {clause}",
                                   (days, *args)).fetchone()[0]
        rows = connection.execute(
            f"SELECT payload FROM mail_events WHERE days=? AND {clause} ORDER BY position LIMIT ? OFFSET ?",
            (days, *args, page_size, (page - 1) * page_size),
        ).fetchall()
    return {"days": days, "page": page, "pageSize": page_size, "total": total,
            "items": [json.loads(row[0]) for row in rows]}


def endpoint_ip(value):
    value = text(value).strip("[]")
    if value.startswith("[") and "]:" in value:
        return value[1:value.rfind("]")]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def is_missing_recipient(value):
    value = text(value).lower()
    return bool(re.search(
        r"5\.1\.1|5\.1\.10|recipientdoesnotexist|recipientnotfound|recipient not found|"
        r"recipientnotfound|unknown recipient|user unknown|unknown user|no such user|"
        r"resolver\.adr\.(?:recipnotfound|recipientnotfound)", value
    ))


def rejection_category(status, reason=""):
    value = f"{text(status)} {text(reason)}".lower()
    if is_missing_recipient(value):
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


def analyze_dashboard(days):
    if not COMPANY_DOMAIN or not TRUSTED_EXCHANGE_IPS:
        raise RuntimeError("COMPANY_DOMAIN and TRUSTED_EXCHANGE_IP/TRUSTED_EXCHANGE_IPS are required")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    tracking = log_files("MessageTracking", cutoff)
    trusted = set()
    for row, stamp, _ in read_rows("MessageTracking", cutoff):
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

    for row, stamp, source_path in read_rows("MessageTracking", cutoff):
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
    for row, stamp, source_path in read_rows("AgentLog", cutoff):
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
        if is_company_sender(sender) and endpoint_ip(remote) not in TRUSTED_EXCHANGE_IPS:
            kind = "匿名冒充公司域（已拒收）"
        elif is_missing_recipient(f"{response} {reason}"):
            kind = "无效邮箱投递"
        else:
            kind = "已有邮箱邮件被拒"
        category = "外部连接冒充公司域发件人" if kind.startswith("匿名冒充") else rejection_category(response or action, reason)
        records.append(item(stamp, kind, sender, recipient, remote,
                            "", response or action, reason, "AgentLog", category,
                            row.get("Agent"), node_name))

    protocol_files = log_files("ProtocolLog/SmtpReceive", cutoff)
    sessions = {}
    for row, stamp, source_path in read_rows("ProtocolLog/SmtpReceive", cutoff):
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
        if is_company_sender(sender) and endpoint_ip(remote) not in TRUSTED_EXCHANGE_IPS:
            kind = "匿名冒充公司域（已拒收）"
        elif is_missing_recipient(f"{data} {row.get('context')}"):
            kind = "无效邮箱投递"
        else:
            kind = "已有邮箱邮件被拒"
        category = "外部连接冒充公司域发件人" if kind.startswith("匿名冒充") else rejection_category(data, row.get("context"))
        records.append(item(stamp, kind, sender, state.get("recipient"),
                            remote, "", data, row.get("context"), "SmtpReceive", category,
                            row.get("connector-id"), node_name))

    records = merge_rejection_records(records)
    records.sort(key=lambda row: row["time"], reverse=True)
    if len(records) > MAX_ROWS:
        records = records[:MAX_ROWS]
    counts = {
        "inbound": sum(r["type"] == "收件" for r in records),
        "outbound": sum(r["type"] == "发件" for r in records),
        "rejected": sum(r["type"] in ("已有邮箱邮件被拒", "无效邮箱投递") for r in records),
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
                      "rejected": sum(r["type"] in ("已有邮箱邮件被拒", "无效邮箱投递") for r in subset),
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
                           "rejected": sum(r["type"] in ("已有邮箱邮件被拒", "无效邮箱投递") for r in subset),
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
                       "nodes": [node["name"] for node in EDGE_NODES],
                       "analyzerVersion": ANALYZER_VERSION},
            "files": {"tracking": len(tracking), "agent": len(agent_files), "protocol": len(protocol_files)},
            "trustedMessages": len(trusted), "counts": counts, "daily": daily, "hourly": hourly,
            "sync": {"mode": "sftp" if any(node["host"] for node in EDGE_NODES) else "mount",
                     "lastSuccess": datetime.fromtimestamp(last_success, timezone.utc).isoformat() if last_success else "",
                     "newestRecord": newest_record, "intervalSeconds": SFTP_SYNC_SECONDS,
                     "nodes": node_status},
            "index": dict(_index_state),
            "items": records}


def empty_dashboard(days):
    local_now = datetime.now().astimezone()
    daily = [{"date": (local_now - timedelta(days=offset)).date().isoformat(),
              "inbound": 0, "outbound": 0, "rejected": 0, "spoofed": 0}
             for offset in range(days - 1, -1, -1)]
    hourly = []
    if days == 1:
        hour_now = local_now.replace(minute=0, second=0, microsecond=0)
        hourly = [{"time": (hour_now - timedelta(hours=offset)).isoformat(),
                   "label": (hour_now - timedelta(hours=offset)).strftime("%H:00"),
                   "inbound": 0, "outbound": 0, "rejected": 0, "spoofed": 0}
                  for offset in range(23, -1, -1)]
    return {"generatedAt": datetime.now(timezone.utc).isoformat(), "days": days,
            "config": {"domain": COMPANY_DOMAIN, "trustedIps": sorted(TRUSTED_EXCHANGE_IPS),
                       "nodes": [node["name"] for node in EDGE_NODES],
                       "analyzerVersion": ANALYZER_VERSION},
            "files": {"tracking": 0, "agent": 0, "protocol": 0}, "trustedMessages": 0,
            "counts": {"inbound": 0, "outbound": 0, "rejected": 0, "failed": 0,
                       "systemNdr": 0, "anomaly": 0, "spoofed": 0},
            "daily": daily, "hourly": hourly,
            "sync": {"mode": "sftp" if any(node["host"] for node in EDGE_NODES) else "mount",
                     "lastSuccess": "", "newestRecord": "", "intervalSeconds": SFTP_SYNC_SECONDS,
                     "nodes": []}, "totalEvents": 0}


def dashboard(days):
    now = time.time()
    with _cache_lock:
        cached = _cache.get(days)
        if cached and now - cached[0] < CACHE_SECONDS:
            return cached[1]
    with _build_lock:
        now = time.time()
        with _cache_lock:
            cached = _cache.get(days)
            if cached and now - cached[0] < CACHE_SECONDS:
                return cached[1]
        with database() as connection:
            row = connection.execute("SELECT payload FROM dashboard_snapshots WHERE days=?", (days,)).fetchone()
        result = json.loads(row[0]) if row else empty_dashboard(days)
        expected_config = {"domain": COMPANY_DOMAIN, "trustedIps": sorted(TRUSTED_EXCHANGE_IPS),
                           "nodes": [node["name"] for node in EDGE_NODES],
                           "analyzerVersion": ANALYZER_VERSION}
        if result.get("config") != expected_config:
            result = empty_dashboard(days)
        result["generatedAt"] = datetime.now(timezone.utc).isoformat()
        result["index"] = dict(_index_state)
        with _cache_lock:
            _cache[days] = (time.time(), result)
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
                states = [{"name": node["name"], "logRootExists": node["localRoot"].is_dir(),
                           "online": (bool(_sync_state[node["name"]]["lastSuccess"]) if node["host"] else node["localRoot"].is_dir()) and not _sync_state[node["name"]]["lastError"],
                           "error": _sync_state[node["name"]]["lastError"]} for node in EDGE_NODES]
                ok = any(state["online"] for state in states)
                return self.send_json({"status": "ok" if ok else "error", "nodes": states,
                                       "mode": "sftp" if any(node["host"] for node in EDGE_NODES) else "mount",
                                       "index": dict(_index_state)}, 200 if ok else 503)
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
        if parsed.path == "/api/logs":
            try:
                query = parse_qs(parsed.query)
                days = int(query.get("days", ["1"])[0])
                page = int(query.get("page", ["1"])[0])
                page_size = int(query.get("pageSize", ["500"])[0])
                if days not in (1, 7, 30):
                    raise ValueError
                return self.send_json(raw_log_page(days, page, page_size))
            except ValueError:
                return self.send_json({"error": "invalid days, page or pageSize"}, 400)
            except Exception as exc:
                return self.send_json({"error": str(exc)}, 500)
        if parsed.path == "/api/log-detail":
            try:
                query = parse_qs(parsed.query)
                return self.send_json(raw_log_details(query.get("id", [])))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            except Exception as exc:
                return self.send_json({"error": str(exc)}, 500)
        if parsed.path == "/api/events":
            try:
                query = parse_qs(parsed.query)
                days = int(query.get("days", ["1"])[0])
                page = int(query.get("page", ["1"])[0])
                page_size = int(query.get("pageSize", ["200"])[0])
                event_filter = query.get("type", [""])[0]
                if days not in (1, 7, 30):
                    raise ValueError
                return self.send_json(event_page(days, page, page_size, event_filter))
            except ValueError:
                return self.send_json({"error": "invalid days, page or pageSize"}, 400)
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
    threading.Thread(target=background_index_loop, name="log-indexer", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
