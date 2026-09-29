#!/usr/bin/env python3
"""W3 supplied inspection-service prototype; extend routes in later Sprints."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import urlsplit


MAX_EVENT_BYTES = 4096
EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
REQUIRED_EVENT_FIELDS = ("event_id", "device_id", "observed_at", "type")
ALLOWED_EVENT_FIELDS = set(REQUIRED_EVENT_FIELDS) | {"note"}
EVENT_TYPES = {"status", "anomaly", "test"}
AUTH_FILE = Path("/etc/inspection/app.env")


def read_tokens(path=None):
    if path is None:
        values = {key: os.environ.get(key, "") for key in
                  ("REPORTER_TOKEN", "OPERATOR_TOKEN")}
    else:
        values = {}
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key in {"REPORTER_TOKEN", "OPERATOR_TOKEN"}:
                    values[key] = value
        except OSError:
            pass
    reporter = values.get("REPORTER_TOKEN", "")
    operator = values.get("OPERATOR_TOKEN", "")
    configured = bool(reporter and operator and not hmac.compare_digest(reporter, operator))
    return {"reporter": reporter, "operator": operator}, configured


def validate_event(value):
    if not isinstance(value, dict):
        return None, {"error": "expected_object", "field": "body"}
    extra = sorted(set(value) - ALLOWED_EVENT_FIELDS)
    if extra:
        return None, {"error": "unexpected_field", "field": extra[0]}
    for field in REQUIRED_EVENT_FIELDS:
        if field not in value:
            return None, {"error": "required", "field": field}
    if not isinstance(value["event_id"], str) or not EVENT_ID_PATTERN.fullmatch(value["event_id"]):
        return None, {"error": "invalid_format", "field": "event_id"}
    if not isinstance(value["device_id"], str) or not DEVICE_ID_PATTERN.fullmatch(value["device_id"]):
        return None, {"error": "invalid_format", "field": "device_id"}
    if not isinstance(value["observed_at"], str):
        return None, {"error": "invalid_datetime", "field": "observed_at"}
    try:
        observed = datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    except ValueError:
        return None, {"error": "invalid_datetime", "field": "observed_at"}
    if observed.tzinfo is None or observed.utcoffset() is None:
        return None, {"error": "timezone_required", "field": "observed_at"}
    if not isinstance(value["type"], str) or value["type"] not in EVENT_TYPES:
        return None, {"error": "invalid_choice", "field": "type"}
    if "note" in value and (not isinstance(value["note"], str) or len(value["note"]) > 200):
        return None, {"error": "invalid_note", "field": "note"}
    return dict(value), None


def make_server(version_file, port=8080, auth_file=None):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    tokens, auth_configured = read_tokens(auth_file)
    events = {}
    events_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def send_json(self, status, body):
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def send_error_json(self, status, error, field):
            self.send_json(status, {"error": error, "field": field})

        def authenticated_role(self):
            authorization = self.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                return None
            supplied = authorization[7:]
            for role in ("reporter", "operator"):
                expected = tokens[role]
                if expected and hmac.compare_digest(supplied, expected):
                    return role
            return None

        def require_role(self, expected_role):
            role = self.authenticated_role()
            if role is None:
                self.send_error_json(401, "unauthorized", "authorization")
                return False
            if role != expected_role:
                self.send_error_json(403, "forbidden", "authorization")
                return False
            return True

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                self.send_json(200, {"status": "ok", "service": "inspection", "version": version,
                                     "started_at": started, "auth_configured": auth_configured})
                return
            if path == "/":
                data = DISPLAY_PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            if path == "/events":
                if not self.require_role("operator"):
                    return
                with events_lock:
                    latest = list(events.values())[-50:][::-1]
                self.send_json(200, {"events": latest})
                return
            if path.startswith("/events/"):
                if not self.require_role("operator"):
                    return
                event_id = path.removeprefix("/events/")
                with events_lock:
                    event = events.get(event_id)
                if event is None:
                    self.send_error_json(404, "not_found", "event_id")
                else:
                    self.send_json(200, event)
                return
            self.send_json(404, {"error": "not_found", "field": "path"})

        def do_POST(self):
            if urlsplit(self.path).path != "/events":
                self.send_error_json(404, "not_found", "path")
                return
            if not self.require_role("reporter"):
                return
            if self.headers.get_content_type() != "application/json":
                self.send_error_json(400, "content_type_must_be_application_json", "content_type")
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.send_error_json(400, "invalid_content_length", "content_length")
                return
            if length < 0 or length > MAX_EVENT_BYTES:
                self.send_error_json(400, "body_too_large_or_invalid_length", "body")
                return
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.send_error_json(400, "invalid_json", "body")
                return
            event, error = validate_event(value)
            if error:
                self.send_json(400, error)
                return
            with events_lock:
                if event["event_id"] in events:
                    self.send_error_json(409, "duplicate_event_id", "event_id")
                    return
                event["received_at"] = datetime.now(timezone.utc).isoformat(
                    timespec="seconds").replace("+00:00", "Z")
                events[event["event_id"]] = event
            self.send_json(201, event)

        def log_message(self, fmt, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


DISPLAY_PAGE = """<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>巡檢事件</title><style>
body{font:16px/1.5 sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#17212b;background:#f3f6f8}
h1{font-size:1.6rem}form{display:flex;gap:.5rem;flex-wrap:wrap}input{flex:1;min-width:15rem;padding:.7rem;border:1px solid #9aa8b2;border-radius:4px}
button{padding:.7rem 1rem;border:0;border-radius:4px;background:#145c63;color:white;cursor:pointer}
li{padding:.8rem 0;border-bottom:1px solid #ccd5da;overflow-wrap:anywhere}pre{white-space:pre-wrap;margin:.25rem 0}
#message{min-height:1.5em}
</style></head><body><main><h1>巡檢事件</h1>
<form id="load-form"><label for="operator-token">Operator 權杖</label><input id="operator-token" type="password" autocomplete="off" required>
<button type="submit">讀取事件</button></form><p id="message" role="status"></p><ol id="events"></ol>
<script>
const form=document.querySelector('#load-form');
const tokenInput=document.querySelector('#operator-token');
const message=document.querySelector('#message');
const list=document.querySelector('#events');
form.addEventListener('submit',async(event)=>{
  event.preventDefault();
  const token=tokenInput.value;
  tokenInput.value='';
  message.textContent='讀取中…';
  list.replaceChildren();
  try{
    const response=await fetch('/events',{headers:{Authorization:'Bearer '+token}});
    const data=await response.json();
    if(!response.ok){message.textContent=data.error||'讀取失敗';return;}
    message.textContent='共 '+data.events.length+' 筆';
    for(const item of data.events){
      const row=document.createElement('li');
      const content=document.createElement('pre');
      content.textContent=JSON.stringify(item,null,2);
      row.append(content);
      list.append(row);
    }
  }catch(_error){message.textContent='連線失敗';}
});
</script></main></body></html>"""


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
