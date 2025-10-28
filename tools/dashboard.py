"""Simple web dashboard for the IS-Lab E2EE demo.

Run with:
    python -m tools.dashboard --port 8080
Then open http://localhost:8080/ to inspect live traffic.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_PATHS: Tuple[Path, ...] = (
    PROJECT_ROOT / "malory_logs" / "intercepted_messages.json",
    PROJECT_ROOT / "src" / "network" / "malory_logs" / "intercepted_messages.json",
)

INDEX_HTML = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<title>E2EE Demo Dashboard</title>
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
<style>
body { font-family: system-ui, sans-serif; margin: 0; background: #111827; color: #e5e7eb; }
header { padding: 1.5rem; background: #1f2937; display: flex; flex-wrap: wrap; align-items: baseline; gap: 1rem; }
h1 { margin: 0; font-size: 1.6rem; }
section { padding: 1.5rem; }
.card { background: #1f2937; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 15px 35px rgba(15, 23, 42, 0.45); }
.card h2 { margin-top: 0; font-size: 1.2rem; color: #a855f7; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
th, td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #374151; text-align: left; }
th { color: #f3f4f6; background: #312e81; position: sticky; top: 0; }
tr:nth-child(even) { background: #111827; }
.badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 999px; font-size: 0.75rem; background: #2563eb; color: white; }
.tag { display: inline-block; padding: 0.15rem 0.45rem; margin-right: 0.3rem; border-radius: 0.5rem; font-size: 0.75rem; background: #374151; color: #f9fafb; }
#status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-top: 1rem; }
.status-card { background: #111827; border-radius: 0.75rem; padding: 1rem 1.2rem; border: 1px solid rgba(129, 140, 248, 0.25); }
.status-card h3 { margin: 0 0 0.4rem; font-size: 0.95rem; color: #c4b5fd; }
.status-card span { font-size: 1.6rem; }
small { color: #9ca3af; }
button { background: #111827; color: #f3f4f6; border: 1px solid rgba(148, 163, 184, 0.4); border-radius: 0.5rem; padding: 0.4rem 0.9rem; cursor: pointer; }
button:hover { background: #312e81; border-color: #c084fc; color: white; }
#message-table-wrapper { max-height: 420px; overflow-y: auto; margin-top: 1rem; }
.notice { padding: 0.75rem 1rem; border-radius: 0.5rem; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.4); color: #bfdbfe; }
.error { background: rgba(248, 113, 113, 0.12); border-color: rgba(248, 113, 113, 0.5); color: #fecaca; }
</style>
</head>
<body>
<header>
  <h1>IS-Lab E2EE Demo Dashboard</h1>
  <div><button id=\"refresh-button\">Refresh now</button> <small id=\"last-refresh\"></small></div>
</header>
<section>
  <div class=\"card\">
    <h2>Live Status</h2>
    <div id=\"status-grid\"></div>
    <div id=\"status-message\" class=\"notice\" style=\"display:none; margin-top:1rem;\"></div>
  </div>
  <div class=\"card\">
    <h2>Intercepted Messages</h2>
    <div class=\"notice\" id=\"sealed-hint\">Sealed sender traffic will show sender hints (e.g., sealed:xxxx). Bob can decrypt envelopes to reveal identities; the server cannot.</div>
    <div id=\"message-table-wrapper\">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Timestamp</th>
            <th>From → To</th>
            <th>Seq</th>
            <th>Message ID</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody id=\"message-body\"></tbody>
      </table>
    </div>
  </div>
</section>
<script>
const statusGrid = document.getElementById('status-grid');
const statusMessage = document.getElementById('status-message');
const messageBody = document.getElementById('message-body');
const lastRefresh = document.getElementById('last-refresh');
const refreshButton = document.getElementById('refresh-button');

function formatTimestamp(ts) {
  if (!ts) return '—';
  const date = new Date(ts);
  return date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'}) + '\n' + date.toLocaleDateString();
}

function renderStatus(data) {
  statusGrid.innerHTML = '';
  const entries = [
    ['Total Messages', data.total_messages],
    ['Unique Senders', data.unique_senders],
    ['Recipients', data.unique_recipients],
    ['Sealed Messages', data.sealed_count],
    ['Last Message Age', data.last_message_age_human || '—']
  ];
  entries.forEach(([label, value]) => {
    const card = document.createElement('div');
    card.className = 'status-card';
    card.innerHTML = `<h3>${label}</h3><span>${value ?? '—'}</span>`;
    statusGrid.appendChild(card);
  });
  if (data.notice) {
    statusMessage.style.display = 'block';
    statusMessage.textContent = data.notice;
  } else {
    statusMessage.style.display = 'none';
  }
}

function renderMessages(messages) {
  messageBody.innerHTML = '';
  if (!messages.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.textContent = 'No messages intercepted yet.';
    tr.appendChild(td);
    messageBody.appendChild(tr);
    return;
  }
  messages.forEach((msg, idx) => {
    const tr = document.createElement('tr');
    const flagBadges = [];
    if (msg.sealed_sender) flagBadges.push('<span class="badge">sealed</span>');
    if (msg.metadata?.encryption_algorithm) flagBadges.push(`<span class="tag">${msg.metadata.encryption_algorithm}</span>`);
    const fields = [
      messages.length - idx,
      formatTimestamp(msg.timestamp_ms),
      `${msg.sender_label} → ${msg.to || '—'}`,
      msg.sequence_number ?? '—',
      msg.message_id || '—',
      flagBadges.join(' ')
    ];
    fields.forEach(value => {
      const td = document.createElement('td');
      td.innerHTML = value;
      tr.appendChild(td);
    });
    messageBody.appendChild(tr);
  });
}

async function refreshAll() {
  try {
    const [statusResp, messageResp] = await Promise.all([
      fetch('/api/status').then(r => r.json()),
      fetch('/api/messages?limit=100').then(r => r.json())
    ]);
    renderStatus(statusResp);
    renderMessages(messageResp.messages || []);
    lastRefresh.textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    statusMessage.style.display = 'block';
    statusMessage.classList.add('error');
    statusMessage.textContent = `Dashboard error: ${err}`;
  }
}

refreshButton.addEventListener('click', refreshAll);
setInterval(refreshAll, 2500);
refreshAll();
</script>
</body>
</html>"""


def locate_log_file() -> Path | None:
    for candidate in LOG_PATHS:
        if candidate.exists():
            return candidate
    return None


def _sender_label(message: Dict[str, Any]) -> str:
    sender = message.get("from")
    if sender:
        return sender
    sealed = message.get("sealed_sender") or {}
    hint = sealed.get("hint")
    return f"sealed:{hint}" if hint else "sealed"


def load_messages(limit: int = 100) -> List[Dict[str, Any]]:
    log_file = locate_log_file()
    if not log_file:
        return []

    try:
        with log_file.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return []

    messages: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            messages.append(record)
        except json.JSONDecodeError:
            continue

    messages.sort(key=lambda m: m.get("timestamp", 0))
    return messages


def build_status(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(messages)
    if not total:
        return {
            "total_messages": 0,
            "unique_senders": 0,
            "unique_recipients": 0,
            "sealed_count": 0,
            "last_message_age_human": "waiting for traffic",
            "notice": "Start the server plus Alice/Bob to populate the dashboard.",
        }

    now = time.time()
    timestamps = [msg.get("timestamp", 0) for msg in messages]
    last_ts = max(timestamps)
    age_seconds = max(now - last_ts, 0)

    def human_age(seconds: float) -> str:
        if seconds < 1:
            return "<1s"
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds/60:.1f} min"
        return f"{seconds/3600:.2f} h"

    senders = {_sender_label(msg) for msg in messages}
    recipients = {msg.get("to") for msg in messages if msg.get("to")}
    sealed_count = sum(1 for msg in messages if msg.get("sealed_sender"))

    return {
        "total_messages": total,
        "unique_senders": len(senders),
        "unique_recipients": len(recipients),
        "sealed_count": sealed_count,
        "last_message_age_human": human_age(age_seconds),
        "notice": None,
    }


def format_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    formatted: List[Dict[str, Any]] = []
    for message in messages:
        timestamp = message.get("timestamp")
        timestamp_ms = timestamp * 1000 if isinstance(timestamp, (int, float)) else None
        formatted.append(
            {
                "timestamp": timestamp,
                "timestamp_ms": timestamp_ms,
                "timestamp_iso": datetime.fromtimestamp(timestamp).isoformat() if timestamp else None,
                "sender_label": _sender_label(message),
                "to": message.get("to"),
                "sequence_number": message.get("sequence_number"),
                "message_id": message.get("message_id"),
                "sealed_sender": bool(message.get("sealed_sender")),
                "metadata": message.get("metadata", {}),
            }
        )
    return formatted


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "E2EEDashboard/0.1"

    def _write_json(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http handler signature)
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/messages":
            params = parse_qs(parsed.query)
            limit = int(params.get("limit", ["100"])[0])
            limit = max(1, min(limit, 500))
            messages = load_messages(limit)
            self._write_json({"messages": format_messages(messages)})
            return
        if parsed.path == "/api/status":
            messages = load_messages(250)
            status = build_status(messages)
            self._write_json(status)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - match BaseHTTPRequestHandler
        # Quieter console output; comment out to debug requests
        return


def run_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Dashboard running on http://{host}:{port}/ (Press Ctrl+C to stop)")
    try:
        while thread.is_alive():
            thread.join(timeout=1.0)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local dashboard for the IS-Lab E2EE demo")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    args = parser.parse_args()

    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
