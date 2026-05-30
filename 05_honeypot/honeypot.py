"""
Project 5 — SSH / HTTP Honeypot + Live Dashboard
Listens on fake SSH (port 2222) and HTTP (port 8080), logs every attacker.
Dashboard lives at http://127.0.0.1:5001
Dependencies: pip install paramiko flask requests
Run: python honeypot.py
"""

import socket, sqlite3, threading, time, logging
from datetime import datetime

import paramiko
from flask import Flask, request, jsonify, render_template_string

DB = "honeypot.db"
logging.basicConfig(level=logging.WARNING)   # suppress paramiko noise


# ── Database ──────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      TEXT,
        service TEXT,
        src_ip  TEXT,
        country TEXT,
        detail  TEXT
    )""")
    con.commit()
    con.close()


def log_event(service: str, src_ip: str, detail: str):
    country = geo_lookup(src_ip)
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO events(ts,service,src_ip,country,detail) VALUES(?,?,?,?,?)",
        (datetime.now().isoformat(), service, src_ip, country, detail)
    )
    con.commit()
    con.close()
    print(f"[{service}] {src_ip} ({country}) — {detail[:80]}")


def geo_lookup(ip: str) -> str:
    try:
        import requests as req
        r = req.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        return r.json().get("country", "??")
    except Exception:
        return "??"


# ── SSH Honeypot ──────────────────────────────────────────
class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str):
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        log_event("SSH", self.client_ip, f"cred attempt: {username}/{password}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def ssh_handler(client_sock, client_addr):
    try:
        key = paramiko.RSAKey.generate(2048)
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(key)
        transport.start_server(server=FakeSSHServer(client_addr[0]))
        time.sleep(5)
    except Exception:
        pass
    finally:
        client_sock.close()


def run_ssh_honeypot(port: int = 2222):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    print(f"[*] SSH honeypot listening on port {port}")
    while True:
        client, addr = srv.accept()
        threading.Thread(target=ssh_handler, args=(client, addr), daemon=True).start()


# ── HTTP Honeypot ─────────────────────────────────────────
http_app = Flask("honeypot_http")

@http_app.route("/", defaults={"path": ""})
@http_app.route("/<path:path>")
def catch_all(path):
    detail = f"GET /{path}  UA:{request.headers.get('User-Agent','')[:60]}"
    log_event("HTTP", request.remote_addr, detail)
    return "<h1>404 Not Found</h1>", 404


# ── Dashboard ─────────────────────────────────────────────
dash_app = Flask("dashboard")

DASH_HTML = """<!DOCTYPE html><html><head><title>Honeypot Dashboard</title>
<style>
  body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}
  h1{color:#58a6ff}
  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{border:1px solid #30363d;padding:8px;text-align:left}
  th{background:#161b22}
  tr:nth-child(even){background:#111820}
  tr:hover{background:#1c2128}
  .ssh{color:#79c0ff}.http{color:#56d364}
</style></head><body>
<h1>🍯 Honeypot Dashboard</h1>
<p>Total events: <b>{{ total }}</b> &nbsp;|&nbsp;
   <a href="/api/events" style="color:#58a6ff">JSON API</a></p>
<table>
  <tr><th>Time</th><th>Service</th><th>IP</th><th>Country</th><th>Detail</th></tr>
  {% for e in events %}
  <tr>
    <td>{{ e[1][:19] }}</td>
    <td class="{{ e[2]|lower }}">{{ e[2] }}</td>
    <td>{{ e[3] }}</td>
    <td>{{ e[4] }}</td>
    <td>{{ e[5][:90] }}</td>
  </tr>
  {% endfor %}
</table>
</body></html>"""

@dash_app.route("/")
def dashboard():
    con   = sqlite3.connect(DB)
    rows  = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    con.close()
    return render_template_string(DASH_HTML, events=rows, total=total)

@dash_app.route("/api/events")
def api_events():
    con  = sqlite3.connect(DB)
    rows = con.execute(
        "SELECT ts,service,src_ip,country,detail FROM events ORDER BY id DESC LIMIT 500"
    ).fetchall()
    con.close()
    keys = ["ts", "service", "src_ip", "country", "detail"]
    return jsonify([dict(zip(keys, r)) for r in rows])


# ── Entry point ───────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    threading.Thread(target=run_ssh_honeypot, daemon=True).start()
    threading.Thread(
        target=lambda: http_app.run(port=8080, use_reloader=False),
        daemon=True
    ).start()
    print("[*] HTTP honeypot on port 8080")
    print("[*] Dashboard → http://127.0.0.1:5001")
    dash_app.run(port=5001, use_reloader=False)
