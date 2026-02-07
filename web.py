# web.py — Gproxy Web Panel (FastAPI) ✅ Admin password + Client magic link
# SaaS premium UI + Admin sexxy + Client portal
# - Admin login con clave (cookie segura)
# - Clientes entran con link mágico /c/{token} (cookie segura)
# - Lee la misma DB sqlite (data.db)
# - Panel admin + mantenimiento ON/OFF + mensaje personalizado
# - Outbox opcional: el bot.py puede leer y mandar broadcast

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
from typing import Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

# =========================
# CONFIG (Railway Variables)
# =========================
DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")                 # EJ: "MiClaveSuperFuerte"
JWT_SECRET = os.getenv("JWT_SECRET", "change_me_admin")          # secreto largo random
import os
import secrets

# =========================
# CLIENT SECRET (Seguro)
# =========================
# 1️⃣ Intenta leer de ENV (Railway / Vercel / Docker / etc)
_client_secret_env = os.getenv("CLIENT_SECRET")

# 2️⃣ Si no existe o está en default inseguro → genera uno seguro
if not _client_secret_env or _client_secret_env.strip() in ("", "change_me_client"):
    CLIENT_SECRET = secrets.token_urlsafe(64)  # 🔐 ~384 bits
    print("⚠️ CLIENT_SECRET no estaba definido. Se generó uno temporal seguro.")
else:
    CLIENT_SECRET = _client_secret_env.strip()


APP_TITLE = os.getenv("APP_TITLE", "Gproxy")
ENABLE_OUTBOX = os.getenv("ENABLE_OUTBOX", "1").strip() == "1"

# =========================
# APP (IMPORTANT: 'app' MUST EXIST)
# =========================
app = FastAPI(title=APP_TITLE)

# =========================
# DB helpers
# =========================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def ensure_web_schema():
    conn = db()
    cur = conn.cursor()

    # settings
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    # outbox (optional)
    if ENABLE_OUTBOX:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT NOT NULL DEFAULT ''
            )
            """
        )

    # defaults
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("maintenance_enabled", "0", now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("maintenance_message", "⚠️ Estamos en mantenimiento. Vuelve en unos minutos.", now_str()),
    )

    conn.commit()
    conn.close()


ensure_web_schema()


def get_setting(key: str, default: str = "") -> str:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cur.fetchone()
    conn.close()
    return (row["value"] if row else default) or default


def set_setting(key: str, value: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now_str()),
    )
    conn.commit()
    conn.close()


def outbox_add(kind: str, message: str):
    if not ENABLE_OUTBOX:
        return
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO outbox(kind,message,created_at,sent_at) VALUES(?,?,?,?)",
        (kind, message or "", now_str(), ""),
    )
    conn.commit()
    conn.close()


# =========================
# Token (HMAC signed)
# =========================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64urldecode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def sign(payload: Dict[str, Any], secret: str, exp_seconds: int = 3600) -> str:
    p = dict(payload)
    p["exp"] = int(time.time()) + int(exp_seconds)
    raw = json.dumps(p, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64url(raw)}.{_b64url(sig)}"


def verify(token: str, secret: str) -> Dict[str, Any]:
    """
    Verifica token tipo: base64url(payload_json).base64url(hmac_sha256(payload_json))
    - Acepta "Bearer <token>"
    - Valida formato, firma, JSON y expiración
    - Lanza HTTPException(401) con detalle específico
    """
    try:
        if not token:
            raise HTTPException(status_code=401, detail="No autorizado")

        t = (token or "").strip()
        if t.lower().startswith("bearer "):
            t = t.split(" ", 1)[1].strip()

        parts = t.split(".")
        if len(parts) != 2:
            raise HTTPException(status_code=401, detail="Token inválido")

        a, b = parts[0], parts[1]

        try:
            raw = _b64urldecode(a)
            sig = _b64urldecode(b)
        except Exception:
            raise HTTPException(status_code=401, detail="Token inválido")

        good = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            raise HTTPException(status_code=401, detail="Firma inválida")

        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=401, detail="Token inválido")

        exp = int(payload.get("exp", 0) or 0)
        if exp <= 0 or exp < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expirado")

        return payload

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="No autorizado")


# =========================
# Auth guards
# =========================
def require_admin(request: Request) -> Dict[str, Any]:
    tok = request.cookies.get("admin_session", "")
    payload = verify(tok, JWT_SECRET)
    if payload.get("role") != "admin":
        raise HTTPException(401, "No autorizado")
    return payload


def require_client(request: Request) -> Dict[str, Any]:
    tok = request.cookies.get("client_session", "")
    payload = verify(tok, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")
    return payload


# =========================
# UI helpers
# =========================
def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def page(title: str, body: str, subtitle: str = "") -> str:
    t = html_escape(title)
    st = html_escape(subtitle)
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{t}</title>

  <style>
    :root {{
      --bg1:#070019;
      --bg2:#14002e;
      --bg3:#24003f;
      --card: rgba(255,255,255,.06);
      --card2: rgba(255,255,255,.08);
      --border: rgba(255,255,255,.10);
      --muted:#cbb6ff;
      --text:#ffffff;
      --p1:#7b00ff;
      --p2:#c400ff;
      --p3:#00d4ff;
      --ok:#2bff9a;
      --warn:#ffb020;
      --bad:#ff4d6d;
      --shadow: 0 18px 60px rgba(0,0,0,.45);
    }}

    * {{ box-sizing:border-box; }}
    body {{
      margin:0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
      color:var(--text);
      background:
        radial-gradient(1200px 500px at 10% 10%, rgba(196,0,255,.25), transparent 60%),
        radial-gradient(1000px 600px at 90% 20%, rgba(0,212,255,.18), transparent 55%),
        radial-gradient(900px 700px at 40% 90%, rgba(123,0,255,.18), transparent 60%),
        linear-gradient(135deg, var(--bg1), var(--bg2), var(--bg3));
      min-height:100vh;
      overflow-x:hidden;
    }}

    .noise {{
      position:fixed; inset:0;
      pointer-events:none;
      opacity:.06;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='.6'/%3E%3C/svg%3E");
    }}

    .wrap {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px 18px 60px;
    }}

    .topbar {{
      display:flex; justify-content:space-between; align-items:center;
      gap:14px; margin-bottom:14px;
    }}

    .brand {{
      display:flex; align-items:center; gap:12px;
    }}

    .logo {{
      width:44px; height:44px; border-radius:14px;
      background: linear-gradient(45deg, var(--p1), var(--p2));
      box-shadow: 0 0 30px rgba(196,0,255,.35);
      display:flex; align-items:center; justify-content:center;
      position:relative; overflow:hidden;
    }}

    .logo:before {{
      content:"";
      position:absolute; inset:-40%;
      background: conic-gradient(from 180deg, rgba(255,255,255,.0), rgba(255,255,255,.35), rgba(255,255,255,.0));
      animation: spin 4s linear infinite;
    }}

    .logo span {{
      position:relative;
      font-weight:900;
      letter-spacing:.5px;
    }}

    @keyframes spin {{
      to {{ transform: rotate(360deg); }}
    }}

    .title {{
      font-size: 18px;
      font-weight: 800;
      letter-spacing: .2px;
      margin:0;
    }}

    .subtitle {{
      margin:0;
      color: var(--muted);
      font-size: 13px;
    }}

    .chip {{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      animation: floaty 5s ease-in-out infinite;
      white-space:nowrap;
    }}

    @keyframes floaty {{
      0%,100% {{ transform: translateY(0); }}
      50% {{ transform: translateY(-4px); }}
    }}

    .grid {{
      display:grid;
      grid-template-columns: 1.4fr .9fr;
      gap: 16px;
    }}

    @media (max-width: 980px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}

    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 18px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
      animation: pop .35s ease both;
    }}

    @keyframes pop {{
      from {{ transform: translateY(6px); opacity:0; }}
      to {{ transform: translateY(0); opacity:1; }}
    }}

    .row {{
      display:flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items:center;
    }}

    .btn {{
      appearance:none;
      border: none;
      border-radius: 14px;
      padding: 12px 16px;
      font-weight: 750;
      color: white;
      text-decoration:none;
      cursor:pointer;
      background: linear-gradient(45deg, var(--p1), var(--p2));
      box-shadow: 0 12px 30px rgba(123,0,255,.22);
      transition: transform .15s ease, box-shadow .15s ease, filter .15s ease;
      display:inline-flex; align-items:center; gap:10px;
    }}

    .btn:hover {{
      transform: translateY(-2px);
      box-shadow: 0 16px 38px rgba(196,0,255,.30);
      filter: brightness(1.03);
    }}

    .btn.ghost {{
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      box-shadow: none;
    }}

    .btn.ghost:hover {{
      box-shadow: 0 12px 30px rgba(0,0,0,.22);
    }}

    .kpi {{
      font-size: 34px;
      font-weight: 900;
      letter-spacing: .3px;
      margin-top: 6px;
      background: linear-gradient(90deg, #fff, #e9dbff, #b9f2ff);
      -webkit-background-clip:text;
      background-clip:text;
      color: transparent;
    }}

    .muted {{ color: var(--muted); font-size: 13px; }}
    .hr {{
      height:1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent);
      margin: 14px 0;
    }}

    input, textarea {{
      width:100%;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.20);
      color: white;
      outline:none;
    }}

    textarea {{ min-height: 120px; }}

    table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:14px; }}
    th, td {{
      border-bottom: 1px solid rgba(255,255,255,.10);
      padding: 12px;
      text-align:left;
      font-size: 13px;
    }}
    th {{ color:#f0eaff; font-weight:800; }}

    pre, code {{
      background: rgba(0,0,0,.25);
      border: 1px solid rgba(255,255,255,.10);
      border-radius: 14px;
      padding: 12px;
      overflow:auto;
    }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}

    .status {{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding: 10px 12px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(255,255,255,.06);
    }}
    .dot {{
      width:10px; height:10px; border-radius:50%;
      background: var(--ok);
      box-shadow: 0 0 16px rgba(43,255,154,.35);
    }}
    .dot.warn {{
      background: var(--warn);
      box-shadow: 0 0 16px rgba(255,176,32,.35);
    }}

    .footer {{
      margin-top: 16px;
      color: rgba(255,255,255,.55);
      font-size: 12px;
      text-align:center;
    }}

    .hero {{
      padding: 18px;
      border-radius: 20px;
      background: linear-gradient(135deg, rgba(123,0,255,.18), rgba(0,212,255,.10));
      border: 1px solid rgba(255,255,255,.10);
    }}
    .hero h1 {{
      margin:0 0 8px 0;
      font-size: 26px;
      letter-spacing:.2px;
    }}
    .hero p {{
      margin:0;
      color: rgba(255,255,255,.78);
      line-height:1.5;
    }}
    .pill {{
      display:inline-flex;
      gap:8px;
      padding: 8px 10px;
      border-radius: 999px;
      border:1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.18);
      font-size: 12px;
      color: rgba(255,255,255,.85);
    }}
  </style>
</head>

<body>
  <div class="noise"></div>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"><span>G</span></div>
        <div>
          <p class="title">{t}</p>
          <p class="subtitle">{st}</p>
        </div>
      </div>
      <div class="chip">🛡️ Proxies USA • Privadas • Estables</div>
    </div>
    {body}
    <div class="footer">© {html_escape(APP_TITLE)} • Web Panel</div>
  </div>
</body>
</html>"""


# =========================
# Public
# =========================
@app.get("/", response_class=HTMLResponse)
def home():
    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    status = "🟠 Mantenimiento" if maint else "🟢 Online"
    dot_class = "warn" if maint else ""

    body = f"""
    <div class="grid">
      <div class="card hero">
        <div class="pill">⚡ Activación rápida</div>
        <div class="pill" style="margin-left:8px;">🔒 Conexión privada</div>
        <div class="pill" style="margin-left:8px;">📩 Soporte directo</div>
        <div style="height:12px;"></div>

        <h1>Gproxy — Panel Web</h1>
        <p>
          Plataforma de proxies USA 🇺🇸 para automatización, cuentas, bots y trabajo online.
          Administra tu estado, monitorea pedidos y mantén tu servicio activo con recordatorios.
        </p>
        <div class="hr"></div>

        <div class="row">
          <a class="btn" href="/admin/login">🔐 Admin</a>
          <a class="btn ghost" href="/client">👤 Clientes</a>
        </div>
      </div>

      <div class="card">
        <div class="muted">Estado del sistema</div>
        <div class="kpi">{status}</div>
        <div class="status" style="margin-top:10px;">
          <span class="dot {dot_class}"></span>
          <span>{html_escape(mtxt) if maint else "Todo funcionando perfecto."}</span>
        </div>

        <div class="hr"></div>
        <div class="muted">Acceso de clientes</div>
        <p style="margin:8px 0 0 0; color: rgba(255,255,255,.78);">
          Entra con el link mágico enviado por el bot: <code>/c/TOKEN</code>
        </p>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="SaaS moderno • Panel Admin & Cliente")


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH}


# =========================
# Admin Auth
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Admin Access</h1>
        <p>Entra al panel premium para gestionar usuarios, ver métricas y activar mantenimiento con broadcast.</p>
        <div class="hr"></div>
        <div class="pill">🧠 Control</div>
        <div class="pill" style="margin-left:8px;">📊 Métricas</div>
        <div class="pill" style="margin-left:8px;">🛠 Mantenimiento</div>
      </div>

      <div class="card">
        <form method="post" action="/admin/login">
          <label class="muted">Clave Admin</label><br/>
          <input type="password" name="password" placeholder="Tu clave admin" />
          <div style="height:12px;"></div>
          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>
        <div class="hr"></div>
        <p class="muted">
          Variables Railway: <code>ADMIN_PASSWORD</code>, <code>JWT_SECRET</code>.
        </p>
      </div>
    </div>
    """
    return page("Admin Login", body, subtitle="Ingreso seguro")


@app.post("/admin/login")
def admin_login(password: str = Form(...)):
    if not ADMIN_PASSWORD:
        raise HTTPException(500, "Falta ADMIN_PASSWORD en variables.")
    if password != ADMIN_PASSWORD:
        raise HTTPException(401, "Clave incorrecta")

    token = sign({"role": "admin"}, JWT_SECRET, exp_seconds=8 * 3600)
    resp = RedirectResponse(url="/admin", status_code=302)
    resp.set_cookie("admin_session", token, httponly=True, secure=True, samesite="lax")
    return resp


@app.get("/admin/logout")
def admin_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("admin_session")
    return resp


# =========================
# Admin Panel
# =========================
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()

    def count(sql: str) -> int:
        try:
            cur.execute(sql)
            return int(cur.fetchone()[0])
        except Exception:
            return 0

    users = count("SELECT COUNT(*) FROM users")
    proxies = count("SELECT COUNT(*) FROM proxies")
    tickets = count("SELECT COUNT(*) FROM tickets")
    pending = count("SELECT COUNT(*) FROM requests WHERE estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')")
    conn.close()

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>Admin Dashboard</h1>
      <p>Control total de tu plataforma: usuarios, proxies, pedidos y mantenimiento con broadcast.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/users">👥 Usuarios</a>
        <a class="btn" href="/admin/maintenance">🛠 Mantenimiento</a>
        <a class="btn ghost" href="/admin/logout">🚪 Salir</a>
      </div>
    </div>

    <div class="row">
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Usuarios</div>
        <div class="kpi">{users}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Proxies</div>
        <div class="kpi">{proxies}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Pendientes</div>
        <div class="kpi">{pending}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Tickets</div>
        <div class="kpi">{tickets}</div>
      </div>
    </div>

    <div class="card">
      <div class="muted">Mantenimiento</div>
      <div class="kpi">{'🟠 ON' if maint else '🟢 OFF'}</div>
      <p class="muted">{html_escape(mtxt)}</p>
    </div>
    """
    return page("Admin", body, subtitle="Panel premium • Gproxy")


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(admin=Depends(require_admin), q: str = ""):
    conn = db()
    cur = conn.cursor()

    rows = []
    try:
        if q.strip():
            cur.execute(
                "SELECT user_id, username, is_blocked, last_seen FROM users "
                "WHERE CAST(user_id AS TEXT) LIKE ? OR username LIKE ? "
                "ORDER BY last_seen DESC LIMIT 50",
                (f"%{q.strip()}%", f"%{q.strip()}%"),
            )
        else:
            cur.execute(
                "SELECT user_id, username, is_blocked, last_seen FROM users "
                "ORDER BY last_seen DESC LIMIT 50"
            )
        rows = cur.fetchall()
    except Exception:
        rows = []

    conn.close()

    trs = ""
    for r in rows:
        uid = r["user_id"]
        uname = r["username"] or "-"
        blocked = "🚫" if int(r["is_blocked"] or 0) == 1 else "✅"
        last_seen = r["last_seen"] or "-"
        trs += (
            "<tr>"
            f"<td>{blocked}</td>"
            f"<td><a class='btn ghost' href='/admin/user/{uid}'>👤 {uid}</a></td>"
            f"<td>@{html_escape(uname)}</td>"
            f"<td>{html_escape(last_seen)}</td>"
            "</tr>"
        )

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>
      <form method="get" action="/admin/users">
        <label class="muted">Buscar (id o username)</label>
        <input name="q" value="{html_escape(q or '')}" placeholder="Ej: 1915349159 o yudith" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Buscar</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>Estado</th><th>ID</th><th>Username</th><th>Last seen</th></tr>
        {trs or "<tr><td colspan='4' class='muted'>No hay resultados</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Usuarios", body, subtitle="Gestión de usuarios")


@app.get("/admin/user/{user_id}", response_class=HTMLResponse)
def admin_user_detail(user_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT user_id, username, is_blocked, created_at, last_seen FROM users WHERE user_id=?", (user_id,))
        u = cur.fetchone()
    except Exception:
        u = None

    proxies_rows = []
    req_rows = []
    try:
        cur.execute("SELECT id, ip, vence, estado FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 20", (user_id,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, ip, cantidad, monto, estado, created_at FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
            (user_id,),
        )
        req_rows = cur.fetchall()
    except Exception:
        req_rows = []

    conn.close()

    if not u:
        body = """
        <div class="card">
          <p>No encontré ese usuario.</p>
          <a class="btn" href="/admin/users">⬅️ Volver</a>
        </div>
        """
        return page("Admin • Usuario", body, subtitle="Detalle")

    uname = u["username"] or "-"
    blocked = int(u["is_blocked"] or 0)
    tag = "🚫 BLOQUEADO" if blocked == 1 else "✅ ACTIVO"

    phtml = ""
    for r in proxies_rows:
        phtml += f"<tr><td>{r['id']}</td><td>{html_escape(r['ip'] or '')}</td><td>{html_escape(r['vence'] or '')}</td><td>{html_escape(r['estado'] or '')}</td></tr>"
    if not phtml:
        phtml = "<tr><td colspan='4' class='muted'>Sin proxies</td></tr>"

    ohtml = ""
    for r in req_rows:
        ohtml += (
            "<tr>"
            f"<td>#{r['id']}</td>"
            f"<td>{html_escape(r['tipo'] or '')}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{r['cantidad']}</td>"
            f"<td>{r['monto']}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            "</tr>"
        )
    if not ohtml:
        ohtml = "<tr><td colspan='7' class='muted'>Sin pedidos</td></tr>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/users">⬅️ Usuarios</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>
      </div>
      <div class="hr"></div>
      <div class="muted">Usuario</div>
      <div class="kpi">{user_id}</div>
      <p class="muted">@{html_escape(uname)} • {tag}</p>
      <p class="muted">Creado: {html_escape(u['created_at'] or '-')} • Last seen: {html_escape(u['last_seen'] or '-')}</p>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📦 Proxies (20)</h3>
      <table>
        <tr><th>PID</th><th>IP</th><th>Vence</th><th>Estado</th></tr>
        {phtml}
      </table>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📨 Pedidos (20)</h3>
      <table>
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th></tr>
        {ohtml}
      </table>
    </div>
    """
    return page(f"Admin • Usuario {user_id}", body, subtitle="Detalle premium")


# =========================
# Maintenance (Admin)
# =========================
@app.get("/admin/maintenance", response_class=HTMLResponse)
def admin_maintenance_page(admin=Depends(require_admin)):
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>Mantenimiento</h1>
      <p>Activa o desactiva mantenimiento. Si tienes outbox, el bot puede avisar a todos.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
    </div>

    <div class="card">
      <div class="muted">Estado actual</div>
      <div class="kpi">{'🟠 ON' if enabled else '🟢 OFF'}</div>
      <div class="hr"></div>

      <form method="post" action="/admin/maintenance">
        <label class="muted">Mensaje para clientes</label>
        <textarea name="message" placeholder="Ej: Estamos mejorando el sistema. Volvemos pronto.">{html_escape(msg)}</textarea>

        <div style="height:12px;"></div>
        <div class="row">
          <button class="btn" type="submit" name="action" value="on">✅ Activar</button>
          <button class="btn ghost" type="submit" name="action" value="off">❌ Desactivar</button>
        </div>

        <p class="muted" style="margin-top:10px;">
          Outbox: <code>{'ACTIVO' if ENABLE_OUTBOX else 'OFF'}</code>
        </p>
      </form>
    </div>
    """
    return page("Admin • Mantenimiento", body, subtitle="Control y broadcast")


@app.post("/admin/maintenance")
def admin_maintenance_set(
    action: str = Form(...),
    message: str = Form(""),
    admin=Depends(require_admin),
):
    msg = (message or "").strip() or "⚠️ Estamos en mantenimiento. Vuelve en unos minutos."
    set_setting("maintenance_message", msg)

    if action == "on":
        set_setting("maintenance_enabled", "1")
        outbox_add("maintenance_on", msg)
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    if action == "off":
        set_setting("maintenance_enabled", "0")
        outbox_add("maintenance_off", msg)
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    raise HTTPException(400, "Acción inválida")


# =========================
# Client portal
# =========================
@app.get("/client", response_class=HTMLResponse)
def client_landing():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Panel Cliente</h1>
        <p>Acceso seguro por link mágico enviado por el bot.</p>
        <div class="hr"></div>
        <div class="pill">🔐 Login por token</div>
        <div class="pill" style="margin-left:8px;">📦 Tus proxies</div>
        <div class="pill" style="margin-left:8px;">📨 Tus pedidos</div>
      </div>

      <div class="card">
        <p class="muted">
          Pídele al bot tu acceso. El link se ve así:
        </p>
        <code>/c/TOKEN</code>
        <div class="hr"></div>
        <a class="btn ghost" href="/">⬅️ Inicio</a>
      </div>
    </div>
    """
    return page("Cliente", body, subtitle="Acceso por Telegram")


@app.get("/c/{token}")
def client_magic_login(token: str):
    payload = verify(token, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")

    session = sign({"role": "client", "uid": int(payload["uid"])}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie("client_session", session, httponly=True, secure=True, samesite="lax")
    return resp


@app.get("/logout")
def client_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("client_session")
    return resp


@app.get("/me", response_class=HTMLResponse)
def client_me(client=Depends(require_client)):
    uid = int(client["uid"])

    conn = db()
    cur = conn.cursor()

    proxies_rows = []
    orders_rows = []

    try:
        cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, ip, cantidad, monto, estado, created_at FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 50",
            (uid,),
        )
        orders_rows = cur.fetchall()
    except Exception:
        orders_rows = []

    conn.close()

    phtml = ""
    for r in proxies_rows:
        raw = (r["raw"] or "").strip()
        if raw and not raw.upper().startswith("HTTP"):
            raw = "HTTP\n" + raw
        proxy_text = raw or ("HTTP\n" + (r["ip"] or ""))

        raw_block = f"<pre>{html_escape(proxy_text)}</pre>"

        phtml += f"""
        <div class="card">
          <div class="muted">Proxy ID {r['id']} • {html_escape(r['estado'] or '')}</div>
          <div style="height:6px;"></div>
          <div><b>{html_escape(r['ip'] or '')}</b></div>
          <div class="muted">Inicio: {html_escape(r['inicio'] or '')} • Vence: {html_escape(r['vence'] or '')}</div>
          <div style="height:10px;"></div>
          {raw_block}
        </div>
        """

    if not phtml:
        phtml = "<div class='card'><p class='muted'>No tienes proxies todavía.</p></div>"

    ohtml = ""
    for r in orders_rows:
        ohtml += (
            "<tr>"
            f"<td>#{r['id']}</td>"
            f"<td>{html_escape(r['tipo'] or '')}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{r['cantidad']}</td>"
            f"<td>{r['monto']}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            "</tr>"
        )

    if not ohtml:
        ohtml = "<tr><td colspan='7' class='muted'>No hay pedidos</td></tr>"

    body = f"""
    <div class="card hero">
      <h1>Panel Cliente</h1>
      <p>Gestiona tus proxies, revisa pedidos y copia tu configuración en 1 click.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/">🏠 Inicio</a>
        <a class="btn ghost" href="/logout">🚪 Salir</a>
      </div>
    </div>

    <div class="row">
      <div class="card" style="flex:1; min-width:240px;">
        <div class="muted">Tu Telegram ID</div>
        <div class="kpi">{uid}</div>
      </div>
      <div class="card" style="flex:2; min-width:240px;">
        <div class="muted">Tips</div>
        <div class="kpi">🛡️ Seguro</div>
        <p class="muted">No compartas tu link mágico. Si crees que alguien lo vio, pide uno nuevo en el bot.</p>
      </div>
    </div>

    <h3 style="margin:18px 0 10px 0;">📦 Mis proxies</h3>
    {phtml}

    <h3 style="margin:18px 0 10px 0;">📨 Mis pedidos</h3>
    <div class="card">
      <table>
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th></tr>
        {ohtml}
      </table>
    </div>
    """
    return page("Cliente", body, subtitle="Tus proxies y pedidos")


# =========================
# Helper endpoint:
# Bot can call this to know maintenance status
# =========================
@app.get("/api/maintenance")
def api_maintenance():
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")
    return {"enabled": enabled, "message": msg}


# =========================
# Optional: bot reads outbox
# =========================
@app.get("/api/outbox")
def api_outbox(admin=Depends(require_admin)):
    if not ENABLE_OUTBOX:
        return {"enabled": False, "items": []}
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, kind, message, created_at, sent_at FROM outbox ORDER BY id DESC LIMIT 50")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"enabled": True, "items": rows}

