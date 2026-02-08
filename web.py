# web.py — Gproxy Web Panel (FastAPI)
# ✅ Admin login con clave (cookie)
# ✅ Clientes: login por Teléfono + PIN (WEB ONLY)
# ✅ Admin: usuarios + bloquear/desbloquear, pedidos + aprobar/rechazar, mantenimiento, proxies
# ✅ Admin: gestión de auth (teléfono + PIN) sin Telegram
# ✅ Lee la misma DB sqlite (data.db)
# ✅ Outbox opcional

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

# =========================
# CONFIG (Railway Variables)
# =========================
DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()           # EJ: "MiClaveSuperFuerte"
JWT_SECRET = os.getenv("JWT_SECRET", "change_me_admin").strip()    # secreto largo random

APP_TITLE = os.getenv("APP_TITLE", "Gproxy")
ENABLE_OUTBOX = os.getenv("ENABLE_OUTBOX", "1").strip() == "1"

# ✅ PIN_SECRET recomendado (separado del CLIENT_SECRET)
PIN_SECRET = os.getenv("PIN_SECRET", "").strip()

# ✅ Para que cookies no fallen en local (en Railway pon 1)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1").strip() == "1"

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

    # ✅ auth_users (login web por teléfono+PIN)
    # user_id = el mismo id del usuario en tu tabla users
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_users(
            user_id INTEGER PRIMARY KEY,
            phone TEXT NOT NULL DEFAULT '',
            pin_hash TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
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

    # ✅ Persistir CLIENT_SECRET en DB (no cambia con reinicios)
    cur.execute("SELECT value FROM settings WHERE key=?", ("client_secret_persist",))
    row = cur.fetchone()
    db_secret = (row["value"] if row else "").strip()

    env_secret = (os.getenv("CLIENT_SECRET") or "").strip()
    if env_secret and env_secret not in ("change_me_client", ""):
        CLIENT_SECRET = env_secret
        if db_secret != CLIENT_SECRET:
            cur.execute(
                "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("client_secret_persist", CLIENT_SECRET, now_str()),
            )
    else:
        if db_secret:
            CLIENT_SECRET = db_secret
        else:
            CLIENT_SECRET = secrets.token_urlsafe(64)
            cur.execute(
                "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
                ("client_secret_persist", CLIENT_SECRET, now_str()),
            )
            print("⚠️ CLIENT_SECRET no estaba definido. Se generó y guardó uno seguro en DB (settings).")

    # ✅ PIN_SECRET fallback
    global PIN_SECRET
    if not PIN_SECRET:
        PIN_SECRET = CLIENT_SECRET

    conn.commit()
    conn.close()
    return CLIENT_SECRET


CLIENT_SECRET = ensure_web_schema()


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
    # Si mantenimiento ON, dejamos entrar solo a login/logout/home
    if get_setting("maintenance_enabled", "0") == "1":
        path = (request.url.path or "").lower()
        allowed = {"/", "/client/login", "/logout", "/health", "/api/maintenance"}
        if path not in allowed and not path.startswith("/c/"):
            raise HTTPException(503, "En mantenimiento")

    tok = request.cookies.get("client_session", "")
    payload = verify(tok, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")
    return payload


# =========================
# Client auth (phone + pin)
# =========================
def pin_hash(pin: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), pin.encode("utf-8"), hashlib.sha256).hexdigest()


def auth_verify_phone_pin(phone: str, pin: str) -> Optional[int]:
    phone = (phone or "").strip()
    pin = (pin or "").strip()
    if not phone or not pin:
        return None

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT user_id, pin_hash, verified FROM auth_users WHERE phone=?", (phone,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return None
    if int(row["verified"] or 0) != 1:
        return None

    good = (row["pin_hash"] or "").strip()
    if not good:
        return None

    given = pin_hash(pin, PIN_SECRET)
    if not hmac.compare_digest(good, given):
        return None

    return int(row["user_id"])


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

    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 28px 18px 60px; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:14px; margin-bottom:14px; }}
    .brand {{ display:flex; align-items:center; gap:12px; }}
    .logo {{
      width:44px; height:44px; border-radius:14px;
      background: linear-gradient(45deg, var(--p1), var(--p2));
      box-shadow: 0 0 30px rgba(196,0,255,.35);
      display:flex; align-items:center; justify-content:center;
    }}
    .logo span {{ font-weight:900; letter-spacing:.5px; }}
    .title {{ font-size: 18px; font-weight: 800; margin:0; }}
    .subtitle {{ margin:0; color: var(--muted); font-size: 13px; }}

    .chip {{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px; border-radius: 999px;
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      white-space:nowrap;
    }}

    .grid {{ display:grid; grid-template-columns: 1.4fr .9fr; gap: 16px; }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}

    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 18px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }}

    .row {{ display:flex; gap: 12px; flex-wrap: wrap; align-items:center; }}

    .btn {{
      appearance:none; border: none; border-radius: 14px;
      padding: 12px 16px; font-weight: 750;
      color: white; text-decoration:none; cursor:pointer;
      background: linear-gradient(45deg, var(--p1), var(--p2));
      box-shadow: 0 12px 30px rgba(123,0,255,.22);
      transition: transform .15s ease, box-shadow .15s ease, filter .15s ease;
      display:inline-flex; align-items:center; gap:10px;
    }}
    .btn:hover {{ transform: translateY(-2px); filter: brightness(1.03); }}
    .btn.ghost {{ background: rgba(255,255,255,.06); border: 1px solid var(--border); box-shadow: none; }}
    .btn.bad {{ background: linear-gradient(45deg, #ff2b6a, #ff7a2b); box-shadow: 0 12px 30px rgba(255,43,106,.20); }}

    .kpi {{
      font-size: 34px; font-weight: 900; margin-top: 6px;
      background: linear-gradient(90deg, #fff, #e9dbff, #b9f2ff);
      -webkit-background-clip:text; background-clip:text; color: transparent;
    }}

    .muted {{ color: var(--muted); font-size: 13px; }}
    .hr {{ height:1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent); margin: 14px 0; }}

    input, textarea {{
      width:100%; padding: 12px 14px; border-radius: 14px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.20); color: white; outline:none;
    }}
    textarea {{ min-height: 120px; }}

    table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:14px; }}
    th, td {{
      border-bottom: 1px solid rgba(255,255,255,.10);
      padding: 12px; text-align:left; font-size: 13px; vertical-align: top;
    }}
    th {{ color:#f0eaff; font-weight:800; }}

    pre {{
      background: rgba(0,0,0,.25);
      border: 1px solid rgba(255,255,255,.10);
      border-radius: 14px; padding: 12px;
      overflow:auto; white-space: pre-wrap; word-break: break-word;
    }}

    .status {{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px; border-radius: 999px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(255,255,255,.06);
    }}
    .dot {{ width:10px; height:10px; border-radius:50%; background: var(--ok); box-shadow: 0 0 16px rgba(43,255,154,.35); }}
    .dot.warn {{ background: var(--warn); box-shadow: 0 0 16px rgba(255,176,32,.35); }}

    .footer {{ margin-top: 16px; color: rgba(255,255,255,.55); font-size: 12px; text-align:center; }}

    .hero {{
      padding: 18px; border-radius: 20px;
      background: linear-gradient(135deg, rgba(123,0,255,.18), rgba(0,212,255,.10));
      border: 1px solid rgba(255,255,255,.10);
    }}
    .hero h1 {{ margin:0 0 8px 0; font-size: 26px; }}
    .hero p {{ margin:0; color: rgba(255,255,255,.78); line-height:1.5; }}
    .pill {{
      display:inline-flex; gap:8px; padding: 8px 10px; border-radius: 999px;
      border:1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.18);
      font-size: 12px; color: rgba(255,255,255,.85);
    }}
  </style>
</head>

<body>
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
          Plataforma web para administrar proxies USA 🇺🇸.
          Acceso de clientes con <b>Teléfono + PIN</b>.
        </p>
        <div class="hr"></div>

        <div class="row">
          <a class="btn" href="/admin/login">🔐 Admin</a>
          <a class="btn ghost" href="/client/login">👤 Clientes</a>
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
          Si no puedes entrar, pídele al admin que te cree o resetee el PIN desde el panel.
        </p>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="SaaS moderno • Panel Admin & Cliente")


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH, "cookie_secure": COOKIE_SECURE}


# =========================
# Admin Auth
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Admin Access</h1>
        <p>Entra al panel premium para gestionar usuarios, pedidos y mantenimiento.</p>
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
    resp.set_cookie("admin_session", token, httponly=True, secure=COOKIE_SECURE, samesite="lax")
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
      <p>Control total: usuarios, proxies, pedidos, auth de clientes y mantenimiento.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/users">👥 Usuarios</a>
        <a class="btn" href="/admin/orders">📨 Pedidos</a>
        <a class="btn" href="/admin/proxies">📦 Proxies</a>
        <a class="btn" href="/admin/auth">🔐 Auth Clientes</a>
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


# =========================
# Admin: Auth Clientes (WEB ONLY)
# =========================
@app.get("/admin/auth", response_class=HTMLResponse)
def admin_auth_list(admin=Depends(require_admin), q: str = ""):
    conn = db()
    cur = conn.cursor()

    rows = []
    if q.strip():
        cur.execute(
            """
            SELECT au.user_id, au.phone, au.verified, au.updated_at
            FROM auth_users au
            WHERE CAST(au.user_id AS TEXT) LIKE ? OR au.phone LIKE ?
            ORDER BY au.updated_at DESC
            LIMIT 80
            """,
            (f"%{q.strip()}%", f"%{q.strip()}%"),
        )
    else:
        cur.execute(
            """
            SELECT au.user_id, au.phone, au.verified, au.updated_at
            FROM auth_users au
            ORDER BY au.updated_at DESC
            LIMIT 80
            """
        )
    rows = cur.fetchall()
    conn.close()

    trs = ""
    for r in rows:
        v = "✅" if int(r["verified"] or 0) == 1 else "⚠️"
        trs += (
            "<tr>"
            f"<td>{v}</td>"
            f"<td><a class='btn ghost' href='/admin/auth/{int(r['user_id'])}'>👤 {int(r['user_id'])}</a></td>"
            f"<td>{html_escape(r['phone'] or '')}</td>"
            f"<td>{html_escape(r['updated_at'] or '')}</td>"
            "</tr>"
        )

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
        <a class="btn" href="/admin/auth/new">➕ Crear/Asignar PIN</a>
      </div>
      <div class="hr"></div>
      <form method="get" action="/admin/auth">
        <label class="muted">Buscar (user_id o teléfono)</label>
        <input name="q" value="{html_escape(q or '')}" placeholder="Ej: 1915349159 o +1809..." />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Buscar</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>Verif</th><th>User</th><th>Teléfono</th><th>Updated</th></tr>
        {trs or "<tr><td colspan='4' class='muted'>No hay registros</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Auth Clientes", body, subtitle="Teléfono + PIN (sin Telegram)")


@app.get("/admin/auth/new", response_class=HTMLResponse)
def admin_auth_new_page(admin=Depends(require_admin)):
    body = """
    <div class="card hero">
      <h1>Crear / Asignar PIN</h1>
      <p>Esto crea o actualiza el acceso web de un cliente: Teléfono + PIN.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin/auth">⬅️ Volver</a>
      </div>
    </div>

    <div class="card">
      <form method="post" action="/admin/auth/new">
        <label class="muted">User ID (de tu tabla users)</label>
        <input name="user_id" placeholder="Ej: 1915349159" />
        <div style="height:12px;"></div>

        <label class="muted">Teléfono</label>
        <input name="phone" placeholder="+1809..." />
        <div style="height:12px;"></div>

        <label class="muted">PIN (4-8 dígitos)</label>
        <input name="pin" placeholder="Ej: 1234" />
        <div style="height:12px;"></div>

        <label class="muted">Marcar como verificado</label>
        <select name="verified" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,.10);background:rgba(0,0,0,.20);color:white;">
          <option value="1" selected>Sí (puede entrar)</option>
          <option value="0">No (bloquea login)</option>
        </select>

        <div style="height:12px;"></div>
        <button class="btn" type="submit">Guardar</button>
      </form>
      <div class="hr"></div>
      <p class="muted">
        Nota: si el user_id no existe en <code>users</code>, igual se guarda en <code>auth_users</code> (pero recomendado que exista).
      </p>
    </div>
    """
    return page("Admin • Crear PIN", body, subtitle="Alta web de clientes")


@app.post("/admin/auth/new")
def admin_auth_new(
    user_id: str = Form(...),
    phone: str = Form(...),
    pin: str = Form(...),
    verified: str = Form("1"),
    admin=Depends(require_admin),
):
    uid_s = (user_id or "").strip()
    phone = (phone or "").strip()
    pin = (pin or "").strip()
    ver = 1 if (verified or "0").strip() == "1" else 0

    if not uid_s.isdigit():
        raise HTTPException(400, "user_id inválido")
    uid = int(uid_s)

    if not phone or len(phone) < 6:
        raise HTTPException(400, "Teléfono inválido")
    if not pin or len(pin) < 4 or len(pin) > 8:
        raise HTTPException(400, "PIN inválido (4-8 dígitos)")

    phash = pin_hash(pin, PIN_SECRET)

    conn = db()
    cur = conn.cursor()

    # Evitar teléfonos duplicados para 2 users
    cur.execute("SELECT user_id FROM auth_users WHERE phone=? AND user_id<>?", (phone, uid))
    if cur.fetchone():
        conn.close()
        raise HTTPException(400, "Ese teléfono ya está asignado a otro user_id")

    cur.execute("SELECT user_id FROM auth_users WHERE user_id=?", (uid,))
    exists = cur.fetchone() is not None

    if exists:
        cur.execute(
            """
            UPDATE auth_users
            SET phone=?, pin_hash=?, verified=?, updated_at=?
            WHERE user_id=?
            """,
            (phone, phash, ver, now_str(), uid),
        )
    else:
        cur.execute(
            """
            INSERT INTO auth_users(user_id, phone, pin_hash, verified, created_at, updated_at)
            VALUES(?,?,?,?,?,?)
            """,
            (uid, phone, phash, ver, now_str(), now_str()),
        )

    conn.commit()
    conn.close()

    outbox_add("auth_upsert", json.dumps({"user_id": uid, "phone": phone, "verified": ver}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/auth/{uid}", status_code=302)


@app.get("/admin/auth/{user_id}", response_class=HTMLResponse)
def admin_auth_detail(user_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT user_id, phone, verified, created_at, updated_at FROM auth_users WHERE user_id=?", (user_id,))
    au = cur.fetchone()
    conn.close()

    if not au:
        body = f"""
        <div class="card">
          <p class="muted">No existe auth para user <b>{user_id}</b>.</p>
          <a class="btn" href="/admin/auth/new">➕ Crear</a>
          <a class="btn ghost" href="/admin/auth">⬅️ Volver</a>
        </div>
        """
        return page("Admin • Auth", body, subtitle="Detalle")

    v = "✅ Verificado" if int(au["verified"] or 0) == 1 else "⚠️ No verificado"
    body = f"""
    <div class="card hero">
      <h1>Auth Cliente</h1>
      <p>{v}</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin/auth">⬅️ Volver</a>
        <form method="post" action="/admin/auth/{user_id}/toggle" style="margin-left:auto;">
          <button class="btn" type="submit">🔁 Toggle Verified</button>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="muted">User ID</div>
      <div class="kpi">{int(au["user_id"])}</div>
      <p class="muted">Teléfono: <b>{html_escape(au["phone"] or "")}</b></p>
      <p class="muted">Creado: {html_escape(au["created_at"] or "-")} • Updated: {html_escape(au["updated_at"] or "-")}</p>
      <div class="hr"></div>

      <h3 style="margin:0 0 10px 0;">🔐 Reset / Cambiar PIN</h3>
      <form method="post" action="/admin/auth/{user_id}/reset_pin">
        <label class="muted">Nuevo PIN (4-8 dígitos)</label>
        <input name="pin" placeholder="Ej: 4455" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Guardar PIN</button>
      </form>

      <div class="hr"></div>
      <h3 style="margin:0 0 10px 0;">📱 Cambiar teléfono</h3>
      <form method="post" action="/admin/auth/{user_id}/set_phone">
        <label class="muted">Teléfono</label>
        <input name="phone" value="{html_escape(au["phone"] or "")}" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Guardar teléfono</button>
      </form>
    </div>
    """
    return page("Admin • Auth", body, subtitle="Gestión web")


@app.post("/admin/auth/{user_id}/toggle")
def admin_auth_toggle(user_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT verified FROM auth_users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "No existe auth_users para ese user")
    curv = 1 if int(row["verified"] or 0) == 1 else 0
    newv = 0 if curv == 1 else 1
    cur.execute("UPDATE auth_users SET verified=?, updated_at=? WHERE user_id=?", (newv, now_str(), user_id))
    conn.commit()
    conn.close()
    outbox_add("auth_toggle_verified", json.dumps({"user_id": user_id, "verified": newv}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/auth/{user_id}", status_code=302)


@app.post("/admin/auth/{user_id}/reset_pin")
def admin_auth_reset_pin(user_id: int, pin: str = Form(...), admin=Depends(require_admin)):
    pin = (pin or "").strip()
    if not pin or len(pin) < 4 or len(pin) > 8:
        raise HTTPException(400, "PIN inválido (4-8 dígitos)")
    phash = pin_hash(pin, PIN_SECRET)

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM auth_users WHERE user_id=?", (user_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(404, "No existe auth_users para ese user")

    cur.execute("UPDATE auth_users SET pin_hash=?, updated_at=? WHERE user_id=?", (phash, now_str(), user_id))
    conn.commit()
    conn.close()

    outbox_add("auth_reset_pin", json.dumps({"user_id": user_id}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/auth/{user_id}", status_code=302)


@app.post("/admin/auth/{user_id}/set_phone")
def admin_auth_set_phone(user_id: int, phone: str = Form(...), admin=Depends(require_admin)):
    phone = (phone or "").strip()
    if not phone or len(phone) < 6:
        raise HTTPException(400, "Teléfono inválido")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM auth_users WHERE phone=? AND user_id<>?", (phone, user_id))
    if cur.fetchone():
        conn.close()
        raise HTTPException(400, "Ese teléfono ya está asignado a otro user_id")

    cur.execute("UPDATE auth_users SET phone=?, updated_at=? WHERE user_id=?", (phone, now_str(), user_id))
    conn.commit()
    conn.close()

    outbox_add("auth_set_phone", json.dumps({"user_id": user_id, "phone": phone}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/auth/{user_id}", status_code=302)


# =========================
# Admin: Users
# =========================
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


@app.post("/admin/user/{user_id}/toggle_block")
def admin_toggle_block(user_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT is_blocked FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    curv = int(row["is_blocked"] or 0) if row else 0
    newv = 0 if curv == 1 else 1
    cur.execute("UPDATE users SET is_blocked=? WHERE user_id=?", (newv, user_id))
    conn.commit()
    conn.close()

    outbox_add("user_block_toggled", json.dumps({"user_id": user_id, "is_blocked": newv}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/user/{user_id}", status_code=302)


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
    auth_row = None

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

    try:
        cur.execute("SELECT phone, verified FROM auth_users WHERE user_id=?", (user_id,))
        auth_row = cur.fetchone()
    except Exception:
        auth_row = None

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

    phone_txt = "-"
    if auth_row:
        phone_txt = (auth_row["phone"] or "-") + (" ✅" if int(auth_row["verified"] or 0) == 1 else " ⚠️")

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

    toggle_label = "🔓 Desbloquear" if blocked == 1 else "⛔ Bloquear"
    toggle_class = "btn" if blocked == 1 else "btn bad"

    auth_btn = f"<a class='btn' href='/admin/auth/{user_id}'>🔐 Auth</a>" if auth_row else "<a class='btn' href='/admin/auth/new'>➕ Crear PIN</a>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/users">⬅️ Usuarios</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>
        {auth_btn}

        <form method="post" action="/admin/user/{user_id}/toggle_block" style="margin-left:auto;">
          <button class="{toggle_class}" type="submit">{toggle_label}</button>
        </form>
      </div>

      <div class="hr"></div>
      <div class="muted">Usuario</div>
      <div class="kpi">{user_id}</div>
      <p class="muted">@{html_escape(uname)} • {tag}</p>
      <p class="muted">Teléfono: <b>{html_escape(phone_txt)}</b></p>
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
# Admin: Orders (Aprobar / Rechazar)
# =========================
@app.get("/admin/orders", response_class=HTMLResponse)
def admin_orders(admin=Depends(require_admin), state: str = ""):
    conn = db()
    cur = conn.cursor()

    where = ""
    params = ()
    if state.strip():
        where = "WHERE estado=?"
        params = (state.strip(),)

    cur.execute(
        f"""
        SELECT id, user_id, tipo, ip, cantidad, monto, estado, created_at
        FROM requests
        {where}
        ORDER BY id DESC
        LIMIT 80
        """,
        params,
    )
    rows = cur.fetchall()
    conn.close()

    options = [
        ("", "Todos"),
        ("awaiting_voucher", "awaiting_voucher"),
        ("voucher_received", "voucher_received"),
        ("awaiting_admin_verify", "awaiting_admin_verify"),
        ("approved", "approved"),
        ("rejected", "rejected"),
        ("cancelled", "cancelled"),
    ]

    opt_html = ""
    for val, label in options:
        sel = "selected" if (state or "") == val else ""
        opt_html += f"<option value='{html_escape(val)}' {sel}>{html_escape(label)}</option>"

    cards = ""
    for r in rows:
        rid = int(r["id"])
        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Pedido <b>#{rid}</b> • Estado: <b>{html_escape(r["estado"] or "")}</b></div>
          <div style="height:8px;"></div>
          <div><b>U:</b> <a class="btn ghost" href="/admin/user/{int(r["user_id"])}">👤 {int(r["user_id"])}</a></div>
          <div class="muted" style="margin-top:6px;">
            Tipo: <b>{html_escape(r["tipo"] or "")}</b> • IP: <b>{html_escape(r["ip"] or "-")}</b> • Qty: <b>{r["cantidad"]}</b> • Monto: <b>{r["monto"]}</b>
            <br/>Creado: {html_escape(r["created_at"] or "")}
          </div>

          <div class="hr"></div>
          <div class="row">
            <form method="post" action="/admin/order/{rid}/approve">
              <button class="btn" type="submit">✅ Aprobar</button>
            </form>
            <form method="post" action="/admin/order/{rid}/reject">
              <button class="btn bad" type="submit">❌ Rechazar</button>
            </form>
          </div>
        </div>
        """

    if not cards:
        cards = "<div class='card'><p class='muted'>No hay pedidos en ese filtro.</p></div>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>

      <form method="get" action="/admin/orders">
        <label class="muted">Filtrar por estado</label>
        <select name="state" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,.10);background:rgba(0,0,0,.20);color:white;">
          {opt_html}
        </select>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Aplicar filtro</button>
      </form>
    </div>

    {cards}
    """
    return page("Admin • Pedidos", body, subtitle="Aprobar / Rechazar")


@app.post("/admin/order/{rid}/approve")
def admin_order_approve(rid: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, tipo, ip FROM requests WHERE id=?", (rid,))
    req = cur.fetchone()
    if not req:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado")

    cur.execute("UPDATE requests SET estado=? WHERE id=?", ("approved", rid))
    conn.commit()
    conn.close()

    outbox_add("order_approved", json.dumps({"rid": rid, "user_id": int(req["user_id"]), "tipo": req["tipo"], "ip": req["ip"]}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


@app.post("/admin/order/{rid}/reject")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, tipo, ip FROM requests WHERE id=?", (rid,))
    req = cur.fetchone()
    if not req:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado")

    cur.execute("UPDATE requests SET estado=? WHERE id=?", ("rejected", rid))
    conn.commit()
    conn.close()

    outbox_add("order_rejected", json.dumps({"rid": rid, "user_id": int(req["user_id"]), "tipo": req["tipo"], "ip": req["ip"]}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


# =========================
# Admin: Proxies list
# =========================
@app.get("/admin/proxies", response_class=HTMLResponse)
def admin_proxies(admin=Depends(require_admin), q: str = ""):
    conn = db()
    cur = conn.cursor()

    if q.strip():
        cur.execute(
            """
            SELECT id, user_id, ip, vence, estado
            FROM proxies
            WHERE CAST(user_id AS TEXT) LIKE ? OR ip LIKE ?
            ORDER BY id DESC
            LIMIT 80
            """,
            (f"%{q.strip()}%", f"%{q.strip()}%"),
        )
    else:
        cur.execute(
            """
            SELECT id, user_id, ip, vence, estado
            FROM proxies
            ORDER BY id DESC
            LIMIT 80
            """
        )

    rows = cur.fetchall()
    conn.close()

    trs = ""
    for r in rows:
        trs += (
            "<tr>"
            f"<td><code>{r['id']}</code></td>"
            f"<td><a class='btn ghost' href='/admin/user/{int(r['user_id'])}'>👤 {int(r['user_id'])}</a></td>"
            f"<td>{html_escape(r['ip'] or '')}</td>"
            f"<td>{html_escape(r['vence'] or '')}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            "</tr>"
        )

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>

      <form method="get" action="/admin/proxies">
        <label class="muted">Buscar (user_id o ip)</label>
        <input name="q" value="{html_escape(q or '')}" placeholder="Ej: 1915349159 o 104." />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Buscar</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>PID</th><th>User</th><th>IP</th><th>Vence</th><th>Estado</th></tr>
        {trs or "<tr><td colspan='5' class='muted'>No hay proxies</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Proxies", body, subtitle="Listado rápido")


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
      <p>Activa o desactiva mantenimiento.</p>
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
    return page("Admin • Mantenimiento", body, subtitle="Control")


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
# Client portal (Phone + PIN) — WEB ONLY
# =========================
@app.get("/client/login", response_class=HTMLResponse)
def client_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Panel Cliente</h1>
        <p>Entra con tu <b>Teléfono + PIN</b>.</p>
        <div class="hr"></div>
        <div class="pill">📱 Teléfono</div>
        <div class="pill" style="margin-left:8px;">🔐 PIN</div>
        <div class="pill" style="margin-left:8px;">📦 Proxies</div>
      </div>

      <div class="card">
        <form method="post" action="/client/login">
          <label class="muted">Teléfono</label><br/>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">PIN (4-8 dígitos)</label><br/>
          <input name="pin" type="password" placeholder="••••" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">
          Si no tienes PIN o lo olvidaste, pídeselo al admin para que te lo cree o resetee.
        </p>
      </div>
    </div>
    """
    return page("Cliente • Login", body, subtitle="Acceso seguro")


@app.post("/client/login")
def client_login(phone: str = Form(...), pin: str = Form(...)):
    uid = auth_verify_phone_pin(phone, pin)
    if not uid:
        body = """
        <div class="card">
          <h3>Login inválido</h3>
          <p class="muted">Verifica tu teléfono y PIN. Si no tienes acceso, el admin debe crearte el PIN.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/login">⬅️ Intentar de nuevo</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Error", body, subtitle="No autorizado"), status_code=401)

    session = sign({"role": "client", "uid": int(uid)}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie("client_session", session, httponly=True, secure=COOKIE_SECURE, samesite="lax")
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

        phtml += f"""
        <div class="card">
          <div class="muted">Proxy ID {r['id']} • {html_escape(r['estado'] or '')}</div>
          <div style="height:6px;"></div>
          <div><b>{html_escape(r['ip'] or '')}</b></div>
          <div class="muted">Inicio: {html_escape(r['inicio'] or '')} • Vence: {html_escape(r['vence'] or '')}</div>
          <div style="height:10px;"></div>
          <pre>{html_escape(proxy_text)}</pre>
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
      <p>Gestiona tus proxies y revisa tus pedidos.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/">🏠 Inicio</a>
        <a class="btn ghost" href="/logout">🚪 Salir</a>
      </div>
    </div>

    <div class="row">
      <div class="card" style="flex:1; min-width:240px;">
        <div class="muted">Tu ID</div>
        <div class="kpi">{uid}</div>
      </div>
      <div class="card" style="flex:2; min-width:240px;">
        <div class="muted">Tips</div>
        <div class="kpi">🛡️ Seguro</div>
        <p class="muted">No compartas tu PIN. Si lo olvidaste, pide reset al admin.</p>
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
# Backwards compatibility (optional)
# =========================
@app.get("/c/{token}")
def client_magic_login(token: str):
    payload = verify(token, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")

    session = sign({"role": "client", "uid": int(payload["uid"])}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie("client_session", session, httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return resp


# =========================
# Helper endpoint: maintenance
# =========================
@app.get("/api/maintenance")
def api_maintenance():
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")
    return {"enabled": enabled, "message": msg}


# =========================
# Optional: outbox
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
