# web.py — Gproxy Web Panel (FastAPI) ✅ Admin password + Client magic link
# - Admin login con clave (cookie segura)
# - Clientes entran con link mágico /c/{token} (cookie segura)
# - Lee la misma DB sqlite (data.db)
# - Panel admin básico + mantenimiento ON/OFF + mensaje personalizado
# - Opcional: crea una "outbox" para que el BOT mande broadcast (mantenimiento on/off)

from fastapi import FastAPI
app = FastAPI()

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Depends, HTTPException, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse

# =========================
# CONFIG (Railway Variables)
# =========================
DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")          # EJ: "MiClaveSuperFuerte"
JWT_SECRET = os.getenv("JWT_SECRET", "change_me_admin")   # secreto largo random
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "change_me_client")  # secreto largo random

APP_TITLE = os.getenv("APP_TITLE", "Gproxy Panel")

# Para que el BOT haga broadcast:
# - El web panel NO manda a Telegram directamente.
# - En su lugar, guarda un "mensaje pendiente" en outbox.
# - El bot.py puede leer esa tabla cada X segundos/minutos y enviar a todos.
ENABLE_OUTBOX = os.getenv("ENABLE_OUTBOX", "1").strip() == "1"


# =========================
# APP
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

    # Tabla para mantenimiento (1 fila)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    # Outbox opcional (para que el bot haga broadcast)
    if ENABLE_OUTBOX:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,            -- "maintenance_on" / "maintenance_off" / etc
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT NOT NULL DEFAULT ''  -- se llena cuando el bot lo procese
            )
            """
        )

    # Defaults
    # maintenance_enabled: "0" / "1"
    cur.execute("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
                ("maintenance_enabled", "0", now_str()))
    # maintenance_message: texto
    cur.execute("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
                ("maintenance_message", "⚠️ Estamos en mantenimiento. Vuelve en unos minutos.", now_str()))

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
    try:
        a, b = token.split(".", 1)
        raw = _b64urldecode(a)
        sig = _b64urldecode(b)
        good = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            raise ValueError("bad sig")
        payload = json.loads(raw.decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
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
# UI helpers (HTML)
# =========================
def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; background:#0b0f17; color:#e8eefc; }}
    .wrap {{ max-width: 980px; margin: 0 auto; padding: 24px; }}
    .card {{ background:#121a2a; border:1px solid #22304d; border-radius:14px; padding:16px; margin: 14px 0; }}
    .row {{ display:flex; gap:12px; flex-wrap:wrap; }}
    .btn {{ display:inline-block; padding:10px 14px; border-radius:10px; border:1px solid #2b3a5a; background:#18233a; color:#e8eefc; text-decoration:none; }}
    .btn:hover {{ background:#1d2a44; }}
    input, textarea {{ width:100%; padding:10px; border-radius:10px; border:1px solid #2b3a5a; background:#0e1524; color:#e8eefc; }}
    textarea {{ min-height: 110px; }}
    .muted {{ color:#a9b7d6; font-size: 13px; }}
    .kpi {{ font-size:26px; font-weight:700; }}
    table {{ width:100%; border-collapse: collapse; }}
    td, th {{ border-bottom:1px solid #22304d; padding:10px; text-align:left; }}
    code, pre {{ background:#0e1524; padding:6px 8px; border-radius:10px; border:1px solid #22304d; overflow:auto; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h2 style="margin:0 0 10px 0;">{title}</h2>
    {body}
    <div class="muted" style="margin-top:20px;">Gproxy Web • Railway</div>
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
    body = f"""
    <div class="card">
      <div class="muted">Estado</div>
      <div class="kpi">{'🟠 Mantenimiento' if maint else '🟢 Online'}</div>
      <p class="muted">{mtxt if maint else 'Todo funcionando.'}</p>
    </div>

    <div class="card">
      <div class="row">
        <a class="btn" href="/admin/login">🔐 Admin Login</a>
        <a class="btn" href="/client">👤 Panel Cliente</a>
      </div>
      <p class="muted" style="margin-top:10px;">
        Para clientes: entra con el link mágico que te manda el bot (ruta /c/...)
      </p>
    </div>
    """
    return page(APP_TITLE, body)


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH}


# =========================
# Admin Auth
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <div class="card">
      <form method="post" action="/admin/login">
        <label class="muted">Clave Admin</label><br/>
        <input type="password" name="password" placeholder="Tu clave admin" />
        <div style="height:10px;"></div>
        <button class="btn" type="submit">Entrar</button>
      </form>
      <p class="muted" style="margin-top:10px;">
        Configura ADMIN_PASSWORD y JWT_SECRET en Railway Variables.
      </p>
    </div>
    """
    return page("Admin Login", body)


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

    # Tablas base (de tu bot.py)
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
      <div class="row">
        <a class="btn" href="/admin/users">👥 Usuarios</a>
        <a class="btn" href="/admin/maintenance">🛠 Mantenimiento</a>
        <a class="btn" href="/admin/logout">🚪 Salir</a>
      </div>
    </div>

    <div class="card">
      <div class="muted">Mantenimiento</div>
      <div class="kpi">{'🟠 ON' if maint else '🟢 OFF'}</div>
      <p class="muted">{mtxt}</p>
    </div>
    """
    return page("Admin Dashboard", body)


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
        trs += f"<tr><td>{blocked}</td><td><a class='btn' href='/admin/user/{uid}'>👤 {uid}</a></td><td>@{uname}</td><td>{last_seen}</td></tr>"

    body = f"""
    <div class="card">
      <form method="get" action="/admin/users">
        <label class="muted">Buscar (id o username)</label>
        <input name="q" value="{q or ''}" placeholder="Ej: 1915349159 o yudith" />
        <div style="height:10px;"></div>
        <button class="btn" type="submit">Buscar</button>
        <a class="btn" href="/admin">⬅️ Dashboard</a>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>Estado</th><th>ID</th><th>Username</th><th>Last seen</th></tr>
        {trs or "<tr><td colspan='4' class='muted'>No hay resultados</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Usuarios", body)


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
        body = f"""
        <div class="card">
          <p>No encontré ese usuario.</p>
          <a class="btn" href="/admin/users">⬅️ Volver</a>
        </div>
        """
        return page("Admin • Usuario", body)

    uname = u["username"] or "-"
    blocked = int(u["is_blocked"] or 0)
    tag = "🚫 BLOQUEADO" if blocked == 1 else "✅ ACTIVO"

    phtml = ""
    for r in proxies_rows:
        phtml += f"<tr><td>{r['id']}</td><td>{r['ip']}</td><td>{r['vence']}</td><td>{r['estado']}</td></tr>"
    if not phtml:
        phtml = "<tr><td colspan='4' class='muted'>Sin proxies</td></tr>"

    ohtml = ""
    for r in req_rows:
        ohtml += f"<tr><td>#{r['id']}</td><td>{r['tipo']}</td><td>{r['ip'] or '-'}</td><td>{r['cantidad']}</td><td>{r['monto']}</td><td>{r['estado']}</td><td>{r['created_at']}</td></tr>"
    if not ohtml:
        ohtml = "<tr><td colspan='7' class='muted'>Sin pedidos</td></tr>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn" href="/admin/users">⬅️ Usuarios</a>
        <a class="btn" href="/admin">🏠 Dashboard</a>
      </div>
      <div style="height:10px;"></div>
      <div class="muted">Usuario</div>
      <div class="kpi">{user_id}</div>
      <p class="muted">@{uname} • {tag}</p>
      <p class="muted">Creado: {u['created_at'] or '-'} • Last seen: {u['last_seen'] or '-'}</p>
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
    return page(f"Admin • Usuario {user_id}", body)


# =========================
# Maintenance (Admin)
# =========================
@app.get("/admin/maintenance", response_class=HTMLResponse)
def admin_maintenance_page(admin=Depends(require_admin)):
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn" href="/admin">⬅️ Dashboard</a>
      </div>
      <div style="height:10px;"></div>

      <div class="muted">Estado actual</div>
      <div class="kpi">{'🟠 Mantenimiento ON' if enabled else '🟢 Mantenimiento OFF'}</div>

      <div style="height:10px;"></div>
      <form method="post" action="/admin/maintenance">
        <label class="muted">Mensaje para clientes (se enviará cuando actives y cuando desactives)</label>
        <textarea name="message" placeholder="Ej: Estamos mejorando el sistema. Volvemos pronto.">{msg}</textarea>

        <div style="height:12px;"></div>
        <div class="row">
          <button class="btn" type="submit" name="action" value="on">✅ Activar mantenimiento</button>
          <button class="btn" type="submit" name="action" value="off">❌ Quitar mantenimiento</button>
        </div>

        <p class="muted" style="margin-top:10px;">
          Si ENABLE_OUTBOX=1, esto crea una notificación en la tabla <code>outbox</code> para que el bot la mande a todos.
        </p>
      </form>
    </div>
    """
    return page("Admin • Mantenimiento", body)


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
        # outbox para bot: aviso global
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
    <div class="card">
      <p class="muted">
        Para entrar al panel cliente, abre el bot y pide el link de acceso.
      </p>
      <p class="muted">
        El link es así: <code>/c/TOKEN</code>
      </p>
      <a class="btn" href="/">⬅️ Inicio</a>
    </div>
    """
    return page("Cliente", body)


@app.get("/c/{token}")
def client_magic_login(token: str):
    payload = verify(token, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")

    # cookie de sesión cliente por 7 días
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

    # Traer proxies
    proxies_rows = []
    try:
        cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    # Traer pedidos
    orders_rows = []
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
        proxy_text = raw or "HTTP\n" + (r['ip'] or "")
raw_block = f"<pre>{proxy_text}</pre>"
phtml += f"""
        <div class="card">
          <div class="muted">Proxy ID {r['id']} • {r['estado']}</div>
          <div style="height:6px;"></div>
          <div><b>{r['ip']}</b></div>
          <div class="muted">Inicio: {r['inicio']} • Vence: {r['vence']}</div>
          <div style="height:8px;"></div>
          {raw_block}
        </div>
        """
if not phtml:
        phtml = "<div class='card'><p class='muted'>No tienes proxies todavía.</p></div>"

ohtml = ""
for r in orders_rows:
        ohtml += f"<tr><td>#{r['id']}</td><td>{r['tipo']}</td><td>{r['ip'] or '-'}</td><td>{r['cantidad']}</td><td>{r['monto']}</td><td>{r['estado']}</td><td>{r['created_at']}</td></tr>"
if not ohtml:
        ohtml = "<tr><td colspan='7' class='muted'>No hay pedidos</td></tr>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn" href="/">🏠 Inicio</a>
        <a class="btn" href="/logout">🚪 Salir</a>
      </div>
      <div style="height:10px;"></div>
      <div class="muted">Tu Telegram ID</div>
      <div class="kpi">{uid}</div>
    </div>

    <h3 style="margin:12px 0 0 0;">📦 Mis proxies</h3>
    {phtml}

    <h3 style="margin:18px 0 0 0;">📨 Mis pedidos</h3>
    <div class="card">
      <table>
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th></tr>
        {ohtml}
      </table>
    </div>
    """
    return page("Panel Cliente", body)


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






