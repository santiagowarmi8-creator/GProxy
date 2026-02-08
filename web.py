# web.py — Gproxy Web Panel (FastAPI) PREMIUM + FIXED (FULL)
# ✅ Soporte (FAB flotante) => tickets (quejas) crear/ver + admin responde/cierra
# ✅ Aprobar/Rechazar sin "database is locked" (WAL + busy_timeout + BEGIN IMMEDIATE + retries)
# ✅ Stock = solo contador (admin pone cuántas proxies hay)
# ✅ Comprar/Renovar + voucher (imagen)
# ✅ Clientes viejos: "Agregar proxy existente" -> admin valida -> aparece en proxies y se puede renovar
# ✅ Recuperación de contraseña por PIN creado al registrarse
# ✅ Errores premium (sin detail/códigos)
#
# Railway: recomendado Volume y UPLOAD_DIR=/data/uploads

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, Tuple

from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# =========================
# CONFIG
# =========================
DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
JWT_SECRET = os.getenv("JWT_SECRET", "change_me_admin").strip()

APP_TITLE = os.getenv("APP_TITLE", "Gproxy")
ENABLE_OUTBOX = os.getenv("ENABLE_OUTBOX", "1").strip() == "1"

PIN_SECRET = os.getenv("PIN_SECRET", "").strip()

COOKIE_SECURE = (os.getenv("COOKIE_SECURE", "1").strip() == "1")
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").strip()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
VOUCHER_DIR = os.path.join(UPLOAD_DIR, "vouchers")

DEFAULT_DIAS_PROXY = 30

# =========================
# APP
# =========================
app = FastAPI(title=APP_TITLE)

os.makedirs(VOUCHER_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=UPLOAD_DIR), name="static")

CLIENT_SECRET: Optional[str] = None


# =========================
# Time helpers
# =========================
def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def parse_dt(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# =========================
# DB robust helpers (NO LOCKS)
# =========================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=8000;")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, coldef: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = {row[1] for row in cur.fetchall()}
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")
        conn.commit()


def _ensure_table(conn: sqlite3.Connection, create_sql: str) -> None:
    conn.execute(create_sql)
    conn.commit()


def db_exec(fn: Callable[[sqlite3.Connection], Any], retries: int = 5) -> Any:
    """
    Ejecuta una transacción segura evitando 'database is locked'.
    IMPORTANTÍSIMO: NO llames notify_user/admin_log/outbox_add dentro de fn().
    """
    last_err = None
    for i in range(retries):
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            res = fn(conn)
            conn.commit()
            return res
        except sqlite3.OperationalError as e:
            conn.rollback()
            last_err = e
            time.sleep(0.18 * (i + 1))
        except HTTPException:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            raise HTTPException(500, "Ocurrió un error interno. Intenta de nuevo.") from e
        finally:
            conn.close()
    raise HTTPException(503, "La base de datos está ocupada. Intenta de nuevo.") from last_err


# =========================
# UI helpers
# =========================
def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def page(title: str, body: str, subtitle: str = "", show_support: bool = True) -> str:
    t = html_escape(title)
    st = html_escape(subtitle)
    fab = """<a href="/support" class="support-fab" title="Soporte / Quejas">💬</a>""" if show_support else ""
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{t}</title>
<style>
:root {{
  --bg1:#070019; --bg2:#14002e; --bg3:#24003f;
  --card: rgba(255,255,255,.06);
  --border: rgba(255,255,255,.10);
  --muted:#cbb6ff; --text:#ffffff;
  --p1:#7b00ff; --p2:#c400ff; --p3:#00d4ff;
  --ok:#2bff9a; --warn:#ffb020; --bad:#ff4d6d;
  --shadow: 0 18px 60px rgba(0,0,0,.45);
}}
*{{box-sizing:border-box}}
body{{
  margin:0;
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
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
.wrap{{max-width:1100px;margin:0 auto;padding:28px 18px 60px;}}
.topbar{{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:14px;}}
.brand{{display:flex;align-items:center;gap:12px;}}
.logo{{
  width:44px;height:44px;border-radius:14px;
  background: linear-gradient(45deg, var(--p1), var(--p2));
  box-shadow: 0 0 30px rgba(196,0,255,.35);
  display:flex;align-items:center;justify-content:center;
  position:relative;overflow:hidden;
}}
.logo:before{{
  content:"";
  position:absolute; inset:-40%;
  background: conic-gradient(from 180deg, rgba(255,255,255,.0), rgba(255,255,255,.35), rgba(255,255,255,.0));
  animation: spin 4s linear infinite;
}}
.logo span{{position:relative;font-weight:900;}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.title{{font-size:18px;font-weight:800;margin:0;}}
.subtitle{{margin:0;color:var(--muted);font-size:13px;}}
.chip{{
  display:inline-flex;align-items:center;gap:8px;
  padding:10px 12px;border-radius:999px;
  background: rgba(255,255,255,.06);
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  white-space:nowrap;
}}
.grid{{display:grid;grid-template-columns:1.4fr .9fr;gap:16px;}}
@media (max-width:980px){{.grid{{grid-template-columns:1fr;}}}}
.card{{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 18px;
  box-shadow: var(--shadow);
  backdrop-filter: blur(14px);
  animation: pop .35s ease both;
}}
@keyframes pop{{from{{transform:translateY(6px);opacity:0}}to{{transform:translateY(0);opacity:1}}}}
.row{{display:flex;gap:12px;flex-wrap:wrap;align-items:center;}}
.btn{{
  appearance:none;border:none;border-radius:14px;
  padding:12px 16px;font-weight:750;color:white;text-decoration:none;
  cursor:pointer;
  background: linear-gradient(45deg, var(--p1), var(--p2));
  box-shadow: 0 12px 30px rgba(123,0,255,.22);
  transition: transform .15s ease, box-shadow .15s ease, filter .15s ease;
  display:inline-flex;align-items:center;gap:10px;
}}
.btn:hover{{transform: translateY(-2px); box-shadow:0 16px 38px rgba(196,0,255,.30); filter: brightness(1.03);}}
.btn:active{{transform: translateY(0); filter: brightness(.98);}}
.btn.ghost{{
  background: rgba(255,255,255,.06);
  border: 1px solid var(--border);
  box-shadow:none;
}}
.btn.bad{{
  background: linear-gradient(45deg, #ff2b6a, #ff7a2b);
  box-shadow: 0 12px 30px rgba(255,43,106,.20);
}}
.kpi{{
  font-size:34px;font-weight:900;margin-top:6px;
  background: linear-gradient(90deg, #fff, #e9dbff, #b9f2ff);
  -webkit-background-clip:text;background-clip:text;color: transparent;
}}
.muted{{color:var(--muted);font-size:13px;}}
.hr{{height:1px;background: linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent); margin: 14px 0;}}
input, textarea, select{{
  width:100%;
  padding:12px 14px;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.20);
  color:white;
  outline:none;
}}
textarea{{min-height:120px;}}
table{{width:100%;border-collapse:collapse;overflow:hidden;border-radius:14px;}}
th, td{{border-bottom:1px solid rgba(255,255,255,.10);padding:12px;text-align:left;font-size:13px;vertical-align:top;}}
th{{color:#f0eaff;font-weight:800;}}
pre, code{{background:rgba(0,0,0,.25); border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:12px; overflow:auto;}}
pre{{white-space:pre-wrap; word-break:break-word;}}
.status{{display:inline-flex;align-items:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.06);}}
.dot{{width:10px;height:10px;border-radius:50%;background:var(--ok);box-shadow:0 0 16px rgba(43,255,154,.35);}}
.dot.warn{{background:var(--warn);box-shadow:0 0 16px rgba(255,176,32,.35);}}
.badge{{
  display:inline-flex;align-items:center;justify-content:center;
  min-width:22px;height:22px;padding:0 8px;border-radius:999px;
  background: rgba(255,255,255,.10);
  border: 1px solid rgba(255,255,255,.14);
  font-size:12px;font-weight:800;color:white;
}}
.hero{{
  padding:18px;border-radius:20px;
  background: linear-gradient(135deg, rgba(123,0,255,.18), rgba(0,212,255,.10));
  border: 1px solid rgba(255,255,255,.10);
}}
.support-fab{{
  position:fixed; right:18px; bottom:18px;
  width:58px;height:58px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  text-decoration:none;font-size:26px;
  background: linear-gradient(45deg, var(--p3), var(--p2));
  box-shadow: 0 16px 40px rgba(0,212,255,.25);
  border: 1px solid rgba(255,255,255,.16);
  z-index:9999;
  transition: transform .15s ease, filter .15s ease;
}}
.support-fab:hover{{transform: translateY(-2px); filter: brightness(1.05);}}
.support-fab:active{{transform: translateY(0); filter: brightness(.98);}}
.footer{{margin-top:16px;color: rgba(255,255,255,.55);font-size:12px;text-align:center;}}
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

  {fab}
  <div class="footer">© {html_escape(APP_TITLE)} • Web Panel</div>
</div>
</body>
</html>"""


def nice_msg(title: str, msg: str, back_href: str = "/", show_support: bool = False) -> HTMLResponse:
    body = f"""
    <div class="card hero">
      <h1>{html_escape(title)}</h1>
      <p class="muted">{html_escape(msg)}</p>
      <div class="hr"></div>
      <a class="btn ghost" href="{html_escape(back_href)}">⬅️ Volver</a>
    </div>
    """
    return HTMLResponse(page(title, body, subtitle="", show_support=show_support), status_code=200)


# =========================
# Global error handlers (premium)
# =========================
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept or "*/*" in accept or accept == ""
    path = request.url.path

    # Redirecciones suaves para evitar "detail"
    if exc.status_code in (401, 403):
        if path.startswith("/admin"):
            return RedirectResponse(url="/admin/login", status_code=302)
        # rutas cliente
        return RedirectResponse(url="/client/login", status_code=302)

    if wants_html:
        msg = exc.detail if isinstance(exc.detail, str) else "Ocurrió un error."
        return nice_msg("⚠️ Aviso", msg, back_href="/", show_support=False)

    return HTMLResponse(json.dumps({"detail": exc.detail}, ensure_ascii=False), status_code=exc.status_code)


@app.exception_handler(Exception)
async def any_exc_handler(request: Request, exc: Exception):
    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept or "*/*" in accept or accept == ""
    if wants_html:
        return nice_msg("⚠️ Error interno", "Intenta de nuevo.", back_href="/", show_support=False)
    return HTMLResponse(json.dumps({"detail": "Internal Server Error"}), status_code=500)


# =========================
# Token helpers
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
    if not token:
        raise HTTPException(401, "No autorizado")
    t = (token or "").strip()
    parts = t.split(".")
    if len(parts) != 2:
        raise HTTPException(401, "No autorizado")
    raw = _b64urldecode(parts[0])
    sig = _b64urldecode(parts[1])
    good = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, good):
        raise HTTPException(401, "No autorizado")
    payload = json.loads(raw.decode("utf-8"))
    exp = int(payload.get("exp", 0) or 0)
    if exp <= 0 or exp < int(time.time()):
        raise HTTPException(401, "Sesión expirada")
    return payload


def require_admin(request: Request) -> Dict[str, Any]:
    tok = request.cookies.get("admin_session", "")
    payload = verify(tok, JWT_SECRET)
    if payload.get("role") != "admin":
        raise HTTPException(401, "No autorizado")
    return payload


def require_client(request: Request) -> Dict[str, Any]:
    if not CLIENT_SECRET:
        raise HTTPException(503, "Servidor iniciando. Intenta de nuevo.")
    tok = request.cookies.get("client_session", "")
    payload = verify(tok, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")
    return payload


# =========================
# Password hashing (PBKDF2)
# =========================
def _pbkdf2_hash(password: str, salt: bytes, rounds: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)


def password_make_hash(password: str) -> str:
    pwd = (password or "").strip()
    if len(pwd) < 6:
        raise HTTPException(400, "La contraseña debe tener mínimo 6 caracteres.")
    salt = secrets.token_bytes(16)
    dk = _pbkdf2_hash(pwd, salt)
    return "pbkdf2_sha256$200000$%s$%s" % (_b64url(salt), _b64url(dk))


def password_check(password: str, stored: str) -> bool:
    try:
        parts = (stored or "").split("$")
        if len(parts) != 4:
            return False
        algo, rounds_s, salt_b64, hash_b64 = parts
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = _b64urldecode(salt_b64)
        good = _b64urldecode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, rounds)
        return hmac.compare_digest(dk, good)
    except Exception:
        return False


# =========================
# PIN helpers
# =========================
def pin_hash(pin: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), pin.encode("utf-8"), hashlib.sha256).hexdigest()


def _pin_gen6() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(6))


def _time_plus_minutes(minutes: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + minutes * 60))


# =========================
# Settings helpers
# =========================
def get_setting(key: str, default: str = "") -> str:
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        return (row["value"] if row else default) or default
    finally:
        conn.close()


def set_setting(key: str, value: str):
    def _fn(conn):
        conn.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_str()),
        )
    db_exec(_fn)


# =========================
# Outbox/Logs/Notifications (separado para evitar locks)
# =========================
def outbox_add(kind: str, message: str):
    if not ENABLE_OUTBOX:
        return
    conn = db()
    try:
        conn.execute(
            "INSERT INTO outbox(kind,message,created_at,sent_at) VALUES(?,?,?,?)",
            (kind, message or "", now_str(), ""),
        )
        conn.commit()
    finally:
        conn.close()


def admin_log(action: str, details: str = ""):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO admin_logs(action,details,created_at) VALUES(?,?,?)",
            (action, details or "", now_str()),
        )
        conn.commit()
    finally:
        conn.close()


def notify_user(user_id: int, message: str):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO notifications(user_id,message,seen,created_at) VALUES(?,?,?,?)",
            (int(user_id), message or "", 0, now_str()),
        )
        conn.commit()
    finally:
        conn.close()


# =========================
# Schema / migrations
# =========================
def ensure_web_schema() -> str:
    conn = db()
    cur = conn.cursor()

    _ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)
    _ensure_column(conn, "settings", "updated_at", "TEXT NOT NULL DEFAULT ''")

    _ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_pin_hash TEXT NOT NULL DEFAULT '',
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT ''
    );
    """)

    _ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS signup_pins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      estado TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT ''
    );
    """)

    _ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      subject TEXT NOT NULL DEFAULT '',
      message TEXT NOT NULL,
      admin_reply TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT ''
    );
    """)

    _ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      seen INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT ''
    );
    """)

    _ensure_table(conn, """
    CREATE TABLE IF NOT EXISTS admin_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT ''
    );
    """)

    if ENABLE_OUTBOX:
        _ensure_table(conn, """
        CREATE TABLE IF NOT EXISTS outbox(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL,
          message TEXT NOT NULL,
          created_at TEXT NOT NULL,
          sent_at TEXT NOT NULL DEFAULT ''
        )
        """)

    def ins(key: str, val: str):
        cur.execute(
            "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
            (key, val, now_str()),
        )

    ins("maintenance_enabled", "0")
    ins("maintenance_message", "⚠️ Estamos en mantenimiento. Vuelve en unos minutos.")
    ins("bank_title", "Cuenta bancaria")
    ins("bank_details", "Banco: Banreservas (Ahorro)\nTitular: Yudith Domínguez\nCuenta: 4248676174")
    ins("precio_primera", "1500")
    ins("precio_renovacion", "1000")
    ins("dias_proxy", str(DEFAULT_DIAS_PROXY))
    ins("currency", "DOP")
    ins("stock_available", "0")

    # Persist client secret
    cur.execute("SELECT value FROM settings WHERE key=?", ("client_secret_persist",))
    row = cur.fetchone()
    db_secret = (row["value"] if row else "").strip()

    env_secret = (os.getenv("CLIENT_SECRET") or "").strip()
    if env_secret and env_secret not in ("change_me_client", ""):
        client_secret = env_secret
        if db_secret != client_secret:
            cur.execute(
                "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("client_secret_persist", client_secret, now_str()),
            )
    else:
        if db_secret:
            client_secret = db_secret
        else:
            client_secret = secrets.token_urlsafe(64)
            cur.execute(
                "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
                ("client_secret_persist", client_secret, now_str()),
            )

    global PIN_SECRET
    if not PIN_SECRET:
        PIN_SECRET = client_secret

    conn.commit()

    # Migraciones para tablas del bot (si existen)
    try:
        _ensure_column(conn, "requests", "voucher_path", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "voucher_uploaded_at", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "email", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "currency", "TEXT NOT NULL DEFAULT 'DOP'")
        _ensure_column(conn, "requests", "target_proxy_id", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "requests", "note", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "kind", "TEXT NOT NULL DEFAULT ''")  # para add_existing
    except Exception:
        pass

    try:
        _ensure_column(conn, "proxies", "inicio", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "proxies", "vence", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "proxies", "raw", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "proxies", "estado", "TEXT NOT NULL DEFAULT 'active'")
    except Exception:
        pass

    conn.close()
    return client_secret


@app.on_event("startup")
def _startup():
    global CLIENT_SECRET
    CLIENT_SECRET = ensure_web_schema()


# =========================
# Helpers business
# =========================
def _dias_proxy() -> int:
    try:
        d = int(float(get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY)) or DEFAULT_DIAS_PROXY))
    except Exception:
        d = DEFAULT_DIAS_PROXY
    if d > 30:
        d = 30
    if d <= 0:
        d = DEFAULT_DIAS_PROXY
    return d


# =========================
# HOME
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
        <h1>{html_escape(APP_TITLE)} — Panel Web</h1>
        <p class="muted">Proxies USA 🇺🇸 rápidas, privadas y estables.</p>
        <div class="hr"></div>
        <div class="row">
          <a class="btn" href="/admin/login">🔐 Admin</a>
          <a class="btn ghost" href="/client/login">👤 Clientes</a>
          <a class="btn ghost" href="/client/signup">✨ Crear cuenta</a>
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
        <div class="muted">¿Olvidaste tu contraseña?</div>
        <a class="btn ghost" href="/client/reset">🔑 Restablecer con PIN</a>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="Panel premium • Admin & Cliente", show_support=True)


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH, "client_secret_loaded": bool(CLIENT_SECRET)}


# =========================
# ADMIN AUTH
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Admin Access</h1>
        <p class="muted">Panel premium para pedidos, soporte, usuarios y control total.</p>
      </div>
      <div class="card">
        <form method="post" action="/admin/login">
          <label class="muted">Clave Admin</label>
          <input type="password" name="password" placeholder="Tu clave admin" />
          <div style="height:12px;"></div>
          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>
      </div>
    </div>
    """
    return page("Admin Login", body, subtitle="Ingreso seguro", show_support=False)


@app.post("/admin/login")
def admin_login(password: str = Form(...)):
    if not ADMIN_PASSWORD:
        return nice_msg("Falta configuración", "Define ADMIN_PASSWORD en Railway.", "/admin/login", False)
    if password != ADMIN_PASSWORD:
        return nice_msg("Clave incorrecta", "Verifica la clave e intenta de nuevo.", "/admin/login", False)

    token = sign({"role": "admin"}, JWT_SECRET, exp_seconds=8 * 3600)
    resp = RedirectResponse(url="/admin", status_code=302)
    resp.set_cookie("admin_session", token, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
    return resp


@app.get("/admin/logout")
def admin_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("admin_session")
    return resp


# =========================
# ADMIN DASHBOARD
# =========================
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()

    def count(sql: str, params=()) -> int:
        try:
            cur.execute(sql, params)
            return int(cur.fetchone()[0])
        except Exception:
            return 0

    users = count("SELECT COUNT(*) FROM users")
    proxies = count("SELECT COUNT(*) FROM proxies")
    tickets_open = count("SELECT COUNT(*) FROM tickets WHERE status='open'")
    pending = count("SELECT COUNT(*) FROM requests WHERE estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')")
    stock = int(float(get_setting("stock_available", "0") or "0"))

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    conn.close()

    body = f"""
    <div class="card hero">
      <h1>Admin Dashboard</h1>
      <p class="muted">Control total: pedidos, soporte, usuarios y configuración.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/orders">📨 Pedidos <span class="badge">{pending}</span></a>
        <a class="btn" href="/admin/users">👥 Usuarios</a>
        <a class="btn" href="/admin/tickets">💬 Tickets <span class="badge">{tickets_open}</span></a>
        <a class="btn" href="/admin/proxies">📦 Proxies</a>
        <a class="btn" href="/admin/settings">⚙️ Banco/Precios/Stock</a>
        <a class="btn" href="/admin/maintenance">🛠 Mantenimiento</a>
        <a class="btn ghost" href="/admin/logout" style="margin-left:auto;">🚪 Salir</a>
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
        <div class="muted">Stock disponible</div>
        <div class="kpi">{stock}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Tickets abiertos</div>
        <div class="kpi">{tickets_open}</div>
      </div>
    </div>

    <div class="card">
      <div class="muted">Mantenimiento</div>
      <div class="kpi">{'🟠 ON' if maint else '🟢 OFF'}</div>
      <p class="muted">{html_escape(mtxt)}</p>
    </div>
    """
    return page("Admin", body, subtitle="Panel premium • Gproxy", show_support=False)


# =========================
# ADMIN SETTINGS (Banco + precios + stock)
# =========================
@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_page(admin=Depends(require_admin)):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")
    precio_primera = get_setting("precio_primera", "1500")
    precio_renov = get_setting("precio_renovacion", "1000")
    dias_proxy = get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY))
    currency = get_setting("currency", "DOP")
    stock_available = get_setting("stock_available", "0")

    body = f"""
    <div class="card hero">
      <h1>⚙️ Banco / Precios / Stock</h1>
      <p class="muted">Configura el sistema sin complicaciones.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
    </div>

    <div class="card">
      <form method="post" action="/admin/settings">
        <h3 style="margin:0 0 10px 0;">🏦 Cuenta bancaria</h3>
        <label class="muted">Título</label>
        <input name="bank_title" value="{html_escape(title)}" />
        <div style="height:12px;"></div>

        <label class="muted">Detalles</label>
        <textarea name="bank_details">{html_escape(details)}</textarea>

        <div class="hr"></div>
        <h3 style="margin:0 0 10px 0;">💰 Precios</h3>

        <label class="muted">Moneda</label>
        <input name="currency" value="{html_escape(currency)}" />

        <div style="height:12px;"></div>
        <label class="muted">Primera compra</label>
        <input name="precio_primera" value="{html_escape(precio_primera)}" />

        <div style="height:12px;"></div>
        <label class="muted">Renovación</label>
        <input name="precio_renovacion" value="{html_escape(precio_renov)}" />

        <div style="height:12px;"></div>
        <label class="muted">Duración proxy (días) — máximo 30</label>
        <input name="dias_proxy" value="{html_escape(dias_proxy)}" />

        <div class="hr"></div>
        <h3 style="margin:0 0 10px 0;">🧰 Stock (contador)</h3>
        <label class="muted">Proxies disponibles</label>
        <input name="stock_available" value="{html_escape(stock_available)}" />

        <div style="height:12px;"></div>
        <button class="btn" type="submit">💾 Guardar</button>
      </form>
    </div>
    """
    return page("Admin • Settings", body, subtitle="Configurar sistema", show_support=False)


@app.post("/admin/settings")
def admin_settings_save(
    bank_title: str = Form("Cuenta bancaria"),
    bank_details: str = Form(""),
    currency: str = Form("DOP"),
    precio_primera: str = Form("1500"),
    precio_renovacion: str = Form("1000"),
    dias_proxy: str = Form(str(DEFAULT_DIAS_PROXY)),
    stock_available: str = Form("0"),
    admin=Depends(require_admin),
):
    def to_int(x: str, default: int) -> int:
        try:
            v = int(float((x or "").strip()))
            return v if v >= 0 else default
        except Exception:
            return default

    p1 = to_int(precio_primera, 1500)
    pr = to_int(precio_renovacion, 1000)
    dp = to_int(dias_proxy, DEFAULT_DIAS_PROXY)
    if dp > 30:
        dp = 30
    if dp <= 0:
        dp = DEFAULT_DIAS_PROXY

    stock = to_int(stock_available, 0)

    set_setting("bank_title", (bank_title or "Cuenta bancaria").strip())
    set_setting("bank_details", (bank_details or "").strip())
    set_setting("currency", (currency or "DOP").strip() or "DOP")
    set_setting("precio_primera", str(p1))
    set_setting("precio_renovacion", str(pr))
    set_setting("dias_proxy", str(dp))
    set_setting("stock_available", str(stock))

    admin_log("settings_update", json.dumps({"p1": p1, "pr": pr, "dias": dp, "stock": stock}, ensure_ascii=False))
    return RedirectResponse(url="/admin/settings", status_code=302)


# =========================
# ADMIN MAINTENANCE
# =========================
@app.get("/admin/maintenance", response_class=HTMLResponse)
def admin_maintenance_page(admin=Depends(require_admin)):
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>Mantenimiento</h1>
      <p class="muted">Activa o desactiva mantenimiento (web).</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
    </div>

    <div class="card">
      <div class="muted">Estado actual</div>
      <div class="kpi">{'🟠 ON' if enabled else '🟢 OFF'}</div>
      <div class="hr"></div>

      <form method="post" action="/admin/maintenance">
        <label class="muted">Mensaje para clientes</label>
        <textarea name="message">{html_escape(msg)}</textarea>
        <div style="height:12px;"></div>
        <div class="row">
          <button class="btn" type="submit" name="action" value="on">✅ Activar</button>
          <button class="btn ghost" type="submit" name="action" value="off">❌ Desactivar</button>
        </div>
      </form>
    </div>
    """
    return page("Admin • Mantenimiento", body, subtitle="Control", show_support=False)


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
        admin_log("maintenance_on", msg)
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    if action == "off":
        set_setting("maintenance_enabled", "0")
        admin_log("maintenance_off", msg)
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    raise HTTPException(400, "Acción inválida")


# =========================
# ADMIN USERS
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
                "ORDER BY last_seen DESC LIMIT 80",
                (f"%{q.strip()}%", f"%{q.strip()}%"),
            )
        else:
            cur.execute("SELECT user_id, username, is_blocked, last_seen FROM users ORDER BY last_seen DESC LIMIT 80")
        rows = cur.fetchall()
    except Exception:
        rows = []
    conn.close()

    trs = ""
    for r in rows:
        uid = int(r["user_id"])
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
    return page("Admin • Usuarios", body, subtitle="Gestión de usuarios", show_support=False)


@app.post("/admin/user/{user_id}/toggle_block")
def admin_toggle_block(user_id: int, admin=Depends(require_admin)):
    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT is_blocked FROM users WHERE user_id=?", (int(user_id),))
        row = cur.fetchone()
        curv = int(row["is_blocked"] or 0) if row else 0
        newv = 0 if curv == 1 else 1
        cur.execute("UPDATE users SET is_blocked=? WHERE user_id=?", (newv, int(user_id)))
        return newv

    newv = db_exec(_fn)
    admin_log("user_toggle_block", json.dumps({"user_id": user_id, "blocked": newv}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/user/{int(user_id)}", status_code=302)


@app.get("/admin/user/{user_id}", response_class=HTMLResponse)
def admin_user_detail(user_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT user_id, username, is_blocked, created_at, last_seen FROM users WHERE user_id=?", (int(user_id),))
        u = cur.fetchone()
    except Exception:
        u = None

    proxies_rows = []
    req_rows = []
    try:
        cur.execute("SELECT id, ip, vence, estado FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 80", (int(user_id),))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, kind, ip, cantidad, monto, estado, created_at, voucher_path FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 80",
            (int(user_id),),
        )
        req_rows = cur.fetchall()
    except Exception:
        req_rows = []

    conn.close()

    if not u:
        return nice_msg("No encontrado", "No encontré ese usuario.", "/admin/users", False)

    uname = u["username"] or "-"
    blocked = int(u["is_blocked"] or 0)
    tag = "🚫 BLOQUEADO" if blocked == 1 else "✅ ACTIVO"

    phtml = ""
    for r in proxies_rows:
        phtml += f"<tr><td>{int(r['id'])}</td><td>{html_escape(r['ip'] or '')}</td><td>{html_escape(r['vence'] or '')}</td><td>{html_escape(r['estado'] or '')}</td></tr>"
    if not phtml:
        phtml = "<tr><td colspan='4' class='muted'>Sin proxies</td></tr>"

    ohtml = ""
    for r in req_rows:
        voucher = (r["voucher_path"] or "").strip()
        vcell = f"<a href='/static/{html_escape(voucher)}' target='_blank'>ver</a>" if voucher else "-"
        kind = (r["kind"] or "").strip()
        kind_txt = f" / {html_escape(kind)}" if kind else ""
        ohtml += (
            "<tr>"
            f"<td>#{int(r['id'])}</td>"
            f"<td>{html_escape(r['tipo'] or '')}{kind_txt}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{int(r['cantidad'] or 0)}</td>"
            f"<td>{html_escape(str(r['monto'] or ''))}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{vcell}</td>"
            "</tr>"
        )
    if not ohtml:
        ohtml = "<tr><td colspan='8' class='muted'>Sin pedidos</td></tr>"

    toggle_label = "🔓 Desbloquear" if blocked == 1 else "⛔ Bloquear"
    toggle_class = "btn" if blocked == 1 else "btn bad"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/users">⬅️ Usuarios</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>

        <form method="post" action="/admin/user/{int(user_id)}/toggle_block" style="margin-left:auto;">
          <button class="{toggle_class}" type="submit">{toggle_label}</button>
        </form>
      </div>

      <div class="hr"></div>
      <div class="muted">Usuario</div>
      <div class="kpi">{int(user_id)}</div>
      <p class="muted">@{html_escape(uname)} • {tag}</p>
      <p class="muted">Creado: {html_escape(u['created_at'] or '-')} • Last seen: {html_escape(u['last_seen'] or '-')}</p>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📦 Proxies</h3>
      <table>
        <tr><th>PID</th><th>IP</th><th>Vence</th><th>Estado</th></tr>
        {phtml}
      </table>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📨 Pedidos</h3>
      <table>
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th><th>Voucher</th></tr>
        {ohtml}
      </table>
    </div>
    """
    return page(f"Admin • Usuario {int(user_id)}", body, subtitle="Detalle", show_support=False)


# =========================
# ADMIN PROXIES + EDIT
# =========================
@app.get("/admin/proxies", response_class=HTMLResponse)
def admin_proxies(admin=Depends(require_admin), q: str = ""):
    conn = db()
    cur = conn.cursor()
    rows = []
    try:
        if q.strip():
            cur.execute(
                "SELECT id, user_id, ip, vence, estado FROM proxies WHERE CAST(user_id AS TEXT) LIKE ? OR ip LIKE ? ORDER BY id DESC LIMIT 150",
                (f"%{q.strip()}%", f"%{q.strip()}%"),
            )
        else:
            cur.execute("SELECT id, user_id, ip, vence, estado FROM proxies ORDER BY id DESC LIMIT 150")
        rows = cur.fetchall()
    except Exception:
        rows = []
    conn.close()

    trs = ""
    for r in rows:
        trs += (
            "<tr>"
            f"<td><code>{int(r['id'])}</code></td>"
            f"<td><a class='btn ghost' href='/admin/user/{int(r['user_id'])}'>👤 {int(r['user_id'])}</a></td>"
            f"<td>{html_escape(r['ip'] or '')}</td>"
            f"<td>{html_escape(r['vence'] or '')}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td><a class='btn ghost' href='/admin/proxy/{int(r['id'])}/edit'>✏️ Editar</a></td>"
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
        <tr><th>PID</th><th>User</th><th>IP</th><th>Vence</th><th>Estado</th><th></th></tr>
        {trs or "<tr><td colspan='6' class='muted'>No hay proxies</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Proxies", body, subtitle="Listado", show_support=False)


@app.get("/admin/proxy/{pid}/edit", response_class=HTMLResponse)
def admin_proxy_edit(pid: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,user_id,ip,raw,estado,vence FROM proxies WHERE id=?", (int(pid),))
    p = cur.fetchone()
    conn.close()
    if not p:
        return nice_msg("No existe", "No encontré ese proxy.", "/admin/proxies", False)

    body = f"""
    <div class="card hero">
      <h1>✏️ Editar proxy #{int(pid)}</h1>
      <p class="muted">Usuario: <b>{int(p['user_id'])}</b> • Vence: <b>{html_escape(p['vence'] or '')}</b></p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin/proxies">⬅️ Volver</a>
    </div>

    <div class="card">
      <form method="post" action="/admin/proxy/{int(pid)}/edit">
        <label class="muted">IP</label>
        <input name="ip" value="{html_escape(p['ip'] or '')}" />
        <div style="height:12px;"></div>

        <label class="muted">RAW (proxy completo)</label>
        <textarea name="raw">{html_escape(p['raw'] or '')}</textarea>
        <div style="height:12px;"></div>

        <label class="muted">Estado</label>
        <input name="estado" value="{html_escape(p['estado'] or '')}" placeholder="active / pending_delivery" />
        <div style="height:12px;"></div>

        <button class="btn" type="submit">💾 Guardar</button>
      </form>
    </div>
    """
    return page("Admin • Editar proxy", body, subtitle="Control", show_support=False)


@app.post("/admin/proxy/{pid}/edit")
def admin_proxy_edit_save(pid: int, ip: str = Form(""), raw: str = Form(""), estado: str = Form("active"), admin=Depends(require_admin)):
    ip = (ip or "").strip()
    raw = (raw or "").strip()
    estado = (estado or "active").strip()

    def _fn(conn):
        conn.execute("UPDATE proxies SET ip=?, raw=?, estado=? WHERE id=?", (ip, raw, estado, int(pid)))

    db_exec(_fn)
    admin_log("proxy_edit", json.dumps({"pid": pid, "ip": ip, "estado": estado}, ensure_ascii=False))
    return RedirectResponse(url="/admin/proxies", status_code=302)


# =========================
# ADMIN ORDERS
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

    try:
        cur.execute(
            f"""SELECT id, user_id, tipo, kind, ip, cantidad, monto, estado, created_at,
                       voucher_path, email, currency, target_proxy_id, note
                FROM requests
                {where}
                ORDER BY id DESC
                LIMIT 160""",
            params,
        )
        rows = cur.fetchall()
    except Exception:
        rows = []

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
        voucher_path = (r["voucher_path"] or "").strip()
        voucher_link = f"<a class='btn ghost' href='/static/{html_escape(voucher_path)}' target='_blank'>🧾 Ver voucher</a>" if voucher_path else "<span class='muted'>Sin voucher</span>"
        email = (r["email"] or "").strip()
        email_txt = f" • Factura: <b>{html_escape(email)}</b>" if email else ""
        kind = (r["kind"] or "").strip()
        kind_txt = f" / <b>{html_escape(kind)}</b>" if kind else ""

        extra = ""
        if (r["tipo"] or "") == "renew" and int(r["target_proxy_id"] or 0) > 0:
            extra = f"<div class='muted'>Proxy a renovar: <b>#{int(r['target_proxy_id'])}</b></div>"
        if (r["tipo"] or "") == "add" and kind == "existing_proxy":
            extra = "<div class='muted'>Solicitud: agregar proxy existente</div>"

        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Pedido <b>#{rid}</b> • Estado: <b>{html_escape(r["estado"] or "")}</b></div>
          <div style="height:8px;"></div>
          <div><b>Usuario:</b> <a class="btn ghost" href="/admin/user/{int(r["user_id"])}">👤 {int(r["user_id"])}</a></div>
          <div class="muted" style="margin-top:6px;">
            Tipo: <b>{html_escape(r["tipo"] or "")}</b>{kind_txt}
            • IP: <b>{html_escape(r["ip"] or "-")}</b>
            • Qty: <b>{int(r["cantidad"] or 0)}</b>
            • Monto: <b>{html_escape(str(r["monto"] or ""))} {html_escape(r["currency"] or "DOP")}</b>
            {email_txt}
            <br/>Creado: {html_escape(r["created_at"] or "")}
          </div>
          {extra}

          <div class="hr"></div>
          <div class="row">
            {voucher_link}
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
        <select name="state">{opt_html}</select>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Aplicar filtro</button>
      </form>
    </div>
    {cards}
    """
    return page("Admin • Pedidos", body, subtitle="Aprobar / Rechazar", show_support=False)


def _deliver_buy_placeholder(conn: sqlite3.Connection, user_id: int, qty: int, dias: int) -> int:
    """
    No usas pool. Entregamos placeholders 'PENDING_ASSIGNMENT' para que el admin edite luego (control premium).
    """
    start = datetime.now()
    vence = start + timedelta(days=dias)

    # stock contador
    stock = int(float(get_setting("stock_available", "0") or "0"))
    if stock < qty:
        raise HTTPException(400, f"No hay stock suficiente. Disponible: {stock}")

    conn.execute(
        "UPDATE settings SET value=?, updated_at=? WHERE key=?",
        (str(stock - qty), now_str(), "stock_available"),
    )

    for _ in range(qty):
        conn.execute(
            "INSERT INTO proxies(user_id, ip, inicio, vence, estado, raw) VALUES(?,?,?,?,?,?)",
            (int(user_id), "PENDING_ASSIGNMENT", fmt_dt(start), fmt_dt(vence), "pending_delivery", ""),
        )
    return qty


def _deliver_renew(conn: sqlite3.Connection, user_id: int, proxy_id: int, dias: int):
    cur = conn.cursor()
    cur.execute("SELECT id, vence FROM proxies WHERE id=? AND user_id=?", (int(proxy_id), int(user_id)))
    p = cur.fetchone()
    if not p:
        raise HTTPException(400, "No encontré ese proxy para renovar en ese usuario.")

    v_old = parse_dt(p["vence"] or "") or datetime.now()
    base = v_old if v_old > datetime.now() else datetime.now()
    v_new = base + timedelta(days=dias)
    conn.execute("UPDATE proxies SET vence=?, estado='active' WHERE id=?", (fmt_dt(v_new), int(proxy_id)))


def _approve_existing_proxy(conn: sqlite3.Connection, user_id: int, raw: str, ip: str, dias: int):
    start = datetime.now()
    vence = start + timedelta(days=dias)
    conn.execute(
        "INSERT INTO proxies(user_id, ip, inicio, vence, estado, raw) VALUES(?,?,?,?,?,?)",
        (int(user_id), ip or "EXISTING", fmt_dt(start), fmt_dt(vence), "active", raw or ""),
    )


@app.post("/admin/order/{rid}/approve")
def admin_order_approve(rid: int, admin=Depends(require_admin)):
    dias = _dias_proxy()

    def _fn(conn) -> Tuple[int, int, str, str]:
        cur = conn.cursor()
        cur.execute("SELECT * FROM requests WHERE id=?", (int(rid),))
        req = cur.fetchone()
        if not req:
            raise HTTPException(404, "Pedido no encontrado")

        estado = (req["estado"] or "").strip()
        if estado in ("approved", "rejected", "cancelled"):
            return int(req["user_id"]), int(req["cantidad"] or 1), (req["tipo"] or ""), (req["kind"] or "")

        tipo = (req["tipo"] or "").strip()
        kind = (req["kind"] or "").strip()
        uid = int(req["user_id"])
        qty = int(req["cantidad"] or 1)
        target_proxy_id = int(req["target_proxy_id"] or 0)
        ip = (req["ip"] or "").strip()
        note = (req["note"] or "").strip()

        if tipo == "buy":
            _deliver_buy_placeholder(conn, uid, max(1, qty), dias)
        elif tipo == "renew":
            if target_proxy_id <= 0:
                raise HTTPException(400, "Pedido de renovación sin Proxy ID.")
            _deliver_renew(conn, uid, target_proxy_id, dias)
        elif tipo == "add" and kind == "existing_proxy":
            _approve_existing_proxy(conn, uid, raw=note, ip=ip, dias=dias)

        conn.execute("UPDATE requests SET estado=? WHERE id=?", ("approved", int(rid)))
        return uid, qty, tipo, kind

    uid, qty, tipo, kind = db_exec(_fn)

    if tipo == "buy":
        notify_user(uid, f"✅ Compra aprobada. Se entregaron {qty} proxy(s). Si ves PENDING, espera asignación.")
    elif tipo == "renew":
        notify_user(uid, f"✅ Renovación aprobada. Tu proxy fue extendida {dias} días.")
    elif tipo == "add" and kind == "existing_proxy":
        notify_user(uid, "✅ Proxy existente aprobada y agregada a tu cuenta.")
    else:
        notify_user(uid, "✅ Tu pedido fue aprobado.")

    admin_log("order_approve", json.dumps({"rid": rid, "uid": uid, "tipo": tipo, "kind": kind}, ensure_ascii=False))
    outbox_add("order_approved", json.dumps({"rid": rid, "uid": uid, "tipo": tipo, "kind": kind}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


@app.post("/admin/order/{rid}/reject")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    def _fn(conn) -> Tuple[int, str, str]:
        cur = conn.cursor()
        cur.execute("SELECT id,user_id,tipo,kind,estado FROM requests WHERE id=?", (int(rid),))
        req = cur.fetchone()
        if not req:
            raise HTTPException(404, "Pedido no encontrado")
        if (req["estado"] or "") in ("approved", "rejected", "cancelled"):
            return int(req["user_id"]), (req["tipo"] or ""), (req["kind"] or "")
        conn.execute("UPDATE requests SET estado=? WHERE id=?", ("rejected", int(rid)))
        return int(req["user_id"]), (req["tipo"] or ""), (req["kind"] or "")

    uid, tipo, kind = db_exec(_fn)
    notify_user(uid, f"❌ Tu pedido #{rid} fue rechazado. Si necesitas ayuda, escribe a soporte.")
    admin_log("order_reject", json.dumps({"rid": rid, "uid": uid, "tipo": tipo, "kind": kind}, ensure_ascii=False))
    outbox_add("order_rejected", json.dumps({"rid": rid, "uid": uid, "tipo": tipo, "kind": kind}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


# =========================
# ADMIN TICKETS
# =========================
@app.get("/admin/tickets", response_class=HTMLResponse)
def admin_tickets(admin=Depends(require_admin), state: str = "open"):
    state = (state or "open").strip()
    if state not in ("open", "answered", "closed"):
        state = "open"

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,user_id,subject,message,admin_reply,status,created_at FROM tickets WHERE status=? ORDER BY id DESC LIMIT 150",
        (state,),
    )
    rows = cur.fetchall()
    conn.close()

    cards = ""
    for t in rows:
        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Ticket <b>#{int(t['id'])}</b> • Usuario <b>{int(t['user_id'])}</b> • Estado: <b>{html_escape(t['status'])}</b></div>
          <div style="height:8px;"></div>
          <div><b>{html_escape(t['subject'] or 'Soporte / Queja')}</b></div>
          <pre>{html_escape(t['message'] or '')}</pre>
          <div class="hr"></div>

          <form method="post" action="/admin/ticket/{int(t['id'])}/reply">
            <label class="muted">Respuesta</label>
            <textarea name="reply" placeholder="Escribe respuesta...">{html_escape(t['admin_reply'] or '')}</textarea>
            <div style="height:12px;"></div>
            <div class="row">
              <button class="btn" type="submit" name="action" value="reply">📩 Guardar respuesta</button>
              <button class="btn ghost" type="submit" name="action" value="close">✅ Cerrar</button>
            </div>
          </form>
        </div>
        """
    if not cards:
        cards = "<div class='card'><p class='muted'>No hay tickets en este estado.</p></div>"

    body = f"""
    <div class="card hero">
      <h1>💬 Tickets de soporte</h1>
      <p class="muted">Responde y cierra quejas/tickets.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
        <a class="btn ghost" href="/admin/tickets?state=open">Abiertos</a>
        <a class="btn ghost" href="/admin/tickets?state=answered">Respondidos</a>
        <a class="btn ghost" href="/admin/tickets?state=closed">Cerrados</a>
      </div>
    </div>
    {cards}
    """
    return page("Admin • Tickets", body, subtitle="Soporte", show_support=False)


@app.post("/admin/ticket/{tid}/reply")
def admin_ticket_reply(tid: int, reply: str = Form(""), action: str = Form("reply"), admin=Depends(require_admin)):
    reply = (reply or "").strip()
    action = (action or "reply").strip()

    def _fn(conn) -> int:
        cur = conn.cursor()
        cur.execute("SELECT id,user_id FROM tickets WHERE id=?", (int(tid),))
        t = cur.fetchone()
        if not t:
            raise HTTPException(404, "Ticket no encontrado")

        if action == "close":
            conn.execute("UPDATE tickets SET status='closed', updated_at=? WHERE id=?", (now_str(), int(tid)))
            return int(t["user_id"])

        new_status = "answered" if reply else "open"
        conn.execute(
            "UPDATE tickets SET admin_reply=?, status=?, updated_at=? WHERE id=?",
            (reply, new_status, now_str(), int(tid)),
        )
        return int(t["user_id"])

    uid = db_exec(_fn)

    if action == "close":
        notify_user(uid, f"✅ Tu ticket #{tid} fue cerrado. Si necesitas más ayuda, abre otro.")
        admin_log("ticket_close", json.dumps({"tid": tid}, ensure_ascii=False))
    else:
        if reply:
            notify_user(uid, f"💬 Soporte respondió tu ticket #{tid}. Entra a Soporte para verlo.")
        admin_log("ticket_reply", json.dumps({"tid": tid}, ensure_ascii=False))

    return RedirectResponse(url="/admin/tickets?state=open", status_code=302)


# =========================
# CLIENT AUTH (signup / verify / login / reset)
# =========================
@app.get("/client/signup", response_class=HTMLResponse)
def client_signup_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Crear cuenta</h1>
        <p class="muted">Regístrate con Teléfono + Contraseña. Crea un PIN de recuperación para cuando olvides tu clave.</p>
      </div>

      <div class="card">
        <form method="post" action="/client/signup">
          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Contraseña (mín 6)</label>
          <input name="password" type="password" placeholder="••••••" />
          <div style="height:12px;"></div>

          <label class="muted">PIN de recuperación (6 dígitos)</label>
          <input name="recovery_pin" placeholder="Ej: 123456" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Crear cuenta</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">¿Ya tienes cuenta? <a href="/client/login" style="color:white;">Inicia sesión</a></p>
      </div>
    </div>
    """
    return page("Cliente • Crear cuenta", body, subtitle="Registro", show_support=False)


@app.post("/client/signup", response_class=HTMLResponse)
def client_signup(phone: str = Form(...), password: str = Form(...), recovery_pin: str = Form(...)):
    phone = (phone or "").strip()
    password = (password or "").strip()
    recovery_pin = (recovery_pin or "").strip()

    if not phone or len(phone) < 8:
        return nice_msg("Teléfono inválido", "Escribe un teléfono válido.", "/client/signup", False)
    if not password or len(password) < 6:
        return nice_msg("Contraseña inválida", "Mínimo 6 caracteres.", "/client/signup", False)
    if not (recovery_pin.isdigit() and len(recovery_pin) == 6):
        return nice_msg("PIN inválido", "El PIN debe ser de 6 dígitos.", "/client/signup", False)

    pwd_hash = password_make_hash(password)
    rpin_hash = pin_hash(recovery_pin, PIN_SECRET)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id FROM accounts WHERE phone=?", (phone,))
        if cur.fetchone():
            raise HTTPException(400, "Ese teléfono ya existe. Inicia sesión o usa otro.")

        cur.execute(
            "INSERT INTO accounts(phone,password_hash,recovery_pin_hash,verified,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (phone, pwd_hash, rpin_hash, 0, now_str(), now_str()),
        )

        pin = _pin_gen6()
        exp = _time_plus_minutes(5)
        cur.execute(
            "INSERT INTO signup_pins(phone,pin_hash,expires_at,attempts,estado,created_at) VALUES(?,?,?,?,?,?)",
            (phone, pin_hash(pin, PIN_SECRET), exp, 0, "pending", now_str()),
        )
        return pin, exp

    try:
        pin, exp = db_exec(_fn)
    except HTTPException as e:
        return nice_msg("No se pudo crear", str(e.detail), "/client/signup", False)

    body = f"""
    <div class="card hero">
      <h1>✅ Cuenta creada</h1>
      <p class="muted">Confirma tu cuenta con el PIN de verificación (expira en 5 minutos).</p>
    </div>

    <div class="card">
      <div class="muted">Tu PIN (se muestra una sola vez)</div>
      <div class="kpi" style="letter-spacing:6px;">{html_escape(pin)}</div>
      <p class="muted">Expira: <b>{html_escape(exp)}</b></p>
    </div>

    <div class="card">
      <form method="post" action="/client/verify">
        <input type="hidden" name="phone" value="{html_escape(phone)}" />
        <label class="muted">Escribe el PIN</label>
        <input name="pin" placeholder="123456" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Verificar cuenta</button>
        <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
      </form>
    </div>
    """
    return HTMLResponse(page("Cliente • Verificación", body, subtitle="Confirmar cuenta", show_support=False))


@app.post("/client/verify", response_class=HTMLResponse)
def client_verify(phone: str = Form(...), pin: str = Form(...)):
    phone = (phone or "").strip()
    pin = (pin or "").strip()

    if not phone or not (pin.isdigit() and len(pin) == 6):
        return nice_msg("Datos inválidos", "Revisa el PIN.", "/client/login", False)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            """SELECT id, pin_hash, expires_at, attempts, estado
               FROM signup_pins
               WHERE phone=? AND estado='pending'
               ORDER BY id DESC LIMIT 1""",
            (phone,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "No hay un PIN activo. Vuelve a registrarte.")

        pid = int(row["id"])
        exp = row["expires_at"] or ""
        attempts = int(row["attempts"] or 0)

        try:
            exp_ts = time.mktime(time.strptime(exp, "%Y-%m-%d %H:%M:%S"))
            if time.time() > exp_ts:
                cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
                raise HTTPException(400, "PIN expirado. Regístrate de nuevo.")
        except HTTPException:
            raise
        except Exception:
            pass

        given = pin_hash(pin, PIN_SECRET)
        good = (row["pin_hash"] or "").strip()
        if not hmac.compare_digest(good, given):
            attempts += 1
            cur.execute("UPDATE signup_pins SET attempts=? WHERE id=?", (attempts, pid))
            if attempts >= 3:
                cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
            raise HTTPException(400, f"PIN incorrecto. Intentos: {attempts}/3")

        cur.execute("UPDATE signup_pins SET estado='done' WHERE id=?", (pid,))
        cur.execute("UPDATE accounts SET verified=1, updated_at=? WHERE phone=?", (now_str(), phone))

    try:
        db_exec(_fn)
    except HTTPException as e:
        return nice_msg("No se pudo verificar", str(e.detail), "/client/login", False)

    body = """
    <div class="card hero">
      <h1>✅ Cuenta verificada</h1>
      <p class="muted">Ya puedes iniciar sesión.</p>
      <div class="hr"></div>
      <a class="btn" href="/client/login">🔐 Iniciar sesión</a>
    </div>
    """
    return HTMLResponse(page("Cliente • Verificado", body, subtitle="Listo", show_support=False))


@app.get("/client/login", response_class=HTMLResponse)
def client_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Panel Cliente</h1>
        <p class="muted">Entra con tu Teléfono + Contraseña.</p>
      </div>

      <div class="card">
        <form method="post" action="/client/login">
          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Contraseña</label>
          <input name="password" type="password" placeholder="••••••" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <div class="row">
          <a class="btn ghost" href="/client/signup">✨ Crear cuenta</a>
          <a class="btn ghost" href="/client/reset">🔑 Olvidé mi contraseña</a>
        </div>
      </div>
    </div>
    """
    return page("Cliente • Login", body, subtitle="Acceso seguro", show_support=False)


def account_verify_login(phone: str, password: str) -> Optional[int]:
    phone = (phone or "").strip()
    password = (password or "").strip()
    if not phone or not password:
        return None

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, verified FROM accounts WHERE phone=?", (phone,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return None
    if int(row["verified"] or 0) != 1:
        return None
    if not password_check(password, (row["password_hash"] or "")):
        return None
    return int(row["id"])


@app.post("/client/login")
def client_login(phone: str = Form(...), password: str = Form(...)):
    uid = account_verify_login(phone, password)
    if not uid:
        return nice_msg("Login inválido", "Verifica teléfono/contraseña y que la cuenta esté verificada.", "/client/login", False)

    session = sign({"role": "client", "uid": int(uid)}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie("client_session", session, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
    return resp


@app.get("/logout")
def client_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("client_session")
    return resp


@app.get("/client/reset", response_class=HTMLResponse)
def client_reset_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>🔑 Restablecer contraseña</h1>
        <p class="muted">Usa tu PIN de recuperación (el que creaste al registrarte).</p>
      </div>

      <div class="card">
        <form method="post" action="/client/reset">
          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">PIN de recuperación (6 dígitos)</label>
          <input name="recovery_pin" placeholder="123456" />
          <div style="height:12px;"></div>

          <label class="muted">Nueva contraseña</label>
          <input name="new_password" type="password" placeholder="mín 6" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Cambiar contraseña</button>
          <a class="btn ghost" href="/client/login" style="margin-left:10px;">⬅️ Login</a>
        </form>
      </div>
    </div>
    """
    return page("Cliente • Reset", body, subtitle="Recuperación", show_support=False)


@app.post("/client/reset", response_class=HTMLResponse)
def client_reset_submit(phone: str = Form(...), recovery_pin: str = Form(...), new_password: str = Form(...)):
    phone = (phone or "").strip()
    recovery_pin = (recovery_pin or "").strip()
    new_password = (new_password or "").strip()

    if not phone or len(phone) < 8:
        return nice_msg("Teléfono inválido", "Revisa el teléfono.", "/client/reset", False)
    if not (recovery_pin.isdigit() and len(recovery_pin) == 6):
        return nice_msg("PIN inválido", "Debe ser de 6 dígitos.", "/client/reset", False)
    if len(new_password) < 6:
        return nice_msg("Clave inválida", "Mínimo 6 caracteres.", "/client/reset", False)

    new_hash = password_make_hash(new_password)
    given = pin_hash(recovery_pin, PIN_SECRET)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, recovery_pin_hash FROM accounts WHERE phone=?", (phone,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "No existe una cuenta con ese teléfono.")
        good = (row["recovery_pin_hash"] or "").strip()
        if not good or not hmac.compare_digest(good, given):
            raise HTTPException(400, "PIN de recuperación incorrecto.")
        conn.execute("UPDATE accounts SET password_hash=?, updated_at=? WHERE phone=?", (new_hash, now_str(), phone))

    try:
        db_exec(_fn)
    except HTTPException as e:
        return nice_msg("No se pudo", str(e.detail), "/client/reset", False)

    return nice_msg("✅ Listo", "Tu contraseña fue actualizada. Inicia sesión.", "/client/login", False)


# =========================
# CLIENT: Notifications
# =========================
@app.get("/notifications", response_class=HTMLResponse)
def client_notifications(client=Depends(require_client)):
    uid = int(client["uid"])
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,message,seen,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 60", (uid,))
    rows = cur.fetchall()
    cur.execute("UPDATE notifications SET seen=1 WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()

    items = ""
    for n in rows:
        items += f"<div class='card'><div class='muted'>{html_escape(n['created_at'] or '')}</div><div>{html_escape(n['message'] or '')}</div></div>"
    if not items:
        items = "<div class='card'><p class='muted'>No tienes notificaciones.</p></div>"

    body = f"""
    <div class="card hero">
      <h1>🔔 Notificaciones</h1>
      <p class="muted">Mensajes del sistema.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/me">⬅️ Volver</a>
    </div>
    {items}
    """
    return page("Cliente • Notificaciones", body, subtitle="Actualizaciones", show_support=True)


# =========================
# CLIENT: Panel
# =========================
@app.get("/me", response_class=HTMLResponse)
def client_me(client=Depends(require_client)):
    if get_setting("maintenance_enabled", "0") == "1":
        msg = get_setting("maintenance_message", "⚠️ Estamos en mantenimiento.")
        return HTMLResponse(page("Mantenimiento", f"""
        <div class="card hero">
          <h1>🛠 Mantenimiento</h1>
          <p class="muted">{html_escape(msg)}</p>
          <div class="hr"></div>
          <a class="btn ghost" href="/logout">🚪 Salir</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """, subtitle="En mantenimiento", show_support=False))

    uid = int(client["uid"])

    conn = db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND seen=0", (uid,))
        unread = int(cur.fetchone()[0])
    except Exception:
        unread = 0

    try:
        cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, kind, ip, cantidad, monto, estado, created_at, voucher_path FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
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

        vence = (r["vence"] or "").strip()
        countdown = f"<span class='badge' data-exp='{html_escape(vence)}'>...</span>" if vence else "<span class='badge'>-</span>"

        phtml += f"""
        <div class="card">
          <div class="muted">Proxy ID {int(r['id'])} • {html_escape(r['estado'] or '')} • {countdown}</div>
          <div style="height:6px;"></div>
          <div><b>{html_escape(r['ip'] or '')}</b></div>
          <div class="muted">Inicio: {html_escape(r['inicio'] or '')} • Vence: {html_escape(vence)}</div>
          <div style="height:10px;"></div>
          <pre>{html_escape(proxy_text)}</pre>
          <div class="row">
            <a class="btn ghost" href="/renew?proxy_id={int(r['id'])}">♻️ Renovar</a>
          </div>
        </div>
        """
    if not phtml:
        phtml = "<div class='card'><p class='muted'>No tienes proxies todavía.</p></div>"

    ohtml = ""
    for r in orders_rows:
        voucher = (r["voucher_path"] or "").strip()
        vcell = f"<a href='/static/{html_escape(voucher)}' target='_blank'>ver</a>" if voucher else "-"
        kind = (r["kind"] or "").strip()
        kind_txt = f" / {html_escape(kind)}" if kind else ""
        ohtml += (
            "<tr>"
            f"<td>#{int(r['id'])}</td>"
            f"<td>{html_escape(r['tipo'] or '')}{kind_txt}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{int(r['cantidad'] or 0)}</td>"
            f"<td>{html_escape(str(r['monto'] or ''))}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{vcell}</td>"
            "</tr>"
        )
    if not ohtml:
        ohtml = "<tr><td colspan='8' class='muted'>No hay pedidos</td></tr>"

    notif_btn = f"🔔 Notificaciones <span class='badge'>{unread}</span>" if unread else "🔔 Notificaciones"

    body = f"""
    <div class="card hero">
      <h1>Panel Cliente</h1>
      <p class="muted">Gestiona tus proxies, pedidos y soporte.</p>
      <div class="hr"></div>

      <div class="row">
        <a class="btn" href="/buy">🛒 Comprar proxy</a>
        <a class="btn" href="/renew">♻️ Renovar proxy</a>
        <a class="btn ghost" href="/add-existing">➕ Agregar proxy existente</a>
        <a class="btn ghost" href="/proxies">📦 Ver mis proxies</a>
        <a class="btn ghost" href="/bank">🏦 Cuenta bancaria</a>
        <a class="btn ghost" href="/notifications">{notif_btn}</a>
        <a class="btn ghost" href="/logout" style="margin-left:auto;">🚪 Salir</a>
      </div>
    </div>

    <h3 style="margin:18px 0 10px 0;">📦 Mis proxies (últimos 10)</h3>
    {phtml}

    <h3 style="margin:18px 0 10px 0;">📨 Mis pedidos (últimos 20)</h3>
    <div class="card">
      <table>
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th><th>Voucher</th></tr>
        {ohtml}
      </table>
    </div>

    <script>
      function pad(n){{return String(n).padStart(2,'0');}}
      function tick(){{
        const els = document.querySelectorAll('[data-exp]');
        const now = new Date().getTime();
        els.forEach(el => {{
          const s = el.getAttribute('data-exp');
          if(!s) return;
          let t = new Date(s.replace(' ', 'T')).getTime();
          if (isNaN(t)) t = new Date(s.replace(' ', 'T') + 'Z').getTime();
          let diff = Math.floor((t - now)/1000);
          if (isNaN(diff)) {{ el.textContent = '...'; return; }}
          if (diff <= 0) {{ el.textContent='EXPIRADO'; return; }}
          const days = Math.floor(diff / 86400);
          diff -= days*86400;
          const h = Math.floor(diff/3600); diff -= h*3600;
          const m = Math.floor(diff/60); diff -= m*60;
          const sec = diff;
          el.textContent = (days>0? (days+'d ') : '') + pad(h)+':'+pad(m)+':'+pad(sec);
        }});
      }}
      tick(); setInterval(tick, 1000);
    </script>
    """
    return page("Cliente", body, subtitle="Tus proxies y pedidos", show_support=True)


# =========================
# CLIENT: proxies list
# =========================
@app.get("/proxies", response_class=HTMLResponse)
def client_proxies(client=Depends(require_client)):
    uid = int(client["uid"])
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 250", (uid,))
        rows = cur.fetchall()
    except Exception:
        rows = []
    conn.close()

    cards = ""
    for r in rows:
        raw = (r["raw"] or "").strip()
        if raw and not raw.upper().startswith("HTTP"):
            raw = "HTTP\n" + raw
        proxy_text = raw or ("HTTP\n" + (r["ip"] or ""))
        vence = (r["vence"] or "").strip()
        countdown = f"<span class='badge' data-exp='{html_escape(vence)}'>...</span>" if vence else "<span class='badge'>-</span>"

        cards += f"""
        <div class="card">
          <div class="muted">Proxy ID {int(r['id'])} • {html_escape(r['estado'] or '')} • {countdown}</div>
          <div><b>{html_escape(r['ip'] or '')}</b></div>
          <div class="muted">Inicio: {html_escape(r['inicio'] or '')} • Vence: {html_escape(vence)}</div>
          <div style="height:10px;"></div>
          <pre>{html_escape(proxy_text)}</pre>
          <div class="row">
            <a class="btn" href="/renew?proxy_id={int(r['id'])}">♻️ Renovar</a>
          </div>
        </div>
        """
    if not cards:
        cards = "<div class='card'><p class='muted'>No tienes proxies todavía.</p></div>"

    body = f"""
    <div class="card hero">
      <h1>📦 Mis proxies</h1>
      <p class="muted">Listado completo de tus proxies.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn" href="/buy">🛒 Comprar</a>
        <a class="btn ghost" href="/add-existing">➕ Agregar existente</a>
      </div>
    </div>
    {cards}

    <script>
      function pad(n){{return String(n).padStart(2,'0');}}
      function tick(){{
        const els = document.querySelectorAll('[data-exp]');
        const now = new Date().getTime();
        els.forEach(el => {{
          const s = el.getAttribute('data-exp');
          if(!s) return;
          let t = new Date(s.replace(' ', 'T')).getTime();
          if (isNaN(t)) t = new Date(s.replace(' ', 'T') + 'Z').getTime();
          let diff = Math.floor((t - now)/1000);
          if (diff <= 0) {{ el.textContent='EXPIRADO'; return; }}
          const days = Math.floor(diff / 86400);
          diff -= days*86400;
          const h = Math.floor(diff/3600); diff -= h*3600;
          const m = Math.floor(diff/60); diff -= m*60;
          const sec = diff;
          el.textContent = (days>0? (days+'d ') : '') + pad(h)+':'+pad(m)+':'+pad(sec);
        }});
      }}
      tick(); setInterval(tick, 1000);
    </script>
    """
    return page("Cliente • Mis proxies", body, subtitle="Listado", show_support=True)


# =========================
# CLIENT: Bank
# =========================
@app.get("/bank", response_class=HTMLResponse)
def client_bank(client=Depends(require_client)):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")

    body = f"""
    <div class="card hero">
      <h1>🏦 {html_escape(title)}</h1>
      <p class="muted">Usa estos datos para pagar y luego sube tu voucher.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn" href="/buy">🛒 Comprar</a>
      </div>
    </div>

    <div class="card">
      <pre>{html_escape(details or "Aún no hay datos bancarios configurados.")}</pre>
    </div>
    """
    return page("Cliente • Cuenta bancaria", body, subtitle="Datos de pago", show_support=True)


# =========================
# CLIENT: Add existing proxy (clientes viejos)
# =========================
@app.get("/add-existing", response_class=HTMLResponse)
def client_add_existing_page(client=Depends(require_client)):
    body = f"""
    <div class="card hero">
      <h1>➕ Agregar proxy existente</h1>
      <p class="muted">Si ya tenías una proxy de antes, solicita agregarla. El admin valida y aparece en tu cuenta.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/me">⬅️ Volver</a>
    </div>

    <div class="card">
      <form method="post" action="/add-existing">
        <label class="muted">IP / Host (obligatorio)</label>
        <input name="ip" placeholder="Ej: 104.12.34.56:1234" />
        <div style="height:12px;"></div>

        <label class="muted">Proxy completa RAW (opcional pero recomendado)</label>
        <textarea name="raw" placeholder="HTTP&#10;ip:port:user:pass"></textarea>
        <div style="height:12px;"></div>

        <label class="muted">Nota (opcional)</label>
        <input name="note" placeholder="Ej: proxy vieja de mi cuenta" />
        <div style="height:12px;"></div>

        <button class="btn" type="submit">📨 Enviar solicitud</button>
      </form>
    </div>
    """
    return page("Agregar existente", body, subtitle="Clientes viejos", show_support=True)


@app.post("/add-existing")
def client_add_existing_submit(
    ip: str = Form(...),
    raw: str = Form(""),
    note: str = Form(""),
    client=Depends(require_client),
):
    uid = int(client["uid"])
    ip = (ip or "").strip()
    raw = (raw or "").strip()
    note = (note or "").strip()

    if len(ip) < 3:
        return nice_msg("IP inválida", "Escribe un IP/host válido.", "/add-existing", True)

    # Creamos un pedido tipo add/existing_proxy sin pago
    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note,kind) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "add", ip, 1, 0, "awaiting_admin_verify", now_str(), "", get_setting("currency", "DOP"), 0, raw, "existing_proxy"),
        )
        return cur.lastrowid

    rid = db_exec(_fn)

    notify_user(uid, f"📨 Solicitud #{rid} enviada para agregar proxy existente. En revisión.")
    admin_log("existing_proxy_request", json.dumps({"rid": rid, "uid": uid, "ip": ip}, ensure_ascii=False))
    outbox_add("existing_proxy_request", json.dumps({"rid": rid, "uid": uid, "ip": ip}, ensure_ascii=False))

    return RedirectResponse(url="/me", status_code=302)


# =========================
# CLIENT: Buy / Renew
# =========================
@app.get("/buy", response_class=HTMLResponse)
def client_buy_page(client=Depends(require_client)):
    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")

    body = f"""
    <div class="card hero">
      <h1>🛒 Comprar proxy</h1>
      <p class="muted">Precio por proxy: <b>{p1} {html_escape(currency)}</b>. Luego sube el voucher.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/bank">🏦 Ver cuenta</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <form method="post" action="/buy">
          <label class="muted">Cantidad</label>
          <input name="cantidad" value="1" />
          <div style="height:12px;"></div>

          <label class="muted">Gmail para factura (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Crear pedido</button>
        </form>
      </div>

      <div class="card">
        <div class="muted">Cuenta bancaria</div>
        <pre>{html_escape(bank)}</pre>
        <div class="muted">Después del pago, sube tu voucher.</div>
      </div>
    </div>
    """
    return page("Cliente • Comprar", body, subtitle="Nuevo pedido", show_support=True)


@app.post("/buy")
def client_buy_submit(
    cantidad: str = Form("1"),
    email: str = Form(""),
    client=Depends(require_client),
):
    uid = int(client["uid"])
    email = (email or "").strip()

    try:
        qty = int(float((cantidad or "1").strip()))
        if qty <= 0:
            qty = 1
    except Exception:
        qty = 1

    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")
    monto = int(p1 * qty)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note,kind) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "buy", "-", qty, monto, "awaiting_voucher", now_str(), email, currency, 0, "", ""),
        )
        return cur.lastrowid

    rid = db_exec(_fn)
    notify_user(uid, f"🧾 Pedido #{rid} creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{rid}/pay", status_code=302)


@app.get("/renew", response_class=HTMLResponse)
def client_renew_page(client=Depends(require_client), proxy_id: str = ""):
    pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")

    uid = int(client["uid"])
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, ip, vence FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 200", (uid,))
        rows = cur.fetchall()
    except Exception:
        rows = []
    conn.close()

    opts = "<option value=''>Selecciona...</option>"
    for r in rows:
        sel = "selected" if proxy_id and str(r["id"]) == str(proxy_id) else ""
        opts += f"<option value='{int(r['id'])}' {sel}>#{int(r['id'])} • {html_escape(r['ip'] or '')} • vence {html_escape(r['vence'] or '')}</option>"

    body = f"""
    <div class="card hero">
      <h1>♻️ Renovar proxy</h1>
      <p class="muted">Renovación: <b>{pr} {html_escape(currency)}</b>. Luego subes el voucher.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/proxies">📦 Mis proxies</a>
        <a class="btn ghost" href="/bank">🏦 Cuenta</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <form method="post" action="/renew">
          <label class="muted">Proxy a renovar</label>
          <select name="proxy_id">{opts}</select>
          <div style="height:12px;"></div>

          <label class="muted">Gmail para factura (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com" />
          <div style="height:12px;"></div>

          <label class="muted">Nota (opcional)</label>
          <input name="note" placeholder="Opcional" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Crear pedido</button>
        </form>
      </div>

      <div class="card">
        <div class="muted">Cuenta bancaria</div>
        <pre>{html_escape(bank)}</pre>
        <div class="muted">Después del pago, sube tu voucher.</div>
      </div>
    </div>
    """
    return page("Cliente • Renovar", body, subtitle="Renovación", show_support=True)


@app.post("/renew")
def client_renew_submit(
    proxy_id: str = Form(...),
    email: str = Form(""),
    note: str = Form(""),
    client=Depends(require_client),
):
    uid = int(client["uid"])
    email = (email or "").strip()
    note = (note or "").strip()

    try:
        pid = int(proxy_id)
        if pid <= 0:
            raise ValueError()
    except Exception:
        return nice_msg("Proxy inválido", "Selecciona un proxy válido.", "/renew", True)

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, ip FROM proxies WHERE id=? AND user_id=?", (pid, uid))
    p = cur.fetchone()
    conn.close()
    if not p:
        return nice_msg("No encontrado", "No encontré ese proxy en tu cuenta.", "/renew", True)

    pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
    currency = get_setting("currency", "DOP")
    monto = int(pr)

    def _fn(conn2):
        cur2 = conn2.cursor()
        cur2.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note,kind) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "renew", p["ip"] or "-", 1, monto, "awaiting_voucher", now_str(), email, currency, pid, note, ""),
        )
        return cur2.lastrowid

    rid = db_exec(_fn)
    notify_user(uid, f"🧾 Pedido #{rid} (renovación) creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{rid}/pay", status_code=302)


# =========================
# CLIENT: Order pay + upload voucher
# =========================
@app.get("/order/{rid}/pay", response_class=HTMLResponse)
def client_order_pay(rid: int, client=Depends(require_client)):
    uid = int(client["uid"])
    bank = get_setting("bank_details", "")
    title = get_setting("bank_title", "Cuenta bancaria")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,user_id,tipo,kind,cantidad,monto,estado,created_at,voucher_path,email,currency,target_proxy_id FROM requests WHERE id=?",
        (int(rid),),
    )
    r = cur.fetchone()
    conn.close()

    if not r or int(r["user_id"]) != uid:
        return nice_msg("No encontrado", "Pedido no encontrado.", "/me", True)

    voucher = (r["voucher_path"] or "").strip()
    voucher_block = f"<p class='muted'>Voucher subido: <a href='/static/{html_escape(voucher)}' target='_blank'>ver</a></p>" if voucher else ""

    extra = ""
    if (r["tipo"] or "") == "renew" and int(r["target_proxy_id"] or 0) > 0:
        extra = f"<p class='muted'>Proxy a renovar: <b>#{int(r['target_proxy_id'])}</b></p>"

    if (r["tipo"] or "") == "add" and (r["kind"] or "") == "existing_proxy":
        extra = "<p class='muted'>Este pedido no requiere voucher. Está en revisión del admin.</p>"

    body = f"""
    <div class="card hero">
      <h1>💳 Pedido #{int(r['id'])}</h1>
      <p class="muted">Tipo: <b>{html_escape(r['tipo'] or '')}</b> • Total: <b>{int(r['monto'])} {html_escape(r['currency'] or 'DOP')}</b></p>
      {extra}
      <div class="hr"></div>
      <a class="btn ghost" href="/me">⬅️ Volver</a>
    </div>

    <div class="grid">
      <div class="card">
        <div class="muted">{html_escape(title)}</div>
        <pre>{html_escape(bank)}</pre>
        <div class="hr"></div>
        <div class="muted">Estado: <b>{html_escape(r['estado'] or '')}</b></div>
        {voucher_block}
      </div>

      <div class="card">
        <h3 style="margin:0 0 10px 0;">🧾 Subir voucher</h3>
        <form method="post" action="/order/{int(r['id'])}/voucher" enctype="multipart/form-data">
          <label class="muted">Imagen (jpg/png/webp)</label>
          <input type="file" name="file" accept="image/*" />
          <div style="height:12px;"></div>
          <button class="btn" type="submit">📤 Enviar voucher</button>
        </form>
        <p class="muted" style="margin-top:10px;">El admin revisará tu voucher y aprobará tu pedido.</p>
      </div>
    </div>
    """
    return page("Cliente • Pago", body, subtitle="Sube tu comprobante", show_support=True)


@app.post("/order/{rid}/voucher", response_class=HTMLResponse)
def client_order_voucher(rid: int, file: UploadFile = File(...), client=Depends(require_client)):
    uid = int(client["uid"])
    if not file or not file.filename:
        return nice_msg("Falta archivo", "Sube una imagen.", f"/order/{rid}/pay", True)

    # Validar pedido
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,user_id,tipo,kind,estado FROM requests WHERE id=?", (int(rid),))
    r = cur.fetchone()
    conn.close()
    if not r or int(r["user_id"]) != uid:
        return nice_msg("No encontrado", "Pedido no encontrado.", "/me", True)

    # si es add existing no necesita voucher
    if (r["tipo"] or "") == "add" and (r["kind"] or "") == "existing_proxy":
        return nice_msg("No requerido", "Este pedido no necesita voucher.", "/me", True)

    ext = os.path.splitext(file.filename)[1].lower().strip()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
        ext = ".jpg"

    fname = f"rid{int(rid)}_u{uid}_{secrets.token_hex(8)}{ext}"
    rel_path = os.path.join("vouchers", fname)
    abs_path = os.path.join(UPLOAD_DIR, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    data = file.file.read()
    if not data or len(data) < 200:
        return nice_msg("Archivo inválido", "El archivo parece vacío.", f"/order/{rid}/pay", True)
    if len(data) > 8 * 1024 * 1024:
        return nice_msg("Muy grande", "Máximo 8MB.", f"/order/{rid}/pay", True)

    with open(abs_path, "wb") as f:
        f.write(data)

    def _fn(conn2):
        conn2.execute(
            "UPDATE requests SET voucher_path=?, voucher_uploaded_at=?, estado=? WHERE id=?",
            (rel_path, now_str(), "voucher_received", int(rid)),
        )

    db_exec(_fn)

    notify_user(uid, f"🧾 Voucher recibido para pedido #{rid}. En revisión.")
    admin_log("voucher_uploaded", json.dumps({"rid": rid, "uid": uid, "path": rel_path}, ensure_ascii=False))

    body = f"""
    <div class="card hero">
      <h1>✅ Voucher enviado</h1>
      <p class="muted">Tu voucher fue subido correctamente. El admin lo revisará.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/order/{int(rid)}/pay">🔎 Ver pedido</a>
        <a class="btn ghost" href="/me">⬅️ Volver al panel</a>
      </div>
    </div>
    """
    return HTMLResponse(page("Voucher enviado", body, subtitle="En revisión", show_support=True))


# =========================
# CLIENT: Support (FAB) — tickets tipo messenger
# =========================
@app.get("/support", response_class=HTMLResponse)
def support_page(client=Depends(require_client)):
    uid = int(client["uid"])

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,subject,message,admin_reply,status,created_at FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 12",
        (uid,),
    )
    rows = cur.fetchall()
    conn.close()

    hist = ""
    for t in rows:
        reply = (t["admin_reply"] or "").strip()
        reply_block = f"<div class='muted'><b>Agente:</b></div><pre>{html_escape(reply)}</pre>" if reply else "<div class='muted'>Aún sin respuesta.</div>"
        hist += f"""
        <div class="card">
          <div class="muted">Ticket #{int(t['id'])} • {html_escape(t['created_at'] or '')} • {html_escape(t['status'] or '')}</div>
          <div><b>{html_escape(t['subject'] or 'Queja / Soporte')}</b></div>
          <pre>{html_escape(t['message'] or '')}</pre>
          {reply_block}
        </div>
        """
    if not hist:
        hist = "<div class='card'><p class='muted'>Aún no has creado tickets.</p></div>"

    body = f"""
    <div class="card hero">
      <h1>💬 Soporte / Quejas</h1>
      <p class="muted">
        Escribe tu queja o problema y un agente te responderá.
      </p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
    </div>

    <div class="card">
      <form method="post" action="/support">
        <label class="muted">Asunto (opcional)</label>
        <input name="subject" placeholder="Ej: No puedo conectar" />
        <div style="height:12px;"></div>

        <label class="muted">Mensaje / queja</label>
        <textarea name="message" placeholder="Escribe aquí..."></textarea>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">📨 Enviar</button>
      </form>
    </div>

    <h3 style="margin:18px 0 10px 0;">📜 Historial</h3>
    {hist}
    """
    return page("Soporte", body, subtitle=f"Cliente #{uid}", show_support=True)


@app.post("/support", response_class=HTMLResponse)
def support_submit(subject: str = Form(""), message: str = Form(...), client=Depends(require_client)):
    uid = int(client["uid"])
    msg = (message or "").strip()
    subj = (subject or "").strip()

    if len(msg) < 5:
        return nice_msg("Mensaje muy corto", "Escribe un mensaje más largo.", "/support", True)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tickets(user_id,subject,message,admin_reply,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (uid, subj, msg, "", "open", now_str(), now_str()),
        )
        return cur.lastrowid

    tid = db_exec(_fn)

    outbox_add("ticket_new", json.dumps({"ticket_id": tid, "user_id": uid, "message": msg}, ensure_ascii=False))
    notify_user(uid, f"💬 Ticket #{tid} creado. Un agente te responderá pronto.")
    admin_log("ticket_new", json.dumps({"tid": tid, "uid": uid}, ensure_ascii=False))

    return RedirectResponse(url="/support", status_code=302)


# =========================
# Optional APIs
# =========================
@app.get("/api/maintenance")
def api_maintenance():
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")
    return {"enabled": enabled, "message": msg}


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
