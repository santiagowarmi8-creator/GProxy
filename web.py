# web.py — Gproxy Web Panel (FastAPI)
# ✅ Admin login con clave (cookie)
# ✅ Clientes: registro Phone + Password (PIN mostrado en pantalla) + login Phone + Password
# ✅ Cliente: comprar/renovar + ver banco + subir voucher + soporte (tipo messenger) + mis proxies con contador
# ✅ Admin: usuarios + bloquear/desbloquear, pedidos + ver voucher + aprobar/rechazar (entrega/renueva 30 días),
#          mantenimiento, proxies, banco+precios, tickets soporte, stock de proxies, auditoría/logs
# ✅ Lee DB sqlite (data.db)
# ✅ Migraciones automáticas (settings.updated_at, columnas nuevas en requests, tickets, stock, etc.)
# ✅ Startup safe (no crashea al importar)
#
# Nota Railway: para vouchers/imagenes es RECOMENDADO usar Volume y setear UPLOAD_DIR=/data/uploads

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# =========================
# CONFIG (Railway Variables)
# =========================
DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
JWT_SECRET = os.getenv("JWT_SECRET", "change_me_admin").strip()

APP_TITLE = os.getenv("APP_TITLE", "Gproxy")
ENABLE_OUTBOX = os.getenv("ENABLE_OUTBOX", "1").strip() == "1"

# Secret para cookies cliente (persistido en DB si no lo pones)
PIN_SECRET = os.getenv("PIN_SECRET", "").strip()

COOKIE_SECURE = (os.getenv("COOKIE_SECURE", "1").strip() == "1")
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").strip()

# Uploads (vouchers / facturas)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
VOUCHER_DIR = os.path.join(UPLOAD_DIR, "vouchers")
INVOICE_DIR = os.path.join(UPLOAD_DIR, "invoices")

# Duración fija (30 días)
DEFAULT_DIAS_PROXY = 30

# =========================
# APP
# =========================
app = FastAPI(title=APP_TITLE)

# Montar estáticos para ver vouchers (si existen)
os.makedirs(VOUCHER_DIR, exist_ok=True)
os.makedirs(INVOICE_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=UPLOAD_DIR), name="static")

CLIENT_SECRET: Optional[str] = None

# =========================
# DB helpers
# =========================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def parse_dt(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, coldef: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = {row[1] for row in cur.fetchall()}
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")
        conn.commit()


def _ensure_table_exists(conn: sqlite3.Connection, create_sql: str) -> None:
    cur = conn.cursor()
    cur.execute(create_sql)
    conn.commit()


def ensure_web_schema() -> str:
    conn = db()
    cur = conn.cursor()

    # settings base
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.commit()
    _ensure_column(conn, "settings", "updated_at", "TEXT NOT NULL DEFAULT ''")

    # accounts
    _ensure_table_exists(
        conn,
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    # signup pins
    _ensure_table_exists(
        conn,
        """
        CREATE TABLE IF NOT EXISTS signup_pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            estado TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    # outbox optional
    if ENABLE_OUTBOX:
        _ensure_table_exists(
            conn,
            """
            CREATE TABLE IF NOT EXISTS outbox(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT NOT NULL DEFAULT ''
            )
            """,
        )

    # tickets soporte
    _ensure_table_exists(
        conn,
        """
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL,
            admin_reply TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
        """,
    )

    # notificaciones simples
    _ensure_table_exists(
        conn,
        """
        CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            seen INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT ''
        )
        """,
    )

    # logs admin (auditoría)
    _ensure_table_exists(
        conn,
        """
        CREATE TABLE IF NOT EXISTS admin_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ''
        )
        """,
    )

    # stock de proxies (pool)
    _ensure_table_exists(
        conn,
        """
        CREATE TABLE IF NOT EXISTS proxy_stock(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL DEFAULT '',
            raw TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'available',
            created_at TEXT NOT NULL DEFAULT ''
        )
        """,
    )

    # defaults: mantenimiento
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("maintenance_enabled", "0", now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("maintenance_message", "⚠️ Estamos en mantenimiento. Vuelve en unos minutos.", now_str()),
    )

    # defaults: banco (tus datos)
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("bank_title", "Cuenta bancaria", now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        (
            "bank_details",
            "Banco: Banreservas (Ahorro)\nTitular: Yudith Domínguez\nCuenta: 4248676174",
            now_str(),
        ),
    )

    # defaults: precios y días (DOP)
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("precio_primera", "1500", now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("precio_renovacion", "1000", now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("dias_proxy", str(DEFAULT_DIAS_PROXY), now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("currency", "DOP", now_str()),
    )

    # Persistir CLIENT_SECRET
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
            print("⚠️ CLIENT_SECRET no estaba definido. Se generó y guardó uno seguro en DB (settings).")

    # PIN_SECRET fallback
    global PIN_SECRET
    if not PIN_SECRET:
        PIN_SECRET = client_secret

    conn.commit()

    # Migraciones columnas en tablas existentes (requests / proxies)
    # requests debe existir en tu bot original; si no existe, esto no lo crea (no adivinamos schema)
    try:
        _ensure_column(conn, "requests", "voucher_path", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "voucher_uploaded_at", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "email", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "requests", "currency", "TEXT NOT NULL DEFAULT 'DOP'")
        _ensure_column(conn, "requests", "target_proxy_id", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "requests", "note", "TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass

    try:
        _ensure_column(conn, "proxies", "inicio", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "proxies", "vence", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "proxies", "raw", "TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass

    conn.commit()
    conn.close()
    return client_secret


@app.on_event("startup")
def _startup():
    global CLIENT_SECRET
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


def admin_log(action: str, details: str = ""):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO admin_logs(action,details,created_at) VALUES(?,?,?)",
        (action, details or "", now_str()),
    )
    conn.commit()
    conn.close()


def notify_user(user_id: int, message: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO notifications(user_id,message,seen,created_at) VALUES(?,?,?,?)",
        (int(user_id), message or "", 0, now_str()),
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
        raw = _b64urldecode(a)
        sig = _b64urldecode(b)

        good = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            raise HTTPException(status_code=401, detail="Firma inválida")

        payload = json.loads(raw.decode("utf-8"))
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
# PIN hashing (temporal)
# =========================
def pin_hash(pin: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), pin.encode("utf-8"), hashlib.sha256).hexdigest()


def _pin_gen() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(6))


def _time_plus_minutes(minutes: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + minutes * 60))


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

    .brand {{ display:flex; align-items:center; gap:12px; }}

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

    .logo span {{ position:relative; font-weight:900; letter-spacing:.5px; }}

    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

    .title {{ font-size: 18px; font-weight: 800; letter-spacing: .2px; margin:0; }}
    .subtitle {{ margin:0; color: var(--muted); font-size: 13px; }}

    .chip {{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      white-space:nowrap;
    }}

    .grid {{
      display:grid;
      grid-template-columns: 1.4fr .9fr;
      gap: 16px;
    }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}

    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 18px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
      animation: pop .35s ease both;
    }}
    @keyframes pop {{ from {{ transform: translateY(6px); opacity:0; }} to {{ transform: translateY(0); opacity:1; }} }}

    .row {{ display:flex; gap: 12px; flex-wrap: wrap; align-items:center; }}

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
    .btn:hover {{ transform: translateY(-2px); box-shadow: 0 16px 38px rgba(196,0,255,.30); filter: brightness(1.03); }}

    .btn.ghost {{
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      box-shadow: none;
    }}
    .btn.ghost:hover {{ box-shadow: 0 12px 30px rgba(0,0,0,.22); }}

    .btn.bad {{
      background: linear-gradient(45deg, #ff2b6a, #ff7a2b);
      box-shadow: 0 12px 30px rgba(255,43,106,.20);
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
    .hr {{ height:1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent); margin: 14px 0; }}

    input, textarea, select {{
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
      vertical-align: top;
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
    .hero h1 {{ margin:0 0 8px 0; font-size: 26px; letter-spacing:.2px; }}
    .hero p {{ margin:0; color: rgba(255,255,255,.78); line-height:1.5; }}

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

    .pinbox {{
      border: 1px dashed rgba(255,255,255,.22);
      background: rgba(0,0,0,.18);
      border-radius: 18px;
      padding: 14px;
    }}

    /* Soporte floating bubble */
    .support-fab {{
      position: fixed;
      right: 18px;
      bottom: 18px;
      width: 58px;
      height: 58px;
      border-radius: 50%;
      display:flex;
      align-items:center;
      justify-content:center;
      text-decoration:none;
      font-size: 26px;
      background: linear-gradient(45deg, var(--p3), var(--p2));
      box-shadow: 0 16px 40px rgba(0,212,255,.25);
      border: 1px solid rgba(255,255,255,.16);
      z-index: 9999;
    }}
    .support-fab:hover {{ transform: translateY(-2px); filter: brightness(1.05); }}

    .badge {{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-width:22px;
      height:22px;
      padding:0 8px;
      border-radius:999px;
      background: rgba(255,255,255,.10);
      border:1px solid rgba(255,255,255,.14);
      font-size:12px;
      font-weight:800;
      color:white;
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

    <a href="/support" class="support-fab" title="Soporte">💬</a>
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
          Plataforma de proxies USA 🇺🇸 para automatización y trabajo online.
          Todo se gestiona desde esta web.
        </p>
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
        <div class="muted">Acceso de clientes</div>
        <p style="margin:8px 0 0 0; color: rgba(255,255,255,.78);">
          Crea tu cuenta con <b>Teléfono + Contraseña</b>.
          Para confirmar, verás un <b>PIN</b> en pantalla y lo escribes abajo.
        </p>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="SaaS moderno • Panel Admin & Cliente")


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH, "client_secret_loaded": bool(CLIENT_SECRET)}


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
    resp.set_cookie("admin_session", token, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
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
    tickets = count("SELECT COUNT(*) FROM tickets WHERE status='open'")
    pending = count("SELECT COUNT(*) FROM requests WHERE estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')")
    stock = count("SELECT COUNT(*) FROM proxy_stock WHERE status='available'")
    conn.close()

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>Admin Dashboard</h1>
      <p>Control total: usuarios, proxies, pedidos, soporte y configuraciones.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/users">👥 Usuarios</a>
        <a class="btn" href="/admin/orders">📨 Pedidos <span class="badge">{pending}</span></a>
        <a class="btn" href="/admin/proxies">📦 Proxies</a>
        <a class="btn" href="/admin/tickets">💬 Tickets <span class="badge">{tickets}</span></a>
        <a class="btn" href="/admin/stock">🧰 Stock <span class="badge">{stock}</span></a>
        <a class="btn" href="/admin/settings">⚙️ Banco/Precios</a>
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
        <div class="muted">Tickets abiertos</div>
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
# Admin: Settings (Banco + Precios + Días)
# =========================
@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_page(admin=Depends(require_admin)):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")
    precio_primera = get_setting("precio_primera", "1500")
    precio_renov = get_setting("precio_renovacion", "1000")
    dias_proxy = get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY))
    currency = get_setting("currency", "DOP")

    body = f"""
    <div class="card hero">
      <h1>⚙️ Banco / Precios</h1>
      <p>Configura la cuenta bancaria y precios en pesos dominicanos.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
    </div>

    <div class="card">
      <form method="post" action="/admin/settings">
        <h3 style="margin:0 0 10px 0;">🏦 Cuenta bancaria</h3>
        <label class="muted">Título</label>
        <input name="bank_title" value="{html_escape(title)}" />
        <div style="height:12px;"></div>

        <label class="muted">Detalles (Banco, titular, cuenta...)</label>
        <textarea name="bank_details">{html_escape(details)}</textarea>

        <div class="hr"></div>
        <h3 style="margin:0 0 10px 0;">💰 Precios</h3>

        <label class="muted">Moneda</label>
        <input name="currency" value="{html_escape(currency)}" />

        <div style="height:12px;"></div>
        <label class="muted">Primera compra (DOP)</label>
        <input name="precio_primera" value="{html_escape(precio_primera)}" />

        <div style="height:12px;"></div>
        <label class="muted">Renovación (DOP)</label>
        <input name="precio_renovacion" value="{html_escape(precio_renov)}" />

        <div style="height:12px;"></div>
        <label class="muted">Duración proxy (días) — máximo 30</label>
        <input name="dias_proxy" value="{html_escape(dias_proxy)}" />

        <div style="height:12px;"></div>
        <button class="btn" type="submit">💾 Guardar</button>
      </form>
    </div>
    """
    return page("Admin • Settings", body, subtitle="Configurar sistema")


@app.post("/admin/settings")
def admin_settings_save(
    bank_title: str = Form("Cuenta bancaria"),
    bank_details: str = Form(""),
    currency: str = Form("DOP"),
    precio_primera: str = Form("1500"),
    precio_renovacion: str = Form("1000"),
    dias_proxy: str = Form(str(DEFAULT_DIAS_PROXY)),
    admin=Depends(require_admin),
):
    set_setting("bank_title", (bank_title or "Cuenta bancaria").strip())
    set_setting("bank_details", (bank_details or "").strip())
    set_setting("currency", (currency or "DOP").strip() or "DOP")

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

    set_setting("precio_primera", str(p1))
    set_setting("precio_renovacion", str(pr))
    set_setting("dias_proxy", str(dp))

    admin_log("settings_update", json.dumps({"p1": p1, "pr": pr, "dias": dp}, ensure_ascii=False))
    return RedirectResponse(url="/admin/settings", status_code=302)


# =========================
# Admin: Stock
# =========================
@app.get("/admin/stock", response_class=HTMLResponse)
def admin_stock_page(admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,label,ip,status,created_at FROM proxy_stock ORDER BY id DESC LIMIT 120")
    rows = cur.fetchall()
    conn.close()

    trs = ""
    for r in rows:
        trs += (
            "<tr>"
            f"<td><code>{r['id']}</code></td>"
            f"<td>{html_escape(r['label'] or '-')}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{html_escape(r['status'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            "</tr>"
        )

    body = f"""
    <div class="card hero">
      <h1>🧰 Stock de Proxies</h1>
      <p>Agrega proxies en bloque. Al aprobar compras se asignan desde aquí.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
    </div>

    <div class="card">
      <form method="post" action="/admin/stock/add">
        <label class="muted">Pega aquí proxies (1 por línea). Puede ser RAW completo.</label>
        <textarea name="raw_lines" placeholder="HTTP&#10;ip:port:user:pass&#10;..."></textarea>
        <div style="height:12px;"></div>
        <label class="muted">Etiqueta (opcional)</label>
        <input name="label" placeholder="USA-RESI / DC / etc." />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">➕ Agregar al stock</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>ID</th><th>Label</th><th>IP</th><th>Status</th><th>Creado</th></tr>
        {trs or "<tr><td colspan='5' class='muted'>Sin stock</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Stock", body, subtitle="Inventario")


@app.post("/admin/stock/add")
def admin_stock_add(
    raw_lines: str = Form(""),
    label: str = Form(""),
    admin=Depends(require_admin),
):
    lines = [ln.strip() for ln in (raw_lines or "").splitlines() if ln.strip()]
    if not lines:
        raise HTTPException(400, "Pega al menos 1 proxy.")
    conn = db()
    cur = conn.cursor()
    added = 0
    for ln in lines:
        ip_guess = ""
        # heurística: si viene ip:port al inicio, usarlo como ip
        parts = ln.replace("http://", "").replace("https://", "").split()
        first = parts[0] if parts else ln
        if ":" in first:
            ip_guess = first.split("@")[-1]
        cur.execute(
            "INSERT INTO proxy_stock(label,raw,ip,status,created_at) VALUES(?,?,?,?,?)",
            ((label or "").strip(), ln, ip_guess, "available", now_str()),
        )
        added += 1
    conn.commit()
    conn.close()
    admin_log("stock_add", json.dumps({"added": added}, ensure_ascii=False))
    return RedirectResponse(url="/admin/stock", status_code=302)


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
    admin_log("user_toggle_block", json.dumps({"user_id": user_id, "blocked": newv}, ensure_ascii=False))
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
    try:
        cur.execute("SELECT id, ip, vence, estado FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 50", (user_id,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, ip, cantidad, monto, estado, created_at FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 50",
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

    toggle_label = "🔓 Desbloquear" if blocked == 1 else "⛔ Bloquear"
    toggle_class = "btn" if blocked == 1 else "btn bad"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/users">⬅️ Usuarios</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>

        <form method="post" action="/admin/user/{user_id}/toggle_block" style="margin-left:auto;">
          <button class="{toggle_class}" type="submit">{toggle_label}</button>
        </form>
      </div>

      <div class="hr"></div>
      <div class="muted">Usuario</div>
      <div class="kpi">{user_id}</div>
      <p class="muted">@{html_escape(uname)} • {tag}</p>
      <p class="muted">Creado: {html_escape(u['created_at'] or '-')} • Last seen: {html_escape(u['last_seen'] or '-')}</p>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📦 Proxies (50)</h3>
      <table>
        <tr><th>PID</th><th>IP</th><th>Vence</th><th>Estado</th></tr>
        {phtml}
      </table>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📨 Pedidos (50)</h3>
      <table>
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th></tr>
        {ohtml}
      </table>
    </div>
    """
    return page(f"Admin • Usuario {user_id}", body, subtitle="Detalle premium")


# =========================
# Admin: Orders
# =========================
def _estado_label(s: str) -> str:
    return s or ""


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
        SELECT id, user_id, tipo, ip, cantidad, monto, estado, created_at,
               voucher_path, voucher_uploaded_at, email, currency, target_proxy_id, note
        FROM requests
        {where}
        ORDER BY id DESC
        LIMIT 120
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
        voucher_path = (r["voucher_path"] or "").strip()
        voucher_link = ""
        if voucher_path:
            # voucher_path guardado como "vouchers/archivo.jpg" -> accesible en /static/...
            voucher_link = f"<a class='btn ghost' href='/static/{html_escape(voucher_path)}' target='_blank'>🧾 Ver voucher</a>"

        extra = ""
        if r["tipo"] == "renew" and int(r["target_proxy_id"] or 0) > 0:
            extra = f"<div class='muted'>Proxy a renovar: <b>#{int(r['target_proxy_id'])}</b></div>"

        email = (r["email"] or "").strip()
        email_txt = f" • Email factura: <b>{html_escape(email)}</b>" if email else ""

        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Pedido <b>#{rid}</b> • Estado: <b>{html_escape(_estado_label(r["estado"]))}</b></div>
          <div style="height:8px;"></div>
          <div><b>U:</b> <a class="btn ghost" href="/admin/user/{int(r["user_id"])}">👤 {int(r["user_id"])}</a></div>
          <div class="muted" style="margin-top:6px;">
            Tipo: <b>{html_escape(r["tipo"] or "")}</b>
            • IP: <b>{html_escape(r["ip"] or "-")}</b>
            • Qty: <b>{r["cantidad"]}</b>
            • Monto: <b>{r["monto"]} {html_escape(r["currency"] or "DOP")}</b>
            {email_txt}
            <br/>Creado: {html_escape(r["created_at"] or "")}
          </div>
          {extra}

          <div class="hr"></div>
          <div class="row">
            {voucher_link or "<span class='muted'>Sin voucher</span>"}
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
        <a class="btn ghost" href="/admin/orders/export">⬇️ Export CSV</a>
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
    return page("Admin • Pedidos", body, subtitle="Aprobar / Rechazar")


@app.get("/admin/orders/export", response_class=HTMLResponse)
def admin_orders_export(admin=Depends(require_admin)):
    # CSV simple en pantalla para copiar
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,user_id,tipo,ip,cantidad,monto,estado,created_at,email,voucher_path FROM requests ORDER BY id DESC LIMIT 500"
    )
    rows = cur.fetchall()
    conn.close()

    lines = ["id,user_id,tipo,ip,cantidad,monto,estado,created_at,email,voucher_path"]
    for r in rows:
        def esc(x: Any) -> str:
            s = str(x or "").replace('"', '""')
            return f'"{s}"'
        lines.append(",".join([
            esc(r["id"]), esc(r["user_id"]), esc(r["tipo"]), esc(r["ip"]),
            esc(r["cantidad"]), esc(r["monto"]), esc(r["estado"]), esc(r["created_at"]),
            esc(r["email"]), esc(r["voucher_path"])
        ]))
    body = f"""
    <div class="card hero">
      <h1>⬇️ Export CSV</h1>
      <p>Copia y pega este CSV.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin/orders">⬅️ Volver</a>
    </div>
    <div class="card">
      <pre>{csv_text}</pre>
    </div>
    """
    return page("Admin • Export", body, subtitle="CSV")


def _take_stock(conn: sqlite3.Connection, qty: int) -> List[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, raw, ip FROM proxy_stock WHERE status='available' ORDER BY id ASC LIMIT ?", (qty,))
    rows = cur.fetchall()
    if len(rows) < qty:
        return []
    ids = [int(r["id"]) for r in rows]
    cur.execute(
        f"UPDATE proxy_stock SET status='assigned' WHERE id IN ({','.join(['?']*len(ids))})",
        ids,
    )
    return rows


def _deliver_buy(conn: sqlite3.Connection, user_id: int, qty: int, dias: int):
    # Asigna proxies desde stock y crea entradas en proxies
    rows = _take_stock(conn, qty)
    if not rows:
        raise HTTPException(400, "No hay suficiente stock disponible para esta compra.")

    cur = conn.cursor()
    start = datetime.now()
    vence = start + timedelta(days=dias)

    for r in rows:
        raw = (r["raw"] or "").strip()
        ip = (r["ip"] or "").strip()
        if not ip:
            # intentar inferir ip
            ip = raw.split()[0] if raw else ""
        cur.execute(
            "INSERT INTO proxies(user_id,ip,inicio,vence,estado,raw) VALUES(?,?,?,?,?,?)",
            (int(user_id), ip, fmt_dt(start), fmt_dt(vence), "active", raw),
        )

    return len(rows)


def _deliver_renew(conn: sqlite3.Connection, user_id: int, proxy_id: int, dias: int):
    cur = conn.cursor()
    cur.execute("SELECT id, vence FROM proxies WHERE id=? AND user_id=?", (int(proxy_id), int(user_id)))
    p = cur.fetchone()
    if not p:
        raise HTTPException(400, "No encontré ese proxy para renovar en ese usuario.")

    v_old = parse_dt(p["vence"] or "") or datetime.now()
    base = v_old if v_old > datetime.now() else datetime.now()
    v_new = base + timedelta(days=dias)
    cur.execute("UPDATE proxies SET vence=? WHERE id=?", (fmt_dt(v_new), int(proxy_id)))


@app.post("/admin/order/{rid}/approve")
def admin_order_approve(rid: int, admin=Depends(require_admin)):
    dias = int(float(get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY)) or DEFAULT_DIAS_PROXY))
    if dias > 30:
        dias = 30
    if dias <= 0:
        dias = DEFAULT_DIAS_PROXY

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, user_id, tipo, cantidad, estado, target_proxy_id, email FROM requests WHERE id=?",
        (rid,),
    )
    req = cur.fetchone()
    if not req:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado")

    tipo = (req["tipo"] or "").strip()
    uid = int(req["user_id"])
    qty = int(req["cantidad"] or 1)
    target_proxy_id = int(req["target_proxy_id"] or 0)
    email = (req["email"] or "").strip()

    try:
        if tipo == "buy":
            delivered = _deliver_buy(conn, uid, max(1, qty), dias)
            notify_user(uid, f"✅ Tu compra fue aprobada. Proxies entregadas: {delivered}.")
        elif tipo == "renew":
            if target_proxy_id <= 0:
                raise HTTPException(400, "Pedido de renovación sin Proxy ID.")
            _deliver_renew(conn, uid, target_proxy_id, dias)
            notify_user(uid, f"✅ Renovación aprobada. Proxy #{target_proxy_id} extendida {dias} días.")
        else:
            # fallback: solo marcar aprobado
            notify_user(uid, "✅ Tu pedido fue aprobado.")
        cur.execute("UPDATE requests SET estado=? WHERE id=?", ("approved", rid))
        conn.commit()
    except HTTPException:
        conn.rollback()
        conn.close()
        raise
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(500, f"Error al aprobar: {e}")

    conn.close()
    outbox_add("order_approved", json.dumps({"rid": rid, "user_id": uid, "tipo": tipo}, ensure_ascii=False))
    admin_log("order_approve", json.dumps({"rid": rid, "tipo": tipo, "uid": uid, "email": email}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


@app.post("/admin/order/{rid}/reject")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, tipo FROM requests WHERE id=?", (rid,))
    req = cur.fetchone()
    if not req:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado")

    cur.execute("UPDATE requests SET estado=? WHERE id=?", ("rejected", rid))
    conn.commit()
    conn.close()

    uid = int(req["user_id"])
    notify_user(uid, f"❌ Tu pedido #{rid} fue rechazado. Contacta soporte si necesitas ayuda.")
    outbox_add("order_rejected", json.dumps({"rid": rid, "user_id": uid, "tipo": req["tipo"]}, ensure_ascii=False))
    admin_log("order_reject", json.dumps({"rid": rid, "uid": uid}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


# =========================
# Admin: Proxies list
# =========================
@app.get("/admin/proxies", response_class=HTMLResponse)
def admin_proxies(admin=Depends(require_admin), q: str = ""):
    conn = db()
    cur = conn.cursor()

    try:
        if q.strip():
            cur.execute(
                """
                SELECT id, user_id, ip, vence, estado
                FROM proxies
                WHERE CAST(user_id AS TEXT) LIKE ? OR ip LIKE ?
                ORDER BY id DESC
                LIMIT 120
                """,
                (f"%{q.strip()}%", f"%{q.strip()}%"),
            )
        else:
            cur.execute(
                """
                SELECT id, user_id, ip, vence, estado
                FROM proxies
                ORDER BY id DESC
                LIMIT 120
                """
            )
        rows = cur.fetchall()
    except Exception:
        rows = []
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
      <p>Activa o desactiva mantenimiento (solo web).</p>
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
        <textarea name="message">{html_escape(msg)}</textarea>

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
        admin_log("maintenance_on", msg)
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    if action == "off":
        set_setting("maintenance_enabled", "0")
        outbox_add("maintenance_off", msg)
        admin_log("maintenance_off", msg)
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    raise HTTPException(400, "Acción inválida")


# =========================
# Admin: Tickets
# =========================
@app.get("/admin/tickets", response_class=HTMLResponse)
def admin_tickets(admin=Depends(require_admin), state: str = "open"):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,user_id,subject,message,admin_reply,status,created_at,updated_at FROM tickets WHERE status=? ORDER BY id DESC LIMIT 120",
        ((state or "open").strip(),),
    )
    rows = cur.fetchall()
    conn.close()

    cards = ""
    for t in rows:
        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Ticket <b>#{t['id']}</b> • Usuario <b>{t['user_id']}</b> • Estado: <b>{html_escape(t['status'])}</b></div>
          <div style="height:8px;"></div>
          <div><b>{html_escape(t['subject'] or 'Soporte')}</b></div>
          <pre>{html_escape(t['message'] or '')}</pre>

          <div class="hr"></div>
          <form method="post" action="/admin/ticket/{t['id']}/reply">
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
      <h1>💬 Tickets</h1>
      <p>Responde y cierra tickets de soporte.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
        <a class="btn ghost" href="/admin/tickets?state=open">Abiertos</a>
        <a class="btn ghost" href="/admin/tickets?state=closed">Cerrados</a>
      </div>
    </div>
    {cards}
    """
    return page("Admin • Tickets", body, subtitle="Soporte")


@app.post("/admin/ticket/{tid}/reply")
def admin_ticket_reply(
    tid: int,
    reply: str = Form(""),
    action: str = Form("reply"),
    admin=Depends(require_admin),
):
    reply = (reply or "").strip()
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,user_id FROM tickets WHERE id=?", (int(tid),))
    t = cur.fetchone()
    if not t:
        conn.close()
        raise HTTPException(404, "Ticket no encontrado")

    if action == "close":
        cur.execute("UPDATE tickets SET status='closed', updated_at=? WHERE id=?", (now_str(), int(tid)))
        conn.commit()
        conn.close()
        notify_user(int(t["user_id"]), f"✅ Tu ticket #{tid} fue cerrado. Si necesitas más ayuda, abre otro.")
        admin_log("ticket_close", json.dumps({"tid": tid}, ensure_ascii=False))
        return RedirectResponse(url="/admin/tickets?state=open", status_code=302)

    cur.execute(
        "UPDATE tickets SET admin_reply=?, updated_at=? WHERE id=?",
        (reply, now_str(), int(tid)),
    )
    conn.commit()
    conn.close()
    if reply:
        notify_user(int(t["user_id"]), f"💬 Soporte respondió tu ticket #{tid}. Entra a Soporte para verlo.")
    admin_log("ticket_reply", json.dumps({"tid": tid}, ensure_ascii=False))
    return RedirectResponse(url="/admin/tickets?state=open", status_code=302)


# =========================
# CLIENT: Signup / Verify / Login
# =========================
@app.get("/client/signup", response_class=HTMLResponse)
def client_signup_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Crear cuenta</h1>
        <p>Regístrate con <b>Teléfono + Contraseña</b>. Te mostraremos un <b>PIN</b> en pantalla para confirmar.</p>
        <div class="hr"></div>
        <div class="pill">📱 Teléfono</div>
        <div class="pill" style="margin-left:8px;">🔒 Contraseña</div>
        <div class="pill" style="margin-left:8px;">🧷 PIN</div>
      </div>

      <div class="card">
        <form method="post" action="/client/signup">
          <label class="muted">Teléfono (ej: +1809...)</label><br/>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Contraseña (mín 6)</label><br/>
          <input name="password" type="password" placeholder="••••••" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Crear cuenta</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">
          Ya tienes cuenta? <a href="/client/login" style="color:white;">Inicia sesión</a>
        </p>
      </div>
    </div>
    """
    return page("Cliente • Crear cuenta", body, subtitle="Registro seguro")


@app.post("/client/signup", response_class=HTMLResponse)
def client_signup(phone: str = Form(...), password: str = Form(...)):
    phone = (phone or "").strip()
    password = (password or "").strip()

    if not phone or len(phone) < 8:
        raise HTTPException(400, "Teléfono inválido.")
    if not password or len(password) < 6:
        raise HTTPException(400, "La contraseña debe tener mínimo 6 caracteres.")

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id, verified FROM accounts WHERE phone=?", (phone,))
    existing = cur.fetchone()
    if existing:
        conn.close()
        body = """
        <div class="card">
          <h3>Ese teléfono ya existe</h3>
          <p class="muted">Intenta iniciar sesión o usa otro número.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/login">🔐 Login</a>
          <a class="btn ghost" href="/client/signup">↩️ Volver</a>
        </div>
        """
        return page("Cliente • Registro", body, subtitle="Cuenta existente")

    pwd_hash = password_make_hash(password)
    cur.execute(
        "INSERT INTO accounts(phone,password_hash,verified,created_at,updated_at) VALUES(?,?,?,?,?)",
        (phone, pwd_hash, 0, now_str(), now_str()),
    )
    conn.commit()

    pin = _pin_gen()
    exp = _time_plus_minutes(5)
    cur.execute(
        "INSERT INTO signup_pins(phone,pin_hash,expires_at,attempts,estado,created_at) VALUES(?,?,?,?,?,?)",
        (phone, pin_hash(pin, PIN_SECRET), exp, 0, "pending", now_str()),
    )
    conn.commit()
    conn.close()

    body = f"""
    <div class="card hero">
      <h1>✅ Cuenta creada</h1>
      <p>Ahora confirma tu cuenta escribiendo el PIN que ves abajo.</p>
    </div>

    <div class="card pinbox">
      <div class="muted">Tu PIN (se muestra una sola vez)</div>
      <div class="kpi" style="letter-spacing:6px;">{html_escape(pin)}</div>
      <p class="muted">Expira: <b>{html_escape(exp)}</b></p>
    </div>

    <div class="card">
      <form method="post" action="/client/verify">
        <input type="hidden" name="phone" value="{html_escape(phone)}" />
        <label class="muted">Escribe el PIN para verificar</label><br/>
        <input name="pin" placeholder="123456" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Verificar cuenta</button>
        <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
      </form>
      <div class="hr"></div>
      <p class="muted">Luego podrás iniciar sesión con Teléfono + Contraseña.</p>
    </div>
    """
    return page("Cliente • Verificación", body, subtitle="Confirmar cuenta")


@app.post("/client/verify", response_class=HTMLResponse)
def client_verify(phone: str = Form(...), pin: str = Form(...)):
    phone = (phone or "").strip()
    pin = (pin or "").strip()

    if not phone or not pin:
        raise HTTPException(400, "Datos inválidos.")

    conn = db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, pin_hash, expires_at, attempts, estado
        FROM signup_pins
        WHERE phone=? AND estado='pending'
        ORDER BY id DESC
        LIMIT 1
        """,
        (phone,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        body = """
        <div class="card">
          <h3>No hay un PIN activo</h3>
          <p class="muted">Vuelve a crear la cuenta.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/signup">✨ Crear cuenta</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return page("Cliente • Verificación", body, subtitle="PIN no encontrado")

    pid = int(row["id"])
    exp = row["expires_at"] or ""
    attempts = int(row["attempts"] or 0)

    try:
        exp_ts = time.mktime(time.strptime(exp, "%Y-%m-%d %H:%M:%S"))
        if time.time() > exp_ts:
            cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
            conn.commit()
            conn.close()
            body = """
            <div class="card">
              <h3>⏳ PIN expirado</h3>
              <p class="muted">El PIN venció. Crea tu cuenta de nuevo para generar otro.</p>
              <div class="hr"></div>
              <a class="btn" href="/client/signup">✨ Crear cuenta</a>
              <a class="btn ghost" href="/">🏠 Inicio</a>
            </div>
            """
            return page("Cliente • Verificación", body, subtitle="PIN vencido")
    except Exception:
        pass

    given = pin_hash(pin, PIN_SECRET)
    good = (row["pin_hash"] or "").strip()

    if not hmac.compare_digest(good, given):
        attempts += 1
        cur.execute("UPDATE signup_pins SET attempts=? WHERE id=?", (attempts, pid))
        if attempts >= 3:
            cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
        conn.commit()
        conn.close()
        body = f"""
        <div class="card">
          <h3>❌ PIN incorrecto</h3>
          <p class="muted">Intentos: <b>{attempts}/3</b></p>
          <div class="hr"></div>
          <a class="btn" href="/client/signup">✨ Crear cuenta otra vez</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return page("Cliente • Verificación", body, subtitle="Error")

    cur.execute("UPDATE signup_pins SET estado='done' WHERE id=?", (pid,))
    cur.execute("UPDATE accounts SET verified=1, updated_at=? WHERE phone=?", (now_str(), phone))
    conn.commit()
    conn.close()

    body = """
    <div class="card hero">
      <h1>✅ Cuenta verificada</h1>
      <p>Ya puedes iniciar sesión con tu Teléfono + Contraseña.</p>
      <div class="hr"></div>
      <a class="btn" href="/client/login">🔐 Iniciar sesión</a>
      <a class="btn ghost" href="/">🏠 Inicio</a>
    </div>
    """
    return page("Cliente • Verificado", body, subtitle="Listo")


@app.get("/client/login", response_class=HTMLResponse)
def client_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Panel Cliente</h1>
        <p>Entra con tu <b>Teléfono + Contraseña</b>.</p>
        <div class="hr"></div>
        <div class="pill">📱 Teléfono</div>
        <div class="pill" style="margin-left:8px;">🔒 Contraseña</div>
        <div class="pill" style="margin-left:8px;">📦 Proxies</div>
      </div>

      <div class="card">
        <form method="post" action="/client/login">
          <label class="muted">Teléfono (ej: +1809...)</label><br/>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Contraseña</label><br/>
          <input name="password" type="password" placeholder="••••••" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">
          No tienes cuenta? <a href="/client/signup" style="color:white;">Crear cuenta</a>
        </p>
      </div>
    </div>
    """
    return page("Cliente • Login", body, subtitle="Acceso seguro")


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
        body = """
        <div class="card">
          <h3>Login inválido</h3>
          <p class="muted">Verifica teléfono/contraseña y que la cuenta esté verificada.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/login">⬅️ Intentar de nuevo</a>
          <a class="btn ghost" href="/client/signup">✨ Crear cuenta</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Error", body, subtitle="No autorizado"), status_code=401)

    session = sign({"role": "client", "uid": int(uid)}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie("client_session", session, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
    return resp


@app.get("/logout")
def client_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("client_session")
    return resp


# =========================
# Cliente: Notificaciones
# =========================
@app.get("/notifications", response_class=HTMLResponse)
def client_notifications(client=Depends(require_client)):
    uid = int(client["uid"])
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,message,seen,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,))
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
      <p>Mensajes del sistema.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
    </div>
    {items}
    """
    return page("Cliente • Notificaciones", body, subtitle="Actualizaciones")


# =========================
# Client portal
# =========================
@app.get("/me", response_class=HTMLResponse)
def client_me(client=Depends(require_client)):
    uid = int(client["uid"])

    maint = get_setting("maintenance_enabled", "0") == "1"
    if maint:
        msg = get_setting("maintenance_message", "⚠️ Estamos en mantenimiento.")
        body = f"""
        <div class="card hero">
          <h1>🛠 Mantenimiento</h1>
          <p>{html_escape(msg)}</p>
          <div class="hr"></div>
          <a class="btn ghost" href="/logout">🚪 Salir</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return page("Cliente", body, subtitle="En mantenimiento")

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
            "SELECT id, tipo, ip, cantidad, monto, estado, created_at, voucher_path FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
            (uid,),
        )
        orders_rows = cur.fetchall()
    except Exception:
        orders_rows = []

    conn.close()

    # Proxies cards con contador
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
          <div class="muted">Proxy ID {r['id']} • {html_escape(r['estado'] or '')} • {countdown}</div>
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

    # Orders table
    ohtml = ""
    for r in orders_rows:
        voucher = (r["voucher_path"] or "").strip()
        voucher_cell = f"<a href='/static/{html_escape(voucher)}' target='_blank'>ver</a>" if voucher else "-"
        ohtml += (
            "<tr>"
            f"<td>#{r['id']}</td>"
            f"<td>{html_escape(r['tipo'] or '')}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{r['cantidad']}</td>"
            f"<td>{r['monto']}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{voucher_cell}</td>"
            "</tr>"
        )

    if not ohtml:
        ohtml = "<tr><td colspan='8' class='muted'>No hay pedidos</td></tr>"

    notif_btn = f"🔔 Notificaciones <span class='badge'>{unread}</span>" if unread else "🔔 Notificaciones"

    body = f"""
    <div class="card hero">
      <h1>Panel Cliente</h1>
      <p>Gestiona tus proxies, pedidos y soporte.</p>
      <div class="hr"></div>

      <div class="row">
        <a class="btn" href="/buy">🛒 Comprar proxy</a>
        <a class="btn" href="/renew">♻️ Renovar proxy</a>
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
          const dt = new Date(s.replace(' ', 'T') + 'Z'); // intento simple
          let t = dt.getTime();
          if (isNaN(t)) {{
            // fallback local parse
            t = new Date(s.replace(' ', 'T')).getTime();
          }}
          let diff = Math.floor((t - now)/1000);
          if (isNaN(diff)) {{
            el.textContent = '...';
            return;
          }}
          if (diff <= 0) {{
            el.textContent = 'EXPIRADO';
            return;
          }}
          const days = Math.floor(diff / 86400);
          diff -= days*86400;
          const h = Math.floor(diff/3600); diff -= h*3600;
          const m = Math.floor(diff/60); diff -= m*60;
          const sec = diff;
          el.textContent = (days>0? (days+'d ') : '') + pad(h)+':'+pad(m)+':'+pad(sec);
        }});
      }}
      tick();
      setInterval(tick, 1000);
    </script>
    """
    return page("Cliente", body, subtitle="Tus proxies y pedidos")


# =========================
# Cliente: Ver mis proxies
# =========================
@app.get("/proxies", response_class=HTMLResponse)
def client_proxies(client=Depends(require_client)):
    uid = int(client["uid"])
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 200", (uid,))
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
          <div class="muted">Proxy ID {r['id']} • {html_escape(r['estado'] or '')} • {countdown}</div>
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
      <p>Listado completo de tus proxies.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn" href="/buy">🛒 Comprar</a>
        <a class="btn ghost" href="/bank">🏦 Cuenta bancaria</a>
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
    return page("Cliente • Mis proxies", body, subtitle="Listado")


# =========================
# Cliente: Cuenta bancaria
# =========================
@app.get("/bank", response_class=HTMLResponse)
def client_bank(client=Depends(require_client)):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")

    body = f"""
    <div class="card hero">
      <h1>🏦 {html_escape(title)}</h1>
      <p>Usa estos datos para realizar el pago y luego sube tu voucher.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn" href="/buy">🛒 Comprar proxy</a>
      </div>
    </div>

    <div class="card">
      <pre>{html_escape(details or "Aún no hay datos bancarios configurados. (Admin: /admin/settings)")}</pre>
    </div>
    """
    return page("Cliente • Cuenta bancaria", body, subtitle="Datos de pago")


# =========================
# Cliente: Comprar proxy -> crea pedido y luego sube voucher
# =========================
@app.get("/buy", response_class=HTMLResponse)
def client_buy_page(client=Depends(require_client)):
    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")

    body = f"""
    <div class="card hero">
      <h1>🛒 Comprar proxy</h1>
      <p>Precio por proxy: <b>{p1} {html_escape(currency)}</b>. Luego verás la cuenta bancaria y podrás subir el voucher.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/bank">🏦 Ver cuenta bancaria</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <form method="post" action="/buy">
          <label class="muted">Cantidad</label>
          <input name="cantidad" value="1" />
          <div style="height:12px;"></div>

          <label class="muted">Gmail para factura (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com (opcional)" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Crear pedido</button>
        </form>
      </div>

      <div class="card">
        <div class="muted">Cuenta bancaria (para pagar)</div>
        <pre>{html_escape(bank)}</pre>
        <div class="muted">Después del pago, sube tu voucher.</div>
      </div>
    </div>
    """
    return page("Cliente • Comprar", body, subtitle="Nuevo pedido")


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

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "buy", "-", qty, monto, "awaiting_voucher", now_str(), email, currency, 0, ""),
        )
        conn.commit()
        rid = cur.lastrowid
    except Exception as e:
        conn.close()
        raise HTTPException(500, f"No pude crear el pedido: {e}")
    conn.close()

    notify_user(uid, f"🧾 Pedido #{rid} creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{rid}/pay", status_code=302)


# =========================
# Cliente: Renovar proxy -> crea pedido y luego sube voucher
# =========================
@app.get("/renew", response_class=HTMLResponse)
def client_renew_page(client=Depends(require_client), proxy_id: str = ""):
    pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")

    # listar proxies del usuario para selector
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
      <p>Renovación: <b>{pr} {html_escape(currency)}</b> (30 días). Luego subes el voucher.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/proxies">📦 Ver mis proxies</a>
        <a class="btn ghost" href="/bank">🏦 Ver cuenta bancaria</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <form method="post" action="/renew">
          <label class="muted">Proxy a renovar</label>
          <select name="proxy_id">{opts}</select>
          <div style="height:12px;"></div>

          <label class="muted">Gmail para factura (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com (opcional)" />
          <div style="height:12px;"></div>

          <label class="muted">Nota (opcional)</label>
          <input name="note" placeholder="Opcional" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Crear pedido de renovación</button>
        </form>
      </div>

      <div class="card">
        <div class="muted">Cuenta bancaria (para pagar)</div>
        <pre>{html_escape(bank)}</pre>
        <div class="muted">Después del pago, sube tu voucher.</div>
      </div>
    </div>
    """
    return page("Cliente • Renovar", body, subtitle="Renovación")


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
        raise HTTPException(400, "Proxy inválido.")

    # validar pertenencia
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, ip FROM proxies WHERE id=? AND user_id=?", (pid, uid))
    p = cur.fetchone()
    if not p:
        conn.close()
        raise HTTPException(400, "No encontré ese proxy en tu cuenta.")

    pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
    currency = get_setting("currency", "DOP")
    monto = int(pr)

    try:
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "renew", p["ip"] or "-", 1, monto, "awaiting_voucher", now_str(), email, currency, pid, note),
        )
        conn.commit()
        rid = cur.lastrowid
    except Exception as e:
        conn.close()
        raise HTTPException(500, f"No pude crear el pedido: {e}")
    conn.close()

    notify_user(uid, f"🧾 Pedido #{rid} (renovación) creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{rid}/pay", status_code=302)


# =========================
# Cliente: Pantalla pago + subir voucher
# =========================
@app.get("/order/{rid}/pay", response_class=HTMLResponse)
def client_order_pay(rid: int, client=Depends(require_client)):
    uid = int(client["uid"])
    bank = get_setting("bank_details", "")
    title = get_setting("bank_title", "Cuenta bancaria")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,user_id,tipo,cantidad,monto,estado,created_at,voucher_path,email,currency,target_proxy_id FROM requests WHERE id=?",
        (int(rid),),
    )
    r = cur.fetchone()
    conn.close()

    if not r or int(r["user_id"]) != uid:
        raise HTTPException(404, "Pedido no encontrado.")

    voucher = (r["voucher_path"] or "").strip()
    voucher_block = ""
    if voucher:
        voucher_block = f"<p class='muted'>Voucher subido: <a href='/static/{html_escape(voucher)}' target='_blank'>ver</a></p>"

    extra = ""
    if (r["tipo"] or "") == "renew" and int(r["target_proxy_id"] or 0) > 0:
        extra = f"<p class='muted'>Proxy a renovar: <b>#{int(r['target_proxy_id'])}</b></p>"

    body = f"""
    <div class="card hero">
      <h1>💳 Pago del pedido #{int(r['id'])}</h1>
      <p>Tipo: <b>{html_escape(r['tipo'] or '')}</b> • Total: <b>{int(r['monto'])} {html_escape(r['currency'] or 'DOP')}</b></p>
      {extra}
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="muted">{html_escape(title)}</div>
        <pre>{html_escape(bank)}</pre>
        <div class="hr"></div>
        <div class="muted">Estado actual: <b>{html_escape(r['estado'] or '')}</b></div>
        {voucher_block}
      </div>

      <div class="card">
        <h3 style="margin:0 0 10px 0;">🧾 Subir voucher</h3>
        <form method="post" action="/order/{int(r['id'])}/voucher" enctype="multipart/form-data">
          <label class="muted">Selecciona una imagen (jpg/png)</label>
          <input type="file" name="file" accept="image/*" />
          <div style="height:12px;"></div>
          <button class="btn" type="submit">📤 Enviar voucher</button>
        </form>
        <p class="muted" style="margin-top:10px;">El admin revisará tu voucher y aprobará tu pedido.</p>
      </div>
    </div>
    """
    return page("Cliente • Pago", body, subtitle="Sube tu comprobante")


@app.post("/order/{rid}/voucher", response_class=HTMLResponse)
def client_order_voucher(rid: int, file: UploadFile = File(...), client=Depends(require_client)):
    uid = int(client["uid"])

    if not file or not file.filename:
        raise HTTPException(400, "Sube una imagen.")

    # Validar pedido
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id,user_id,estado FROM requests WHERE id=?", (int(rid),))
    r = cur.fetchone()
    if not r or int(r["user_id"]) != uid:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado.")
    conn.close()

    # Guardar imagen
    ext = os.path.splitext(file.filename)[1].lower().strip()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
        ext = ".jpg"

    fname = f"rid{int(rid)}_u{uid}_{secrets.token_hex(8)}{ext}"
    rel_path = os.path.join("vouchers", fname)  # relativo a /static/
    abs_path = os.path.join(UPLOAD_DIR, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    data = file.file.read()
    if not data or len(data) < 200:
        raise HTTPException(400, "Archivo inválido.")
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(400, "Imagen muy grande (máx 8MB).")

    with open(abs_path, "wb") as f:
        f.write(data)

    # Actualizar pedido
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE requests SET voucher_path=?, voucher_uploaded_at=?, estado=? WHERE id=?",
        (rel_path, now_str(), "voucher_received", int(rid)),
    )
    conn.commit()
    conn.close()

    notify_user(uid, f"🧾 Voucher recibido para pedido #{rid}. En revisión.")
    admin_log("voucher_uploaded", json.dumps({"rid": rid, "uid": uid, "path": rel_path}, ensure_ascii=False))

    body = f"""
    <div class="card hero">
      <h1>✅ Voucher enviado</h1>
      <p>Tu voucher fue subido correctamente. El admin lo revisará.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/order/{int(rid)}/pay">🔎 Ver pedido</a>
        <a class="btn ghost" href="/me">⬅️ Volver al panel</a>
      </div>
    </div>
    """
    return page("Voucher enviado", body, subtitle="En revisión")


# =========================
# Cliente: Soporte (tipo messenger)
# =========================
@app.get("/support", response_class=HTMLResponse)
def support_page(client=Depends(require_client)):
    uid = int(client["uid"])

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,subject,message,admin_reply,status,created_at FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 10",
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
          <div class="muted">Ticket #{t['id']} • {html_escape(t['created_at'] or '')} • {html_escape(t['status'] or '')}</div>
          <div><b>{html_escape(t['subject'] or 'Soporte')}</b></div>
          <pre>{html_escape(t['message'] or '')}</pre>
          {reply_block}
        </div>
        """

    if not hist:
        hist = "<div class='card'><p class='muted'>Aún no has creado tickets.</p></div>"

    body = f"""
    <div class="card hero">
      <h1>💬 Soporte</h1>
      <p>
        Bienvenido/a 👋<br/>
        Cuéntanos cuál es el problema y un agente libre te contestará lo más rápido posible.
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

        <label class="muted">Describe tu problema</label>
        <textarea name="message" placeholder="Escribe aquí..."></textarea>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">📨 Enviar a soporte</button>
      </form>
    </div>

    <h3 style="margin:18px 0 10px 0;">📜 Historial (últimos 10)</h3>
    {hist}
    """
    return page("Soporte", body, subtitle=f"Cliente #{uid}")


@app.post("/support", response_class=HTMLResponse)
def support_submit(subject: str = Form(""), message: str = Form(...), client=Depends(require_client)):
    uid = int(client["uid"])
    msg = (message or "").strip()
    subj = (subject or "").strip()

    if len(msg) < 5:
        raise HTTPException(400, "Escribe un mensaje más largo.")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tickets(user_id,subject,message,admin_reply,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        (uid, subj, msg, "", "open", now_str(), now_str()),
    )
    conn.commit()
    tid = cur.lastrowid
    conn.close()

    outbox_add("ticket_new", json.dumps({"ticket_id": tid, "user_id": uid, "message": msg}, ensure_ascii=False))
    notify_user(uid, f"💬 Ticket #{tid} creado. Un agente te responderá pronto.")
    admin_log("ticket_new", json.dumps({"tid": tid, "uid": uid}, ensure_ascii=False))

    body = f"""
    <div class="card hero">
      <h1>✅ Mensaje enviado</h1>
      <p>Tu ticket <b>#{tid}</b> fue creado. Un agente te responderá lo antes posible.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/support">📜 Ver historial</a>
        <a class="btn ghost" href="/me">⬅️ Volver al panel</a>
      </div>
    </div>
    """
    return page("Soporte", body, subtitle="Listo")


# =========================
# Helper endpoint: maintenance status
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

