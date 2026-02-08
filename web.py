# web.py — Gproxy Web Panel (FastAPI) ✅ WEB ONLY (SIN TELEGRAM)
# ✅ Admin login con clave (cookie)
# ✅ Clientes: Registro Teléfono + Contraseña + OTP (código al teléfono)
# ✅ Login Teléfono + Contraseña (cookie)
# ✅ Panel Cliente: ver proxies + pedidos (usando user_id = account_id)
# ✅ Panel Admin: cuentas, bloquear/desbloquear, pedidos, proxies, mantenimiento
# ✅ SQLite (data.db) + migraciones automáticas
#
# NOTA SMS:
# - Soporta Twilio SMS si configuras: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER
# - Si NO configuras Twilio, por seguridad el OTP se registra en consola (y en modo DEBUG se muestra en pantalla).

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional, Tuple

from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

# =========================
# CONFIG (Railway Variables)
# =========================
DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()          # EJ: "MiClaveSuperFuerte"
JWT_SECRET = os.getenv("JWT_SECRET", "change_me_admin").strip()   # secreto largo random

APP_TITLE = os.getenv("APP_TITLE", "Gproxy")

# Tokens cookies
CLIENT_SECRET = (os.getenv("CLIENT_SECRET") or "").strip()        # si no se pone, se genera y se guarda en DB
DEBUG_SHOW_OTP = (os.getenv("DEBUG_SHOW_OTP", "0").strip() == "1")

# OTP settings
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))        # 5 min
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "3"))

# Twilio (opcional)
TWILIO_ACCOUNT_SID = (os.getenv("TWILIO_ACCOUNT_SID") or "").strip()
TWILIO_AUTH_TOKEN = (os.getenv("TWILIO_AUTH_TOKEN") or "").strip()
TWILIO_FROM_NUMBER = (os.getenv("TWILIO_FROM_NUMBER") or "").strip()
TWILIO_SMS_ENABLED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER)

# Password hashing (PBKDF2)
PWD_ITERATIONS = int(os.getenv("PWD_ITERATIONS", "210000"))

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


def _ensure_column(cur: sqlite3.Cursor, table: str, col: str, coldef: str):
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if col not in cols:
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coldef}")
        except Exception:
            pass


def ensure_web_schema() -> str:
    """
    Crea tablas necesarias del panel web + settings + cuentas web + otp.
    También persiste CLIENT_SECRET en settings para que no cambie en reinicios.
    """
    conn = db()
    cur = conn.cursor()

    # -------------------------
    # settings
    # -------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    # Defaults settings
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("maintenance_enabled", "0", now_str()),
    )
    cur.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("maintenance_message", "⚠️ Estamos en mantenimiento. Vuelve en unos minutos.", now_str()),
    )

    # -------------------------
    # Persist CLIENT_SECRET
    # -------------------------
    cur.execute("SELECT value FROM settings WHERE key=?", ("client_secret_persist",))
    row = cur.fetchone()
    db_secret = (row["value"] if row else "").strip()

    env_secret = (os.getenv("CLIENT_SECRET") or "").strip()
    if env_secret and env_secret not in ("change_me_client", ""):
        _client_secret = env_secret
        if db_secret != _client_secret:
            cur.execute(
                "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("client_secret_persist", _client_secret, now_str()),
            )
    else:
        if db_secret:
            _client_secret = db_secret
        else:
            _client_secret = secrets.token_urlsafe(64)
            cur.execute(
                "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
                ("client_secret_persist", _client_secret, now_str()),
            )
            print("⚠️ CLIENT_SECRET no estaba definido. Se generó y guardó uno seguro en DB (settings).")

    # -------------------------
    # WEB ONLY: accounts + otp
    # -------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS otp_codes_web(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending'
        )
        """
    )

    # Migraciones suaves por si ya existía accounts sin columnas
    _ensure_column(cur, "accounts", "is_blocked", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(cur, "accounts", "verified", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(cur, "accounts", "created_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(cur, "accounts", "updated_at", "TEXT NOT NULL DEFAULT ''")

    conn.commit()
    conn.close()
    return _client_secret


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
    tok = request.cookies.get("client_session", "")
    payload = verify(tok, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")
    return payload


# =========================
# Password hashing (PBKDF2)
# =========================
def _pwd_hash(password: str) -> str:
    pwd = (password or "").encode("utf-8")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd, salt, PWD_ITERATIONS, dklen=32)
    # store: iterations$salt$dk
    return f"{PWD_ITERATIONS}${_b64url(salt)}${_b64url(dk)}"


def _pwd_verify(password: str, stored: str) -> bool:
    try:
        parts = (stored or "").split("$")
        if len(parts) != 3:
            return False
        iters = int(parts[0])
        salt = _b64urldecode(parts[1])
        good = _b64urldecode(parts[2])
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iters, dklen=32)
        return hmac.compare_digest(good, dk)
    except Exception:
        return False


# =========================
# OTP helpers
# =========================
def _sha256(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def otp_create(account_id: int) -> str:
    code = "".join(secrets.choice("0123456789") for _ in range(6))
    expires_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + OTP_TTL_SECONDS))
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO otp_codes_web(account_id,code_hash,expires_at,attempts,status) VALUES(?,?,?,?,?)",
        (int(account_id), _sha256(code), expires_at, 0, "pending"),
    )
    conn.commit()
    conn.close()
    return code


def otp_check_and_consume(account_id: int, code: str) -> Tuple[bool, str]:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, code_hash, expires_at, attempts, status
        FROM otp_codes_web
        WHERE account_id=? AND status='pending'
        ORDER BY id DESC
        LIMIT 1
        """,
        (int(account_id),),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return False, "No tienes un código activo. Pide uno nuevo."

    otp_id = int(row["id"])
    expires_at = (row["expires_at"] or "").strip()
    attempts = int(row["attempts"] or 0)

    # expiry
    try:
        exp_ts = time.mktime(time.strptime(expires_at, "%Y-%m-%d %H:%M:%S"))
        if time.time() > exp_ts:
            cur.execute("UPDATE otp_codes_web SET status='expired' WHERE id=?", (otp_id,))
            conn.commit()
            conn.close()
            return False, "El código expiró. Pide otro."
    except Exception:
        pass

    if _sha256(code) != (row["code_hash"] or ""):
        attempts += 1
        cur.execute("UPDATE otp_codes_web SET attempts=? WHERE id=?", (attempts, otp_id))
        if attempts >= OTP_MAX_ATTEMPTS:
            cur.execute("UPDATE otp_codes_web SET status='expired' WHERE id=?", (otp_id,))
        conn.commit()
        conn.close()
        if attempts >= OTP_MAX_ATTEMPTS:
            return False, "Código incorrecto. Se bloqueó este intento. Pide otro código."
        return False, f"Código incorrecto. Intentos: {attempts}/{OTP_MAX_ATTEMPTS}"

    cur.execute("UPDATE otp_codes_web SET status='done' WHERE id=?", (otp_id,))
    conn.commit()
    conn.close()
    return True, "Código verificado."


def send_sms_twilio(to_phone: str, text: str) -> bool:
    """
    Envío SMS por Twilio Messages API (sin librerías externas).
    Requiere: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER
    """
    if not TWILIO_SMS_ENABLED:
        return False

    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
    data = urllib.parse.urlencode({"To": to_phone, "From": TWILIO_FROM_NUMBER, "Body": text}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")

    auth = base64.b64encode(f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}".encode("utf-8")).decode("utf-8")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            _ = resp.read()
        return True
    except Exception as e:
        print("❌ Twilio SMS error:", repr(e))
        return False


def send_verification_code(phone: str, code: str) -> bool:
    msg = f"{APP_TITLE}: tu código de verificación es {code}. Expira en {OTP_TTL_SECONDS//60} min."
    ok = send_sms_twilio(phone, msg)
    if not ok:
        # Fallback: consola (para pruebas / si no tienes proveedor)
        print(f"⚠️ OTP (NO ENVIADO POR SMS) para {phone}: {code}")
    return ok


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
    .hr {{
      height:1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent);
      margin: 14px 0;
    }}

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

    sms_status = "Twilio ✅" if TWILIO_SMS_ENABLED else "SMS ⚠️ (sin proveedor)"

    body = f"""
    <div class="grid">
      <div class="card hero">
        <div class="pill">⚡ Activación rápida</div>
        <div class="pill" style="margin-left:8px;">🔒 Conexión privada</div>
        <div class="pill" style="margin-left:8px;">📩 Soporte</div>
        <div style="height:12px;"></div>

        <h1>{html_escape(APP_TITLE)} — Panel Web</h1>
        <p>
          Plataforma web para gestionar tus proxies, pedidos y soporte.
          Acceso de clientes con <b>Teléfono + Contraseña</b> y verificación por código.
        </p>
        <div class="hr"></div>

        <div class="row">
          <a class="btn" href="/admin/login">🔐 Admin</a>
          <a class="btn ghost" href="/client/login">👤 Login</a>
          <a class="btn ghost" href="/client/register">✨ Crear cuenta</a>
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
        <div class="muted">Verificación</div>
        <p style="margin:8px 0 0 0; color: rgba(255,255,255,.78);">
          Envío de código: <b>{sms_status}</b><br/>
          (Configura variables <code>TWILIO_*</code> para enviar OTP por SMS)
        </p>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="WEB ONLY • Panel Admin & Cliente")


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH, "twilio_sms": TWILIO_SMS_ENABLED}


# =========================
# Admin Auth
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <div class="grid">
      <div class="card hero">
        <h1>Admin Access</h1>
        <p>Entra al panel premium para gestionar cuentas, pedidos y mantenimiento.</p>
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

    accounts = count("SELECT COUNT(*) FROM accounts")
    proxies = count("SELECT COUNT(*) FROM proxies")
    tickets = count("SELECT COUNT(*) FROM tickets")
    pending = count("SELECT COUNT(*) FROM requests WHERE estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')")

    conn.close()

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>Admin Dashboard</h1>
      <p>Control total: cuentas, proxies, pedidos y mantenimiento.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/accounts">👥 Cuentas</a>
        <a class="btn" href="/admin/orders">📨 Pedidos</a>
        <a class="btn" href="/admin/proxies">📦 Proxies</a>
        <a class="btn" href="/admin/maintenance">🛠 Mantenimiento</a>
        <a class="btn ghost" href="/admin/logout">🚪 Salir</a>
      </div>
    </div>

    <div class="row">
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Cuentas</div>
        <div class="kpi">{accounts}</div>
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
    return page("Admin", body, subtitle="Panel premium • WEB ONLY")


# =========================
# Admin: Accounts
# =========================
@app.get("/admin/accounts", response_class=HTMLResponse)
def admin_accounts(admin=Depends(require_admin), q: str = ""):
    conn = db()
    cur = conn.cursor()

    if q.strip():
        cur.execute(
            """
            SELECT id, phone, verified, is_blocked, created_at
            FROM accounts
            WHERE phone LIKE ? OR CAST(id AS TEXT) LIKE ?
            ORDER BY id DESC
            LIMIT 80
            """,
            (f"%{q.strip()}%", f"%{q.strip()}%"),
        )
    else:
        cur.execute(
            """
            SELECT id, phone, verified, is_blocked, created_at
            FROM accounts
            ORDER BY id DESC
            LIMIT 80
            """
        )

    rows = cur.fetchall()
    conn.close()

    trs = ""
    for r in rows:
        aid = int(r["id"])
        phone = r["phone"] or "-"
        verified = "✅" if int(r["verified"] or 0) == 1 else "⚠️"
        blocked = "🚫" if int(r["is_blocked"] or 0) == 1 else "✅"
        created = r["created_at"] or "-"
        trs += (
            "<tr>"
            f"<td>{blocked}</td>"
            f"<td><a class='btn ghost' href='/admin/account/{aid}'>👤 {aid}</a></td>"
            f"<td>{html_escape(phone)}</td>"
            f"<td>{verified}</td>"
            f"<td>{html_escape(created)}</td>"
            "</tr>"
        )

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>
      <form method="get" action="/admin/accounts">
        <label class="muted">Buscar (id o teléfono)</label>
        <input name="q" value="{html_escape(q or '')}" placeholder="Ej: +1809... o 12" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Buscar</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>Estado</th><th>ID</th><th>Teléfono</th><th>Verificado</th><th>Creado</th></tr>
        {trs or "<tr><td colspan='5' class='muted'>No hay resultados</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Cuentas", body, subtitle="Usuarios WEB")


@app.post("/admin/account/{account_id}/toggle_block")
def admin_toggle_account_block(account_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT is_blocked FROM accounts WHERE id=?", (account_id,))
    row = cur.fetchone()
    curv = int(row["is_blocked"] or 0) if row else 0
    newv = 0 if curv == 1 else 1
    cur.execute("UPDATE accounts SET is_blocked=?, updated_at=? WHERE id=?", (newv, now_str(), account_id))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/admin/account/{account_id}", status_code=302)


@app.get("/admin/account/{account_id}", response_class=HTMLResponse)
def admin_account_detail(account_id: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id, phone, verified, is_blocked, created_at, updated_at FROM accounts WHERE id=?", (account_id,))
    a = cur.fetchone()

    proxies_rows = []
    req_rows = []

    try:
        cur.execute("SELECT id, ip, vence, estado FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 20", (account_id,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, ip, cantidad, monto, estado, created_at FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
            (account_id,),
        )
        req_rows = cur.fetchall()
    except Exception:
        req_rows = []

    conn.close()

    if not a:
        body = """
        <div class="card">
          <p>No encontré esa cuenta.</p>
          <a class="btn" href="/admin/accounts">⬅️ Volver</a>
        </div>
        """
        return page("Admin • Cuenta", body, subtitle="Detalle")

    blocked = int(a["is_blocked"] or 0)
    tag = "🚫 BLOQUEADO" if blocked == 1 else "✅ ACTIVO"
    verified = int(a["verified"] or 0)
    vtag = "✅ VERIFICADO" if verified == 1 else "⚠️ NO VERIFICADO"

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
        <a class="btn ghost" href="/admin/accounts">⬅️ Cuentas</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>

        <form method="post" action="/admin/account/{account_id}/toggle_block" style="margin-left:auto;">
          <button class="{toggle_class}" type="submit">{toggle_label}</button>
        </form>
      </div>

      <div class="hr"></div>
      <div class="muted">Cuenta</div>
      <div class="kpi">{account_id}</div>
      <p class="muted">Tel: <b>{html_escape(a['phone'] or '-')}</b> • {tag} • {vtag}</p>
      <p class="muted">Creado: {html_escape(a['created_at'] or '-')} • Actualizado: {html_escape(a['updated_at'] or '-')}</p>
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
    return page(f"Admin • Cuenta {account_id}", body, subtitle="Detalle premium")


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
          <div><b>Cuenta:</b> <a class="btn ghost" href="/admin/account/{int(r["user_id"])}">👤 {int(r["user_id"])}</a></div>
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
        <select name="state">
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
    cur.execute("SELECT id FROM requests WHERE id=?", (rid,))
    req = cur.fetchone()
    if not req:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado")

    cur.execute("UPDATE requests SET estado=? WHERE id=?", ("approved", rid))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/admin/orders", status_code=302)


@app.post("/admin/order/{rid}/reject")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM requests WHERE id=?", (rid,))
    req = cur.fetchone()
    if not req:
        conn.close()
        raise HTTPException(404, "Pedido no encontrado")

    cur.execute("UPDATE requests SET estado=? WHERE id=?", ("rejected", rid))
    conn.commit()
    conn.close()

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
            f"<td><a class='btn ghost' href='/admin/account/{int(r['user_id'])}'>👤 {int(r['user_id'])}</a></td>"
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
        <label class="muted">Buscar (account_id o ip)</label>
        <input name="q" value="{html_escape(q or '')}" placeholder="Ej: 12 o 104." />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Buscar</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr><th>PID</th><th>Cuenta</th><th>IP</th><th>Vence</th><th>Estado</th></tr>
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
      <p>Activa o desactiva mantenimiento. Los clientes verán el mensaje en el login/panel.</p>
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
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    if action == "off":
        set_setting("maintenance_enabled", "0")
        return RedirectResponse(url="/admin/maintenance", status_code=302)

    raise HTTPException(400, "Acción inválida")


# =========================
# Client: Register / Verify / Login
# =========================
@app.get("/client/register", response_class=HTMLResponse)
def client_register_page():
    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    warn = ""
    if maint:
        warn = f"""
        <div class="card" style="border-color: rgba(255,176,32,.35);">
          <div class="muted">🟠 Mantenimiento</div>
          <p style="color: rgba(255,255,255,.78); margin: 8px 0 0 0;">{html_escape(mtxt)}</p>
        </div>
        <div style="height:12px;"></div>
        """

    body = f"""
    {warn}
    <div class="grid">
      <div class="card hero">
        <h1>Crear cuenta</h1>
        <p>Regístrate con <b>teléfono + contraseña</b>. Te enviaremos un <b>código</b> para verificar tu número.</p>
        <div class="hr"></div>
        <div class="pill">📱 Teléfono</div>
        <div class="pill" style="margin-left:8px;">🔒 Contraseña</div>
        <div class="pill" style="margin-left:8px;">🔑 Código</div>
      </div>

      <div class="card">
        <form method="post" action="/client/register">
          <label class="muted">Teléfono (ej: +1809...)</label><br/>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Contraseña (mín 6)</label><br/>
          <input name="password" type="password" placeholder="••••••" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Crear cuenta</button>
          <a class="btn ghost" href="/client/login" style="margin-left:10px;">Tengo cuenta</a>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">
          SMS: {("Twilio activo ✅" if TWILIO_SMS_ENABLED else "Sin proveedor ⚠️ (se mostrará solo si DEBUG_SHOW_OTP=1)")}
        </p>
      </div>
    </div>
    """
    return page("Cliente • Registro", body, subtitle="Cuenta WEB")


@app.post("/client/register", response_class=HTMLResponse)
def client_register(phone: str = Form(...), password: str = Form(...)):
    phone = (phone or "").strip()
    password = (password or "").strip()

    if len(phone) < 7:
        raise HTTPException(400, "Teléfono inválido.")
    if len(password) < 6:
        raise HTTPException(400, "Contraseña muy corta (mínimo 6).")

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id, verified FROM accounts WHERE phone=?", (phone,))
    row = cur.fetchone()

    if row:
        account_id = int(row["id"])
        # si existe, solo reenviamos OTP si no está verificado
        if int(row["verified"] or 0) == 1:
            conn.close()
            body = f"""
            <div class="card">
              <h3>Ya existe una cuenta</h3>
              <p class="muted">Ese teléfono ya está verificado. Puedes iniciar sesión.</p>
              <div class="hr"></div>
              <a class="btn" href="/client/login">Ir a login</a>
              <a class="btn ghost" href="/">🏠 Inicio</a>
            </div>
            """
            return HTMLResponse(page("Cliente • Registro", body, subtitle=""), status_code=200)

        # si no está verificado, regeneramos OTP
        code = otp_create(account_id)
        conn.close()
        send_verification_code(phone, code)

        extra = ""
        if DEBUG_SHOW_OTP and (not TWILIO_SMS_ENABLED):
            extra = f"<div class='hr'></div><p class='muted'>DEBUG OTP: <b>{html_escape(code)}</b></p>"

        body = f"""
        <div class="card">
          <h3>Código enviado</h3>
          <p class="muted">Te enviamos un código al teléfono <b>{html_escape(phone)}</b>.</p>
          {extra}
          <div class="hr"></div>
          <a class="btn" href="/client/verify?phone={urllib.parse.quote(phone)}">✅ Verificar ahora</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Verificación", body, subtitle=""), status_code=200)

    # Crear cuenta nueva (no verificada)
    phash = _pwd_hash(password)
    cur.execute(
        "INSERT INTO accounts(phone,password_hash,verified,is_blocked,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        (phone, phash, 0, 0, now_str(), now_str()),
    )
    account_id = int(cur.lastrowid)
    conn.commit()
    conn.close()

    code = otp_create(account_id)
    send_verification_code(phone, code)

    extra = ""
    if DEBUG_SHOW_OTP and (not TWILIO_SMS_ENABLED):
        extra = f"<div class='hr'></div><p class='muted'>DEBUG OTP: <b>{html_escape(code)}</b></p>"

    body = f"""
    <div class="card">
      <h3>Cuenta creada</h3>
      <p class="muted">Te enviamos un código al teléfono <b>{html_escape(phone)}</b> para verificar tu cuenta.</p>
      {extra}
      <div class="hr"></div>
      <a class="btn" href="/client/verify?phone={urllib.parse.quote(phone)}">✅ Verificar ahora</a>
      <a class="btn ghost" href="/">🏠 Inicio</a>
    </div>
    """
    return HTMLResponse(page("Cliente • Verificación", body, subtitle=""), status_code=200)


@app.get("/client/verify", response_class=HTMLResponse)
def client_verify_page(phone: str = ""):
    phone = (phone or "").strip()
    body = f"""
    <div class="grid">
      <div class="card hero">
        <h1>Verificar teléfono</h1>
        <p>Escribe el código de 6 dígitos que te llegó por SMS.</p>
        <div class="hr"></div>
        <div class="pill">🔑 Código</div>
        <div class="pill" style="margin-left:8px;">⏳ Expira</div>
      </div>

      <div class="card">
        <form method="post" action="/client/verify">
          <label class="muted">Teléfono</label><br/>
          <input name="phone" value="{html_escape(phone)}" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Código (6 dígitos)</label><br/>
          <input name="code" placeholder="123456" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Verificar</button>
          <a class="btn ghost" href="/client/login" style="margin-left:10px;">Ir a login</a>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>
      </div>
    </div>
    """
    return page("Cliente • Verificar", body, subtitle="Confirmación")


@app.post("/client/verify", response_class=HTMLResponse)
def client_verify(phone: str = Form(...), code: str = Form(...)):
    phone = (phone or "").strip()
    code = (code or "").strip()

    if len(phone) < 7:
        raise HTTPException(400, "Teléfono inválido.")
    if not (code.isdigit() and len(code) == 6):
        raise HTTPException(400, "Código inválido (debe ser 6 dígitos).")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, verified, is_blocked FROM accounts WHERE phone=?", (phone,))
    row = cur.fetchone()
    if not row:
        conn.close()
        body = """
        <div class="card">
          <h3>No existe esa cuenta</h3>
          <p class="muted">Primero crea tu cuenta.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/register">✨ Crear cuenta</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Verificación", body, subtitle=""), status_code=404)

    if int(row["is_blocked"] or 0) == 1:
        conn.close()
        body = """
        <div class="card">
          <h3>Acceso bloqueado</h3>
          <p class="muted">Tu cuenta está bloqueada. Contacta soporte.</p>
          <div class="hr"></div>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Bloqueado", body, subtitle=""), status_code=403)

    account_id = int(row["id"])
    ok, msg = otp_check_and_consume(account_id, code)
    if not ok:
        conn.close()
        body = f"""
        <div class="card">
          <h3>No se pudo verificar</h3>
          <p class="muted">{html_escape(msg)}</p>
          <div class="hr"></div>
          <a class="btn" href="/client/verify?phone={urllib.parse.quote(phone)}">⬅️ Intentar de nuevo</a>
          <a class="btn ghost" href="/client/register">Reenviar código</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Verificación", body, subtitle=""), status_code=400)

    # marcar verified
    cur.execute("UPDATE accounts SET verified=1, updated_at=? WHERE id=?", (now_str(), account_id))
    conn.commit()
    conn.close()

    body = f"""
    <div class="card">
      <h3>✅ Verificado</h3>
      <p class="muted">Tu teléfono quedó verificado. Ya puedes iniciar sesión.</p>
      <div class="hr"></div>
      <a class="btn" href="/client/login">🔐 Ir a login</a>
      <a class="btn ghost" href="/">🏠 Inicio</a>
    </div>
    """
    return HTMLResponse(page("Cliente • Verificación", body, subtitle=""), status_code=200)


@app.get("/client/login", response_class=HTMLResponse)
def client_login_page():
    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    warn = ""
    if maint:
        warn = f"""
        <div class="card" style="border-color: rgba(255,176,32,.35);">
          <div class="muted">🟠 Mantenimiento</div>
          <p style="color: rgba(255,255,255,.78); margin: 8px 0 0 0;">{html_escape(mtxt)}</p>
        </div>
        <div style="height:12px;"></div>
        """

    body = f"""
    {warn}
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
          <a class="btn ghost" href="/client/register" style="margin-left:10px;">✨ Crear cuenta</a>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">
          Si no verificaste tu número, entra a <a class="btn ghost" href="/client/verify">Verificar</a>.
        </p>
      </div>
    </div>
    """
    return page("Cliente • Login", body, subtitle="Acceso seguro")


@app.post("/client/login", response_class=HTMLResponse)
def client_login(phone: str = Form(...), password: str = Form(...)):
    phone = (phone or "").strip()
    password = (password or "").strip()

    if len(phone) < 7 or not password:
        body = """
        <div class="card">
          <h3>Login inválido</h3>
          <p class="muted">Verifica tu teléfono y contraseña.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/login">⬅️ Intentar de nuevo</a>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Error", body, subtitle=""), status_code=401)

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, verified, is_blocked FROM accounts WHERE phone=?", (phone,))
    row = cur.fetchone()
    conn.close()

    if not row:
        body = """
        <div class="card">
          <h3>Login inválido</h3>
          <p class="muted">Cuenta no encontrada.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/register">✨ Crear cuenta</a>
          <a class="btn ghost" href="/client/login">⬅️ Login</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Error", body, subtitle=""), status_code=401)

    if int(row["is_blocked"] or 0) == 1:
        body = """
        <div class="card">
          <h3>Acceso bloqueado</h3>
          <p class="muted">Tu cuenta está bloqueada. Contacta soporte.</p>
          <div class="hr"></div>
          <a class="btn ghost" href="/">🏠 Inicio</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Bloqueado", body, subtitle=""), status_code=403)

    if int(row["verified"] or 0) != 1:
        body = f"""
        <div class="card">
          <h3>Falta verificación</h3>
          <p class="muted">Tu teléfono aún no está verificado. Verifica con el código.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/verify?phone={urllib.parse.quote(phone)}">✅ Verificar</a>
          <a class="btn ghost" href="/client/register">Reenviar código</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Verificación", body, subtitle=""), status_code=403)

    if not _pwd_verify(password, row["password_hash"] or ""):
        body = """
        <div class="card">
          <h3>Login inválido</h3>
          <p class="muted">Contraseña incorrecta.</p>
          <div class="hr"></div>
          <a class="btn" href="/client/login">⬅️ Intentar de nuevo</a>
        </div>
        """
        return HTMLResponse(page("Cliente • Error", body, subtitle=""), status_code=401)

    account_id = int(row["id"])
    session = sign({"role": "client", "aid": account_id}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie("client_session", session, httponly=True, secure=True, samesite="lax")
    return resp


@app.get("/logout")
def client_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("client_session")
    return resp


# =========================
# Client portal
# =========================
@app.get("/me", response_class=HTMLResponse)
def client_me(client=Depends(require_client)):
    aid = int(client["aid"])

    # bloqueado?
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT phone, is_blocked FROM accounts WHERE id=?", (aid,))
    arow = cur.fetchone()
    if not arow:
        conn.close()
        resp = RedirectResponse(url="/client/login", status_code=302)
        resp.delete_cookie("client_session")
        return resp
    if int(arow["is_blocked"] or 0) == 1:
        conn.close()
        resp = RedirectResponse(url="/client/login", status_code=302)
        resp.delete_cookie("client_session")
        return resp

    phone = arow["phone"] or "-"

    proxies_rows = []
    orders_rows = []

    try:
        cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 50", (aid,))
        proxies_rows = cur.fetchall()
    except Exception:
        proxies_rows = []

    try:
        cur.execute(
            "SELECT id, tipo, ip, cantidad, monto, estado, created_at FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 50",
            (aid,),
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

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    maint_card = ""
    if maint:
        maint_card = f"""
        <div class="card" style="border-color: rgba(255,176,32,.35);">
          <div class="muted">🟠 Mantenimiento</div>
          <p style="color: rgba(255,255,255,.78); margin: 8px 0 0 0;">{html_escape(mtxt)}</p>
        </div>
        <div style="height:12px;"></div>
        """

    body = f"""
    {maint_card}
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
        <div class="muted">Tu cuenta</div>
        <div class="kpi">{aid}</div>
        <p class="muted">{html_escape(phone)}</p>
      </div>
      <div class="card" style="flex:2; min-width:240px;">
        <div class="muted">Tips</div>
        <div class="kpi">🛡️ Seguro</div>
        <p class="muted">No compartas tu contraseña. Si la olvidas, el admin puede resetearla.</p>
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
# API: Maintenance status
# =========================
@app.get("/api/maintenance")
def api_maintenance():
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")
    return {"enabled": enabled, "message": msg}
