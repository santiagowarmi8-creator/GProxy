# web.py — Gproxy Web Panel (FastAPI) PREMIUM (FULL)
# ✅ Anti "database is locked" (WAL + busy_timeout + retry)
# ✅ No muestra trazas/códigos al usuario (handlers HTML)
# ✅ Soporte FAB funciona (si no hay sesión, redirige al login)
# ✅ Stock por cantidad (no pegar proxies)
# ✅ PIN recuperación (en signup) + forgot password
# ✅ Admin wipe (borrar todo) con confirmación y feedback
# ✅ UI premium + ripple efecto botones
# ✅ Incluye rutas: /me /buy /renew /bank /proxies /notifications /support /order/{rid}/pay /voucher etc.

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Callable

from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError


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

SQLITE_TIMEOUT = float(os.getenv("SQLITE_TIMEOUT", "30"))
SQLITE_BUSY_MS = int(os.getenv("SQLITE_BUSY_MS", "8000"))
SQLITE_RETRIES = int(os.getenv("SQLITE_RETRIES", "6"))
SQLITE_RETRY_SLEEP = float(os.getenv("SQLITE_RETRY_SLEEP", "0.25"))


# =========================
# APP
# =========================
app = FastAPI(title=APP_TITLE)

os.makedirs(VOUCHER_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=UPLOAD_DIR), name="static")

CLIENT_SECRET: Optional[str] = None


# =========================
# TIME helpers
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
# DB (anti-lock)
# =========================
def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=SQLITE_TIMEOUT)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_MS};")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn


def db_exec(fn: Callable[[sqlite3.Connection], Any]) -> Any:
    last_err = None
    for i in range(SQLITE_RETRIES):
        conn = _connect()
        try:
            res = fn(conn)
            conn.commit()
            conn.close()
            return res
        except HTTPException:
            conn.rollback()
            conn.close()
            raise
        except sqlite3.OperationalError as e:
            conn.rollback()
            conn.close()
            last_err = e
            msg = str(e).lower()
            if "database is locked" in msg or "database busy" in msg:
                time.sleep(SQLITE_RETRY_SLEEP * (i + 1))
                continue
            raise
        except Exception:
            conn.rollback()
            conn.close()
            raise
    raise HTTPException(503, "El sistema está ocupado. Intenta de nuevo en unos segundos.")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, coldef: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = {row[1] for row in cur.fetchall()}
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")


def _ensure_table_exists(conn: sqlite3.Connection, create_sql: str) -> None:
    conn.execute(create_sql)


# =========================
# Schema / settings
# =========================
def ensure_web_schema() -> str:
    conn = _connect()
    cur = conn.cursor()

    # settings
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
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
            recovery_pin_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )
    _ensure_column(conn, "accounts", "recovery_pin_hash", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "accounts", "verified", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "accounts", "created_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "accounts", "updated_at", "TEXT NOT NULL DEFAULT ''")

    # signup pins (verificación)
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

    # tickets
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
        );
        """,
    )

    # notifications
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

    # admin_logs
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

    def ins(key: str, value: str):
        cur.execute(
            "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
            (key, value, now_str()),
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

    # Persist CLIENT_SECRET
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

    global PIN_SECRET
    if not PIN_SECRET:
        PIN_SECRET = client_secret

    conn.commit()
    conn.close()

    # Migraciones para tablas del bot (si existen)
    def safe_migrate():
        c = _connect()
        try:
            _ensure_column(c, "requests", "voucher_path", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(c, "requests", "voucher_uploaded_at", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(c, "requests", "email", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(c, "requests", "currency", "TEXT NOT NULL DEFAULT 'DOP'")
            _ensure_column(c, "requests", "target_proxy_id", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(c, "requests", "note", "TEXT NOT NULL DEFAULT ''")
            c.commit()
        except Exception:
            pass
        try:
            _ensure_column(c, "proxies", "inicio", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(c, "proxies", "vence", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(c, "proxies", "raw", "TEXT NOT NULL DEFAULT ''")
            c.commit()
        except Exception:
            pass
        c.close()

    safe_migrate()
    return client_secret


@app.on_event("startup")
def _startup():
    global CLIENT_SECRET
    CLIENT_SECRET = ensure_web_schema()


# =========================
# Settings helper
# =========================
def get_setting(key: str, default: str = "") -> str:
    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        return (row["value"] if row else default) or default

    return db_exec(_fn)


def set_setting(key: str, value: str):
    def _fn(conn):
        conn.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_str()),
        )

    db_exec(_fn)


def admin_log(action: str, details: str = ""):
    def _fn(conn):
        conn.execute(
            "INSERT INTO admin_logs(action,details,created_at) VALUES(?,?,?)",
            (action, details or "", now_str()),
        )

    db_exec(_fn)


def outbox_add(kind: str, message: str):
    if not ENABLE_OUTBOX:
        return

    def _fn(conn):
        conn.execute(
            "INSERT INTO outbox(kind,message,created_at,sent_at) VALUES(?,?,?,?)",
            (kind, message or "", now_str(), ""),
        )

    db_exec(_fn)


def notify_user(user_id: int, message: str):
    def _fn(conn):
        conn.execute(
            "INSERT INTO notifications(user_id,message,seen,created_at) VALUES(?,?,?,?)",
            (int(user_id), message or "", 0, now_str()),
        )

    db_exec(_fn)


# =========================
# Token (HMAC)
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
    if t.lower().startswith("bearer "):
        t = t.split(" ", 1)[1].strip()

    parts = t.split(".")
    if len(parts) != 2:
        raise HTTPException(401, "Sesión inválida")

    raw = _b64urldecode(parts[0])
    sig = _b64urldecode(parts[1])

    good = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, good):
        raise HTTPException(401, "Sesión inválida")

    payload = json.loads(raw.decode("utf-8"))
    exp = int(payload.get("exp", 0) or 0)
    if exp <= 0 or exp < int(time.time()):
        raise HTTPException(401, "Sesión expirada")
    return payload


# =========================
# Cookie helper (FIX login "no hace nada")
# =========================
def _is_https(request: Request) -> bool:
    # Railway / reverse proxy usually sends x-forwarded-proto
    xf = (request.headers.get("x-forwarded-proto") or "").lower().strip()
    if xf in ("https", "http"):
        return xf == "https"
    return (request.url.scheme or "").lower() == "https"


def set_cookie_smart(request: Request, resp: RedirectResponse, name: str, value: str, max_age: Optional[int] = None):
    secure = COOKIE_SECURE and _is_https(request)
    resp.set_cookie(
        name,
        value,
        httponly=True,
        secure=secure,
        samesite=COOKIE_SAMESITE,
        max_age=max_age,
    )


# =========================
# Guards
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


def client_optional(request: Request) -> Optional[Dict[str, Any]]:
    if not CLIENT_SECRET:
        return None
    try:
        tok = request.cookies.get("client_session", "")
        if not tok:
            return None
        payload = verify(tok, CLIENT_SECRET)
        if payload.get("role") != "client":
            return None
        return payload
    except Exception:
        return None


# =========================
# Password + PIN helpers
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


def toast(msg: str, kind: str = "info") -> str:
    if not msg:
        return ""
    color = {
        "info": "rgba(0,212,255,.18)",
        "ok": "rgba(43,255,154,.18)",
        "warn": "rgba(255,176,32,.18)",
        "bad": "rgba(255,77,109,.18)",
    }.get(kind, "rgba(255,255,255,.10)")
    border = {
        "info": "rgba(0,212,255,.28)",
        "ok": "rgba(43,255,154,.28)",
        "warn": "rgba(255,176,32,.28)",
        "bad": "rgba(255,77,109,.28)",
    }.get(kind, "rgba(255,255,255,.18)")
    return f"""
    <div class="toast" style="background:{color}; border-color:{border};">
      {html_escape(msg)}
    </div>
    """


def pretty_error_page(title: str, msg: str, back_href: str = "/", back_label: str = "Volver"):
    body = f"""
    <div class="card hero">
      <h1>{html_escape(title)}</h1>
      <p>{html_escape(msg)}</p>
      <div class="hr"></div>
      <a class="btn ghost" href="{html_escape(back_href)}">⬅️ {html_escape(back_label)}</a>
    </div>
    """
    return page(title, body, subtitle="")


def _guess_back(path: str) -> str:
    if path.startswith("/admin"):
        return "/admin/login"
    if path.startswith("/client") or path in ("/me", "/buy", "/renew", "/bank", "/proxies", "/support", "/notifications"):
        return "/client/login"
    return "/"


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
      --bg1:#070019; --bg2:#14002e; --bg3:#24003f;
      --card: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.12);
      --muted:#cbb6ff; --text:#ffffff;
      --p1:#7b00ff; --p2:#c400ff; --p3:#00d4ff;
      --ok:#2bff9a; --warn:#ffb020; --bad:#ff4d6d;
      --shadow: 0 18px 60px rgba(0,0,0,.45);
    }}
    *{{box-sizing:border-box}}
    body{{
      margin:0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
      color:var(--text);
      background:
        radial-gradient(1200px 500px at 10% 10%, rgba(196,0,255,.25), transparent 60%),
        radial-gradient(1000px 600px at 90% 20%, rgba(0,212,255,.18), transparent 55%),
        radial-gradient(900px 700px at 40% 90%, rgba(123,0,255,.18), transparent 60%),
        linear-gradient(135deg, var(--bg1), var(--bg2), var(--bg3));
      min-height:100vh; overflow-x:hidden;
    }}
    .noise{{position:fixed; inset:0; pointer-events:none; opacity:.06;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='.6'/%3E%3C/svg%3E");
    }}
    .wrap{{max-width:1120px; margin:0 auto; padding:28px 18px 80px;}}
    .topbar{{display:flex; justify-content:space-between; align-items:center; gap:14px; margin-bottom:14px;}}
    .brand{{display:flex; align-items:center; gap:12px;}}
    .logo{{width:44px; height:44px; border-radius:14px;
      background:linear-gradient(45deg,var(--p1),var(--p2));
      box-shadow:0 0 30px rgba(196,0,255,.35);
      display:flex; align-items:center; justify-content:center;
      position:relative; overflow:hidden;
    }}
    .logo:before{{content:""; position:absolute; inset:-40%;
      background:conic-gradient(from 180deg, rgba(255,255,255,0), rgba(255,255,255,.35), rgba(255,255,255,0));
      animation:spin 4s linear infinite;
    }}
    .logo span{{position:relative; font-weight:900; letter-spacing:.5px;}}
    @keyframes spin{{to{{transform:rotate(360deg)}}}}
    .title{{font-size:18px; font-weight:900; margin:0; letter-spacing:.2px;}}
    .subtitle{{margin:0; color:var(--muted); font-size:13px;}}
    .chip{{display:inline-flex; align-items:center; gap:8px; padding:10px 12px; border-radius:999px;
      background:rgba(255,255,255,.06); border:1px solid var(--border); box-shadow:var(--shadow); white-space:nowrap;
    }}
    .grid{{display:grid; grid-template-columns: 1.4fr .9fr; gap:16px;}}
    @media (max-width: 980px){{.grid{{grid-template-columns:1fr;}}}}

    .card{{background:var(--card); border:1px solid var(--border); border-radius:20px; padding:18px;
      box-shadow:var(--shadow); backdrop-filter: blur(14px);
      animation: pop .35s ease both;
    }}
    @keyframes pop{{from{{transform:translateY(6px); opacity:0}} to{{transform:translateY(0); opacity:1}}}}
    .hero{{padding:18px; border-radius:20px;
      background: linear-gradient(135deg, rgba(123,0,255,.18), rgba(0,212,255,.10));
      border:1px solid rgba(255,255,255,.12);
    }}
    .hero h1{{margin:0 0 8px 0; font-size:26px; letter-spacing:.2px;}}
    .hero p{{margin:0; color:rgba(255,255,255,.80); line-height:1.5;}}
    .row{{display:flex; gap:12px; flex-wrap:wrap; align-items:center;}}
    .muted{{color:var(--muted); font-size:13px;}}
    .hr{{height:1px; background:linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent); margin:14px 0;}}
    .kpi{{font-size:34px; font-weight:900; letter-spacing:.3px; margin-top:6px;
      background:linear-gradient(90deg,#fff,#e9dbff,#b9f2ff);
      -webkit-background-clip:text; background-clip:text; color:transparent;
    }}
    input, textarea, select{{width:100%; padding:12px 14px; border-radius:14px;
      border:1px solid rgba(255,255,255,.12); background:rgba(0,0,0,.22); color:white; outline:none;
    }}
    textarea{{min-height:120px}}
    table{{width:100%; border-collapse:collapse; overflow:hidden; border-radius:14px;}}
    th,td{{border-bottom:1px solid rgba(255,255,255,.10); padding:12px; text-align:left; font-size:13px; vertical-align:top;}}
    th{{color:#f0eaff; font-weight:900}}
    pre,code{{background:rgba(0,0,0,.25); border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:12px; overflow:auto;}}
    pre{{white-space:pre-wrap; word-break:break-word;}}

    .btn{{appearance:none; border:none; border-radius:14px; padding:12px 16px; font-weight:850; color:white; text-decoration:none;
      cursor:pointer; background:linear-gradient(45deg,var(--p1),var(--p2)); box-shadow:0 12px 30px rgba(123,0,255,.22);
      transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
      display:inline-flex; align-items:center; gap:10px; position:relative; overflow:hidden;
    }}
    .btn:hover{{transform:translateY(-2px); box-shadow:0 16px 38px rgba(196,0,255,.30); filter:brightness(1.04)}}
    .btn:active{{transform:translateY(0px) scale(.98); filter:brightness(.98)}}
    .btn.ghost{{background:rgba(255,255,255,.06); border:1px solid var(--border); box-shadow:none;}}
    .btn.bad{{background:linear-gradient(45deg,#ff2b6a,#ff7a2b); box-shadow:0 12px 30px rgba(255,43,106,.20);}}
    .badge{{display:inline-flex; align-items:center; justify-content:center; min-width:22px; height:22px; padding:0 8px;
      border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.14);
      font-size:12px; font-weight:900; color:white;
    }}
    .pill{{display:inline-flex; gap:8px; padding:8px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.10);
      background:rgba(0,0,0,.18); font-size:12px; color:rgba(255,255,255,.85);
    }}
    .toast{{border:1px solid rgba(255,255,255,.18); border-radius:16px; padding:12px 14px; margin: 12px 0; color:white;}}
    .footer{{margin-top:16px; color:rgba(255,255,255,.55); font-size:12px; text-align:center;}}

    .support-fab{{
      position:fixed; right:18px; bottom:18px; width:58px; height:58px; border-radius:50%;
      display:flex; align-items:center; justify-content:center; text-decoration:none; font-size:26px;
      background:linear-gradient(45deg,var(--p3),var(--p2)); box-shadow:0 16px 40px rgba(0,212,255,.25);
      border:1px solid rgba(255,255,255,.16); z-index:9999;
      transition: transform .12s ease, filter .12s ease;
    }}
    .support-fab:hover{{transform:translateY(-2px); filter:brightness(1.05)}}
    .support-fab:active{{transform:translateY(0) scale(.97)}}

    .ripple {{
      position:absolute; border-radius:50%; transform:scale(0);
      background:rgba(255,255,255,.35); animation:ripple .55s ease-out;
      pointer-events:none;
    }}
    @keyframes ripple {{
      to {{ transform:scale(6); opacity:0; }}
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

  <script>
    document.addEventListener('click', function(e){{
      const btn = e.target.closest('.btn');
      if(!btn) return;
      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const s = document.createElement('span');
      s.className = 'ripple';
      s.style.left = x + 'px';
      s.style.top = y + 'px';
      s.style.width = s.style.height = Math.max(rect.width, rect.height) + 'px';
      btn.appendChild(s);
      setTimeout(()=>s.remove(), 600);
    }});
  </script>
</body>
</html>"""


# =========================
# Global exception handlers (NO códigos)
# =========================
@app.exception_handler(RequestValidationError)
def validation_exc_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Datos inválidos", "errors": exc.errors()}, status_code=422)

    back = _guess_back(request.url.path)
    return HTMLResponse(
        pretty_error_page("Datos inválidos", "Revisa los campos del formulario e intenta de nuevo.", back_href=back),
        status_code=422,
    )


@app.exception_handler(HTTPException)
def http_exc_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    back = _guess_back(request.url.path)
    return HTMLResponse(pretty_error_page("Ups", str(exc.detail), back_href=back), status_code=exc.status_code)


@app.exception_handler(Exception)
def any_exc_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Error interno"}, status_code=500)
    return HTMLResponse(pretty_error_page("Error", "Ocurrió un error interno. Intenta de nuevo.", back_href="/"), status_code=500)


# =========================
# PUBLIC
# =========================
@app.get("/", response_class=HTMLResponse)
def home():
    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")
    status = "🟠 Mantenimiento" if maint else "🟢 Online"

    body = f"""
    <div class="grid">
      <div class="card hero">
        <div class="pill">⚡ Activación rápida</div>
        <div class="pill" style="margin-left:8px;">🔒 Conexión privada</div>
        <div class="pill" style="margin-left:8px;">📩 Soporte directo</div>
        <div style="height:12px;"></div>

        <h1>{html_escape(APP_TITLE)} — Panel Web</h1>
        <p>Plataforma premium para gestión de proxies, pagos y soporte.</p>
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
        <div class="hr"></div>
        <div class="muted">{html_escape(mtxt) if maint else "Todo funcionando perfecto."}</div>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="Premium Panel")


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH, "client_secret_loaded": bool(CLIENT_SECRET)}


# =========================
# ADMIN AUTH
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(msg: str = ""):
    body = f"""
    <div class="grid">
      <div class="card hero">
        <h1>Admin Access</h1>
        <p>Acceso seguro al panel premium.</p>
        <div class="hr"></div>
        <div class="pill">🧠 Control</div>
        <div class="pill" style="margin-left:8px;">📊 Pedidos</div>
        <div class="pill" style="margin-left:8px;">💬 Soporte</div>
      </div>

      <div class="card">
        {toast(msg, "bad") if msg else ""}
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
    return page("Admin Login", body, subtitle="Ingreso seguro")


@app.post("/admin/login")
def admin_login(request: Request, password: str = Form("")):
    if not ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login?msg=Falta+ADMIN_PASSWORD", status_code=302)
    if (password or "").strip() != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login?msg=Clave+incorrecta", status_code=302)

    token = sign({"role": "admin"}, JWT_SECRET, exp_seconds=8 * 3600)
    resp = RedirectResponse(url="/admin", status_code=302)
    set_cookie_smart(request, resp, "admin_session", token, max_age=8 * 3600)
    return resp


@app.get("/admin/logout")
def admin_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("admin_session")
    return resp


# =========================
# ADMIN DASHBOARD
# =========================
def safe_count(sql: str, params: Tuple = ()) -> int:
    def _fn(conn):
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            return int(cur.fetchone()[0])
        except Exception:
            return 0
    return db_exec(_fn)


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(admin=Depends(require_admin)):
    users = safe_count("SELECT COUNT(*) FROM users")
    proxies = safe_count("SELECT COUNT(*) FROM proxies")
    pending = safe_count("SELECT COUNT(*) FROM requests WHERE estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')")
    open_tickets = safe_count("SELECT COUNT(*) FROM tickets WHERE status='open'")
    stock = int(float(get_setting("stock_available", "0") or 0))

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>Admin Dashboard</h1>
      <p>Control premium: usuarios, pedidos, stock, soporte y configuraciones.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/orders">📨 Pedidos <span class="badge">{pending}</span></a>
        <a class="btn" href="/admin/tickets">💬 Tickets <span class="badge">{open_tickets}</span></a>
        <a class="btn" href="/admin/stock">🧰 Stock <span class="badge">{stock}</span></a>
        <a class="btn" href="/admin/settings">⚙️ Banco/Precios</a>
        <a class="btn" href="/admin/maintenance">🛠 Mantenimiento</a>
        <a class="btn ghost" href="/admin/tools">🧹 Tools</a>
        <a class="btn ghost" href="/admin/logout" style="margin-left:auto;">🚪 Salir</a>
      </div>
    </div>

    <div class="row">
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Usuarios (bot)</div>
        <div class="kpi">{users}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Proxies (bot)</div>
        <div class="kpi">{proxies}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Pedidos pendientes</div>
        <div class="kpi">{pending}</div>
      </div>
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Stock disponible</div>
        <div class="kpi">{stock}</div>
      </div>
    </div>

    <div class="card">
      <div class="muted">Mantenimiento</div>
      <div class="kpi">{'🟠 ON' if maint else '🟢 OFF'}</div>
      <p class="muted">{html_escape(mtxt)}</p>
    </div>
    """
    return page("Admin", body, subtitle="Premium Panel")


# =========================
# ADMIN SETTINGS
# =========================
@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_page(admin=Depends(require_admin), msg: str = ""):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")
    precio_primera = get_setting("precio_primera", "1500")
    precio_renov = get_setting("precio_renovacion", "1000")
    dias_proxy = get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY))
    currency = get_setting("currency", "DOP")

    body = f"""
    <div class="card hero">
      <h1>⚙️ Banco / Precios</h1>
      <p>Configura pagos y precios.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
    </div>

    <div class="card">
      {toast(msg, "ok") if msg else ""}
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
        <label class="muted">Duración (días, max 30)</label>
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
    set_setting("currency", ((currency or "DOP").strip() or "DOP"))

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
    return RedirectResponse(url="/admin/settings?msg=Guardado", status_code=302)


# =========================
# ADMIN STOCK (cantidad)
# =========================
@app.get("/admin/stock", response_class=HTMLResponse)
def admin_stock_page(admin=Depends(require_admin), msg: str = ""):
    stock = int(float(get_setting("stock_available", "0") or 0))

    body = f"""
    <div class="card hero">
      <h1>🧰 Stock</h1>
      <p>Stock por <b>cantidad</b>. No necesitas pegar proxies aquí.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
    </div>

    <div class="card">
      {toast(msg, "ok") if msg else ""}
      <div class="muted">Stock disponible</div>
      <div class="kpi">{stock}</div>
      <div class="hr"></div>
      <form method="post" action="/admin/stock/set">
        <label class="muted">Actualizar stock</label>
        <input name="stock" value="{stock}" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">💾 Guardar stock</button>
      </form>
    </div>
    """
    return page("Admin • Stock", body, subtitle="Inventario (cantidad)")


@app.post("/admin/stock/set")
def admin_stock_set(stock: str = Form("0"), admin=Depends(require_admin)):
    try:
        v = int(float((stock or "0").strip()))
        if v < 0:
            v = 0
    except Exception:
        v = 0
    set_setting("stock_available", str(v))
    admin_log("stock_set", json.dumps({"stock": v}, ensure_ascii=False))
    return RedirectResponse(url="/admin/stock?msg=Stock+actualizado", status_code=302)


# =========================
# ADMIN MAINTENANCE
# =========================
@app.get("/admin/maintenance", response_class=HTMLResponse)
def admin_maintenance_page(admin=Depends(require_admin), msg: str = ""):
    enabled = get_setting("maintenance_enabled", "0") == "1"
    message = get_setting("maintenance_message", "")

    body = f"""
    <div class="card hero">
      <h1>🛠 Mantenimiento</h1>
      <p>Activa/desactiva mantenimiento (solo web).</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
    </div>

    <div class="card">
      {toast(msg, "ok") if msg else ""}
      <div class="muted">Estado</div>
      <div class="kpi">{'🟠 ON' if enabled else '🟢 OFF'}</div>
      <div class="hr"></div>

      <form method="post" action="/admin/maintenance">
        <label class="muted">Mensaje</label>
        <textarea name="message">{html_escape(message)}</textarea>
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
    action: str = Form(""),
    message: str = Form(""),
    admin=Depends(require_admin),
):
    msg = (message or "").strip() or "⚠️ Estamos en mantenimiento. Vuelve en unos minutos."
    set_setting("maintenance_message", msg)

    if action == "on":
        set_setting("maintenance_enabled", "1")
        outbox_add("maintenance_on", msg)
        admin_log("maintenance_on", msg)
        return RedirectResponse(url="/admin/maintenance?msg=Activado", status_code=302)

    if action == "off":
        set_setting("maintenance_enabled", "0")
        outbox_add("maintenance_off", msg)
        admin_log("maintenance_off", msg)
        return RedirectResponse(url="/admin/maintenance?msg=Desactivado", status_code=302)

    raise HTTPException(400, "Acción inválida")


# =========================
# ADMIN TOOLS (wipe) - FIXED
# =========================
@app.get("/admin/tools", response_class=HTMLResponse)
def admin_tools(admin=Depends(require_admin), msg: str = ""):
    body = f"""
    <div class="card hero">
      <h1>🧹 Tools</h1>
      <p>Herramientas avanzadas.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
    </div>

    <div class="card">
      {toast(msg, "warn") if msg else ""}
      <h3 style="margin:0 0 10px 0;">⚠️ Reset total</h3>
      <p class="muted">Borra datos del panel web y del bot (si las tablas existen).</p>
      <div class="hr"></div>
      <form method="post" action="/admin/tools/wipe">
        <label class="muted">Escribe <b>RESET</b></label>
        <input name="confirm" placeholder="RESET" />
        <div style="height:12px;"></div>
        <button class="btn bad" type="submit">🧨 BORRAR TODO</button>
      </form>
    </div>
    """
    return page("Admin • Tools", body, subtitle="Avanzado")


@app.post("/admin/tools/wipe")
def admin_wipe(confirm: str = Form(""), admin=Depends(require_admin)):
    if (confirm or "").strip().upper() != "RESET":
        return RedirectResponse(url="/admin/tools?msg=Confirmación+inválida", status_code=302)

    def _fn(conn):
        cur = conn.cursor()
        # web tables
        for table in ("accounts", "tickets", "notifications", "signup_pins"):
            try:
                cur.execute(f"DELETE FROM {table}")
            except Exception:
                pass

        # bot tables (optional)
        for table in ("requests", "proxies", "users"):
            try:
                cur.execute(f"DELETE FROM {table}")
            except Exception:
                pass

        # reset stock
        cur.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            ("stock_available", "0", now_str()),
        )

    db_exec(_fn)
    admin_log("wipe_all", "RESET")
    return RedirectResponse(url="/admin/tools?msg=Reset+completado", status_code=302)


# =========================
# ADMIN ORDERS
# =========================
@app.get("/admin/orders", response_class=HTMLResponse)
def admin_orders(admin=Depends(require_admin), state: str = ""):
    def _fn(conn):
        cur = conn.cursor()
        where = ""
        params: Tuple[Any, ...] = ()
        if (state or "").strip():
            where = "WHERE estado=?"
            params = ((state or "").strip(),)
        cur.execute(
            f"""
            SELECT id, user_id, tipo, ip, cantidad, monto, estado, created_at,
                   voucher_path, voucher_uploaded_at, email, currency, target_proxy_id, note
            FROM requests
            {where}
            ORDER BY id DESC
            LIMIT 160
            """,
            params,
        )
        return cur.fetchall()

    try:
        rows = db_exec(_fn)
    except Exception:
        rows = []

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
        voucher_link = (
            f"<a class='btn ghost' href='/static/{html_escape(voucher_path)}' target='_blank'>🧾 Ver voucher</a>"
            if voucher_path
            else "<span class='muted'>Sin voucher</span>"
        )

        extra = ""
        if (r["tipo"] or "") == "renew" and int(r["target_proxy_id"] or 0) > 0:
            extra = f"<div class='muted'>Proxy a renovar: <b>#{int(r['target_proxy_id'])}</b></div>"

        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Pedido <b>#{rid}</b> • Estado: <b>{html_escape(r["estado"] or "")}</b></div>
          <div style="height:8px;"></div>
          <div class="muted">
            User: <b>{int(r["user_id"])}</b> • Tipo: <b>{html_escape(r["tipo"] or "")}</b>
            • Qty: <b>{int(r["cantidad"] or 1)}</b>
            • Monto: <b>{int(r["monto"] or 0)} {html_escape(r["currency"] or "DOP")}</b>
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
        cards = "<div class='card'><p class='muted'>No hay pedidos en este filtro.</p></div>"

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
    return page("Admin • Pedidos", body, subtitle="Aprobar / Rechazar")


@app.post("/admin/order/{rid}/approve")
def admin_order_approve(rid: int, admin=Depends(require_admin)):
    stock = int(float(get_setting("stock_available", "0") or 0))

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, tipo, cantidad FROM requests WHERE id=?", (int(rid),))
        req = cur.fetchone()
        if not req:
            raise HTTPException(404, "Pedido no encontrado")

        tipo = (req["tipo"] or "").strip()
        uid = int(req["user_id"])
        qty = max(1, int(req["cantidad"] or 1))

        nonlocal stock
        if tipo == "buy":
            if stock < qty:
                raise HTTPException(400, f"Stock insuficiente. Disponible: {stock}")
            stock -= qty
            cur.execute("UPDATE requests SET estado=? WHERE id=?", ("approved", int(rid)))
            notify_user(uid, f"✅ Pedido #{rid} aprobado. Compra: {qty} proxy(s).")
        else:
            cur.execute("UPDATE requests SET estado=? WHERE id=?", ("approved", int(rid)))
            notify_user(uid, f"✅ Pedido #{rid} aprobado.")

        cur.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            ("stock_available", str(stock), now_str()),
        )

    db_exec(_fn)
    admin_log("order_approve", json.dumps({"rid": rid}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


@app.post("/admin/order/{rid}/reject")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, user_id FROM requests WHERE id=?", (int(rid),))
        req = cur.fetchone()
        if not req:
            raise HTTPException(404, "Pedido no encontrado")
        cur.execute("UPDATE requests SET estado=? WHERE id=?", ("rejected", int(rid)))
        notify_user(int(req["user_id"]), f"❌ Tu pedido #{rid} fue rechazado. Contacta soporte si necesitas ayuda.")

    db_exec(_fn)
    admin_log("order_reject", json.dumps({"rid": rid}, ensure_ascii=False))
    return RedirectResponse(url="/admin/orders", status_code=302)


# =========================
# ADMIN TICKETS
# =========================
@app.get("/admin/tickets", response_class=HTMLResponse)
def admin_tickets(admin=Depends(require_admin), state: str = "open"):
    state = (state or "open").strip()

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "SELECT id,user_id,subject,message,admin_reply,status,created_at,updated_at "
            "FROM tickets WHERE status=? ORDER BY id DESC LIMIT 160",
            (state,),
        )
        return cur.fetchall()

    rows = db_exec(_fn)

    cards = ""
    for t in rows:
        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Ticket <b>#{t['id']}</b> • Usuario <b>{t['user_id']}</b> • Estado: <b>{html_escape(t['status'])}</b></div>
          <div style="height:8px;"></div>
          <div><b>{html_escape(t['subject'] or 'Soporte')}</b></div>
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
      <h1>💬 Tickets</h1>
      <p>Responde y cierra tickets de soporte.</p>
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
    return page("Admin • Tickets", body, subtitle="Soporte")


@app.post("/admin/ticket/{tid}/reply")
def admin_ticket_reply(tid: int, reply: str = Form(""), action: str = Form("reply"), admin=Depends(require_admin)):
    reply = (reply or "").strip()

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id,user_id FROM tickets WHERE id=?", (int(tid),))
        t = cur.fetchone()
        if not t:
            raise HTTPException(404, "Ticket no encontrado")

        if action == "close":
            cur.execute("UPDATE tickets SET status='closed', updated_at=? WHERE id=?", (now_str(), int(tid)))
            notify_user(int(t["user_id"]), f"✅ Tu ticket #{tid} fue cerrado. Si necesitas más ayuda, abre otro.")
            return

        new_status = "answered" if reply else "open"
        cur.execute(
            "UPDATE tickets SET admin_reply=?, status=?, updated_at=? WHERE id=?",
            (reply, new_status, now_str(), int(tid)),
        )
        if reply:
            notify_user(int(t["user_id"]), f"💬 Soporte respondió tu ticket #{tid}. Entra a Soporte para verlo.")

    db_exec(_fn)
    admin_log("ticket_reply", json.dumps({"tid": tid}, ensure_ascii=False))
    return RedirectResponse(url="/admin/tickets?state=open", status_code=302)


# =========================
# CLIENT SIGNUP / LOGIN / RECOVERY
# =========================
@app.get("/client/signup", response_class=HTMLResponse)
def client_signup_page(msg: str = ""):
    body = f"""
    <div class="grid">
      <div class="card hero">
        <h1>Crear cuenta</h1>
        <p>Regístrate con <b>Teléfono + Contraseña</b> y define un <b>PIN de recuperación</b>.</p>
        <div class="hr"></div>
        <div class="pill">📱 Teléfono</div>
        <div class="pill" style="margin-left:8px;">🔒 Contraseña</div>
        <div class="pill" style="margin-left:8px;">🧷 PIN recuperación</div>
      </div>

      <div class="card">
        {toast(msg, "bad") if msg else ""}
        <form method="post" action="/client/signup">
          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..." />
          <div style="height:12px;"></div>

          <label class="muted">Contraseña (mín 6)</label>
          <input name="password" type="password" placeholder="••••••" />
          <div style="height:12px;"></div>

          <label class="muted">PIN de recuperación (4-6 dígitos)</label>
          <input name="recovery_pin" placeholder="Ej: 1234" />
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Crear cuenta</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>

        <div class="hr"></div>
        <p class="muted">Ya tienes cuenta? <a href="/client/login" style="color:white;">Inicia sesión</a></p>
      </div>
    </div>
    """
    return page("Cliente • Crear cuenta", body, subtitle="Registro seguro")


@app.post("/client/signup", response_class=HTMLResponse)
def client_signup(
    phone: str = Form(""),
    password: str = Form(""),
    recovery_pin: str = Form(""),
):
    phone = (phone or "").strip()
    password = (password or "").strip()
    recovery_pin = (recovery_pin or "").strip()

    if not phone or len(phone) < 8:
        return RedirectResponse(url="/client/signup?msg=Teléfono+inválido", status_code=302)
    if not password or len(password) < 6:
        return RedirectResponse(url="/client/signup?msg=Contraseña+muy+corta", status_code=302)
    if not recovery_pin.isdigit() or not (4 <= len(recovery_pin) <= 6):
        return RedirectResponse(url="/client/signup?msg=PIN+de+recuperación+inválido", status_code=302)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id FROM accounts WHERE phone=?", (phone,))
        if cur.fetchone():
            raise HTTPException(400, "Ese teléfono ya existe.")

        pwd_hash = password_make_hash(password)
        rec_hash = pin_hash(recovery_pin, PIN_SECRET)
        cur.execute(
            "INSERT INTO accounts(phone,password_hash,verified,recovery_pin_hash,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (phone, pwd_hash, 0, rec_hash, now_str(), now_str()),
        )

        pin = _pin_gen()
        exp = _time_plus_minutes(5)
        cur.execute(
            "INSERT INTO signup_pins(phone,pin_hash,expires_at,attempts,estado,created_at) VALUES(?,?,?,?,?,?)",
            (phone, pin_hash(pin, PIN_SECRET), exp, 0, "pending", now_str()),
        )
        return pin, exp

    try:
        pin, exp = db_exec(_fn)
    except HTTPException:
        return RedirectResponse(url="/client/signup?msg=Ese+teléfono+ya+existe", status_code=302)

    body = f"""
    <div class="card hero">
      <h1>✅ Cuenta creada</h1>
      <p>Confirma tu cuenta con este PIN (se muestra una sola vez).</p>
    </div>

    <div class="card">
      <div class="muted">PIN verificación</div>
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
    return page("Cliente • Verificación", body, subtitle="Confirmar cuenta")


@app.post("/client/verify", response_class=HTMLResponse)
def client_verify(phone: str = Form(""), pin: str = Form("")):
    phone = (phone or "").strip()
    pin = (pin or "").strip()

    if not phone or not pin:
        return HTMLResponse(pretty_error_page("Verificación", "Completa el teléfono y el PIN.", back_href="/client/signup"), status_code=400)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, pin_hash, expires_at, attempts
            FROM signup_pins
            WHERE phone=? AND estado='pending'
            ORDER BY id DESC
            LIMIT 1
            """,
            (phone,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "No hay un PIN activo para ese teléfono.")

        pid = int(row["id"])
        exp = row["expires_at"] or ""
        attempts = int(row["attempts"] or 0)

        try:
            exp_ts = time.mktime(time.strptime(exp, "%Y-%m-%d %H:%M:%S"))
            if time.time() > exp_ts:
                cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
                raise HTTPException(400, "PIN expirado.")
        except HTTPException:
            raise

        given = pin_hash(pin, PIN_SECRET)
        good = (row["pin_hash"] or "").strip()
        if not hmac.compare_digest(good, given):
            attempts += 1
            cur.execute("UPDATE signup_pins SET attempts=? WHERE id=?", (attempts, pid))
            if attempts >= 3:
                cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
            raise HTTPException(400, "PIN incorrecto.")

        cur.execute("UPDATE signup_pins SET estado='done' WHERE id=?", (pid,))
        cur.execute("UPDATE accounts SET verified=1, updated_at=? WHERE phone=?", (now_str(), phone))

    try:
        db_exec(_fn)
    except HTTPException as e:
        return HTMLResponse(pretty_error_page("Verificación", str(e.detail), back_href="/client/signup"), status_code=400)

    body = """
    <div class="card hero">
      <h1>✅ Cuenta verificada</h1>
      <p>Ya puedes iniciar sesión.</p>
      <div class="hr"></div>
      <a class="btn" href="/client/login">🔐 Iniciar sesión</a>
      <a class="btn ghost" href="/">🏠 Inicio</a>
    </div>
    """
    return page("Cliente • Verificado", body, subtitle="Listo")


@app.get("/client/login", response_class=HTMLResponse)
def client_login_page(msg: str = ""):
    body = f"""
    <div class="grid">
      <div class="card hero">
        <h1>Panel Cliente</h1>
        <p>Entra con tu <b>Teléfono + Contraseña</b>.</p>
        <div class="hr"></div>
        <div class="pill">📦 Proxies</div>
        <div class="pill" style="margin-left:8px;">🧾 Pedidos</div>
        <div class="pill" style="margin-left:8px;">💬 Soporte</div>
      </div>

      <div class="card">
        {toast(msg, "bad") if msg else ""}
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
          <a class="btn ghost" href="/client/forgot">🔁 Olvidé mi contraseña</a>
        </div>
      </div>
    </div>
    """
    return page("Cliente • Login", body, subtitle="Acceso seguro")


def account_verify_login(phone: str, password: str) -> Optional[int]:
    phone = (phone or "").strip()
    password = (password or "").strip()
    if not phone or not password:
        return None

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash, verified FROM accounts WHERE phone=?", (phone,))
        return cur.fetchone()

    row = db_exec(_fn)
    if not row:
        return None
    if int(row["verified"] or 0) != 1:
        return None
    if not password_check(password, (row["password_hash"] or "")):
        return None
    return int(row["id"])


@app.post("/client/login")
def client_login(request: Request, phone: str = Form(""), password: str = Form("")):
    uid = account_verify_login(phone, password)
    if not uid:
        return RedirectResponse(url="/client/login?msg=Login+inválido+o+cuenta+no+verificada", status_code=302)

    session = sign({"role": "client", "uid": int(uid)}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    set_cookie_smart(request, resp, "client_session", session, max_age=7 * 24 * 3600)
    return resp


@app.get("/client/forgot", response_class=HTMLResponse)
def client_forgot_page(msg: str = ""):
    body = f"""
    <div class="card hero">
      <h1>🔁 Recuperar contraseña</h1>
      <p>Usa tu <b>PIN de recuperación</b>.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/client/login">⬅️ Volver</a>
    </div>

    <div class="card">
      {toast(msg, "bad") if msg else ""}
      <form method="post" action="/client/forgot">
        <label class="muted">Teléfono</label>
        <input name="phone" placeholder="+1809..." />
        <div style="height:12px;"></div>

        <label class="muted">PIN recuperación</label>
        <input name="recovery_pin" placeholder="1234" />
        <div style="height:12px;"></div>

        <label class="muted">Nueva contraseña</label>
        <input name="new_password" type="password" placeholder="••••••" />
        <div style="height:12px;"></div>

        <button class="btn" type="submit">✅ Cambiar contraseña</button>
      </form>
    </div>
    """
    return page("Cliente • Recuperar", body, subtitle="Seguridad")


@app.post("/client/forgot")
def client_forgot(phone: str = Form(""), recovery_pin: str = Form(""), new_password: str = Form("")):
    phone = (phone or "").strip()
    recovery_pin = (recovery_pin or "").strip()
    new_password = (new_password or "").strip()

    if not phone or len(phone) < 8:
        return RedirectResponse(url="/client/forgot?msg=Teléfono+inválido", status_code=302)
    if not recovery_pin.isdigit() or not (4 <= len(recovery_pin) <= 6):
        return RedirectResponse(url="/client/forgot?msg=PIN+inválido", status_code=302)
    if len(new_password) < 6:
        return RedirectResponse(url="/client/forgot?msg=Contraseña+muy+corta", status_code=302)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, recovery_pin_hash FROM accounts WHERE phone=? AND verified=1", (phone,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "Cuenta no encontrada o no verificada.")

        good = (row["recovery_pin_hash"] or "").strip()
        given = pin_hash(recovery_pin, PIN_SECRET)
        if not good or not hmac.compare_digest(good, given):
            raise HTTPException(400, "PIN de recuperación incorrecto.")

        cur.execute(
            "UPDATE accounts SET password_hash=?, updated_at=? WHERE id=?",
            (password_make_hash(new_password), now_str(), int(row["id"])),
        )

    try:
        db_exec(_fn)
    except HTTPException as e:
        return RedirectResponse(url="/client/forgot?msg=" + str(e.detail).replace(" ", "+"), status_code=302)

    return RedirectResponse(url="/client/login?msg=Contraseña+actualizada", status_code=302)


@app.get("/logout")
def client_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("client_session")
    return resp


# =========================
# CLIENT: PANEL /ME (FIX "NO HACE NADA")
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

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND seen=0", (uid,))
        unread = int(cur.fetchone()[0])

        proxies_rows = []
        orders_rows = []
        try:
            cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,))
            proxies_rows = cur.fetchall()
        except Exception:
            proxies_rows = []

        try:
            cur.execute(
                "SELECT id, tipo, ip, cantidad, monto, estado, created_at, voucher_path, currency "
                "FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
                (uid,),
            )
            orders_rows = cur.fetchall()
        except Exception:
            orders_rows = []

        return unread, proxies_rows, orders_rows

    unread, proxies_rows, orders_rows = db_exec(_fn)

    # Proxies cards
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
            <a class="btn ghost" href="/renew">♻️ Renovar</a>
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
            f"<td>{int(r['cantidad'] or 1)}</td>"
            f"<td>{int(r['monto'] or 0)} {html_escape(r['currency'] or 'DOP')}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td><a class='btn ghost' href='/order/{int(r['id'])}/pay'>pago</a></td>"
            f"<td>{voucher_cell}</td>"
            "</tr>"
        )
    if not ohtml:
        ohtml = "<tr><td colspan='10' class='muted'>No hay pedidos</td></tr>"

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
        <tr><th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th><th>Pago</th><th>Voucher</th></tr>
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
          let diff = Math.floor((t - now)/1000);
          if (isNaN(diff)) {{ el.textContent='...'; return; }}
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
    return page("Cliente", body, subtitle="Tus proxies y pedidos")


# =========================
# CLIENT: NOTIFICATIONS
# =========================
@app.get("/notifications", response_class=HTMLResponse)
def client_notifications(client=Depends(require_client)):
    uid = int(client["uid"])

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id,message,seen,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 60", (uid,))
        rows = cur.fetchall()
        cur.execute("UPDATE notifications SET seen=1 WHERE user_id=?", (uid,))
        return rows

    rows = db_exec(_fn)

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
      <a class="btn ghost" href="/me">⬅️ Volver</a>
    </div>
    {items}
    """
    return page("Cliente • Notificaciones", body, subtitle="Actualizaciones")


# =========================
# CLIENT: PROXIES
# =========================
@app.get("/proxies", response_class=HTMLResponse)
def client_proxies(client=Depends(require_client)):
    uid = int(client["uid"])

    def _fn(conn):
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 200", (uid,))
            return cur.fetchall()
        except Exception:
            return []

    rows = db_exec(_fn)

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
# CLIENT: BANK
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
# CLIENT: BUY
# =========================
@app.get("/buy", response_class=HTMLResponse)
def client_buy_page(client=Depends(require_client), msg: str = ""):
    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")
    stock = int(float(get_setting("stock_available", "0") or 0))

    body = f"""
    <div class="card hero">
      <h1>🛒 Comprar proxy</h1>
      <p>Precio por proxy: <b>{p1} {html_escape(currency)}</b></p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/bank">🏦 Ver cuenta bancaria</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        {toast(msg, "bad") if msg else ""}
        <div class="muted">Stock disponible: <b>{stock}</b></div>
        <div style="height:10px;"></div>
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

    stock = int(float(get_setting("stock_available", "0") or 0))
    if stock <= 0:
        return RedirectResponse(url="/buy?msg=Sin+stock+por+ahora", status_code=302)

    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")
    monto = int(p1 * qty)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "buy", "-", qty, monto, "awaiting_voucher", now_str(), email, currency, 0, ""),
        )
        return cur.lastrowid

    rid = db_exec(_fn)
    notify_user(uid, f"🧾 Pedido #{rid} creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{rid}/pay", status_code=302)


# =========================
# CLIENT: RENEW
# =========================
@app.get("/renew", response_class=HTMLResponse)
def client_renew_page(client=Depends(require_client), msg: str = ""):
    pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")

    uid = int(client["uid"])

    def _fn(conn):
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, ip, vence FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 200", (uid,))
            return cur.fetchall()
        except Exception:
            return []

    rows = db_exec(_fn)

    opts = "<option value=''>Selecciona...</option>"
    for r in rows:
        opts += f"<option value='{int(r['id'])}'>#{int(r['id'])} • {html_escape(r['ip'] or '')} • vence {html_escape(r['vence'] or '')}</option>"

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
        {toast(msg, "bad") if msg else ""}
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
    proxy_id: str = Form(""),
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
        return RedirectResponse(url="/renew?msg=Proxy+inválido", status_code=302)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, ip FROM proxies WHERE id=? AND user_id=?", (pid, uid))
        p = cur.fetchone()
        if not p:
            raise HTTPException(400, "No encontré ese proxy en tu cuenta.")

        pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
        currency = get_setting("currency", "DOP")
        monto = int(pr)

        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "renew", p["ip"] or "-", 1, monto, "awaiting_voucher", now_str(), email, currency, pid, note),
        )
        return cur.lastrowid

    try:
        rid = db_exec(_fn)
    except HTTPException as e:
        return RedirectResponse(url="/renew?msg=" + str(e.detail).replace(" ", "+"), status_code=302)

    notify_user(uid, f"🧾 Pedido #{rid} (renovación) creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{rid}/pay", status_code=302)


# =========================
# CLIENT: ORDER PAY + UPLOAD VOUCHER
# =========================
@app.get("/order/{rid}/pay", response_class=HTMLResponse)
def client_order_pay(rid: int, client=Depends(require_client)):
    uid = int(client["uid"])
    bank = get_setting("bank_details", "")
    title = get_setting("bank_title", "Cuenta bancaria")

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "SELECT id,user_id,tipo,cantidad,monto,estado,created_at,voucher_path,email,currency,target_proxy_id "
            "FROM requests WHERE id=?",
            (int(rid),),
        )
        return cur.fetchone()

    r = db_exec(_fn)

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
          <label class="muted">Selecciona una imagen (jpg/png/webp)</label>
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

    # validar pedido
    def _chk(conn):
        cur = conn.cursor()
        cur.execute("SELECT id,user_id,estado FROM requests WHERE id=?", (int(rid),))
        return cur.fetchone()

    r = db_exec(_chk)
    if not r or int(r["user_id"]) != uid:
        raise HTTPException(404, "Pedido no encontrado.")

    ext = os.path.splitext(file.filename)[1].lower().strip()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
        ext = ".jpg"

    fname = f"rid{int(rid)}_u{uid}_{secrets.token_hex(8)}{ext}"
    rel_path = os.path.join("vouchers", fname)
    abs_path = os.path.join(UPLOAD_DIR, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    data = file.file.read()
    if not data or len(data) < 200:
        raise HTTPException(400, "Archivo inválido.")
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(400, "Imagen muy grande (máx 8MB).")

    with open(abs_path, "wb") as f:
        f.write(data)

    def _upd(conn):
        cur = conn.cursor()
        cur.execute(
            "UPDATE requests SET voucher_path=?, voucher_uploaded_at=?, estado=? WHERE id=?",
            (rel_path, now_str(), "voucher_received", int(rid)),
        )

    db_exec(_upd)
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
# SUPPORT (FAB works) - FIXED
# =========================
@app.get("/support", response_class=HTMLResponse)
def support_page(request: Request):
    client = client_optional(request)
    if not client:
        return RedirectResponse(url="/client/login?msg=Inicia+sesión+para+soporte", status_code=302)

    uid = int(client["uid"])

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "SELECT id,subject,message,admin_reply,status,created_at FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 10",
            (uid,),
        )
        return cur.fetchall()

    rows = db_exec(_fn)

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
      <p>Cuéntanos tu problema y te responderemos lo antes posible.</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/me">⬅️ Volver</a>
    </div>

    <div class="card">
      <form method="post" action="/support">
        <label class="muted">Asunto (opcional)</label>
        <input name="subject" placeholder="Ej: No puedo conectar" />
        <div style="height:12px;"></div>

        <label class="muted">Mensaje</label>
        <textarea name="message" placeholder="Escribe aquí..."></textarea>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">📨 Enviar</button>
      </form>
    </div>

    <h3 style="margin:18px 0 10px 0;">📜 Historial</h3>
    {hist}
    """
    return page("Soporte", body, subtitle=f"Cliente #{uid}")


@app.post("/support", response_class=HTMLResponse)
def support_submit(request: Request, subject: str = Form(""), message: str = Form("")):
    client = client_optional(request)
    if not client:
        return RedirectResponse(url="/client/login?msg=Inicia+sesión+para+soporte", status_code=302)

    uid = int(client["uid"])
    msg = (message or "").strip()
    subj = (subject or "").strip()

    if len(msg) < 5:
        return HTMLResponse(pretty_error_page("Soporte", "Escribe un mensaje más largo.", back_href="/support"), status_code=400)

    def _fn(conn):
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tickets(user_id,subject,message,admin_reply,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (uid, subj, msg, "", "open", now_str(), now_str()),
        )
        return cur.lastrowid

    tid = db_exec(_fn)
    notify_user(uid, f"💬 Ticket #{tid} creado. Un agente te responderá pronto.")
    admin_log("ticket_new", json.dumps({"tid": tid, "uid": uid}, ensure_ascii=False))

    body = f"""
    <div class="card hero">
      <h1>✅ Mensaje enviado</h1>
      <p>Tu ticket <b>#{tid}</b> fue creado.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/support">📜 Ver historial</a>
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
    </div>
    """
    return page("Soporte", body, subtitle="Listo")


# =========================
# API: maintenance/outbox
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

    def _fn(conn):
        cur = conn.cursor()
        cur.execute("SELECT id, kind, message, created_at, sent_at FROM outbox ORDER BY id DESC LIMIT 50")
        return [dict(r) for r in cur.fetchall()]

    rows = db_exec(_fn)
    return {"enabled": True, "items": rows}
