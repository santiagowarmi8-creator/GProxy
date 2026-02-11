# -*- coding: utf-8 -*-
# web.py — PARTE 1 (MEJORADA)
# ✅ Incluye: tablas extra (recordatorios / cola de emails), índices y helpers base
# ✅ NO rompe tu panel actual (todo es CREATE IF NOT EXISTS + migraciones seguras)

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles


# ====== CONFIG EMAIL ======
import smtplib
from email.message import EmailMessage

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", "").strip() or SMTP_USER

def send_email(to_email: str, subject: str, body: str):
    """
    Envío directo (sin cola). Útil para cosas puntuales.
    Para recordatorios y envíos masivos => usa email_job_add() (Parte 3 los dispara).
    """
    to_email = (to_email or "").strip()
    if not (SMTP_USER and SMTP_PASS and to_email):
        print("⚠️ Email no enviado: falta SMTP_USER/SMTP_PASS o destinatario vacío")
        return

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT), timeout=20) as s:
        s.ehlo()
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

    print(f"✅ Email enviado a {to_email} ({subject})")


def email_pro(subject: str, greeting: str, lines: list[str], footer_extra: str = "") -> tuple[str, str]:
    """
    Helper para emails más “profesionales” (texto plano).
    Devuelve (subject, body)
    """
    subj = (subject or "").strip()
    g = (greeting or "Hola,").strip()
    body_lines = [g, ""]
    for ln in lines or []:
        body_lines.append(str(ln))
    body_lines += [
        "",
        "Si necesitas ayuda, responde este correo o escribe por el chat del panel.",
        "",
        f"Atentamente,",
        f"{os.getenv('APP_TITLE','Gproxy')}",
    ]
    if footer_extra:
        body_lines += ["", str(footer_extra)]
    return subj, "\n".join(body_lines)


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
COOKIE_SAMESITE = (os.getenv("COOKIE_SAMESITE", "lax").strip() or "lax")

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
VOUCHER_DIR = os.path.join(UPLOAD_DIR, "vouchers")
INVOICE_DIR = os.path.join(UPLOAD_DIR, "invoices")

DEFAULT_DIAS_PROXY = 30

os.makedirs(VOUCHER_DIR, exist_ok=True)
os.makedirs(INVOICE_DIR, exist_ok=True)


def _normalize_samesite(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in ("lax", "strict", "none"):
        v = "lax"
    return v

COOKIE_SAMESITE = _normalize_samesite(COOKIE_SAMESITE)
if COOKIE_SAMESITE == "none":
    COOKIE_SECURE = True


# =========================
# APP
# =========================
app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory=UPLOAD_DIR), name="static")

CLIENT_SECRET: Optional[str] = None


# =========================
# Time helpers
# =========================
def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def day_floor(dt: datetime) -> datetime:
    return datetime(dt.year, dt.month, dt.day)

def parse_dt(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def _time_plus_minutes(minutes: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + minutes * 60))


# =========================
# DB (robusto)
# =========================
def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA busy_timeout=10000;")
        cur.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn

def _retry_sqlite(fn, tries: int = 7, base_sleep: float = 0.10):
    for i in range(tries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "locked" in msg or "busy" in msg:
                time.sleep(base_sleep * (2 ** i))
                continue
            raise
    raise sqlite3.OperationalError("database is locked (retries exceeded)")

def _ensure_column(conn: sqlite3.Connection, table: str, column: str, coldef: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = {row[1] for row in cur.fetchall()}
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")
        conn.commit()

def _ensure_table(conn: sqlite3.Connection, sql: str) -> None:
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()

def _ensure_index(conn: sqlite3.Connection, sql: str) -> None:
    # CREATE INDEX IF NOT EXISTS ...
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()


# =========================
# Settings helpers
# =========================
def get_setting(key: str, default: str = "") -> str:
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        conn.close()
        return (row["value"] if row else default) or default
    return _retry_sqlite(_do)

def set_setting(key: str, value: str):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_str()),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

def outbox_add(kind: str, message: str):
    if not ENABLE_OUTBOX:
        return
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO outbox(kind,message,created_at,sent_at) VALUES(?,?,?,?)",
            (kind, message or "", now_str(), ""),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

def admin_log(action: str, details: str = ""):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO admin_logs(action,details,created_at) VALUES(?,?,?)",
            (action, details or "", now_str()),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

def notify_user(user_id: int, message: str):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO notifications(user_id,message,seen,created_at) VALUES(?,?,?,?)",
            (int(user_id), message or "", 0, now_str()),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)


# =========================
# ✅ EMAIL JOBS (COLA LOCAL) + RECORDATORIOS
# - Sin VPS, sin cron: tu app (PC prendida) puede procesarlo con un loop (Parte 3)
# =========================
def email_job_add(kind: str, to_email: str, subject: str, body: str, send_at: str = ""):
    """
    Inserta un envío en cola.
    kind: "order_approved", "proxy_exp_7", "admin_custom", etc.
    send_at: "YYYY-MM-DD HH:MM:SS" (vacío = ahora)
    """
    to_email = (to_email or "").strip()
    if not to_email:
        return

    if not send_at:
        send_at = now_str()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO email_jobs(kind,to_email,subject,body,send_at,sent_at,attempts,last_error,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (kind or "", to_email, subject or "", body or "", send_at, "", 0, "", now_str()),
        )
        conn.commit()
        conn.close()

    _retry_sqlite(_do)

def email_job_mark_sent(job_id: int):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("UPDATE email_jobs SET sent_at=?, last_error='' WHERE id=?", (now_str(), int(job_id)))
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

def email_job_mark_fail(job_id: int, err: str):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE email_jobs SET attempts=COALESCE(attempts,0)+1, last_error=? WHERE id=?",
            ((err or "")[:500], int(job_id)),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)


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
    if not token:
        raise HTTPException(401, "No autorizado")
    t = (token or "").strip()
    if t.lower().startswith("bearer "):
        t = t.split(" ", 1)[1].strip()

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


# =========================
# Auth guards
# =========================
def require_admin(request: Request) -> Dict[str, Any]:
    tok = request.cookies.get("admin_session", "")
    payload = verify(tok, JWT_SECRET)
    if payload.get("role") != "admin":
        raise HTTPException(401, "No autorizado")
    return payload

def _account_is_blocked_and_touch_last_seen(uid: int) -> bool:
    def _do():
        conn = db_conn()
        cur = conn.cursor()

        blocked = 0
        try:
            cur.execute("SELECT is_blocked FROM accounts WHERE id=?", (int(uid),))
            row = cur.fetchone()
            if row is None:
                conn.close()
                return True
            blocked = int(row["is_blocked"] or 0)
        except Exception:
            blocked = 0

        try:
            cur.execute("UPDATE accounts SET last_seen=?, updated_at=? WHERE id=?", (now_str(), now_str(), int(uid)))
            conn.commit()
        except Exception:
            pass

        conn.close()
        return blocked == 1
    return _retry_sqlite(_do)

def require_client(request: Request) -> Dict[str, Any]:
    if not CLIENT_SECRET:
        raise HTTPException(503, "Servidor ocupado. Intenta de nuevo.")
    tok = request.cookies.get("client_session", "")
    payload = verify(tok, CLIENT_SECRET)
    if payload.get("role") != "client":
        raise HTTPException(401, "No autorizado")

    uid = int(payload.get("uid") or 0)
    if uid <= 0:
        raise HTTPException(401, "No autorizado")

    if _account_is_blocked_and_touch_last_seen(uid):
        raise HTTPException(403, "Tu cuenta está bloqueada. Contacta soporte.")

    return payload

def try_client(request: Request) -> Optional[Dict[str, Any]]:
    try:
        if not CLIENT_SECRET:
            return None
        tok = request.cookies.get("client_session", "")
        payload = verify(tok, CLIENT_SECRET)
        if payload.get("role") != "client":
            return None
        uid = int(payload.get("uid") or 0)
        if uid <= 0:
            return None
        if _account_is_blocked_and_touch_last_seen(uid):
            return None
        return payload
    except Exception:
        return None


# =========================
# Password hashing
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

def _pin_gen(n: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(n))


# =========================
# Schema / migrations (+ tablas de recordatorio + índices)
# =========================
def ensure_schema() -> str:
    conn = db_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.commit()

    try:
        _ensure_column(conn, "settings", "updated_at", "TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass

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

    # ✅ para recordatorios
    ins("reminders_enabled", "1")          # 1/0
    ins("reminders_days_before", "7")      # 7 días
    ins("reminders_hour", "09")            # 00-23 (hora local)
    ins("smtp_test_to", "")                # opcional

    _ensure_table(
        conn,
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            recovery_pin_hash TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'client',
            last_seen TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    for col, coldef in [
        ("email", "TEXT NOT NULL DEFAULT ''"),
        ("recovery_pin_hash", "TEXT NOT NULL DEFAULT ''"),
        ("verified", "INTEGER NOT NULL DEFAULT 0"),
        ("is_blocked", "INTEGER NOT NULL DEFAULT 0"),
        ("role", "TEXT NOT NULL DEFAULT 'client'"),
        ("last_seen", "TEXT NOT NULL DEFAULT ''"),
        ("created_at", "TEXT NOT NULL DEFAULT ''"),
        ("updated_at", "TEXT NOT NULL DEFAULT ''"),
    ]:
        try:
            _ensure_column(conn, "accounts", col, coldef)
        except Exception:
            pass

    _ensure_table(
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

    _ensure_table(
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

    _ensure_table(
        conn,
        """
        CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            seen INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    # ✅ chat (ya lo usas)
    _ensure_table(
        conn,
        """
        CREATE TABLE IF NOT EXISTS chat_messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sender TEXT NOT NULL DEFAULT 'user',
            message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            seen_by_admin INTEGER NOT NULL DEFAULT 0,
            seen_by_user INTEGER NOT NULL DEFAULT 0
        );
        """,
    )

    _ensure_table(
        conn,
        """
        CREATE TABLE IF NOT EXISTS admin_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    if ENABLE_OUTBOX:
        _ensure_table(
            conn,
            """
            CREATE TABLE IF NOT EXISTS outbox(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT NOT NULL DEFAULT ''
            );
            """,
        )

    # ✅ COLA DE EMAILS (para recordatorios + correos personalizados)
    _ensure_table(
        conn,
        """
        CREATE TABLE IF NOT EXISTS email_jobs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL DEFAULT '',
            to_email TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            send_at TEXT NOT NULL DEFAULT '',
            sent_at TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    # ✅ LOG DE RECORDATORIOS (evita mandar 7 días seguidos repetido al mismo proxy/día)
    _ensure_table(
        conn,
        """
        CREATE TABLE IF NOT EXISTS reminder_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            proxy_id INTEGER NOT NULL,
            days_left INTEGER NOT NULL,
            kind TEXT NOT NULL DEFAULT 'proxy_exp',
            sent_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ''
        );
        """,
    )

    # Secret persistente
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
            print("⚠️ CLIENT_SECRET no definido. Se generó uno y se guardó en DB.")

    global PIN_SECRET
    if not PIN_SECRET:
        PIN_SECRET = client_secret

    # Migraciones suaves si existen tablas del bot
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
        _ensure_column(conn, "proxies", "estado", "TEXT NOT NULL DEFAULT 'active'")
    except Exception:
        pass

    # ✅ ÍNDICES (mejoran rendimiento y evitan lentitud)
    try:
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_accounts_phone ON accounts(phone)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_accounts_role ON accounts(role)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_signup_pins_phone_state ON signup_pins(phone, estado)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_notifications_user_seen ON notifications(user_id, seen)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_tickets_user_status ON tickets(user_id, status)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_chat_user_created ON chat_messages(user_id, created_at)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_email_jobs_send ON email_jobs(sent_at, send_at)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_reminder_log_key ON reminder_log(user_id, proxy_id, days_left, kind)")
        # si existen:
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_proxies_user ON proxies(user_id)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_proxies_vence ON proxies(vence)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_requests_user ON requests(user_id)")
        _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_requests_estado ON requests(estado)")
    except Exception:
        pass

    conn.commit()
    conn.close()
    return client_secret


@app.on_event("startup")
def _startup():
    global CLIENT_SECRET
    CLIENT_SECRET = ensure_schema()


# =========================
# UI helpers
# =========================
def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _support_fab_html() -> str:
    return """<a href="/support" class="support-fab">💬</a>"""

def _normalize_phone(phone: str) -> str:
    p = (phone or "").strip()
    if not p:
        return ""
    if p.startswith("00"):
        p = "+" + p[2:]
    out = []
    for ch in p:
        if ch.isdigit():
            out.append(ch)
        elif ch == "+" and not out:
            out.append(ch)
    if out == ["+"]:
        return ""
    return "".join(out)

def page(title: str, body: str, subtitle: str = "") -> str:
    t = html_escape(title)
    st = html_escape(subtitle)
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
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
    body {{
      margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
      color:var(--text);
      background:
        radial-gradient(1200px 500px at 10% 10%, rgba(196,0,255,.25), transparent 60%),
        radial-gradient(1000px 600px at 90% 20%, rgba(0,212,255,.18), transparent 55%),
        radial-gradient(900px 700px at 40% 90%, rgba(123,0,255,.18), transparent 60%),
        linear-gradient(135deg, var(--bg1), var(--bg2), var(--bg3));
      min-height:100vh; overflow-x:hidden;
    }}
    .noise {{
      position:fixed; inset:0; pointer-events:none; opacity:.06;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='.6'/%3E%3C/svg%3E");
    }}
    .wrap {{max-width:1100px; margin:0 auto; padding:28px 18px 70px}}
    .topbar {{display:flex; justify-content:space-between; align-items:center; gap:14px; margin-bottom:14px}}
    .brand {{display:flex; align-items:center; gap:12px}}
    .logo {{
      width:44px; height:44px; border-radius:14px;
      background:linear-gradient(45deg,var(--p1),var(--p2));
      box-shadow:0 0 30px rgba(196,0,255,.35);
      display:flex; align-items:center; justify-content:center;
      position:relative; overflow:hidden;
    }}
    .logo:before {{
      content:""; position:absolute; inset:-40%;
      background:conic-gradient(from 180deg, rgba(255,255,255,.0), rgba(255,255,255,.35), rgba(255,255,255,.0));
      animation:spin 4s linear infinite;
    }}
    .logo span {{position:relative; font-weight:900; letter-spacing:.5px}}
    @keyframes spin {{to{{transform:rotate(360deg)}}}}
    .title {{font-size:18px; font-weight:800; margin:0}}
    .subtitle {{margin:0; color:var(--muted); font-size:13px}}
    .chip {{
      display:inline-flex; align-items:center; gap:8px;
      padding:10px 12px; border-radius:999px;
      background:rgba(255,255,255,.06); border:1px solid var(--border);
      box-shadow:var(--shadow); white-space:nowrap;
    }}
    .grid {{display:grid; grid-template-columns:1.4fr .9fr; gap:16px}}
    @media (max-width:980px){{.grid{{grid-template-columns:1fr}}}}
    .card {{
      background:var(--card); border:1px solid var(--border);
      border-radius:20px; padding:18px; box-shadow:var(--shadow);
      backdrop-filter:blur(14px);
      animation:pop .25s ease both;
    }}
    @keyframes pop{{from{{transform:translateY(6px);opacity:0}}to{{transform:translateY(0);opacity:1}}}}
    .row{{display:flex; gap:12px; flex-wrap:wrap; align-items:center}}
    .btn {{
      appearance:none; border:none; border-radius:14px;
      padding:12px 16px; font-weight:800; color:white;
      text-decoration:none; cursor:pointer;
      background:linear-gradient(45deg,var(--p1),var(--p2));
      box-shadow:0 12px 30px rgba(123,0,255,.22);
      transition: transform .12s ease, filter .12s ease, box-shadow .12s ease;
      display:inline-flex; align-items:center; gap:10px;
      position:relative; overflow:hidden;
    }}
    .btn:hover{{transform:translateY(-2px); filter:brightness(1.04); box-shadow:0 16px 38px rgba(196,0,255,.30)}}
    .btn:active{{transform:translateY(0px) scale(.98)}}
    .btn.ghost{{background:rgba(255,255,255,.06); border:1px solid var(--border); box-shadow:none}}
    .btn.bad{{background:linear-gradient(45deg,#ff2b6a,#ff7a2b); box-shadow:0 12px 30px rgba(255,43,106,.20)}}
    .kpi {{
      font-size:34px; font-weight:900; margin-top:6px;
      background:linear-gradient(90deg,#fff,#e9dbff,#b9f2ff);
      -webkit-background-clip:text; background-clip:text; color:transparent;
    }}
    .muted{{color:var(--muted); font-size:13px}}
    .hr{{height:1px; background:linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent); margin:14px 0}}
    input,textarea,select {{
      width:100%; padding:12px 14px; border-radius:14px;
      border:1px solid rgba(255,255,255,.10);
      background:rgba(0,0,0,.20); color:white; outline:none;
    }}
    textarea{{min-height:120px; max-width:100%}}
    table{{width:100%; border-collapse:collapse; overflow:hidden; border-radius:14px; display:block; overflow-x:auto}}
    th,td{{border-bottom:1px solid rgba(255,255,255,.10); padding:12px; text-align:left; font-size:13px; vertical-align:top; max-width:420px; word-break:break-word}}
    th{{color:#f0eaff; font-weight:900}}
    pre,code{{background:rgba(0,0,0,.25); border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:12px; overflow:auto; max-width:100%}}
    pre{{white-space:pre-wrap; word-break:break-word}}

    td form {{ max-width: 520px; }}

    .pill{{display:inline-flex; gap:8px; padding:8px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.10); background:rgba(0,0,0,.18); font-size:12px}}
    .pinbox{{border:1px dashed rgba(255,255,255,.22); background:rgba(0,0,0,.18); border-radius:18px; padding:14px}}
    .badge{{display:inline-flex; align-items:center; justify-content:center; min-width:22px; height:22px; padding:0 8px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.14); font-size:12px; font-weight:900; color:white}}

    .support-fab {{
      position: fixed; right: 18px; bottom: 18px;
      width: 58px; height: 58px; border-radius: 50%;
      display:flex; align-items:center; justify-content:center;
      text-decoration:none; font-size: 26px;
      background: linear-gradient(45deg, var(--p3), var(--p2));
      box-shadow: 0 16px 40px rgba(0,212,255,.25);
      border: 1px solid rgba(255,255,255,.16);
      z-index: 9999;
      transition: transform .12s ease, filter .12s ease;
    }}
    .support-fab:hover {{ transform: translateY(-2px); filter: brightness(1.05); }}
    .support-fab:active {{ transform: translateY(0px) scale(.98); }}
    textarea {{ max-width:100%; }}

    /* ===== FIX TABLAS MOBILE ===== */
    table {{
      display: block;
      overflow-x: auto;
      width: 100%;
    }}
    th, td {{
      white-space: nowrap;
    }}
    @media (max-width: 600px) {{
      th, td {{
        font-size: 12px;
        padding: 10px;
      }}
    }}
  </style>
</head>
<body>
  <div class="noise"></div>
  <div class="wrap">
    <div class="topbar">
      <a href="/" class="brand" style="text-decoration:none; color:inherit;">
        <div class="logo"><span>G</span></div>
        <div>
          <p class="title">GProxy</p>
          <p class="subtitle">{st}</p>
        </div>
      </a>
      <div class="chip">🛡️ Proxies USA • Privadas • Estables</div>
    </div>

    {body}

    {_support_fab_html()}

    <div class="muted" style="text-align:center; margin-top:16px;">© {html_escape(APP_TITLE)} • Web Panel</div>
  </div>
</body>
</html>"""

def nice_error_page(title: str, msg: str, back_href: str = "/", back_label: str = "🏠 Inicio") -> HTMLResponse:
    body = f"""
    <div class="card">
      <div class="kpi">{html_escape(title)}</div>
      <p class="muted">{html_escape(msg)}</p>
      <div class="hr"></div>
      <a class="btn" href="{html_escape(back_href)}">{html_escape(back_label)}</a>
    </div>
    """
    return HTMLResponse(page(title, body, subtitle=""), status_code=200)


# =========================
# Global error handlers
# =========================
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept and "text/html" not in accept:
        return HTMLResponse(content=json.dumps({"detail": exc.detail}), status_code=exc.status_code)

    if exc.status_code in (401, 403):
        return nice_error_page("Acceso restringido", "Necesitas iniciar sesión para continuar.", "/client/login", "🔐 Iniciar sesión")
    if exc.status_code == 404:
        return nice_error_page("No encontrado", "La página que buscas no existe.", "/", "🏠 Inicio")
    if exc.status_code == 503:
        return nice_error_page("Servidor ocupado", "Estamos iniciando o el servidor está ocupado. Intenta de nuevo.", "/", "🔄 Reintentar")
    return nice_error_page("Ups", str(exc.detail or "Ocurrió un error."), "/", "🏠 Inicio")

@app.exception_handler(Exception)
async def unhandled_exc_handler(request: Request, exc: Exception):
    return nice_error_page("Ocurrió un error interno", "Intenta de nuevo. Si continúa, contacta soporte.", "/", "🏠 Inicio")


# =========================
# HOME
# =========================
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")
    status = "🟠 Mantenimiento" if maint else "🟢 Online"

    c = try_client(request)
    me_btn = "<a class='btn' href='/me'>👤 Mi panel</a>" if c else "<a class='btn ghost' href='/client/login'>👤 Clientes</a>"

    body = f"""
    <div class="grid">
      <div class="card">
        <div class="pill">⚡ Premium Panel</div>
        <div class="pill" style="margin-left:8px;">🔒 Seguro</div>
        <div class="pill" style="margin-left:8px;">💬 Tickets</div>
        <div style="height:12px;"></div>

        <div class="kpi">{html_escape(APP_TITLE)}</div>
        <p class="muted">Compra, renueva, sube voucher y gestiona soporte desde aquí.</p>
        <div class="hr"></div>

        <div class="row">
          <a class="btn" href="/admin/login">🔐 Admin</a>
          {me_btn}
          <a class="btn ghost" href="/client/signup">✨ Crear cuenta</a>
          <a class="btn ghost" href="/support">💬 Soporte</a>
        </div>
      </div>

      <div class="card">
        <div class="muted">Estado del sistema</div>
        <div class="kpi">{status}</div>
        <div class="hr"></div>
        <pre>{html_escape(mtxt) if maint else "Todo funcionando perfecto."}</pre>
      </div>
    </div>
    """
    return page(APP_TITLE, body, subtitle="Premium Panel • Admin & Cliente")


@app.get("/health")
def health():
    return {"ok": True, "time": now_str(), "db": DB_PATH, "client_secret_loaded": bool(CLIENT_SECRET)}

@app.get("/admin/debug/email")
def debug_email(admin=Depends(require_admin)):
    return {
        "SMTP_HOST": SMTP_HOST,
        "SMTP_PORT": SMTP_PORT,
        "SMTP_USER_set": bool(SMTP_USER),
        "SMTP_PASS_set": bool(SMTP_PASS),
        "SMTP_FROM": SMTP_FROM,
    }


# =========================
# ADMIN AUTH
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
@app.get("/admin/login/", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <div class="grid">
      <div class="card">
        <div class="kpi">Admin Access</div>
        <p class="muted">Control total: usuarios, pedidos, soporte, ajustes y limpieza.</p>
      </div>
      <div class="card">
        <form method="post" action="/admin/login">
          <label class="muted">Clave Admin</label>
          <input type="password" name="password" placeholder="Tu clave admin"/>
          <div style="height:12px;"></div>
          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/" style="margin-left:10px;">🏠 Inicio</a>
        </form>
      </div>
    </div>
    """
    return page("Admin Login", body, subtitle="Ingreso seguro")


@app.post("/admin/login")
@app.post("/admin/login/")
def admin_login(password: str = Form(...)):
    if not ADMIN_PASSWORD:
        raise HTTPException(500, "Falta ADMIN_PASSWORD en variables.")
    if (password or "").strip() != ADMIN_PASSWORD:
        return nice_error_page(
            "Clave incorrecta",
            "La clave admin no es válida.",
            "/admin/login",
            "↩️ Intentar de nuevo",
        )

    token = sign({"role": "admin"}, JWT_SECRET, exp_seconds=8 * 3600)
    resp = RedirectResponse(url="/admin", status_code=302)
    resp.set_cookie(
        "admin_session",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )
    return resp


@app.get("/admin/logout")
@app.get("/admin/logout/")
def admin_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("admin_session")
    return resp


# =========================
# ADMIN DASHBOARD
# =========================
@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
def admin_dashboard(admin=Depends(require_admin)):
    def count(sql: str) -> int:
        def _do():
            conn = db_conn()
            cur = conn.cursor()
            try:
                cur.execute(sql)
                v = int(cur.fetchone()[0])
            except Exception:
                v = 0
            conn.close()
            return v
        return _retry_sqlite(_do)

    accounts = count("SELECT COUNT(*) FROM accounts")
    proxies = count("SELECT COUNT(*) FROM proxies")
    pending = count("SELECT COUNT(*) FROM requests WHERE estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')")
    tickets = count("SELECT COUNT(*) FROM tickets WHERE status='open'")
    stock = int(float(get_setting("stock_available", "0") or 0))

    maint = get_setting("maintenance_enabled", "0") == "1"
    mtxt = get_setting("maintenance_message", "")

    body = f"""
    <div class="card">
      <div class="kpi">Admin Dashboard</div>
      <p class="muted">Panel premium. Todo lo importante aquí.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="/admin/accounts">👥 Usuarios</a>
        <a class="btn" href="/admin/orders">📨 Pedidos <span class="badge">{pending}</span></a>
        <a class="btn" href="/admin/proxies">📦 Proxies</a>
        <a class="btn" href="/admin/tickets">💬 Tickets <span class="badge">{tickets}</span></a>
        <a class="btn" href="/admin/settings">⚙️ Banco/Precios</a>
        <a class="btn" href="/admin/stock">🧰 Stock <span class="badge">{stock}</span></a>
        <a class="btn ghost" href="/admin/chat">💬 Chat</a>
        <a class="btn bad" href="/admin/reset">🧹 Reset/Limpieza</a>
        <a class="btn ghost" href="/admin/logout" style="margin-left:auto;">🚪 Salir</a>
      </div>
    </div>

    <div class="row">
      <div class="card" style="flex:1; min-width:220px;">
        <div class="muted">Usuarios</div>
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
        <div class="muted">Stock disponible</div>
        <div class="kpi">{stock}</div>
      </div>
    </div>

    <div class="card">
      <div class="muted">Mantenimiento</div>
      <div class="kpi">{'🟠 ON' if maint else '🟢 OFF'}</div>
      <p class="muted">{html_escape(mtxt)}</p>
      <div class="hr"></div>
      <a class="btn ghost" href="/admin/maintenance">🛠 Configurar mantenimiento</a>
    </div>
    """
    return page("Admin", body, subtitle="Panel premium")

# =========================
# ADMIN SETTINGS / STOCK / MAINTENANCE / RESET
# =========================
@app.get("/admin/settings", response_class=HTMLResponse)
@app.get("/admin/settings/", response_class=HTMLResponse)
def admin_settings_page(admin=Depends(require_admin)):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")
    precio_primera = get_setting("precio_primera", "1500")
    precio_renov = get_setting("precio_renovacion", "1000")
    dias_proxy = get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY))
    currency = get_setting("currency", "DOP")

    # recordatorios
    reminders_enabled = get_setting("reminders_enabled", "1")
    reminders_days_before = get_setting("reminders_days_before", "7")
    reminders_hour = get_setting("reminders_hour", "09")

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>

      <form method="post" action="/admin/settings">
        <h3 style="margin:0 0 10px 0;">🏦 Cuenta bancaria</h3>
        <label class="muted">Título</label>
        <input name="bank_title" value="{html_escape(title)}"/>
        <div style="height:12px;"></div>
        <label class="muted">Detalles</label>
        <textarea name="bank_details">{html_escape(details)}</textarea>

        <div class="hr"></div>
        <h3 style="margin:0 0 10px 0;">💰 Precios</h3>
        <label class="muted">Moneda</label>
        <input name="currency" value="{html_escape(currency)}"/>

        <div style="height:12px;"></div>
        <label class="muted">Primera compra</label>
        <input name="precio_primera" value="{html_escape(precio_primera)}"/>

        <div style="height:12px;"></div>
        <label class="muted">Renovación</label>
        <input name="precio_renovacion" value="{html_escape(precio_renov)}"/>

        <div style="height:12px;"></div>
        <label class="muted">Duración (máx 30 días)</label>
        <input name="dias_proxy" value="{html_escape(dias_proxy)}"/>

        <div class="hr"></div>
        <h3 style="margin:0 0 10px 0;">📩 Recordatorios por email</h3>
        <label class="muted">Activar (1 = sí, 0 = no)</label>
        <input name="reminders_enabled" value="{html_escape(reminders_enabled)}"/>

        <div style="height:12px;"></div>
        <label class="muted">Días antes (ej: 7)</label>
        <input name="reminders_days_before" value="{html_escape(reminders_days_before)}"/>

        <div style="height:12px;"></div>
        <label class="muted">Hora de envío (00-23)</label>
        <input name="reminders_hour" value="{html_escape(reminders_hour)}"/>

        <div style="height:12px;"></div>
        <button class="btn" type="submit">💾 Guardar</button>
      </form>
    </div>
    """
    return page("Admin • Settings", body, subtitle="Configurar")


@app.post("/admin/settings")
@app.post("/admin/settings/")
def admin_settings_save(
    bank_title: str = Form("Cuenta bancaria"),
    bank_details: str = Form(""),
    currency: str = Form("DOP"),
    precio_primera: str = Form("1500"),
    precio_renovacion: str = Form("1000"),
    dias_proxy: str = Form(str(DEFAULT_DIAS_PROXY)),
    reminders_enabled: str = Form("1"),
    reminders_days_before: str = Form("7"),
    reminders_hour: str = Form("09"),
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

    # recordatorios
    re = "1" if (reminders_enabled or "").strip() == "1" else "0"
    rdb = to_int(reminders_days_before, 7)
    if rdb <= 0:
        rdb = 7
    if rdb > 30:
        rdb = 30
    rh = (reminders_hour or "09").strip()
    if not rh.isdigit():
        rh = "09"
    rh_i = int(rh)
    if rh_i < 0:
        rh_i = 0
    if rh_i > 23:
        rh_i = 23
    rh = str(rh_i).zfill(2)

    set_setting("bank_title", (bank_title or "Cuenta bancaria").strip())
    set_setting("bank_details", (bank_details or "").strip())
    set_setting("currency", (currency or "DOP").strip() or "DOP")
    set_setting("precio_primera", str(p1))
    set_setting("precio_renovacion", str(pr))
    set_setting("dias_proxy", str(dp))

    set_setting("reminders_enabled", re)
    set_setting("reminders_days_before", str(rdb))
    set_setting("reminders_hour", rh)

    admin_log(
        "settings_update",
        json.dumps({"p1": p1, "pr": pr, "dias": dp, "reminders_enabled": re, "reminders_days_before": rdb, "reminders_hour": rh}, ensure_ascii=False),
    )
    return RedirectResponse(url="/admin/settings", status_code=302)


@app.get("/admin/stock", response_class=HTMLResponse)
@app.get("/admin/stock/", response_class=HTMLResponse)
def admin_stock_page(admin=Depends(require_admin)):
    stock = get_setting("stock_available", "0")
    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>

      <form method="post" action="/admin/stock">
        <label class="muted">Proxies disponibles</label>
        <input name="stock_available" value="{html_escape(stock)}" />
        <div style="height:12px;"></div>
        <button class="btn" type="submit">💾 Guardar stock</button>
      </form>
      <div class="hr"></div>
      <p class="muted">Contador simple. Baja cuando apruebas compras.</p>
    </div>
    """
    return page("Admin • Stock", body, subtitle="Inventario")


@app.post("/admin/stock")
@app.post("/admin/stock/")
def admin_stock_save(stock_available: str = Form("0"), admin=Depends(require_admin)):
    try:
        v = int(float((stock_available or "0").strip()))
        if v < 0:
            v = 0
    except Exception:
        v = 0
    set_setting("stock_available", str(v))
    admin_log("stock_set", json.dumps({"stock_available": v}, ensure_ascii=False))
    return RedirectResponse(url="/admin/stock", status_code=303)


@app.get("/admin/maintenance", response_class=HTMLResponse)
@app.get("/admin/maintenance/", response_class=HTMLResponse)
def admin_maintenance_page(admin=Depends(require_admin)):
    enabled = get_setting("maintenance_enabled", "0") == "1"
    msg = get_setting("maintenance_message", "")

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>

      <div class="muted">Estado actual</div>
      <div class="kpi">{'🟠 ON' if enabled else '🟢 OFF'}</div>
      <div class="hr"></div>

      <form method="post" action="/admin/maintenance">
        <label class="muted">Mensaje</label>
        <textarea name="message">{html_escape(msg)}</textarea>
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
@app.post("/admin/maintenance/")
def admin_maintenance_set(action: str = Form(...), message: str = Form(""), admin=Depends(require_admin)):
    msg = (message or "").strip() or "⚠️ Estamos en mantenimiento. Vuelve en unos minutos."
    set_setting("maintenance_message", msg)

    if action == "on":
        set_setting("maintenance_enabled", "1")
        outbox_add("maintenance_on", msg)
        admin_log("maintenance_on", msg)
    elif action == "off":
        set_setting("maintenance_enabled", "0")
        outbox_add("maintenance_off", msg)
        admin_log("maintenance_off", msg)

    return RedirectResponse(url="/admin/maintenance", status_code=302)


@app.get("/admin/reset", response_class=HTMLResponse)
@app.get("/admin/reset/", response_class=HTMLResponse)
def admin_reset_page(admin=Depends(require_admin)):
    body = """
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>

      <div class="kpi">🧹 Reset / Limpieza</div>
      <p class="muted">Esto borra datos del panel web. Úsalo con cuidado.</p>

      <div class="hr"></div>
      <form method="post" action="/admin/reset">
        <label><input type="checkbox" name="wipe_requests" value="1"/> Pedidos (requests)</label><br/>
        <label><input type="checkbox" name="wipe_tickets" value="1"/> Tickets</label><br/>
        <label><input type="checkbox" name="wipe_notifications" value="1"/> Notificaciones</label><br/>
        <label><input type="checkbox" name="wipe_stock" value="1"/> Stock (contador)</label><br/>
        <label><input type="checkbox" name="wipe_proxies" value="1"/> Proxies (PELIGROSO)</label><br/>
        <label><input type="checkbox" name="wipe_email_jobs" value="1"/> Cola de Emails</label><br/>
        <label><input type="checkbox" name="wipe_reminder_log" value="1"/> Log Recordatorios</label><br/>

        <div class="hr"></div>
        <label class="muted">Escribe: <b>CONFIRMAR</b></label>
        <input name="confirm" placeholder="CONFIRMAR"/>
        <div style="height:12px;"></div>
        <button class="btn bad" type="submit">🧨 Ejecutar limpieza</button>
      </form>
    </div>
    """
    return page("Admin • Reset", body, subtitle="Limpieza premium")


@app.post("/admin/reset")
@app.post("/admin/reset/")
def admin_reset_do(
    confirm: str = Form(""),
    wipe_requests: str = Form("0"),
    wipe_tickets: str = Form("0"),
    wipe_notifications: str = Form("0"),
    wipe_stock: str = Form("0"),
    wipe_proxies: str = Form("0"),
    wipe_email_jobs: str = Form("0"),
    wipe_reminder_log: str = Form("0"),
    admin=Depends(require_admin),
):
    if (confirm or "").strip().upper() != "CONFIRMAR":
        return nice_error_page("Confirmación requerida", "Para limpiar debes escribir CONFIRMAR.", "/admin/reset", "↩️ Volver")

    def _do():
        conn = db_conn()
        cur = conn.cursor()

        if wipe_requests == "1":
            try:
                cur.execute("DELETE FROM requests")
            except Exception:
                pass

        if wipe_tickets == "1":
            cur.execute("DELETE FROM tickets")

        if wipe_notifications == "1":
            cur.execute("DELETE FROM notifications")

        if wipe_stock == "1":
            cur.execute("UPDATE settings SET value=?, updated_at=? WHERE key='stock_available'", ("0", now_str()))

        if wipe_proxies == "1":
            try:
                cur.execute("DELETE FROM proxies")
            except Exception:
                pass

        if wipe_email_jobs == "1":
            try:
                cur.execute("DELETE FROM email_jobs")
            except Exception:
                pass

        if wipe_reminder_log == "1":
            try:
                cur.execute("DELETE FROM reminder_log")
            except Exception:
                pass

        conn.commit()
        conn.close()

    _retry_sqlite(_do)
    admin_log(
        "admin_reset",
        json.dumps(
            {
                "requests": wipe_requests == "1",
                "tickets": wipe_tickets == "1",
                "notifications": wipe_notifications == "1",
                "stock": wipe_stock == "1",
                "proxies": wipe_proxies == "1",
                "email_jobs": wipe_email_jobs == "1",
                "reminder_log": wipe_reminder_log == "1",
            },
            ensure_ascii=False,
        ),
    )

    return nice_error_page("Limpieza lista", "Se aplicó la limpieza seleccionada.", "/admin", "⬅️ Volver al Dashboard")

# =========================
# PARTE 2 (CORREGIDA + MEJORADA)
# - ✅ FIX 405 Method Not Allowed en “Crear cuenta”: agrega rutas con y sin “/”
# - ✅ Signup POST queda AQUÍ (y en Parte 3 NO debe existir duplicado)
# - ✅ Emails más “profesionales” (asunto + firma) para PIN/verificación
# - ✅ Pequeñas mejoras de validación y consistencia
# =========================


# =========================
# ADMIN: CREAR USUARIO + BORRAR USUARIO + HACER ADMIN
# =========================
@app.get("/admin/users/create", response_class=HTMLResponse)
@app.get("/admin/users/create/", response_class=HTMLResponse)
def admin_user_create_page(admin=Depends(require_admin)):
    body = """
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/accounts">⬅️ Usuarios</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>
      </div>
      <div class="hr"></div>

      <div class="kpi">➕ Crear usuario</div>
      <p class="muted">Crea un usuario desde el panel admin.</p>

      <div class="hr"></div>
      <form method="post" action="/admin/users/create">
        <label class="muted">Teléfono</label>
        <input name="phone" placeholder="+1809..." />
        <div style="height:12px;"></div>

        <label class="muted">Email (opcional)</label>
        <input name="email" placeholder="tuemail@gmail.com" />
        <div style="height:12px;"></div>

        <label class="muted">Contraseña (mín 6)</label>
        <input name="password" type="password" placeholder="••••••" />
        <div style="height:12px;"></div>

        <label class="muted">PIN recuperación (opcional 4-6 dígitos)</label>
        <input name="recovery_pin" placeholder="Ej: 1234" />
        <div style="height:12px;"></div>

        <label class="muted">Rol</label>
        <select name="role">
          <option value="client" selected>client</option>
          <option value="admin">admin</option>
        </select>
        <div style="height:12px;"></div>

        <label><input type="checkbox" name="verified" value="1" checked/> Verificado</label>
        <div style="height:12px;"></div>

        <button class="btn" type="submit">✅ Crear</button>
      </form>
    </div>
    """
    return page("Admin • Crear usuario", body, subtitle="Usuarios")


@app.post("/admin/users/create", response_class=HTMLResponse)
@app.post("/admin/users/create/", response_class=HTMLResponse)
def admin_user_create_submit(
    phone: str = Form(...),
    email: str = Form(""),
    password: str = Form(...),
    recovery_pin: str = Form(""),
    role: str = Form("client"),
    verified: str = Form("0"),
    admin=Depends(require_admin),
):
    phone_n = _normalize_phone(phone)
    if not phone_n:
        return nice_error_page("Datos inválidos", "Teléfono inválido.", "/admin/users/create", "↩️ Volver")

    role = (role or "client").strip().lower()
    if role not in ("client", "admin"):
        role = "client"

    ver = 1 if (verified or "") == "1" else 0
    email = (email or "").strip()

    rec_hash = ""
    rp = (recovery_pin or "").strip()
    if rp:
        if (not rp.isdigit()) or (len(rp) < 4 or len(rp) > 6):
            return nice_error_page("Datos inválidos", "PIN recuperación inválido (4-6 dígitos).", "/admin/users/create", "↩️ Volver")
        rec_hash = pin_hash(rp, PIN_SECRET)

    try:
        pwd_hash = password_make_hash(password)
    except HTTPException as e:
        return nice_error_page("Datos inválidos", str(e.detail), "/admin/users/create", "↩️ Volver")

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM accounts WHERE phone=?", (phone_n,))
        ex = cur.fetchone()
        if ex:
            conn.close()
            return ("exists", int(ex["id"]))

        cur.execute(
            "INSERT INTO accounts(phone,email,password_hash,recovery_pin_hash,verified,is_blocked,role,last_seen,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (phone_n, email, pwd_hash, rec_hash, ver, 0, role, "", now_str(), now_str()),
        )
        conn.commit()
        uid = int(cur.lastrowid)
        conn.close()
        return ("ok", uid)

    st, uid = _retry_sqlite(_do)
    if st == "exists":
        return nice_error_page("Ya existe", f"Ya existe un usuario con ese teléfono (ID {uid}).", f"/admin/user/{uid}", "👤 Ver usuario")

    admin_log("admin_user_create", json.dumps({"uid": uid, "phone": phone_n, "role": role, "verified": ver}, ensure_ascii=False))
    notify_user(uid, f"✅ Tu cuenta fue creada por el admin. Bienvenido a {APP_TITLE}.")
    return RedirectResponse(url=f"/admin/user/{uid}", status_code=302)


@app.post("/admin/user/{user_id}/toggle_role")
@app.post("/admin/user/{user_id}/toggle_role/")
def admin_user_toggle_role(user_id: int, admin=Depends(require_admin)):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, COALESCE(role,'client') AS role FROM accounts WHERE id=?", (int(user_id),))
        r = cur.fetchone()
        if not r:
            conn.close()
            raise HTTPException(404, "Usuario no encontrado")
        role = (r["role"] or "client").strip().lower()
        new_role = "admin" if role != "admin" else "client"
        cur.execute("UPDATE accounts SET role=?, updated_at=? WHERE id=?", (new_role, now_str(), int(user_id)))
        conn.commit()
        conn.close()
        return new_role

    new_role = _retry_sqlite(_do)
    admin_log("user_toggle_role", json.dumps({"user_id": user_id, "role": new_role}, ensure_ascii=False))
    notify_user(int(user_id), f"🔐 Tu rol cambió a: {new_role}")
    return RedirectResponse(url=f"/admin/user/{int(user_id)}", status_code=302)


@app.post("/admin/user/{user_id}/delete")
@app.post("/admin/user/{user_id}/delete/")
def admin_user_delete(user_id: int, admin=Depends(require_admin)):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, phone FROM accounts WHERE id=?", (int(user_id),))
        u = cur.fetchone()
        if not u:
            conn.close()
            raise HTTPException(404, "Usuario no encontrado")

        for sql in [
            ("DELETE FROM proxies WHERE user_id=?", (int(user_id),)),
            ("DELETE FROM tickets WHERE user_id=?", (int(user_id),)),
            ("DELETE FROM notifications WHERE user_id=?", (int(user_id),)),
            ("DELETE FROM chat_messages WHERE user_id=?", (int(user_id),)),
            ("DELETE FROM requests WHERE user_id=?", (int(user_id),)),
        ]:
            try:
                cur.execute(sql[0], sql[1])
            except Exception:
                pass

        cur.execute("DELETE FROM accounts WHERE id=?", (int(user_id),))
        conn.commit()
        conn.close()
        return (int(u["id"]), (u["phone"] or ""))

    uid, phone = _retry_sqlite(_do)
    admin_log("admin_user_delete", json.dumps({"user_id": uid, "phone": phone}, ensure_ascii=False))
    return RedirectResponse(url="/admin/accounts", status_code=302)


# =========================
# ADMIN: accounts
# =========================
@app.get("/admin/accounts", response_class=HTMLResponse)
@app.get("/admin/accounts/", response_class=HTMLResponse)
def admin_accounts(admin=Depends(require_admin), q: str = ""):
    q = (q or "").strip()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        if q:
            cur.execute(
                """
                SELECT id, phone,
                       COALESCE(email,'') AS email,
                       COALESCE(role,'client') AS role,
                       verified, created_at, updated_at,
                       COALESCE(is_blocked,0) AS is_blocked,
                       COALESCE(last_seen,'') AS last_seen
                FROM accounts
                WHERE CAST(id AS TEXT) LIKE ? OR phone LIKE ? OR email LIKE ?
                ORDER BY id DESC
                LIMIT 200
                """,
                (f"%{q}%", f"%{q}%", f"%{q}%"),
            )
        else:
            cur.execute(
                """
                SELECT id, phone,
                       COALESCE(email,'') AS email,
                       COALESCE(role,'client') AS role,
                       verified, created_at, updated_at,
                       COALESCE(is_blocked,0) AS is_blocked,
                       COALESCE(last_seen,'') AS last_seen
                FROM accounts
                ORDER BY id DESC
                LIMIT 200
                """
            )
        rows = cur.fetchall()
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    trs = ""
    for r in rows:
        uid = int(r["id"])
        verified = "✅ Verificado" if int(r["verified"] or 0) == 1 else "⏳ Sin verificar"
        blocked = "🚫 Bloqueado" if int(r["is_blocked"] or 0) == 1 else "✅ Activo"
        role = (r["role"] or "client").strip()

        trs += (
            "<tr>"
            f"<td><code>{uid}</code></td>"
            f"<td>{html_escape(r['phone'] or '')}</td>"
            f"<td>{html_escape(r['email'] or '')}</td>"
            f"<td>{html_escape(role)}</td>"
            f"<td>{verified}</td>"
            f"<td>{blocked}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{html_escape(r['updated_at'] or '')}</td>"
            f"<td><a class='btn ghost' href='/admin/user/{uid}'>Ver</a></td>"
            "</tr>"
        )

    body = f"""
    <div class="card hero">
      <h1>👥 Usuarios (Web)</h1>
      <p>Clientes registrados en el panel web.</p>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
        <a class="btn" href="/admin/users/create">➕ Crear usuario</a>
      </div>
    </div>

    <div class="card">
      <form method="get" action="/admin/accounts">
        <label class="muted">Buscar por ID / Teléfono / Email</label>
        <input name="q" value="{html_escape(q)}" placeholder="Ej: 1 o +1809... o gmail"/>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Buscar</button>
      </form>
    </div>

    <div class="card">
      <table>
        <tr>
          <th>ID</th><th>Teléfono</th><th>Email</th><th>Rol</th><th>Verificación</th><th>Estado</th><th>Creado</th><th>Actualizado</th><th></th>
        </tr>
        {trs or "<tr><td colspan='9' class='muted'>No hay usuarios todavía.</td></tr>"}
      </table>
    </div>
    """
    return page("Admin • Usuarios", body, subtitle="Cuentas Web")


@app.post("/admin/user/{user_id}/toggle_block")
@app.post("/admin/user/{user_id}/toggle_block/")
def admin_user_toggle_block(user_id: int, admin=Depends(require_admin)):
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(is_blocked,0) AS is_blocked FROM accounts WHERE id=?", (int(user_id),))
        r = cur.fetchone()
        if not r:
            conn.close()
            raise HTTPException(404, "Usuario no encontrado")
        blocked = int(r["is_blocked"] or 0)
        newv = 0 if blocked == 1 else 1
        cur.execute("UPDATE accounts SET is_blocked=?, updated_at=? WHERE id=?", (newv, now_str(), int(user_id)))
        conn.commit()
        conn.close()
        return newv

    newv = _retry_sqlite(_do)
    admin_log("user_toggle_block", json.dumps({"user_id": user_id, "is_blocked": newv}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/user/{int(user_id)}", status_code=302)


@app.get("/admin/user/{user_id}", response_class=HTMLResponse)
@app.get("/admin/user/{user_id}/", response_class=HTMLResponse)
def admin_user_detail(user_id: int, admin=Depends(require_admin)):
    def _do():
        conn = db_conn()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id, phone,
                   COALESCE(email,'') AS email,
                   COALESCE(role,'client') AS role,
                   verified,
                   COALESCE(is_blocked,0) AS is_blocked,
                   COALESCE(last_seen,'') AS last_seen,
                   created_at, updated_at
            FROM accounts
            WHERE id=?
            """,
            (int(user_id),),
        )
        u = cur.fetchone()

        proxies_rows = []
        try:
            cur.execute(
                "SELECT id, ip, vence, estado FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 50",
                (int(user_id),),
            )
            proxies_rows = cur.fetchall()
        except Exception:
            proxies_rows = []

        req_rows = []
        try:
            cur.execute(
                "SELECT id, tipo, ip, cantidad, monto, estado, created_at, voucher_path, target_proxy_id "
                "FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 50",
                (int(user_id),),
            )
            req_rows = cur.fetchall()
        except Exception:
            req_rows = []

        conn.close()
        return u, proxies_rows, req_rows

    u, proxies_rows, req_rows = _retry_sqlite(_do)

    if not u:
        return nice_error_page("Usuario", "No encontré ese usuario.", "/admin/accounts", "⬅️ Volver")

    blocked = int(u["is_blocked"] or 0)
    tag = "🚫 BLOQUEADO" if blocked == 1 else "✅ ACTIVO"

    phtml = ""
    for r in proxies_rows:
        pid = int(r["id"])
        phtml += (
            "<tr>"
            f"<td>{pid}</td>"
            f"<td>{html_escape(r['ip'] or '')}</td>"
            f"<td>{html_escape(r['vence'] or '')}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>"
            f"  <form method='post' action='/admin/proxy/{pid}/delete' "
            f"        onsubmit=\"return confirm('Eliminar proxy #{pid}?')\">"
            f"    <button class='btn bad' type='submit'>🗑 Eliminar</button>"
            f"  </form>"
            f"</td>"
            "</tr>"
        )
    if not phtml:
        phtml = "<tr><td colspan='5' class='muted'>Sin proxies</td></tr>"

    ohtml = ""
    for r in req_rows:
        voucher = (r["voucher_path"] or "").strip()
        voucher_cell = f"<a href='/static/{html_escape(voucher)}' target='_blank'>ver</a>" if voucher else "-"

        extra = ""
        if (r["tipo"] or "") == "renew" and int(r["target_proxy_id"] or 0) > 0:
            extra = f" • Proxy #{int(r['target_proxy_id'])}"

        ohtml += (
            "<tr>"
            f"<td>#{int(r['id'])}</td>"
            f"<td>{html_escape((r['tipo'] or '') + extra)}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{int(r['cantidad'] or 0)}</td>"
            f"<td>{html_escape(str(r['monto'] or '0'))}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{voucher_cell}</td>"
            "</tr>"
        )
    if not ohtml:
        ohtml = "<tr><td colspan='8' class='muted'>No hay pedidos</td></tr>"

    toggle_label = "🔓 Desbloquear" if blocked == 1 else "⛔ Bloquear"
    toggle_class = "btn" if blocked == 1 else "btn bad"

    role = (u["role"] or "client").strip().lower()
    role_label = "👑 Quitar admin" if role == "admin" else "👑 Hacer admin"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/accounts">⬅️ Usuarios</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>

        <form method="post" action="/admin/user/{int(user_id)}/toggle_role" style="margin-left:auto;">
          <button class="btn" type="submit">{role_label}</button>
        </form>

        <form method="post" action="/admin/user/{int(user_id)}/toggle_block">
          <button class="{toggle_class}" type="submit">{toggle_label}</button>
        </form>

        <form method="post" action="/admin/user/{int(user_id)}/delete"
              onsubmit="return confirm('⚠️ BORRAR usuario #{int(user_id)} y TODO lo asociado?');">
          <button class="btn bad" type="submit">🗑 Borrar usuario</button>
        </form>
      </div>

      <div class="hr"></div>
      <div class="muted">Usuario</div>
      <div class="kpi">{int(user_id)}</div>

      <p class="muted">{html_escape(u['phone'] or '')} • {html_escape(u['email'] or '')} • Rol: <b>{html_escape(u['role'] or 'client')}</b> • {tag}</p>
      <p class="muted">Última vez: {html_escape(u['last_seen'] or '-')}</p>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px 0;">📦 Proxies</h3>
      <table>
        <tr><th>PID</th><th>IP</th><th>Vence</th><th>Estado</th><th>Acciones</th></tr>
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
    return page(f"Admin • Usuario {int(user_id)}", body, subtitle="Detalle")


# =========================
# ADMIN: ORDERS (LIST)  (approve/reject están en Parte 3)
# =========================
@app.get("/admin/orders", response_class=HTMLResponse)
@app.get("/admin/orders/", response_class=HTMLResponse)
def admin_orders(admin=Depends(require_admin), state: str = ""):
    state = (state or "").strip()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        try:
            if state:
                cur.execute(
                    "SELECT id,user_id,tipo,ip,cantidad,monto,estado,created_at,voucher_path,target_proxy_id,note, "
                    "COALESCE(email,'') AS email, COALESCE(currency,'DOP') AS currency "
                    "FROM requests WHERE estado=? ORDER BY id DESC LIMIT 160",
                    (state,),
                )
            else:
                cur.execute(
                    "SELECT id,user_id,tipo,ip,cantidad,monto,estado,created_at,voucher_path,target_proxy_id,note, "
                    "COALESCE(email,'') AS email, COALESCE(currency,'DOP') AS currency "
                    "FROM requests ORDER BY id DESC LIMIT 160"
                )
            rows = cur.fetchall()
        except Exception:
            rows = []
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    trs = ""
    for r in rows:
        voucher = (r["voucher_path"] or "").strip()
        voucher_cell = f"<a href='/static/{html_escape(voucher)}' target='_blank'>ver</a>" if voucher else "-"

        rid = int(r["id"])
        uid = int(r["user_id"])
        tipo = (r["tipo"] or "").strip()
        qty = int(r["cantidad"] or 0)

        extra = ""
        if tipo == "renew" and int(r["target_proxy_id"] or 0) > 0:
            extra = f" • Proxy #{int(r['target_proxy_id'])}"

        deliver_box = f"""
  <div style="margin-top:8px; max-width:520px;">
    <label class="muted">Pega aquí {qty} proxies (RAW) — 1 por línea</label>
    <textarea
      name="delivery_raw"
      style="width:100%; max-width:520px;"
      placeholder="ip:port:user:pass&#10;ip:port:user:pass"></textarea>
  </div>
"""

        approve_form = f"""
          <form method="post" action="/admin/order/{rid}/approve" style="display:inline; min-width:320px;">
            {deliver_box}
            <button class="btn" type="submit" style="margin-top:8px;">✅ Aprobar</button>
          </form>
        """
        reject_form = f"""
          <form method="post" action="/admin/order/{rid}/reject" style="display:inline; margin-left:8px;">
            <button class="btn bad" type="submit">❌ Rechazar</button>
          </form>
        """

        trs += (
            "<tr>"
            f"<td>#{rid}</td>"
            f"<td><a class='btn ghost' href='/admin/user/{uid}'>👤 {uid}</a></td>"
            f"<td>{html_escape(tipo)}{html_escape(extra)}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{qty}</td>"
            f"<td>{html_escape(str(r['monto'] or '0'))} {html_escape(r['currency'] or 'DOP')}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{voucher_cell}</td>"
            f"<td>{approve_form}{reject_form}</td>"
            "</tr>"
        )

    if not trs:
        trs = "<tr><td colspan='10' class='muted'>No hay pedidos</td></tr>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
        <a class="btn ghost" href="/admin/orders">Todos</a>
        <a class="btn ghost" href="/admin/orders?state=voucher_received">Voucher recibidos</a>
        <a class="btn ghost" href="/admin/orders?state=awaiting_admin_verify">Claims</a>
      </div>
      <div class="hr"></div>

      <table>
        <tr>
          <th>ID</th><th>User</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th><th>Voucher</th><th>Acciones</th>
        </tr>
        {trs}
      </table>
    </div>
    """
    return page("Admin • Pedidos", body, subtitle="Aprobar / Rechazar")


# =========================
# ADMIN: PROXIES (listado)
# =========================
@app.get("/admin/proxies", response_class=HTMLResponse)
@app.get("/admin/proxies/", response_class=HTMLResponse)
def admin_proxies(admin=Depends(require_admin), q: str = ""):
    q = (q or "").strip()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        rows = []
        try:
            if q:
                cur.execute(
                    "SELECT id, user_id, ip, vence, estado FROM proxies "
                    "WHERE CAST(user_id AS TEXT) LIKE ? OR ip LIKE ? "
                    "ORDER BY id DESC LIMIT 200",
                    (f"%{q}%", f"%{q}%"),
                )
            else:
                cur.execute("SELECT id, user_id, ip, vence, estado FROM proxies ORDER BY id DESC LIMIT 200")
            rows = cur.fetchall()
        except Exception:
            rows = []
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    trs = ""
    for r in rows:
        trs += (
            "<tr>"
            f"<td><code>{int(r['id'])}</code></td>"
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
        <label class="muted">Buscar</label>
        <input name="q" value="{html_escape(q)}" placeholder="user_id o ip"/>
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
    return page("Admin • Proxies", body, subtitle="Listado")


# =========================
# ADMIN: TICKETS
# =========================
@app.get("/admin/tickets", response_class=HTMLResponse)
@app.get("/admin/tickets/", response_class=HTMLResponse)
def admin_tickets(admin=Depends(require_admin), state: str = "open"):
    state = (state or "open").strip()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id,user_id,subject,message,admin_reply,status,created_at,updated_at "
            "FROM tickets WHERE status=? ORDER BY id DESC LIMIT 120",
            (state,),
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    cards = ""
    for t in rows:
        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Ticket <b>#{int(t['id'])}</b> • Usuario <b>{int(t['user_id'])}</b> • Estado: <b>{html_escape(t['status'])}</b></div>
          <div style="height:8px;"></div>
          <div><b>{html_escape(t['subject'] or 'Soporte')}</b></div>
          <pre>{html_escape(t['message'] or '')}</pre>
          <div class="hr"></div>
          <form method="post" action="/admin/ticket/{int(t['id'])}/reply">
            <input type="hidden" name="return_state" value="{html_escape(state)}"/>
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
    <div class="card">
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
@app.post("/admin/ticket/{tid}/reply/")
def admin_ticket_reply(
    tid: int,
    reply: str = Form(""),
    action: str = Form("reply"),
    return_state: str = Form("open"),
    admin=Depends(require_admin),
):
    reply = (reply or "").strip()
    return_state = (return_state or "open").strip() or "open"

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id,user_id FROM tickets WHERE id=?", (int(tid),))
        t = cur.fetchone()
        if not t:
            conn.close()
            raise HTTPException(404, "Ticket no encontrado")

        uid = int(t["user_id"])

        if action == "close":
            cur.execute("UPDATE tickets SET status='closed', updated_at=? WHERE id=?", (now_str(), int(tid)))
            conn.commit()
            conn.close()
            notify_user(uid, f"✅ Tu ticket #{tid} fue cerrado.")
            admin_log("ticket_close", json.dumps({"tid": tid}, ensure_ascii=False))
            return

        cur.execute(
            "UPDATE tickets SET admin_reply=?, status='answered', updated_at=? WHERE id=?",
            (reply, now_str(), int(tid)),
        )
        conn.commit()
        conn.close()

        if reply:
            notify_user(uid, f"💬 Soporte respondió tu ticket #{tid}. Entra a Soporte para verlo.")
        admin_log("ticket_reply", json.dumps({"tid": tid}, ensure_ascii=False))

    _retry_sqlite(_do)
    return RedirectResponse(url=f"/admin/tickets?state={html_escape(return_state)}", status_code=302)


# =========================
# CLIENT AUTH: SIGNUP / VERIFY / LOGIN / LOGOUT / RESET
# =========================

@app.get("/client/signup", response_class=HTMLResponse)
@app.get("/client/signup/", response_class=HTMLResponse)
def client_signup_page():
    body = """
    <div class="grid">
      <div class="card">
        <div class="kpi">Crear cuenta</div>
        <p class="muted">Regístrate con Teléfono + Contraseña y define un PIN de recuperación.</p>
      </div>
      <div class="card">
        <form method="post" action="/client/signup">
          <label class="muted">Gmail (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com"/>
          <div style="height:12px;"></div>

          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..."/>
          <div style="height:12px;"></div>

          <label class="muted">Contraseña (mín 6)</label>
          <input name="password" type="password" placeholder="••••••"/>
          <div style="height:12px;"></div>

          <label class="muted">PIN de recuperación (4-6 dígitos)</label>
          <input name="recovery_pin" placeholder="Ej: 1234"/>
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Crear cuenta</button>
          <a class="btn ghost" href="/client/login" style="margin-left:10px;">🔐 Login</a>
        </form>
        <div class="hr"></div>
        <p class="muted">¿Olvidaste tu clave? <a href="/client/reset" style="color:white;">Resetear contraseña</a></p>
      </div>
    </div>
    """
    return page("Cliente • Crear cuenta", body, subtitle="Registro seguro")


@app.get("/client/verify-page", response_class=HTMLResponse)
@app.get("/client/verify-page/", response_class=HTMLResponse)
def client_verify_page(phone: str = ""):
    phone = _normalize_phone(phone)
    body = f"""
    <div class="grid">
      <div class="card">
        <div class="kpi">Verificar cuenta</div>
        <p class="muted">Si tu cuenta existe pero no está verificada, coloca el PIN aquí.</p>
        <div class="hr"></div>
        <p class="muted">Teléfono: <b>{html_escape(phone)}</b></p>
      </div>

      <div class="card">
        <form method="post" action="/client/verify">
          <input type="hidden" name="phone" value="{html_escape(phone)}"/>
          <label class="muted">PIN</label>
          <input name="pin" placeholder="123456"/>
          <div style="height:12px;"></div>
          <button class="btn" type="submit">✅ Verificar</button>
        </form>

        <div class="hr"></div>

        <form method="post" action="/client/resend_pin">
          <input type="hidden" name="phone" value="{html_escape(phone)}"/>
          <button class="btn ghost" type="submit">📩 Reenviar PIN</button>
          <a class="btn ghost" href="/client/signup" style="margin-left:10px;">✨ Crear de nuevo</a>
        </form>
      </div>
    </div>
    """
    return page("Verificación", body, subtitle="Completa el PIN")


@app.post("/client/verify", response_class=HTMLResponse)
@app.post("/client/verify/", response_class=HTMLResponse)
def client_verify(phone: str = Form(...), pin: str = Form(...)):
    phone = _normalize_phone(phone)
    pin = (pin or "").strip()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, pin_hash, expires_at, attempts FROM signup_pins "
            "WHERE phone=? AND estado='pending' ORDER BY id DESC LIMIT 1",
            (phone,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return ("no_pin", None)

        pid = int(row["id"])
        exp = row["expires_at"] or ""
        attempts = int(row["attempts"] or 0)

        try:
            exp_ts = time.mktime(time.strptime(exp, "%Y-%m-%d %H:%M:%S"))
            if time.time() > exp_ts:
                cur.execute("UPDATE signup_pins SET estado='expired' WHERE id=?", (pid,))
                conn.commit()
                conn.close()
                return ("expired", None)
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
            return ("bad", attempts)

        cur.execute("UPDATE signup_pins SET estado='done' WHERE id=?", (pid,))
        cur.execute("UPDATE accounts SET verified=1, updated_at=? WHERE phone=?", (now_str(), phone))
        conn.commit()
        conn.close()
        return ("ok", None)

    status, extra = _retry_sqlite(_do)

    if status == "no_pin":
        return nice_error_page("PIN no encontrado", "No hay un PIN activo. Crea la cuenta de nuevo.", "/client/signup", "✨ Crear cuenta")
    if status == "expired":
        return nice_error_page("PIN expirado", "El PIN venció. Reenvíalo o crea la cuenta de nuevo.", f"/client/verify-page?phone={phone}", "↩️ Volver a verificación")
    if status == "bad":
        return nice_error_page("PIN incorrecto", f"PIN incorrecto. Intentos: {extra}/3", f"/client/verify-page?phone={phone}", "↩️ Volver a verificación")

    def _get_uid_email():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, COALESCE(email,'') AS email FROM accounts WHERE phone=?", (phone,))
        r = cur.fetchone()
        conn.close()
        if not r:
            return 0, ""
        return int(r["id"]), (r["email"] or "").strip()

    uid, uemail = _retry_sqlite(_get_uid_email)

    if uid:
        notify_user(uid, f"🎉 Bienvenido a {APP_TITLE}. Tu cuenta ya está verificada.")
        if uemail:
            try:
                send_email(
                    uemail,
                    f"Cuenta verificada • {APP_TITLE}",
                    (
                        "Hola,\n\n"
                        "Tu cuenta fue verificada con éxito.\n\n"
                        "Ya puedes comprar y gestionar tus proxies desde tu panel.\n"
                        f"{APP_TITLE}\n"
                    ),
                )
            except Exception:
                pass

    return nice_error_page("Cuenta verificada", "Ya puedes iniciar sesión.", "/client/login", "🔐 Iniciar sesión")


@app.get("/client/login", response_class=HTMLResponse)
@app.get("/client/login/", response_class=HTMLResponse)
def client_login_page():
    body = """
    <div class="grid">
      <div class="card">
        <div class="kpi">Panel Cliente</div>
        <p class="muted">Entra con tu Teléfono + Contraseña.</p>
      </div>
      <div class="card">
        <form method="post" action="/client/login">
          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..."/>
          <div style="height:12px;"></div>

          <label class="muted">Contraseña</label>
          <input name="password" type="password" placeholder="••••••"/>
          <div style="height:12px;"></div>

          <button class="btn" type="submit">Entrar</button>
          <a class="btn ghost" href="/client/signup" style="margin-left:10px;">✨ Crear cuenta</a>
        </form>
        <div class="hr"></div>
        <p class="muted">¿Olvidaste tu clave? <a href="/client/reset" style="color:white;">Resetear contraseña</a></p>
      </div>
    </div>
    """
    return page("Cliente • Login", body, subtitle="Acceso seguro")


def account_verify_login(phone: str, password: str) -> Optional[int]:
    phone = _normalize_phone(phone)
    password = (password or "").strip()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash, verified, COALESCE(is_blocked,0) AS is_blocked FROM accounts WHERE phone=?",
            (phone,),
        )
        row = cur.fetchone()
        conn.close()
        return row

    row = _retry_sqlite(_do)
    if not row:
        return None
    if int(row["verified"] or 0) != 1:
        return None
    if int(row["is_blocked"] or 0) == 1:
        return None
    if not password_check(password, (row["password_hash"] or "")):
        return None
    return int(row["id"])


@app.post("/client/login")
@app.post("/client/login/")
def client_login(phone: str = Form(...), password: str = Form(...)):
    uid = account_verify_login(phone, password)

    if not uid:
        pnorm = _normalize_phone(phone)

        def _check_unverified():
            conn = db_conn()
            cur = conn.cursor()
            cur.execute("SELECT verified FROM accounts WHERE phone=?", (pnorm,))
            r = cur.fetchone()
            conn.close()
            return (int(r["verified"] or 0) == 0) if r else False

        if _retry_sqlite(_check_unverified):
            return RedirectResponse(url=f"/client/verify-page?phone={pnorm}", status_code=302)

        return nice_error_page(
            "Login inválido",
            "Teléfono/contraseña incorrectos, cuenta no verificada o bloqueada.",
            "/client/login",
            "↩️ Intentar de nuevo",
        )

    def _touch():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE accounts SET last_seen=?, updated_at=? WHERE id=?",
            (now_str(), now_str(), int(uid)),
        )
        conn.commit()
        conn.close()

    _retry_sqlite(_touch)

    session = sign({"role": "client", "uid": int(uid)}, CLIENT_SECRET, exp_seconds=7 * 24 * 3600)
    resp = RedirectResponse(url="/me", status_code=302)
    resp.set_cookie(
        "client_session",
        session,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )
    return resp


@app.post("/client/resend_pin", response_class=HTMLResponse)
@app.post("/client/resend_pin/", response_class=HTMLResponse)
def client_resend_pin(phone: str = Form(...)):
    phone = _normalize_phone(phone)

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, verified, COALESCE(email,'') AS email FROM accounts WHERE phone=?", (phone,))
        acc = cur.fetchone()
        if not acc:
            conn.close()
            return ("no_account", "", "", "")

        if int(acc["verified"] or 0) == 1:
            conn.close()
            return ("already", "", "", "")

        pin = _pin_gen(6)
        exp = _time_plus_minutes(5)

        cur.execute(
            "INSERT INTO signup_pins(phone,pin_hash,expires_at,attempts,estado,created_at) VALUES(?,?,?,?,?,?)",
            (phone, pin_hash(pin, PIN_SECRET), exp, 0, "pending", now_str()),
        )
        conn.commit()
        email = (acc["email"] or "").strip()
        conn.close()
        return ("ok", pin, exp, email)

    st, pin, exp, email = _retry_sqlite(_do)
    if st == "no_account":
        return nice_error_page("No existe", "Ese teléfono no está registrado.", "/client/signup", "✨ Crear cuenta")
    if st == "already":
        return nice_error_page("Ya verificada", "Esa cuenta ya está verificada. Inicia sesión.", "/client/login", "🔐 Login")

    # email “pro” si hay
    if email:
        try:
            send_email(
                email,
                f"PIN de verificación • {APP_TITLE}",
                (
                    "Hola,\n\n"
                    f"Tu PIN de verificación es: {pin}\n"
                    f"Expira: {exp}\n\n"
                    f"{APP_TITLE}\n"
                ),
            )
        except Exception:
            pass

    body = f"""
    <div class="card pinbox">
      <div class="muted">Nuevo PIN de verificación</div>
      <div class="kpi" style="letter-spacing:6px;">{html_escape(pin)}</div>
      <p class="muted">Expira: <b>{html_escape(exp)}</b></p>
      <p class="muted">Si tienes Gmail registrado, también te lo enviamos por email.</p>
    </div>
    <div class="card">
      <form method="post" action="/client/verify">
        <input type="hidden" name="phone" value="{html_escape(phone)}"/>
        <label class="muted">PIN</label>
        <input name="pin" placeholder="123456"/>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">Verificar</button>
      </form>
      <div class="hr"></div>
      <a class="btn ghost" href="/client/verify-page?phone={html_escape(phone)}">↩️ Volver a verificación</a>
    </div>
    """
    return page("Verificación", body, subtitle="Reenviar PIN")


@app.get("/logout")
@app.get("/logout/")
def client_logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("client_session")
    return resp


@app.get("/client/reset", response_class=HTMLResponse)
@app.get("/client/reset/", response_class=HTMLResponse)
def client_reset_page():
    body = """
    <div class="grid">
      <div class="card">
        <div class="kpi">🔑 Resetear contraseña</div>
        <p class="muted">Usa tu PIN de recuperación creado al registrarte.</p>
      </div>

      <div class="card">
        <form method="post" action="/client/reset">
          <label class="muted">Teléfono</label>
          <input name="phone" placeholder="+1809..."/>
          <div style="height:12px;"></div>

          <label class="muted">PIN de recuperación</label>
          <input name="recovery_pin" placeholder="Ej: 1234"/>
          <div style="height:12px;"></div>

          <label class="muted">Nueva contraseña</label>
          <input name="new_password" type="password" placeholder="••••••"/>
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Cambiar contraseña</button>
          <a class="btn ghost" href="/client/login" style="margin-left:10px;">🔐 Login</a>
        </form>
      </div>
    </div>
    """
    return page("Reset contraseña", body, subtitle="Recuperación")


@app.post("/client/reset", response_class=HTMLResponse)
@app.post("/client/reset/", response_class=HTMLResponse)
def client_reset_submit(phone: str = Form(...), recovery_pin: str = Form(...), new_password: str = Form(...)):
    phone = _normalize_phone(phone)
    recovery_pin = (recovery_pin or "").strip()
    new_password = (new_password or "").strip()

    if len(new_password) < 6:
        return nice_error_page("Datos inválidos", "La contraseña debe tener mínimo 6 caracteres.", "/client/reset", "↩️ Volver")
    if not recovery_pin.isdigit() or len(recovery_pin) < 4 or len(recovery_pin) > 6:
        return nice_error_page("Datos inválidos", "PIN de recuperación inválido.", "/client/reset", "↩️ Volver")

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, recovery_pin_hash FROM accounts WHERE phone=?", (phone,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False

        given = pin_hash(recovery_pin, PIN_SECRET)
        good = (row["recovery_pin_hash"] or "").strip()
        if not good or not hmac.compare_digest(good, given):
            conn.close()
            return False

        cur.execute(
            "UPDATE accounts SET password_hash=?, updated_at=? WHERE phone=?",
            (password_make_hash(new_password), now_str(), phone),
        )
        conn.commit()
        conn.close()
        return True

    ok = _retry_sqlite(_do)
    if not ok:
        return nice_error_page("No se pudo resetear", "Teléfono o PIN de recuperación incorrecto.", "/client/reset", "↩️ Intentar de nuevo")

    return nice_error_page("Contraseña actualizada", "Ya puedes iniciar sesión con tu nueva contraseña.", "/client/login", "🔐 Iniciar sesión")


# =========================
# ✅ SIGNUP POST (AQUÍ) — FIX 405 + email pro
# IMPORTANTE: en Parte 3 NO debe existir otro @app.post("/client/signup")
# =========================
@app.post("/client/signup", response_class=HTMLResponse)
@app.post("/client/signup/", response_class=HTMLResponse)
def client_signup_submit(
    email: str = Form(""),
    phone: str = Form(...),
    password: str = Form(...),
    recovery_pin: str = Form(...),
):
    email = (email or "").strip()
    phone = _normalize_phone(phone)
    password = (password or "").strip()
    recovery_pin = (recovery_pin or "").strip()

    if not phone:
        return nice_error_page("Datos inválidos", "Teléfono inválido.", "/client/signup", "↩️ Volver")

    if len(password) < 6:
        return nice_error_page("Datos inválidos", "La contraseña debe tener mínimo 6 caracteres.", "/client/signup", "↩️ Volver")

    if not recovery_pin.isdigit() or len(recovery_pin) < 4 or len(recovery_pin) > 6:
        return nice_error_page("Datos inválidos", "El PIN de recuperación debe ser de 4 a 6 dígitos.", "/client/signup", "↩️ Volver")

    def _do():
        conn = db_conn()
        cur = conn.cursor()

        cur.execute("SELECT id, verified FROM accounts WHERE phone=?", (phone,))
        acc = cur.fetchone()

        pwd_hash = password_make_hash(password)
        rpin_hash = pin_hash(recovery_pin, PIN_SECRET)

        if acc:
            uid = int(acc["id"])
            verified = int(acc["verified"] or 0)

            if verified == 1:
                conn.close()
                return ("already_verified", "", "", 0)

            cur.execute(
                "UPDATE accounts SET email=?, password_hash=?, recovery_pin_hash=?, verified=0, updated_at=? WHERE id=?",
                (email, pwd_hash, rpin_hash, now_str(), uid),
            )
        else:
            cur.execute(
                "INSERT INTO accounts(phone,email,password_hash,recovery_pin_hash,verified,is_blocked,last_seen,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (phone, email, pwd_hash, rpin_hash, 0, 0, "", now_str(), now_str()),
            )
            uid = int(cur.lastrowid)

        pin = _pin_gen(6)
        exp = _time_plus_minutes(5)
        cur.execute(
            "INSERT INTO signup_pins(phone,pin_hash,expires_at,attempts,estado,created_at) VALUES(?,?,?,?,?,?)",
            (phone, pin_hash(pin, PIN_SECRET), exp, 0, "pending", now_str()),
        )

        conn.commit()
        conn.close()
        return ("ok", pin, exp, uid)

    status, pin, exp, uid = _retry_sqlite(_do)

    if status == "already_verified":
        return nice_error_page(
            "Cuenta ya existe",
            "Este teléfono ya tiene una cuenta verificada. Inicia sesión.",
            "/client/login",
            "🔐 Login",
        )

    # Email pro con PIN si hay gmail
    if email:
        try:
            send_email(
                email,
                f"PIN de verificación • {APP_TITLE}",
                (
                    "Hola,\n\n"
                    f"Gracias por registrarte en {APP_TITLE}.\n\n"
                    f"Tu PIN de verificación es: {pin}\n"
                    f"Expira: {exp}\n\n"
                    f"{APP_TITLE}\n"
                ),
            )
        except Exception:
            pass

    body = f"""
    <div class="card pinbox">
      <div class="muted">PIN de verificación</div>
      <div class="kpi" style="letter-spacing:6px;">{html_escape(pin)}</div>
      <p class="muted">Expira: <b>{html_escape(exp)}</b></p>
      <p class="muted">Si pusiste Gmail, también lo enviamos por email (si tu SMTP está configurado).</p>
    </div>

    <div class="card">
      <form method="post" action="/client/verify">
        <input type="hidden" name="phone" value="{html_escape(phone)}"/>
        <label class="muted">PIN</label>
        <input name="pin" placeholder="123456"/>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">✅ Verificar</button>
        <a class="btn ghost" href="/client/login" style="margin-left:10px;">🔐 Login</a>
      </form>
    </div>
    """
    return page("Verificación", body, subtitle="Completa el PIN")


# =========================
# CLIENT PANEL: /me (SINGLE, FIXED)
# =========================
@app.get("/me", response_class=HTMLResponse)
@app.get("/me/", response_class=HTMLResponse)
def client_me(client=Depends(require_client)):
    uid = int(client["uid"])

    maint = get_setting("maintenance_enabled", "0") == "1"
    if maint:
        msg = get_setting("maintenance_message", "⚠️ Estamos en mantenimiento.")
        return nice_error_page("Mantenimiento", msg, "/logout", "🚪 Salir")

    def _do():
        conn = db_conn()
        cur = conn.cursor()

        try:
            cur.execute("UPDATE accounts SET last_seen=?, updated_at=? WHERE id=?", (now_str(), now_str(), uid))
            conn.commit()
        except Exception:
            pass

        cur.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND seen=0", (uid,))
        unread = int(cur.fetchone()[0])

        proxies_rows = []
        try:
            cur.execute(
                "SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 10",
                (uid,),
            )
            proxies_rows = cur.fetchall()
        except Exception:
            proxies_rows = []

        orders_rows = []
        try:
            cur.execute(
                "SELECT id, tipo, ip, cantidad, monto, estado, created_at, voucher_path "
                "FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
                (uid,),
            )
            orders_rows = cur.fetchall()
        except Exception:
            orders_rows = []

        conn.close()
        return unread, proxies_rows, orders_rows

    unread, proxies_rows, orders_rows = _retry_sqlite(_do)

    phtml = ""
    for r in proxies_rows:
        raw = (r["raw"] or "").strip()
        if raw and not raw.upper().startswith("HTTP"):
            raw = "HTTP\n" + raw
        proxy_text = raw or ("HTTP\n" + (r["ip"] or ""))

        vence = (r["vence"] or "").strip()
        countdown = (
            f"<span class='badge' data-exp='{html_escape(vence)}'>...</span>"
            if vence
            else "<span class='badge'>-</span>"
        )

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
        voucher_cell = f"<a href='/static/{html_escape(voucher)}' target='_blank'>ver</a>" if voucher else "-"
        ohtml += (
            "<tr>"
            f"<td>#{int(r['id'])}</td>"
            f"<td>{html_escape(r['tipo'] or '')}</td>"
            f"<td>{html_escape(r['ip'] or '-')}</td>"
            f"<td>{int(r['cantidad'] or 0)}</td>"
            f"<td>{html_escape(str(r['monto'] or '0'))}</td>"
            f"<td>{html_escape(r['estado'] or '')}</td>"
            f"<td>{html_escape(r['created_at'] or '')}</td>"
            f"<td>{voucher_cell}</td>"
            "</tr>"
        )

    if not ohtml:
        ohtml = "<tr><td colspan='8' class='muted'>No hay pedidos</td></tr>"

    notif_badge = f"<span class='badge'>{int(unread)}</span>" if int(unread) > 0 else ""
    notif_btn = f"🔔 Notificaciones {notif_badge}"

    body = f"""
    <div class="card">
      <div class="kpi">Panel Cliente</div>
      <p class="muted">Gestiona tus proxies, pedidos, notificaciones y soporte.</p>
      <div class="hr"></div>

      <div class="row">
        <a class="btn" href="/buy">🛒 Comprar proxy</a>
        <a class="btn" href="/renew">♻️ Renovar proxy</a>
        <a class="btn ghost" href="/add-existing">➕ Agregar proxy existente</a>
        <a class="btn ghost" href="/proxies">📦 Mis proxies</a>
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
        <tr>
          <th>ID</th><th>Tipo</th><th>IP</th><th>Qty</th><th>Monto</th><th>Estado</th><th>Creado</th><th>Voucher</th>
        </tr>
        {ohtml}
      </table>
    </div>

    <script>
      function pad(n){{return String(n).padStart(2,'0');}}
      function parseExp(s){{
        if(!s) return NaN;
        const parts = s.trim().split(' ');
        if(parts.length !== 2) return Date.parse(s);
        const d = parts[0].split('-').map(Number);
        const t = parts[1].split(':').map(Number);
        if(d.length!==3 || t.length!==3) return Date.parse(s);
        return new Date(d[0], d[1]-1, d[2], t[0], t[1], t[2]).getTime();
      }}
      function tick(){{
        const els = document.querySelectorAll('[data-exp]');
        const now = Date.now();
        els.forEach(el => {{
          const s = el.getAttribute('data-exp');
          const t = parseExp(s);
          if (isNaN(t)) {{ el.textContent='...'; return; }}
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
      tick();
      setInterval(tick, 1000);
    </script>
    """
    return page("Cliente", body, subtitle="Tus proxies y pedidos")


# =========================
# CLIENT: BANK / PROXIES  (Parte 3 sigue con notifications/chat/buy/etc)
# =========================
@app.get("/bank", response_class=HTMLResponse)
@app.get("/bank/", response_class=HTMLResponse)
def client_bank(client=Depends(require_client)):
    title = get_setting("bank_title", "Cuenta bancaria")
    details = get_setting("bank_details", "")

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn" href="/buy">🛒 Comprar</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">🏦 {html_escape(title)}</div>
      <pre>{html_escape(details)}</pre>
    </div>
    """
    return page("Cuenta bancaria", body, subtitle="Pago")


@app.get("/proxies", response_class=HTMLResponse)
@app.get("/proxies/", response_class=HTMLResponse)
def client_proxies(client=Depends(require_client)):
    uid = int(client["uid"])

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        rows = []
        try:
            cur.execute(
                "SELECT id, ip, inicio, vence, estado, raw FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 300",
                (uid,),
            )
            rows = cur.fetchall()
        except Exception:
            rows = []
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    cards = ""
    for r in rows:
        raw = (r["raw"] or "").strip()
        if raw and not raw.upper().startswith("HTTP"):
            raw = "HTTP\n" + raw
        proxy_text = raw or ("HTTP\n" + (r["ip"] or ""))

        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Proxy #{int(r['id'])} • {html_escape(r['estado'] or '')}</div>
          <div style="height:6px;"></div>
          <div><b>{html_escape(r['ip'] or '')}</b></div>
          <div class="muted">Inicio: {html_escape(r['inicio'] or '')} • Vence: {html_escape(r['vence'] or '')}</div>
          <div style="height:10px;"></div>
          <pre>{html_escape(proxy_text)}</pre>
          <div class="row">
            <a class="btn ghost" href="/renew?proxy_id={int(r['id'])}">♻️ Renovar</a>
          </div>
        </div>
        """

    if not cards:
        cards = "<div class='card'><p class='muted'>No tienes proxies todavía.</p></div>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">📦 Mis proxies</div>
      <p class="muted">Aquí salen todas tus proxies.</p>
    </div>
    {cards}
    """
    return page("Mis proxies", body, subtitle="Listado")

# =========================
# PARTE 3 (CORREGIDA + MEJORADA)
# - ✅ Se elimina el /client/signup duplicado (causaba líos)
# - ✅ Chat unificado con el schema REAL (seen_by_admin / seen_by_user)
# - ✅ Admin Approve/Reject con emails PROFESIONALES + entrega de proxies por email
# - ✅ Recordatorios 7 días antes (sin VPS): thread interno + tabla anti-duplicados
# - ✅ Admin puede enviar correos personalizados desde el panel
# =========================

@app.get("/notifications", response_class=HTMLResponse)
def client_notifications(client=Depends(require_client)):
    uid = int(client["uid"])

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id,message,seen,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 200",
            (uid,),
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    cards = ""
    unseen_ids = []
    for n in rows:
        seen = int(n["seen"] or 0)
        if seen == 0:
            unseen_ids.append(int(n["id"]))
        badge = "<span class='badge'>NEW</span>" if seen == 0 else "<span class='badge'>OK</span>"
        cards += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">{badge} • {html_escape(n['created_at'] or '')}</div>
          <pre>{html_escape(n['message'] or '')}</pre>
        </div>
        """

    if not cards:
        cards = "<div class='card'><p class='muted'>No tienes notificaciones.</p></div>"

    if unseen_ids:
        def _mark():
            conn = db_conn()
            cur = conn.cursor()
            cur.execute("UPDATE notifications SET seen=1 WHERE user_id=? AND seen=0", (uid,))
            conn.commit()
            conn.close()
        _retry_sqlite(_mark)

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">🔔 Notificaciones</div>
      <p class="muted">Tus actualizaciones recientes.</p>
    </div>
    {cards}
    """
    return page("Notificaciones", body, subtitle="Actualizaciones")


# =========================
# EMAIL PRO (helpers)
# =========================
def _email_footer() -> str:
    return (
        f"\n\n—\n"
        f"{APP_TITLE}\n"
        f"Soporte: abre un ticket en tu panel o usa el Chat.\n"
    )

def _email_subject(prefix: str) -> str:
    prefix = (prefix or "").strip()
    return f"{prefix} • {APP_TITLE}".strip()

def _email_order_approved_body(rid: int, tipo: str, total: int, currency: str, delivered: str = "") -> str:
    t = (tipo or "").strip().upper()
    body = (
        f"Hola,\n\n"
        f"Tu pedido #{rid} ha sido APROBADO.\n"
        f"Tipo: {t}\n"
        f"Total: {int(total)} {currency}\n"
    )
    if delivered:
        body += (
            f"\nDetalles de entrega:\n"
            f"{delivered}\n"
        )
    body += _email_footer()
    return body

def _email_order_rejected_body(rid: int) -> str:
    return (
        f"Hola,\n\n"
        f"Tu pedido #{rid} ha sido RECHAZADO.\n"
        f"Si necesitas ayuda, responde por Chat o abre un ticket en Soporte.\n"
        + _email_footer()
    )

def _email_proxy_reminder_body(proxy_id: int, ip: str, vence: str, days_left: int) -> str:
    return (
        f"Hola,\n\n"
        f"Recordatorio: tu proxy #{proxy_id} está por vencer.\n"
        f"IP: {ip}\n"
        f"Vence: {vence}\n"
        f"Faltan: {days_left} día(s)\n\n"
        f"Para evitar interrupciones, entra a tu panel y renueva a tiempo:\n"
        f"/renew\n"
        + _email_footer()
    )

def _email_custom_body(subject: str, message: str) -> str:
    subj = (subject or "").strip()
    msg = (message or "").strip()
    return (
        f"Hola,\n\n"
        f"{msg}\n"
        + _email_footer()
    )


# =========================
# ADMIN: EMAIL PERSONALIZADO (sin VPS)
# =========================
@app.get("/admin/email", response_class=HTMLResponse)
def admin_email_page(admin=Depends(require_admin), user_id: str = ""):
    user_id = (user_id or "").strip()
    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">📧 Enviar correo</div>
      <p class="muted">Envía un correo profesional a un usuario (usa SMTP configurado).</p>

      <div class="hr"></div>
      <form method="post" action="/admin/email/send">
        <label class="muted">User ID (opcional si pones email directo)</label>
        <input name="user_id" value="{html_escape(user_id)}" placeholder="Ej: 12"/>

        <div style="height:12px;"></div>
        <label class="muted">Email destino (opcional)</label>
        <input name="to_email" placeholder="cliente@gmail.com"/>

        <div style="height:12px;"></div>
        <label class="muted">Asunto</label>
        <input name="subject" placeholder="Ej: Información de tu servicio"/>

        <div style="height:12px;"></div>
        <label class="muted">Mensaje</label>
        <textarea name="message" placeholder="Escribe tu mensaje aquí..."></textarea>

        <div style="height:12px;"></div>
        <button class="btn" type="submit">✅ Enviar</button>
      </form>
    </div>
    """
    return page("Admin • Email", body, subtitle="Correo profesional")


@app.post("/admin/email/send", response_class=HTMLResponse)
def admin_email_send(
    user_id: str = Form(""),
    to_email: str = Form(""),
    subject: str = Form(""),
    message: str = Form(""),
    admin=Depends(require_admin),
):
    user_id = (user_id or "").strip()
    to_email = (to_email or "").strip()
    subject = (subject or "").strip()
    message = (message or "").strip()

    if not subject or not message:
        return nice_error_page("Faltan datos", "Asunto y mensaje son obligatorios.", "/admin/email", "↩️ Volver")

    uid = 0
    if user_id:
        try:
            uid = int(float(user_id))
        except Exception:
            uid = 0

    # si no dio email, lo buscamos por uid
    if not to_email and uid > 0:
        def _get():
            conn = db_conn()
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(email,'') AS email FROM accounts WHERE id=?", (uid,))
            r = cur.fetchone()
            conn.close()
            return (r["email"] or "").strip() if r else ""
        to_email = _retry_sqlite(_get)

    if not to_email:
        return nice_error_page("Sin email", "No pude determinar el email destino.", "/admin/email", "↩️ Volver")

    try:
        send_email(to_email, _email_subject(subject), _email_custom_body(subject, message))
    except Exception:
        pass

    if uid > 0:
        notify_user(uid, "📧 El administrador te envió un correo. Revisa tu Gmail.")
    admin_log("admin_email_send", json.dumps({"uid": uid, "to": to_email, "subject": subject}, ensure_ascii=False))
    return nice_error_page("Listo", f"Correo enviado a {to_email}", "/admin", "⬅️ Volver al Dashboard")


# =========================
# LIVE CHAT (CLIENTE <-> ADMIN) ✅ FIX REAL (schema unificado)
# =========================
def ensure_chat_schema():
    def _do():
        conn = db_conn()
        _ensure_table(
            conn,
            """
            CREATE TABLE IF NOT EXISTS chat_messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                sender TEXT NOT NULL DEFAULT 'user',  -- 'user' o 'admin'
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                seen_by_admin INTEGER NOT NULL DEFAULT 0,
                seen_by_user INTEGER NOT NULL DEFAULT 0
            );
            """,
        )
        # migraciones seguras si ya existía vieja
        for col, coldef in [
            ("seen_by_admin", "INTEGER NOT NULL DEFAULT 0"),
            ("seen_by_user", "INTEGER NOT NULL DEFAULT 0"),
        ]:
            try:
                _ensure_column(conn, "chat_messages", col, coldef)
            except Exception:
                pass
        conn.close()
    _retry_sqlite(_do)

def chat_add(user_id: int, sender: str, message: str):
    ensure_chat_schema()
    sender = (sender or "user").strip().lower()
    if sender not in ("user", "admin"):
        sender = "user"
    msg = (message or "").strip()
    if not msg:
        return

    # si escribe el user: admin no lo ha visto aún
    s_admin = 0 if sender == "user" else 1
    s_user = 1 if sender == "user" else 0

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO chat_messages(user_id,sender,message,created_at,seen_by_admin,seen_by_user) VALUES(?,?,?,?,?,?)",
            (int(user_id), sender, msg, now_str(), s_admin, s_user),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

def chat_get(user_id: int, limit: int = 120):
    ensure_chat_schema()
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id,user_id,sender,message,created_at,seen_by_admin,seen_by_user "
            "FROM chat_messages WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (int(user_id), int(limit)),
        )
        rows = cur.fetchall()
        conn.close()
        return list(reversed(rows))
    return _retry_sqlite(_do)

def chat_mark_seen_by_admin(user_id: int):
    ensure_chat_schema()
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE chat_messages SET seen_by_admin=1 "
            "WHERE user_id=? AND sender='user' AND COALESCE(seen_by_admin,0)=0",
            (int(user_id),),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

def chat_mark_seen_by_user(user_id: int):
    ensure_chat_schema()
    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE chat_messages SET seen_by_user=1 "
            "WHERE user_id=? AND sender='admin' AND COALESCE(seen_by_user,0)=0",
            (int(user_id),),
        )
        conn.commit()
        conn.close()
    _retry_sqlite(_do)

@app.get("/chat", response_class=HTMLResponse)
def client_chat_page(client=Depends(require_client)):
    uid = int(client["uid"])
    rows = chat_get(uid, 200)

    # al abrir, marcar como visto lo que envió admin
    chat_mark_seen_by_user(uid)

    msgs = ""
    for r in rows:
        sender = (r["sender"] or "user").strip()
        who = "🧑‍💻 Tú" if sender == "user" else "🛠 Admin"
        bubble_bg = "rgba(255,255,255,.08)" if sender == "user" else "rgba(0,212,255,.12)"
        msgs += f"""
        <div class="card" style="margin-bottom:10px; background:{bubble_bg};">
          <div class="muted">{who} • {html_escape(r['created_at'] or '')}</div>
          <div style="height:6px;"></div>
          <pre>{html_escape(r['message'] or '')}</pre>
        </div>
        """

    if not msgs:
        msgs = "<div class='card'><p class='muted'>Aún no hay mensajes. Escribe abajo para iniciar el chat.</p></div>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">💬 Chat</div>
      <p class="muted">Escribe y el admin te responde.</p>
    </div>

    {msgs}

    <div class="card">
      <form method="post" action="/chat/send">
        <label class="muted">Mensaje</label>
        <textarea name="message" placeholder="Escribe aquí..."></textarea>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">📨 Enviar</button>
      </form>
    </div>
    """
    return page("Chat", body, subtitle=f"Cliente #{uid}")

@app.post("/chat/send", response_class=HTMLResponse)
def client_chat_send(message: str = Form(...), client=Depends(require_client)):
    uid = int(client["uid"])
    msg = (message or "").strip()
    if not msg:
        return RedirectResponse(url="/chat", status_code=302)

    chat_add(uid, "user", msg)
    outbox_add("chat_new", json.dumps({"user_id": uid}, ensure_ascii=False))
    admin_log("chat_user_msg", json.dumps({"uid": uid}, ensure_ascii=False))
    return RedirectResponse(url="/chat", status_code=302)

@app.get("/admin/chat", response_class=HTMLResponse)
def admin_chat_list(admin=Depends(require_admin)):
    ensure_chat_schema()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT a.id AS user_id,
                   a.phone AS phone,
                   COALESCE(a.email,'') AS email,
                   MAX(c.created_at) AS last_at,
                   SUM(CASE WHEN c.sender='user' AND COALESCE(c.seen_by_admin,0)=0 THEN 1 ELSE 0 END) AS unread
            FROM accounts a
            JOIN chat_messages c ON c.user_id=a.id
            GROUP BY a.id
            ORDER BY last_at DESC
            LIMIT 200
            """
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    trs = ""
    for r in rows:
        uid = int(r["user_id"])
        unread = int(r["unread"] or 0)
        badge = f" <span class='badge'>{unread}</span>" if unread > 0 else ""
        trs += (
            "<tr>"
            f"<td><a class='btn ghost' href='/admin/chat/{uid}'>💬 {uid}{badge}</a></td>"
            f"<td>{html_escape(r['phone'] or '')}</td>"
            f"<td>{html_escape(r['email'] or '')}</td>"
            f"<td>{html_escape(r['last_at'] or '')}</td>"
            "</tr>"
        )
    if not trs:
        trs = "<tr><td colspan='4' class='muted'>No hay chats todavía.</td></tr>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin">⬅️ Dashboard</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">💬 Chats</div>
      <p class="muted">Selecciona un usuario para chatear.</p>
    </div>

    <div class="card">
      <table>
        <tr><th>User</th><th>Teléfono</th><th>Email</th><th>Último</th></tr>
        {trs}
      </table>
    </div>
    """
    return page("Admin • Chat", body, subtitle="Chat en vivo")

@app.get("/admin/chat/{user_id}", response_class=HTMLResponse)
def admin_chat_room(user_id: int, admin=Depends(require_admin)):
    uid = int(user_id)

    # al abrir, marcar como visto lo que mandó el user
    chat_mark_seen_by_admin(uid)

    rows = chat_get(uid, 250)

    def _u():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, phone, COALESCE(email,'') AS email FROM accounts WHERE id=?", (uid,))
        r = cur.fetchone()
        conn.close()
        return r
    u = _retry_sqlite(_u)

    msgs = ""
    for r in rows:
        sender = (r["sender"] or "user").strip()
        who = "🧑 Cliente" if sender == "user" else "🛠 Tú (Admin)"
        bubble_bg = "rgba(255,255,255,.08)" if sender == "user" else "rgba(0,212,255,.12)"
        msgs += f"""
        <div class="card" style="margin-bottom:10px; background:{bubble_bg};">
          <div class="muted">{who} • {html_escape(r['created_at'] or '')}</div>
          <div style="height:6px;"></div>
          <pre>{html_escape(r['message'] or '')}</pre>
        </div>
        """
    if not msgs:
        msgs = "<div class='card'><p class='muted'>Aún no hay mensajes.</p></div>"

    head = f"Cliente #{uid}"
    if u:
        head = f"{html_escape(u['phone'] or '')} • {html_escape(u['email'] or '')} • ID {uid}"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/admin/chat">⬅️ Chats</a>
        <a class="btn ghost" href="/admin/user/{uid}">👤 Ver usuario</a>
        <a class="btn ghost" href="/admin">🏠 Dashboard</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">💬 Chat</div>
      <p class="muted">{head}</p>
    </div>

    {msgs}

    <div class="card">
      <form method="post" action="/admin/chat/{uid}/send">
        <label class="muted">Mensaje (admin)</label>
        <textarea name="message" placeholder="Escribe aquí..."></textarea>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">📨 Enviar</button>
      </form>
    </div>
    """
    return page("Admin • Chat", body, subtitle="Chat en vivo")

@app.post("/admin/chat/{user_id}/send", response_class=HTMLResponse)
def admin_chat_send(user_id: int, message: str = Form(...), admin=Depends(require_admin)):
    uid = int(user_id)
    msg = (message or "").strip()
    if not msg:
        return RedirectResponse(url=f"/admin/chat/{uid}", status_code=302)

    chat_add(uid, "admin", msg)
    notify_user(uid, "💬 Tienes un nuevo mensaje del admin. Entra a Chat para verlo.")
    admin_log("chat_admin_msg", json.dumps({"uid": uid}, ensure_ascii=False))
    return RedirectResponse(url=f"/admin/chat/{uid}", status_code=302)


# =========================
# RECORDATORIOS 7 DÍAS ANTES (sin VPS)
# - corre en un thread dentro del mismo proceso FastAPI
# - guarda en DB qué recordatorio ya fue enviado (para no duplicar)
# =========================
def ensure_reminders_schema():
    def _do():
        conn = db_conn()
        _ensure_table(
            conn,
            """
            CREATE TABLE IF NOT EXISTS proxy_reminders(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy_id INTEGER NOT NULL,
                days_left INTEGER NOT NULL,
                sent_at TEXT NOT NULL DEFAULT ''
            );
            """,
        )
        try:
            _ensure_table(conn, "CREATE UNIQUE INDEX IF NOT EXISTS ux_proxy_reminders ON proxy_reminders(proxy_id, days_left);")
        except Exception:
            pass
        conn.close()
    _retry_sqlite(_do)

def _calc_days_left(vence_str: str) -> Optional[int]:
    vdt = parse_dt(vence_str or "")
    if not vdt:
        return None
    now = datetime.now()
    # días restantes según piso de día
    dnow = day_floor(now)
    dv = day_floor(vdt)
    return int((dv - dnow).days)

def send_proxy_expiry_reminders_once():
    """
    Envía recordatorios si faltan 7..1 días.
    Se protege con tabla proxy_reminders para no repetir el mismo día_left.
    """
    ensure_reminders_schema()

    def _do():
        conn = db_conn()
        cur = conn.cursor()

        # buscar proxies activos con vence válido
        try:
            cur.execute(
                "SELECT p.id AS pid, p.user_id AS uid, p.ip AS ip, p.vence AS vence, "
                "COALESCE(a.email,'') AS email "
                "FROM proxies p "
                "LEFT JOIN accounts a ON a.id=p.user_id "
                "WHERE COALESCE(p.estado,'active')='active' "
                "ORDER BY p.id DESC LIMIT 2000"
            )
            rows = cur.fetchall()
        except Exception:
            rows = []

        sent_count = 0

        for r in rows:
            pid = int(r["pid"])
            uid = int(r["uid"])
            ip = (r["ip"] or "").strip()
            vence = (r["vence"] or "").strip()
            uemail = (r["email"] or "").strip()

            days_left = _calc_days_left(vence)
            if days_left is None:
                continue

            if days_left < 1 or days_left > 7:
                continue

            # ya enviado este recordatorio?
            try:
                cur.execute(
                    "SELECT 1 FROM proxy_reminders WHERE proxy_id=? AND days_left=? LIMIT 1",
                    (pid, days_left),
                )
                if cur.fetchone():
                    continue
            except Exception:
                pass

            # registrar envío (anti duplicado)
            try:
                cur.execute(
                    "INSERT OR IGNORE INTO proxy_reminders(proxy_id, days_left, sent_at) VALUES(?,?,?)",
                    (pid, days_left, now_str()),
                )
                conn.commit()
            except Exception:
                pass

            # notificación in-app
            notify_user(uid, f"⏳ Tu proxy #{pid} vence en {days_left} día(s). Renueva para evitar cortes.")

            # email si hay
            if uemail:
                try:
                    send_email(
                        uemail,
                        _email_subject(f"Recordatorio: tu proxy vence en {days_left} día(s)"),
                        _email_proxy_reminder_body(pid, ip, vence, days_left),
                    )
                except Exception:
                    pass

            sent_count += 1

        conn.close()
        return sent_count

    return _retry_sqlite(_do)

def _reminder_loop():
    # loop simple (cada 6 horas)
    while True:
        try:
            send_proxy_expiry_reminders_once()
        except Exception:
            pass
        time.sleep(6 * 3600)

@app.on_event("startup")
def _start_reminder_thread():
    # thread daemon: solo funciona si tu PC/servidor está prendido (como dijiste)
    try:
        import threading
        t = threading.Thread(target=_reminder_loop, daemon=True)
        t.start()
    except Exception:
        pass


# =========================
# ADMIN: APPROVE / REJECT ORDERS ✅ (emails PRO + entrega)
# =========================
def _parse_delivery_items_for_email(raw_text: str, qty: int) -> str:
    """
    Para 'buy': prepara texto bonito para email con lo que el admin pegó.
    Respeta tu lógica: puede venir con 'HTTP' en línea separada.
    """
    lines = [ln.strip() for ln in (raw_text or "").splitlines()]
    items = []
    i = 0

    while i < len(lines) and len(items) < qty:
        ln = lines[i].strip()
        if not ln:
            i += 1
            continue

        up = ln.upper()
        if up in ("HTTP", "HTTPS", "SOCKS5", "SOCKS4"):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                break
            proxy_line = lines[j].strip()
            items.append(f"{up}\n{proxy_line}")
            i = j + 1
            continue

        items.append(ln)
        i += 1

    if len(items) < qty:
        return ""

    # formato email
    out = "PROXIES ENTREGADOS (1 por bloque):\n\n"
    for idx, raw in enumerate(items[:qty], start=1):
        rr = raw.strip()
        if rr and not rr.upper().startswith(("HTTP", "HTTPS", "SOCKS")):
            rr = "HTTP\n" + rr
        out += f"[{idx}]\n{rr}\n\n"
    return out.strip()

@app.post("/admin/order/{rid}/approve")
def admin_order_approve(rid: int, delivery_raw: str = Form(""), admin=Depends(require_admin)):
    ensure_requests_schema()
    ensure_requests_schema()
    ensure_proxies_schema()

    def _do():
        conn = db_conn()
        cur = conn.cursor()

        cur.execute(
            "SELECT id,user_id,tipo,cantidad,monto,estado,target_proxy_id,note, "
            "COALESCE(email,'') AS email, COALESCE(currency,'DOP') AS currency "
            "FROM requests WHERE id=?",
            (int(rid),),
        )
        r = cur.fetchone()
        if not r:
            conn.close()
            raise HTTPException(404, "Pedido no encontrado")

        estado = (r["estado"] or "").strip()
        if estado not in ("voucher_received", "awaiting_admin_verify", "awaiting_voucher"):
            conn.close()
            raise HTTPException(400, f"Este pedido está en estado '{estado}' y no se puede aprobar.")

        uid = int(r["user_id"])
        tipo = (r["tipo"] or "").strip()
        qty = int(r["cantidad"] or 0)
        total = int(r["monto"] or 0)
        currency = (r["currency"] or "DOP").strip()

        dias = int(float(get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY)) or DEFAULT_DIAS_PROXY))
        if dias <= 0:
            dias = DEFAULT_DIAS_PROXY
        if dias > 30:
            dias = 30

        delivered_for_email = ""

        if tipo == "buy":
            if not _deliver_buy_only_count(qty):
                conn.close()
                raise HTTPException(400, "No hay stock suficiente para este pedido.")

            # preparar email con lo que pegó el admin
            delivered_for_email = _parse_delivery_items_for_email(delivery_raw, qty)

            _deliver_buy_add_proxies(conn, uid, delivery_raw, qty, dias)

        elif tipo == "renew":
            pid = int(r["target_proxy_id"] or 0)
            if pid <= 0:
                conn.close()
                raise HTTPException(400, "Pedido de renovación sin proxy_id.")
            _deliver_renew_extend(conn, uid, pid, dias)

        elif tipo == "claim":
            _deliver_claim_add_proxy(conn, uid, r["note"] or "")

        else:
            conn.close()
            raise HTTPException(400, f"Tipo desconocido: {tipo}")

        cur.execute("UPDATE requests SET estado='approved' WHERE id=?", (int(rid),))
        conn.commit()
        conn.close()

        # notificación interna
        notify_user(uid, f"✅ Tu pedido #{rid} fue aprobado.")

        # email: usa email del pedido, si no existe busca email de account
        uemail = (r["email"] or "").strip()
        if not uemail:
            def _get_email():
                c2 = db_conn()
                cu2 = c2.cursor()
                cu2.execute("SELECT COALESCE(email,'') AS email FROM accounts WHERE id=?", (uid,))
                rr2 = cu2.fetchone()
                c2.close()
                return (rr2["email"] or "").strip() if rr2 else ""
            uemail = _retry_sqlite(_get_email)

        if uemail:
            try:
                send_email(
                    uemail,
                    _email_subject(f"Pedido #{rid} aprobado"),
                    _email_order_approved_body(rid, tipo, total, currency, delivered_for_email),
                )
            except Exception:
                pass

        admin_log("order_approved", json.dumps({"rid": rid, "uid": uid, "tipo": tipo}, ensure_ascii=False))

    _retry_sqlite(_do)
    return RedirectResponse(url="/admin/orders", status_code=302)

# =========================
# DELIVERY HELPERS (necesarios para aprobar pedidos)
# =========================

def _deliver_buy_only_count(qty: int) -> bool:
    """
    Si estás usando 'stock_available' en settings, valida y descuenta.
    Si no te importa el stock, puedes retornar True siempre.
    """
    try:
        stock = int(float(get_setting("stock_available", "0") or 0))
    except Exception:
        stock = 0

    if stock < int(qty):
        return False

    set_setting("stock_available", str(stock - int(qty)))
    return True


def _deliver_buy_add_proxies(conn: sqlite3.Connection, user_id: int, raw_text: str, qty: int, dias: int):
    """
    Crea 'qty' proxies nuevas usando el texto pegado por el admin (RAW).
    Acepta:
      - 1 proxy por línea: ip:port:user:pass
      - o bloques con 'HTTP' en una línea y la proxy en la siguiente.
    """
    ensure_proxies_schema()

    lines = [ln.strip() for ln in (raw_text or "").splitlines()]
    items = []
    i = 0

    while i < len(lines) and len(items) < qty:
        ln = lines[i].strip()
        if not ln:
            i += 1
            continue

        up = ln.upper()
        if up in ("HTTP", "HTTPS", "SOCKS5", "SOCKS4"):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                break
            proxy_line = lines[j].strip()
            items.append(f"{up}\n{proxy_line}")
            i = j + 1
            continue

        items.append(ln)
        i += 1

    if len(items) < qty:
        raise HTTPException(400, f"Pegaste {len(items)} proxies pero el pedido es de {qty}.")

    start = day_floor(datetime.now())
    vdt = start + timedelta(days=int(dias))

    cur = conn.cursor()
    for raw in items[:qty]:
        # La IP visible se saca de la última línea del RAW
        last = raw.splitlines()[-1].strip()
        ip = last.replace("http://", "").replace("https://", "").split()[0]

        cur.execute(
            "INSERT INTO proxies(user_id,ip,inicio,vence,estado,raw) VALUES(?,?,?,?,?,?)",
            (int(user_id), ip, fmt_dt(start), fmt_dt(vdt), "active", raw),
        )


def _deliver_renew_extend(conn: sqlite3.Connection, user_id: int, proxy_id: int, dias: int):
    """
    Extiende 'vence' del proxy (renovación).
    """
    ensure_proxies_schema()

    cur = conn.cursor()
    cur.execute("SELECT id, vence FROM proxies WHERE id=? AND user_id=?", (int(proxy_id), int(user_id)))
    p = cur.fetchone()
    if not p:
        raise HTTPException(400, "No encontré ese proxy para renovar.")

    now = datetime.now()
    v_old = parse_dt(p["vence"] or "") or now
    base_dt = v_old if v_old > now else now
    base = day_floor(base_dt)
    v_new = base + timedelta(days=int(dias))

    cur.execute("UPDATE proxies SET vence=? WHERE id=?", (fmt_dt(v_new), int(proxy_id)))


def _deliver_claim_add_proxy(conn: sqlite3.Connection, user_id: int, note: str):
    """
    Aprobación de 'claim': agrega un proxy basado en note JSON (ip/raw/vence).
    """
    ensure_proxies_schema()

    try:
        payload = json.loads(note or "{}")
    except Exception:
        payload = {}

    raw = (payload.get("raw") or "").strip()
    ip = (payload.get("ip") or "").strip()
    vence = (payload.get("vence") or "").strip()

    if not raw and not ip:
        raise HTTPException(400, "La solicitud no tiene proxy válido.")

    if not ip and raw:
        last = raw.splitlines()[-1].strip()
        ip = last.replace("http://", "").replace("https://", "").split()[0]

    start = day_floor(datetime.now())

    dias_cfg = int(float(get_setting("dias_proxy", "30") or 30))
    if dias_cfg <= 0:
        dias_cfg = 30
    if dias_cfg > 30:
        dias_cfg = 30

    if vence:
        vdt = day_floor(parse_dt(vence) or (start + timedelta(days=dias_cfg)))
    else:
        vdt = start + timedelta(days=dias_cfg)

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO proxies(user_id,ip,inicio,vence,estado,raw) VALUES(?,?,?,?,?,?)",
        (int(user_id), ip, fmt_dt(start), fmt_dt(vdt), "active", raw or ip),
    )


@app.post("/admin/order/{rid}/reject")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    ensure_requests_schema()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id,user_id,COALESCE(email,'') AS email, COALESCE(currency,'DOP') AS currency FROM requests WHERE id=?",
            (int(rid),),
        )
        r = cur.fetchone()
        if not r:
            conn.close()
            raise HTTPException(404, "Pedido no encontrado")

        uid = int(r["user_id"])
        cur.execute("UPDATE requests SET estado='rejected' WHERE id=?", (int(rid),))
        conn.commit()
        conn.close()

        notify_user(uid, f"❌ Tu pedido #{rid} fue rechazado. Si necesitas ayuda, abre un ticket o usa el chat.")

        # email si hay
        uemail = (r["email"] or "").strip()
        if not uemail:
            def _get_email():
                c2 = db_conn()
                cu2 = c2.cursor()
                cu2.execute("SELECT COALESCE(email,'') AS email FROM accounts WHERE id=?", (uid,))
                rr2 = cu2.fetchone()
                c2.close()
                return (rr2["email"] or "").strip() if rr2 else ""
            uemail = _retry_sqlite(_get_email)

        if uemail:
            try:
                send_email(
                    uemail,
                    _email_subject(f"Pedido #{rid} rechazado"),
                    _email_order_rejected_body(rid),
                )
            except Exception:
                pass

        admin_log("order_rejected", json.dumps({"rid": rid, "uid": uid}, ensure_ascii=False))

    _retry_sqlite(_do)
    return RedirectResponse(url="/admin/orders", status_code=302)

# =========================
# BUY / RENEW / PAY / VOUCHER  ✅ FULL BLOCK
# =========================

def ensure_requests_schema():
    """
    Asegura que exista la tabla requests y columnas necesarias.
    Evita 500 si la DB está vieja o incompleta.
    """
    def _do():
        conn = db_conn()

        _ensure_table(
            conn,
            """
            CREATE TABLE IF NOT EXISTS requests(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                tipo TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '-',
                cantidad INTEGER NOT NULL DEFAULT 1,
                monto INTEGER NOT NULL DEFAULT 0,
                estado TEXT NOT NULL DEFAULT 'awaiting_voucher',
                created_at TEXT NOT NULL DEFAULT '',
                voucher_path TEXT NOT NULL DEFAULT '',
                voucher_uploaded_at TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                currency TEXT NOT NULL DEFAULT 'DOP',
                target_proxy_id INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT ''
            );
            """
        )

        # Migraciones seguras
        for col, coldef in [
            ("voucher_path", "TEXT NOT NULL DEFAULT ''"),
            ("voucher_uploaded_at", "TEXT NOT NULL DEFAULT ''"),
            ("email", "TEXT NOT NULL DEFAULT ''"),
            ("currency", "TEXT NOT NULL DEFAULT 'DOP'"),
            ("target_proxy_id", "INTEGER NOT NULL DEFAULT 0"),
            ("note", "TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                _ensure_column(conn, "requests", col, coldef)
            except Exception:
                pass

        # Índices útiles
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_user_id ON requests(user_id);")
        except Exception:
            pass
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_estado ON requests(estado);")
        except Exception:
            pass

        conn.commit()
        conn.close()

    _retry_sqlite(_do)


def ensure_proxies_schema():
    """
    Asegura que exista la tabla proxies y columnas necesarias.
    Evita error interno al aprobar pedidos o listar/renovar.
    """
    def _do():
        conn = db_conn()

        _ensure_table(
            conn,
            """
            CREATE TABLE IF NOT EXISTS proxies(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT '',
                inicio TEXT NOT NULL DEFAULT '',
                vence TEXT NOT NULL DEFAULT '',
                estado TEXT NOT NULL DEFAULT 'active',
                raw TEXT NOT NULL DEFAULT ''
            );
            """
        )

        for col, coldef in [
            ("ip", "TEXT NOT NULL DEFAULT ''"),
            ("inicio", "TEXT NOT NULL DEFAULT ''"),
            ("vence", "TEXT NOT NULL DEFAULT ''"),
            ("estado", "TEXT NOT NULL DEFAULT 'active'"),
            ("raw", "TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                _ensure_column(conn, "proxies", col, coldef)
            except Exception:
                pass

        # Índices (mejoran velocidad en listados)
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_proxies_user_id ON proxies(user_id);")
        except Exception:
            pass
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_proxies_user_id_vence ON proxies(user_id, vence);")
        except Exception:
            pass

        conn.commit()
        conn.close()

    _retry_sqlite(_do)


# ---------- BUY (GET) ----------
@app.get("/buy", response_class=HTMLResponse)
@app.get("/buy/", response_class=HTMLResponse)
def client_buy_page(client=Depends(require_client)):
    ensure_requests_schema()

    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/bank">🏦 Ver cuenta</a>
      </div>
      <div class="hr"></div>

      <div class="kpi">🛒 Comprar proxy</div>

      <p class="muted">
        Precio base por proxy: <b>{p1} {html_escape(currency)}</b>
      </p>

      <p class="muted">
        Promo: 5 proxies = <b>800</b> c/u • 10+ proxies = <b>700</b> c/u
      </p>
    </div>

    <div class="grid">
      <div class="card">
        <form method="post" action="/buy">
          <label class="muted">Cantidad</label>
          <input name="cantidad" value="1"/>
          <div style="height:12px;"></div>

          <label class="muted">Gmail para factura (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com"/>
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Crear pedido</button>
        </form>
      </div>

      <div class="card">
        <div class="muted">Cuenta bancaria</div>
        <pre>{html_escape(bank)}</pre>
        <div class="muted">Luego sube tu voucher.</div>
      </div>
    </div>
    """
    return page("Comprar", body, subtitle="Pedido nuevo")


# ---------- BUY (POST) ----------
@app.post("/buy")
@app.post("/buy/")
def client_buy_submit(
    cantidad: str = Form("1"),
    email: str = Form(""),
    client=Depends(require_client),
):
    ensure_requests_schema()

    uid = int(client["uid"])
    email = (email or "").strip()

    try:
        qty = int(float((cantidad or "1").strip()))
    except Exception:
        qty = 1
    if qty <= 0:
        qty = 1
    if qty > 50:
        qty = 50

    p1 = int(float(get_setting("precio_primera", "1500") or 1500))
    currency = get_setting("currency", "DOP")

    if qty >= 10:
        unit = 700
    elif qty >= 5:
        unit = 800
    else:
        unit = p1

    monto = int(unit * qty)

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "buy", "-", qty, monto, "awaiting_voucher", now_str(), email, currency, 0, ""),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        return rid

    rid = _retry_sqlite(_do)
    notify_user(uid, f"🧾 Pedido #{rid} creado por {qty} proxy(s). Sube tu voucher para continuar.")
    admin_log("order_created_buy", json.dumps({"rid": rid, "uid": uid, "qty": qty, "monto": monto}, ensure_ascii=False))
    return RedirectResponse(url=f"/order/{int(rid)}/pay", status_code=302)


# ---------- RENEW (GET) ----------
@app.get("/renew", response_class=HTMLResponse)
@app.get("/renew/", response_class=HTMLResponse)
def client_renew_page(client=Depends(require_client), proxy_id: str = ""):
    ensure_requests_schema()
    ensure_proxies_schema()  # <-- importante para que exista proxies

    pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
    currency = get_setting("currency", "DOP")
    bank = get_setting("bank_details", "")
    uid = int(client["uid"])

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        rows = []
        try:
            cur.execute("SELECT id, ip, vence FROM proxies WHERE user_id=? ORDER BY id DESC LIMIT 300", (uid,))
            rows = cur.fetchall()
        except Exception:
            rows = []
        conn.close()
        return rows

    rows = _retry_sqlite(_do)
    opts = "<option value=''>Selecciona...</option>"
    for r in rows:
        sel = "selected" if proxy_id and str(r["id"]) == str(proxy_id) else ""
        opts += f"<option value='{int(r['id'])}' {sel}>#{int(r['id'])} • {html_escape(r['ip'] or '')} • vence {html_escape(r['vence'] or '')}</option>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/bank">🏦 Ver cuenta</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">♻️ Renovar proxy</div>
      <p class="muted">Renovación: <b>{pr} {html_escape(currency)}</b>. Luego sube el voucher.</p>
    </div>

    <div class="grid">
      <div class="card">
        <form method="post" action="/renew">
          <label class="muted">Proxy a renovar</label>
          <select name="proxy_id">{opts}</select>
          <div style="height:12px;"></div>

          <label class="muted">Gmail para factura (opcional)</label>
          <input name="email" placeholder="tuemail@gmail.com"/>
          <div style="height:12px;"></div>

          <label class="muted">Nota (opcional)</label>
          <input name="note" placeholder="Opcional"/>
          <div style="height:12px;"></div>

          <button class="btn" type="submit">✅ Crear pedido</button>
        </form>
      </div>

      <div class="card">
        <div class="muted">Cuenta bancaria</div>
        <pre>{html_escape(bank)}</pre>
        <div class="muted">Luego sube tu voucher.</div>
      </div>
    </div>
    """
    return page("Renovar", body, subtitle="Renovación")


# ---------- RENEW (POST) ----------
@app.post("/renew")
@app.post("/renew/")
def client_renew_submit(
    proxy_id: str = Form(...),
    email: str = Form(""),
    note: str = Form(""),
    client=Depends(require_client),
):
    ensure_requests_schema()
    ensure_proxies_schema()  # <-- importante

    uid = int(client["uid"])
    email = (email or "").strip()
    note = (note or "").strip()

    try:
        pid = int(proxy_id)
        if pid <= 0:
            raise ValueError()
    except Exception:
        return nice_error_page("Dato inválido", "Selecciona un proxy válido.", "/renew", "↩️ Volver")

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, ip FROM proxies WHERE id=? AND user_id=?", (pid, uid))
        p = cur.fetchone()
        if not p:
            conn.close()
            raise HTTPException(400, "No encontré ese proxy en tu cuenta.")

        pr = int(float(get_setting("precio_renovacion", "1000") or 1000))
        currency = get_setting("currency", "DOP")
        monto = int(pr)

        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "renew", p["ip"] or "-", 1, monto, "awaiting_voucher", now_str(), email, currency, pid, note),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        return rid

    rid = _retry_sqlite(_do)
    notify_user(uid, f"🧾 Pedido #{rid} (renovación) creado. Sube tu voucher para continuar.")
    return RedirectResponse(url=f"/order/{int(rid)}/pay", status_code=302)


# ---------- PAY PAGE ----------
@app.get("/order/{rid}/pay", response_class=HTMLResponse)
@app.get("/order/{rid}/pay/", response_class=HTMLResponse)
def client_order_pay(rid: int, client=Depends(require_client)):
    ensure_requests_schema()

    uid = int(client["uid"])
    bank = get_setting("bank_details", "")
    title = get_setting("bank_title", "Cuenta bancaria")

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id,user_id,tipo,cantidad,monto,estado,created_at,voucher_path,email,currency,target_proxy_id "
            "FROM requests WHERE id=?",
            (int(rid),),
        )
        r = cur.fetchone()
        conn.close()
        return r

    r = _retry_sqlite(_do)
    if not r or int(r["user_id"]) != uid:
        raise HTTPException(404, "Pedido no encontrado.")

    voucher = (r["voucher_path"] or "").strip()
    voucher_block = f"<p class='muted'>Voucher: <a href='/static/{html_escape(voucher)}' target='_blank'>ver</a></p>" if voucher else ""

    extra = ""
    if (r["tipo"] or "") == "renew" and int(r["target_proxy_id"] or 0) > 0:
        extra = f"<p class='muted'>Proxy a renovar: <b>#{int(r['target_proxy_id'])}</b></p>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
      </div>
      <div class="hr"></div>

      <div class="kpi">💳 Pago del pedido #{int(r['id'])}</div>
      <p class="muted">Tipo: <b>{html_escape(r['tipo'] or '')}</b> • Total: <b>{int(r['monto'])} {html_escape(r['currency'] or 'DOP')}</b></p>
      {extra}
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
          <input type="file" name="file" accept="image/*"/>
          <div style="height:12px;"></div>
          <button class="btn" type="submit">📤 Enviar voucher</button>
        </form>
        <p class="muted" style="margin-top:10px;">El admin revisará tu voucher.</p>
      </div>
    </div>
    """
    return page("Pago", body, subtitle="Sube comprobante")


# ---------- UPLOAD VOUCHER ----------
@app.post("/order/{rid}/voucher", response_class=HTMLResponse)
@app.post("/order/{rid}/voucher/", response_class=HTMLResponse)
def client_order_voucher(rid: int, file: UploadFile = File(...), client=Depends(require_client)):
    ensure_requests_schema()

    uid = int(client["uid"])

    if not file or not file.filename:
        return nice_error_page("Archivo inválido", "Debes subir una imagen.", f"/order/{rid}/pay", "↩️ Volver")

    def _check_order():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id,user_id,estado FROM requests WHERE id=?", (int(rid),))
        r = cur.fetchone()
        conn.close()
        return r

    r = _retry_sqlite(_check_order)
    if not r or int(r["user_id"]) != uid:
        raise HTTPException(404, "Pedido no encontrado.")

    estado = (r["estado"] or "").strip()
    if estado not in ("awaiting_voucher", "voucher_received"):
        return nice_error_page("No permitido", f"Este pedido está en estado '{estado}' y no admite voucher.", f"/order/{rid}/pay", "↩️ Volver")

    ext = os.path.splitext(file.filename)[1].lower().strip()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
        ext = ".jpg"

    fname = f"rid{int(rid)}_u{uid}_{secrets.token_hex(8)}{ext}"
    rel_path = os.path.join("vouchers", fname)
    abs_path = os.path.join(UPLOAD_DIR, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    data = file.file.read()
    if not data or len(data) < 200:
        return nice_error_page("Archivo inválido", "La imagen parece corrupta.", f"/order/{rid}/pay", "↩️ Volver")
    if len(data) > 8 * 1024 * 1024:
        return nice_error_page("Archivo grande", "Máximo 8MB.", f"/order/{rid}/pay", "↩️ Volver")

    with open(abs_path, "wb") as f:
        f.write(data)

    def _update():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE requests SET voucher_path=?, voucher_uploaded_at=?, estado=? WHERE id=?",
            (rel_path, now_str(), "voucher_received", int(rid)),
        )
        conn.commit()
        conn.close()

    _retry_sqlite(_update)
    notify_user(uid, f"🧾 Voucher recibido para pedido #{rid}. En revisión.")
    admin_log("voucher_uploaded", json.dumps({"rid": rid, "uid": uid, "path": rel_path}, ensure_ascii=False))
    return nice_error_page("Voucher enviado", "Tu voucher fue subido correctamente.", f"/order/{rid}/pay", "🔎 Ver pedido")


# =========================
# ADMIN: APPROVE / REJECT (necesario para que /admin/orders apruebe)
# =========================

@app.post("/admin/order/{rid}/approve")
@app.post("/admin/order/{rid}/approve/")
def admin_order_approve(rid: int, delivery_raw: str = Form(""), admin=Depends(require_admin)):
    ensure_requests_schema()
    ensure_proxies_schema()

    def _do():
        conn = db_conn()
        cur = conn.cursor()

        cur.execute(
            "SELECT id,user_id,tipo,cantidad,estado,target_proxy_id,note,COALESCE(email,'') AS email "
            "FROM requests WHERE id=?",
            (int(rid),),
        )
        r = cur.fetchone()
        if not r:
            conn.close()
            raise HTTPException(404, "Pedido no encontrado")

        estado = (r["estado"] or "").strip()
        if estado not in ("voucher_received", "awaiting_admin_verify", "awaiting_voucher"):
            conn.close()
            raise HTTPException(400, f"Este pedido está en estado '{estado}' y no se puede aprobar.")

        uid = int(r["user_id"])
        tipo = (r["tipo"] or "").strip()
        qty = int(r["cantidad"] or 0)

        dias = int(float(get_setting("dias_proxy", str(DEFAULT_DIAS_PROXY)) or DEFAULT_DIAS_PROXY))
        if dias <= 0:
            dias = DEFAULT_DIAS_PROXY
        if dias > 30:
            dias = 30

        if tipo == "buy":
            if not _deliver_buy_only_count(qty):
                conn.close()
                raise HTTPException(400, "No hay stock suficiente para este pedido.")
            _deliver_buy_add_proxies(conn, uid, delivery_raw, qty, dias)

        elif tipo == "renew":
            pid = int(r["target_proxy_id"] or 0)
            if pid <= 0:
                conn.close()
                raise HTTPException(400, "Pedido de renovación sin proxy_id.")
            _deliver_renew_extend(conn, uid, pid, dias)

        elif tipo == "claim":
            _deliver_claim_add_proxy(conn, uid, r["note"] or "")

        else:
            conn.close()
            raise HTTPException(400, f"Tipo desconocido: {tipo}")

        cur.execute("UPDATE requests SET estado='approved' WHERE id=?", (int(rid),))
        conn.commit()
        conn.close()

        notify_user(uid, f"✅ Tu pedido #{rid} fue aprobado.")
        uemail = (r["email"] or "").strip()
        if uemail:
            try:
                send_email(
                    uemail,
                    f"✅ Pedido #{rid} aprobado • {APP_TITLE}",
                    f"Hola,\n\nTu pedido #{rid} fue aprobado.\n\nGracias,\n{APP_TITLE}\n",
                )
            except Exception:
                pass

        admin_log("order_approved", json.dumps({"rid": rid, "uid": uid, "tipo": tipo}, ensure_ascii=False))

    _retry_sqlite(_do)
    return RedirectResponse(url="/admin/orders", status_code=302)


@app.post("/admin/order/{rid}/reject")
@app.post("/admin/order/{rid}/reject/")
def admin_order_reject(rid: int, admin=Depends(require_admin)):
    ensure_requests_schema()

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id,user_id,estado FROM requests WHERE id=?", (int(rid),))
        r = cur.fetchone()
        if not r:
            conn.close()
            raise HTTPException(404, "Pedido no encontrado")

        uid = int(r["user_id"])
        cur.execute("UPDATE requests SET estado='rejected' WHERE id=?", (int(rid),))
        conn.commit()
        conn.close()

        notify_user(uid, f"❌ Tu pedido #{rid} fue rechazado. Si necesitas ayuda, abre un ticket o usa el chat.")
        admin_log("order_rejected", json.dumps({"rid": rid, "uid": uid}, ensure_ascii=False))

    _retry_sqlite(_do)
    return RedirectResponse(url="/admin/orders", status_code=302)



# =========================
# CLIENT: ADD EXISTING (CLAIM)
# =========================
@app.get("/add-existing", response_class=HTMLResponse)
def client_add_existing_page(client=Depends(require_client)):
    body = """
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/chat" style="margin-left:auto;">💬 Chat</a>
      </div>
      <div class="hr"></div>

      <div class="kpi">➕ Agregar proxy existente</div>
      <p class="muted">Envía la solicitud para que el admin la verifique y te la active.</p>
    </div>

    <div class="card">
      <form method="post" action="/add-existing">
        <label class="muted">IP (opcional si pegas raw)</label>
        <input name="ip" placeholder="ip:port"/>
        <div style="height:12px;"></div>

        <label class="muted">RAW (recomendado)</label>
        <textarea name="raw" placeholder="HTTP\\nip:port:user:pass"></textarea>
        <div style="height:12px;"></div>

        <label class="muted">Vence (opcional) formato: YYYY-MM-DD HH:MM:SS</label>
        <input name="vence" placeholder="2026-03-01 10:00:00"/>
        <div style="height:12px;"></div>

        <button class="btn" type="submit">📨 Enviar solicitud</button>
      </form>
    </div>
    """
    return page("Agregar proxy", body, subtitle="Verificación por admin")

@app.post("/add-existing", response_class=HTMLResponse)
def client_add_existing_submit(ip: str = Form(""), raw: str = Form(""), vence: str = Form(""), client=Depends(require_client)):
    ensure_requests_schema()

    uid = int(client["uid"])
    ip = (ip or "").strip()
    raw = (raw or "").strip()
    vence = (vence or "").strip()

    if not ip and not raw:
        return nice_error_page("Faltan datos", "Debes poner IP o pegar el RAW.", "/add-existing", "↩️ Volver")

    payload = {"ip": ip, "raw": raw, "vence": vence}
    note = json.dumps(payload, ensure_ascii=False)

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at,email,currency,target_proxy_id,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, "claim", ip or "-", 1, 0, "awaiting_admin_verify", now_str(), "", get_setting("currency", "DOP"), 0, note),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        return rid

    rid = _retry_sqlite(_do)
    notify_user(uid, f"📨 Solicitud #{rid} enviada. El admin la revisará.")
    admin_log("claim_proxy_request", json.dumps({"rid": rid, "uid": uid}, ensure_ascii=False))
    return nice_error_page("Solicitud enviada", f"Solicitud #{rid} enviada. El admin la revisará.", "/me", "⬅️ Volver al panel")




# =========================
# SUPPORT (TICKETS)
# =========================
@app.get("/support", response_class=HTMLResponse)
def support_page(request: Request):
    c = try_client(request)
    if not c:
        return RedirectResponse(url="/client/login", status_code=302)

    uid = int(c["uid"])

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id,subject,message,admin_reply,status,created_at FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 20",
            (uid,),
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    rows = _retry_sqlite(_do)

    hist = ""
    for t in rows:
        reply = (t["admin_reply"] or "").strip()
        reply_block = f"<div class='muted'><b>Agente:</b></div><pre>{html_escape(reply)}</pre>" if reply else "<div class='muted'>Aún sin respuesta.</div>"
        hist += f"""
        <div class="card" style="margin-bottom:12px;">
          <div class="muted">Ticket #{int(t['id'])} • {html_escape(t['created_at'] or '')} • {html_escape(t['status'] or '')}</div>
          <div><b>{html_escape(t['subject'] or 'Soporte')}</b></div>
          <pre>{html_escape(t['message'] or '')}</pre>
          {reply_block}
        </div>
        """
    if not hist:
        hist = "<div class='card'><p class='muted'>Aún no has creado tickets.</p></div>"

    body = f"""
    <div class="card">
      <div class="row">
        <a class="btn ghost" href="/me">⬅️ Volver</a>
        <a class="btn ghost" href="/chat" style="margin-left:auto;">💬 Chat</a>
      </div>
      <div class="hr"></div>
      <div class="kpi">💬 Soporte</div>
      <p class="muted">Crea un ticket y te respondemos.</p>
    </div>

    <div class="card">
      <form method="post" action="/support">
        <label class="muted">Asunto (opcional)</label>
        <input name="subject" placeholder="Ej: No puedo conectar"/>
        <div style="height:12px;"></div>

        <label class="muted">Mensaje</label>
        <textarea name="message" placeholder="Escribe aquí..."></textarea>
        <div style="height:12px;"></div>
        <button class="btn" type="submit">📨 Enviar ticket</button>
      </form>
    </div>

    <h3 style="margin:18px 0 10px 0;">📜 Historial</h3>
    {hist}
    """
    return page("Soporte", body, subtitle=f"Cliente #{uid}")

@app.post("/support", response_class=HTMLResponse)
def support_submit(request: Request, subject: str = Form(""), message: str = Form(...)):
    c = try_client(request)
    if not c:
        return RedirectResponse(url="/client/login", status_code=302)

    uid = int(c["uid"])
    msg = (message or "").strip()
    subj = (subject or "").strip()
    if len(msg) < 5:
        return nice_error_page("Mensaje corto", "Escribe un mensaje más largo.", "/support", "↩️ Volver")

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tickets(user_id,subject,message,admin_reply,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (uid, subj, msg, "", "open", now_str(), now_str()),
        )
        conn.commit()
        tid = cur.lastrowid
        conn.close()
        return tid

    tid = _retry_sqlite(_do)
    outbox_add("ticket_new", json.dumps({"ticket_id": tid, "user_id": uid}, ensure_ascii=False))
    notify_user(uid, f"💬 Ticket #{tid} creado. Un agente te responderá pronto.")
    admin_log("ticket_new", json.dumps({"tid": tid, "uid": uid}, ensure_ascii=False))

    return nice_error_page("Ticket enviado", f"Tu ticket #{tid} fue creado. Te responderemos pronto.", "/support", "📜 Ver soporte")


# =========================
# API helpers
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

    def _do():
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, kind, message, created_at, sent_at FROM outbox ORDER BY id DESC LIMIT 50")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    rows = _retry_sqlite(_do)
    return {"enabled": True, "items": rows}
