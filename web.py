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
      font-size: 34px; font-weight: 900; margin-top: 6p
