# bot.py — Gproxy PRO FINAL (PTB 20.7) ✅ NO-REQUESTS ✅ NO-JOBQUEUE SAFE
# ✅ Panel Admin PRO funcional + FIX DB MIGRATIONS + FIX KEYBOARD MERGE
# ✅ Cliente: comprar/renovar/registrar + tickets + cancelación
# ✅ Compra sin FIN (auto-cierre por qty)
# ✅ MODO MANTENIMIENTO (Admin ON/OFF + mensaje personalizado + broadcast)
# ✅ Se removió IA (Groq) para simplificar

import logging
import sqlite3
import random
import string
import re
import os
import asyncio
from datetime import datetime, timedelta, time
from typing import Optional, Tuple, List, Dict, Any

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

import config

# ---------------- Logging ----------------
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger("gproxy")
print("🔧 Iniciando Gproxy BOT (PRO FINAL + MANTENIMIENTO + IA REMOVIDA)...")

# ---------------- Database ----------------
DB = os.getenv("DB_PATH", "data.db")
conn = sqlite3.connect(DB, check_same_thread=False)



def ensure_schema():
    # Crea tablas si no existen
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS proxies(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            raw TEXT NOT NULL DEFAULT '',
            inicio TEXT NOT NULL,
            vence TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'activa'
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            cantidad INTEGER NOT NULL DEFAULT 1,
            monto INTEGER NOT NULL DEFAULT 0,
            estado TEXT NOT NULL DEFAULT 'awaiting_voucher',
            created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS delete_tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            proxy_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL DEFAULT '',
            is_blocked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT ''
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mensaje TEXT NOT NULL DEFAULT '',
            estado TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ticket_messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            sender TEXT NOT NULL, -- 'user' o 'admin'
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    # ✅ SETTINGS para mantenimiento / mensajes
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
        """
    )

    conn.commit()

    # ---- Migraciones HARDENED: arregla DB vieja aunque le falten columnas ----
    def ensure_column(table: str, col: str, coldef: str):
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [r[1] for r in cursor.fetchall()]
        if col not in cols:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coldef}")
                conn.commit()
                logger.info("DB MIGRATION: Added column %s.%s", table, col)
            except Exception as e:
                logger.warning("DB MIGRATION FAILED %s.%s: %s", table, col, e)

    # requests
    ensure_column("requests", "cantidad", "INTEGER NOT NULL DEFAULT 1")
    ensure_column("requests", "monto", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("requests", "estado", "TEXT NOT NULL DEFAULT 'awaiting_voucher'")
    ensure_column("requests", "ip", "TEXT NOT NULL DEFAULT ''")
    ensure_column("requests", "created_at", "TEXT NOT NULL DEFAULT ''")

    # proxies
    ensure_column("proxies", "estado", "TEXT NOT NULL DEFAULT 'activa'")
    ensure_column("proxies", "raw", "TEXT NOT NULL DEFAULT ''")

    # delete_tokens
    ensure_column("delete_tokens", "attempts", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("delete_tokens", "estado", "TEXT NOT NULL DEFAULT 'pending'")

    # tickets (por si DB vieja)
    ensure_column("tickets", "estado", "TEXT NOT NULL DEFAULT 'open'")
    ensure_column("tickets", "mensaje", "TEXT NOT NULL DEFAULT ''")
    ensure_column("tickets", "created_at", "TEXT NOT NULL DEFAULT ''")
    ensure_column("tickets", "updated_at", "TEXT NOT NULL DEFAULT ''")

    conn.commit()


ensure_schema()

# ---------------- Helpers ----------------
def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def date_str(d: datetime) -> str:
    return d.strftime("%Y-%m-%d")


def days_left(vence: str) -> int:
    try:
        v = datetime.strptime(vence, "%Y-%m-%d")
        return (v - datetime.now()).days
    except Exception:
        return 0


def add_days_from(base_date: datetime, days: int) -> str:
    return date_str(base_date + timedelta(days=days))


def gen_code(n=6) -> str:
    return "".join(random.choice(string.digits) for _ in range(n))


def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default


def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def bank_text() -> str:
    return (
        f"🏦 Banreservas\n"
        f"Cuenta: {config.CUENTA_BANRESERVAS}\n"
        f"Nombre: {config.NOMBRE_CUENTA}\n"
    )



def add_http_header(raw_block: str) -> str:
    b = (raw_block or "").strip()
    if not b:
        return b
    first = b.splitlines()[0].strip().upper()
    if first == "HTTP":
        return b
    return "HTTP\n" + b


def is_valid_proxy_line(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    if "@" in s:
        left, right = s.split("@", 1)
        return (":" in left) and (":" in right)
    return ":" in s


def looks_like_ip_only(line: str) -> bool:
    line = (line or "").strip()
    return bool(re.fullmatch(r"[0-9.]{7,}", line))


def extract_port_from_block(block: str) -> str:
    for ln in (block or "").splitlines():
        m = re.search(r"^\s*(port|puerto)\s*:\s*([0-9]{1,6})\s*$", ln.strip(), re.IGNORECASE)
        if m:
            return m.group(2)
    return ""


def parse_admin_blocks(text: str) -> List[Dict[str, str]]:
    """
    Admin puede pegar:
      A) 1 línea: ip:port o user:pass@ip:port
      B) 4 líneas:
         ip
         port:xxx
         user:yyy
         pass:zzz

    Devuelve lista: {"raw": bloque, "key": ip:port o línea}
    """
    t = (text or "").strip()
    if not t:
        return []

    lines = [ln.rstrip() for ln in t.splitlines()]
    cleaned = []
    for ln in lines:
        if ln.strip() == "" and (not cleaned or cleaned[-1].strip() == ""):
            continue
        cleaned.append(ln)
    lines = cleaned

    blocks: List[str] = []
    current: List[str] = []

    def flush():
        nonlocal current
        if current:
            blocks.append("\n".join(current).strip())
            current = []

    for ln in lines:
        if ln.strip() == "":
            flush()
            continue

        if is_valid_proxy_line(ln) and ("port:" not in ln.lower()) and ("user:" not in ln.lower()) and ("pass:" not in ln.lower()):
            flush()
            blocks.append(ln.strip())
            continue

        if looks_like_ip_only(ln) and current:
            flush()

        current.append(ln.strip())

    flush()

    out: List[Dict[str, str]] = []
    for b in blocks:
        b2 = b.strip()
        if not b2:
            continue
        if is_valid_proxy_line(b2) and ("\n" not in b2):
            key = b2.strip()
        else:
            first = b2.splitlines()[0].strip()
            port = extract_port_from_block(b2)
            key = f"{first}:{port}" if port else first
        out.append({"raw": b2, "key": key})
    return out


# ✅ FIX UNIVERSAL: merge keyboards aunque PTB devuelva tuple
def kb_merge(*parts) -> InlineKeyboardMarkup:
    rows: List[List[InlineKeyboardButton]] = []
    for p in parts:
        if not p:
            continue
        if isinstance(p, InlineKeyboardMarkup):
            rows.extend([list(r) for r in p.inline_keyboard])
        elif isinstance(p, (list, tuple)):
            rows.extend([list(r) for r in p])
    return InlineKeyboardMarkup(rows)


# ---------------- Users helpers ----------------
def upsert_user(user_id: int, username: str):
    uname = (username or "").strip()
    cursor.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute("UPDATE users SET username=?, last_seen=? WHERE user_id=?", (uname, now_str(), user_id))
    else:
        cursor.execute(
            "INSERT INTO users(user_id, username, is_blocked, created_at, last_seen) VALUES(?,?,?,?,?)",
            (user_id, uname, 0, now_str(), now_str()),
        )
    conn.commit()


def is_blocked_user(user_id: int) -> bool:
    cursor.execute("SELECT is_blocked FROM users WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    return bool(row and int(row[0]) == 1)


def set_block_user(user_id: int, blocked: bool):
    cursor.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    if not row:
        cursor.execute(
            "INSERT INTO users(user_id, username, is_blocked, created_at, last_seen) VALUES(?,?,?,?,?)",
            (user_id, "", 1 if blocked else 0, now_str(), now_str()),
        )
    else:
        cursor.execute(
            "UPDATE users SET is_blocked=?, last_seen=? WHERE user_id=?",
            (1 if blocked else 0, now_str(), user_id),
        )
    conn.commit()


# ---------------- Settings / Maintenance ----------------
def get_setting(key: str, default: str = "") -> str:
    cursor.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cursor.fetchone()
    return row[0] if row and row[0] is not None else default


def set_setting(key: str, value: str):
    cursor.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, str(value)))
    conn.commit()


def maintenance_is_on() -> bool:
    return get_setting("maintenance", "0") == "1"


def set_maintenance(on: bool):
    set_setting("maintenance", "1" if on else "0")


def maint_message_default(on: bool) -> str:
    if on:
        return "🛠 Estamos en mantenimiento ahora mismo.\nVolvemos en breve. Gracias por tu paciencia 🙏"
    return "✅ Mantenimiento finalizado.\nYa puedes usar el bot normal. Gracias por esperar 🙌"


def get_all_user_ids() -> List[int]:
    cursor.execute("SELECT user_id FROM users WHERE is_blocked=0")
    return [int(r[0]) for r in cursor.fetchall()]


async def broadcast_to_all_users(context: ContextTypes.DEFAULT_TYPE, text: str) -> Tuple[int, int]:
    ok = 0
    fail = 0
    for uid in get_all_user_ids():
        try:
            await context.bot.send_message(chat_id=uid, text=text)
            ok += 1
        except Exception:
            fail += 1
        await asyncio.sleep(0.05)
    return ok, fail


# ---------------- Money helpers ----------------
def calc_purchase_amount(cantidad: int) -> int:
    return cantidad * int(config.PRECIO_PRIMERA)


def calc_renew_amount(cantidad: int) -> int:
    return cantidad * int(config.PRECIO_RENOVACION)


# ---------------- Requests / Proxies ----------------
PENDING_STATES = ("awaiting_voucher", "voucher_received", "awaiting_admin_verify")


def create_request(user_id: int, tipo: str, ip: str = "", cantidad: int = 1, monto: int = 0, estado: str = "awaiting_voucher") -> int:
    cursor.execute(
        """
        INSERT INTO requests(user_id,tipo,ip,cantidad,monto,estado,created_at)
        VALUES(?,?,?,?,?,?,?)
        """,
        (user_id, tipo, ip or "", int(cantidad), int(monto), estado, now_str()),
    )
    conn.commit()
    return cursor.lastrowid


def get_request(req_id: int) -> Optional[Tuple]:
    cursor.execute("SELECT id,user_id,tipo,ip,cantidad,monto,estado,created_at FROM requests WHERE id=?", (req_id,))
    return cursor.fetchone()


def set_request_state(req_id: int, estado: str):
    cursor.execute("UPDATE requests SET estado=? WHERE id=?", (estado, req_id))
    conn.commit()


def get_latest_request_waiting_voucher(user_id: int) -> Optional[Tuple]:
    cursor.execute(
        """
        SELECT id,user_id,tipo,ip,cantidad,monto,estado,created_at
        FROM requests
        WHERE user_id=? AND estado='awaiting_voucher'
        ORDER BY id DESC LIMIT 1
        """,
        (user_id,),
    )
    return cursor.fetchone()


def user_pending_count(user_id: int) -> int:
    cursor.execute(
        "SELECT COUNT(*) FROM requests WHERE user_id=? AND estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')",
        (user_id,),
    )
    return cursor.fetchone()[0]


def has_pending_request_for_ip(user_id: int, ip: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) FROM requests
        WHERE user_id=? AND ip=? AND estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')
        """,
        (user_id, ip),
    )
    return cursor.fetchone()[0] > 0


def upsert_proxy_for_user(user_id: int, ip: str, raw: str, new_vence: str) -> int:
    cursor.execute("SELECT id FROM proxies WHERE user_id=? AND ip=?", (user_id, ip))
    row = cursor.fetchone()
    inicio = date_str(datetime.now())

    if row:
        pid = int(row[0])
        cursor.execute(
            "UPDATE proxies SET raw=?, inicio=?, vence=?, estado='activa' WHERE id=?",
            (raw, inicio, new_vence, pid),
        )
    else:
        cursor.execute(
            "INSERT INTO proxies(user_id,ip,raw,inicio,vence,estado) VALUES(?,?,?,?,?,?)",
            (user_id, ip, raw, inicio, new_vence, "activa"),
        )
        pid = int(cursor.lastrowid)

    conn.commit()
    return pid


def renew_proxy(user_id: int, ip: str) -> str:
    cursor.execute("SELECT vence FROM proxies WHERE user_id=? AND ip=?", (user_id, ip))
    row = cursor.fetchone()
    base = datetime.now()
    if row:
        try:
            old = datetime.strptime(row[0], "%Y-%m-%d")
            if old > base:
                base = old
        except Exception:
            pass
    new_vence = add_days_from(base, int(config.DIAS_PROXY))

    cursor.execute("SELECT raw FROM proxies WHERE user_id=? AND ip=?", (user_id, ip))
    r2 = cursor.fetchone()
    raw = (r2[0] if r2 and r2[0] else f"HTTP\n{ip}").strip()
    raw = add_http_header(raw)

    upsert_proxy_for_user(user_id, ip, raw, new_vence)
    return new_vence


def activate_new_proxy(user_id: int, key: str, raw: str) -> Tuple[int, str, str]:
    inicio = date_str(datetime.now())
    vence = add_days_from(datetime.now(), int(config.DIAS_PROXY))
    pid = upsert_proxy_for_user(user_id, key, raw, vence)
    return pid, inicio, vence


def get_user_proxies(user_id: int) -> List[Tuple]:
    cursor.execute("SELECT id, ip, raw, inicio, vence, estado FROM proxies WHERE user_id=? ORDER BY id DESC", (user_id,))
    return cursor.fetchall()


# ---------------- Tickets helpers ----------------
def create_ticket(user_id: int, mensaje: str) -> int:
    cursor.execute(
        "INSERT INTO tickets(user_id, mensaje, estado, created_at, updated_at) VALUES(?,?,?,?,?)",
        (user_id, mensaje or "", "open", now_str(), now_str()),
    )
    conn.commit()
    tid = cursor.lastrowid
    cursor.execute(
        "INSERT INTO ticket_messages(ticket_id, sender, message, created_at) VALUES(?,?,?,?)",
        (tid, "user", mensaje or "", now_str()),
    )
    conn.commit()
    return tid


def add_ticket_message(ticket_id: int, sender: str, message: str):
    cursor.execute(
        "INSERT INTO ticket_messages(ticket_id, sender, message, created_at) VALUES(?,?,?,?)",
        (ticket_id, sender, message, now_str()),
    )
    cursor.execute("UPDATE tickets SET updated_at=? WHERE id=?", (now_str(), ticket_id))
    conn.commit()


def close_ticket(ticket_id: int):
    cursor.execute("UPDATE tickets SET estado='closed', updated_at=? WHERE id=?", (now_str(), ticket_id))
    conn.commit()


def get_ticket(ticket_id: int) -> Optional[Tuple]:
    cursor.execute("SELECT id, user_id, mensaje, estado, created_at, updated_at FROM tickets WHERE id=?", (ticket_id,))
    return cursor.fetchone()


def get_ticket_messages(ticket_id: int, limit: int = 12) -> List[Tuple]:
    cursor.execute(
        """
        SELECT sender, message, created_at
        FROM ticket_messages
        WHERE ticket_id=?
        ORDER BY id DESC
        LIMIT ?
        """,
        (ticket_id, limit),
    )
    rows = cursor.fetchall()
    rows.reverse()
    return rows


# ---------------- Keyboards ----------------
def reply_menu(is_admin: bool = False) -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton("🛒 Pedir proxies nuevos"), KeyboardButton("📋 Mis proxies")],
        [KeyboardButton("♻️ Registrar proxy existente"), KeyboardButton("🔄 Renovar proxy existente")],
        [KeyboardButton("🧾 Mis pedidos"), KeyboardButton("❌ Cancelar pedido")],
        [KeyboardButton("🎫 Soporte (Ticket)")],
        [KeyboardButton("🆘 Contacto de emergencia")],
    ]
    if is_admin:
        rows.append([KeyboardButton("📊 Panel Admin")])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)


def inline_contact_admin():
    return InlineKeyboardMarkup([[InlineKeyboardButton("🆘 Hablar con soporte (Admin)", url=f"tg://user?id={config.ADMIN_ID}")]])


def admin_panel_kb():
    maint = "🛠 Mantenimiento: ON" if maintenance_is_on() else "🛠 Mantenimiento: OFF"
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🏠 Dashboard", callback_data="admin_dash")],
            [InlineKeyboardButton("👥 Usuarios", callback_data="admin_users_0"), InlineKeyboardButton("📦 Proxies", callback_data="admin_proxies_menu")],
            [InlineKeyboardButton("📨 Pedidos", callback_data="admin_orders_menu"), InlineKeyboardButton("🎫 Tickets", callback_data="admin_tickets_0")],
            [InlineKeyboardButton("🔍 Buscar", callback_data="admin_search")],
            [InlineKeyboardButton(maint, callback_data="admin_maint_menu")],
        ]
    )


def admin_maint_menu_kb():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("✅ Activar mantenimiento", callback_data="admin_maint_on")],
            [InlineKeyboardButton("🟢 Desactivar mantenimiento", callback_data="admin_maint_off")],
            [InlineKeyboardButton("✍️ Mensaje personalizado (Activar)", callback_data="admin_maint_msg_on")],
            [InlineKeyboardButton("✍️ Mensaje personalizado (Desactivar)", callback_data="admin_maint_msg_off")],
            [InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")],
        ]
    )


def admin_orders_menu_kb():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⏳ Awaiting voucher", callback_data="admin_orders_awaiting_voucher_0")],
            [InlineKeyboardButton("💳 Voucher received", callback_data="admin_orders_voucher_received_0")],
            [InlineKeyboardButton("🧾 Verify IP (registro)", callback_data="admin_orders_awaiting_admin_verify_0")],
            [InlineKeyboardButton("✅ Approved", callback_data="admin_orders_approved_0")],
            [InlineKeyboardButton("❌ Rejected", callback_data="admin_orders_rejected_0")],
            [InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")],
        ]
    )


def admin_proxies_menu_kb():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⚠️ Por vencer (≤7 días)", callback_data="admin_expiring_0")],
            [InlineKeyboardButton("📂 Últimas 50", callback_data="admin_proxies_last50_0")],
            [InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")],
        ]
    )


def admin_users_page_kb(user_ids: List[int], page: int, has_next: bool):
    rows = [[InlineKeyboardButton(f"👤 {uid}", callback_data=f"admin_user_{uid}")] for uid in user_ids]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_users_{page-1}"))
    if has_next:
        nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_users_{page+1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def admin_user_detail_kb(user_id: int, is_blocked: bool):
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📦 Ver proxies", callback_data=f"admin_user_proxies_{user_id}_0"),
             InlineKeyboardButton("📨 Ver pedidos", callback_data=f"admin_user_orders_{user_id}_0")],
            [InlineKeyboardButton("🚫 Bloquear" if not is_blocked else "✅ Desbloquear", callback_data=f"admin_user_toggleblock_{user_id}"),
             InlineKeyboardButton("🗑 Eliminar usuario", callback_data=f"admin_user_del_{user_id}")],
            [InlineKeyboardButton("⬅️ Usuarios", callback_data="admin_users_0")],
            [InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")],
        ]
    )


def admin_user_delete_confirm_kb(user_id: int):
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("✅ CONFIRMAR ELIMINAR", callback_data=f"admin_user_del_confirm_{user_id}"),
             InlineKeyboardButton("❌ Cancelar", callback_data=f"admin_user_{user_id}")]
        ]
    )


def admin_user_proxies_page_kb(user_id: int, page: int, has_next: bool):
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_user_proxies_{user_id}_{page-1}"))
    if has_next:
        nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_user_proxies_{user_id}_{page+1}"))
    rows = []
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Usuario", callback_data=f"admin_user_{user_id}")])
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def admin_user_orders_page_kb(user_id: int, page: int, has_next: bool):
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_user_orders_{user_id}_{page-1}"))
    if has_next:
        nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_user_orders_{user_id}_{page+1}"))
    rows = []
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Usuario", callback_data=f"admin_user_{user_id}")])
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def admin_proxy_detail_kb(proxy_id: int, owner_id: int):
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🗑 Eliminar proxy", callback_data=f"admin_delproxy_{proxy_id}"),
             InlineKeyboardButton("👤 Ver usuario", callback_data=f"admin_user_{owner_id}")],
            [InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")],
        ]
    )


def admin_expiring_page_kb(page: int, has_next: bool):
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_expiring_{page-1}"))
    if has_next:
        nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_expiring_{page+1}"))
    rows = []
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Proxies", callback_data="admin_proxies_menu")])
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def admin_orders_page_kb(state: str, page: int, has_next: bool):
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_orders_{state}_{page-1}"))
    if has_next:
        nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_orders_{state}_{page+1}"))
    rows = []
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Pedidos", callback_data="admin_orders_menu")])
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def admin_order_detail_kb(req_id: int, user_id: int, estado: str):
    rows = []
    if estado in ("voucher_received", "awaiting_admin_verify", "awaiting_voucher"):
        rows.append([InlineKeyboardButton("✅ Aprobar", callback_data=f"admin_approve_{req_id}"),
                     InlineKeyboardButton("❌ Rechazar", callback_data=f"admin_reject_{req_id}")])
    rows.append([InlineKeyboardButton("👤 Ver usuario", callback_data=f"admin_user_{user_id}")])
    rows.append([InlineKeyboardButton("⬅️ Pedidos", callback_data="admin_orders_menu")])
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def client_proxy_actions_kb(proxy_id: int):
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔄 Renovar", callback_data=f"proxy_renew_{proxy_id}"),
          InlineKeyboardButton("🗑 Eliminar", callback_data=f"proxy_delete_{proxy_id}")]]
    )


def client_register_choice_kb(ip: str):
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(f"🔄 Renovar {config.PRECIO_RENOVACION} DOP", callback_data=f"client_reg_renew_{ip}")],
         [InlineKeyboardButton("❌ Cancelar", callback_data=f"client_reg_cancel_{ip}")]]
    )


def client_cancel_request_kb(req_id: int):
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancelar este pedido", callback_data=f"client_cancelreq_{req_id}")]])


def admin_ticket_detail_kb(ticket_id: int, user_id: int, estado: str):
    rows = []
    if estado == "open":
        rows.append([InlineKeyboardButton("✉️ Responder", callback_data=f"admin_ticket_reply_{ticket_id}")])
        rows.append([InlineKeyboardButton("✅ Cerrar ticket", callback_data=f"admin_ticket_close_{ticket_id}")])
    rows.append([InlineKeyboardButton("👤 Ver usuario", callback_data=f"admin_user_{user_id}")])
    rows.append([InlineKeyboardButton("⬅️ Tickets", callback_data="admin_tickets_0")])
    rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


# ---------------- Runtime state ----------------
admin_send_state: Dict[int, Dict[str, Any]] = {}  # admin_id -> {"req_id","user_id","cantidad","received"}


# ---------------- Gate ----------------
def is_user_blocked_gate(user_id: int, is_admin: bool) -> bool:
    if is_admin:
        return False
    return is_blocked_user(user_id)


# ---------------- Core handlers ----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    is_admin = user.id == config.ADMIN_ID
    upsert_user(user.id, user.username or "")

    if is_user_blocked_gate(user.id, is_admin):
        await update.message.reply_text("⛔ Tu acceso está bloqueado.\nUsa 🆘 Contacto de emergencia.", reply_markup=reply_menu(is_admin))
        return

    # Si está en mantenimiento, se lo mostramos al cliente
    if (not is_admin) and maintenance_is_on():
        await update.message.reply_text(get_setting("maint_msg_on", maint_message_default(True)), reply_markup=reply_menu(False))
        return

    text = config.WELCOME_MESSAGE.format(precio_primera=config.PRECIO_PRIMERA, precio_renovacion=config.PRECIO_RENOVACION,dias_proxy=config.DIAS_PROXY)
    await update.message.reply_text(text, reply_markup=reply_menu(is_admin))


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    text = (update.message.text or "").strip()
    is_admin = user.id == config.ADMIN_ID
    upsert_user(user.id, user.username or "")

    # 🛠 Mantenimiento (solo afecta clientes)
    if (not is_admin) and maintenance_is_on():
        await update.message.reply_text(get_setting("maint_msg_on", maint_message_default(True)), reply_markup=reply_menu(False))
        return

    # ADMIN flows (search / ticket_reply / maint_msg)
    admin_flow = context.user_data.get("admin_flow")

    # ✅ Captura de mensaje personalizado para mantenimiento
    if is_admin and isinstance(admin_flow, tuple) and admin_flow and admin_flow[0] == "maint_msg":
        _, mode = admin_flow
        if text.upper() == "CANCELAR":
            context.user_data.pop("admin_flow", None)
            await update.message.reply_text("✅ Cancelado.", reply_markup=admin_panel_kb())
            return
        key = "maint_msg_on" if mode == "on" else "maint_msg_off"
        set_setting(key, text.strip())
        context.user_data.pop("admin_flow", None)
        await update.message.reply_text(
            f"✅ Mensaje guardado para {'ACTIVAR' if mode=='on' else 'DESACTIVAR'} mantenimiento.",
            reply_markup=admin_panel_kb(),
        )
        return

    if is_admin and isinstance(admin_flow, tuple) and admin_flow and admin_flow[0] == "ticket_reply":
        _, ticket_id = admin_flow
        context.user_data.pop("admin_flow", None)

        t = get_ticket(ticket_id)
        if not t:
            await update.message.reply_text("Ticket no encontrado.", reply_markup=admin_panel_kb())
            return

        tid, uid, _, estado, _, _ = t
        if estado != "open":
            await update.message.reply_text("Ese ticket ya está cerrado.", reply_markup=admin_panel_kb())
            return

        reply_msg = text.strip()
        if not reply_msg:
            await update.message.reply_text("Escribe un mensaje válido.")
            return

        add_ticket_message(tid, "admin", reply_msg)

        try:
            await context.bot.send_message(
                chat_id=uid,
                text=f"📩 Respuesta de soporte (Ticket #{tid}):\n\n{reply_msg}\n\nSi necesitas más ayuda, responde aquí o abre otro ticket.",
            )
        except Exception:
            pass

        await update.message.reply_text(f"✅ Respondido Ticket #{tid}.", reply_markup=admin_panel_kb())
        return

    if is_admin and admin_flow == "search":
        context.user_data.pop("admin_flow", None)
        q = text.strip()
        if q.isdigit():
            await admin_show_user_detail(update.message, int(q))
        else:
            await admin_search_chat(update.message, q)
        return

    # ADMIN: pegado de proxies (compra aprobada) -> SIN FIN obligatorio
    if is_admin and user.id in admin_send_state:
        st = admin_send_state[user.id]
        if text.upper() == "FIN":
            try:
                await context.bot.send_message(chat_id=st["user_id"], text="✅ Tu pedido fue cerrado por el admin. Ve a 📋 Mis proxies.")
            except Exception:
                pass
            await update.message.reply_text("✅ Proceso cerrado (FIN).", reply_markup=admin_panel_kb())
            admin_send_state.pop(user.id, None)
            return

        blocks = parse_admin_blocks(text)
        if not blocks:
            await update.message.reply_text(
                "⚠️ No vi proxies válidas.\n"
                "Pega así:\n"
                "• ip:port\n"
                "• user:pass@ip:port\n"
                "• o 4 líneas ip/port/user/pass\n\n"
                "TIP: No necesitas FIN. Cuando llegue al límite, se cierra solo.",
            )
            return

        added = 0
        sent = 0
        for item in blocks:
            if st["received"] >= st["cantidad"]:
                break
            raw_block = add_http_header(item["raw"])
            key = item["key"]
            pid, inicio, vence = activate_new_proxy(st["user_id"], key, raw_block)
            st["received"] += 1
            added += 1

            msg = (
                "✅ <b>Gproxy — Proxy asignada</b>\n\n"
                f"👤 <b>Cliente ID:</b> <code>{st['user_id']}</code>\n"
                f"🧾 <b>Proxy ID:</b> <code>{pid}</code>\n\n"
                f"🌐 <b>Proxy:</b>\n<pre>{html_escape(raw_block)}</pre>\n"
                f"📅 <b>Inicio:</b> {inicio}\n"
                f"⏳ <b>Vence:</b> {vence} (quedan {days_left(vence)} días)\n"
            )
            try:
                await context.bot.send_message(chat_id=st["user_id"], text=msg, parse_mode="HTML")
                sent += 1
            except Exception:
                pass

        await update.message.reply_text(f"✅ Guardadas {added}. Enviadas {sent}. Total {st['received']}/{st['cantidad']}.")

        if st["received"] >= st["cantidad"]:
            try:
                await context.bot.send_message(chat_id=st["user_id"], text="✅ Pedido completado. Ve a 📋 Mis proxies.")
            except Exception:
                pass
            await update.message.reply_text("✅ Pedido completado (auto-cierre).", reply_markup=admin_panel_kb())
            admin_send_state.pop(user.id, None)
        return

    # Bloqueado
    if is_user_blocked_gate(user.id, is_admin):
        if text == "🆘 Contacto de emergencia":
            await update.message.reply_text("Soporte directo:", reply_markup=inline_contact_admin())
            return
        if text == "📋 Mis proxies":
            await send_my_proxies(update, context)
            return
        await update.message.reply_text("⛔ Tu acceso está bloqueado.", reply_markup=reply_menu(False))
        return

    # ====== Menú cliente ======
    if text == "🛒 Pedir proxies nuevos":
        context.user_data["flow"] = "purchase_qty"
        await update.message.reply_text("¿Cuántos proxies quieres? (Ej: 1, 2, 5)\n\nEscribe CANCELAR para salir.")
        return

    if context.user_data.get("flow") == "purchase_qty":
        if text.upper() == "CANCELAR":
            context.user_data.pop("flow", None)
            await update.message.reply_text("✅ Cancelado.", reply_markup=reply_menu(is_admin))
            return

        qty = safe_int(text, 0)
        if qty <= 0 or qty > 100:
            await update.message.reply_text("Pon un número válido (1 a 100).")
            return

        if user_pending_count(user.id) >= int(getattr(config, "MAX_PENDING_REQUESTS", 5)):
            await update.message.reply_text("⚠️ Tienes muchas solicitudes pendientes. Espera que el admin las procese.")
            return

        monto = calc_purchase_amount(qty)
        req_id = create_request(user.id, "purchase", ip="", cantidad=qty, monto=monto, estado="awaiting_voucher")
        context.user_data["awaiting_voucher_req_id"] = req_id
        context.user_data.pop("flow", None)

        await update.message.reply_text(
            f"💰 Pedido #{req_id}\n"
            f"Cantidad: {qty}\n"
            f"Total: {monto} DOP\n\n"
            f"🏦 Banreservas\nCuenta: {config.CUENTA_BANRESERVAS}\nNombre: {config.NOMBRE_CUENTA}\n\n"
            "📸 Envía el comprobante (foto).",
            reply_markup=client_cancel_request_kb(req_id),
        )
        return

    if text == "♻️ Registrar proxy existente":
        context.user_data["flow"] = "register_ip"
        await update.message.reply_text("Envía la IP (ej: 104.xx.xx.xx:8080)\n\nEscribe CANCELAR para salir.")
        return

    if context.user_data.get("flow") == "register_ip":
        if text.upper() == "CANCELAR":
            context.user_data.pop("flow", None)
            await update.message.reply_text("✅ Cancelado.", reply_markup=reply_menu(is_admin))
            return

        ip = text.strip()
        if not is_valid_proxy_line(ip):
            await update.message.reply_text("Formato inválido. Ej: 104.28.1.2:8080")
            return

        req_id = create_request(user.id, "registro", ip=ip, cantidad=1, monto=calc_renew_amount(1), estado="awaiting_admin_verify")
        context.user_data.pop("flow", None)

        await context.bot.send_message(
            chat_id=config.ADMIN_ID,
            text=(
                "♻️ Registro de IP existente\n"
                f"Solicitud #{req_id}\n"
                f"Cliente ID: {user.id}\n"
                f"IP: {ip}\n\n"
                "👉 Verifica si esa IP es tuya y aprueba/rechaza en el panel."
            ),
        )
        await update.message.reply_text("✅ Enviado al admin para verificación.")
        return

    if text == "🔄 Renovar proxy existente":
        context.user_data["flow"] = "renew_ip"
        await update.message.reply_text("Envía la IP que quieres renovar.\n\nEscribe CANCELAR para salir.")
        return

    if context.user_data.get("flow") == "renew_ip":
        if text.upper() == "CANCELAR":
            context.user_data.pop("flow", None)
            await update.message.reply_text("✅ Cancelado.", reply_markup=reply_menu(is_admin))
            return

        ip = text.strip()
        if not is_valid_proxy_line(ip):
            await update.message.reply_text("Formato inválido. Ej: 104.28.1.2:8080")
            return
        if has_pending_request_for_ip(user.id, ip):
            await update.message.reply_text("⚠️ Ya tienes una solicitud pendiente para esa IP.")
            return

        req_id = create_request(user.id, "renovacion", ip=ip, cantidad=1, monto=calc_renew_amount(1), estado="awaiting_voucher")
        context.user_data["awaiting_voucher_req_id"] = req_id
        context.user_data.pop("flow", None)

        await update.message.reply_text(
            f"🔄 Renovación #{req_id}\n"
            f"IP: {ip}\n"
            f"Total: {calc_renew_amount(1)} DOP\n\n"
            f"🏦 Banreservas\nCuenta: {config.CUENTA_BANRESERVAS}\nNombre: {config.NOMBRE_CUENTA}\n\n"
            "📸 Envía el comprobante (foto).",
            reply_markup=client_cancel_request_kb(req_id),
        )
        return

    if text == "📋 Mis proxies":
        await send_my_proxies(update, context)
        return

    if text == "🧾 Mis pedidos":
        await send_my_orders(update, context)
        return

    if text == "❌ Cancelar pedido":
        await cancel_latest_pending_request(update, context)
        return

    if text == "🎫 Soporte (Ticket)":
        context.user_data["flow"] = "ticket_text"
        await update.message.reply_text("🎫 Escribe tu problema (un solo mensaje). Escribe CANCELAR para salir.")
        return

    if context.user_data.get("flow") == "ticket_text":
        if text.upper() == "CANCELAR":
            context.user_data.pop("flow", None)
            await update.message.reply_text("✅ Cancelado.", reply_markup=reply_menu(is_admin))
            return

        context.user_data.pop("flow", None)
        tid = create_ticket(user.id, mensaje=text)
        await update.message.reply_text(f"✅ Ticket creado: #{tid}\nEl admin lo revisará pronto.")

        admin_note = f"🎫 Nuevo ticket #{tid}\nU:{user.id}\n\n{text}"
        try:
            await context.bot.send_message(chat_id=config.ADMIN_ID, text=admin_note)
        except Exception:
            pass
        return

    if text == "🆘 Contacto de emergencia":
        await update.message.reply_text("Soporte directo:", reply_markup=inline_contact_admin())
        return

    if is_admin and text == "📊 Panel Admin":
        await update.message.reply_text("Panel Admin:", reply_markup=admin_panel_kb())
        return

    if re.fullmatch(r"\d{6}", text):
        handled = await try_confirm_delete_code(update, context, text)
        if handled:
            return

    await update.message.reply_text("Usa los botones del menú 👇", reply_markup=reply_menu(is_admin))


async def on_voucher(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id == config.ADMIN_ID:
        return

    if is_blocked_user(user.id):
        await update.message.reply_text("⛔ No puedes enviar comprobantes porque tu acceso está bloqueado.")
        return

    req_id = context.user_data.get("awaiting_voucher_req_id")
    req = None
    if req_id:
        req = get_request(req_id)
        if not req or req[6] != "awaiting_voucher" or req[1] != user.id:
            req = None

    if not req:
        req = get_latest_request_waiting_voucher(user.id)

    if not req:
        await update.message.reply_text("❌ No tienes solicitudes esperando comprobante.")
        return

    req_id, user_id, tipo, ip, cantidad, monto, estado, created_at = req
    set_request_state(req_id, "voucher_received")

    try:
        await context.bot.forward_message(chat_id=config.ADMIN_ID, from_chat_id=update.message.chat_id, message_id=update.message.message_id)
    except Exception:
        pass

    await context.bot.send_message(
        chat_id=config.ADMIN_ID,
        text=(
            "💰 Voucher recibido\n"
            f"Solicitud #{req_id}\n"
            f"Cliente: {user.id}\n"
            f"Tipo: {tipo}\n"
            f"IP: {ip or '-'}\n"
            f"Cantidad: {cantidad}\n"
            f"Monto: {monto} DOP\n"
        ),
        reply_markup=admin_order_detail_kb(req_id, user.id, "voucher_received"),
    )

    await update.message.reply_text("✅ Comprobante recibido. El admin lo revisará.")


# ---------------- Client: orders/cancel ----------------
async def send_my_orders(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    cursor.execute(
        """
        SELECT id,tipo,ip,cantidad,monto,estado,created_at
        FROM requests
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 20
        """,
        (uid,),
    )
    rows = cursor.fetchall()
    if not rows:
        await update.message.reply_text("No tienes pedidos todavía.")
        return

    msg = "🧾 Tus últimos 20 pedidos:\n\n"
    for rid, tipo, ip, cantidad, monto, estado, created_at in rows:
        msg += f"• #{rid} | {tipo} | IP:{ip or '-'} | qty:{cantidad} | {monto} | {estado} | {created_at}\n"
    await update.message.reply_text(msg)


async def cancel_latest_pending_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    cursor.execute(
        """
        SELECT id, estado
        FROM requests
        WHERE user_id=? AND estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')
        ORDER BY id DESC LIMIT 1
        """,
        (uid,),
    )
    row = cursor.fetchone()
    if not row:
        await update.message.reply_text("No tienes pedidos pendientes para cancelar.")
        return

    rid, estado = row
    set_request_state(rid, "cancelled")
    await update.message.reply_text(f"✅ Pedido #{rid} cancelado.")
    try:
        await context.bot.send_message(chat_id=config.ADMIN_ID, text=f"🗑 Cliente canceló pedido #{rid} (estado previo: {estado})\nU:{uid}")
    except Exception:
        pass


# ---------------- Proxy delete (client safe) ----------------
async def handle_proxy_delete_start(user_id: int, proxy_id: int, context: ContextTypes.DEFAULT_TYPE, reply_target):
    if is_blocked_user(user_id):
        await reply_target.reply_text("⛔ Acceso bloqueado. Contacta soporte.")
        return

    cursor.execute("SELECT ip FROM proxies WHERE id=? AND user_id=?", (proxy_id, user_id))
    row = cursor.fetchone()
    if not row:
        await reply_target.reply_text("Proxy no encontrada.")
        return

    ip = row[0]
    if has_pending_request_for_ip(user_id, ip):
        await reply_target.reply_text("⛔ No puedes eliminar: tienes solicitud pendiente/deuda relacionada.")
        return

    code = gen_code(6)
    expires_at = (datetime.now() + timedelta(seconds=int(getattr(config, "DELETE_CODE_EXPIRE", 120)))).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO delete_tokens(user_id, proxy_id, code, expires_at, estado, attempts) VALUES(?,?,?,?,?,?)",
        (user_id, proxy_id, code, expires_at, "pending", 0),
    )
    conn.commit()

    await context.bot.send_message(
        chat_id=user_id,
        text=f"🔴 Clave de eliminación para {ip}: {code}\nResponde con esa clave para confirmar (expira en 2 min)."
    )


async def try_confirm_delete_code(update: Update, context: ContextTypes.DEFAULT_TYPE, code: str) -> bool:
    user_id = update.effective_user.id
    cursor.execute(
        """
        SELECT id, proxy_id, code, expires_at, attempts
        FROM delete_tokens
        WHERE user_id=? AND estado='pending'
        ORDER BY id DESC LIMIT 1
        """,
        (user_id,),
    )
    row = cursor.fetchone()
    if not row:
        return False

    token_id, proxy_id, token_code, expires_at, attempts = row

    try:
        exp_dt = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
        if datetime.now() > exp_dt:
            cursor.execute("UPDATE delete_tokens SET estado='expired' WHERE id=?", (token_id,))
            conn.commit()
            await update.message.reply_text("⏳ Ese código expiró. Intenta eliminar de nuevo.")
            return True
    except Exception:
        pass

    max_attempts = int(getattr(config, "DELETE_CODE_ATTEMPTS", 3))
    if code != token_code:
        attempts = int(attempts) + 1
        cursor.execute("UPDATE delete_tokens SET attempts=? WHERE id=?", (attempts, token_id))
        conn.commit()
        if attempts >= max_attempts:
            cursor.execute("UPDATE delete_tokens SET estado='expired' WHERE id=?", (token_id,))
            conn.commit()
            await update.message.reply_text("❌ Clave incorrecta. Se canceló la eliminación por seguridad.")
        else:
            await update.message.reply_text(f"❌ Clave incorrecta. Intentos: {attempts}/{max_attempts}")
        return True

    cursor.execute("SELECT ip FROM proxies WHERE id=? AND user_id=?", (proxy_id, user_id))
    prow = cursor.fetchone()
    if not prow:
        cursor.execute("UPDATE delete_tokens SET estado='expired' WHERE id=?", (token_id,))
        conn.commit()
        await update.message.reply_text("Proxy no encontrada.")
        return True

    ip = prow[0]
    if has_pending_request_for_ip(user_id, ip):
        cursor.execute("UPDATE delete_tokens SET estado='expired' WHERE id=?", (token_id,))
        conn.commit()
        await update.message.reply_text("⛔ No puedes eliminar: solicitud pendiente relacionada.")
        return True

    cursor.execute("DELETE FROM proxies WHERE id=? AND user_id=?", (proxy_id, user_id))
    cursor.execute("UPDATE delete_tokens SET estado='done' WHERE id=?", (token_id,))
    conn.commit()

    await update.message.reply_text(f"✅ Proxy eliminada: {ip}")
    try:
        await context.bot.send_message(chat_id=config.ADMIN_ID, text=f"🗑 Cliente eliminó proxy\nU:{user_id}\nIP:{ip}\nPID:{proxy_id}")
    except Exception:
        pass
    return True


# ---------------- Admin views ----------------
async def admin_dashboard(chat):
    cursor.execute("SELECT COUNT(*) FROM users")
    users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM proxies")
    proxies = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM requests WHERE estado='awaiting_voucher'")
    aw = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM requests WHERE estado='voucher_received'")
    vr = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM requests WHERE estado='awaiting_admin_verify'")
    av = cursor.fetchone()[0]

    cursor.execute("SELECT vence FROM proxies")
    exp = 0
    for (vence,) in cursor.fetchall():
        if days_left(vence) <= 7:
            exp += 1

    maint = "🛠 ON" if maintenance_is_on() else "🟢 OFF"
    await chat.reply_text(
        "🏠 <b>Dashboard Admin</b>\n\n"
        f"🛠 Mantenimiento: <b>{maint}</b>\n\n"
        f"👥 Usuarios: <b>{users}</b>\n"
        f"📦 Proxies: <b>{proxies}</b>\n"
        f"⚠️ Por vencer (≤7d): <b>{exp}</b>\n\n"
        "📨 Pedidos:\n"
        f"• Awaiting voucher: <b>{aw}</b>\n"
        f"• Voucher received: <b>{vr}</b>\n"
        f"• Verify IP: <b>{av}</b>\n",
        parse_mode="HTML",
        reply_markup=admin_panel_kb(),
    )


async def admin_show_user_detail(chat, user_id: int):
    cursor.execute("SELECT username, is_blocked, created_at, last_seen FROM users WHERE user_id=?", (user_id,))
    urow = cursor.fetchone()
    if not urow:
        cursor.execute(
            "INSERT INTO users(user_id, username, is_blocked, created_at, last_seen) VALUES(?,?,?,?,?)",
            (user_id, "", 0, now_str(), now_str()),
        )
        conn.commit()
        urow = ("", 0, now_str(), now_str())

    username, is_blocked, created_at, last_seen = urow
    cursor.execute("SELECT COUNT(*) FROM proxies WHERE user_id=?", (user_id,))
    total_proxies = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM requests WHERE user_id=? AND estado IN ('awaiting_voucher','voucher_received','awaiting_admin_verify')", (user_id,))
    pending = cursor.fetchone()[0]

    cursor.execute("SELECT vence FROM proxies WHERE user_id=?", (user_id,))
    exp = 0
    for (vence,) in cursor.fetchall():
        if days_left(vence) <= 7:
            exp += 1

    tag = "🚫 BLOQUEADO" if int(is_blocked) == 1 else "✅ ACTIVO"
    udisp = f"@{username}" if username else "-"

    msg = (
        f"👤 <b>Usuario</b> <code>{user_id}</code>\n"
        f"Estado: <b>{tag}</b>\n"
        f"Username: <b>{udisp}</b>\n"
        f"Creado: {created_at}\n"
        f"Last seen: {last_seen}\n\n"
        f"📦 Proxies: <b>{total_proxies}</b> | ⚠️ Por vencer(≤7d): <b>{exp}</b>\n"
        f"📨 Pendientes: <b>{pending}</b>\n"
    )
    await chat.reply_text(msg, parse_mode="HTML", reply_markup=admin_user_detail_kb(user_id, int(is_blocked) == 1))


async def admin_search_chat(chat, q: str):
    q2 = (q or "").strip()
    if not q2:
        await chat.reply_text("Pon algo para buscar.", reply_markup=admin_panel_kb())
        return

    cursor.execute("SELECT user_id, username, is_blocked FROM users WHERE username LIKE ? ORDER BY last_seen DESC LIMIT 20", (f"%{q2}%",))
    urows = cursor.fetchall()

    cursor.execute(
        """
        SELECT user_id, id, ip, vence, estado
        FROM proxies
        WHERE ip LIKE ? OR raw LIKE ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (f"%{q2}%", f"%{q2}%"),
    )
    prows = cursor.fetchall()

    if not urows and not prows:
        await chat.reply_text("No encontré resultados.", reply_markup=admin_panel_kb())
        return

    msg = "🔍 Resultados:\n\n"
    if urows:
        msg += "👥 Usuarios:\n"
        for uid, uname, blocked in urows:
            tag = "🚫" if int(blocked) == 1 else "✅"
            msg += f"{tag} {uid} (@{uname or '-'})\n"
        msg += "\n"

    if prows:
        msg += "📦 Proxies:\n"
        for uid, pid, ip, vence, estado in prows:
            msg += f"U:{uid} | PID:{pid} | {ip} | {days_left(vence)}d | {estado}\n"

    await chat.reply_text(msg, reply_markup=admin_panel_kb())


# ---------------- Client view ----------------
async def send_my_proxies(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    rows = get_user_proxies(user_id)
    if not rows:
        await update.message.reply_text("No tienes proxies registradas todavía.")
        return

    await update.message.reply_text("📋 Tus proxies:")
    for pid, key, raw, inicio, vence, estado in rows[:50]:
        d = days_left(vence)
        shown = add_http_header(raw) if (raw or "").strip() else f"HTTP\n{key}"
        msg = f"🧾 Proxy ID: {pid}\n📅 Vence: {vence} ({d} días)\n🟢 Estado: {estado}\n\n{shown}"
        await update.message.reply_text(msg, reply_markup=client_proxy_actions_kb(pid))


# ---------------- Callbacks ----------------
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query:
        return
    await query.answer()
    data = query.data or ""
    caller = query.from_user.id

    # ---------- CLIENT: cancelar pedido específico ----------
    if data.startswith("client_cancelreq_"):
        rid = safe_int(data.split("_")[-1], 0)
        req = get_request(rid)
        if not req or req[1] != caller:
            await query.message.reply_text("No encontré ese pedido.")
            return
        if req[6] not in ("awaiting_voucher", "voucher_received", "awaiting_admin_verify"):
            await query.message.reply_text("Ese pedido ya no se puede cancelar.")
            return
        set_request_state(rid, "cancelled")
        await query.message.reply_text(f"✅ Pedido #{rid} cancelado.")
        try:
            await context.bot.send_message(chat_id=config.ADMIN_ID, text=f"🗑 Cliente canceló pedido #{rid}\nU:{caller}")
        except Exception:
            pass
        return

    # ---------- CLIENT: renovar proxy (desde Mis proxies) ----------
    if data.startswith("proxy_renew_"):
        pid = safe_int(data.split("_")[-1], 0)
        cursor.execute("SELECT ip FROM proxies WHERE id=? AND user_id=?", (pid, caller))
        row = cursor.fetchone()
        if not row:
            await query.message.reply_text("Proxy no encontrada.")
            return
        ip = row[0]
        if has_pending_request_for_ip(caller, ip):
            await query.message.reply_text("⚠️ Ya tienes solicitud pendiente para esa IP.")
            return
        rid = create_request(caller, "renovacion", ip=ip, cantidad=1, monto=calc_renew_amount(1), estado="awaiting_voucher")
        context.user_data["awaiting_voucher_req_id"] = rid
        await query.message.reply_text(
            f"🔄 Renovación #{rid}\nIP: {ip}\nTotal: {calc_renew_amount(1)} DOP\n\nEnvía el comprobante.",
            reply_markup=client_cancel_request_kb(rid),
        )
        return

    # ---------- CLIENT: eliminar proxy ----------
       # ✅ FIX CRÍTICO: CLIENTE "IP verificada" -> Renovar/Cancelar (DEBE IR ANTES DEL ADMIN GATE)
    if data.startswith("client_reg_renew_") or data.startswith("client_reg_cancel_"):
        ip = data.replace("client_reg_renew_", "").replace("client_reg_cancel_", "")

        if data.startswith("client_reg_cancel_"):
            await query.message.reply_text("❌ Cancelado.")
            return

        if is_blocked_user(caller):
            await query.message.reply_text("⛔ Acceso bloqueado. Contacta soporte.")
            return

        if has_pending_request_for_ip(caller, ip):
            await query.message.reply_text("⚠️ Ya tienes una solicitud pendiente para esa IP.")
            return

        rid = create_request(
            caller,
            "renovacion",
            ip=ip,
            cantidad=1,
            monto=calc_renew_amount(1),
            estado="awaiting_voucher",
        )
        context.user_data["awaiting_voucher_req_id"] = rid

        # ✅ aquí agregamos también la cuenta de banco como tú querías
        await query.message.reply_text(
            f"🔄 Renovación #{rid}\n"
            f"IP: {ip}\n"
            f"Total: {calc_renew_amount(1)} DOP\n\n"
            f"🏦 Banreservas\n"
            f"Cuenta: {config.CUENTA_BANRESERVAS}\n"
            f"Nombre: {config.NOMBRE_CUENTA}\n\n"
            "📸 Envía el comprobante (foto).",
            reply_markup=client_cancel_request_kb(rid),
        )
        return

        

    # ---------- ADMIN gate ----------
    if caller != config.ADMIN_ID:
        return

    if data == "admin_maint_menu":
        await query.message.reply_text("🛠 Mantenimiento — opciones:", reply_markup=admin_maint_menu_kb())
        return

    if data == "admin_maint_on":
        set_maintenance(True)
        msg = get_setting("maint_msg_on", maint_message_default(True))
        ok, fail = await broadcast_to_all_users(context, msg)
        await query.message.reply_text(
            f"✅ Mantenimiento ACTIVADO.\n📣 Broadcast enviado: {ok} ok / {fail} fallos",
            reply_markup=admin_panel_kb(),
        )
        return

    if data == "admin_maint_off":
        set_maintenance(False)
        msg = get_setting("maint_msg_off", maint_message_default(False))
        ok, fail = await broadcast_to_all_users(context, msg)
        await query.message.reply_text(
            f"🟢 Mantenimiento DESACTIVADO.\n📣 Broadcast enviado: {ok} ok / {fail} fallos",
            reply_markup=admin_panel_kb(),
        )
        return

    if data == "admin_maint_msg_on":
        context.user_data["admin_flow"] = ("maint_msg", "on")
        await query.message.reply_text(
            "✍️ Escribe el mensaje que se enviará cuando ACTIVES mantenimiento.\n"
            "Tip: puedes usar saltos de línea.\n\n"
            "Escribe CANCELAR para salir."
        )
        return

    if data == "admin_maint_msg_off":
        context.user_data["admin_flow"] = ("maint_msg", "off")
        await query.message.reply_text(
            "✍️ Escribe el mensaje que se enviará cuando DESACTIVES mantenimiento.\n\n"
            "Escribe CANCELAR para salir."
        )
        return

    # Panel root
    if data == "admin_panel":
        await query.message.reply_text("Panel Admin:", reply_markup=admin_panel_kb())
        return

    # 🛠 Mantenimiento menu
    if data == "admin_maint_menu":
        await query.message.reply_text("🛠 Mantenimiento — opciones:", reply_markup=admin_maint_menu_kb())
        return

    if data == "admin_maint_on":
        set_maintenance(True)
        msg = get_setting("maint_msg_on", maint_message_default(True))
        ok, fail = await broadcast_to_all_users(context, msg)
        await query.message.reply_text(
            f"✅ Mantenimiento ACTIVADO.\n📣 Broadcast: {ok} ok / {fail} fallos",
            reply_markup=admin_panel_kb(),
        )
        return

    if data == "admin_maint_off":
        set_maintenance(False)
        msg = get_setting("maint_msg_off", maint_message_default(False))
        ok, fail = await broadcast_to_all_users(context, msg)
        await query.message.reply_text(
            f"🟢 Mantenimiento DESACTIVADO.\n📣 Broadcast: {ok} ok / {fail} fallos",
            reply_markup=admin_panel_kb(),
        )
        return

    if data == "admin_maint_msg_on":
        context.user_data["admin_flow"] = ("maint_msg", "on")
        await query.message.reply_text(
            "✍️ Escribe el mensaje que se enviará cuando ACTIVES mantenimiento.\n\nEscribe CANCELAR para salir."
        )
        return

    if data == "admin_maint_msg_off":
        context.user_data["admin_flow"] = ("maint_msg", "off")
        await query.message.reply_text(
            "✍️ Escribe el mensaje que se enviará cuando DESACTIVES mantenimiento.\n\nEscribe CANCELAR para salir."
        )
        return

    if data == "admin_dash":
        await admin_dashboard(query.message)
        return

    if data == "admin_search":
        context.user_data["admin_flow"] = "search"
        await query.message.reply_text("🔍 Escribe user_id / username / IP / texto:")
        return

    if data == "admin_proxies_menu":
        await query.message.reply_text("📦 Proxies:", reply_markup=admin_proxies_menu_kb())
        return

    if data == "admin_orders_menu":
        await query.message.reply_text("📨 Pedidos:", reply_markup=admin_orders_menu_kb())
        return

    # Usuarios paginados
    if data.startswith("admin_users_"):
        page = safe_int(data.split("_")[-1], 0)
        per_page = 20
        offset = page * per_page
        cursor.execute(
            """
            SELECT user_id, username, is_blocked, last_seen
            FROM users
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (per_page + 1, offset),
        )
        rows = cursor.fetchall()
        has_next = len(rows) > per_page
        rows = rows[:per_page]
        if not rows:
            await query.message.reply_text("👥 No hay usuarios todavía.", reply_markup=admin_panel_kb())
            return

        msg = "👥 <b>Usuarios</b>\n\n"
        user_ids = []
        for uid, uname, blocked, last_seen in rows:
            user_ids.append(int(uid))
            tag = "🚫" if int(blocked) == 1 else "✅"
            udisp = f"@{uname}" if uname else "-"
            msg += f"{tag} <code>{uid}</code> ({udisp}) — {last_seen}\n"

        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=admin_users_page_kb(user_ids, page, has_next))
        return

    # Detalle usuario
    if data.startswith("admin_user_") and not data.startswith("admin_user_proxies_") and not data.startswith("admin_user_orders_") and not data.startswith("admin_user_toggleblock_") and not data.startswith("admin_user_del_"):
        uid = safe_int(data.split("_")[-1], 0)
        await admin_show_user_detail(query.message, uid)
        return

    # Toggle block
    if data.startswith("admin_user_toggleblock_"):
        uid = safe_int(data.split("_")[-1], 0)
        cursor.execute("SELECT is_blocked FROM users WHERE user_id=?", (uid,))
        row = cursor.fetchone()
        cur = int(row[0]) if row else 0
        newv = 0 if cur == 1 else 1
        set_block_user(uid, bool(newv))
        try:
            await context.bot.send_message(chat_id=uid, text=("⛔ Acceso bloqueado." if newv == 1 else "✅ Acceso restaurado. /start"))
        except Exception:
            pass
        await admin_show_user_detail(query.message, uid)
        return

    # Delete user confirm
    if data.startswith("admin_user_del_confirm_"):
        uid = safe_int(data.split("_")[-1], 0)
        cursor.execute("DELETE FROM proxies WHERE user_id=?", (uid,))
        cursor.execute("DELETE FROM requests WHERE user_id=?", (uid,))
        cursor.execute("DELETE FROM delete_tokens WHERE user_id=?", (uid,))
        cursor.execute("DELETE FROM ticket_messages WHERE ticket_id IN (SELECT id FROM tickets WHERE user_id=?)", (uid,))
        cursor.execute("DELETE FROM tickets WHERE user_id=?", (uid,))
        cursor.execute("DELETE FROM users WHERE user_id=?", (uid,))
        conn.commit()
        try:
            await context.bot.send_message(chat_id=uid, text="🗑 Tu cuenta fue eliminada del sistema.")
        except Exception:
            pass
        await query.message.reply_text(f"✅ Usuario {uid} eliminado.", reply_markup=admin_panel_kb())
        return

    if data.startswith("admin_user_del_") and not data.startswith("admin_user_del_confirm_"):
        uid = safe_int(data.split("_")[-1], 0)
        await query.message.reply_text(
            f"⚠️ Vas a eliminar al usuario <code>{uid}</code> y TODO lo asociado.\n\n¿Confirmas?",
            parse_mode="HTML",
            reply_markup=admin_user_delete_confirm_kb(uid),
        )
        return

    # Ver proxies de usuario
    if data.startswith("admin_user_proxies_"):
        parts = data.split("_")
        uid = safe_int(parts[3], 0)
        page = safe_int(parts[4], 0)
        per_page = 10
        offset = page * per_page

        cursor.execute(
            """
            SELECT id, ip, vence, estado
            FROM proxies
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (uid, per_page + 1, offset),
        )
        rows = cursor.fetchall()
        has_next = len(rows) > per_page
        rows = rows[:per_page]
        if not rows:
            await query.message.reply_text("Este usuario no tiene proxies.", reply_markup=admin_user_detail_kb(uid, is_blocked_user(uid)))
            return

        msg = f"📦 <b>Proxies</b> de <code>{uid}</code>\n\n"
        kb_rows = []
        for pid, ip, vence, estado in rows:
            msg += f"• PID:<code>{pid}</code> — {ip} — {days_left(vence)}d — {estado}\n"
            kb_rows.append([InlineKeyboardButton(f"🔎 Abrir PID {pid}", callback_data=f"admin_proxy_{pid}")])

        nav_kb = admin_user_proxies_page_kb(uid, page, has_next)
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=kb_merge(kb_rows, nav_kb))
        return

    # Ver pedidos de usuario
    if data.startswith("admin_user_orders_"):
        parts = data.split("_")
        uid = safe_int(parts[3], 0)
        page = safe_int(parts[4], 0)
        per_page = 10
        offset = page * per_page

        cursor.execute(
            """
            SELECT id, tipo, ip, cantidad, monto, estado, created_at
            FROM requests
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (uid, per_page + 1, offset),
        )
        rows = cursor.fetchall()
        has_next = len(rows) > per_page
        rows = rows[:per_page]
        if not rows:
            await query.message.reply_text("Este usuario no tiene pedidos.", reply_markup=admin_user_detail_kb(uid, is_blocked_user(uid)))
            return

        msg = f"📨 <b>Pedidos</b> de <code>{uid}</code>\n\n"
        kb_rows = []
        for rid, tipo, ip, cantidad, monto, estado, created_at in rows:
            msg += f"• #{rid} | {tipo} | IP:{ip or '-'} | qty:{cantidad} | {monto} | {estado}\n"
            kb_rows.append([InlineKeyboardButton(f"🔎 Abrir Pedido #{rid}", callback_data=f"admin_order_{rid}")])

        nav_kb = admin_user_orders_page_kb(uid, page, has_next)
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=kb_merge(kb_rows, nav_kb))
        return

    # Proxies: últimas 50
    if data.startswith("admin_proxies_last50_"):
        page = safe_int(data.split("_")[-1], 0)
        per_page = 10
        offset = page * per_page

        cursor.execute(
            """
            SELECT id, user_id, ip, vence, estado
            FROM proxies
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (per_page + 1, offset),
        )
        rows = cursor.fetchall()
        has_next = len(rows) > per_page
        rows = rows[:per_page]
        if not rows:
            await query.message.reply_text("No hay proxies.", reply_markup=admin_proxies_menu_kb())
            return

        msg = "📂 <b>Proxies</b> (últimas)\n\n"
        kb_rows = []
        for pid, uid, ip, vence, estado in rows:
            msg += f"• PID:<code>{pid}</code> | U:<code>{uid}</code> | {ip} | {days_left(vence)}d | {estado}\n"
            kb_rows.append([InlineKeyboardButton(f"🔎 Abrir PID {pid}", callback_data=f"admin_proxy_{pid}")])

        nav = []
        if page > 0:
            nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_proxies_last50_{page-1}"))
        if has_next:
            nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_proxies_last50_{page+1}"))

        footer = [
            [InlineKeyboardButton("⬅️ Proxies", callback_data="admin_proxies_menu")],
            [InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")],
        ]
        if nav:
            kb_rows.append(nav)

        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=kb_merge(kb_rows, footer))
        return

    # Proxies: por vencer
    if data.startswith("admin_expiring_"):
        page = safe_int(data.split("_")[-1], 0)
        per_page = 10
        offset = page * per_page

        cursor.execute("SELECT id, user_id, ip, vence, estado FROM proxies ORDER BY id DESC")
        all_rows = cursor.fetchall()
        exp = []
        for pid, uid, ip, vence, estado in all_rows:
            d = days_left(vence)
            if d <= 7:
                exp.append((pid, uid, ip, vence, estado, d))
        exp.sort(key=lambda x: x[5])
        chunk = exp[offset: offset + per_page + 1]
        has_next = len(chunk) > per_page
        chunk = chunk[:per_page]
        if not chunk:
            await query.message.reply_text("✅ No hay proxies por vencer (≤7 días).", reply_markup=admin_proxies_menu_kb())
            return

        msg = "⚠️ <b>Proxies por vencer</b>\n\n"
        kb_rows = []
        for pid, uid, ip, vence, estado, d in chunk:
            msg += f"• PID:<code>{pid}</code> | U:<code>{uid}</code> | {ip} | {d}d | {vence}\n"
            kb_rows.append([InlineKeyboardButton(f"🔎 Abrir PID {pid}", callback_data=f"admin_proxy_{pid}")])

        nav_kb = admin_expiring_page_kb(page, has_next)
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=kb_merge(kb_rows, nav_kb))
        return

    # Abrir proxy (detalle)
    if data.startswith("admin_proxy_"):
        pid = safe_int(data.split("_")[-1], 0)
        cursor.execute("SELECT id, user_id, ip, raw, inicio, vence, estado FROM proxies WHERE id=?", (pid,))
        row = cursor.fetchone()
        if not row:
            await query.message.reply_text("Proxy no encontrada.", reply_markup=admin_panel_kb())
            return
        pid, uid, ip, raw, inicio, vence, estado = row
        shown = add_http_header(raw) if (raw or "").strip() else f"HTTP\n{ip}"
        msg = (
            f"📦 <b>Proxy Detalle</b>\n\n"
            f"PID: <code>{pid}</code>\n"
            f"Owner: <code>{uid}</code>\n"
            f"Estado: <b>{estado}</b>\n"
            f"Inicio: {inicio}\n"
            f"Vence: {vence} ({days_left(vence)} días)\n\n"
            f"<pre>{html_escape(shown)}</pre>"
        )
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=admin_proxy_detail_kb(pid, int(uid)))
        return

    # Pedidos: menú por estado (lista)
    if data.startswith("admin_orders_"):
        parts = data.split("_")
        page = safe_int(parts[-1], 0)
        state = "_".join(parts[2:-1])
        per_page = 10
        offset = page * per_page

        cursor.execute(
            """
            SELECT id, user_id, tipo, ip, cantidad, monto, estado, created_at
            FROM requests
            WHERE estado=?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (state, per_page + 1, offset),
        )
        rows = cursor.fetchall()
        has_next = len(rows) > per_page
        rows = rows[:per_page]
        if not rows:
            await query.message.reply_text("No hay pedidos en ese estado.", reply_markup=admin_orders_menu_kb())
            return

        msg = f"📨 <b>Pedidos</b> — <code>{state}</code>\n\n"
        kb_rows = []
        for rid, uid, tipo, ip, cantidad, monto, estado, created_at in rows:
            msg += f"• #{rid} | U:<code>{uid}</code> | {tipo} | IP:{ip or '-'} | qty:{cantidad} | {monto} | {created_at}\n"
            kb_rows.append([InlineKeyboardButton(f"🔎 Abrir Pedido #{rid}", callback_data=f"admin_order_{rid}")])

        nav_kb = admin_orders_page_kb(state, page, has_next)
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=kb_merge(kb_rows, nav_kb))
        return

    # Abrir pedido (detalle)
    if data.startswith("admin_order_"):
        rid = safe_int(data.split("_")[-1], 0)
        req = get_request(rid)
        if not req:
            await query.message.reply_text("Pedido no encontrado.", reply_markup=admin_panel_kb())
            return
        rid, uid, tipo, ip, cantidad, monto, estado, created_at = req
        msg = (
            f"🧾 <b>Pedido Detalle</b>\n\n"
            f"ID: <code>{rid}</code>\n"
            f"User: <code>{uid}</code>\n"
            f"Tipo: <b>{tipo}</b>\n"
            f"IP: <b>{ip or '-'}</b>\n"
            f"Cantidad: <b>{cantidad}</b>\n"
            f"Monto: <b>{monto}</b> DOP\n"
            f"Estado: <b>{estado}</b>\n"
            f"Creado: {created_at}\n"
        )
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=admin_order_detail_kb(rid, int(uid), estado))
        return

    # Aprobar / Rechazar
    if data.startswith("admin_approve_") or data.startswith("admin_reject_"):
        action = "approve" if data.startswith("admin_approve_") else "reject"
        rid = safe_int(data.split("_")[-1], 0)
        req = get_request(rid)
        if not req:
            await query.message.reply_text("Solicitud no encontrada.")
            return
        rid, uid, tipo, ip, cantidad, monto, estado, created_at = req

        if action == "reject":
            set_request_state(rid, "rejected")
            try:
                await context.bot.send_message(chat_id=uid, text=f"❌ Tu solicitud #{rid} fue rechazada.")
            except Exception:
                pass
            await query.message.reply_text(f"❌ Rechazado #{rid}.", reply_markup=admin_panel_kb())
            return

        set_request_state(rid, "approved")

        if tipo == "registro":
            try:
                await context.bot.send_message(
                    chat_id=uid,
                    text=(
    f"✅ IP verificada: {ip}\n\n"
    f"💡 Puedes renovarla ahora.\n\n"
    f"{bank_text()}\n"
    "Presiona 🔄 Renovar cuando estés listo."
)
,
                    reply_markup=client_register_choice_kb(ip),
                )
            except Exception:
                pass
            await query.message.reply_text(f"✅ Aprobado registro #{rid}.", reply_markup=admin_panel_kb())
            return

        if tipo == "renovacion":
            new_vence = renew_proxy(uid, ip)
            try:
                await context.bot.send_message(chat_id=uid, text=f"✅ Renovación aprobada.\nIP: {ip}\nNuevo vencimiento: {new_vence}")
            except Exception:
                pass
            await query.message.reply_text(f"✅ Renovación #{rid} aplicada.", reply_markup=admin_panel_kb())
            return

        if tipo == "purchase":
            try:
                await context.bot.send_message(chat_id=uid, text="✅ Pago aprobado. Te asignaremos tus proxies ahora mismo.")
            except Exception:
                pass
            await query.message.reply_text(
                f"✅ Compra #{rid} aprobada.\n\n"
                f"📌 Pega las proxies aquí.\n"
                f"✅ NO necesitas FIN. Se cierra solo cuando llegue a {int(cantidad)}.\n"
                f"(Si quieres cerrar manual: escribe FIN)"
            )
            admin_send_state[config.ADMIN_ID] = {"req_id": rid, "user_id": uid, "cantidad": int(cantidad), "received": 0}
            return

    # Admin delete proxy
    if data.startswith("admin_delproxy_"):
        pid = safe_int(data.split("_")[-1], 0)
        cursor.execute("SELECT user_id, ip FROM proxies WHERE id=?", (pid,))
        row = cursor.fetchone()
        if not row:
            await query.message.reply_text("Proxy no encontrada.")
            return
        owner_id, ip = int(row[0]), row[1]
        cursor.execute("DELETE FROM proxies WHERE id=?", (pid,))
        conn.commit()
        await query.message.reply_text(f"✅ Proxy eliminada PID:{pid}\n{ip}", reply_markup=admin_panel_kb())
        try:
            await context.bot.send_message(chat_id=owner_id, text=f"🗑 El admin eliminó una proxy de tu cuenta:\n{ip}")
        except Exception:
            pass
        return

    # Tickets admin (lista)
    if data.startswith("admin_tickets_"):
        page = safe_int(data.split("_")[-1], 0)
        per_page = 10
        offset = page * per_page
        cursor.execute(
            """
            SELECT id, user_id, estado, created_at
            FROM tickets
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (per_page + 1, offset),
        )
        rows = cursor.fetchall()
        has_next = len(rows) > per_page
        rows = rows[:per_page]
        if not rows:
            await query.message.reply_text("No hay tickets.", reply_markup=admin_panel_kb())
            return

        msg = "🎫 <b>Tickets</b>\n\n"
        kb_rows = []
        for tid, uid, estado, created_at in rows:
            msg += f"• #{tid} | U:<code>{uid}</code> | {estado} | {created_at}\n"
            kb_rows.append([InlineKeyboardButton(f"🔎 Abrir Ticket #{tid}", callback_data=f"admin_ticket_{tid}")])

        nav = []
        if page > 0:
            nav.append(InlineKeyboardButton("⬅️ Atrás", callback_data=f"admin_tickets_{page-1}"))
        if has_next:
            nav.append(InlineKeyboardButton("➡️ Más", callback_data=f"admin_tickets_{page+1}"))
        if nav:
            kb_rows.append(nav)

        kb_rows.append([InlineKeyboardButton("⬅️ Panel", callback_data="admin_panel")])

        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb_rows))
        return

    # Tickets admin (detalle)
    if data.startswith("admin_ticket_") and not data.startswith("admin_ticket_close_") and not data.startswith("admin_ticket_reply_"):
        tid = safe_int(data.split("_")[-1], 0)
        t = get_ticket(tid)
        if not t:
            await query.message.reply_text("Ticket no encontrado.", reply_markup=admin_panel_kb())
            return
        tid, uid, mensaje, estado, created_at, updated_at = t

        msgs = get_ticket_messages(tid, limit=12)
        chatlog = ""
        for sender, m, ts in msgs:
            who = "👤 Cliente" if sender == "user" else "🛠 Admin"
            chatlog += f"{who} ({ts}):\n{m}\n\n"
        chatlog = chatlog.strip() or mensaje

        msg = (
            f"🎫 <b>Ticket #{tid}</b>\n\n"
            f"User: <code>{uid}</code>\n"
            f"Estado: <b>{estado}</b>\n"
            f"Creado: {created_at}\n"
            f"Actualizado: {updated_at}\n\n"
            f"<b>Conversación:</b>\n<pre>{html_escape(chatlog[:3500])}</pre>\n\n"
            f"✅ Usa <b>Responder</b> para contestarle al cliente."
        )
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=admin_ticket_detail_kb(tid, int(uid), estado))
        return

    if data.startswith("admin_ticket_reply_"):
        tid = safe_int(data.split("_")[-1], 0)
        t = get_ticket(tid)
        if not t:
            await query.message.reply_text("Ticket no encontrado.", reply_markup=admin_panel_kb())
            return
        _, _, _, estado, _, _ = t
        if estado != "open":
            await query.message.reply_text("Ese ticket está cerrado.", reply_markup=admin_panel_kb())
            return

        context.user_data["admin_flow"] = ("ticket_reply", tid)
        await query.message.reply_text(f"✉️ Respondiendo Ticket #{tid}\n\nEscribe tu respuesta en un solo mensaje:")
        return

    if data.startswith("admin_ticket_close_"):
        tid = safe_int(data.split("_")[-1], 0)
        t = get_ticket(tid)
        if not t:
            await query.message.reply_text("Ticket no encontrado.")
            return
        tid, uid, _, estado, _, _ = t
        close_ticket(tid)
        try:
            await context.bot.send_message(chat_id=uid, text=f"✅ Tu ticket #{tid} fue cerrado por el admin.")
        except Exception:
            pass
        await query.message.reply_text(f"✅ Ticket #{tid} cerrado.", reply_markup=admin_panel_kb())
        return


# ✅ job opcional (si existe JobQueue)
async def reminders_daily_job(context):
    days_list = list(getattr(config, "REMINDER_DAYS", [7, 3, 1, 0]))
    cursor.execute("SELECT user_id, ip, vence FROM proxies")
    for user_id, ip, vence in cursor.fetchall():
        d = days_left(vence)
        try:
            if d in days_list:
                await context.bot.send_message(chat_id=user_id, text=f"🔔 Recordatorio: tu proxy {ip} vence en {d} día(s).")
        except Exception:
            pass


# ✅ Error handler (para que el bot NO se caiga)
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception: %s", context.error)
    try:
        if isinstance(update, Update) and update.effective_message:
            await update.effective_message.reply_text("⚠️ Error interno (ya lo registré en consola).")
    except Exception:
        pass


def main():
    if not (config.TOKEN or "").strip() or "PEGA_AQUI" in (config.TOKEN or ""):
        print("❌ FALTA TOKEN. Pon tu token en config.py.")
        return

    # Migra DB al iniciar SIEMPRE
    ensure_schema()

    app = ApplicationBuilder().token(config.TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, on_voucher))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    app.add_error_handler(on_error)

    if app.job_queue:
        app.job_queue.run_daily(reminders_daily_job, time=time(hour=9, minute=0, second=0))
        print("✅ JobQueue activo: recordatorios programados.")
    else:
        print("⚠️ JobQueue NO disponible. El bot corre normal sin recordatorios.")
        print('   Si lo quieres: py -m pip install "python-telegram-bot[job-queue]"')

   
    print("✅ Gproxy corriendo. Abre Telegram y escribe al bot.")
    app.run_polling()


if __name__ == "__main__":
    main()

