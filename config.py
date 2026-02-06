import os

# ===============================
# TELEGRAM
# ===============================

TOKEN = os.getenv("GPROXY_BOT_TOKEN")
ADMIN_ID = int(os.getenv("GPROXY_ADMIN_ID", "1915349159"))

# ===============================
# PAGOS
# ===============================

CUENTA_BANRESERVAS = "4248676174"
NOMBRE_CUENTA = "YUDITH DOMINGUEZ"

# ===============================
# PRECIOS
# ===============================

PRECIO_PRIMERA = 1500
PRECIO_RENOVACION = 1000

# ===============================
# DURACION
# ===============================

DIAS_PROXY = 30

# ===============================
# RECORDATORIOS
# ===============================

REMINDER_DAYS = [7, 3, 1, 0]

WELCOME_MESSAGE = """
🚀 Bienvenido a Gproxy | Proxies USA 🇺🇸

🌐 Conexiones rápidas • Estables • Privadas  
🔒 Ideal para automatización, cuentas, bots y trabajo online

━━━━━━━━━━━━━━━━━━

💰 PLANES DISPONIBLES

🆕 Primera compra:
💵 {precio_primera} DOP por proxy

🔄 Renovación mensual:
💵 {precio_renovacion} DOP por proxy

⏳ Duración: {dias_proxy} días por proxy

━━━━━━━━━━━━━━━━━━

⚡ Activación rápida después del pago  
📩 Soporte directo  
🛡 Proxies verificadas

👇 Usa los botones del menú para empezar
""".strip()
