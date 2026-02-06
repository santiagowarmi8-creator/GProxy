import os
import threading
import time

# inicia web
def run_web():
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("web:app", host="0.0.0.0", port=port, log_level="info")

# inicia bot
def run_bot():
    import bot
    bot.main()

if __name__ == "__main__":
    t1 = threading.Thread(target=run_web, daemon=True)
    t1.start()

    # espera 1s para que web suba
    time.sleep(1)

    run_bot()
