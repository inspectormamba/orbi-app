"""Entry point: `pythonw -m orbi` (tray + server) or `python -m orbi --no-tray` (server only)."""
import argparse
import ctypes
import logging
import os
import sys
import threading
import webbrowser
from logging.handlers import RotatingFileHandler

import uvicorn

from . import config
from .monitor import Monitor
from .store import Store
from .web import create_app


def setup_logging():
    log_dir = config.DATA_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handlers = [RotatingFileHandler(log_dir / "orbi.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")]
    if sys.stderr:  # pythonw has no console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=handlers)
    logging.getLogger("pynetgear").setLevel(logging.CRITICAL)  # it logs every expected router hiccup as an error
    # Windows' asyncio logs a traceback whenever a phone browser drops its connection; that's normal.
    logging.getLogger("asyncio").addFilter(
        lambda r: not (r.exc_info and isinstance(r.exc_info[1], ConnectionResetError)))
    for noisy in ("selenium", "urllib3", "websocket"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def single_instance() -> bool:
    """One instance per data folder (so a test copy with its own folder can run alongside)."""
    import hashlib
    tag = hashlib.sha1(str(config.DATA_DIR).lower().encode()).hexdigest()[:12]
    ctypes.windll.kernel32.CreateMutexW(None, False, f"Local\\OrbiControl-{tag}")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-tray", action="store_true", help="run the server without the tray icon")
    parser.add_argument("--port", type=int)
    parser.add_argument("--background", action="store_true", help="started by the scheduler: never open a browser")
    args = parser.parse_args()

    settings = config.load()
    port = args.port or settings["port"]
    url = f"http://localhost:{port}"
    if not single_instance():
        if not args.background:
            webbrowser.open(url)  # already running: just open the dashboard
        return

    setup_logging()
    log = logging.getLogger("orbi")
    store = Store(config.DATA_DIR / "orbi.db")
    tray = None
    monitor = Monitor(store, notify=lambda t, m: tray and tray.notify(t, m))
    monitor.start()

    server = uvicorn.Server(uvicorn.Config(create_app(monitor), host="0.0.0.0", port=port, log_level="warning",
                                           access_log=False, log_config=None, proxy_headers=False))  # never trust X-Forwarded-For
    log.info("Orbi Control starting on port %s", port)
    if args.no_tray:
        server.run()
        return

    server_thread = threading.Thread(target=server.run, name="web", daemon=True)
    server_thread.start()

    from .tray import Tray

    def quit_all():
        monitor.stop()
        server.should_exit = True

    tray = Tray(monitor, url, quit_all)
    if not settings["pin_hash"] and not args.background:
        threading.Timer(2, lambda: webbrowser.open(url)).start()  # first run: open setup
    tray.run()
    server_thread.join(timeout=5)
    os._exit(0)


if __name__ == "__main__":
    main()
