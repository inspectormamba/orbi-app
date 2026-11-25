"""Entry point: `pythonw -m orbi` (tray + server) or `python -m orbi --no-tray` (server only)."""
import argparse
import logging
import os
import sys
import threading
import webbrowser
from logging.handlers import RotatingFileHandler

import uvicorn

from . import config, osdep, tamper, tls, updater
from .monitor import Monitor
from .store import Store
from .web import _lan_ips, create_app

# The phone link is HTTPS on the settings port (all interfaces). This PC's own browser, the tray, and the
# health checks use plain HTTP on the next port, bound to 127.0.0.1 only, so nothing on the network can reach it.
LOOPBACK_OFFSET = 1


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
    return osdep.single_instance(config.DATA_DIR)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-tray", action="store_true", help="run the server without the tray icon")
    parser.add_argument("--port", type=int)
    parser.add_argument("--background", action="store_true", help="started by the scheduler: never open a browser")
    args = parser.parse_args()

    settings = config.load()
    port = args.port or settings["port"]
    local_port = port + LOOPBACK_OFFSET
    url = f"http://localhost:{local_port}"
    if not single_instance():
        if not args.background:
            webbrowser.open(url)  # already running: just open the dashboard
        return

    setup_logging()
    log = logging.getLogger("orbi")
    store = Store(config.DATA_DIR / "orbi.db")
    tray = None
    log.info("Orbi Control %s", updater.current_version())
    update_note = updater.record_result(store, config.DATA_DIR)
    monitor = Monitor(store, notify=lambda t, m: tray and tray.notify(t, m))
    monitor.tamper = tamper.Tamper(monitor)
    monitor.start()

    app = create_app(monitor)
    common = dict(log_level="warning", access_log=False, log_config=None, proxy_headers=False)  # never trust X-Forwarded-For
    if settings.get("phone_https", False):
        cert, key = tls.ensure(_lan_ips())
        log.info("Phone link: HTTPS, certificate %s", tls.fingerprint(cert))
        server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, ssl_certfile=str(cert), ssl_keyfile=str(key), **common))
    else:
        log.warning("Phone link: plain HTTP on the home network (phone_https is off in settings)")
        server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, **common))
    local = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=local_port, **common))
    log.info("Orbi Control starting on port %s and %s (this PC only)", port, local_port)
    local_thread = threading.Thread(target=local.run, name="web-local", daemon=True)
    local_thread.start()
    if args.no_tray:
        server.run()
        local.should_exit = True
        return

    server_thread = threading.Thread(target=server.run, name="web", daemon=True)
    server_thread.start()

    from .tray import Tray

    def quit_all():
        monitor.tamper.stopped("Quit from the tray")
        monitor.stop()
        server.should_exit = True
        local.should_exit = True

    tray = Tray(monitor, url, quit_all)
    if update_note:
        threading.Timer(5, lambda: tray.notify(*update_note)).start()
    if not settings["pin_hash"] and not args.background:
        threading.Timer(2, lambda: webbrowser.open(url)).start()  # first run: open setup
    tray.run()
    server_thread.join(timeout=5)
    os._exit(0)


if __name__ == "__main__":
    main()
