"""Windows notification-area icon: live status color, quick actions, toast notifications."""
import threading
import webbrowser

import pystray
from PIL import Image, ImageDraw

COLORS = {"ok": (46, 160, 67), "warn": (219, 154, 4), "down": (218, 54, 51), "unknown": (130, 130, 130)}


def _icon_image(state: str) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = COLORS[state]
    d.ellipse((4, 4, 60, 60), fill=(40, 44, 52, 255))
    for i, r in enumerate((22, 15, 8)):  # wifi-style arcs
        d.arc((32 - r, 34 - r, 32 + r, 34 + r), 225, 315, fill=color + (255,), width=5)
        if i == 2:
            d.ellipse((28, 38, 36, 46), fill=color + (255,))
    return img


class Tray:
    def __init__(self, monitor, url: str, on_quit):
        self.monitor, self.url, self.on_quit = monitor, url, on_quit
        self.icon = pystray.Icon("OrbiControl", _icon_image("unknown"), "Orbi Control", menu=pystray.Menu(
            pystray.MenuItem(lambda item: self._status_text(), None, enabled=False),
            pystray.MenuItem("Open Orbi Control", self._open, default=True),
            pystray.MenuItem("Run speed test", self._speedtest),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        ))
        self._last_state = None

    def _status(self):
        st = self.monitor.state
        if st["internet"] is None:
            return "unknown", "Checking…"
        if not st["router"]:
            return "down", "Router unreachable"
        if not st["internet"]:
            return "down", "Internet down"
        offline = [s["name"] for s in st["satellites"] if not s.get("online", True)]
        if offline:
            return "warn", f"Satellite offline: {', '.join(offline)}"
        if st["scan_error"]:
            return "warn", "Online · router not answering"
        lat = st["latency_ms"]
        return "ok", f"Online{f' · {lat:.0f} ms' if lat else ''}"

    def _status_text(self):
        return self._status()[1]

    def refresh(self):
        state, text = self._status()
        if state != self._last_state:
            self.icon.icon = _icon_image(state)
            self._last_state = state
        self.icon.title = f"Orbi Control — {text}"[:120]

    def notify(self, title, message):
        try:
            self.icon.notify(message, title)
        except Exception:
            pass

    def _open(self, *_):
        webbrowser.open(self.url)

    def _speedtest(self, *_):
        if self.monitor.start_speedtest("manual"):
            self.notify("Speed test started", "Results in about a minute.")

    def _quit(self, *_):
        self.icon.stop()
        self.on_quit()

    def run(self):
        stop = threading.Event()

        def ticker():
            while not stop.wait(5):
                try:
                    self.refresh()
                except Exception:
                    pass
        threading.Thread(target=ticker, daemon=True).start()
        self.icon.run()  # blocks until Quit
        stop.set()
