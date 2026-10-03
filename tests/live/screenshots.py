"""Logs into a running instance with Firefox at phone size and screenshots every screen."""
import sys, time
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

BASE, PIN, OUT = sys.argv[1], sys.argv[2], Path(sys.argv[3])
opts = Options(); opts.add_argument("-headless"); opts.binary_location = r"C:\Program Files\Mozilla Firefox\firefox.exe"
if len(sys.argv) > 4 and sys.argv[4] == "light":
    opts.set_preference("ui.systemUsesDarkTheme", 0); opts.set_preference("layout.css.prefers-color-scheme.content-override", 1)
else:
    opts.set_preference("ui.systemUsesDarkTheme", 1); opts.set_preference("layout.css.prefers-color-scheme.content-override", 0)
d = webdriver.Firefox(options=opts)
d.set_window_size(430, 932)
errors = []
try:
    d.get(BASE)
    time.sleep(1.5)
    d.save_screenshot(str(OUT / "0-login.png"))
    pin = d.find_element(By.CSS_SELECTOR, ".pin-input"); pin.send_keys(PIN)
    d.find_element(By.CSS_SELECTOR, "form.login button").click()
    time.sleep(3)
    for tab in ["home", "devices", "family", "history", "more"]:
        d.find_element(By.CSS_SELECTOR, f'.tabs button[data-tab="{tab}"]').click()
        time.sleep(3.5)
        if d.find_elements(By.CSS_SELECTOR, "#view > .empty .spinner"):
            errors.append(f"{tab}: still loading")
        d.save_screenshot(str(OUT / f"{tab}.png"))
        # full-page capture for long screens
        d.set_window_size(430, max(932, d.execute_script("return document.body.scrollHeight") + 80))
        time.sleep(0.5); d.save_screenshot(str(OUT / f"{tab}-full.png")); d.set_window_size(430, 932)
    d.find_element(By.CSS_SELECTOR, '.tabs button[data-tab="devices"]').click(); time.sleep(3)
    d.find_elements(By.CSS_SELECTOR, ".row.tap")[0].click(); time.sleep(1)
    d.save_screenshot(str(OUT / "device-sheet.png"))
finally:
    d.quit()
print("screens saved;", "problems: " + "; ".join(errors) if errors else "no loading problems")
