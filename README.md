# Orbi Control

A local replacement for the Netgear Orbi app. It runs on a Windows PC, talks to the Orbi directly over its local admin API (no Netgear cloud), and serves a web app you can use from the PC or install on your phone's home screen. Tested against an RBR750 + two RBS750 satellites on firmware V7.2.8.8.

## What it does

- **Status:** internet up/down with latency, uptime over 24 h / 7 d / 30 d, router and satellite health (backhaul type, signal, device counts), public IP, content-filter DNS detection.
- **Outage log:** checks the internet every 30 s and records each outage with its start, its duration, and the likely cause (WAN/modem link down vs. ISP vs. router not responding). You get Windows notifications for outages, satellites going offline, and new devices.
- **Devices:** every connected device, grouped by router/satellite, with IP, band, signal and link rate. You can rename devices, block or unblock them, and search or filter the list.
- **Family (parental controls):** put each person's devices in a profile, then:
  - pause their internet (15 min to "until I resume");
  - set schedules (Bedtime, School hours, etc.; overnight schedules work);
  - give extra time.

  Devices that aren't in a profile, including any brand-new device, follow an optional **default profile** ("Everyone else"). That counters kids changing their device's MAC address, because a new address just lands in the default rules. A new address whose device name matches a device already in a profile is held until you approve it, with that profile already selected. It isn't joined automatically, because a device name is easy to fake. You can also **hold brand-new devices** blocked until you approve them.
  Blocking is enforced by the Orbi's Access Control, so it covers every app and browser. The app also re-applies blocks if they're changed outside it, such as in the official Orbi app.
- **Content filtering:** choose the router's family-DNS service (AdGuard Family by default: SafeSearch, YouTube Restricted Mode, adult sites blocked, Reddit allowed; it also blocks ads and trackers, which stops some streaming apps such as ESPN from playing). A change snapshots the Internet settings, then verifies the internet still works and rolls back automatically if it doesn't. It applies to the whole house, because the Orbi relays DNS for every device and can't filter per device.
- **Block apps & sites:** presets (TikTok, Roblox, Instagram, Fortnite…) plus custom keywords, all the time or on a schedule. The Orbi's Block Sites feature enforces them, so blocking works even when the PC is off. Whole house only.
- **DNS & VPN workarounds:** one button (under Content filtering) adds router rules that block outside DNS (port 53), DNS-over-TLS (853) and the standard VPN ports (OpenVPN 1194, WireGuard 51820). Without those rules, devices can sidestep the filter. Once they're in place, you get an alert naming any device that tries.
- **Advanced tab** (switch on under More): router, WAN, LAN/DHCP with reservations, Wi-Fi radios, satellites, the VPN server's status, firewall rules, UPnP port forwards, and the searchable router log (DHCP assignments, blocked attempts, admin logins). Failed admin logins raise a security alert.
- **Controls:** guest Wi-Fi on/off (and show its password), router reboot, firmware check, speed tests run by the router (on demand plus a daily test at 04:00).
- **History:** connection timeline, outages, speed-test trends, daily data usage, activity log.

## Using it

- On this PC: http://localhost:8470 (or the tray icon → Open). The tray icon turns green, amber, or red with status.
- On your phone: run `allow-phone-access.ps1` once and approve the admin prompt. Then open the address shown under **More → Use it on your phone** (or scan its QR code) while on home Wi-Fi, and add it to your home screen.
- The first time you open it, choose a PIN. Do this on the PC **before** running `allow-phone-access.ps1`, because whoever opens the app first sets it. Everyone on your Wi-Fi can reach the page, so the PIN keeps kids from unpausing themselves. Prefer a passphrase over 6 digits; any characters work. After 5 wrong guesses from one device, or 20 across the house, PIN entry locks, with lockouts that grow longer each time. Changing the PIN removes any extra PINs and signs out every other device.

## Reliability

- One serialized router session with automatic re-login. Slow calls (the Orbi takes 10–20 s to list devices) never block health checks.
- Every background loop restarts itself after errors, and a supervisor revives dead threads.
- A Windows scheduled task starts the app at logon and checks every 5 minutes that it's running (tested by killing the process: it came back within about a minute).
- The device running Orbi Control is never blocked, and the app only ever unblocks devices that it blocked itself.
- The router password is stored encrypted with Windows DPAPI under `%LOCALAPPDATA%\OrbiControl`. The database and logs are kept there too.

## Limits

- Orbi satellites don't accept commands over this API, so you can reboot the whole router but not one satellite.
- Monitoring and schedule changes need the PC to be on. Blocks that are already applied stay in force on the router while it's off.
- Phones that use a "Private Wi-Fi address" that keeps rotating look like new devices. Turn rotation off for your home network on kids' devices.
- The Orbi doesn't report usage per device, only totals for the network. So there are no per-device time limits; use schedules, pause and extra time instead.
- Content filtering and app blocking apply to the whole house. Per-person filtering needs device-level controls (Apple Screen Time / Google Family Link).
- The app is plain HTTP on your home network, so your PIN and session cookie travel unencrypted over Wi-Fi. Anyone already on your network who can capture traffic could read them. Skip `allow-phone-access.ps1` if you only use it on this PC.
- The router's admin pages use a self-signed certificate, so the app can't verify it. It only ever logs in over HTTPS, and only to a private (LAN) address.
- Browsers that use their own encrypted DNS (DNS-over-HTTPS) can sidestep DNS-based filtering. The protection rules block encrypted DNS on port 853, but not DNS-over-HTTPS, which shares port 443 with normal web traffic.
- The Orbi doesn't report who is connected to its VPN server.
- Settings only available on the router's admin pages (DNS, Block Sites, schedules, block rules, VPN status) are read and changed by driving those pages in a headless Firefox. Firefox must stay installed.

## Install / uninstall

```powershell
.\install.ps1              # venv + dependencies, auto-start at logon with watchdog, starts it now
.\allow-phone-access.ps1   # for phones (home Wi-Fi and the Orbi VPN): marks the home network Private + opens port 8470 to Orbi Control's Python on Private networks only (asks for admin once)
.\uninstall.ps1            # stop and remove auto-start; also undoes allow-phone-access (firewall rule + network category)
```

## Development

```
orbi/router.py     Orbi SOAP access (pynetgear) — serialized, retried, normalized
orbi/monitor.py    health checks, outage tracking, scans, speed tests, block enforcement
orbi/parental.py   pure schedule/pause logic
orbi/web.py        FastAPI API + serves web/
orbi/tray.py       Windows tray icon and notifications
orbi/routerui.py   router admin pages via headless Firefox (reads/writes), router log via plain HTTPS
orbi/filtering.py  family-DNS providers, live verification, safe apply with rollback
web/               the app (vanilla JS, no build step)
```

- `pip install -r requirements-dev.txt` then `pytest`. The tests use a fake router: schedules (including overnight and week-wrap), precedence of pause, extra time and schedules, enforcement and self-healing, outage detection, auth and lockout, and the full API.
- `tests/live/live_e2e.py <url> <mac> <ip>` runs against a real router through a running instance. It briefly pauses one test device and confirms with ping that the device really goes offline.
- `tests/live/screenshots.py <url> <pin> <outdir> [light]` takes phone-sized screenshots of every screen.
