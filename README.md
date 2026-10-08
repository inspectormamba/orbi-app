# Orbi Control

A local replacement for the Netgear Orbi app. It runs on a Windows PC, talks to the Orbi directly over its local admin API (no Netgear cloud), and serves a web app you can use from the PC or install on your phone's home screen. Tested against an RBR750 + two RBS750 satellites on firmware V7.2.8.8.

## What it does

- **Status:** internet up/down with latency, uptime over 24 h / 7 d / 30 d, router and satellite health (backhaul type, signal, device counts), public IP, content-filter DNS detection.
- **Outage log:** checks the internet every 30 s and records each outage with its start, its duration, and the likely cause (WAN/modem link down vs. ISP vs. router not responding). When it ends, it also says whether the router restarted during it or your public IP changed (the modem or provider reset the connection). If only this PC loses the internet while the router is still online, that's reported separately and doesn't count against uptime: "Your VPN dropped; the internet is fine" when this PC's traffic goes through a VPN, otherwise a problem on this PC (adapter, firewall, proxy). You get Windows notifications for outages, satellites going offline, and new devices. A satellite that normally uses a wired (Ethernet) backhaul and falls back to wireless raises an alert (once two device scans in a row agree, so within 2–4 minutes at the default 2-minute scan interval), and Status marks it "Wireless" until the cable link is back.
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
- **Advanced tab** (switch on under More): WAN, LAN/DHCP with reservations, the Wi-Fi networks, firewall rules and UPnP port forwards.
  - **Firewall rules** (the router's Block Services): add, edit and delete rules (ports, protocol, and every device, one address or a range) and choose when they apply. Each change is read back from the router to confirm it, and removing or narrowing a rule, or turning rules off, raises an alert.
  - **Wi-Fi networks:** the main network, Guest Wi-Fi (on/off, show its password) and IoT Wi-Fi together. IoT Wi-Fi: turn the separate IoT network on or off and change its name, band, security and password. Saving restarts the router's Wi-Fi for about a minute; the app then checks your main Wi-Fi settings came back unchanged. The password is never shown.
- **Controls (More):** router details (model, firmware, uptime, memory), router reboot, firmware check, speed tests run by the router (on demand plus a daily test at 04:00).
- **Away from home (More):** whether the Orbi's VPN server is on, and the router's Dynamic DNS (No-IP or Dyn), with a check that the name points at your current internet address. You can change the Dynamic DNS settings there; the password is never shown. It also lists recent connections to the Orbi's VPN from the router log (when and from which address; the Orbi doesn't log who), and failed connection attempts from outside your home raise an alert.
- **History:** connection timeline, outages, speed-test trends, daily data usage, activity log, and the searchable router log (DHCP assignments, blocked attempts, admin logins). Failed admin logins raise a security alert.
- **Family → Whole house** also lists devices that tried to use a VPN app and were blocked. Tapping a satellite on Home shows its IP, firmware, MAC and backhaul.

## Using it

- On this PC: http://localhost:8470 (or the tray icon → Open). The tray icon turns green, amber, or red with status.
- On your phone: run `allow-phone-access.ps1` once and approve the admin prompt. Then open the address shown under **More → Use it on your phone** (or scan its QR code) while on home Wi-Fi, and add it to your home screen.
- The first time you open it, choose a PIN. Do this on the PC **before** running `allow-phone-access.ps1`, because whoever opens the app first sets it. Everyone on your Wi-Fi can reach the page, so the PIN keeps kids from unpausing themselves. Prefer a passphrase over 6 digits; any characters work. After 5 wrong guesses from one device, or 20 across the house, within an hour, PIN entry locks, with lockouts that grow longer each time. Wrong guesses are forgotten after an hour, and the house-wide lockout never applies to this PC, so wrong PINs sent from another device can't lock you out at the PC. Changing the PIN removes any extra PINs and signs out every other device; removing an extra PIN signs out the devices that used it.
- A device signs itself out after 30 minutes without use, and restarting the app signs everyone out.
- Every change made in the app is recorded with the device that made it (Recent alerts and History). If whole-house blocking loses sites, or the content filter is switched off, you get an alert.

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
- Outside connections: the update check to GitHub (can be turned off), a one-time download of geckodriver (the program that drives Firefox) from Mozilla's GitHub releases, checked against a pinned hash before it's used, and connection checks to 1.1.1.1, 8.8.8.8 and 9.9.9.9 (port 443) every 30 seconds to tell an internet outage from a router problem. While this PC can't reach those, it also asks the router to look up a made-up name under example.com, which only the internet can answer, to tell whether the whole house is offline or just this PC. Selenium's usage statistics are turned off.
- The app is plain HTTP on your home network, so your PIN and session cookie travel unencrypted over Wi-Fi. Anyone already on your network who can capture traffic could read them. Skip `allow-phone-access.ps1` if you only use it on this PC.
- The router's admin pages use a self-signed certificate, which can't be verified the usual way, so the app pins it: the first time it connects to a router address it remembers the certificate's SHA-256 fingerprint, and from then on the SOAP API, the log reader and Firefox all refuse any other certificate before sending the admin password. A firmware update or factory reset can change the certificate; the app then stops, raises an alert, and waits for you to choose "Trust the router's new certificate" under More → Router. It only ever logs in over HTTPS, and only to a private (LAN) address. Changing the router address clears the saved password, so it is never sent to a new address until you type it in again.
- Browsers that use their own encrypted DNS (DNS-over-HTTPS) can sidestep DNS-based filtering. The protection rules block encrypted DNS on port 853, but not DNS-over-HTTPS, which shares port 443 with normal web traffic.
- The Orbi doesn't report who is connected to its VPN server.
- Settings only available on the router's admin pages (DNS, Block Sites, schedules, block rules, VPN status) are read and changed by driving those pages in a headless Firefox. Firefox must stay installed.

## Install / uninstall

```powershell
.\install.ps1              # venv + dependencies, auto-start at logon with watchdog, starts it now
.\allow-phone-access.ps1   # for phones (home Wi-Fi and the Orbi VPN): marks the home network Private + opens port 8470 to Orbi Control's Python on Private networks only (asks for admin once)
.\uninstall.ps1            # stop and remove auto-start; also undoes allow-phone-access (firewall rule + network category)
```

## Updating

Download the zip from GitHub (Code → Download ZIP) and the app can update itself. Clone with git instead if you'd rather review every change yourself; a git copy never updates itself.

- Twice a day it checks this repository's version tags (`vX.Y.Z`) for a newer release. You get a Windows notification, and **More → Updates** shows what changed. Turning updates off there stops both the check and installing.
- Every release is signed with the project's release key, which lives on the maintainer's PC and never on GitHub. Before installing, the app hashes every downloaded file and checks the signature against the key built into it, and refuses anything unsigned or changed. So taking over the GitHub account isn't enough to push code to your PC.
- **Update now** downloads that release from this repository over HTTPS and backs up the current code. It swaps in the new code (your settings, history and `.venv` are kept), reinstalls dependencies only if `requirements.txt` changed, and restarts the app. Everyone is signed out by the restart.
- If the new version doesn't start within 2 minutes, the previous version is restored and restarted automatically, and Recent alerts says so.
- Nothing installs without someone clicking Update. A copy cloned with git is never touched: update it with `git pull` and restart the app.
- Copies installed before version 1.1.2 have no working updater, so update those once by hand: download the zip, copy its files over the old folder, and restart the app. Versions before 1.1.3 don't check signatures; they start checking once they're on 1.1.3.

**Publishing an update** (only from the PC with the release key): set `VERSION` to the new number (e.g. `1.2.0`) and commit. Then run `.venv\Scripts\python scripts\release.py 1.2.0 "What changed"`, which adds the notes to `CHANGELOG.md` (as its own commit) and creates the signed tag, and `git push origin main --tags`. The notes are shown in the app as the release notes, so write them for users. A tag made with plain `git tag` won't install.

## Development

```
orbi/router.py     Orbi SOAP access (pynetgear) — serialized, retried, normalized
orbi/monitor.py    health checks, outage tracking, scans, speed tests, block enforcement
orbi/parental.py   pure schedule/pause logic
orbi/web.py        FastAPI API + serves web/
orbi/tray.py       Windows tray icon and notifications
orbi/routerui.py   router admin pages via headless Firefox (reads/writes), router log via plain HTTPS
orbi/filtering.py  family-DNS providers, live verification, safe apply with rollback
orbi/updater.py    update check against GitHub tags, signature check, download, swap with backup, restart helper with rollback
orbi/ed25519.py    release signatures (RFC 8032 reference code, no dependencies)
scripts/release.py        tag and sign a release; --verify checks an existing tag
scripts/lock_requirements.py  regenerate the hash-pinned requirements.txt from requirements.in
orbi/routercert.py router certificate pinning (trust on first use) for every connection that carries the password
orbi/geckodriver.py the pinned geckodriver version and its hashes; to upgrade, verify the new release and update all three
web/               the app (vanilla JS, no build step)
```

- `pip install -r requirements.txt`, then `pip install -r requirements-dev.txt`, then `pytest`. `requirements.txt` pins every package with its hashes; change versions in `requirements.in` and run `scripts/lock_requirements.py`. The tests use a fake router: schedules (including overnight and week-wrap), precedence of pause, extra time and schedules, enforcement and self-healing, outage detection, auth and lockout, and the full API.
- `tests/live/live_e2e.py <url> <mac> <ip>` runs against a real router through a running instance. It briefly pauses one test device and confirms with ping that the device really goes offline.
- `tests/live/screenshots.py <url> <pin> <outdir> [light]` takes phone-sized screenshots of every screen.
