# Changelog

What changed in each version, newest first. The same notes appear in the app under More → Updates.

## 1.1.18 (2026-10-23)

### Router watch
- New: an alert when Orbi Control can't work with the router for 10 minutes, whatever the reason (unreachable, a new security certificate, a rejected password), with a reminder every 2 hours until it's back. On reconnecting it re-checks the firewall rules and block list straight away.
- If the router restarts without the app asking (unplugged, a power cut, a crash), the app reconnects by itself when it's clearly the same router, and alerts "Router restarted". Unplugging the router no longer switches schedules off until a parent notices.
- The firewall rules and the block list are re-read every 15 minutes, so changes made on the router itself are caught. New alerts when rules are limited to a schedule, moved to other ports or narrowed to fewer devices, and when an address is given a pass through the block list.
- New: Outside check-in (More). The app checks in with a free healthchecks.io check every 5 minutes, so you're alerted when this PC goes offline or is turned off.

### Block apps & sites
- AI chatbots (ChatGPT, Claude, Gemini, Copilot, Grok, Character.AI and more) and social media (Instagram, Snapchat, X, Reddit, Discord, WhatsApp and more) can be blocked, in groups with All and None buttons.
- The router keeps only a keyword's main name and blocks every address containing it, so keywords whose main name is shorter than 4 letters are refused (api.x.ai would have blocked everything with an "x", Netflix included).
- Fixed: saving a long list failed partway through.
- Fixed: the card spun forever when the router couldn't be read; it now says why and offers Try again.

## 1.1.17 (2026-10-20)

### Security
- New: Device check (More → Device check, off until you turn it on). Once a day it checks every device in the house, the router and its satellites for logins that travel unencrypted (Telnet, FTP, admin pages on plain http), ports that malware and router backdoors use, and known serious vulnerabilities in the firmware each device reports, with the version that fixes them. Anything attackers are actively using is marked urgent. It never tries passwords, and only product names and versions are looked up online (in NIST's and CISA's public vulnerability lists).
- The Security checklist now includes the Device check's results.

## 1.1.16 (2026-10-20)

### Security
- New: a Security checklist at the top of More. It checks the things a paid "network security" subscription's scan looks for (malicious-site filtering, the rules that stop DNS and VPN workarounds, WPS, Wi-Fi encryption, devices open to remote control, firmware checks, failed-login alerts) and says where to fix each one.
- New: fake-router alert. You're told if another device starts answering as the router, or starts handing out addresses on your network, which can send the house's traffic through that device. It names the device when it can.
- New: unusual-upload alert. You're told when the house uploads far more than it normally does at that time of day for 45 minutes. The Orbi only counts the whole house, so the alert lists what was online and how much this PC sent rather than naming one device. It learns your normal for 5 days first.
### Family and History
- Blocked VPN attempts are now listed in History instead of on the Family page.

## 1.1.15 (2026-10-15)

- New: every pop-up has an X in the top corner to close it, and it stays in view when you scroll a long list.
- New: the remote-access check (SSH, Remote Desktop, VNC and the like) can be turned on or off in More → Remote access. It's off unless you turn it on; turning it on checks every device right away, then once a day.
- Fixed: on iPhone, the Change PIN boxes on the More page ran off the side of the screen.
- Fixed: in Break-in attempts, "Show what was typed" was cut off at the edge of the screen. It now shows on its own line.

## 1.1.14 (2026-10-13)

- Fixed: an internet outage (or router-unreachable or PC-offline alert) that was still open when Orbi Control restarted stayed "ongoing" in History forever and lowered the uptime figures. It's now closed at the moment the internet was first seen working again, and the stuck one is fixed when you update.

## 1.1.13 (2026-10-13)

- The remote-access watch now checks the house once a day instead of every 30 minutes. Check now under More → Remote access still runs it any time.

## 1.1.12 (2026-10-13)

### Alerts on your phone
- Every alert can now go to your phone, wherever you are, not just to the tray on this PC. Set it up under More → Phone alerts with the free ntfy app (iPhone and Android, no account).
- The code your phone subscribes with is random and stored encrypted. Showing it, replacing it and turning phone alerts off are recorded in History, and your phone is told first, so they can't be switched off without you knowing.
### Remote-access watch
- Every 30 minutes Orbi Control checks every device in the house, this PC and the router for remote-control services: SSH, Telnet, Remote Desktop, VNC, TeamViewer, AnyDesk and PowerShell remoting.
- You get an alert when a device starts accepting them. The first check reports whatever is already open. See the list under More → Remote access.

## 1.1.11 (2026-10-13)

### More content filters
- Six more services to choose from: Control D Family (blocks adult sites, forces Google and Bing SafeSearch and YouTube Restricted Mode), OpenDNS FamilyShield, Control D No Social (blocks social media but not adult sites), and Quad9, Cloudflare and CleanBrowsing malware-only filters.
- The list is grouped by what each one blocks, and the malware-only and social-only ones say plainly that they don't block adult sites.
- You get an alert if the router switches from a filter that blocks adult sites to one that doesn't.
### Your own NextDNS or OpenDNS account
- NextDNS and OpenDNS Home let you choose exactly what's blocked on their website. They only filter while they know your home's internet address, so Orbi Control keeps them told: right away when you connect, before switching the router, and every 15 minutes after. If that fails twice in a row you get an alert.
- NextDNS connects with the update link from its setup page. OpenDNS Home uses your OpenDNS login, stored encrypted on this PC.
- You have to confirm the account is set up before switching to it, since until then it filters nothing.

## 1.1.10 (2026-10-12)

### Parental controls that can't be quietly bypassed

- Other programs on this PC can no longer move a device to a different profile, change its block status, or add, edit, or remove a schedule - the same protection that already covered History now covers these too.
- Moving a device between profiles, and adding, changing, or removing a schedule, now show up in History with who did it.

## 1.1.9 (2026-10-10)

### History that can't be quietly erased
- Other programs on this PC can no longer delete Orbi Control's alerts or router log.
- Every alert is also copied to the Windows Event Log (Event Viewer > Windows Logs > Application, source "Orbi Control"). Alerts deleted anyway are put back from that copy.
- New alerts when history is deleted, when alert or protection switches are turned off from outside the app (they're switched back on), when the PIN is changed while the app was stopped, when the app is shut down without Quit, and when the Windows log is cleared.
### Devices
- Devices shows what the router itself says each device is (brand and kind), and you get an alert when a device's own name doesn't fit, such as a laptop calling itself an Echo.
- While a profile's devices are cut off, History notes when one moves to a different Orbi.
### More
- More router details: firmware install date, auto-update and last check, first setup date, average CPU.
- Usage details now include this week, this month and last month, with per-day averages.

## 1.1.8 (2026-10-09)

### Break-in detection on the PIN page
- Every PIN attempt is recorded under More → Break-in attempts: the device it came from (by hardware address), the program that sent it, and what was typed. What was typed is encrypted, kept 30 days, never written to the log, and erased when that device then signs in, since it was probably a typo of the real PIN.
- A program attacking the PIN page (PINs faster than anyone can type, guessing straight through the lockout, a client that isn't a web browser, or dozens of requests without signing in) raises an immediate alert. That device is shut out of the app for 24 hours and blocked at the router (you can switch the router block off). This PC is never shut out.
- Unblocking the device in Devices, or "Let it back in", lifts the ban.

### Router certificate after a filter change
- Saving the router's Internet settings, which is how the content filter is changed, makes the Orbi create a new security certificate. Orbi Control used to cut itself off from the router until someone trusted it by hand. It now follows the router to its new certificate and trusts it on its own, only if it's Netgear's own certificate from the router's hardware address. History records it, and the filter change finishes normally.

### Reports
- A device that set another device's address by hand is now credited with what it tried from that address, instead of the device the router gave the address to.

After updating, sign in again (the restart signs everyone out).

## 1.1.7 (2026-10-08)

### Catching a device that's trying to get around the controls
- Someone guessing the PIN: three wrong PINs from one device within an hour now raise an alert (at most once an hour per device), including attempts made while PIN entry is locked. Before, they were only locked out, and nothing told you.
- A device passing as another: if a device is using an address the router gave to a different device, its address was set by hand. That's how a laptop renamed "Echo" can take the real Echo's address and land in an unrestricted profile. You now get an alert naming both devices.
- The activity log names the right device: sign-ins and changes are credited to the device by its hardware address at that moment, not by whichever device last had that address. A device using someone else's address shows as "X, using Y's address".
- A weekly check of devices without limits: with Sunday's reports, History lists the devices that had no bedtime or limits that week. Any that joined that week, or tried to get around the content filter, are named, so a kid's device hiding in an adults' profile gets noticed.

After updating, sign in again (the restart signs everyone out).

## 1.1.6 (2026-10-08)

### New for parents
- Reports: for each profile, see what its devices tried that got blocked: sites and apps, attempts to get around the content filter, VPN attempts, and joining the IoT or Guest Wi-Fi. A weekly summary goes into History every Sunday evening.
- An alert when a device in a profile with schedules (or a paused one) joins the IoT or Guest Wi-Fi.
- Later bedtime tonight: evening schedules start 30 minutes to 2 hours later for one night. Morning times don't change, and everything is back to normal the next day.

### New for the network
- Address reservations: add, edit and delete them on the Advanced tab, or use Devices → a device → Reserve this address. Every change is read back from the router to confirm it took.
- UPnP on/off. Turning it off warns you which devices use it. Manual port-forwarding rules are listed too.
- A weekly backup of the router's settings to this PC (the last 8 are kept).
- An alert when new router firmware is available (checked twice a day).

### Wi-Fi changes that actually stick
- The Orbi doesn't always disconnect devices that were already connected when a network gets a new name or password, or is turned off. They can stay on with the old password until the router restarts. About 2 minutes after you change the IoT Wi-Fi, or turn the Guest Wi-Fi off, the app checks which devices stayed on. If any did, you get an alert and the offer to restart the router now or tonight at 3 AM. It also lists the devices that came back with the new password, so you can spot one that shouldn't have it. After the restart, it reports who rejoined.
- Restarting the router from the app now saves the router's log first, because a restart clears it. It also warns you if a satellite is offline. A restart scheduled for 3 AM is skipped (and you're told) if this PC was asleep then, rather than happening later in the morning.
- WPS on the Advanced tab. Pressing Sync on the router (and probably on a satellite) lets a device that supports WPS join your main Wi-Fi without the password for 2 minutes. This Orbi firmware has no setting to turn WPS off, and the router doesn't log it. Keep "Hold new devices" on so a device that joins this way stays blocked until you approve it.

### Security
- The Orbi makes itself a new security certificate every time it restarts, which used to stop the app until someone chose "Trust the router's new certificate". After a restart the app asked for, it now trusts the new certificate on its own, but only if all of these are true: it's Netgear's own router certificate, it was created after the restart, it shows up within 20 minutes, and it comes from the router's hardware address as recorded before the restart. Anything else stops the app and alerts you, as before.
- Text the app types into the router's pages (the IoT network name and password, and the Dynamic DNS user name and password) can no longer contain " \ < > or `. The router puts these values inside its own pages, so they could have been used to plant script there.
- Later bedtime and turning UPnP on now send a notification, because both loosen controls.

After updating, sign in again (the restart signs everyone out).

## 1.1.5 (2026-10-07)

### New
- See who's on your home VPN. "Away from home" (More) lists recent connections to the Orbi's own VPN server, from the router log: when each one started, when it ended (if the router logged it) and the address it came from. Phones on mobile data reconnect every few minutes, so those are grouped into one session; "Show all" has two weeks. The Orbi doesn't record who connected, only from where.
- Alerts for failed VPN connections from outside your home, once per burst. That would mean a device without a working VPN profile is trying to get in. Failed attempts from inside your home (usually your own phone trying the VPN while on Wi-Fi) are listed but not alerted. Connections and disconnections also appear in History → Activity.
- Dynamic DNS. "Away from home" shows the router's Dynamic DNS name and checks that it points at your current internet address. You can change the No-IP or Dyn settings there (the password is never shown). The Orbi's VPN uses this name to find your home from outside, so the screen warns before you change it.
- Which Wi-Fi network each device is on. Devices now shows the main, guest or IoT network for every wireless device, with new Guest Wi-Fi and IoT Wi-Fi filters.

### Reorganized
- The Advanced tab now holds only network setup: Internet, LAN & DHCP, the Wi-Fi networks (main, Guest and IoT together), firewall rules and port forwarding.
- Router details (model, firmware, uptime, memory) moved to the Router card on More, next to reboot and the firmware check.
- The router log moved to History.
- Blocked VPN-app attempts moved to Family → Whole house.
- The satellites table is gone: tap a satellite on Home to see its IP, firmware, MAC and backhaul.

After updating, sign in again (the restart signs everyone out).

## 1.1.4 (2026-10-07)

New: firewall rules and IoT Wi-Fi (Advanced tab)
- Firewall rules (the router's Block Services): add, edit and delete rules, choosing the ports, protocol, and whether a rule covers every device, one address or a range. You can also choose when rules apply (always, on the blocking schedule, or never). Each change is read back from the router to confirm it took, and is recorded with the device that made it. Removing or narrowing a rule, or turning rules off, sends an alert.
- IoT Wi-Fi: turn the separate IoT network on or off and change its name, band, security and password. Saving restarts the router's Wi-Fi for about a minute; afterwards the app checks that your main Wi-Fi settings came back unchanged. The password is never displayed.
- The "block DNS & VPN workarounds" button now also repairs its own rules if one covers only some devices. An earlier version could save a rule for the PC running the app only, so press the button once after updating to check.

### Security
- Router certificate pinning. The router uses a self-signed certificate, which the app used to accept from anything answering at the router's address. Now it remembers the router's certificate the first time it connects, and every connection that carries the admin password (the router API, the log reader and the browser that drives the admin pages) refuses any other certificate. A device on your network pretending to be the router can't capture the password.
  - If you update the router's firmware or factory-reset it, its certificate may change. The app then stops talking to the router and alerts you; choose "Trust the router's new certificate" under More → Router to continue.
- geckodriver (the program that lets the app drive Firefox) is now pinned to version 0.37.1 and checked against its known hash before it runs, instead of Selenium downloading whatever version it chose.

### Fixes
- iPhones (especially the home-screen web app) could keep running an old copy of the app after an update. The app now always loads its current script and styles.

After updating, sign in again (the restart signs everyone out).

## 1.1.3 (2026-10-06)

### Security
- Updates are now signed. Each release is signed with a key that never leaves the maintainer's PC, and the app checks every downloaded file against that signature before installing. An unsigned or altered release is refused, so taking over the GitHub account isn't enough to push code to your PC. (Your current version doesn't check signatures yet, so this update installs the way updates always have; every update after it is checked.)
- Turning off "Allow updates" (More → Updates) now blocks installing as well as checking.
- A device signs itself out after 30 minutes without use, even with the page left open. Restarting the app (including after an update) signs everyone out, so sign in again after updating.
- Wrong-PIN lockout is fairer: misses are forgotten after an hour, wrong PINs sent from other devices can't lock you out at the PC running the app, and a correct PIN no longer restarts anyone else's lockout.
- Removing an extra PIN signs out the devices that used it.
- Changing the router address clears the saved router password, so it's never sent to a new address until you type it again.
- The sign-in screen no longer shows the app version to people who aren't signed in.
- All dependencies are pinned with their published hashes, and Selenium's usage statistics are turned off.

### Know who changed what
- Every change made in the app is recorded with the device that made it (for example "Whole-house blocking updated · by Kids-iPad (192.168.1.40)"), and sign-ins are recorded too.
- You get an alert when sites are removed from whole-house blocking, blocking is turned off, or the content filter is switched off or changed.

### Network
- Satellite backhaul alerts: if a satellite that normally uses a wired (Ethernet) connection falls back to wireless, you get an alert, and Status marks it "Wireless" until the cable link is back. (Requested by the community.)
- "Is it the internet or just my VPN?": when the PC running Orbi Control loses the internet but the router is still online, it now says "Your VPN dropped; the internet is fine" (or that the problem is on this PC) instead of reporting an outage, and it doesn't count against uptime. (Requested by the community.)
- When a real outage ends, it says whether the router restarted during it or your public IP changed (the modem or provider reset the connection).

### Other
- The "block DNS & VPN workarounds" button now explains first that the rules apply to every device, including work laptops on OpenVPN or WireGuard.
- The README lists every outside connection the app makes.

## 1.1.2 (2026-10-04)

- Fixes the restart step of in-app updates. If you installed 1.1.0 or 1.1.1, update to this version once by hand; after that, More -> Updates handles it.

## 1.1.1 (2026-10-04)

- Fixes Update now in More -> Updates.
- Release notes in the app now show this summary instead of developer notes.

## 1.1.0 (2026-10-04)

- In-app updates: More -> Updates checks for new versions and installs them with one click, with automatic rollback if the new version doesn't start.
- Security fixes from an outside review: file API removed, stronger PIN lockout, extra PINs cleared on PIN change, sign-out revokes the session, HTTPS-only router login.
- Satellite-offline alerts arrive within minutes.
- New button to add router rules that block DNS and VPN workarounds.
