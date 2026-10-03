"""Live check against the real router through a running app instance.
Usage: python tests/live/live_e2e.py http://localhost:8471 <test-device-mac> <test-device-ip>
Blocks the test device for ~15 s to prove pause/resume really cut it off."""
import subprocess, sys, time
import httpx

BASE, MAC, IP = sys.argv[1], sys.argv[2], sys.argv[3]
c = httpx.Client(base_url=BASE, timeout=60)
ok = lambda cond, msg: print(("  PASS " if cond else "  FAIL ") + msg) or bool(cond)
results = []

def ping_rate(secs):
    good = total = 0
    end = time.time() + secs
    while time.time() < end:
        total += 1
        good += subprocess.run(["ping", "-n", "1", "-w", "800", IP], capture_output=True).returncode == 0
        time.sleep(0.4)
    return good / total

s = c.get("/api/session").json()
if not s["pin_set"]:
    c.post("/api/setup", json={"pin": "424242"}).raise_for_status()
else:
    c.post("/api/login", json={"pin": "424242"}).raise_for_status()

print("waiting for the first router scan…")
for _ in range(60):
    st = c.get("/api/status").json()
    if st["last_scan"] and st["internet"] is not None:
        break
    time.sleep(2)
results.append(ok(st["internet"] is True and st["router"] is True, f"internet/router online (latency {st['latency_ms']:.0f} ms)"))
results.append(ok(st["info"].get("model") == "RBR750", f"router info: {st['info']}"))
results.append(ok(len(st["satellites"]) == 2 and all(x["online"] for x in st["satellites"]), "satellites: " + ", ".join(f"{x['name']} ({x['devices']} devices, {x['backhaul']})" for x in st["satellites"])))
results.append(ok(st["devices_online"] > 10, f"{st['devices_online']} devices online, router has {st['router_devices']}"))
results.append(ok(st["dns_filter"] is not None, f"DNS filter detected: {st['dns_filter']}"))
devs = c.get("/api/devices").json()
target = next((d for d in devs if d["mac"] == MAC), None)
results.append(ok(target is not None and target["online"], f"test device present: {target and target['name']} on {target and target['ap']}"))
results.append(ok(any(d["protected"] for d in devs), "this PC is marked protected"))

pid = c.post("/api/profiles", json={"name": "E2E Test", "emoji": "🧪"}).json()["id"]
c.patch(f"/api/devices/{MAC}", json={"profile_id": pid}).raise_for_status()
before = ping_rate(4)
t = time.time(); r = c.post(f"/api/profiles/{pid}/pause", json={"minutes": 5}).json()
results.append(ok(not r.get("error"), f"pause applied in {time.time()-t:.1f}s"))
time.sleep(2)
during = ping_rate(10)
t = time.time(); c.post(f"/api/profiles/{pid}/resume", json={}).raise_for_status()
results.append(ok(True, f"resume applied in {time.time()-t:.1f}s"))
time.sleep(3)
after = ping_rate(8)
results.append(ok(before > 0.5 and during < 0.2 and after > 0.5, f"device reachability before/paused/after: {before:.0%} / {during:.0%} / {after:.0%}"))
c.delete(f"/api/profiles/{pid}").raise_for_status()
results.append(ok(not any(d["blocked"] for d in c.get("/api/devices").json() if d["mac"] == MAC), "test device unblocked and profile removed"))

g = c.get("/api/guest").json()
results.append(ok("enabled" in g, f"guest Wi-Fi readable (enabled={g['enabled']})"))
print("running a speed test through the app (~1 min)…")
c.post("/api/speedtest", json={}).raise_for_status()
for _ in range(60):
    time.sleep(3)
    sp = c.get("/api/status").json()["speedtest"]
    if not sp["running"]:
        break
results.append(ok(sp["error"] is None and sp["last"], f"speed test: {sp['last'] and (round(sp['last']['down']), round(sp['last']['up']), sp['last']['ping'])} err={sp['error']}"))
hist = c.get("/api/history?hours=24").json()
results.append(ok(len(hist["points"]) >= 1, f"history has {len(hist['points'])} bucket(s)"))
print(f"\n{sum(results)}/{len(results)} live checks passed")
sys.exit(0 if all(results) else 1)
