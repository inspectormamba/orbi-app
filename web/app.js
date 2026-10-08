"use strict";
// Orbi Control web app: vanilla JS, no build step.

const $ = (sel, root = document) => root.querySelector(sel);
const view = $("#view");
const setView = (...nodes) => view.replaceChildren(...nodes.flat().filter(Boolean));
const fill = (el, ...nodes) => el.replaceChildren(...nodes.flat().filter((n) => n !== null && n !== undefined && n !== false));
let currentTab = "home";
let refreshTimer = null;
let cache = { status: null, devices: null, profiles: null };

// ---------- helpers ----------
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k === "html") el.innerHTML = v; // only used for trusted, app-generated SVG
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}

async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body !== undefined ? "POST" : "GET"), headers: {}, credentials: "same-origin" };
  if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  let res;
  try { res = await fetch(path, init); }
  catch { throw new Error("Can't reach Orbi Control. Is the PC on and connected?"); }
  if (res.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/settings/pin")) { showLogin(); throw new Error("Sign in required"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`);
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 3200);
}

async function act(btn, fn, okMsg) {
  const old = btn && btn.innerHTML;
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>'; }
  try {
    const r = await fn();
    if (r && r.note) toast(r.note); else if (r && r.error) toast(`Router: ${r.error}`); else if (okMsg) toast(okMsg);
    return r;
  } catch (e) { toast(e.message); throw e; }
  finally { if (btn && btn.isConnected) { btn.disabled = false; btn.innerHTML = old; } }
}

const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
const fmtDay = (ts) => new Date(ts * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
function fmtWhen(ts) {
  const d = new Date(ts * 1000), now = new Date();
  if (d.toDateString() === now.toDateString()) return fmtTime(ts);
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return `Yesterday ${fmtTime(ts)}`;
  return `${fmtDay(ts)} ${fmtTime(ts)}`;
}
function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
function dur(sec) {
  sec = Math.round(sec);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60); if (m < 60) return `${m} min`;
  const hr = Math.floor(m / 60); if (hr < 48) return `${hr}h ${m % 60}m`;
  return `${Math.floor(hr / 24)}d ${hr % 24}h`;
}
function fmtMB(mb) {
  if (mb == null) return "—";
  if (mb >= 1e6) return `${(mb / 1e6).toFixed(2)} TB`;
  if (mb >= 1000) return `${(mb / 1000).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}
const pct = (v) => (v == null ? "—" : `${v >= 99.995 ? "100" : v.toFixed(v >= 99 ? 2 : 1)}%`);
const untilText = (iso) => (iso ? new Date(iso).toLocaleString([], { weekday: new Date(iso).toDateString() === new Date().toDateString() ? undefined : "short", hour: "numeric", minute: "2-digit" }) : "");

function signalBars(signal, conn) {
  if (conn === "wired") return h("span", { class: "pill" }, "Wired");
  if (signal == null) return null;
  const level = signal >= 70 ? 4 : signal >= 50 ? 3 : signal >= 30 ? 2 : 1;
  const color = level >= 3 ? "var(--ok)" : level === 2 ? "var(--warn)" : "var(--bad)";
  return h("span", { class: `bars s${level}`, style: `color:${color}`, title: `Signal ${signal}%`, "aria-label": `Signal ${signal}%` }, h("i"), h("i"), h("i"), h("i"));
}

const ICONS = {
  wifi: '<svg viewBox="0 0 24 24"><path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/></svg>',
  wired: '<svg viewBox="0 0 24 24"><rect x="7" y="3" width="10" height="8" rx="1"/><path d="M12 11v10M9 7h6"/></svg>',
  router: '<svg viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 9a6 6 0 0 1 8 0M5.5 6.5a10 10 0 0 1 13 0"/></svg>',
  sat: '<svg viewBox="0 0 24 24"><rect x="7" y="4" width="10" height="16" rx="5"/><path d="M12 8v3"/></svg>',
};
const ico = (name) => h("span", { class: "ico", html: ICONS[name] });

// ---------- sheet ----------
function openSheet(...content) {
  const sheet = $("#sheet");
  sheet.replaceChildren(h("div", { class: "grab" }), ...content.flat().filter(Boolean));
  sheet.hidden = false; $("#sheet-backdrop").hidden = false;
  sheet.scrollTop = 0;
}
function closeSheet() { $("#sheet").hidden = true; $("#sheet-backdrop").hidden = true; }
$("#sheet-backdrop").addEventListener("click", closeSheet);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheet(); });

// ---------- auth ----------
async function boot() {
  let s;
  try { s = await api("/api/session"); }
  catch (e) { setView(h("div", { class: "empty" }, e.message)); return; }
  if (!s.pin_set) return showSetup(s);
  if (!s.authenticated) return showLogin();
  signedIn = true; lastInput = Date.now();
  $("#tabs").hidden = false;
  syncAdvancedTab();
  route(location.hash.slice(1) || "home");
}

// Sign out after 30 minutes without touch, mouse or keyboard input, so an unattended screen can't be used.
// The page refreshes itself while open, so the server alone can't tell an idle tab from a busy one.
const IDLE_MS = 30 * 60 * 1000;
let lastInput = Date.now(), signedIn = false;
["pointerdown", "pointermove", "keydown", "wheel", "touchstart", "scroll"].forEach((ev) =>
  window.addEventListener(ev, () => { lastInput = Date.now(); }, { passive: true, capture: true }));
function checkIdle() {
  if (!signedIn || Date.now() - lastInput < IDLE_MS) return;
  signedIn = false;
  fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {}).finally(() => { showLogin(); toast("Signed out after 30 minutes without use"); });
}
setInterval(checkIdle, 30 * 1000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) checkIdle(); });

function showLogin() {
  signedIn = false;
  stopRefresh(); closeSheet();
  $("#tabs").hidden = true; $("#top-status").replaceChildren();
  const pin = h("input", { class: "pin-input", type: "password", inputmode: "numeric", autocomplete: "current-password", "aria-label": "PIN", maxlength: 32 });
  const err = h("div", { class: "error-text center" });
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Unlock");
  const form = h("form", { class: "login", onsubmit: async (e) => {
    e.preventDefault(); err.textContent = "";
    try { await api("/api/login", { body: { pin: pin.value } }); boot(); }
    catch (ex) { err.textContent = ex.message; pin.value = ""; pin.focus(); }
  } }, h("h1", {}, "Enter your PIN"), pin, btn, err);
  setView(form);
  setTimeout(() => pin.focus(), 50);
}

function showSetup(s) {
  $("#tabs").hidden = true;
  const pin = h("input", { type: "password", inputmode: "numeric", minlength: 6, required: true, autocomplete: "new-password" });
  const pin2 = h("input", { type: "password", inputmode: "numeric", minlength: 6, required: true, autocomplete: "new-password" });
  const rpw = h("input", { type: "password", autocomplete: "off" });
  const err = h("div", { class: "error-text" });
  setView(h("form", { class: "login form", onsubmit: async (e) => {
    e.preventDefault(); err.textContent = "";
    if (pin.value !== pin2.value) { err.textContent = "PINs don't match"; return; }
    try { await act(e.submitter, () => api("/api/setup", { body: { pin: pin.value, router_password: rpw.value || null } })); boot(); }
    catch (ex) { err.textContent = ex.message; }
  } },
    h("h1", {}, "Set up Orbi Control"),
    h("p", { class: "muted small" }, "Choose a PIN (6+ digits). It protects the controls from anyone else on your Wi-Fi, including kids."),
    h("label", { class: "field" }, "New PIN", pin),
    h("label", { class: "field" }, "Confirm PIN", pin2),
    s.router_configured ? null : h("label", { class: "field" }, "Orbi admin password (what you use at orbilogin.com)", rpw),
    h("button", { class: "btn primary block", type: "submit" }, "Save"), err));
}

// ---------- routing ----------
const VIEWS = { home: renderHome, devices: renderDevices, family: renderFamily, history: renderHistory, advanced: renderAdvanced, more: renderMore };
const ADV_KEY = "orbi-advanced-mode";
const advancedOn = () => { try { return localStorage.getItem(ADV_KEY) === "1"; } catch { return false; } };
function syncAdvancedTab() { $("#tab-advanced").hidden = !advancedOn(); }
function route(tab) {
  if (!VIEWS[tab] || (tab === "advanced" && !advancedOn())) tab = "home";
  currentTab = tab;
  if (location.hash.slice(1) !== tab) history.replaceState(null, "", `#${tab}`);
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  closeSheet(); stopRefresh();
  setView(h("div", { class: "empty" }, h("span", { class: "spinner" })));
  VIEWS[tab]().catch((e) => setView(h("div", { class: "empty" }, e.message)));
  window.scrollTo(0, 0);
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => route(b.dataset.tab)));
function stopRefresh() { clearInterval(refreshTimer); refreshTimer = null; }
function every(ms, fn) { stopRefresh(); refreshTimer = setInterval(() => { if (!document.hidden) fn().catch(() => {}); }, ms); }
document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("#tabs").hidden && $("#sheet").hidden) VIEWS[currentTab]().catch(() => {}); });

function topStatus(st) {
  const el = $("#top-status");
  const state = statusLevel(st);
  const color = { ok: "var(--ok)", warn: "var(--warn)", down: "var(--bad)", unknown: "var(--muted)" }[state.level];
  el.replaceChildren(h("span", { style: `width:8px;height:8px;border-radius:50%;background:${color};display:inline-block` }), state.short);
  const badge = $("#alert-badge");
  badge.hidden = !st.unseen_alerts; badge.textContent = st.unseen_alerts > 9 ? "9+" : st.unseen_alerts;
}

function statusLevel(st) {
  if (!st.router_configured) return { level: "unknown", short: "Setup needed", big: "Router not connected", sub: "Add your Orbi admin password under More → Router." };
  if (st.internet === null) return { level: "unknown", short: "Checking…", big: "Checking your connection…", sub: "" };
  if (st.router === false) return { level: "down", short: "Router unreachable", big: "Can't reach the router", sub: "This PC can't reach the Orbi. Check its power, or this PC's network cable." };
  if (st.internet === false) return { level: "down", short: "Internet down", big: "Internet is down", sub: `Since ${st.outage ? fmtWhen(st.outage.ts) : "just now"}. ${st.outage?.detail || ""}` };
  if (st.pc_offline) return { level: "warn", short: "Internet online", big: st.pc_offline.title, sub: `Since ${fmtWhen(st.pc_offline.ts)}. ${st.pc_offline.detail}` };
  const off = (st.satellites || []).filter((s) => s.online === false);
  if (off.length) return { level: "warn", short: "Satellite offline", big: "Online, but a satellite is down", sub: `${off.map((s) => s.name).join(", ")} isn't connected.` };
  if (st.scan_error) return { level: "warn", short: "Online", big: "Internet is online", sub: "The router isn't answering status requests right now; retrying." };
  return { level: "ok", short: "Online", big: "Internet is online", sub: `${st.latency_ms ? `${Math.round(st.latency_ms)} ms latency · ` : ""}checked ${st.last_check ? ago(st.last_check) : "—"}` };
}

// ---------- Home ----------
async function renderHome() {
  const [st, profiles] = await Promise.all([api("/api/status"), api("/api/profiles")]);
  cache.status = st; topStatus(st);
  const lvl = statusLevel(st);

  const hero = h("section", { class: "card" },
    h("div", { class: `hero ${lvl.level}` }, h("div", { class: "dot", "aria-hidden": "true" }),
      h("div", {}, h("div", { class: "big" }, lvl.big), h("div", { class: "sub" }, lvl.sub))),
    h("div", { class: "stats" },
      stat(pct(st.uptime["24h"]), "Uptime 24h"), stat(pct(st.uptime["7d"]), "Uptime 7 days"),
      stat(String(st.outages_7d), `Outage${st.outages_7d === 1 ? "" : "s"} 7 days`),
      st.devices_online ? stat(String(st.devices_online), "Devices online") : null));

  // Mesh
  const mesh = h("section", { class: "card" }, h("h2", {}, "Mesh", st.last_scan ? h("span", { class: "act small" }, `updated ${ago(st.last_scan)}`) : null));
  mesh.append(h("div", { class: "row" }, ico("router"),
    h("div", { class: "main" }, h("div", { class: "name" }, `Router${st.info?.model ? ` · ${st.info.model}` : ""}`),
      h("div", { class: "meta" }, [st.router_devices != null ? `${st.router_devices} devices` : null, st.info?.firmware].filter(Boolean).join(" · "))),
    h("span", { class: `pill ${st.router ? "ok" : "bad"}` }, st.router ? "Online" : "Unreachable")));
  for (const s of st.satellites || []) {
    const wired = s.backhaul_kind === "wired";
    const bh = wired ? "Wired backhaul" : s.backhaul ? `${s.backhaul.replace("GHz", " GHz")} wireless backhaul${s.usually_wired ? " (normally wired: check its cable)" : ""}` : "";
    mesh.append(h("div", { class: `row tap${s.online === false ? " offline" : ""}`, role: "button", tabindex: 0,
      onclick: () => satelliteSheet(s), onkeydown: (e) => e.key === "Enter" && satelliteSheet(s) }, ico("sat"),
      h("div", { class: "main" }, h("div", { class: "name" }, s.name),
        h("div", { class: "meta" }, [s.online === false ? "Not connected" : `${s.devices ?? 0} devices`, bh].filter(Boolean).join(" · "))),
      s.online === false ? h("span", { class: "pill bad" }, "Offline") : wired ? h("span", { class: "pill ok" }, "Wired")
        : s.usually_wired ? h("span", { class: "pill warn" }, "Wireless") : signalBars(s.signal, "")));
  }
  if (st.scan_error) mesh.append(h("div", { class: "note" }, `Router not answering: ${st.scan_error}`));

  // Family quick controls
  const fam = profiles.length ? h("section", { class: "card" }, h("h2", {}, "Family", h("button", { class: "btn small act", onclick: () => route("family") }, "Manage")),
    ...profiles.map((p) => familyQuickRow(p))) : null;

  // Speed
  const sp = st.speedtest;
  const speed = h("section", { class: "card" }, h("h2", {}, "Speed",
    h("button", { class: "btn small act", disabled: sp.running || !st.router_configured, onclick: (e) => act(e.currentTarget, () => api("/api/speedtest", { body: {} }), "Speed test started (about a minute)").then(() => setTimeout(renderHome, 500)) }, sp.running ? "Testing…" : "Run test")),
    sp.running ? h("div", { class: "muted" }, h("span", { class: "spinner" }), " Running on the router — about a minute…") :
      sp.last ? h("div", { class: "stats" }, stat(`${Math.round(sp.last.down)}`, "Mbps down"), stat(`${Math.round(sp.last.up)}`, "Mbps up"), stat(`${sp.last.ping?.toFixed(0) ?? "—"}`, "ms ping")) :
        h("div", { class: "muted small" }, "No tests yet."),
    sp.last && !sp.running ? h("div", { class: "muted small", style: "margin-top:8px" }, `Tested ${fmtWhen(sp.last.ts)}${sp.last.trigger === "scheduled" ? " (daily)" : ""}`) : null,
    sp.error ? h("div", { class: "error-text" }, `Last test failed: ${sp.error}`) : null);

  const tr = st.traffic;
  const usage = tr ? h("section", { class: "card" }, h("h2", {}, "Usage"), h("div", { class: "stats" },
    stat(fmtMB(tr.today_down), "Down today"), stat(fmtMB(tr.today_up), "Up today"), stat(fmtMB(tr.month_down), "Down this month"))) : null;

  const info = h("section", { class: "card" }, h("h2", {}, "Network"), h("dl", { class: "kv" },
    h("dt", {}, "Public IP"), h("dd", {}, st.wan?.ip || "—"),
    h("dt", {}, "DNS filter"), h("dd", {}, st.dns_filter || "None detected"),
    h("dt", {}, "Router load"), h("dd", {}, st.system?.memory != null ? `Memory ${st.system.memory}%` : "—")));

  setView(hero, mesh, fam, speed, usage, info);
  every(sp.running ? 4000 : 15000, renderHome);
}

function stat(v, l) { return h("div", { class: "stat" }, h("div", { class: "v" }, v), h("div", { class: "l" }, l)); }

function profileStatePill(p) {
  const s = p.state;
  if (s.blocked) return h("span", { class: "pill bad" }, s.reason + (s.until ? ` · until ${untilText(s.until)}` : ""));
  if (s.reason === "Extra time") return h("span", { class: "pill accent" }, `Extra time · until ${untilText(s.until)}`);
  return h("span", { class: "pill ok" }, "Online" + (s.until ? ` · until ${untilText(s.until)}` : ""));
}

function familyQuickRow(p) {
  const btn = p.paused
    ? h("button", { class: "btn small primary", onclick: (e) => act(e.currentTarget, () => api(`/api/profiles/${p.id}/resume`, { body: {} }), `${p.name} resumed`).then(renderHome) }, "Resume")
    : p.state.blocked ? h("button", { class: "btn small", onclick: (e) => act(e.currentTarget, () => api(`/api/profiles/${p.id}/bonus`, { body: { minutes: 30 } }), `${p.name} has 30 more minutes`).then(renderHome) }, "+30 min")
      : h("button", { class: "btn small danger", onclick: () => pauseSheet(p, renderHome) }, "Pause");
  return h("div", { class: "row" }, h("span", { class: "avatar", style: "width:34px;height:34px;font-size:17px" }, p.emoji || p.name[0]),
    h("div", { class: "main" }, h("div", { class: "name" }, p.name), h("div", { class: "meta" }, profileStatePill(p))), btn);
}

function pauseSheet(p, after) {
  const choose = (minutes, label) => h("button", { class: "btn block", onclick: (e) => act(e.currentTarget, () => api(`/api/profiles/${p.id}/pause`, { body: { minutes } }), `${p.name} paused ${label}`).then(() => { closeSheet(); after(); }) }, label);
  openSheet(h("h3", {}, `Pause ${p.name}`), h("p", { class: "muted small", style: "margin:0" }, `All of ${p.name}'s devices lose internet right away.`),
    choose(15, "for 15 minutes"), choose(30, "for 30 minutes"), choose(60, "for 1 hour"), choose(120, "for 2 hours"), choose(null, "until I resume"));
}

function satelliteSheet(s) {
  const pairs = [["Status", s.online === false ? "Not connected" : "Online"], ["Devices", s.devices ?? 0],
    ["Backhaul", s.backhaul_kind === "wired" ? "Wired (Ethernet)" : s.backhaul ? `${s.backhaul.replace("GHz", " GHz")} wireless` : "—"],
    s.backhaul_kind === "wired" ? null : ["Signal to router", s.signal == null ? "—" : `${s.signal}%`],
    ["IP", s.ip], ["Model", s.model], ["Firmware", s.firmware], ["MAC", s.mac]].filter(Boolean);
  openSheet(h("h3", {}, s.name), h("dl", { class: "kv" }, ...pairs.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")])),
    s.usually_wired && s.backhaul_kind !== "wired" ? h("div", { class: "note" }, "This satellite is normally wired. Check its Ethernet cable and the switch port, then reboot it.") : null,
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Close")));
}

// ---------- Devices ----------
let devFilter = "online", devQuery = "";
async function renderDevices() {
  const [devices, profiles] = await Promise.all([api("/api/devices"), api("/api/profiles")]);
  cache.devices = devices; cache.profiles = profiles;
  const list = h("div");
  const search = h("input", { class: "search", type: "search", placeholder: "Search name, IP or MAC", value: devQuery, "aria-label": "Search devices",
    oninput: (e) => { devQuery = e.target.value; draw(); } });
  const chips = h("div", { class: "chips" });
  const filters = { online: "Online", all: "All", blocked: "Blocked", unassigned: "No profile", new: "New this week", guest: "Guest Wi-Fi", iot: "IoT Wi-Fi" };
  for (const [k, label] of Object.entries(filters)) {
    chips.append(h("button", { class: `chip${devFilter === k ? " on" : ""}`, onclick: () => { devFilter = k; renderDevices(); } }, label));
  }
  function draw() {
    const q = devQuery.toLowerCase();
    const weekAgo = Date.now() / 1000 - 7 * 86400;
    const shown = devices.filter((d) => {
      if (devFilter === "online" && !d.online) return false;
      if (devFilter === "blocked" && !d.blocked) return false;
      if (devFilter === "unassigned" && d.profile) return false;
      if (devFilter === "new" && d.first_seen < weekAgo) return false;
      if ((devFilter === "guest" || devFilter === "iot") && d.network !== devFilter) return false;
      return !q || [d.name, d.ip, d.mac, d.model, d.router_name].some((v) => (v || "").toLowerCase().includes(q));
    });
    const groups = {};
    for (const d of shown) (groups[d.online ? d.ap || "Other" : "Offline"] ||= []).push(d);
    const order = Object.keys(groups).sort((a, b) => (a === "Offline") - (b === "Offline") || (a === "Router" ? -1 : b === "Router" ? 1 : a.localeCompare(b)));
    list.replaceChildren(...(shown.length ? order.flatMap((g) => [h("div", { class: "group-label" }, `${g} · ${groups[g].length}`), ...groups[g].map(deviceRow)]) : [h("div", { class: "empty" }, "No devices match.")]));
  }
  draw();
  setView(search, chips, h("section", { class: "card" }, list));
  every(30000, async () => { if ($("#sheet").hidden && document.activeElement !== search) await renderDevices(); });
}

function networkLabel(d) {
  if (d.network === "iot") return `${d.ssid || "IoT"} (IoT)`;
  if (d.network === "guest") return `${d.ssid || "Guest"} (guest)`;
  return d.network === "main" ? d.ssid : "";
}

function deviceRow(d) {
  const band = d.connection === "wired" ? "Wired" : d.connection.replace(/\s*-\s*IoT$/i, "").replace("GHz", " GHz");
  return h("div", { class: `row tap${d.online ? "" : " offline"}`, role: "button", tabindex: 0, onclick: () => deviceSheet(d), onkeydown: (e) => e.key === "Enter" && deviceSheet(d) },
    ico(d.connection === "wired" ? "wired" : "wifi"),
    h("div", { class: "main" }, h("div", { class: "name" }, d.name),
      h("div", { class: "meta" }, d.online ? [d.ip, band, networkLabel(d), d.randomized ? "private address" : null].filter(Boolean).join(" · ") : `Last seen ${d.last_seen ? ago(d.last_seen) : "—"}`)),
    d.held ? h("span", { class: "pill warn" }, "Needs approval") : d.blocked ? h("span", { class: "pill bad" }, "Blocked")
      : d.profile ? h("span", { class: "pill accent" }, `${d.profile.emoji || ""} ${d.profile.name}`.trim())
        : d.default_profile ? h("span", { class: "pill", title: "Not in a profile, so it follows the default" }, `↳ ${d.default_profile.name}`) : null,
    d.online && !d.blocked ? signalBars(d.signal, d.connection) : null);
}

function deviceSheet(d) {
  const alias = h("input", { type: "text", value: d.alias || "", placeholder: d.router_name || d.model || "Name", maxlength: 60 });
  const profileSel = h("select", {}, h("option", { value: "" }, "No profile"),
    ...(cache.profiles || []).map((p) => h("option", { value: p.id, selected: d.profile?.id === p.id }, `${p.emoji || ""} ${p.name}`.trim())));
  const save = h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, () => api(`/api/devices/${d.mac}`, { method: "PATCH",
    body: profileSel.value ? { alias: alias.value, profile_id: Number(profileSel.value) } : { alias: alias.value, clear_profile: true } }), "Saved").then(() => { closeSheet(); renderDevices(); }) }, "Save");
  const blockBtn = d.protected ? h("div", { class: "muted small" }, "This is the PC running Orbi Control, so it can't be blocked.")
    : h("button", { class: `btn ${d.blocked ? "primary" : "danger"}`, onclick: (e) => act(e.currentTarget, () => api(`/api/devices/${d.mac}/block`, { body: { blocked: !d.blocked } }), d.blocked ? "Unblocked" : "Blocked").then(() => { closeSheet(); renderDevices(); }) },
      d.blocked ? "Unblock" : "Block internet");
  const approve = d.held ? h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
    if (profileSel.value) await api(`/api/devices/${d.mac}`, { method: "PATCH", body: { alias: alias.value, profile_id: Number(profileSel.value) } });
    return api(`/api/devices/${d.mac}/block`, { body: { blocked: false } });
  }, "Approved").then(() => { closeSheet(); renderDevices(); }) }, "Approve") : null;
  openSheet(h("h3", {}, d.name),
    d.held ? h("div", { class: "note" }, d.profile
      ? `Blocked until you approve it. Its name matches a device in ${d.profile.name}, so it's probably theirs with a new address. Names are easy to fake, so check it really is before approving.`
      : "New device, blocked until you approve it. Pick a profile below (or leave it on the default), then Approve.")
      : d.blocked && d.block_reason ? h("div", { class: "note" }, d.block_reason) : null,
    !d.profile && d.default_profile ? h("div", { class: "muted small" }, `Not in a profile, so it follows ${d.default_profile.name}'s rules (the default).`) : null,
    d.randomized ? h("div", { class: "muted small" }, "Uses a private (randomized) Wi-Fi address. If it changes, the device shows up as new.") : null,
    h("dl", { class: "kv" },
      h("dt", {}, "Status"), h("dd", {}, d.online ? "Online" : `Offline · last seen ${d.last_seen ? fmtWhen(d.last_seen) : "—"}`),
      h("dt", {}, "IP"), h("dd", {}, d.ip || "—"), h("dt", {}, "MAC"), h("dd", {}, d.mac),
      h("dt", {}, "Connected to"), h("dd", {}, [d.ap, d.connection === "wired" ? "wired" : d.connection.replace(/\s*-\s*IoT$/i, "")].filter(Boolean).join(" · ") || "—"),
      d.network && d.network !== "wired" ? [h("dt", {}, "Wi-Fi network"), h("dd", {}, { main: `${d.ssid} (main)`, guest: `${d.ssid} (guest)`, iot: `${d.ssid} (IoT)` }[d.network] || d.ssid || "—")] : null,
      d.signal != null && d.connection !== "wired" ? [h("dt", {}, "Signal"), h("dd", {}, `${d.signal}%${d.link_rate ? ` · ${d.link_rate} Mbps link` : ""}`)] : null,
      d.model ? [h("dt", {}, "Model"), h("dd", {}, d.model)] : null,
      h("dt", {}, "First seen"), h("dd", {}, d.first_seen ? fmtWhen(d.first_seen) : "—")),
    h("label", { class: "field" }, "Name", alias),
    h("label", { class: "field" }, "Family profile", profileSel),
    h("div", { class: "btns" }, approve, save, d.held ? null : blockBtn),
    d.online && d.ip && !d.held ? h("button", { class: "btn small", style: "margin-top:8px", onclick: (e) => act(e.currentTarget, async () => {
      await api("/api/reservations", { body: { ip: d.ip, mac: d.mac, name: d.name } });
      await waitJob("reservation", "Saving to the router");
      return { note: `${d.name} will always get ${d.ip}` };
    }) }, `Reserve this address (${d.ip})`) : null);
}

// ---------- Family ----------
const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
function daysText(days) {
  if (days === "0123456") return "Every day";
  if (days === "01234") return "Weekdays";
  if (days === "56") return "Weekends";
  if (days === "0123" + "6") return "School nights";
  return days.split("").map((d) => DAY_NAMES[d]).join(", ");
}
const fmtHM = (hm) => { const [hh, mm] = hm.split(":").map(Number); return new Date(2000, 0, 1, hh, mm).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }); };

async function renderFamily() {
  const [profiles, status] = await Promise.all([api("/api/profiles"), api("/api/status")]);
  cache.profiles = profiles; topStatus(status);
  const cards = profiles.map((p) => {
    const actions = h("div", { class: "btns" },
      p.paused ? h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, () => api(`/api/profiles/${p.id}/resume`, { body: {} }), `${p.name} resumed`).then(renderFamily) }, "Resume")
        : h("button", { class: "btn danger", onclick: () => pauseSheet(p, renderFamily) }, "Pause internet"),
      p.state.reason === "Extra time" ? h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api(`/api/profiles/${p.id}/bonus/cancel`, { body: {} }), "Extra time ended").then(renderFamily) }, "End extra time")
        : p.state.blocked && !p.paused ? h("button", { class: "btn", onclick: () => bonusSheet(p) }, "Give extra time") : null,
      h("button", { class: "btn", onclick: () => profileSheet(p) }, "Edit"),
      h("button", { class: "btn", onclick: () => reportSheet(p) }, "Report"));
    const devs = p.devices.length ? h("div", { class: "sub-list" }, ...p.devices.map((d) => h("div", { class: `row${d.online ? "" : " offline"}` }, ico("wifi"),
      h("div", { class: "main" }, h("div", { class: "name" }, d.name), h("div", { class: "meta" }, d.online ? "Online" : "Offline")),
      h("button", { class: "btn small", title: "Remove from profile", onclick: (e) => act(e.currentTarget, () => api(`/api/devices/${d.mac}`, { method: "PATCH", body: { clear_profile: true } })).then(renderFamily) }, "Remove"))))
      : h("div", { class: "muted small", style: "margin-top:8px" }, "No devices yet.");
    const rules = h("div", { class: "sub-list" }, h("div", { class: "group-label" }, "Schedules"),
      ...(p.rules.length ? p.rules.map((r) => h("div", { class: `row tap${r.enabled ? "" : " offline"}`, role: "button", tabindex: 0, onclick: () => ruleSheet(p, r) },
        h("div", { class: "main" }, h("div", { class: "name" }, r.label), h("div", { class: "meta" }, `${daysText(r.days)} · ${fmtHM(r.start)} – ${fmtHM(r.end)}`)),
        h("span", { class: `pill${r.enabled ? "" : ""}` }, r.enabled ? "On" : "Off")))
        : [h("div", { class: "muted small" }, "No schedules. Internet is always on unless paused.")]),
      h("button", { class: "btn small", style: "margin-top:8px", onclick: () => ruleSheet(p, null) }, "+ Add schedule"));
    return h("section", { class: "card" },
      h("div", { class: "profile-head" }, h("span", { class: "avatar" }, p.emoji || p.name[0]), h("div", { class: "main" }, h("div", { class: "name" }, p.name), profileStatePill(p))),
      h("div", { style: "margin-top:12px" }, actions), devs,
      h("button", { class: "btn small", style: "margin-top:8px", onclick: () => addDevicesSheet(p) }, "+ Add devices"), rules);
  });
  const intro = !profiles.length ? h("section", { class: "card" }, h("h2", {}, "Parental controls"),
    h("p", { style: "margin:0 0 10px" }, "Group each person's devices into a profile, then pause their internet instantly or set schedules like bedtime. Blocking happens on the Orbi itself, so it works for every app and can't be bypassed by switching browsers."),
    h("p", { class: "muted small", style: "margin:0" }, "Tip: on kids' phones, turn off \"Private Wi-Fi address\" / \"Use randomized MAC\" for your network so their device keeps the same identity.")) : null;
  const dns = filteringCard();
  const blocking = siteBlockCard();
  const ac = status.enforce_error ? h("div", { class: "note" }, `Some blocks couldn't be applied: ${status.enforce_error}`) : null;
  setView(ac, intro, profiles.some((p) => p.rules.some((r) => r.enabled)) ? lateCard(profiles) : null, ...cards, profiles.length ? defaultCard(profiles) : null,
    h("button", { class: "btn primary block", onclick: () => profileSheet(null) }, "+ New profile"),
    h("div", { class: "group-label", style: "margin-top:8px" }, "Whole house"), dns, blocking, vpnAttemptsCard());
  every(30000, async () => { if ($("#sheet").hidden) await renderFamily(); });
}

function profileSheet(p) {
  const name = h("input", { type: "text", value: p?.name || "", maxlength: 40, required: true, placeholder: "e.g. Ethan" });
  const emojis = ["🧒", "👦", "👧", "🧑", "👩", "👨", "🎮", "📱", "📺", "🏠"];
  let emoji = p?.emoji || "🧒";
  const picks = h("div", { class: "chips" }, ...emojis.map((e) => h("button", { class: `chip${e === emoji ? " on" : ""}`, type: "button", onclick: (ev) => { emoji = e; picks.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === ev.currentTarget)); } }, e)));
  const save = h("button", { class: "btn primary", onclick: async (e) => {
    if (!name.value.trim()) { name.focus(); return; }
    const r = await act(e.currentTarget, () => p ? api(`/api/profiles/${p.id}`, { method: "PATCH", body: { name: name.value, emoji } }) : api("/api/profiles", { body: { name: name.value, emoji } }), "Saved");
    closeSheet();
    if (!p && r?.id) { await renderFamily(); const np = cache.profiles.find((x) => x.id === r.id); if (np) addDevicesSheet(np); } else renderFamily();
  } }, p ? "Save" : "Create");
  const del = p ? h("button", { class: "btn danger", onclick: (e) => { if (confirm(`Delete ${p.name}? Their devices will be unblocked.`)) act(e.currentTarget, () => api(`/api/profiles/${p.id}`, { method: "DELETE" }), "Deleted").then(() => { closeSheet(); renderFamily(); }); } }, "Delete profile") : null;
  openSheet(h("h3", {}, p ? `Edit ${p.name}` : "New profile"), h("label", { class: "field" }, "Name", name), picks, h("div", { class: "btns" }, save, del));
  name.focus();
}

async function addDevicesSheet(p) {
  const devices = await api("/api/devices");
  const chosen = new Set();
  const list = h("div");
  const q = h("input", { class: "search", type: "search", placeholder: "Search devices" });
  const draw = () => {
    const s = q.value.toLowerCase();
    const avail = devices.filter((d) => d.profile?.id !== p.id && !d.protected && (!s || [d.name, d.ip, d.mac, d.model].some((v) => (v || "").toLowerCase().includes(s))));
    list.replaceChildren(...(avail.length ? avail.map((d) => {
      const cb = h("input", { type: "checkbox", checked: chosen.has(d.mac), onchange: (e) => e.target.checked ? chosen.add(d.mac) : chosen.delete(d.mac) });
      return h("label", { class: `row tap${d.online ? "" : " offline"}` }, cb, h("div", { class: "main" }, h("div", { class: "name" }, d.name),
        h("div", { class: "meta" }, [d.online ? d.ip : "offline", d.model, d.profile ? `in ${d.profile.name}` : null].filter(Boolean).join(" · "))));
    }) : [h("div", { class: "empty" }, "No devices found.")]));
  };
  q.addEventListener("input", draw); draw();
  openSheet(h("h3", {}, `Add devices to ${p.name}`), q, list, h("button", { class: "btn primary block", onclick: async (e) => {
    if (!chosen.size) { closeSheet(); return; }
    await act(e.currentTarget, async () => { for (const mac of chosen) await api(`/api/devices/${mac}`, { method: "PATCH", body: { profile_id: p.id } }); }, `Added ${chosen.size} device${chosen.size > 1 ? "s" : ""}`);
    closeSheet(); renderFamily();
  } }, "Add selected"));
}

function bonusSheet(p) {
  const give = (m, label) => h("button", { class: "btn block", onclick: (e) => act(e.currentTarget, () => api(`/api/profiles/${p.id}/bonus`, { body: { minutes: m } }), `${p.name} gets ${label}`).then(() => { closeSheet(); renderFamily(); }) }, label);
  openSheet(h("h3", {}, `Extra time for ${p.name}`), h("p", { class: "muted small", style: "margin:0" }, "Lifts the current schedule temporarily."),
    give(15, "15 minutes"), give(30, "30 minutes"), give(60, "1 hour"), give(120, "2 hours"));
}

function ruleSheet(p, r) {
  const presets = [["Bedtime", "0123" + "6", "21:00", "07:00"], ["School hours", "01234", "08:00", "15:00"], ["Homework", "01234", "16:00", "18:00"], ["Dinner", "0123456", "18:00", "19:00"]];
  const label = h("input", { type: "text", value: r?.label || "Bedtime", maxlength: 30 });
  const start = h("input", { type: "time", value: r?.start || "21:00", required: true });
  const end = h("input", { type: "time", value: r?.end || "07:00", required: true });
  const days = h("div", { class: "days" }, ...DAY_NAMES.map((n, i) => h("label", {}, h("input", { type: "checkbox", value: i, checked: (r?.days ?? "01236").includes(String(i)) }), h("span", {}, n.slice(0, 2)))));
  const enabled = h("input", { type: "checkbox", checked: r ? !!r.enabled : true });
  const setDays = (s) => days.querySelectorAll("input").forEach((c) => (c.checked = s.includes(c.value)));
  const presetChips = r ? null : h("div", { class: "chips" }, ...presets.map(([l, d, s, e]) => h("button", { class: "chip", type: "button", onclick: () => { label.value = l; setDays(d); start.value = s; end.value = e; } }, l)));
  const body = () => ({ label: label.value, start: start.value, end: end.value, enabled: enabled.checked,
    days: [...days.querySelectorAll("input:checked")].map((c) => c.value).join("") });
  const save = h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, () => r ? api(`/api/rules/${r.id}`, { method: "PUT", body: body() }) : api(`/api/profiles/${p.id}/rules`, { body: body() }), "Schedule saved").then(() => { closeSheet(); renderFamily(); }) }, "Save");
  const del = r ? h("button", { class: "btn danger", onclick: (e) => act(e.currentTarget, () => api(`/api/rules/${r.id}`, { method: "DELETE" }), "Schedule deleted").then(() => { closeSheet(); renderFamily(); }) }, "Delete") : null;
  openSheet(h("h3", {}, r ? "Edit schedule" : `New schedule for ${p.name}`), presetChips,
    h("label", { class: "field" }, "Name", label),
    h("div", { class: "inline" }, h("label", { class: "field" }, "Internet off from", start), h("label", { class: "field" }, "until", end)),
    h("div", { class: "field" }, "Days (the day it starts)", days),
    h("label", { class: "switch" }, "Schedule is on", enabled),
    h("p", { class: "muted small", style: "margin:0" }, "Overnight schedules (e.g. 9 PM – 7 AM) end the next morning."),
    h("div", { class: "btns" }, save, del));
}

// ---------- History ----------
let histHours = 24;
async function renderHistory() {
  const [hist, events, speeds, traffic] = await Promise.all([api(`/api/history?hours=${histHours}`), api("/api/events?limit=200"), api("/api/speedtests?days=30"), api("/api/traffic?days=30")]);
  const chips = h("div", { class: "chips" }, ...[[24, "24 hours"], [168, "7 days"], [720, "30 days"]].map(([hrs, l]) =>
    h("button", { class: `chip${histHours === hrs ? " on" : ""}`, onclick: () => { histHours = hrs; renderHistory(); } }, l)));
  const outages = events.filter((e) => e.kind === "outage");
  const since = Date.now() / 1000 - histHours * 3600;
  const inRange = outages.filter((e) => (e.end_ts || Date.now() / 1000) > since);
  const totalDown = inRange.reduce((s, e) => s + ((e.end_ts || Date.now() / 1000) - Math.max(e.ts, since)), 0);

  const uptimeCard = h("section", { class: "card" }, h("h2", {}, "Internet connection"),
    hist.points.length ? uptimeChart(hist) : h("div", { class: "empty" }, "Collecting data… check back in a few minutes."),
    h("div", { class: "legend" }, h("span", {}, h("i", { style: "background:var(--ok)" }), "online"), h("span", {}, h("i", { style: "background:var(--bad)" }), "offline"), h("span", {}, h("i", { style: "background:var(--accent)" }), "latency")),
    h("div", { class: "muted small", style: "margin-top:6px" }, `${inRange.length} outage${inRange.length === 1 ? "" : "s"}, ${dur(totalDown)} offline in this period.`));

  const outageCard = h("section", { class: "card" }, h("h2", {}, "Outages"),
    ...(outages.length ? outages.slice(0, 30).map((e) => h("div", { class: "row" },
      h("div", { class: "main" }, h("div", { class: "name" }, `${fmtWhen(e.ts)} · ${e.end_ts ? dur(e.end_ts - e.ts) : "ongoing"}`), h("div", { class: "meta", style: "white-space:normal" }, e.detail || "")),
      h("span", { class: `pill ${e.end_ts ? "" : "bad"}` }, e.end_ts ? "Resolved" : "Now")))
      : [h("div", { class: "empty" }, "No outages recorded. 🎉")]));

  const speedCard = h("section", { class: "card" }, h("h2", {}, "Speed tests (30 days)"),
    speeds.length > 1 ? lineChart(speeds.map((s) => s.ts), [{ values: speeds.map((s) => s.down), color: "var(--accent)" }, { values: speeds.map((s) => s.up), color: "var(--ok)" }], "Mbps") : null,
    speeds.length > 1 ? h("div", { class: "legend" }, h("span", {}, h("i", { style: "background:var(--accent)" }), "download"), h("span", {}, h("i", { style: "background:var(--ok)" }), "upload")) : null,
    ...(speeds.length ? speeds.slice(-6).reverse().map((s) => h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name" }, `${Math.round(s.down)} ↓ / ${Math.round(s.up)} ↑ Mbps`), h("div", { class: "meta" }, `${fmtWhen(s.ts)} · ${s.ping?.toFixed(0)} ms ping${s.trigger === "scheduled" ? " · daily" : ""}`))))
      : [h("div", { class: "empty" }, "No speed tests yet.")]));

  const trafficCard = traffic.length ? h("section", { class: "card" }, h("h2", {}, "Daily usage"), barChart(traffic)) : null;

  const log = h("section", { class: "card" }, h("h2", {}, "Activity"),
    ...events.filter((e) => e.kind !== "outage").slice(0, 60).map((e) => h("div", { class: "row" },
      h("div", { class: "main" }, h("div", { class: "name", style: "white-space:normal" }, e.title), h("div", { class: "meta" }, [fmtWhen(e.ts), e.detail].filter(Boolean).join(" · "))),
      e.severity !== "info" ? h("span", { class: `pill ${e.severity === "error" ? "bad" : "warn"}` }, e.severity === "error" ? "Alert" : "Notice") : null)));
  setView(chips, uptimeCard, outageCard, speedCard, trafficCard, log, routerLogCard());
}

function routerLogCard() {
  const logList = h("div");
  const kinds = [["all", "All"], ["dhcp", "DHCP"], ["blocked", "Blocked"], ["logins", "Admin logins"], ["upnp", "UPnP"]];
  const logChips = h("div", { class: "chips" }, ...kinds.map(([k, l]) => h("button", { class: `chip${logKind === k ? " on" : ""}`, onclick: (e) => {
    logKind = k; logLimit = 25; logChips.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === e.currentTarget)); loadLog();
  } }, l)));
  const logSearch = h("input", { class: "search", type: "search", placeholder: "Search the log (IP, MAC, name…)", value: logQuery,
    oninput: (e) => { logQuery = e.target.value; logLimit = 25; clearTimeout(logSearch.t); logSearch.t = setTimeout(loadLog, 300); } });
  let logLimit = 25;
  async function loadLog() {
    const res = await api(`/api/routerlog?kind=${logKind}&q=${encodeURIComponent(logQuery)}&limit=${logLimit + 1}`);
    const rows = res.rows.slice(0, logLimit);
    const more = res.rows.length > logLimit
      ? h("button", { class: "btn small block", style: "margin-top:8px", onclick: () => { logLimit += 50; loadLog(); } }, "Show more") : null;
    fill(logList, ...(rows.length ? rows.map((x) => h("div", { class: "row" }, h("div", { class: "main" },
      h("div", { class: "name", style: "white-space:normal;font-weight:500;font-size:13.5px" }, x.text.replace(/,?\s*\w+day, \w{3} \d{1,2},\d{4} \d\d:\d\d:\d\d$/, "")),
      h("div", { class: "meta" }, [fmtWhen(x.ts), x.device].filter(Boolean).join(" · ")))))
      : [h("div", { class: "empty" }, res.total ? "No matching entries." : "The router log is read every 10 minutes; check back shortly.")]), more);
  }
  const logCard = h("section", { class: "card" }, h("h2", {}, "Router log"), logSearch, logChips, logList);
  loadLog().catch(() => {});
  return logCard;
}

function uptimeChart(hist) {
  const W = 600, H = 120, pts = hist.points;
  const n = Math.max(1, Math.round((histHours * 3600) / hist.bucket));
  const bw = W / n;
  const maxLat = Math.max(20, ...pts.map((p) => p.lat || 0));
  let svg = `<svg class="chart" viewBox="0 0 ${W} ${H + 18}" role="img" aria-label="Connection history">`;
  let path = "";
  for (const p of pts) {
    const i = Math.floor((p.b - hist.start) / hist.bucket);
    if (i < 0 || i >= n) continue;
    const x = i * bw;
    svg += `<rect x="${x.toFixed(1)}" y="${H - 14}" width="${Math.max(1, bw - 0.5).toFixed(1)}" height="14" fill="${p.up >= 0.999 ? "var(--ok)" : p.up > 0 ? "var(--warn)" : "var(--bad)"}"/>`;
    if (p.lat != null) path += `${path ? "L" : "M"}${(x + bw / 2).toFixed(1)},${(H - 20 - (p.lat / maxLat) * (H - 30)).toFixed(1)}`;
  }
  if (path) svg += `<path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.6"/>`;
  svg += `<text x="0" y="${H + 14}">${histHours <= 24 ? fmtTime(hist.start) : fmtDay(hist.start)}</text><text x="${W}" y="${H + 14}" text-anchor="end">now</text><text x="0" y="10">${Math.round(maxLat)} ms</text></svg>`;
  return h("div", { html: svg });
}

function lineChart(xs, series, unit) {
  const W = 600, H = 130, x0 = xs[0], x1 = xs[xs.length - 1] || x0 + 1;
  const max = Math.max(1, ...series.flatMap((s) => s.values.filter((v) => v != null)));
  const X = (t) => ((t - x0) / Math.max(1, x1 - x0)) * (W - 10) + 5, Y = (v) => H - 6 - (v / max) * (H - 20);
  let svg = `<svg class="chart" viewBox="0 0 ${W} ${H + 16}" role="img" aria-label="Speed history">`;
  for (const s of series) svg += `<path d="${s.values.map((v, i) => `${i ? "L" : "M"}${X(xs[i]).toFixed(1)},${Y(v || 0).toFixed(1)}`).join("")}" fill="none" stroke="${s.color}" stroke-width="2"/>`;
  svg += `<text x="0" y="10">${Math.round(max)} ${unit}</text><text x="0" y="${H + 14}">${fmtDay(x0)}</text><text x="${W}" y="${H + 14}" text-anchor="end">${fmtDay(x1)}</text></svg>`;
  return h("div", { html: svg });
}

function barChart(days) {
  const W = 600, H = 120, max = Math.max(1, ...days.map((d) => d.down || 0)), bw = W / Math.max(days.length, 7);
  let svg = `<svg class="chart" viewBox="0 0 ${W} ${H + 16}" role="img" aria-label="Daily usage">`;
  days.forEach((d, i) => {
    const hgt = ((d.down || 0) / max) * (H - 16);
    svg += `<rect x="${(i * bw + 2).toFixed(1)}" y="${(H - hgt).toFixed(1)}" width="${(bw - 4).toFixed(1)}" height="${hgt.toFixed(1)}" rx="2" fill="var(--accent)"><title>${d.day}: ${fmtMB(d.down)} down</title></rect>`;
  });
  svg += `<text x="0" y="10">${fmtMB(max)}</text><text x="0" y="${H + 14}">${days[0].day.slice(5)}</text><text x="${W}" y="${H + 14}" text-anchor="end">${days[days.length - 1].day.slice(5)}</text></svg>`;
  return h("div", { html: svg });
}

// ---------- More ----------
async function renderMore() {
  const [settings, access, events, st] = await Promise.all([api("/api/settings"), api("/api/access"), api("/api/events?limit=50"), api("/api/status")]);
  api("/api/events/seen", { body: {} }).then(() => ($("#alert-badge").hidden = true)).catch(() => {});
  const alerts = events.filter((e) => e.severity !== "info").slice(0, 8);
  const alertCard = h("section", { class: "card" }, h("h2", {}, "Recent alerts"),
    ...(alerts.length ? alerts.map((e) => h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name", style: "white-space:normal" }, e.title), h("div", { class: "meta" }, [fmtWhen(e.ts), e.detail].filter(Boolean).join(" · ")))))
      : [h("div", { class: "muted small" }, "No alerts.")]));

  const phone = h("section", { class: "card" }, h("h2", {}, "Use it on your phone"),
    h("div", { style: "display:flex;gap:16px;align-items:center;flex-wrap:wrap" },
      access.qr_svg ? h("div", { class: "qr", html: access.qr_svg }) : null,
      h("div", { style: "flex:1;min-width:200px" }, h("div", { style: "font-weight:600;word-break:break-all" }, access.urls[0] || "—"),
        h("p", { class: "muted small" }, "On your home Wi-Fi, scan the code or open this address. Then: iPhone → Share → Add to Home Screen; Android → ⋮ → Add to Home screen."))));

  const speedAt = h("input", { type: "time", value: settings.speedtest_daily_at || "" });
  const health = h("select", {}, ...[[15, "15 s"], [30, "30 s"], [60, "1 min"], [120, "2 min"]].map(([v, l]) => h("option", { value: v, selected: settings.health_interval === v }, l)));
  const scan = h("select", {}, ...[[60, "1 min"], [120, "2 min"], [300, "5 min"], [600, "10 min"]].map(([v, l]) => h("option", { value: v, selected: settings.scan_interval === v }, l)));
  const newDev = h("input", { type: "checkbox", checked: settings.alert_new_devices });
  const monitoring = h("section", { class: "card form" }, h("h2", {}, "Monitoring"),
    h("label", { class: "field" }, "Check internet every", health),
    h("label", { class: "field" }, "Scan devices & satellites every", scan),
    h("label", { class: "field" }, "Daily speed test at (clear to turn off)", speedAt),
    h("label", { class: "switch" }, "Alert me about new devices", newDev),
    h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, () => api("/api/settings", { method: "PATCH", body: {
      health_interval: Number(health.value), scan_interval: Number(scan.value), speedtest_daily_at: speedAt.value, alert_new_devices: newDev.checked } }), "Settings saved") }, "Save"));

  const rpw = h("input", { type: "password", autocomplete: "off", placeholder: settings.router_configured ? "••••••••" : "Orbi admin password" });
  const certInfo = h("div", {});
  const backupInfo = h("div", {});
  const restartInfo = h("div", {});
  const routerFacts = [["Model", st.info?.model], ["Firmware", st.info?.firmware], ["Uptime", st.router_uptime],
    ["Memory used", st.system?.memory != null ? `${st.system.memory}%` : null],
    ["Access Control", st.access_control == null ? null : st.access_control ? "On (needed for device blocking)" : "Off"]].filter(([, v]) => v != null && v !== "");
  const routerCard = h("section", { class: "card form" }, h("h2", {}, "Router"),
    routerFacts.length ? h("dl", { class: "kv" }, ...routerFacts.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])) : null,
    h("label", { class: "field" }, `Admin password for ${settings.router_host}`, rpw),
    h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/settings/router-password", { body: { password: rpw.value } }), "Router password saved").then(() => (rpw.value = "")) }, "Update password"),
    h("button", { class: "btn", onclick: (e) => act(e.currentTarget, async () => { const f = await api("/api/firmware"); toast(f.available ? `Firmware ${f.available} is available` : `Firmware ${f.current} is up to date`); }) }, "Check for firmware update"),
    h("button", { class: "btn danger", onclick: rebootSheet }, "Reboot router…"), restartInfo, certInfo, backupInfo);
  api("/api/router/reboot").then((r) => r.scheduled_at && fill(restartInfo, h("div", { class: "note" }, `Router restart scheduled for ${fmtAt(r.scheduled_at)}. `,
    h("button", { class: "btn small", onclick: (e) => act(e.currentTarget, () => api("/api/router/reboot", { method: "DELETE" }), "Scheduled restart cancelled").then(() => restartInfo.replaceChildren()) }, "Cancel")))).catch(() => {});
  api("/api/router-backup").then((b) => fill(backupInfo, h("div", { class: "group-label" }, "Settings backup"),
    h("div", { class: "muted small" }, b.last ? `Last backup ${fmtWhen(b.last.ts)} · ${b.files.length} kept on this PC (${b.folder}). Backed up weekly; restore from the router's Backup Settings page.` : "Not backed up yet. The app backs the router's settings up to this PC every week."),
    h("button", { class: "btn small", style: "margin-top:6px", onclick: (e) => act(e.currentTarget, async () => {
      await api("/api/router-backup", { body: {} }); await waitJob("backup", "Backing up"); renderMore().catch(() => {}); return { note: "Router settings backed up" }; }) }, "Back up now"))).catch(() => {});
  api("/api/settings/router-cert").then((c) => fill(certInfo,
    c.changed ? h("div", { class: "error-text" }, "The router is showing a different security certificate than the one Orbi Control trusts, so the app has stopped sending it the admin password.") : null,
    h("div", { class: "muted small" }, c.pinned ? `Security certificate: pinned (${c.pinned})` : "Security certificate: trusted on first connection"),
    c.changed ? h("div", { class: "muted small" }, "A firmware update or factory reset can change it. If you didn't do either, a device on your network may be pretending to be the router.") : null,
    c.changed ? h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/settings/router-cert/trust", { body: {} }), "Now trusting the router's new certificate").then(renderMore) }, "Trust the router's new certificate") : null)).catch(() => {});

  const cur = h("input", { type: "password", inputmode: "numeric", autocomplete: "current-password" });
  const nw = h("input", { type: "password", inputmode: "numeric", autocomplete: "new-password" });
  const extraPins = h("div", {});
  const pinCard = h("section", { class: "card form" }, h("h2", {}, "App PIN"),
    h("div", { class: "inline" }, h("label", { class: "field" }, "Current", cur), h("label", { class: "field" }, "New (6+)", nw)),
    h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/settings/pin", { body: { current: cur.value, new: nw.value } }), "PIN changed; other PINs removed and other devices signed out").then(() => { cur.value = nw.value = ""; renderExtraPins(); }) }, "Change PIN"),
    h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/logout", { body: {} })).then(showLogin) }, "Sign out of this device"),
    h("div", { class: "muted small", style: "margin-top:10px" }, "Other PINs that also unlock the app (removed when you change the PIN):"),
    extraPins);
  function renderExtraPins() {
    api("/api/settings/pins").then((r) => fill(extraPins, r.extra.length ? r.extra.map((p) => h("div", { class: "row" },
      h("div", { class: "main" }, h("div", { class: "name" }, p.label)),
      h("button", { class: "btn small danger", onclick: (e) => act(e.currentTarget, () => api(`/api/settings/pins/${encodeURIComponent(p.label)}`, { method: "DELETE" }), "PIN removed").then(renderExtraPins) }, "Remove")))
      : h("div", { class: "muted small" }, "None"))).catch((e) => fill(extraPins, h("div", { class: "error-text" }, e.message)));
  }
  renderExtraPins();

  const advToggle = h("input", { type: "checkbox", checked: advancedOn(), onchange: (e) => {
    try { localStorage.setItem(ADV_KEY, e.target.checked ? "1" : "0"); } catch {}
    syncAdvancedTab(); toast(e.target.checked ? "Advanced tab added" : "Advanced tab hidden");
  } });
  const advCard = h("section", { class: "card" }, h("h2", {}, "Advanced mode"),
    h("label", { class: "switch" }, "Show the Advanced tab (Wi-Fi networks, DHCP, logs, VPN, firewall rules…)", advToggle));
  setView(alertCard, phone, remoteCard(), advCard, monitoring, routerCard, pinCard, updatesCard(settings),
    h("div", { class: "muted small center" }, "Orbi Control runs on your PC and talks to the Orbi directly — no cloud. Outside connections: the optional update check to GitHub, and internet checks to 1.1.1.1, 8.8.8.8 and 9.9.9.9."));
}

// ---------- app updates ----------
function updatesCard(settings) {
  const card = h("section", { class: "card form" }, h("h2", {}, "Updates"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  const auto = h("input", { type: "checkbox", checked: settings.check_updates, onchange: (e) =>
    act(null, () => api("/api/settings", { method: "PATCH", body: { check_updates: e.target.checked } }), e.target.checked ? "Will check for updates" : "Updates off").catch(() => (e.target.checked = !e.target.checked)) });
  const show = (u) => {
    const body = [h("h2", {}, "Updates"), h("div", {}, `Version ${u.current}`)];
    if (u.git_checkout) body.push(h("div", { class: "muted small" }, "This copy is a git checkout, so it updates with git pull instead."));
    else if (u.error) body.push(h("div", { class: "error-text" }, u.error));
    else if (u.available) body.push(
      h("div", { style: "font-weight:600;margin-top:6px" }, `Version ${u.latest} is available`),
      u.notes ? h("pre", { class: "muted small", style: "white-space:pre-wrap;margin:6px 0" }, u.notes) : null,
      h("button", { class: "btn primary", onclick: (e) => installUpdate(e.currentTarget, u.latest) }, `Update to ${u.latest}`),
      h("div", { class: "muted small" }, "Downloads it from GitHub, checks it's signed with the project's release key, restarts Orbi Control (about a minute, and you'll need to sign in again), and puts the current version back automatically if the new one doesn't start."));
    else if (u.latest) body.push(h("div", { class: "muted small" }, `You're up to date${u.checked ? ` (checked ${ago(u.checked)})` : ""}.`));
    body.push(h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/update/check", { body: {} })).then(show) }, "Check now"),
      h("label", { class: "switch" }, "Allow updates (checks GitHub twice a day; installing always needs a click)", auto));
    fill(card, ...body);
  };
  api("/api/update").then(show).catch((e) => fill(card, h("h2", {}, "Updates"), h("div", { class: "error-text" }, e.message)));
  return card;
}

async function installUpdate(btn, version) {
  btn.disabled = true;
  let before;
  try {
    before = (await api("/api/session")).instance;
    await api("/api/update/apply", { body: {} });
    await waitJob("update", "Downloading and installing");
  } catch (ex) { toast(ex.message); btn.disabled = false; return; }
  const t = $("#toast");
  const started = Date.now();
  for (;;) {  // the app restarts (which signs everyone out); wait for the new copy to answer
    t.replaceChildren(h("span", { class: "spinner" }), ` Restarting Orbi Control — ${Math.round((Date.now() - started) / 1000)}s`);
    t.hidden = false;
    await new Promise((r) => setTimeout(r, 3000));
    try {
      const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
      // If version 'version' didn't start, the previous one is restored; Recent alerts says which after signing in.
      if (s.instance !== before && Date.now() - started > 15000) { location.reload(); return; }
    } catch { /* restarting */ }
  }
}

const fmtAt = (ts) => new Date(ts * 1000).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });

function rebootSheet(why) {
  const reason = typeof why === "string" ? why : "";  // also used as a click handler
  const info = h("div", {});
  const restart = (when) => (e) => act(e.currentTarget, () => api("/api/router/reboot", { body: { confirm: true, when } })).then(() => { closeSheet(); if (currentTab === "more") renderMore().catch(() => {}); });
  openSheet(h("h3", {}, "Reboot the router?"),
    reason ? h("p", {}, reason) : null,
    h("p", { style: "margin:0" }, "Internet and Wi-Fi will be down for about 3–5 minutes while the Orbi restarts. Satellites reconnect on their own. The app saves the router's log first, since a restart clears it."),
    info,
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, reason ? "Not now" : "Cancel"),
      h("button", { class: "btn", onclick: restart("tonight") }, "Tonight at 3 AM"),
      h("button", { class: "btn danger solid", onclick: restart("now") }, "Restart now")));
  api("/api/router/reboot").then((r) => fill(info,
    r.satellites_offline.length ? h("div", { class: "note" }, `${r.satellites_offline.join(", ")} ${r.satellites_offline.length === 1 ? "is" : "are"} offline right now. A satellite that misses a change can come back with the old settings, so check it's plugged in and wait until it's back before restarting.`) : null,
    r.scheduled_at ? h("p", { class: "muted small" }, `A restart is already scheduled for ${fmtAt(r.scheduled_at)}.`) : null)).catch(() => {});
}

// After a Wi-Fi network is turned off or gets a new name or password, the server looks (about 2 minutes later)
// for devices that stayed connected; the Orbi doesn't always drop them. Offer a restart if any did.
async function afterWifiChange(r) {
  if (!r || !r.checking) return;
  let c;
  try { c = await waitJob("wifi_check", "Checking which devices are still connected"); } catch (e) { toast(e.message); return; }
  if (!c) return;
  if (!c.devices.length) { toast(`Checked: nothing stayed on the ${c.label} from before the change`); return; }
  const names = c.devices.map((d) => d.name).join(", ");
  const one = c.devices.length === 1;
  toast(`${names} ${one ? "is" : "are"} still on the ${c.label}`);
  rebootSheet(`${names} ${one ? "is" : "are"} still connected to the ${c.label} ${c.change === "off" ? "even though it's turned off" : "with the old password"}. ${one ? "It stays" : "They stay"} on until the router restarts.`);
}

// ---------- background router jobs ----------
// Router setting changes take ~30 s to a few minutes; the server runs them as jobs we poll.
async function waitJob(name, label) {
  const t = $("#toast");
  for (;;) {
    const j = await api(`/api/jobs/${name}`);
    if (!j.running) {
      if (j.error) throw new Error(j.error);
      return j.result;
    }
    t.replaceChildren(h("span", { class: "spinner" }), ` ${label} — ${Math.round(Date.now() / 1000 - j.started)}s`);
    t.hidden = false;
    clearTimeout(toastTimer);
    await new Promise((r) => setTimeout(r, 2500));
  }
}

// ---------- content filtering (router DNS) ----------
function filteringCard() {
  const card = h("section", { class: "card" }, h("h2", {}, "Content filtering"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  api("/api/filtering?check=true").then((f) => {
    const p = f.providers[f.current];
    const c = f.check || {};
    const chip = (ok, label) => h("span", { class: `pill ${ok ? "ok" : "warn"}` }, `${ok ? "✓" : "✗"} ${label}`);
    fill(card, h("h2", {}, "Content filtering", h("button", { class: "btn small act", onclick: () => filteringSheet(f) }, "Change")),
      h("div", { style: "font-weight:600" }, p ? p.name : (f.dns.join(", ") || "Your ISP's DNS (no filtering)")),
      p ? h("div", { class: "muted small", style: "margin:2px 0 8px" }, p.summary) : null,
      h("div", { class: "btns" },
        chip(c.youtube === "moderate" || c.youtube === "strict", `YouTube Restricted${c.youtube && c.youtube !== "unrestricted" ? ` (${c.youtube})` : ""}`),
        chip(!!c.safesearch, "SafeSearch"), chip(!!c.adult_blocked, "Adult sites blocked")),
      h("div", { class: "muted small", style: "margin-top:8px" }, "Applies to every device in the house. To stop devices from switching to their own DNS or a VPN, add the router rules below."),
      h("button", { class: "btn small", style: "margin-top:8px", onclick: protectSheet }, "Add rules that block DNS & VPN workarounds…"));
  }).catch((e) => fill(card, h("h2", {}, "Content filtering"), h("div", { class: "error-text" }, e.message)));
  return card;
}

function protectSheet() {
  openSheet(h("h3", {}, "Block DNS & VPN workarounds?"),
    h("p", { style: "margin:0" }, "Adds router rules that block outside DNS (ports 53 and 853) and OpenVPN and WireGuard VPNs (ports 1194 and 51820) for every device in the house, adults included."),
    h("p", { class: "muted small" }, "A work laptop that connects to the office over OpenVPN or WireGuard on those ports will stop connecting. Check before adding them; you can remove them on the router's Block Services page."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/filtering/protect", { body: {} });
        const r = await waitJob("protect", "Checking router rules");
        closeSheet();
        return { note: r && r.added && r.added.length ? `Fixed: ${r.added.join(", ")}` : "All protection rules were already in place" };
      }) }, "Add the rules")));
}

function filteringSheet(f) {
  let choice = f.current || "adguard_family";
  const opts = Object.entries(f.providers).map(([key, p]) => {
    const radio = h("input", { type: "radio", name: "prov", value: key, checked: key === choice, onchange: () => (choice = key) });
    return h("label", { class: "row tap" }, radio, h("div", { class: "main" }, h("div", { class: "name" }, p.name + (key === f.current ? " (current)" : "")),
      h("div", { class: "meta", style: "white-space:normal" }, p.summary)));
  });
  openSheet(h("h3", {}, "Content filtering"),
    h("p", { class: "muted small", style: "margin:0" }, "Changes the DNS service your Orbi uses. The app checks the internet still works afterwards and undoes the change if not."),
    ...opts,
    h("button", { class: "btn primary block", onclick: async (e) => {
      if (choice === f.current) { closeSheet(); return; }
      e.currentTarget.disabled = true;
      try {
        await api("/api/filtering", { body: { provider: choice } });
        closeSheet();
        const r = await waitJob("filtering", "Updating the router");
        toast(r && r.confirmed ? "Filter changed and verified" : "Filter changed; devices pick it up within a few minutes");
      } catch (ex) { toast(ex.message); }
      renderFamily();
    } }, "Apply"));
}

// ---------- whole-house app & site blocking ----------
const BLOCK_PRESETS = [
  ["TikTok", ["tiktok", "musical.ly", "byteoversea", "ibytedtos"]],
  ["Instagram", ["instagram", "cdninstagram"]],
  ["Snapchat", ["snapchat", "sc-cdn.net", "snapkit"]],
  ["Roblox", ["roblox", "rbxcdn"]],
  ["Fortnite / Epic", ["fortnite", "epicgames"]],
  ["Minecraft", ["minecraft", "mojang"]],
  ["Discord", ["discord"]],
  ["Twitch", ["twitch", "ttvnw", "jtvnw"]],
  ["Facebook", ["facebook", "fbcdn"]],
  ["Netflix", ["netflix", "nflxvideo", "nflximg", "nflxext"]],
  ["YouTube (all of it)", ["youtube", "googlevideo", "ytimg"]],
];
const DAY_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const isPresetKeyword = (k) => BLOCK_PRESETS.some(([, kws]) => kws.includes(k));
function scheduleText(sch) {
  if (!sch) return "";
  return `${daysText(sch.days)}${sch.all_day ? ", all day" : `, ${fmtHM(sch.start)} – ${fmtHM(sch.end)}`}`;
}

function siteBlockCard() {
  const card = h("section", { class: "card" }, h("h2", {}, "Block apps & sites"), h("div", { class: "muted small" }, h("span", { class: "spinner" }), " Reading the router…"));
  const load = async () => {
    const r = await api("/api/siteblock");
    if (!r.block_sites) {
      if (!(r.job && r.job.running)) await api("/api/advanced/refresh", { body: {} });
      setTimeout(() => card.isConnected && load().catch(() => {}), 4000);
      return;
    }
    const bs = r.block_sites;
    const groups = BLOCK_PRESETS.filter(([, kws]) => kws.every((k) => bs.keywords.includes(k))).map(([n]) => n);
    const others = bs.keywords.filter((k) => !isPresetKeyword(k));
    const state = bs.mode === "never" || !bs.keywords.length ? h("span", { class: "pill" }, "Off")
      : bs.mode === "always" ? h("span", { class: "pill bad" }, "Blocking all the time")
        : h("span", { class: "pill warn" }, `Blocking ${scheduleText(r.schedule)}`);
    fill(card, h("h2", {}, "Block apps & sites", h("button", { class: "btn small act", onclick: () => siteBlockSheet(bs, r.schedule) }, "Edit")),
      state,
      bs.keywords.length ? h("div", { class: "chips wrap", style: "margin-top:8px" }, ...[...groups, ...others].map((n) => h("span", { class: "chip" }, n))) : null,
      h("div", { class: "muted small", style: "margin-top:8px" }, "Enforced by the Orbi for every device in the house, even when this PC is off."));
  };
  load().catch((e) => fill(card, h("h2", {}, "Block apps & sites"), h("div", { class: "error-text" }, e.message)));
  return card;
}

function siteBlockSheet(bs, sch) {
  const chosen = new Set(bs.keywords.filter(isPresetKeyword));
  const presetBoxes = BLOCK_PRESETS.map(([name, kws]) => {
    const cb = h("input", { type: "checkbox", checked: kws.every((k) => chosen.has(k)),
      onchange: (e) => kws.forEach((k) => (e.target.checked ? chosen.add(k) : chosen.delete(k))) });
    return h("label", { class: "row tap" }, cb, h("div", { class: "main" }, h("div", { class: "name" }, name), h("div", { class: "meta" }, kws.join(", "))));
  });
  const custom = h("input", { type: "text", placeholder: "e.g. hulu.com, pinterest", value: bs.keywords.filter((k) => !isPresetKeyword(k)).join(", ") });
  const mode = h("select", {},
    h("option", { value: "never", selected: bs.mode === "never" }, "Off"),
    h("option", { value: "perschedule", selected: bs.mode === "perschedule" }, "On a schedule"),
    h("option", { value: "always", selected: bs.mode === "always" }, "All the time"));
  const schedDays = sch && !(sch.days === "0123456" && sch.all_day) ? sch.days : "01234";
  const days = h("div", { class: "days" }, ...DAY_SHORT.map((n, i) => h("label", {},
    h("input", { type: "checkbox", value: i, checked: schedDays.includes(String(i)) }), h("span", {}, n.slice(0, 2)))));
  const allDay = h("input", { type: "checkbox", checked: false });
  const start = h("input", { type: "time", value: sch && !sch.all_day ? sch.start : "08:00" });
  const end = h("input", { type: "time", value: sch && !sch.all_day ? sch.end : "15:00" });
  const times = h("div", { class: "inline" }, h("label", { class: "field" }, "From", start), h("label", { class: "field" }, "Until", end));
  const schedBox = h("div", { class: "form" }, h("div", { class: "field" }, "Days", days), h("label", { class: "switch" }, "All day", allDay), times);
  const sync = () => { schedBox.hidden = mode.value !== "perschedule"; times.hidden = allDay.checked; };
  mode.addEventListener("change", sync);
  allDay.addEventListener("change", sync);
  sync();
  const save = h("button", { class: "btn primary block", onclick: async (e) => {
    const keywords = [...chosen, ...custom.value.split(",").map((k) => k.trim().toLowerCase()).filter(Boolean)];
    const body = { mode: mode.value, keywords: [...new Set(keywords)], days: [...days.querySelectorAll("input:checked")].map((c) => c.value).join(""),
      start: allDay.checked ? "00:00" : start.value, end: allDay.checked ? "00:00" : end.value };
    save.disabled = true;
    try {
      await api("/api/siteblock", { method: "PUT", body });
      closeSheet();
      await waitJob("siteblock", "Updating the router");
      toast("Blocking updated on the router");
    } catch (ex) { toast(ex.message); save.disabled = false; return; }
    renderFamily();
  } }, "Save to router");
  openSheet(h("h3", {}, "Block apps & sites"),
    h("p", { class: "muted small", style: "margin:0" }, "Blocks these for every device in the house (the Orbi can't block apps per person). Takes effect within a few minutes as devices refresh."),
    ...presetBoxes,
    h("label", { class: "field" }, "Other sites or keywords (comma-separated; any web address containing one is blocked)", custom),
    h("label", { class: "field" }, "Block", mode), schedBox,
    h("p", { class: "muted small", style: "margin:0" }, "The Orbi has one blocking schedule, shared with its Block Services rules. Those are set to \"always\", so they're unaffected."),
    save);
}

// ---------- Advanced ----------
let logKind = "all", logQuery = "";
async function renderAdvanced() {
  const r = await api("/api/advanced");
  const refresh = h("button", { class: "btn small", onclick: async (e) => {
    await act(e.currentTarget, () => api("/api/advanced/refresh", { body: {} }));
    try { await waitJob("advanced", "Reading router settings"); toast("Updated"); } catch (ex) { toast(ex.message); }
    renderAdvanced();
  } }, "Refresh");
  const status = r.ts ? `Router settings read ${ago(r.ts)}` : r.job && r.job.running ? "Reading router settings (about a minute)…"
    : r.job && r.job.error ? `Couldn't read router settings: ${r.job.error}` : "";
  const head = h("div", { class: "inline", style: "align-items:center" }, h("div", { class: "muted small" }, status), h("div", { style: "flex:0" }, refresh));
  const d = r.data;
  if (!d) {
    setView(head, h("div", { class: "empty" }, h("span", { class: "spinner" })));
    if (r.job && r.job.running) setTimeout(() => currentTab === "advanced" && renderAdvanced().catch(() => {}), 4000);
    return;
  }
  if (!cache.devices) cache.devices = await api("/api/devices").catch(() => []);
  const devName = (ip) => (cache.devices.find((x) => x.ip === ip) || {}).name || "";
  const kv = (pairs) => h("dl", { class: "kv" }, ...pairs.filter(([, v]) => v !== undefined && v !== null && v !== "").flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  const table = (cols, rows) => rows.length
    ? h("div", { style: "overflow-x:auto" }, h("table", { class: "tbl" }, h("tr", {}, ...cols.map((c) => h("th", {}, c))),
      ...rows.map((row) => h("tr", {}, ...row.map((c) => h("td", {}, c == null ? "" : c))))))
    : h("div", { class: "muted small" }, "None.");

  const wan = h("section", { class: "card" }, h("h2", {}, "Internet (WAN)"), kv([
    ["Connection", (d.wan.type || "").toUpperCase()], ["Public IP", d.wan.ip], ["Gateway", d.wan.gateway], ["Netmask", d.wan.netmask],
    ["DNS", `${d.wan.dns.filter(Boolean).join(", ")} (${d.wan.dns_mode})`], ["ISP's DNS", d.wan.isp_dns.filter(Boolean).join(", ")], ["WAN MAC", d.wan.mac]]));
  const lan = h("section", { class: "card" }, h("h2", {}, "LAN & DHCP"), kv([
    ["Router IP", d.lan.ip], ["Subnet mask", d.lan.netmask], ["DHCP server", d.lan.dhcp_enabled ? `On · hands out ${d.lan.dhcp_start} – ${d.lan.dhcp_end}` : "Off"]]),
    h("div", { class: "group-label" }, `Address reservations · ${d.lan.reservations.length}`, h("button", { class: "btn small act", onclick: () => reservationSheet() }, "Add")),
    h("div", { class: "muted small" }, "A reserved device always gets the same address, which keeps firewall rules for one device or a range pointed at the right device."),
    ...d.lan.reservations.map((x, i) => h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name" }, x.name || x.mac), h("div", { class: "meta" }, `${x.ip} · ${x.mac}`)),
      h("button", { class: "btn small", onclick: () => reservationSheet(x, i) }, "Edit"),
      h("button", { class: "btn small danger", onclick: () => deleteReservationSheet(x, i) }, "Delete"))),
    h("div", { class: "muted small", style: "margin-top:8px" }, "Recent DHCP activity is in History → Router log (DHCP filter)."));
  const wifi = h("section", { class: "card" }, h("h2", {}, "Main Wi-Fi"), table(["Band", "Name", "Channel", "Mode", "Security"],
    (d.wifi || []).map((w) => [w.band, w.ssid + (w.enabled ? "" : " (off)"), w.channel, w.mode, w.security])));

  const modeLabel = { never: "Off (Never)", perschedule: "On the blocking schedule", always: "Always on" };
  const who = (ips) => ips === "all" ? "Every device" : `${ips}${devName(ips) ? ` (${devName(ips)})` : ""}`;
  const fw = h("section", { class: "card" },
    h("h2", {}, "Firewall rules", h("button", { class: "btn small act", onclick: () => firewallRuleSheet() }, "Add")),
    h("div", { class: "inline", style: "align-items:center;margin-bottom:6px" },
      h("div", { class: "muted small" }, `Block Services: stops devices connecting out on these ports · ${modeLabel[d.block_services.mode] || d.block_services.mode}`),
      h("div", { style: "flex:0" }, h("button", { class: "btn small", onclick: () => rulesModeSheet(d.block_services.mode) }, "When…"))),
    ...(d.block_services.rules.length ? d.block_services.rules.map((x, i) => h("div", { class: "row" },
      h("div", { class: "main" }, h("div", { class: "name" }, x.name), h("div", { class: "meta" }, `Port ${x.port} · ${who(x.ips)}`)),
      h("button", { class: "btn small", onclick: () => firewallRuleSheet(x, i) }, "Edit"),
      h("button", { class: "btn small danger", onclick: () => deleteFirewallRuleSheet(x, i) }, "Delete")))
      : [h("div", { class: "muted small" }, "No rules.")]));
  const upnpToggle = h("input", { type: "checkbox", checked: d.upnp_enabled !== false, onchange: (e) => upnpSheet(e.target, d.upnp.map((x) => devName(x.ip) || x.ip)) });
  const ports = h("section", { class: "card" }, h("h2", {}, "Port forwarding"),
    h("label", { class: "switch" }, "UPnP (devices open ports themselves)", upnpToggle),
    h("div", { class: "group-label" }, "Opened by UPnP"),
    table(["Device", "Protocol", "Outside", "Inside"], d.upnp.map((x) => [devName(x.ip) ? `${devName(x.ip)} (${x.ip})` : x.ip, x.protocol, x.external_port, x.internal_port])),
    h("div", { class: "group-label" }, "Manual rules"),
    table(["Service", "Outside", "Inside", "Device"], (d.port_forwards || []).map((x) => [x.name, x.external_port, x.internal_port, devName(x.ip) ? `${devName(x.ip)} (${x.ip})` : x.ip])),
    h("div", { class: "muted small" }, "Manual rules are added on the router's Port Forwarding page."));

  setView(head, wan, lan, h("div", { class: "group-label" }, "Wi-Fi networks"), wifi, guestCard(), iotCard(), wpsCard(d.wps, r.hold_new_devices), fw, ports);
}

// ---------- remote access (More): the Orbi's VPN server + Dynamic DNS ----------
function remoteCard() {
  const card = h("section", { class: "card" }, h("h2", {}, "Away from home"), h("div", { class: "muted small" }, h("span", { class: "spinner" }), " Reading from the router…"));
  const load = async () => {
    const r = await api("/api/remote-access");
    if (!r.vpn && !r.ddns) {
      if (r.reading) { setTimeout(() => load().catch(() => {}), 3000); return; }
      fill(card, h("h2", {}, "Away from home"), h("div", { class: "error-text" }, r.error || "Couldn't read the VPN and Dynamic DNS settings from the router."));
      return;
    }
    const v = r.vpn || {}, d = r.ddns || {}, c = r.ddns_check;
    const ddnsState = !d.enabled ? "Off" : c == null ? `${d.host} (checking…)` : c.current ? `${d.host} → ${c.public_ip} ✓`
      : `${d.host} → ${c.resolves_to.join(", ") || "doesn't resolve"} (your internet address is ${c.public_ip || "unknown"})`;
    fill(card, h("h2", {}, "Away from home", d.provider !== "NETGEAR" ? h("button", { class: "btn small act", onclick: () => ddnsSheet(d) }, "Dynamic DNS…") : null),
      h("dl", { class: "kv" },
        h("dt", {}, "Orbi VPN server"), h("dd", {}, v.enabled ? `On · ${String(v.protocol || "").toUpperCase()} port ${v.port}` : "Off"),
        h("dt", {}, "Dynamic DNS"), h("dd", {}, d.enabled ? `${d.provider} · ${ddnsState}` : "Off")),
      c && !c.current ? h("div", { class: "note" }, "Your Dynamic DNS name doesn't point at your current internet address, so connecting from outside may fail until the router updates it.") : null,
      h("div", { class: "muted small" }, "To use Orbi Control away from home, connect your phone to the Orbi's VPN (set up in the Orbi app), then open the same address as at home. Dynamic DNS keeps a name like myhome.ddns.net pointing at your home's internet address, which the VPN uses to find home."),
      vpnLogList());
  };
  load().catch((e) => fill(card, h("h2", {}, "Away from home"), h("div", { class: "error-text" }, e.message)));
  return card;
}

// Connections to the Orbi's VPN server, from the router log (the Orbi doesn't log who, only from where).
function vpnSessionRow(x) {
  const when = x.start == null ? `Until ${fmtWhen(x.end)}` : x.end ? `${fmtWhen(x.start)} – ${fmtTime(x.end)}` : `Since ${fmtWhen(x.start)}`;
  const extra = [x.reconnects ? `reconnected ${x.reconnects}×` : null, x.end ? null : "disconnect not logged"].filter(Boolean).join(" · ");
  return h("div", { class: "row" }, ico("wifi"), h("div", { class: "main" },
    h("div", { class: "name" }, x.inside ? `From inside your home (${x.ip})` : `From ${x.ip}`),
    h("div", { class: "meta" }, [when, extra].filter(Boolean).join(" · "))));
}

function vpnFailRow(x) {
  const span = x.first === x.last ? fmtWhen(x.first) : `${fmtWhen(x.first)} – ${fmtTime(x.last)}`;
  return h("div", { class: "row" }, h("div", { class: "main" },
    h("div", { class: "name" }, `${x.count} failed attempt${x.count === 1 ? "" : "s"} ${x.inside ? `from inside your home (${x.device || x.ip})` : `from ${x.ip}`}`),
    h("div", { class: "meta" }, span + (x.inside ? " · usually a phone trying the VPN while it's on home Wi-Fi" : ""))),
    x.inside ? null : h("span", { class: "pill warn" }, "Outside"));
}

function vpnLogList() {
  const box = h("div", {}, h("div", { class: "group-label" }, "Recent VPN connections"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  api("/api/vpn-log?days=14").then((r) => {
    const showAll = () => openSheet(h("h3", {}, "VPN connections (14 days)"),
      ...(r.sessions.length ? r.sessions.map(vpnSessionRow) : [h("div", { class: "muted small" }, "None.")]),
      h("div", { class: "group-label" }, "Failed attempts"), ...(r.failures.length ? r.failures.map(vpnFailRow) : [h("div", { class: "muted small" }, "None.")]),
      h("p", { class: "muted small" }, "The Orbi logs where each connection came from, not who made it. Phones on mobile data reconnect every few minutes; those are grouped into one session."),
      h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Close")));
    const outsideFails = r.failures.filter((f) => !f.inside);
    fill(box, h("div", { class: "group-label" }, "Recent VPN connections"),
      ...(r.sessions.length ? r.sessions.slice(0, 4).map(vpnSessionRow) : [h("div", { class: "muted small" }, "No connections in the last 14 days.")]),
      outsideFails.length ? vpnFailRow(outsideFails[0]) : null,
      r.sessions.length > 4 || r.failures.length ? h("button", { class: "btn small", style: "margin-top:6px", onclick: showAll }, "Show all") : null);
  }).catch((e) => fill(box, h("div", { class: "error-text" }, e.message)));
  return box;
}

function ddnsSheet(d) {
  const on = h("input", { type: "checkbox", checked: !!d.enabled });
  const provider = h("select", {}, ...["No-IP", "Dyn"].map((p) => h("option", { value: p, selected: p === d.provider }, p === "No-IP" ? "No-IP (noip.com)" : "Dyn (dyn.com)")));
  const host = h("input", { value: d.host || "", placeholder: "myhome.ddns.net", autocapitalize: "off", spellcheck: "false" });
  const user = h("input", { value: d.user || "", autocapitalize: "off", spellcheck: "false" });
  const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "Leave blank to keep the current password" });
  const fields = h("div", {}, h("label", { class: "field" }, "Service", provider), h("label", { class: "field" }, "Host name", host),
    h("label", { class: "field" }, "User name or email", user), h("label", { class: "field" }, "Password (optional)", pw));
  const sync = () => { fields.hidden = !on.checked; };
  on.addEventListener("change", sync); sync();
  openSheet(h("h3", {}, "Dynamic DNS"), h("label", { class: "switch" }, "Use a Dynamic DNS service", on), fields,
    h("p", { class: "muted small" }, "The Orbi's VPN uses this name to find your home from outside. If it's wrong or turned off, connecting to the VPN away from home stops working. The account details come from your Dynamic DNS provider."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/ddns", { method: "PUT", body: { enabled: on.checked, provider: provider.value, host: host.value, user: user.value, password: pw.value || null } });
        pw.value = "";
        await waitJob("ddns", "Saving to the router");
        closeSheet(); renderMore().catch(() => {});
        return { note: "Dynamic DNS saved" };
      }) }, "Save")));
}

// ---------- address reservations & UPnP (Advanced) ----------
function reservationSheet(x, index) {
  const ip = h("input", { value: x ? x.ip : "", placeholder: "192.168.1.x", inputmode: "decimal" });
  const mac = h("input", { value: x ? x.mac : "", placeholder: "AA:BB:CC:11:22:33", autocapitalize: "characters", spellcheck: "false" });
  const name = h("input", { value: x ? x.name : "", maxlength: 32 });
  openSheet(h("h3", {}, x ? `Edit ${x.name || x.mac}` : "Reserve an address"),
    h("label", { class: "field" }, "IP address", ip), h("label", { class: "field" }, "Device MAC address", mac), h("label", { class: "field" }, "Name", name),
    h("p", { class: "muted small" }, "Tip: Devices → tap a device → Reserve this address fills these in. The device picks up a changed address the next time it reconnects."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
        const body = { ip: ip.value, mac: mac.value, name: name.value };
        if (x) await api(`/api/reservations/${index}`, { method: "PUT", body: { ...body, expected_mac: x.mac } });
        else await api("/api/reservations", { body });
        return routerJob("reservation", "Saving to the router", "Reservation saved");
      }) }, "Save")));
}

function deleteReservationSheet(x, index) {
  openSheet(h("h3", {}, `Remove the reservation for ${x.name || x.mac}?`),
    h("p", { style: "margin:0" }, `${x.ip} will go back to being handed out to any device. Firewall rules that name ${x.ip} may then apply to a different device.`),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn danger solid", onclick: (e) => act(e.currentTarget, async () => {
        await api(`/api/reservations/${index}?mac=${encodeURIComponent(x.mac)}`, { method: "DELETE" });
        return routerJob("reservation", "Removing on the router", "Reservation removed");
      }) }, "Remove")));
}

function upnpSheet(toggle, users) {
  const turningOn = toggle.checked;
  toggle.checked = !turningOn;  // only changes once confirmed and saved
  openSheet(h("h3", {}, turningOn ? "Turn UPnP on?" : "Turn UPnP off?"),
    h("p", { style: "margin:0" }, turningOn
      ? "Any device on your network will be able to open ports to the internet by itself. Game consoles and media servers like this, but so does malware."
      : `Devices will no longer open ports by themselves, and the ones they opened close.${users.length ? ` That affects ${[...new Set(users)].join(", ")}: online gaming or remote streaming on them may stop working until you add manual forwards.` : ""}`),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: `btn ${turningOn ? "primary" : "danger solid"}`, onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/upnp", { method: "PUT", body: { enabled: turningOn } });
        return routerJob("upnp", "Saving to the router", `UPnP ${turningOn ? "on" : "off"}`);
      }) }, turningOn ? "Turn on" : "Turn off")));
}

// ---------- Guest & IoT Wi-Fi (Advanced, under Main Wi-Fi) ----------
function guestCard() {
  const guest = h("section", { class: "card" }, h("h2", {}, "Guest Wi-Fi"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  api("/api/guest").then((g) => {
    const toggle = h("input", { type: "checkbox", checked: g.enabled, onchange: (e) => act(null, () => api("/api/guest", { body: { enabled: e.target.checked } }), `Guest Wi-Fi ${e.target.checked ? "on" : "off"}`).then(afterWifiChange, () => (e.target.checked = !e.target.checked)) });
    const pw = h("span", {}, "••••••••");
    guest.replaceChildren(h("h2", {}, "Guest Wi-Fi"), h("label", { class: "switch" }, "Guest network", toggle),
      h("dl", { class: "kv" }, h("dt", {}, "Name"), h("dd", {}, g.ssid || "—"), h("dt", {}, "Password"),
        h("dd", {}, pw, " ", h("button", { class: "btn small", onclick: (e) => { pw.textContent = pw.textContent.startsWith("•") ? g.password || "(none)" : "••••••••"; e.currentTarget.textContent = pw.textContent.startsWith("•") ? "Show" : "Hide"; } }, "Show"))));
  }).catch((e) => guest.replaceChildren(h("h2", {}, "Guest Wi-Fi"), h("div", { class: "error-text" }, e.message)));
  return guest;
}

function iotCard() {
  const card = h("section", { class: "card" }, h("h2", {}, "IoT Wi-Fi"), h("div", { class: "muted small" }, h("span", { class: "spinner" }), " Reading from the router…"));
  const bandLabel = { "2.4": "2.4 GHz", 5: "5 GHz", both: "2.4 GHz + 5 GHz" };
  const load = async () => {
    const [r, devices] = await Promise.all([api("/api/iot"), cache.devices ? cache.devices : api("/api/devices").catch(() => [])]);
    if (!r.iot) {
      if (r.reading) { setTimeout(() => card.isConnected && load().catch(() => {}), 3000); return; }
      fill(card, h("h2", {}, "IoT Wi-Fi"), h("div", { class: "error-text" }, r.error || "Couldn't read the IoT network from the router."));
      return;
    }
    const iot = r.iot;
    const now = devices.filter((x) => x.online && x.network === "iot");
    fill(card, h("h2", {}, "IoT Wi-Fi", h("button", { class: "btn small act", onclick: () => iotSheet(iot) }, "Change")),
      h("dl", { class: "kv" }, h("dt", {}, "Network"), h("dd", {}, iot.enabled ? "On" : "Off"),
        iot.enabled ? [h("dt", {}, "Name"), h("dd", {}, iot.ssid), h("dt", {}, "Band"), h("dd", {}, bandLabel[iot.band]),
          h("dt", {}, "Security"), h("dd", {}, iot.security === "WPA2-PSK" ? "WPA2-PSK [AES]" : "WPA + WPA2 (older devices)")] : null,
        h("dt", {}, "Connected now"), h("dd", {}, `${now.length} device${now.length === 1 ? "" : "s"}`)),
      h("div", { class: "muted small" }, "A separate network for smart plugs, cameras and other gadgets, so they don't share your main Wi-Fi name and password."));
  };
  load().catch((e) => fill(card, h("h2", {}, "IoT Wi-Fi"), h("div", { class: "error-text" }, e.message)));
  return card;
}

function wpsCard(w, hold) {
  if (!w || w.enabled == null) return null;
  return h("section", { class: "card" }, h("h2", {}, "WPS (Sync button)"),
    h("dl", { class: "kv" }, h("dt", {}, "WPS"), h("dd", {}, w.enabled ? (w.adjustable ? "On" : "On (this firmware can't turn it off)") : "Off"),
      h("dt", {}, "New devices"), h("dd", {}, hold ? "Held until you approve them" : "Allowed straight away")),
    w.enabled ? h("div", { class: "muted small" }, "Pressing Sync on the router or any satellite opens a 2-minute window in which a device that supports WPS (Windows PCs, printers, some TVs and game consoles; not iPhones, iPads, Apple Watches or most current Android phones) can join the main Wi-Fi without the password, and a Windows PC can then show the password. The router doesn't log it. ",
      hold ? "A device that joins this way is new to the app, so it stays blocked until you approve it." : "Turn on \"Hold new devices\" (Family → Everyone else) so a device that joins this way stays blocked until you approve it.",
      w.adjustable ? " You can turn WPS off on the router's Advanced Wireless page." : "") : null);
}

// ---------- firewall rules (Advanced) ----------
async function routerJob(name, label, done) {
  let result;
  try { result = await waitJob(name, label); }
  catch (e) {
    if (/Can't reach/.test(e.message)) return { note: "Lost contact while the router applied it. Refresh Advanced in a minute to confirm." };
    throw e;
  }
  closeSheet(); renderAdvanced().catch(() => {});
  return { note: done, result };
}

function firewallRuleSheet(rule, index) {
  const [ps, pe] = rule ? rule.port.split("-").map((x) => x.trim()) : ["", ""];
  const range = rule && rule.ips.includes(" - ") ? rule.ips.split(" - ") : null;
  const now = !rule || rule.ips === "all" ? "all" : range ? "range" : "single";
  const name = h("input", { value: rule ? rule.name : "", maxlength: 30, placeholder: "e.g. Block-Minecraft" });
  const proto = h("select", {}, ...["TCP/UDP", "TCP", "UDP"].map((p) => h("option", { value: p }, p)));
  const start = h("input", { type: "number", min: 1, max: 65535, value: ps || "" });
  const end = h("input", { type: "number", min: 1, max: 65535, value: pe || "", placeholder: "same" });
  const applies = h("select", {}, h("option", { value: "all", selected: now === "all" }, "Every device"),
    h("option", { value: "single", selected: now === "single" }, "One device (IP address)"),
    h("option", { value: "range", selected: now === "range" }, "A range of addresses"));
  const ip = h("input", { value: now === "single" ? rule.ips : range ? range[0] : "", placeholder: "192.168.1.x", inputmode: "decimal" });
  const ipEnd = h("input", { value: range ? range[1] : "", placeholder: "192.168.1.x", inputmode: "decimal" });
  const ipLabel = h("span", {}, "IP address");
  const ipRow = h("label", { class: "field" }, ipLabel, ip);
  const endRow = h("label", { class: "field" }, "to", ipEnd);
  const sync = () => { ipRow.hidden = applies.value === "all"; endRow.hidden = applies.value !== "range"; ipLabel.textContent = applies.value === "range" ? "From" : "IP address"; };
  applies.addEventListener("change", sync); sync();
  const save = h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
    const body = { name: name.value, protocol: proto.value, port_start: Number(start.value), port_end: Number(end.value || start.value),
      applies: applies.value, ip: ip.value, ip_end: ipEnd.value };
    if (rule) await api(`/api/firewall/rules/${index}`, { method: "PUT", body: { ...body, expected_name: rule.name } });
    else await api("/api/firewall/rules", { body });
    return routerJob("firewall", "Saving to the router", rule ? "Rule saved" : "Rule added");
  }) }, rule ? "Save" : "Add rule");
  openSheet(h("h3", {}, rule ? `Edit ${rule.name}` : "New firewall rule"),
    h("p", { class: "muted small", style: "margin:0" }, "Blocks devices from connecting out on these ports. Saving takes about a minute, and the router's list is checked afterwards."),
    h("label", { class: "field" }, "Name", name), h("label", { class: "field" }, "Protocol", proto),
    h("div", { class: "inline" }, h("label", { class: "field" }, "Port", start), h("label", { class: "field" }, "to port (optional)", end)),
    h("label", { class: "field" }, "Block it for", applies), ipRow, endRow,
    rule ? h("p", { class: "muted small" }, "The router's list doesn't show a rule's protocol, so check it before saving. TCP/UDP blocks both.") : null,
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"), save));
}

function deleteFirewallRuleSheet(rule, index) {
  const guard = /^Block[- ](External[- ]DNS|DoT|VPN)/i.test(rule.name);
  openSheet(h("h3", {}, `Delete ${rule.name}?`),
    h("p", { style: "margin:0" }, `Devices will be able to connect out on port ${rule.port} again${rule.ips === "all" ? "" : ` (${rule.ips})`}.`),
    guard ? h("p", { class: "muted small" }, "This is one of the rules that stops devices getting around content filtering or using a VPN. Deleting it records an alert.") : null,
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn danger solid", onclick: (e) => act(e.currentTarget, async () => {
        await api(`/api/firewall/rules/${index}?name=${encodeURIComponent(rule.name)}`, { method: "DELETE" });
        return routerJob("firewall", "Deleting on the router", "Rule deleted");
      }) }, "Delete")));
}

function rulesModeSheet(mode) {
  const sel = h("select", {}, ...[["always", "Always"], ["perschedule", "On the blocking schedule"], ["never", "Never (all rules off)"]]
    .map(([v, l]) => h("option", { value: v, selected: v === mode }, l)));
  openSheet(h("h3", {}, "When do firewall rules apply?"), h("label", { class: "field" }, "Rules apply", sel),
    h("p", { class: "muted small" }, "The schedule is the router's single blocking schedule, shared with whole-house site blocking. Never turns every rule off, including the ones that protect content filtering."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/firewall/mode", { method: "PUT", body: { mode: sel.value } });
        return routerJob("firewall", "Saving to the router", "Saved");
      }) }, "Save")));
}

function iotSheet(iot) {
  const on = h("input", { type: "checkbox", checked: !!iot.enabled });
  const ssid = h("input", { value: iot.ssid || "", maxlength: 32 });
  const band = h("select", {}, ...[["2.4", "2.4 GHz only (most smart devices)"], ["both", "2.4 GHz and 5 GHz"], ["5", "5 GHz only"]]
    .map(([v, l]) => h("option", { value: v, selected: v === (iot.band || "2.4") }, l)));
  const sec = h("select", {}, h("option", { value: "WPA2-PSK", selected: iot.security !== "WPA-AUTO-PSK" }, "WPA2-PSK [AES]"),
    h("option", { value: "WPA-AUTO-PSK", selected: iot.security === "WPA-AUTO-PSK" }, "WPA + WPA2 (only for very old devices)"));
  const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "Leave blank to keep the current password" });
  const fields = h("div", {}, h("label", { class: "field" }, "Network name", ssid), h("label", { class: "field" }, "Band", band),
    h("label", { class: "field" }, "Security", sec), h("label", { class: "field" }, "New password (optional)", pw));
  const sync = () => { fields.hidden = !on.checked; };
  on.addEventListener("change", sync); sync();
  openSheet(h("h3", {}, "IoT Wi-Fi"), h("label", { class: "switch" }, "IoT network on", on), fields,
    h("p", { class: "muted small" }, "Saving can pause Wi-Fi on the router and satellites for about a minute. The Orbi doesn't always drop devices that were already connected, so after a new name or password, or turning it off, the app checks who stayed on and offers to restart the router."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/iot", { method: "PUT", body: { enabled: on.checked, ssid: ssid.value, band: band.value, security: sec.value, password: pw.value || null } });
        pw.value = "";
        const r = await routerJob("iot", "Saving (Wi-Fi restarts)", "IoT Wi-Fi saved");
        afterWifiChange(r.result);
        return r;
      }) }, "Save")));
}

// ---------- later bedtime tonight ----------
function lateCard(profiles) {
  const late = profiles.filter((p) => p.late_minutes);
  if (late.length) {
    const mins = late[0].late_minutes;
    return h("div", { class: "note" }, `Tonight's schedules start ${mins >= 60 ? `${mins / 60} hour${mins === 60 ? "" : "s"}` : `${mins} minutes`} later for ${late.map((p) => p.name).join(", ")}. Morning times are unchanged. `,
      h("button", { class: "btn small", onclick: (e) => act(e.currentTarget, () => api("/api/family/late-bedtime", { method: "DELETE" }), "Back to normal").then(renderFamily) }, "Cancel"));
  }
  return h("button", { class: "btn block", onclick: () => lateSheet(profiles) }, "🌙 Later bedtime tonight…");
}

function lateSheet(profiles) {
  const withRules = profiles.filter((p) => p.rules.some((r) => r.enabled));
  let minutes = 60;
  const choices = h("div", { class: "chips" }, ...[30, 60, 90, 120].map((m) => h("button", { class: `chip${m === minutes ? " on" : ""}`, onclick: (e) => {
    minutes = m; choices.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === e.currentTarget)); } }, m < 60 ? `${m} min` : `${m / 60} hour${m === 60 ? "" : "s"}`)));
  const boxes = withRules.map((p) => [p, h("input", { type: "checkbox", checked: true })]);
  openSheet(h("h3", {}, "Later bedtime tonight"),
    h("p", { class: "muted small", style: "margin:0" }, "Tonight's schedules start later, for example for no school tomorrow. When they end in the morning doesn't change, pauses still apply, and everything is back to normal tomorrow."),
    choices, ...boxes.map(([p, box]) => h("label", { class: "switch" }, `${p.emoji || ""} ${p.name}`.trim(), box)),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn primary", onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/family/late-bedtime", { body: { minutes, profile_ids: boxes.filter(([, b]) => b.checked).map(([p]) => p.id) } });
        closeSheet(); renderFamily();
        return { note: "Bedtime moved later for tonight" };
      }) }, "Save")));
}

// ---------- per-profile "what did they try?" report ----------
function reportSheet(p) {
  const body = h("div", {}, h("span", { class: "spinner" }));
  let days = 7;
  const chips = h("div", { class: "chips" }, ...[[1, "Today"], [7, "7 days"], [30, "30 days"]].map(([d, l]) => h("button", { class: `chip${d === days ? " on" : ""}`, onclick: (e) => {
    days = d; chips.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === e.currentTarget)); load(); } }, l)));
  const list = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}×`).join(", ");
  const load = () => api(`/api/profiles/${p.id}/report?days=${days}`).then((r) => {
    if (!r.devices.length) { fill(body, h("div", { class: "muted small" }, "Nothing blocked or unusual in this period.")); return; }
    fill(body, h("div", { class: "note" }, r.summary),
      ...r.devices.map((d) => h("div", { class: "sub-list" }, h("div", { class: "group-label" }, d.name),
        Object.keys(d.sites).length ? h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name" }, "Blocked sites & apps"), h("div", { class: "meta", style: "white-space:normal" }, list(d.sites)))) : null,
        Object.keys(d.bypass).length ? h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name" }, "Tried to get around the content filter"), h("div", { class: "meta", style: "white-space:normal" }, list(d.bypass)))) : null,
        Object.keys(d.vpn).length ? h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name" }, "VPN attempts"), h("div", { class: "meta", style: "white-space:normal" }, list(d.vpn)))) : null,
        ...d.networks.map((n) => h("div", { class: "row" }, h("div", { class: "main" }, h("div", { class: "name" }, n.title), h("div", { class: "meta" }, fmtWhen(n.ts))))))));
  }).catch((e) => fill(body, h("div", { class: "error-text" }, e.message)));
  openSheet(h("h3", {}, `${p.name}: what was blocked`), chips, body,
    h("p", { class: "muted small" }, "From the router's log: each blocked attempt by this profile's devices. Apps retry automatically, so large numbers are normal; what matters is what they tried and when. A summary is also added to History every Sunday evening."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Close")));
  load();
}

// ---------- blocked VPN attempts (Family → Whole house) ----------
function vpnAttemptsCard() {
  const card = h("section", { class: "card" }, h("h2", {}, "VPN attempts"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  api("/api/events?kind=vpn_attempt&limit=20").then((list) => fill(card, h("h2", {}, "VPN attempts"),
    h("div", { class: "muted small", style: "margin-bottom:6px" }, "Devices that tried to connect to a VPN app and were blocked by the router's VPN rules (Advanced → Firewall rules)."),
    ...(list.length ? list.map((e) => h("div", { class: "row" }, h("div", { class: "main" },
      h("div", { class: "name" }, e.title), h("div", { class: "meta" }, `${fmtWhen(e.ts)} · ${e.detail}`))))
      : [h("div", { class: "muted small" }, "None so far.")]))).catch((e) => fill(card, h("h2", {}, "VPN attempts"), h("div", { class: "error-text" }, e.message)));
  return card;
}

// ---------- default profile ("everyone else") ----------
function defaultCard(profiles) {
  const card = h("section", { class: "card" }, h("h2", {}, "Everyone else"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  api("/api/family/settings").then((fs) => {
    const sel = h("select", {}, h("option", { value: "" }, "No restrictions"),
      ...profiles.map((p) => h("option", { value: p.id, selected: fs.default_profile_id === p.id }, `Follow ${p.emoji || ""} ${p.name}`.replace("  ", " "))));
    const hold = h("input", { type: "checkbox", checked: fs.hold_new_devices });
    const save = () => act(null, () => api("/api/family/settings", { method: "PUT",
      body: { default_profile_id: sel.value ? Number(sel.value) : null, hold_new_devices: hold.checked } }), "Saved").then(() => renderFamily());
    sel.addEventListener("change", save);
    hold.addEventListener("change", save);
    fill(card, h("h2", {}, "Everyone else"),
      h("div", { class: "muted small", style: "margin-bottom:8px" },
        `${fs.unassigned} device${fs.unassigned === 1 ? " isn't" : "s aren't"} in a profile. They, and any brand-new device (like a phone that changed its address), get these rules:`),
      h("label", { class: "field" }, "Devices without a profile", sel),
      h("label", { class: "switch", style: "margin-top:6px" }, h("span", {}, "Hold brand-new devices until I approve them",
        h("div", { class: "muted small" }, "Strongest protection against address changing. Visitors' devices will need approving too.")), hold),
      fs.unassigned ? h("button", { class: "btn small", style: "margin-top:8px", onclick: () => assignAllSheet(profiles, fs.unassigned) },
        `Move all ${fs.unassigned} into a profile…`) : null,
      h("div", { class: "muted small", style: "margin-top:8px" },
        "Tip: put adults' devices, TVs, cameras and smart-home gear in an unrestricted profile first, so only new devices fall through to these rules. Devices that come back with a new private address but the same name rejoin their profile automatically."));
  }).catch((e) => fill(card, h("h2", {}, "Everyone else"), h("div", { class: "error-text" }, e.message)));
  return card;
}

function assignAllSheet(profiles, count) {
  const move = async (pid, btn) => {
    await act(btn, () => api("/api/family/assign-unassigned", { body: { profile_id: pid } }), `Moved ${count} devices`);
    closeSheet();
    renderFamily();
  };
  openSheet(h("h3", {}, `Move ${count} devices into a profile`),
    h("p", { class: "muted small", style: "margin:0" }, "Moves every device that isn't in a profile right now. Devices that join later aren't affected."),
    ...profiles.map((p) => h("button", { class: "btn block", onclick: (e) => move(p.id, e.currentTarget) }, `${p.emoji || ""} ${p.name}`.trim())),
    h("button", { class: "btn primary block", onclick: async (e) => {
      const btn = e.currentTarget;
      const r = await act(btn, () => api("/api/profiles", { body: { name: "Home & adults", emoji: "🏠" } }));
      if (r && r.id) await move(r.id, btn);
    } }, "Create “Home & adults” (no restrictions) and move them there"));
}

boot();
