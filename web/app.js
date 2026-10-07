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
    const bh = s.backhaul === "wired" ? "Wired backhaul" : s.backhaul ? `${s.backhaul.replace("GHz", " GHz")} wireless backhaul` : "";
    mesh.append(h("div", { class: `row${s.online === false ? " offline" : ""}` }, ico("sat"),
      h("div", { class: "main" }, h("div", { class: "name" }, s.name),
        h("div", { class: "meta" }, [s.online === false ? "Not connected" : `${s.devices ?? 0} devices`, bh].filter(Boolean).join(" · "))),
      s.online === false ? h("span", { class: "pill bad" }, "Offline") : s.backhaul === "wired" ? h("span", { class: "pill ok" }, "Wired") : signalBars(s.signal, "")));
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

// ---------- Devices ----------
let devFilter = "online", devQuery = "";
async function renderDevices() {
  const [devices, profiles] = await Promise.all([api("/api/devices"), api("/api/profiles")]);
  cache.devices = devices; cache.profiles = profiles;
  const list = h("div");
  const search = h("input", { class: "search", type: "search", placeholder: "Search name, IP or MAC", value: devQuery, "aria-label": "Search devices",
    oninput: (e) => { devQuery = e.target.value; draw(); } });
  const chips = h("div", { class: "chips" });
  const filters = { online: "Online", all: "All", blocked: "Blocked", unassigned: "No profile", new: "New this week" };
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

function deviceRow(d) {
  const band = d.connection === "wired" ? "Wired" : d.connection.replace("GHz", " GHz");
  return h("div", { class: `row tap${d.online ? "" : " offline"}`, role: "button", tabindex: 0, onclick: () => deviceSheet(d), onkeydown: (e) => e.key === "Enter" && deviceSheet(d) },
    ico(d.connection === "wired" ? "wired" : "wifi"),
    h("div", { class: "main" }, h("div", { class: "name" }, d.name),
      h("div", { class: "meta" }, d.online ? [d.ip, band, d.randomized ? "private address" : null].filter(Boolean).join(" · ") : `Last seen ${d.last_seen ? ago(d.last_seen) : "—"}`)),
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
      h("dt", {}, "Connected to"), h("dd", {}, [d.ap, d.connection === "wired" ? "wired" : d.connection, d.ssid].filter(Boolean).join(" · ") || "—"),
      d.signal != null && d.connection !== "wired" ? [h("dt", {}, "Signal"), h("dd", {}, `${d.signal}%${d.link_rate ? ` · ${d.link_rate} Mbps link` : ""}`)] : null,
      d.model ? [h("dt", {}, "Model"), h("dd", {}, d.model)] : null,
      h("dt", {}, "First seen"), h("dd", {}, d.first_seen ? fmtWhen(d.first_seen) : "—")),
    h("label", { class: "field" }, "Name", alias),
    h("label", { class: "field" }, "Family profile", profileSel),
    h("div", { class: "btns" }, approve, save, d.held ? null : blockBtn));
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
      h("button", { class: "btn", onclick: () => profileSheet(p) }, "Edit"));
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
  setView(ac, intro, ...cards, profiles.length ? defaultCard(profiles) : null,
    h("button", { class: "btn primary block", onclick: () => profileSheet(null) }, "+ New profile"),
    h("div", { class: "group-label", style: "margin-top:8px" }, "Whole house"), dns, blocking);
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
  setView(chips, uptimeCard, outageCard, speedCard, trafficCard, log);
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
  const [settings, access, events] = await Promise.all([api("/api/settings"), api("/api/access"), api("/api/events?limit=50")]);
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

  const guest = h("section", { class: "card" }, h("h2", {}, "Guest Wi-Fi"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  api("/api/guest").then((g) => {
    const toggle = h("input", { type: "checkbox", checked: g.enabled, onchange: (e) => act(null, () => api("/api/guest", { body: { enabled: e.target.checked } }), `Guest Wi-Fi ${e.target.checked ? "on" : "off"}`).catch(() => (e.target.checked = !e.target.checked)) });
    const pw = h("span", {}, "••••••••");
    guest.replaceChildren(h("h2", {}, "Guest Wi-Fi"), h("label", { class: "switch" }, "Guest network", toggle),
      h("dl", { class: "kv" }, h("dt", {}, "Name"), h("dd", {}, g.ssid || "—"), h("dt", {}, "Password"),
        h("dd", {}, pw, " ", h("button", { class: "btn small", onclick: (e) => { pw.textContent = pw.textContent.startsWith("•") ? g.password || "(none)" : "••••••••"; e.currentTarget.textContent = pw.textContent.startsWith("•") ? "Show" : "Hide"; } }, "Show"))));
  }).catch((e) => guest.replaceChildren(h("h2", {}, "Guest Wi-Fi"), h("div", { class: "error-text" }, e.message)));

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
  const routerCard = h("section", { class: "card form" }, h("h2", {}, "Router"),
    h("label", { class: "field" }, `Admin password for ${settings.router_host}`, rpw),
    h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/settings/router-password", { body: { password: rpw.value } }), "Router password saved").then(() => (rpw.value = "")) }, "Update password"),
    h("button", { class: "btn", onclick: (e) => act(e.currentTarget, async () => { const f = await api("/api/firmware"); toast(f.available ? `Firmware ${f.available} is available` : `Firmware ${f.current} is up to date`); }) }, "Check for firmware update"),
    h("button", { class: "btn danger", onclick: rebootSheet }, "Reboot router…"));

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
    h("label", { class: "switch" }, "Show the Advanced tab (DHCP, logs, VPN, firewall rules…)", advToggle));
  setView(alertCard, phone, guest, advCard, monitoring, routerCard, pinCard, updatesCard(settings),
    h("div", { class: "muted small center" }, "Orbi Control runs on your PC and talks to the Orbi directly — no cloud. The only outside connection is the optional update check to GitHub."));
}

// ---------- app updates ----------
function updatesCard(settings) {
  const card = h("section", { class: "card form" }, h("h2", {}, "Updates"), h("div", { class: "muted small" }, h("span", { class: "spinner" })));
  const auto = h("input", { type: "checkbox", checked: settings.check_updates, onchange: (e) =>
    act(null, () => api("/api/settings", { method: "PATCH", body: { check_updates: e.target.checked } }), e.target.checked ? "Will check for updates" : "Update checks off").catch(() => (e.target.checked = !e.target.checked)) });
  const show = (u) => {
    const body = [h("h2", {}, "Updates"), h("div", {}, `Version ${u.current}`)];
    if (u.git_checkout) body.push(h("div", { class: "muted small" }, "This copy is a git checkout, so it updates with git pull instead."));
    else if (u.error) body.push(h("div", { class: "error-text" }, u.error));
    else if (u.available) body.push(
      h("div", { style: "font-weight:600;margin-top:6px" }, `Version ${u.latest} is available`),
      u.notes ? h("pre", { class: "muted small", style: "white-space:pre-wrap;margin:6px 0" }, u.notes) : null,
      h("button", { class: "btn primary", onclick: (e) => installUpdate(e.currentTarget, u.latest) }, `Update to ${u.latest}`),
      h("div", { class: "muted small" }, "Downloads it from GitHub, restarts Orbi Control (about a minute), and puts the current version back automatically if the new one doesn't start."));
    else if (u.latest) body.push(h("div", { class: "muted small" }, `You're up to date${u.checked ? ` (checked ${ago(u.checked)})` : ""}.`));
    body.push(h("button", { class: "btn", onclick: (e) => act(e.currentTarget, () => api("/api/update/check", { body: {} })).then(show) }, "Check now"),
      h("label", { class: "switch" }, "Check for updates automatically", auto));
    fill(card, ...body);
  };
  api("/api/update").then(show).catch((e) => fill(card, h("h2", {}, "Updates"), h("div", { class: "error-text" }, e.message)));
  return card;
}

async function installUpdate(btn, version) {
  btn.disabled = true;
  try {
    await api("/api/update/apply", { body: {} });
    await waitJob("update", "Downloading and installing");
  } catch (ex) { toast(ex.message); btn.disabled = false; return; }
  const t = $("#toast");
  const started = Date.now();
  for (;;) {  // the app restarts on the new code; wait for it to answer with the new version
    t.replaceChildren(h("span", { class: "spinner" }), ` Restarting Orbi Control — ${Math.round((Date.now() - started) / 1000)}s`);
    t.hidden = false;
    await new Promise((r) => setTimeout(r, 3000));
    try {
      const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
      if (s.version === version) { location.reload(); return; }
      if (Date.now() - started > 150000) { toast(`Still on ${s.version}: the update didn't start, so the previous version was kept. See Recent alerts.`); return; }
    } catch { /* restarting */ }
  }
}

function rebootSheet() {
  openSheet(h("h3", {}, "Reboot the router?"),
    h("p", { style: "margin:0" }, "Internet and Wi-Fi will be down for about 3–5 minutes while the Orbi restarts. Satellites reconnect on their own."),
    h("div", { class: "btns" }, h("button", { class: "btn", onclick: closeSheet }, "Cancel"),
      h("button", { class: "btn danger solid", onclick: (e) => act(e.currentTarget, () => api("/api/router/reboot", { body: { confirm: true } }), "Rebooting — back in a few minutes").then(closeSheet) }, "Reboot now")));
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
      h("button", { class: "btn small", style: "margin-top:8px", onclick: (e) => act(e.currentTarget, async () => {
        await api("/api/filtering/protect", { body: {} });
        const r = await waitJob("protect", "Checking router rules");
        return { note: r && r.added && r.added.length ? `Added: ${r.added.join(", ")}` : "All protection rules were already in place" };
      }) }, "Add rules that block DNS & VPN workarounds"));
  }).catch((e) => fill(card, h("h2", {}, "Content filtering"), h("div", { class: "error-text" }, e.message)));
  return card;
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

  const routerCard = h("section", { class: "card" }, h("h2", {}, "Router"), kv([
    ["Model", r.info && r.info.model], ["Serial", r.info && r.info.serial], ["Firmware", r.info && r.info.firmware], ["Uptime", d.uptime],
    ["Memory used", r.system && r.system.memory != null ? `${r.system.memory}%` : null],
    ["Access Control", r.access_control ? "On (needed for device blocking)" : "Off"]]));
  const wan = h("section", { class: "card" }, h("h2", {}, "Internet (WAN)"), kv([
    ["Connection", (d.wan.type || "").toUpperCase()], ["Public IP", d.wan.ip], ["Gateway", d.wan.gateway], ["Netmask", d.wan.netmask],
    ["DNS", `${d.wan.dns.filter(Boolean).join(", ")} (${d.wan.dns_mode})`], ["ISP's DNS", d.wan.isp_dns.filter(Boolean).join(", ")], ["WAN MAC", d.wan.mac]]));
  const lan = h("section", { class: "card" }, h("h2", {}, "LAN & DHCP"), kv([
    ["Router IP", d.lan.ip], ["Subnet mask", d.lan.netmask], ["DHCP server", d.lan.dhcp_enabled ? `On · hands out ${d.lan.dhcp_start} – ${d.lan.dhcp_end}` : "Off"]]),
    h("div", { class: "group-label" }, `Address reservations · ${d.lan.reservations.length}`),
    table(["IP", "Name", "MAC"], d.lan.reservations.map((x) => [x.ip, x.name, x.mac])),
    h("div", { class: "muted small", style: "margin-top:8px" }, "Recent DHCP activity is in the Router log below (DHCP filter)."));
  const wifi = h("section", { class: "card" }, h("h2", {}, "Wi-Fi"), table(["Band", "Name", "Channel", "Mode", "Security"],
    (d.wifi || []).map((w) => [w.band, w.ssid + (w.enabled ? "" : " (off)"), w.channel, w.mode, w.security])));
  const sats = h("section", { class: "card" }, h("h2", {}, "Satellites"), table(["Name", "IP", "Backhaul", "Signal", "Firmware", "MAC"],
    (r.satellites || []).map((x) => [x.name + (x.online === false ? " (offline)" : ""), x.ip, x.backhaul, x.backhaul === "wired" ? "—" : `${x.signal == null ? "—" : x.signal}%`, x.firmware, x.mac])));

  const vpnAttempts = await api("/api/events?kind=vpn_attempt&limit=20");
  const vpnRules = d.block_services.rules.filter((x) => /vpn/i.test(x.name));
  const vpn = h("section", { class: "card" }, h("h2", {}, "VPN"), kv([
    ["Orbi VPN server", d.vpn.enabled ? `On · ${String(d.vpn.protocol).toUpperCase()} port ${d.vpn.port}` : "Off"],
    ["Who's connected", d.vpn.enabled ? "The Orbi doesn't report active VPN sessions" : "—"],
    ["Kids' VPN apps", vpnRules.length ? `Blocked (${vpnRules.map((x) => `${x.name.replace("Block-VPN-", "")} ${x.port}`).join(", ")})` : "Not blocked"]]),
    h("div", { class: "group-label" }, "Blocked VPN attempts"),
    vpnAttempts.length ? h("div", {}, ...vpnAttempts.map((e) => h("div", { class: "row" }, h("div", { class: "main" },
      h("div", { class: "name" }, e.title), h("div", { class: "meta" }, `${fmtWhen(e.ts)} · ${e.detail}`)))))
      : h("div", { class: "muted small" }, "None so far."));
  const fw = h("section", { class: "card" }, h("h2", {}, `Firewall: Block Services · ${d.block_services.mode}`),
    table(["Rule", "Port", "Applies to"], d.block_services.rules.map((x) => [x.name, x.port, x.ips])));
  const ports = h("section", { class: "card" }, h("h2", {}, "Port forwarding (UPnP)"),
    table(["Device", "Protocol", "Outside", "Inside"], d.upnp.map((x) => [devName(x.ip) ? `${devName(x.ip)} (${x.ip})` : x.ip, x.protocol, x.external_port, x.internal_port])));

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
  setView(head, routerCard, wan, lan, wifi, sats, vpn, fw, ports, logCard);
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
