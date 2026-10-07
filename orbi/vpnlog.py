"""Turns the router log's OpenVPN lines into connection sessions and bursts of failed attempts.

The Orbi logs, with the address the connection came from:
  [OpenVPN, connection successfully] from remote IP address:198.51.100.7 ...
  [OpenVPN, connection drop] from remote IP address:198.51.100.24 ...
  [OpenVPN, connection fail] from reomote IP address:192.168.1.32 ...   (sic)
It does not log who connected (the Orbi's VPN has no user names). A phone on mobile data reconnects every
few minutes, logging a "successfully" each time, so successes from one address with short gaps between
them are one session. Disconnects are only sometimes logged.
"""
import ipaddress
import re

KIND_PREFIX = "OpenVPN, connection"
ADDRESS = re.compile(r"address:\s*(\d{1,3}(?:\.\d{1,3}){3})")
SESSION_GAP = 15 * 60  # successes from the same address closer than this are one session
FAIL_GAP = 30 * 60


def event_of(kind: str, text: str):
    """("connect" | "drop" | "fail", remote address) for an OpenVPN log line, else None."""
    if not kind.startswith(KIND_PREFIX):
        return None
    m = ADDRESS.search(text or "")
    what = kind[len(KIND_PREFIX):].strip(" ,").lower()
    action = "connect" if what.startswith("success") else "drop" if what.startswith("drop") else "fail" if what.startswith("fail") else None
    return (action, m.group(1)) if action and m else None


HOME_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_inside(ip: str) -> bool:
    """A connection attempt from a home (LAN) address, e.g. a phone trying the VPN while on Wi-Fi.
    Only the RFC 1918 ranges count: ipaddress's is_private also covers documentation and carrier ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in HOME_NETWORKS)


def summarize(rows) -> dict:
    """rows: router_log dicts (ts, kind, text) in any order. Returns sessions and failure bursts, newest first."""
    sessions, failures = [], []
    open_session, open_fail = {}, {}
    for r in sorted(rows, key=lambda r: r["ts"]):
        ev = event_of(r["kind"], r["text"])
        if not ev:
            continue
        action, ip = ev
        ts = r["ts"]
        if action == "connect":
            s = open_session.get(ip)
            if s and s["end"] is None and ts - s["last"] <= SESSION_GAP:
                s["last"], s["reconnects"] = ts, s["reconnects"] + 1
            else:
                s = {"ip": ip, "start": ts, "last": ts, "end": None, "reconnects": 0, "inside": is_inside(ip)}
                sessions.append(s)
                open_session[ip] = s
        elif action == "drop":
            s = open_session.get(ip)
            if s and s["end"] is None:
                s["end"] = ts
            else:  # a drop whose connection is older than the log
                sessions.append({"ip": ip, "start": None, "last": ts, "end": ts, "reconnects": 0, "inside": is_inside(ip)})
        else:
            f = open_fail.get(ip)
            if f and ts - f["last"] <= FAIL_GAP:
                f["last"], f["count"] = ts, f["count"] + 1
            else:
                f = {"ip": ip, "first": ts, "last": ts, "count": 1, "inside": is_inside(ip)}
                failures.append(f)
                open_fail[ip] = f
    sessions.sort(key=lambda s: s["last"], reverse=True)
    failures.sort(key=lambda f: f["last"], reverse=True)
    return {"sessions": sessions, "failures": failures}
