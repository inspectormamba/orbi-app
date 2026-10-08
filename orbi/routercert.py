"""Pins the router's HTTPS certificate, so the admin password only ever goes to the real router.

The Orbi's admin pages use a self-signed certificate that can't be verified the normal way. Instead,
the first time the app talks to a router address it remembers the SHA-256 fingerprint of the
certificate it sees ("trust on first use"). Every later connection that carries the password, from
the SOAP API, the router-log reader and the headless Firefox alike, must present exactly that
certificate. A device on the LAN impersonating the router is refused before any password is sent.

A firmware update or factory reset can give the router a new certificate. The app then stops talking
to it and raises an alert until someone chooses "Trust the router's new certificate" (More → Router).

The Orbi also makes itself a new self-signed certificate every time it restarts. When the restart came
from this app, a certificate that looks like the router's own (Netgear's routerlogin.net certificate), was
created after the restart was asked for, and comes from the router's hardware address as it was before
the restart, is trusted without asking; see renewed_since() and Monitor._trust_after_reboot().
"""
import datetime
import hashlib
import logging
import socket
import ssl

from . import config

log = logging.getLogger("orbi.routercert")
OID_SHA256 = "OID.2.16.840.1.101.3.4.2.1"


class CertificateChanged(Exception):
    def __init__(self, host: str):
        super().__init__(f"The router's security certificate changed, so Orbi Control stopped sending it the admin password. "
                         f"If you just updated or reset the router, choose \"Trust the router's new certificate\" under More → Router.")
        self.host = host


def presented_der(host: str, port: int = 443, timeout: float = 10) -> bytes:
    """The certificate `host` presents right now (DER). Nothing is sent but the TLS handshake."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw) as tls:
        return tls.getpeercert(binary_form=True)


def presented(host: str, port: int = 443, timeout: float = 10) -> str:
    """SHA-256 (hex) of the certificate `host` presents right now."""
    return hashlib.sha256(presented_der(host, port, timeout)).hexdigest()


# ---- just enough DER to read a certificate's names and start date (no extra dependency) ----
NAME_OIDS = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O", b"\x55\x04\x0b": "OU"}


def _children(b: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(b):
        tag, n = b[i], b[i + 1]
        i += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[i:i + k], "big")
            i += k
        if i + n > len(b):
            raise ValueError("truncated DER")
        out.append((tag, b[i:i + n]))
        i += n
    return out


def _name(der: bytes) -> dict:
    out = {}
    for _, rdn in _children(der):
        for _, atv in _children(rdn):
            (_, oid), (_, value) = _children(atv)[:2]
            if oid in NAME_OIDS:
                out[NAME_OIDS[oid]] = value.decode("utf-8", "replace")
    return out


def _time(tag: int, value: bytes) -> float:
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"  # UTCTime or GeneralizedTime
    return datetime.datetime.strptime(value.decode("ascii"), fmt).replace(tzinfo=datetime.timezone.utc).timestamp()


def describe(der: bytes) -> dict:
    """Issuer and subject names (CN/O/OU) and the not-before time of a DER certificate."""
    tbs = _children(_children(_children(der)[0][1])[0][1])
    if tbs[0][0] == 0xA0:  # explicit version
        tbs = tbs[1:]
    _serial, _alg, issuer, validity, subject = tbs[:5]
    (t1, v1), _ = _children(validity[1])[:2]
    return {"issuer": _name(issuer[1]), "subject": _name(subject[1]), "not_before": _time(t1, v1)}


def looks_like_router_cert(info: dict) -> bool:
    """The self-signed certificate Netgear routers make for themselves."""
    return (info["subject"].get("CN") == "routerlogin.net" and info["issuer"].get("CN") == "routerlogin.net"
            and info["subject"].get("O") == "NetgearFieldDevices")


def renewed_since(host: str, since: float, now: float | None = None) -> str | None:
    """The fingerprint of the certificate `host` presents if it is a Netgear router certificate created after
    `since` (when this app asked the router to restart), else None. The router's clock can be a little off."""
    import time
    now = time.time() if now is None else now
    der = presented_der(host)
    try:
        info = describe(der)
    except Exception:  # whatever answered sent something we can't read: not the router's certificate
        return None
    if looks_like_router_cert(info) and since - 120 <= info["not_before"] <= now + 120:
        return hashlib.sha256(der).hexdigest()
    return None


def pinned(host: str) -> str:
    """The fingerprint to require from `host`: the saved one, or on first use the one it presents now."""
    pins = config.load().get("router_cert_pins") or {}
    if host not in pins:
        pins = {**pins, host: presented(host)}
        config.save({"router_cert_pins": pins})
        log.info("trusting %s's certificate on first use: %s", host, pins[host])
    return pins[host]


def gateway_mac(host: str) -> str | None:
    """The hardware address this PC's ARP table has for `host` (e.g. C8:9E:43:00:00:01), or None.
    Something impersonating the router on the LAN normally shows up here with its own address."""
    import re
    import subprocess
    try:
        out = subprocess.run(["arp", "-a", host], capture_output=True, text=True, timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == host and re.fullmatch(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", parts[1]):
            return parts[1].replace("-", ":").upper()
    return None


def trust_current(host: str) -> str:
    """Replaces the pin with whatever the router presents now (after the user confirms a new certificate)."""
    return trust(host, presented(host))


def trust(host: str, fp: str) -> str:
    """Replaces the pin with `fp`."""
    config.save({"router_cert_pins": {**(config.load().get("router_cert_pins") or {}), host: fp}})
    log.warning("now trusting a new certificate for %s: %s", host, fp)
    return fp


def check(host: str):
    """Raises CertificateChanged unless `host` presents the pinned certificate."""
    if presented(host) != pinned(host):
        raise CertificateChanged(host)


def is_mismatch(exc: BaseException) -> bool:
    """Whether an error from requests/urllib3 is a pinned-fingerprint mismatch."""
    while exc is not None:
        if isinstance(exc, CertificateChanged) or "Fingerprints did not match" in str(exc):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def session(host: str):
    """A requests.Session whose HTTPS connections to `host` must present the pinned certificate."""
    import requests
    from requests.adapters import HTTPAdapter

    fp = pinned(host)

    class Pinned(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["assert_fingerprint"] = fp  # checked on every new TLS connection
            super().init_poolmanager(*args, **kwargs)

    s = requests.Session()
    s.verify = False  # self-signed: the fingerprint check replaces normal verification
    s.mount(f"https://{host}", Pinned())
    return s


def firefox_override(host: str) -> str:
    """cert_override.txt for a Firefox profile that trusts exactly the pinned certificate (and no other)."""
    h = pinned(host).upper()
    colons = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    return ("# PSM Certificate Override Settings file\n# This is a generated file!  Do not edit.\n"
            f"{host}:443:\t{OID_SHA256}\t{colons}\t\n")
