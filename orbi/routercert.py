"""Pins the router's HTTPS certificate, so the admin password only ever goes to the real router.

The Orbi's admin pages use a self-signed certificate that can't be verified the normal way. Instead,
the first time the app talks to a router address it remembers the SHA-256 fingerprint of the
certificate it sees ("trust on first use"). Every later connection that carries the password, from
the SOAP API, the router-log reader and the headless Firefox alike, must present exactly that
certificate. A device on the LAN impersonating the router is refused before any password is sent.

A firmware update or factory reset can give the router a new certificate. The app then stops talking
to it and raises an alert until someone chooses "Trust the router's new certificate" (More → Router).
"""
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


def presented(host: str, port: int = 443, timeout: float = 10) -> str:
    """SHA-256 (hex) of the certificate `host` presents right now. Nothing is sent but the TLS handshake."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw) as tls:
        return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def pinned(host: str) -> str:
    """The fingerprint to require from `host`: the saved one, or on first use the one it presents now."""
    pins = config.load().get("router_cert_pins") or {}
    if host not in pins:
        pins = {**pins, host: presented(host)}
        config.save({"router_cert_pins": pins})
        log.info("trusting %s's certificate on first use: %s", host, pins[host])
    return pins[host]


def trust_current(host: str) -> str:
    """Replaces the pin with whatever the router presents now (after the user confirms a new certificate)."""
    fp = presented(host)
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
