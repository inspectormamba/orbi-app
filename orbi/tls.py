"""HTTPS for the phone link: one self-signed certificate, made once on this PC, that names this PC's LAN addresses.

Only used when "phone_https" is on (the default is plain HTTP). The phone trusts the certificate once; its file is
downloaded from the PC's own app, never over the network. A new certificate is only made when the PC's LAN
address isn't in the current one, so the trust usually lasts.

Certificates are made with the openssl program: the one on PATH (on macOS that's LibreSSL, on Windows it can be
Git's copy at C:\\Program Files\\Git\\usr\\bin). RSA keys and a config file keep the same commands working on both.
"""
import os
import shutil
import subprocess
from pathlib import Path

from . import config

KEY_BITS = 2048
VALID_DAYS = 3650
EXTENSIONS = """[req]
distinguished_name = dn
x509_extensions = v3
prompt = no

[dn]
CN = Orbi Control

[v3]
subjectAltName = {sans}
# CA:TRUE on purpose: phones only accept a self-signed certificate they've been told to trust as a root.
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth
"""
GIT_OPENSSL = (
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
)


def _openssl() -> str:
    found = shutil.which("openssl")
    if found:
        return found
    for p in GIT_OPENSSL:
        if os.path.exists(p):
            return p
    raise RuntimeError("openssl isn't installed, so Orbi Control can't make its HTTPS certificate")


def paths() -> tuple[Path, Path]:
    d = config.DATA_DIR / "tls"
    return d / "cert.pem", d / "key.pem"


def ensure(lan_ips: list[str]) -> tuple[Path, Path]:
    """The (certificate, key) files, made now if missing or if a LAN address isn't named in the current one."""
    cert, key = paths()
    wanted = sorted({"127.0.0.1", *(ip for ip in lan_ips if ip)})
    named_file = cert.with_suffix(".ips")
    named = named_file.read_text().split() if named_file.exists() else []
    if cert.exists() and key.exists() and all(ip in named for ip in wanted):
        return cert, key
    cert.parent.mkdir(parents=True, exist_ok=True)
    sans = ",".join(["DNS:localhost"] + [f"IP:{ip}" for ip in wanted])
    conf = cert.parent / "openssl.cnf"
    conf.write_text(EXTENSIONS.format(sans=sans), encoding="ascii")
    subprocess.run([
        _openssl(), "req", "-x509", "-new", "-newkey", f"rsa:{KEY_BITS}", "-nodes", "-sha256",
        "-days", str(VALID_DAYS), "-config", str(conf),
        "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True, timeout=120)
    named_file.write_text(" ".join(wanted))
    return cert, key


def fingerprint(cert: Path) -> str:
    """SHA-256 fingerprint, shown in the app so the phone's copy can be checked against it."""
    out = subprocess.run([_openssl(), "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True, check=True, timeout=30).stdout
    return out.split("=", 1)[1].strip() if "=" in out else out.strip()
