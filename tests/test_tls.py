"""HTTPS for the phone link: the certificate, secure cookies, and who may download the certificate."""
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from orbi import config, tls
from orbi.web import create_app

_OPENSSL_HERE = bool(shutil.which("openssl") or os.path.exists(r"C:\Program Files\Git\usr\bin\openssl.exe"))
needs_openssl = pytest.mark.skipif(not _OPENSSL_HERE, reason="openssl isn't installed")


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    return tmp_path


@needs_openssl
def test_certificate_names_the_lan_address_and_is_kept_until_it_changes(data_dir):
    cert, key = tls.ensure(["192.168.1.58"])
    assert cert.exists() and key.exists()
    text = subprocess.run([tls._openssl(), "x509", "-in", str(cert), "-noout", "-text"], capture_output=True, text=True).stdout
    assert "IP Address:192.168.1.58" in text and "IP Address:127.0.0.1" in text and "DNS:localhost" in text
    assert "CA:TRUE" in text and "TLS Web Server Authentication" in text

    before = cert.read_bytes()
    tls.ensure(["192.168.1.58"])
    assert cert.read_bytes() == before, "an unchanged address keeps the certificate (and the phone's trust)"

    tls.ensure(["192.168.1.99"])  # the PC got a new address: a new certificate is needed
    assert cert.read_bytes() != before


@needs_openssl
def test_fingerprint_is_sha256_colon_hex(data_dir):
    cert, _ = tls.ensure(["192.168.1.58"])
    fp = tls.fingerprint(cert)
    parts = fp.split(":")
    assert len(parts) == 32 and all(len(p) == 2 for p in parts)


@pytest.fixture
def app(monitor, data_dir, monkeypatch):
    monitor.scan()
    app = create_app(monitor)
    return app


def test_sign_in_cookie_is_secure_only_over_https(app):
    phone = TestClient(app, base_url="https://testserver", client=("192.168.1.32", 50000))
    assert phone.post("/api/setup", json={"pin": "246810"}).status_code == 200
    cookie_header = phone.post("/api/login", json={"pin": "246810"}).headers["set-cookie"]
    assert "secure" in cookie_header.lower()

    local = TestClient(app, base_url="http://localhost:8471", client=("127.0.0.1", 50000))
    cookie_header = local.post("/api/login", json={"pin": "246810"}).headers["set-cookie"]
    assert "secure" not in cookie_header.lower(), "the PC's plain-HTTP loopback port must still get a usable cookie"


@needs_openssl
def test_certificate_download_is_refused_from_the_network(app, data_dir):
    tls.ensure(["192.168.1.58"])
    phone = TestClient(app, base_url="https://testserver", client=("192.168.1.32", 50000))
    assert phone.get("/api/tls/cert").status_code == 403

    local = TestClient(app, base_url="http://localhost:8471", client=("127.0.0.1", 50000))
    r = local.get("/api/tls/cert")
    assert r.status_code == 200
    assert b"BEGIN CERTIFICATE" in r.content


def test_phone_link_is_plain_http_by_default_and_https_is_an_option(app, data_dir):
    parent = TestClient(app, base_url="http://localhost:8471", client=("127.0.0.1", 50000))
    parent.post("/api/setup", json={"pin": "246810"})
    assert parent.get("/api/settings").json()["phone_https"] is False
    acc = parent.get("/api/access").json()
    assert acc["https"] is False and acc["certificate"] is None
    assert all(u.startswith("http://") for u in acc["urls"])

    assert parent.patch("/api/settings", json={"phone_https": True}).status_code == 200
    assert config.load()["phone_https"] is True
    acc = parent.get("/api/access").json()
    assert acc["https"] is True and acc["certificate"] is not None
    assert all(u.startswith("https://") for u in acc["urls"])
    events = [e["title"] for e in parent.get("/api/events?limit=50").json()]
    assert "Phone connection set to HTTPS" in events
