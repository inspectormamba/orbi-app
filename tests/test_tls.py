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


def test_activity_records_failed_and_successful_sign_ins_and_changes(app, data_dir):
    phone = TestClient(app, base_url="http://localhost:8471", client=("192.168.1.32", 50000))
    phone.post("/api/setup", json={"pin": "246810"})
    assert phone.post("/api/login", json={"pin": "000000"}).status_code == 401
    assert phone.post("/api/login", json={"pin": "246810"}).status_code == 200
    assert phone.patch("/api/settings", json={"check_updates": True}).status_code == 200
    rows = phone.get("/api/audit").json()
    got = [(r["method"], r["path"], r["status"]) for r in rows]
    assert ("POST", "/api/login", 401) in got and ("POST", "/api/login", 200) in got
    assert ("PATCH", "/api/settings", 200) in got
    assert all(r["device"] for r in rows)
    assert all("000000" not in str(r) and "246810" not in str(r) for r in rows), "PINs are never stored in the activity"


def test_login_allowlist_refuses_other_addresses_and_cannot_lock_out_the_saver(app, data_dir):
    parent = TestClient(app, base_url="http://localhost:8471", client=("127.0.0.1", 50000))
    parent.post("/api/setup", json={"pin": "246810"})
    other = TestClient(app, base_url="http://192.168.1.99:8470", client=("192.168.1.99", 50000))
    phone = TestClient(app, base_url="http://192.168.1.32:8470", client=("192.168.1.32", 50000))

    # empty list: anyone on the network may use the app
    assert other.get("/api/session").status_code == 200

    assert parent.patch("/api/settings", json={"allowed_login_ips": ["192.168.1.32", "192.168.1.123"]}).status_code == 200
    assert config.load()["allowed_login_ips"] == ["192.168.1.32/32", "192.168.1.123/32"]
    assert other.get("/api/session").status_code == 403
    assert other.post("/api/login", json={"pin": "246810"}).status_code == 403
    assert phone.get("/api/session").status_code == 200
    assert parent.get("/api/session").status_code == 200, "this PC is always allowed"

    # a range works too
    assert parent.patch("/api/settings", json={"allowed_login_ips": ["192.168.1.0/24"]}).status_code == 200
    assert other.get("/api/session").status_code == 200

    # a start-end range is stored as the CIDR blocks covering exactly that span
    assert parent.patch("/api/settings", json={"allowed_login_ips": ["192.168.1.96-192.168.1.103"]}).status_code == 200
    assert config.load()["allowed_login_ips"] == ["192.168.1.96/29"]
    assert other.get("/api/session").status_code == 200  # .99 is inside
    assert phone.get("/api/session").status_code == 403  # .32 is not
    assert parent.patch("/api/settings", json={"allowed_login_ips": ["192.168.1.20-192.168.1.10"]}).status_code == 400
    assert parent.patch("/api/settings", json={"allowed_login_ips": ["192.168.1.0/24"]}).status_code == 200

    # saving a list that leaves out the device saving it is refused
    assert phone.post("/api/login", json={"pin": "246810"}).status_code == 200
    assert phone.patch("/api/settings", json={"allowed_login_ips": ["192.168.1.123"]}).status_code == 400
    assert parent.patch("/api/settings", json={"allowed_login_ips": ["not an address"]}).status_code == 400
    assert config.load()["allowed_login_ips"] == ["192.168.1.0/24"]
