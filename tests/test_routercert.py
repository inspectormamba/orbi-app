import hashlib
import io
import zipfile

import pytest

from orbi import config, geckodriver, routercert

from .test_api import client  # noqa: F401  (fixture)

A = "67" * 32
B = "ab" * 32


@pytest.fixture
def router_cert(tmp_config, monkeypatch):
    seen = {"fp": A}
    monkeypatch.setattr(routercert, "presented", lambda host, port=443, timeout=10: seen["fp"])
    return seen


def test_trusted_on_first_use_then_pinned(router_cert):
    routercert.check("192.168.1.1")  # first connection: remembered
    assert config.load()["router_cert_pins"] == {"192.168.1.1": A}
    routercert.check("192.168.1.1")
    router_cert["fp"] = B  # an impostor, or a router with a new certificate
    with pytest.raises(routercert.CertificateChanged):
        routercert.check("192.168.1.1")
    assert routercert.pinned("192.168.1.1") == A  # never silently replaced
    routercert.trust_current("192.168.1.1")  # the user confirmed it
    routercert.check("192.168.1.1")


def test_each_router_address_has_its_own_pin(router_cert):
    routercert.check("192.168.1.1")
    router_cert["fp"] = B
    routercert.check("10.0.0.1")
    assert config.load()["router_cert_pins"] == {"192.168.1.1": A, "10.0.0.1": B}


def test_firefox_override_trusts_only_the_pin(router_cert):
    text = routercert.firefox_override("192.168.1.1")
    line = text.splitlines()[-1]
    assert line == "192.168.1.1:443:\tOID.2.16.840.1.101.3.4.2.1\t" + ":".join(["67"] * 32) + "\t"


def test_session_requires_the_pinned_fingerprint(router_cert):
    s = routercert.session("192.168.1.1")
    adapter = s.get_adapter("https://192.168.1.1/soap/server_sa/")
    assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == A
    assert s.verify is False  # replaced by the fingerprint check, not skipped


def test_mismatch_detection():
    try:
        try:
            raise ValueError('Fingerprints did not match. Expected "aa", got "bb"')
        except ValueError as inner:
            raise RuntimeError("SSLError") from inner
    except RuntimeError as e:
        assert routercert.is_mismatch(e)
    assert not routercert.is_mismatch(RuntimeError("timed out"))


def test_certificate_change_alerts_once(monitor, monkeypatch):
    monkeypatch.setattr(routercert, "presented", lambda host, port=443, timeout=10: B)
    msg = str(routercert.CertificateChanged("192.168.1.1"))
    monitor._cert_alert(msg)
    monitor._cert_alert(msg)
    monitor._cert_alert("router offline")
    assert [n[0] for n in monitor.notes] == ["Router certificate changed"]
    assert monitor.store.one("SELECT severity FROM events WHERE kind='router_cert'")["severity"] == "error"


def test_router_cert_api(client, router_cert):
    client.post("/api/setup", json={"pin": "246810"})
    routercert.check("192.168.1.1")
    assert client.get("/api/settings/router-cert").json()["changed"] is False
    router_cert["fp"] = B
    assert client.get("/api/settings/router-cert").json()["changed"] is True
    assert client.post("/api/settings/router-cert/trust", json={}).status_code == 200
    assert client.get("/api/settings/router-cert").json()["changed"] is False
    assert any(e["title"] == "Trusted the router's new security certificate" for e in client.get("/api/events?kind=action").json())


def _zip(exe: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("geckodriver.exe", exe)
    return buf.getvalue()


@pytest.mark.parametrize("tamper", [None, "zip", "exe"])
def test_geckodriver_is_hash_checked(tmp_config, monkeypatch, tamper):
    exe = b"MZ pretend geckodriver"
    good_zip = _zip(exe)
    monkeypatch.setattr(geckodriver, "ZIP_SHA256", hashlib.sha256(good_zip).hexdigest())
    monkeypatch.setattr(geckodriver, "EXE_SHA256", hashlib.sha256(exe).hexdigest())
    served = {None: good_zip, "zip": good_zip + b"x", "exe": _zip(exe + b"x")}[tamper]
    if tamper == "exe":  # a zip that matches its pin but carries a different program
        monkeypatch.setattr(geckodriver, "ZIP_SHA256", hashlib.sha256(served).hexdigest())

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(geckodriver.urllib.request, "urlopen", lambda req, timeout=60: Resp(served))
    if tamper:
        with pytest.raises(geckodriver.GeckodriverError):
            geckodriver.path()
        assert not (tmp_config / "geckodriver" / geckodriver.VERSION / "geckodriver.exe").exists()
    else:
        p = geckodriver.path()
        assert p.read_bytes() == exe
        p.write_bytes(b"swapped later")  # a changed file on disk is replaced, never run
        monkeypatch.setattr(geckodriver.urllib.request, "urlopen", lambda req, timeout=60: Resp(good_zip))
        assert geckodriver.path().read_bytes() == exe
