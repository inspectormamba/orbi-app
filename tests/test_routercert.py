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


# ---------- the Orbi makes a new certificate each time it restarts ----------
def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    size = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + size + body


def _name(**attrs) -> bytes:
    oids = {"CN": b"\x55\x04\x03", "O": b"\x55\x04\x0a"}
    return _tlv(0x30, b"".join(_tlv(0x31, _tlv(0x30, _tlv(0x06, oids[k]) + _tlv(0x0C, v.encode()))) for k, v in attrs.items()))


def fake_cert(not_before: str, subject=None, issuer=None) -> bytes:
    """A minimal DER certificate; not_before is a UTCTime like '261008204735Z'."""
    alg = _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b") + b"\x05\x00")
    tbs = _tlv(0x30, _tlv(0xA0, _tlv(0x02, b"\x02")) + _tlv(0x02, b"\x01") + alg
               + (issuer or _name(CN="routerlogin.net"))
               + _tlv(0x30, _tlv(0x17, not_before.encode()) + _tlv(0x17, b"361005204735Z"))
               + (subject or _name(O="NetgearFieldDevices", CN="routerlogin.net")) + _tlv(0x30, b""))
    return _tlv(0x30, tbs + alg + _tlv(0x03, b"\x00" + b"s" * 200))


RESTART = 1791492336.0  # 2026-10-08 20:45:36 UTC
FRESH = fake_cert("261008204735Z")  # made two minutes after the restart


def test_reads_a_certificate():
    info = routercert.describe(FRESH)
    assert info == {"issuer": {"CN": "routerlogin.net"}, "subject": {"O": "NetgearFieldDevices", "CN": "routerlogin.net"},
                    "not_before": RESTART + 119}
    assert routercert.looks_like_router_cert(info)


def test_renewed_since_only_accepts_a_fresh_netgear_certificate(monkeypatch):
    der = {"v": FRESH}
    monkeypatch.setattr(routercert, "presented_der", lambda host, port=443, timeout=10: der["v"])
    now = RESTART + 300
    assert routercert.renewed_since("192.168.1.1", RESTART, now) == hashlib.sha256(FRESH).hexdigest()
    assert routercert.renewed_since("192.168.1.1", RESTART + 3600, now) is None  # made before the restart
    der["v"] = fake_cert("261008204735Z", subject=_name(CN="routerlogin.net"))  # not Netgear's own
    assert routercert.renewed_since("192.168.1.1", RESTART, now) is None
    der["v"] = fake_cert("261008204735Z", issuer=_name(CN="Evil CA"))
    assert routercert.renewed_since("192.168.1.1", RESTART, now) is None
    der["v"] = fake_cert("361008204735Z")  # dated in the future
    assert routercert.renewed_since("192.168.1.1", RESTART, now) is None
    der["v"] = b"\x30\x05junk"
    assert routercert.renewed_since("192.168.1.1", RESTART, now) is None


@pytest.fixture
def restarted_router(monitor, monkeypatch):
    monkeypatch.setattr(routercert, "presented_der", lambda host, port=443, timeout=10: FRESH)
    monkeypatch.setattr(routercert, "presented", lambda host, port=443, timeout=10: hashlib.sha256(FRESH).hexdigest())
    monkeypatch.setattr("time.time", lambda: RESTART + 300)
    config.save({"router_cert_pins": {"192.168.1.1": A}})
    return monitor


def test_new_certificate_after_an_app_restart_is_trusted(restarted_router, monkeypatch):
    monitor = restarted_router
    monitor.note_reboot("C8:9E:43:00:00:01")
    monitor.store.put("reboot_requested", RESTART)
    monkeypatch.setattr(routercert, "gateway_mac", lambda host: "C8:9E:43:00:00:01")
    monitor._cert_alert(str(routercert.CertificateChanged("192.168.1.1")))
    assert config.load()["router_cert_pins"]["192.168.1.1"] == hashlib.sha256(FRESH).hexdigest()
    assert monitor.notes == []  # no alarm
    ev = monitor.store.one("SELECT severity, title FROM events WHERE kind='router_cert'")
    assert ev["severity"] == "info" and "Trusted" in ev["title"]
    assert not monitor.store.get("reboot_requested")  # one certificate per restart


def test_new_certificate_without_an_app_restart_still_alerts(restarted_router):
    monitor = restarted_router
    monitor._cert_alert(str(routercert.CertificateChanged("192.168.1.1")))
    assert config.load()["router_cert_pins"]["192.168.1.1"] == A
    assert [n[0] for n in monitor.notes] == ["Router certificate changed"]


def test_restart_too_long_ago_still_alerts(restarted_router):
    monitor = restarted_router
    monitor.store.put("reboot_requested", RESTART - 3600)
    monitor._cert_alert(str(routercert.CertificateChanged("192.168.1.1")))
    assert config.load()["router_cert_pins"]["192.168.1.1"] == A
    assert [n[0] for n in monitor.notes] == ["Router certificate changed"]


def test_reboot_endpoint_remembers_the_restart(client, monitor):
    client.post("/api/setup", json={"pin": "246810"})
    assert client.post("/api/router/reboot", json={"confirm": True}).status_code == 200
    assert monitor.store.get("reboot_requested")


def test_new_certificate_from_different_hardware_still_alerts(restarted_router, monkeypatch):
    """Someone impersonating the router during the restart (ARP spoofing) shows up with their own hardware address."""
    monitor = restarted_router
    monitor.note_reboot("C8:9E:43:00:00:01")
    monitor.store.put("reboot_requested", RESTART)
    monkeypatch.setattr(routercert, "gateway_mac", lambda host: "02:11:22:33:44:55")
    monitor._cert_alert(str(routercert.CertificateChanged("192.168.1.1")))
    assert config.load()["router_cert_pins"]["192.168.1.1"] == A
    assert [n[0] for n in monitor.notes] == ["Router certificate changed"]
    monkeypatch.setattr(routercert, "gateway_mac", lambda host: None)  # couldn't tell: don't guess
    monitor.store.put("cert_alerted", None)
    monitor._cert_alert(str(routercert.CertificateChanged("192.168.1.1")))
    assert config.load()["router_cert_pins"]["192.168.1.1"] == A


def test_unreadable_certificate_is_never_trusted(monkeypatch):
    for junk in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x03\x30\x01\x00", FRESH[:-50], b"\xff" * 64):
        monkeypatch.setattr(routercert, "presented_der", lambda host, port=443, timeout=10, j=junk: j)
        assert routercert.renewed_since("192.168.1.1", RESTART, RESTART + 300) is None


def test_gateway_mac_reads_the_arp_table(monkeypatch):
    import subprocess

    class Done:
        stdout = ("\nInterface: 192.168.1.58 --- 0x7\n  Internet Address      Physical Address      Type\n"
                  "  192.168.1.1           c8-9e-43-00-00-01     dynamic\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Done)
    assert routercert.gateway_mac("192.168.1.1") == "C8:9E:43:00:00:01"
    assert routercert.gateway_mac("192.168.1.2") is None


ROUTER = "C8:9E:43:00:00:01"
OLD = fake_cert("261001000000Z")


@pytest.fixture
def saving(tmp_config, monkeypatch):
    """The router right after its Internet settings were saved: `seq` is what it presents on each look."""
    clock, seq = [RESTART], []
    monkeypatch.setattr("time.time", lambda: clock[0])
    monkeypatch.setattr("time.sleep", lambda s: clock.__setitem__(0, clock[0] + s))

    def presented_der(host, port=443, timeout=10):
        der = seq.pop(0) if len(seq) > 1 else seq[0]
        if der is None:
            raise ConnectionRefusedError
        return der
    monkeypatch.setattr(routercert, "presented_der", presented_der)
    monkeypatch.setattr(routercert, "gateway_mac", lambda host: ROUTER)
    config.save({"router_cert_pins": {"192.168.1.1": hashlib.sha256(OLD).hexdigest()}})
    return seq


def test_new_certificate_after_a_settings_save_is_followed(saving):
    """A filter change: the old certificate, a few seconds of nothing while it restarts its web server, then its new one."""
    saving += [OLD, OLD, None, None, FRESH]
    fp = routercert.follow_renewal("192.168.1.1", RESTART, ROUTER)
    assert fp == hashlib.sha256(FRESH).hexdigest() == routercert.pinned("192.168.1.1")


def test_no_new_certificate_after_a_save(saving):
    saving.append(OLD)
    assert routercert.follow_renewal("192.168.1.1", RESTART, ROUTER) is None
    assert routercert.pinned("192.168.1.1") == hashlib.sha256(OLD).hexdigest()


@pytest.mark.parametrize("case", ["other hardware", "not Netgear's", "made before the save", "never came back"])
def test_suspicious_certificate_after_a_save_is_refused(saving, monkeypatch, case):
    der = FRESH
    if case == "other hardware":
        monkeypatch.setattr(routercert, "gateway_mac", lambda host: "02:11:22:33:44:55")
    elif case == "not Netgear's":
        der = fake_cert("261008204735Z", issuer=_name(CN="Evil CA"))
    elif case == "made before the save":
        der = fake_cert("261008100000Z")
    else:
        der = None
    saving += [OLD, der]
    with pytest.raises(routercert.CertificateChanged):
        routercert.follow_renewal("192.168.1.1", RESTART, ROUTER)
    assert routercert.pinned("192.168.1.1") == hashlib.sha256(OLD).hexdigest()


def test_filter_change_records_the_renewed_certificate(client, monitor, monkeypatch):
    """The filter change trusts the new certificate itself; History says so once, and nothing is left expected."""
    from orbi import filtering
    from .test_advanced import wait_job
    client.post("/api/setup", json={"pin": "246810"})
    config.save({"router_cert_pins": {"192.168.1.1": A}})
    monkeypatch.setattr(routercert, "gateway_mac", lambda host: ROUTER)
    seen = {}

    def apply_provider(host, pw, key):
        seen["expected"] = monitor.store.get("reboot_requested")
        routercert.trust(host, B)  # what follow_renewal does inside the router session
        return {"ok": True, "confirmed": True, "provider": key}
    monkeypatch.setattr(filtering, "apply_provider", apply_provider)
    assert client.post("/api/filtering", json={"provider": "adguard_family"}).status_code == 200
    assert wait_job(client, "filtering")["error"] is None
    assert seen["expected"] and not monitor.store.get("reboot_requested")
    ev = monitor.store.q("SELECT detail FROM events WHERE kind='router_cert'")
    assert len(ev) == 1 and "changed the content filter" in ev[0]["detail"]
    assert monitor.notes == []
