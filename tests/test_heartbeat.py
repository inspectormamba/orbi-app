import pytest
from fastapi.testclient import TestClient

from orbi import config, heartbeat, push
from orbi.web import create_app

URL = "https://hc-ping.com/1f2e3d4c-5b6a-7980-a1b2-c3d4e5f60718"


@pytest.fixture
def client(monitor, monkeypatch):
    pings, alerts = [], []
    monkeypatch.setattr(heartbeat, "ping", lambda address=None, suffix="": pings.append((address or heartbeat.url(), suffix))
                        or {"ok": (address or "").endswith("8") or bool(suffix) or address is None, "detail": "checked in (200)"})
    monkeypatch.setattr(push, "send", lambda title, msg, priority=4: alerts.append(title))
    monkeypatch.setattr(push, "send_now", lambda title, msg, priority=4, settings=None: alerts.append(title) or {"ok": True})
    c = TestClient(create_app(monitor))
    assert c.post("/api/setup", json={"pin": "246810"}).status_code == 200
    c.pings, c.alerts = pings, alerts
    return c


def test_check_url():
    assert heartbeat.check_url(f"  {URL} ") == URL
    assert heartbeat.check_url("https://hc-ping.com/abcdEFGH1234/orbi-pc") == "https://hc-ping.com/abcdEFGH1234/orbi-pc"
    for bad in ("http://hc-ping.com/1f2e3d4c5b6a", "https://hc-ping.com/", "hc-ping.com/1f2e3d4c5b6a", "https://x.com/a b c d e f g h",
                "https://hc-ping.com/1f2e3d4c?x=1"):
        with pytest.raises(ValueError):
            heartbeat.check_url(bad)


def test_set_up_change_and_remove(client):
    assert client.get("/api/heartbeat").json()["configured"] is False
    assert client.put("/api/heartbeat", json={"url": "nope"}).status_code == 400
    r = client.put("/api/heartbeat", json={"url": URL[:-1] + "9"})  # the test check-in fails: not saved
    assert r.status_code == 400 and "didn't work" in r.json()["detail"] and not heartbeat.configured()
    r = client.put("/api/heartbeat", json={"url": URL})
    assert r.status_code == 200 and r.json()["configured"] and r.json()["last"]["ok"]
    assert heartbeat.url() == URL and URL not in str(config.load())  # stored encrypted
    assert client.alerts == []
    assert client.put("/api/heartbeat", json={"url": URL}).status_code == 200
    assert client.alerts == ["Outside check-in address changed"]
    r = client.delete("/api/heartbeat")
    assert r.json()["configured"] is False and client.alerts[-1] == "Outside check-in turned off"
    assert (URL, "/fail") in client.pings  # the service raises its alarm right away
    titles = [e["title"] for e in client.get("/api/events?kind=action").json()]
    assert {"Outside check-in set up", "Outside check-in address changed", "Outside check-in turned off"} <= set(titles)


def test_beat_records_the_result(client):
    heartbeat.beat()
    assert config.load().get("heartbeat_last") is None  # not set up: nothing sent
    client.put("/api/heartbeat", json={"url": URL})
    config.save({"heartbeat_last": None})
    heartbeat.beat()
    assert config.load()["heartbeat_last"]["ok"]
