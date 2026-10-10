"""What the router knows about each device that Netgear's app doesn't show, and what Orbi Control does with it."""
import time

from orbi import identity, router

from .conftest import ROUTER_MAC, SAT_MAC


def test_a_renamed_laptop_is_caught():
    assert "made by Apple" in identity.mismatch("Echo-Dot", "Apple", "LAPTOP")
    assert "laptop" in identity.mismatch("Echo-Spot", "", "LAPTOP")  # brand unknown, but it's a computer
    assert "made by Xiaomi" in identity.mismatch("Sams-iPhone", "Xiaomi", "MOBILE")
    assert "game console" in identity.mismatch("PS5-1234", "", "DESKTOP")


def test_real_devices_and_typed_in_names_pass():
    assert identity.mismatch("Echo-Dot", "Amazon", "VOICE_CONTROL") is None
    assert identity.mismatch("Sams-MacBook-Pro", "Apple", "LAPTOP") is None
    assert identity.mismatch("Sonos-347E5C9E6FBB", "Sonos", "LOUDSPEAKER") is None
    assert identity.mismatch("KP400", "TP-Link", "SMART_PLUG") is None
    assert identity.mismatch("Garage echo", "Apple", "LAPTOP", name_user_set=True) is None  # someone named it in the Orbi app
    assert identity.mismatch("Echo-Dot", "", "") is None  # the router doesn't know: don't guess
    assert identity.mismatch("Kristines-iMac", "Apple", "DESKTOP") is None


def test_disguise_alert_once(monitor, fake_router):
    fake_router.devs.append({**fake_router._dev("AA:00:00:00:00:09", "Echo-Spot", "192.168.1.40", ROUTER_MAC),
                             "brand": "Apple", "category": "LAPTOP"})
    monitor.scan()
    monitor.scan()
    ev = monitor.store.q("SELECT * FROM events WHERE kind='identity'")
    assert len(ev) == 1 and ev[0]["title"] == "Echo-Spot may not be what it says" and ev[0]["severity"] == "error"
    assert "made by Apple" in ev[0]["detail"] and ev[0]["mac"] == "AA:00:00:00:00:09"
    assert "Device may be disguised" in [n[0] for n in monitor.notes]


def test_room_changes_noted_while_cut_off(monitor, fake_router):
    """At bedtime, the kid's phone moving from the satellite to the router says where in the house it went."""
    monitor.scan()
    pid = monitor.store.x("INSERT INTO profiles(name, created, paused_until) VALUES('Kid', 0, ?)", (time.time() + 3600,))
    monitor.store.x("UPDATE devices SET profile_id=? WHERE mac='AA:00:00:00:00:01'", (pid,))
    phone = fake_router.devs[0]
    phone["ap_mac"] = ROUTER_MAC
    monitor.scan()  # one scan on the router: could be passing through
    phone["ap_mac"] = SAT_MAC
    monitor.scan()
    assert not monitor.store.q("SELECT * FROM events WHERE kind='room'")
    phone["ap_mac"] = ROUTER_MAC
    monitor.scan()
    monitor.scan()  # settled
    ev = monitor.store.q("SELECT * FROM events WHERE kind='room'")
    assert len(ev) == 1 and ev[0]["title"] == "kid-phone moved to the router"
    assert "Before, it was connected to Garage Satellite" in ev[0]["detail"] and "Kid" in ev[0]["detail"]
    # a device that isn't cut off isn't followed around the house
    fake_router.devs[1]["ap_mac"] = SAT_MAC
    monitor.scan()
    monitor.scan()
    assert len(monitor.store.q("SELECT * FROM events WHERE kind='room'")) == 1


def test_raw_device_list_keeps_every_field():
    class Resp:
        text = """<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body>
        <m:GetAttachDevice2Response xmlns:m="urn:NETGEAR-ROUTER:service:DeviceInfo:1"><NewAttachDevice>
        <Device><IP>192.168.1.40</IP><Name>Echo-Spot</Name><NameUserSet>false</NameUserSet><MAC>aa:00:00:00:00:09</MAC>
        <ConnectionType>5GHz</ConnectionType><SSID>Home</SSID><Linkspeed>866</Linkspeed><SignalStrength>60</SignalStrength>
        <AllowOrBlock>Allow</AllowOrBlock><DeviceTypeV2>LAPTOP</DeviceTypeV2><DeviceModel>65&quot; TV</DeviceModel>
        <ConnAPMAC>C8:9E:43:00:00:01</ConnAPMAC><DeviceBrand>Apple</DeviceBrand></Device>
        <Device><IP>192.168.1.41</IP><Name>plug</Name><NameUserSet>true</NameUserSet><MAC>AA:00:00:00:00:0A</MAC>
        <DeviceTypeV2>GENERIC</DeviceTypeV2><DeviceBrand>Not included in current license</DeviceBrand></Device>
        </NewAttachDevice></m:GetAttachDevice2Response></soap-env:Body></soap-env:Envelope>"""

    class NG:
        def _make_request(self, service, method):
            return True, Resp()

    c = router.RouterClient("192.168.1.1", "pw")
    c.call = lambda method, *a, **k: router._attached_devices_full(NG())
    a, b = c.devices()
    assert (a["mac"], a["brand"], a["category"], a["name_user_set"], a["model"], a["link_rate"]) == \
        ("AA:00:00:00:00:09", "Apple", "LAPTOP", False, '65" TV', 866.0)
    assert (b["brand"], b["category"], b["name_user_set"]) == ("", "", True)


def test_router_dates():
    from datetime import datetime
    assert datetime.fromtimestamp(router.router_date("2026_02.24_02:04:17")) == datetime(2026, 2, 24, 2, 4, 17)
    assert datetime.fromtimestamp(router.router_date("Thursday, 17 Aug 2023 06:30:18")) == datetime(2023, 8, 17, 6, 30, 18)
    assert router.router_date("") is None and router.router_date(None) is None


def test_traffic_has_weekly_and_daily_averages():
    c = router.RouterClient("192.168.1.1", "pw")
    c.call = lambda method, *a, **k: {"NewTodayDownload": 39342.0, "NewWeekDownload": (414508.0, 59215.0), "NewWeekUpload": (103042.0, 14720.0),
                                      "NewMonthDownload": (758064.0, 25268.0), "NewLastMonthDownload": (6489078.0, 216302.0)}
    t = c.traffic()
    assert (t["today_down"], t["week_down"], t["week_avg_down"], t["month_avg_down"], t["last_month_avg_down"]) == \
        (39342.0, 414508.0, 59215.0, 25268.0, 216302.0)
