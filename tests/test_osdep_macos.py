"""The macOS unified-log record format: chunking a record and reassembling it from `log show`.

These exercise the pure helpers, so they run on any OS (the module imports without fcntl/the mac
CLIs). The subprocess-backed parts (Keychain, `logger`/`log`, sysctl) are only reachable on a mac.
"""
import json

from orbi.osdep import macos


def _roundtrip(records):
    """records: [(event_id, text)] -> the (ts, eventMessage) stream a `log show` read would see,
    one line per chunk, in write order, then parse it back."""
    stream = []
    clock = [0]
    for i, (eid, text) in enumerate(records):
        for line in macos._encode_chunks(eid, text, f"uid{i}"):
            clock[0] += 1
            stream.append((f"2026-10-27 10:00:{clock[0]:02d}.000000-0700", line))
    return macos._parse_messages(stream)


def test_short_record_roundtrips():
    out = _roundtrip([(1, "hello world")])
    assert [(eid, text) for _ts, eid, text in out] == [(1, "hello world")]


def test_long_record_is_chunked_and_reassembled():
    big = json.dumps({"detail": "x" * 9000, "title": "Alert history was deleted"})
    lines = macos._encode_chunks(7, big, "uidA")
    assert len(lines) > 1  # it really did split
    out = _roundtrip([(7, big)])
    assert [(eid, text) for _ts, eid, text in out] == [(7, big)]


def test_unicode_survives_chunk_boundaries():
    text = "café — déjà — 日本語 " * 400  # multi-byte chars straddling 1800-byte slices
    out = _roundtrip([(2, text)])
    assert out[0][2] == text


def test_newest_first_and_event_id_filter():
    out = _roundtrip([(1, "first"), (2, "second"), (1, "third")])
    # newest (highest timestamp) first
    assert [text for _ts, _eid, text in out] == ["third", "second", "first"]


def test_partial_record_is_dropped():
    # only the first of two chunks survives (the rest truncated/aged out): skip, don't half-report
    lines = macos._encode_chunks(5, "y" * 5000, "uidP")
    assert len(lines) >= 2
    stream = [("2026-10-27 10:00:01.000000-0700", lines[0])]
    assert macos._parse_messages(stream) == []


def test_non_orbi_lines_ignored():
    stream = [("2026-10-27 10:00:01.000000-0700", "some other process message"),
              ("2026-10-27 10:00:02.000000-0700", macos._encode_chunks(1, "ok", "u")[0])]
    out = macos._parse_messages(stream)
    assert [(eid, text) for _ts, eid, text in out] == [(1, "ok")]


# ---- network parsers (sample output in the formats macOS 14/15 prints) ----
ARP_AN = """\
? (192.168.1.1) at c8:9e:43:c2:e3:33 on en0 ifscope [ethernet]
? (192.168.1.17) at 0:90:4c:1a:9:0 on en0 ifscope [ethernet]
? (192.168.1.20) at 3c:22:fb:1:2:3 on en0 ifscope permanent [ethernet]
? (192.168.1.44) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""


def test_arp_pads_octets_and_skips_own_incomplete_and_group_entries():
    assert macos.parse_arp(ARP_AN) == {"192.168.1.1": "C8:9E:43:C2:E3:33", "192.168.1.17": "00:90:4C:1A:09:00"}


def test_arp_lookup_form_includes_permanent_entries():
    out = "? (192.168.1.20) at 3c:22:fb:1:2:3 on en0 ifscope permanent [ethernet]\n"
    assert macos.parse_arp(out, dynamic_only=False) == {"192.168.1.20": "3C:22:FB:01:02:03"}
    assert macos.parse_arp("192.168.1.9 (192.168.1.9) -- no entry\n", dynamic_only=False) == {}


IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=50b<RXCSUM,TXCSUM,VLAN_HWTAGGING,AV,CHANNEL_IO>
\tether 3c:22:fb:01:02:03
\tinet6 fe80::1c%en0 prefixlen 64 secured scopeid 0x4
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 6a:1:2:3:4:5
\tstatus: inactive
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.64.0.2 --> 10.64.0.2 netmask 0xffffffff
"""


def test_ifconfig_maps_interfaces_to_macs_and_addresses():
    ifaces = macos.parse_ifconfig(IFCONFIG)
    assert ifaces["en0"] == {"mac": "3C:22:FB:01:02:03", "ips": ["192.168.1.20"]}
    assert ifaces["en1"]["mac"] == "6A:01:02:03:04:05" and ifaces["utun4"] == {"mac": None, "ips": ["10.64.0.2"]}
    assert macos._iface_for("10.64.0.2", ifaces) == "utun4" and macos._iface_for("192.168.1.99", ifaces) is None


def test_hardware_ports():
    out = "\nHardware Port: Ethernet\nDevice: en0\nEthernet Address: 3c:22:fb:01:02:03\n\nHardware Port: Wi-Fi\nDevice: en1\n"
    assert macos.parse_hardware_ports(out) == {"en0": "Ethernet", "en1": "Wi-Fi"}


NETSTAT = """\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0        1500  <Link#4>    3c:22:fb:01:02:03  8123456     0 9876543210  4123456     0 1234567890     0
en0        1500  fe80::1c%en0 fe80:4::1c       8123456     - 9876543210  4123456     - 1234567890     -
en0        1500  192.168.1     192.168.1.20      8123456     - 9876543210  4123456     - 1234567890     -
"""


def test_netstat_sent_bytes():
    assert macos.parse_netstat_obytes(NETSTAT, "en0") == 1234567890
    assert macos.parse_netstat_obytes(NETSTAT, "en1") is None
    assert macos.parse_netstat_obytes("", "en0") is None
    # a link row with no Address column has shifted columns: skipped, the address rows still answer
    shifted = NETSTAT.splitlines()[0] + "\nen0 1500 <Link#4> 5 0 6 7 0 8 0\n" + NETSTAT.splitlines()[3] + "\n"
    assert macos.parse_netstat_obytes(shifted, "en0") == 1234567890


def test_venv_python_is_posix_layout():
    from pathlib import Path
    assert macos.venv_python(Path("/opt/orbi")) == Path("/opt/orbi/.venv/bin/python")
