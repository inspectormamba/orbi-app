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
