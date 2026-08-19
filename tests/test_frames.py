import struct

from deauthscan import (
    build_deauth_frame,
    detect_flood,
    detect_handshake_flood,
    parse_mgmt_frame,
)

BSSID = bytes.fromhex("001122334455")
CLIENT = bytes.fromhex("aabbccddeeff")


def build_disassoc(bssid: bytes, src: bytes) -> bytes:
    frame = bytearray()
    frame += struct.pack("<H", (0xA << 4) | 0)
    frame += b"\xff" * 6 + src + bssid + b"\x00" * 2
    frame += struct.pack("<H", 3)
    return bytes(frame)


def build_beacon(bssid: bytes) -> bytes:
    return struct.pack("<H", (0x8 << 4) | 0) + b"\xff" * 6 + bssid + bssid + b"\x00" * 6 + b"\x00" * 20


def test_parse_deauth():
    frame = build_deauth_frame(BSSID, CLIENT, reason=7)
    event = parse_mgmt_frame(frame, timestamp=1.0)
    assert event is not None
    assert event.type == "deauth"
    assert event.bssid == "00:11:22:33:44:55"
    assert event.src == "aa:bb:cc:dd:ee:ff"
    assert event.reason == 7
    assert event.reason_text == "class 3 frame received from nonassociated STA"


def test_parse_disassoc():
    frame = build_disassoc(BSSID, CLIENT)
    event = parse_mgmt_frame(frame)
    assert event is not None
    assert event.type == "disassoc"
    assert event.reason == 3


def test_parse_beacon_returns_none():
    assert parse_mgmt_frame(build_beacon(BSSID)) is None


def test_parse_short_frame():
    assert parse_mgmt_frame(b"\x00" * 20) is None


def test_detect_flood():
    events = [parse_mgmt_frame(build_deauth_frame(BSSID, CLIENT, reason=7), timestamp=i * 0.1) for i in range(15)]
    events += [parse_mgmt_frame(build_deauth_frame(BSSID, bytes.fromhex("112233445566"), reason=1), timestamp=i * 0.1) for i in range(15)]
    alerts = detect_flood([e for e in events if e is not None], threshold=10, window_seconds=5.0)
    assert len(alerts) == 1
    assert alerts[0].bssid == "00:11:22:33:44:55"
    assert alerts[0].count == 30
    assert alerts[0].rate_per_second >= 5.0


def test_detect_flood_below_threshold():
    events = [parse_mgmt_frame(build_deauth_frame(BSSID, CLIENT), timestamp=i) for i in range(3)]
    assert detect_flood([e for e in events if e is not None], threshold=10) == []


def test_handshake_flood():
    events = [parse_mgmt_frame(build_deauth_frame(BSSID, CLIENT, reason=17), timestamp=i) for i in range(6)]
    alerts = detect_handshake_flood([e for e in events if e is not None])
    assert len(alerts) == 1
    assert alerts[0].severity == "low"
