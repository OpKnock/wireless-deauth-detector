from __future__ import annotations

import struct
from dataclasses import dataclass, field

DEAUTH_REASON_CODES = {
    1: "unspecified",
    2: "previous authentication no longer valid",
    3: "deauthentication because sending STA is leaving IBSS or ESS",
    4: "disassociated due to inactivity",
    5: "disassociated because AP is unable to handle all currently associated STAs",
    7: "class 3 frame received from nonassociated STA",
    8: "disassociated because sending STA is leaving BSS",
    9: "STA requesting (re)association is not authenticated",
    15: "4-way handshake timeout",
    17: "4-way handshake failed",
}


@dataclass
class FrameEvent:
    bssid: str
    src: str
    type: str  # deauth | disassoc
    reason: int
    reason_text: str
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "src": self.src,
            "type": self.type,
            "reason": self.reason,
            "reason_text": self.reason_text,
            "timestamp": self.timestamp,
        }


@dataclass
class DeauthAlert:
    bssid: str
    count: int
    window_seconds: float
    rate_per_second: float
    severity: str

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "count": self.count,
            "window_seconds": self.window_seconds,
            "rate_per_second": round(self.rate_per_second, 2),
            "severity": self.severity,
        }


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_mgmt_frame(frame: bytes, timestamp: float = 0.0) -> FrameEvent | None:
    """Parse an 802.11 management frame. Returns None if not deauth/disassoc."""
    if len(frame) < 24:
        return None
    fc = struct.unpack_from("<H", frame, 0)[0]
    frame_type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if frame_type != 0:
        return None
    if subtype == 0xC:  # deauthentication
        ftype = "deauth"
    elif subtype == 0xA:  # disassociation
        ftype = "disassoc"
    else:
        return None
    bssid = _mac(frame[14:20])
    src = _mac(frame[8:14])
    reason = 0
    if len(frame) >= 24:
        reason = struct.unpack_from("<H", frame, 22)[0]
    return FrameEvent(
        bssid=bssid,
        src=src,
        type=ftype,
        reason=reason,
        reason_text=DEAUTH_REASON_CODES.get(reason, "unknown"),
        timestamp=timestamp,
    )


def build_deauth_frame(bssid: bytes, src: bytes, reason: int = 7) -> bytes:
    frame = bytearray()
    frame += struct.pack("<H", (0xC << 4) | 0)  # management/deauth
    frame += b"\xff\xff\xff\xff\xff\xff"  # dest
    frame += src
    frame += bssid
    frame += b"\x00" * 2  # seq
    frame += struct.pack("<H", reason)
    return bytes(frame)


def detect_flood(events: list[FrameEvent], threshold: int = 10, window_seconds: float = 5.0) -> list[DeauthAlert]:
    """Detect per-BSSID deauth bursts within a time window."""
    by_bssid: dict[str, list[FrameEvent]] = {}
    for event in events:
        if event.type != "deauth":
            continue
        by_bssid.setdefault(event.bssid, []).append(event)
    alerts: list[DeauthAlert] = []
    for bssid, hits in by_bssid.items():
        hits.sort(key=lambda e: e.timestamp)
        best = 0
        best_start = 0.0
        best_end = 0.0
        for start in hits:
            group = [h for h in hits if start.timestamp <= h.timestamp <= start.timestamp + window_seconds]
            if len(group) > best:
                best = len(group)
                best_start = start.timestamp
                best_end = start.timestamp + window_seconds
        if best >= threshold:
            rate = best / window_seconds
            alerts.append(
                DeauthAlert(
                    bssid=bssid,
                    count=best,
                    window_seconds=window_seconds,
                    rate_per_second=rate,
                    severity="high" if rate > 20 else "medium",
                )
            )
    return alerts


def detect_handshake_flood(events: list[FrameEvent], threshold: int = 5, window_seconds: float = 5.0) -> list[DeauthAlert]:
    """Repeated reason-17 (4-way handshake failed) patterns suggest interference."""
    out: list[DeauthAlert] = []
    for bssid in {e.bssid for e in events}:
        hits = [e for e in events if e.bssid == bssid and e.reason == 17]
        if len(hits) >= threshold:
            out.append(
                DeauthAlert(bssid=bssid, count=len(hits), window_seconds=window_seconds,
                            rate_per_second=len(hits) / window_seconds, severity="low")
            )
    return out
