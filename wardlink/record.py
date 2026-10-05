"""Compact binary readings and gateway notices.

A reading is 20 bytes before sealing and 40 bytes after (4-byte sequence,
20-byte body, 16-byte tag). The same reading as JSON is about 190 bytes,
which does not fit one LoRa frame at SF12 (51 bytes).

The gateway answers each stored reading with a sealed receipt, so the board
can delete it from its buffer. Until then the board keeps it and resends it
after a reconnect; the gateway ignores copies it already stored.
"""

from __future__ import annotations

import json
import struct
from dataclasses import asdict, dataclass

from wardlink.crypto import ChannelError

VERSION = 2
BUFFERED = 0x01
_READING = struct.Struct(">BBHHHHHhhI")
_NOTICE = struct.Struct(">BBII")
READING_BYTES = _READING.size
NOTICE_BYTES = _NOTICE.size
RECEIPT = 1
SEEN = 2


@dataclass(frozen=True)
class Reading:
    level_pct: float
    distance_m: float
    turbidity_ntu: float
    tds_mgl: int
    ph: float
    water_c: float
    air_c: float
    tank_time: int
    flags: int = 0

    @property
    def buffered(self) -> bool:
        return bool(self.flags & BUFFERED)


def encode_reading(reading: Reading) -> bytes:
    if not 0 <= reading.level_pct <= 100:
        raise ChannelError("tank level must be 0 to 100")
    try:
        return _READING.pack(
            VERSION,
            reading.flags & 0xFF,
            round(reading.level_pct * 10),
            round(reading.distance_m * 1000),
            min(65535, round(reading.turbidity_ntu * 10)),
            min(65535, int(reading.tds_mgl)),
            round(reading.ph * 100),
            round(reading.water_c * 10),
            round(reading.air_c * 10),
            int(reading.tank_time),
        )
    except struct.error as exc:
        raise ChannelError("reading is out of range") from exc


def decode_reading(body: bytes) -> Reading:
    if len(body) != READING_BYTES:
        raise ChannelError("reading has the wrong size")
    version, flags, level, distance, turbidity, tds, ph, water, air, tank_time = _READING.unpack(body)
    if version != VERSION:
        raise ChannelError("reading version is not supported")
    if level > 1000:
        raise ChannelError("tank level is out of range")
    return Reading(
        level_pct=level / 10,
        distance_m=distance / 1000,
        turbidity_ntu=turbidity / 10,
        tds_mgl=tds,
        ph=ph / 100,
        water_c=water / 10,
        air_c=air / 10,
        tank_time=tank_time,
        flags=flags,
    )


def json_bytes(reading: Reading) -> int:
    """Size of the same reading sent as readable JSON, for the size comparison."""
    body = asdict(reading)
    body["device_id"] = "ward-tank-01"
    return len(json.dumps(body, separators=(",", ":")).encode())


def encode_notice(kind: int, first: int, second: int) -> bytes:
    return _NOTICE.pack(VERSION, kind, first, second)


def decode_notice(body: bytes) -> tuple[int, int, int]:
    if len(body) != NOTICE_BYTES:
        raise ChannelError("notice has the wrong size")
    version, kind, first, second = _NOTICE.unpack(body)
    if version != VERSION or kind not in (RECEIPT, SEEN):
        raise ChannelError("notice is not supported")
    return kind, first, second
