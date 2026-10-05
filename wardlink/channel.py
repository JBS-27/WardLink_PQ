"""Handshakes and the sealed record layer. Both sides share these byte layouts.

signed (WL1)
  sensor  -> mark | id | e_x25519 | e_mlkem_pub | time | ML-DSA sig(sensor)
  gateway -> e_x25519 | mlkem_ct(e_mlkem_pub) | ML-DSA sig(gateway)

lean (WL2), Noise-KK shape with KEMs, all four long-term keys enrolled in person
  sensor  -> mark | id | e_x25519 | e_mlkem_pub | ct1 = Encaps(gateway static)
  gateway -> e_x25519 | ct2 = Encaps(sensor ephemeral) | ct3 = Encaps(sensor static) | confirm
  secrets  es, ss1 | ee, ss2 | se, ss3
  The gateway proves itself with the confirm tag (needs es and ss1).
  The sensor proves itself with its first reading (needs se and ss3).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from wardlink.crypto import (
    GATEWAY_TO_SENSOR,
    LEAN_INFO,
    SENSOR_TO_GATEWAY,
    SIGNED_INFO,
    ChannelError,
    Identity,
    StaticKeys,
    confirm_tag,
    derive_keys,
    fingerprint,
    kem_decaps,
    kem_decaps_static,
    kem_encaps,
    new_kem,
    open_seal,
    ratchet_step,
    seal,
    sign_message,
    signature_ok,
    x25519_private,
    x25519_public,
    x25519_shared,
)

SIGNED_MARK = b"WL1"
LEAN_MARK = b"WL2"
WELCOME_MARK = b"WL1W"
SKEW_MS = 300_000
ML_KEM_PUBLIC = 1184
ML_KEM_CIPHERTEXT = 1088
ML_DSA_SIGNATURE = 3309
SEQ_BYTES = 4
TAG_BYTES = 16
MAX_SKIP = 64
LEAN_WELCOME = 32 + 2 * ML_KEM_CIPHERTEXT + 16
SIGNED_WELCOME = 32 + ML_KEM_CIPHERTEXT + ML_DSA_SIGNATURE


@dataclass
class Session:
    """Keys for one conversation. Each reading gets its own key from a one-way chain."""

    device_id: str
    mode: str
    session_id: str
    send_chain: bytes = field(repr=False)
    recv_chain: bytes = field(repr=False)
    send_direction: int
    recv_direction: int
    send_seq: int = 0
    recv_seq: int = 0

    def seal(self, plaintext: bytes) -> bytes:
        sequence = self.send_seq + 1
        header = sequence.to_bytes(SEQ_BYTES, "big")
        message_key, next_chain = ratchet_step(self.send_chain)
        body = seal(message_key, sequence, self.send_direction, plaintext, self._aad(header))
        self.send_chain = next_chain
        self.send_seq = sequence
        return header + body

    def open(self, frame: bytes) -> bytes:
        sequence, chain, plaintext = self.try_open(frame)
        self.recv_chain = chain
        self.recv_seq = sequence
        return plaintext

    def try_open(self, frame: bytes) -> tuple[int, bytes, bytes]:
        """Check a frame without moving the ratchet. Returns (sequence, next chain, plaintext)."""
        if len(frame) < SEQ_BYTES + TAG_BYTES:
            raise ChannelError("sealed message is too short")
        header = frame[:SEQ_BYTES]
        sequence = int.from_bytes(header, "big")
        if sequence <= self.recv_seq:
            raise ChannelError("replayed message: that reading's key is already gone")
        gap = sequence - self.recv_seq - 1
        if gap > MAX_SKIP:
            raise ChannelError("message is too far ahead of the ratchet")
        chain = self.recv_chain
        for _ in range(gap):
            _skipped, chain = ratchet_step(chain)
        message_key, next_chain = ratchet_step(chain)
        plaintext = open_seal(message_key, sequence, self.recv_direction, frame[SEQ_BYTES:], self._aad(header))
        return sequence, next_chain, plaintext

    def _aad(self, header: bytes) -> bytes:
        return self.device_id.encode() + header


def frame_sequence(frame: bytes) -> int:
    return int.from_bytes(frame[:SEQ_BYTES], "big")


def session_for(role: str, device_id: str, mode: str, keys: list[bytes], transcript: bytes) -> Session:
    sensor_to_gateway, gateway_to_sensor = keys[0], keys[1]
    session_id = hashlib.sha256(transcript).hexdigest()[:8]
    if role == "sensor":
        return Session(device_id, mode, session_id, sensor_to_gateway, gateway_to_sensor, SENSOR_TO_GATEWAY, GATEWAY_TO_SENSOR)
    if role == "gateway":
        return Session(device_id, mode, session_id, gateway_to_sensor, sensor_to_gateway, GATEWAY_TO_SENSOR, SENSOR_TO_GATEWAY)
    raise ChannelError("unknown role")


def hello_mode(hello_wire: bytes) -> str:
    if hello_wire.startswith(SIGNED_MARK):
        return "signed"
    if hello_wire.startswith(LEAN_MARK):
        return "lean"
    raise ChannelError("hello message is not WardLink")


def claimed_device_id(hello_wire: bytes) -> str:
    """Device id written in the hello. Trust it only after the keys check out."""
    hello_mode(hello_wire)
    if len(hello_wire) < 5:
        raise ChannelError("hello message is too short")
    name_len = hello_wire[3]
    device_id = hello_wire[4 : 4 + name_len].decode(errors="replace")
    check_device_id(device_id)
    return device_id


def check_device_id(device_id: str) -> None:
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    if not device_id or len(device_id) > 32 or any(ch not in allowed for ch in device_id):
        raise ChannelError("device id must be short lowercase letters, digits, or hyphens")


def _name_prefix(mark: bytes, device_id: str) -> bytes:
    check_device_id(device_id)
    name = device_id.encode()
    return mark + bytes([len(name)]) + name


# Signed handshake ------------------------------------------------------------


@dataclass
class HelloOffer:
    device_id: str
    blob: bytes
    wire: bytes
    _x25519: X25519PrivateKey | None = field(repr=False)
    _kem: MLKEM768PrivateKey | None = field(repr=False)
    _open: bool = field(default=True, repr=False)
    mode: str = "signed"

    def finish(self, welcome_wire: bytes, gateway_public: bytes) -> Session:
        if not self._open:
            raise ChannelError("handshake already finished")
        self._open = False
        try:
            return finish_welcome(self, welcome_wire, gateway_public)
        finally:
            self.discard()

    def discard(self) -> None:
        self._open = False
        self._x25519 = None
        self._kem = None


def sensor_hello(identity: Identity, device_id: str, now: int) -> HelloOffer:
    x_private = X25519PrivateKey.generate()
    kem_public, kem_private = new_kem()
    blob = _name_prefix(SIGNED_MARK, device_id) + x25519_public(x_private) + kem_public + now.to_bytes(8, "big")
    signature = sign_message(identity, blob)
    return HelloOffer(device_id, blob, blob + signature, x_private, kem_private)


def gateway_accept(
    hello_wire: bytes,
    sensor_public: bytes,
    gateway: Identity,
    now: int,
    last_hello_at: dict[str, int],
) -> tuple[bytes, Session]:
    if len(hello_wire) <= ML_DSA_SIGNATURE + ML_KEM_PUBLIC + 32:
        raise ChannelError("hello message is too short")
    blob, signature = hello_wire[:-ML_DSA_SIGNATURE], hello_wire[-ML_DSA_SIGNATURE:]
    if not signature_ok(sensor_public, blob, signature):
        raise ChannelError("sensor signature failed")
    device_id, x_public, kem_public, sent_at = _parse_signed_blob(blob)
    if abs(now - sent_at) > SKEW_MS:
        raise ChannelError("sensor clock is too far from the gateway")
    if sent_at <= last_hello_at.get(device_id, 0):
        raise ChannelError("replayed hello")
    ciphertext, kem_shared = kem_encaps(kem_public)
    gateway_x = X25519PrivateKey.generate()
    gateway_x_public = x25519_public(gateway_x)
    transcript = WELCOME_MARK + blob + gateway_x_public + ciphertext
    welcome_wire = gateway_x_public + ciphertext + sign_message(gateway, transcript)
    keys = derive_keys([x25519_shared(gateway_x, x_public), kem_shared], transcript, SIGNED_INFO)
    last_hello_at[device_id] = sent_at
    return welcome_wire, session_for("gateway", device_id, "signed", keys, transcript)


def finish_welcome(offer: HelloOffer, welcome_wire: bytes, gateway_public: bytes) -> Session:
    if len(welcome_wire) != SIGNED_WELCOME:
        raise ChannelError("welcome message has the wrong size")
    gateway_x_public = welcome_wire[:32]
    ciphertext = welcome_wire[32 : 32 + ML_KEM_CIPHERTEXT]
    signature = welcome_wire[32 + ML_KEM_CIPHERTEXT :]
    transcript = WELCOME_MARK + offer.blob + gateway_x_public + ciphertext
    if not signature_ok(gateway_public, transcript, signature):
        raise ChannelError("gateway signature failed")
    if offer._kem is None or offer._x25519 is None:
        raise ChannelError("handshake keys were already discarded")
    kem_shared = kem_decaps(offer._kem, ciphertext)
    keys = derive_keys([x25519_shared(offer._x25519, gateway_x_public), kem_shared], transcript, SIGNED_INFO)
    return session_for("sensor", offer.device_id, "signed", keys, transcript)


def _parse_signed_blob(blob: bytes) -> tuple[str, bytes, bytes, int]:
    if not blob.startswith(SIGNED_MARK) or len(blob) < 5:
        raise ChannelError("hello message is not WardLink")
    name_len = blob[3]
    end = 4 + name_len
    if name_len < 1 or len(blob) != end + 32 + ML_KEM_PUBLIC + 8:
        raise ChannelError("hello message has the wrong size")
    device_id = blob[4:end].decode(errors="replace")
    check_device_id(device_id)
    x_public = blob[end : end + 32]
    kem_public = blob[end + 32 : end + 32 + ML_KEM_PUBLIC]
    sent_at = int.from_bytes(blob[end + 32 + ML_KEM_PUBLIC :], "big")
    return device_id, x_public, kem_public, sent_at


# Lean handshake --------------------------------------------------------------


@dataclass
class LeanOffer:
    device_id: str
    wire: bytes
    _x25519: X25519PrivateKey | None = field(repr=False)
    _kem: MLKEM768PrivateKey | None = field(repr=False)
    _static: StaticKeys = field(repr=False)
    _first: list[bytes] = field(repr=False)
    _open: bool = field(default=True, repr=False)
    mode: str = "lean"

    def finish(self, welcome_wire: bytes, _gateway_public: bytes | None = None) -> Session:
        if not self._open:
            raise ChannelError("handshake already finished")
        self._open = False
        try:
            return _lean_finish(self, welcome_wire)
        finally:
            self.discard()

    def discard(self) -> None:
        self._open = False
        self._x25519 = None
        self._kem = None
        self._first.clear()


def lean_hello(static: StaticKeys, device_id: str, gateway_kem_public: bytes, gateway_x_public: bytes) -> LeanOffer:
    x_private = X25519PrivateKey.generate()
    kem_public, kem_private = new_kem()
    ct1, ss1 = kem_encaps(gateway_kem_public)
    es = x25519_shared(x_private, gateway_x_public)
    wire = _name_prefix(LEAN_MARK, device_id) + x25519_public(x_private) + kem_public + ct1
    return LeanOffer(device_id, wire, x_private, kem_private, static, [es, ss1])


def lean_accept(
    hello_wire: bytes,
    sensor_kem_public: bytes,
    sensor_x_public: bytes,
    gateway: StaticKeys,
) -> tuple[bytes, Session]:
    device_id, e_x_public, e_kem_public, ct1 = _parse_lean_hello(hello_wire)
    ss1 = kem_decaps_static(gateway.kem_secret, ct1)
    es = x25519_shared(x25519_private(gateway.x_secret), e_x_public)
    gateway_e = X25519PrivateKey.generate()
    ee = x25519_shared(gateway_e, e_x_public)
    se = x25519_shared(gateway_e, sensor_x_public)
    ct2, ss2 = kem_encaps(e_kem_public)
    ct3, ss3 = kem_encaps(sensor_kem_public)
    gateway_e_public = x25519_public(gateway_e)
    transcript = hello_wire + gateway_e_public + ct2 + ct3
    sensor_to_gateway, gateway_to_sensor, confirm = derive_keys([es, ss1, ee, ss2, se, ss3], transcript, LEAN_INFO, 3)
    welcome = gateway_e_public + ct2 + ct3 + confirm_tag(confirm, b"gateway", transcript)
    session = session_for("gateway", device_id, "lean", [sensor_to_gateway, gateway_to_sensor], transcript)
    return welcome, session


def _lean_finish(offer: LeanOffer, welcome_wire: bytes) -> Session:
    session, gateway_proven = lean_derive(offer, welcome_wire)
    if not gateway_proven:
        raise ChannelError("gateway could not prove its enrolled keys")
    return session


def lean_derive(offer: LeanOffer, welcome_wire: bytes) -> tuple[Session, bool]:
    """Sensor-side keys plus whether the gateway's confirm tag matched."""
    if len(welcome_wire) != LEAN_WELCOME:
        raise ChannelError("welcome message has the wrong size")
    gateway_e_public = welcome_wire[:32]
    ct2 = welcome_wire[32 : 32 + ML_KEM_CIPHERTEXT]
    ct3 = welcome_wire[32 + ML_KEM_CIPHERTEXT : 32 + 2 * ML_KEM_CIPHERTEXT]
    tag = welcome_wire[32 + 2 * ML_KEM_CIPHERTEXT :]
    if offer._kem is None or offer._x25519 is None or len(offer._first) != 2:
        raise ChannelError("handshake keys were already discarded")
    es, ss1 = offer._first
    ee = x25519_shared(offer._x25519, gateway_e_public)
    se = x25519_shared(x25519_private(offer._static.x_secret), gateway_e_public)
    ss2 = kem_decaps(offer._kem, ct2)
    ss3 = kem_decaps_static(offer._static.kem_secret, ct3)
    transcript = offer.wire + gateway_e_public + ct2 + ct3
    sensor_to_gateway, gateway_to_sensor, confirm = derive_keys([es, ss1, ee, ss2, se, ss3], transcript, LEAN_INFO, 3)
    proven = hmac.compare_digest(tag, confirm_tag(confirm, b"gateway", transcript))
    session = session_for("sensor", offer.device_id, "lean", [sensor_to_gateway, gateway_to_sensor], transcript)
    return session, proven


def _parse_lean_hello(wire: bytes) -> tuple[str, bytes, bytes, bytes]:
    if not wire.startswith(LEAN_MARK) or len(wire) < 5:
        raise ChannelError("hello message is not WardLink")
    name_len = wire[3]
    end = 4 + name_len
    if name_len < 1 or len(wire) != end + 32 + ML_KEM_PUBLIC + ML_KEM_CIPHERTEXT:
        raise ChannelError("hello message has the wrong size")
    device_id = wire[4:end].decode(errors="replace")
    check_device_id(device_id)
    e_x_public = wire[end : end + 32]
    e_kem_public = wire[end + 32 : end + 32 + ML_KEM_PUBLIC]
    ct1 = wire[end + 32 + ML_KEM_PUBLIC :]
    return device_id, e_x_public, e_kem_public, ct1


def chain_fingerprint(session: Session) -> str:
    return fingerprint(session.recv_chain)
