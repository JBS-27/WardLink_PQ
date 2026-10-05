"""Hybrid session crypto for WardLink PQ.

Two handshakes share one record layer:

signed  Each side signs its handshake with an enrolled ML-DSA-65 key.
        The session secret mixes ephemeral X25519 and ML-KEM-768.
lean    No signatures. Each side proves its enrolled keys by being able
        to open ML-KEM-768 capsules and X25519 exchanges addressed to them
        (the KEMTLS / PQNoise KK idea). About half the bytes on the wire.

Records are sealed with ChaCha20-Poly1305 under a key that changes on every
reading: a one-way hash ratchet, so a key taken from a stolen board cannot
open readings sent before the theft.

Long-term secrets are stored as FIPS 203/204 seeds: 32 bytes for ML-DSA-65
and 64 bytes for ML-KEM-768. The full keys are re-derived when needed.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONTEXT = b"wardlink-pq-v1"
SIGNED_INFO = b"wardlink-pq signed v2"
LEAN_INFO = b"wardlink-pq lean v1"
SENSOR_TO_GATEWAY = 1
GATEWAY_TO_SENSOR = 2
CONFIRM_BYTES = 16
ML_DSA_SEED = 32
ML_KEM_SEED = 64


class ChannelError(Exception):
    """The other side failed a check. The message is not shown."""


@dataclass(frozen=True)
class Identity:
    """ML-DSA-65 signing key, used by the signed handshake."""

    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class StaticKeys:
    """Long-term ML-KEM-768 and X25519 keys, used by the lean handshake."""

    kem_public: bytes
    kem_secret: bytes
    x_public: bytes
    x_secret: bytes


def new_identity() -> Identity:
    private = MLDSA65PrivateKey.generate()
    return Identity(private.public_key().public_bytes_raw(), private.private_bytes_raw())


def new_static_keys() -> StaticKeys:
    kem = MLKEM768PrivateKey.generate()
    x_private = X25519PrivateKey.generate()
    x_secret = x_private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return StaticKeys(kem.public_key().public_bytes_raw(), kem.private_bytes_raw(), x25519_public(x_private), x_secret)


def sign_message(identity: Identity, message: bytes) -> bytes:
    return MLDSA65PrivateKey.from_seed_bytes(identity.secret_key).sign(message, CONTEXT)


def signature_ok(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message, CONTEXT)
    except (InvalidSignature, ValueError):
        return False
    return True


def x25519_public(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def x25519_private(raw_secret: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(raw_secret)


def x25519_shared(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    if len(peer_public) != 32:
        raise ChannelError("X25519 public key must be 32 bytes")
    peer = X25519PublicKey.from_public_bytes(peer_public)
    try:
        return private_key.exchange(peer)
    except ValueError as exc:
        raise ChannelError("X25519 public key is not usable") from exc


def new_kem() -> tuple[bytes, MLKEM768PrivateKey]:
    private = MLKEM768PrivateKey.generate()
    return private.public_key().public_bytes_raw(), private


def kem_encaps(public_key: bytes) -> tuple[bytes, bytes]:
    try:
        shared, ciphertext = MLKEM768PublicKey.from_public_bytes(public_key).encapsulate()
    except ValueError as exc:
        raise ChannelError("ML-KEM public key is not usable") from exc
    return ciphertext, shared


def kem_decaps(private: MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    """A wrong ciphertext yields a useless secret, not an error (FIPS 203 implicit rejection)."""
    try:
        return private.decapsulate(ciphertext)
    except ValueError as exc:
        raise ChannelError("ML-KEM ciphertext has the wrong size") from exc


def kem_decaps_static(seed: bytes, ciphertext: bytes) -> bytes:
    return kem_decaps(MLKEM768PrivateKey.from_seed_bytes(seed), ciphertext)


def derive_keys(secrets: list[bytes], transcript: bytes, info: bytes, count: int = 2) -> list[bytes]:
    if any(len(secret) != 32 for secret in secrets):
        raise ChannelError("every handshake secret must be 32 bytes")
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=32 * count,
        salt=hashlib.sha256(transcript).digest(),
        info=info,
    ).derive(b"".join(secrets))
    return [material[index * 32 : (index + 1) * 32] for index in range(count)]


def confirm_tag(key: bytes, label: bytes, transcript: bytes) -> bytes:
    digest = hashlib.sha256(transcript).digest()
    return hmac.new(key, label + digest, hashlib.sha256).digest()[:CONFIRM_BYTES]


def ratchet_step(chain: bytes) -> tuple[bytes, bytes]:
    """Return (key for this reading, chain for the next one). There is no way back."""
    message_key = hmac.new(chain, b"\x01", hashlib.sha256).digest()
    next_chain = hmac.new(chain, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain


def fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def _nonce(direction: int, sequence: int) -> bytes:
    if sequence < 1 or sequence > 2**32 - 1:
        raise ChannelError("sequence number is out of range")
    return bytes([direction]) + sequence.to_bytes(8, "big") + b"\x00\x00\x00"


def seal(key: bytes, sequence: int, direction: int, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(_nonce(direction, sequence), plaintext, aad)


def open_seal(key: bytes, sequence: int, direction: int, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(_nonce(direction, sequence), ciphertext, aad)
    except InvalidTag as exc:
        raise ChannelError("message was modified") from exc
