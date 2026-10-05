"""In-person enrollment. The sensor's secrets stay in the sensor file.

On a real board that file is the only copy of the sensor's private keys,
kept in flash encrypted under an eFuse key. The gateway roster stores
public keys only.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from wardlink.channel import check_device_id
from wardlink.crypto import ML_DSA_SEED, ML_KEM_SEED, Identity, StaticKeys, new_identity, new_static_keys

DEVICE_ID = "ward-tank-01"
DEVICE_LABEL = "Ward 4 overhead tank"


@dataclass(frozen=True)
class GatewayKeys:
    identity: Identity
    static: StaticKeys


@dataclass(frozen=True)
class SensorRecord:
    device_id: str
    label: str
    public_key: bytes
    kem_public: bytes
    x_public: bytes
    status: str = "active"


@dataclass(frozen=True)
class SensorKeys:
    device_id: str
    label: str
    identity: Identity
    static: StaticKeys
    gateway_public: bytes
    gateway_kem_public: bytes
    gateway_x_public: bytes


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _raw(text: str) -> bytes:
    return base64.b64decode(text)


def _write(path: Path, body: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _stored_identity(body: dict | None) -> Identity | None:
    if body and "public_key" in body and "secret_key" in body:
        secret = _raw(body["secret_key"])
        if len(secret) == ML_DSA_SEED:
            return Identity(_raw(body["public_key"]), secret)
    return None


def _stored_static(body: dict | None) -> StaticKeys | None:
    keys = ("kem_public", "kem_secret", "x_public", "x_secret")
    if body and all(key in body for key in keys):
        static = StaticKeys(*(_raw(body[key]) for key in keys))
        if len(static.kem_secret) == ML_KEM_SEED:
            return static
    return None


def _identity_from(body: dict) -> Identity:
    identity = _stored_identity(body)
    if identity is None:
        raise ValueError("keys are missing or in an old format; run: python -m wardlink enroll")
    return identity


def _static_from(body: dict) -> StaticKeys:
    static = _stored_static(body)
    if static is None:
        raise ValueError("keys are missing or in an old format; run: python -m wardlink enroll")
    return static


def _key_fields(identity: Identity, static: StaticKeys) -> dict:
    return {
        "public_key": _b64(identity.public_key),
        "secret_key": _b64(identity.secret_key),
        "kem_public": _b64(static.kem_public),
        "kem_secret": _b64(static.kem_secret),
        "x_public": _b64(static.x_public),
        "x_secret": _b64(static.x_secret),
    }


def enroll(data_dir: Path, device_id: str = DEVICE_ID, label: str = DEVICE_LABEL) -> str:
    """Create keys, or add the lean-handshake keys to an older enrollment."""
    check_device_id(device_id)
    gateway_path = data_dir / "gateway.json"
    sensor_path = data_dir / "sensors" / f"{device_id}.json"
    roster_path = data_dir / "roster.json"
    old_gateway = _read(gateway_path) if gateway_path.exists() else None
    old_sensor = _read(sensor_path) if sensor_path.exists() else None
    stored = [
        _stored_identity(old_gateway),
        _stored_static(old_gateway),
        _stored_identity(old_sensor),
        _stored_static(old_sensor),
    ]
    if all(stored) and roster_path.exists():
        return "already enrolled"
    gateway_identity = stored[0] or new_identity()
    gateway_static = stored[1] or new_static_keys()
    sensor_identity = stored[2] or new_identity()
    sensor_static = stored[3] or new_static_keys()
    _write(gateway_path, _key_fields(gateway_identity, gateway_static))
    sensor_body = {"device_id": device_id, "label": label}
    sensor_body.update(_key_fields(sensor_identity, sensor_static))
    sensor_body.update(
        {
            "gateway_public_key": _b64(gateway_identity.public_key),
            "gateway_kem_public": _b64(gateway_static.kem_public),
            "gateway_x_public": _b64(gateway_static.x_public),
        }
    )
    _write(sensor_path, sensor_body)
    _write(
        roster_path,
        {
            "sensors": {
                device_id: {
                    "label": label,
                    "status": "active",
                    "public_key": _b64(sensor_identity.public_key),
                    "kem_public": _b64(sensor_static.kem_public),
                    "x_public": _b64(sensor_static.x_public),
                }
            }
        },
    )
    return "re-enrolled with seed keys" if old_gateway or old_sensor else "enrolled"


def set_status(data_dir: Path, device_id: str, status: str) -> None:
    roster_path = data_dir / "roster.json"
    body = _read(roster_path)
    body["sensors"][device_id]["status"] = status
    _write(roster_path, body)


def reenroll(data_dir: Path, device_id: str = DEVICE_ID) -> SensorRecord:
    """On-site re-enrollment after a theft: new sensor keys, old ones stop working."""
    sensor_path = data_dir / "sensors" / f"{device_id}.json"
    roster_path = data_dir / "roster.json"
    body = _read(sensor_path)
    identity, static = new_identity(), new_static_keys()
    body.update(_key_fields(identity, static))
    _write(sensor_path, body)
    roster = _read(roster_path)
    roster["sensors"][device_id].update(
        {
            "status": "active",
            "public_key": _b64(identity.public_key),
            "kem_public": _b64(static.kem_public),
            "x_public": _b64(static.x_public),
        }
    )
    _write(roster_path, roster)
    return SensorRecord(device_id, body["label"], identity.public_key, static.kem_public, static.x_public)


def load_gateway(data_dir: Path) -> tuple[GatewayKeys, dict[str, SensorRecord]]:
    body = _read(data_dir / "gateway.json")
    keys = GatewayKeys(_identity_from(body), _static_from(body))
    roster: dict[str, SensorRecord] = {}
    for device_id, record in _read(data_dir / "roster.json")["sensors"].items():
        roster[device_id] = SensorRecord(
            device_id,
            record["label"],
            _raw(record["public_key"]),
            _raw(record["kem_public"]),
            _raw(record["x_public"]),
            record.get("status", "active"),
        )
    return keys, roster


def load_sensor(data_dir: Path, device_id: str = DEVICE_ID) -> SensorKeys:
    body = _read(data_dir / "sensors" / f"{device_id}.json")
    return SensorKeys(
        device_id=body["device_id"],
        label=body["label"],
        identity=_identity_from(body),
        static=_static_from(body),
        gateway_public=_raw(body["gateway_public_key"]),
        gateway_kem_public=_raw(body["gateway_kem_public"]),
        gateway_x_public=_raw(body["gateway_x_public"]),
    )
