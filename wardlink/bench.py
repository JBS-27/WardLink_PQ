"""Handshake benchmark: bytes, laptop time, and radio cost.

TLS numbers come from real TLS 1.3 handshakes run in memory through this
machine's OpenSSL, with mutual authentication and one self-signed
certificate per side (a real PKI chain adds an intermediate certificate).
WardLink numbers come from the same code the gateway runs.
"""

from __future__ import annotations

import base64
import json
import math
import platform
import shutil
import ssl
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from wardlink.channel import (
    ML_DSA_SIGNATURE,
    ML_KEM_CIPHERTEXT,
    ML_KEM_PUBLIC,
    gateway_accept,
    lean_accept,
    lean_hello,
    sensor_hello,
)
from wardlink.crypto import new_identity, new_static_keys
from wardlink.record import READING_BYTES, Reading, json_bytes

LINKS = [
    {"id": "wifi", "name": "Wi-Fi", "detail": "TCP segment 1,460 B", "payload": 1460, "sf": None},
    {"id": "ble", "name": "BLE 4.2+", "detail": "244 B per notification", "payload": 244, "sf": None},
    {"id": "lora7", "name": "LoRaWAN IN865 SF7", "detail": "242 B per frame", "payload": 242, "sf": 7},
    {"id": "lora12", "name": "LoRaWAN IN865 SF12", "detail": "51 B per frame", "payload": 51, "sf": 12},
]
LORAWAN_OVERHEAD = 13
ECDSA_P256_SIG = 71


def lora_airtime_ms(app_bytes: int, sf: int, bandwidth: int = 125_000) -> float:
    """Semtech SX127x time-on-air for one LoRaWAN uplink (CR 4/5, 8-symbol preamble, CRC on)."""
    phy = app_bytes + LORAWAN_OVERHEAD
    symbol = (2**sf) / bandwidth
    low_rate = 1 if symbol > 0.016 else 0
    numerator = 8 * phy - 4 * sf + 28 + 16
    payload_symbols = 8 + max(math.ceil(numerator / (4 * (sf - 2 * low_rate))) * 5, 0)
    return ((8 + 4.25) + payload_symbols) * symbol * 1000


def radio_cost(directions: list[int]) -> dict:
    out = {}
    for link in LINKS:
        frames = 0
        airtime = 0.0
        for size in directions:
            full, rest = divmod(size, link["payload"])
            frames += full + (1 if rest else 0)
            if link["sf"]:
                airtime += full * lora_airtime_ms(link["payload"], link["sf"])
                if rest:
                    airtime += lora_airtime_ms(rest, link["sf"])
        out[link["id"]] = {"frames": frames, "airtime_s": round(airtime / 1000, 1) if link["sf"] else None}
    return out


def _median_ms(values: list[float]) -> float:
    return round(statistics.median(values) * 1000, 3)


def measure_wardlink(runs: int = 40) -> list[dict]:
    gateway_id, sensor_id = new_identity(), new_identity()
    gateway_static, sensor_static = new_static_keys(), new_static_keys()
    base = time.time_ns() // 1_000_000

    signed_sensor, signed_gateway, signed_sizes = [], [], (0, 0)
    for index in range(runs):
        now = base + index
        t0 = time.perf_counter()
        offer = sensor_hello(sensor_id, "ward-tank-01", now)
        t1 = time.perf_counter()
        welcome, _session = gateway_accept(offer.wire, sensor_id.public_key, gateway_id, now, {})
        t2 = time.perf_counter()
        offer.finish(welcome, gateway_id.public_key)
        t3 = time.perf_counter()
        signed_sensor.append((t1 - t0) + (t3 - t2))
        signed_gateway.append(t2 - t1)
        signed_sizes = (len(offer.wire), len(welcome))

    lean_sensor, lean_gateway, lean_sizes = [], [], (0, 0)
    for _ in range(runs):
        t0 = time.perf_counter()
        offer = lean_hello(sensor_static, "ward-tank-01", gateway_static.kem_public, gateway_static.x_public)
        t1 = time.perf_counter()
        welcome, _session = lean_accept(offer.wire, sensor_static.kem_public, sensor_static.x_public, gateway_static)
        t2 = time.perf_counter()
        offer.finish(welcome)
        t3 = time.perf_counter()
        lean_sensor.append((t1 - t0) + (t3 - t2))
        lean_gateway.append(t2 - t1)
        lean_sizes = (len(offer.wire), len(welcome))

    signed_total = sum(signed_sizes)
    signed_parts = {"signatures": 2 * ML_DSA_SIGNATURE, "certificates": 0, "key_exchange": ML_KEM_PUBLIC + ML_KEM_CIPHERTEXT + 64}
    signed_parts["framing"] = signed_total - sum(signed_parts.values())
    lean_total = sum(lean_sizes)
    lean_parts = {"signatures": 0, "certificates": 0, "key_exchange": ML_KEM_PUBLIC + 3 * ML_KEM_CIPHERTEXT + 64}
    lean_parts["framing"] = lean_total - sum(lean_parts.values())

    return [
        {
            "id": "wl-signed",
            "name": "WardLink signed",
            "detail": "ML-DSA-65 signatures + X25519/ML-KEM-768, enrolled raw keys",
            "pq_confidentiality": True,
            "pq_authentication": True,
            "up": signed_sizes[0],
            "down": signed_sizes[1],
            "total": signed_total,
            "ms": round(_median_ms(signed_sensor) + _median_ms(signed_gateway), 3),
            "sensor_ms": _median_ms(signed_sensor),
            "gateway_ms": _median_ms(signed_gateway),
            "breakdown": signed_parts,
            "sensor_ops": ["ML-KEM keygen", "ML-DSA sign", "ML-DSA verify", "ML-KEM decaps", "X25519 ×1"],
            "sensor_keys": "ML-DSA-65 seed, 32 B (4,032 B once expanded for signing)",
            "sensor_code": "ML-DSA-65 and ML-KEM-768",
        },
        {
            "id": "wl-lean",
            "name": "WardLink lean",
            "detail": "No signatures: ML-KEM-768 + X25519 to enrolled keys (KEMTLS / PQNoise KK idea)",
            "pq_confidentiality": True,
            "pq_authentication": True,
            "up": lean_sizes[0],
            "down": lean_sizes[1],
            "total": lean_total,
            "ms": round(_median_ms(lean_sensor) + _median_ms(lean_gateway), 3),
            "sensor_ms": _median_ms(lean_sensor),
            "gateway_ms": _median_ms(lean_gateway),
            "breakdown": lean_parts,
            "sensor_ops": ["ML-KEM keygen", "ML-KEM encaps", "ML-KEM decaps ×2", "X25519 ×3"],
            "sensor_keys": "ML-KEM-768 seed 64 B + X25519 key 32 B",
            "sensor_code": "ML-KEM-768 only, no signature code",
        },
    ]


def _make_cert(folder: Path, name: str, algorithm: str) -> tuple[str, str, int]:
    key = folder / f"{name}.{algorithm}.key"
    crt = folder / f"{name}.{algorithm}.crt"
    newkey = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if algorithm == "ec" else ["-newkey", algorithm]
    subprocess.run(
        ["openssl", "req", "-x509", *newkey, "-keyout", str(key), "-out", str(crt), "-nodes", "-days", "30",
         "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}"],
        check=True,
        capture_output=True,
    )
    pem = crt.read_text()
    body = "".join(line for line in pem.splitlines() if "CERTIFICATE" not in line)
    return str(crt), str(key), len(base64.b64decode(body))


def _tls_handshake(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext, host: str) -> tuple[int, int]:
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname=host)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    up = down = 0
    client_done = server_done = False
    for _ in range(12):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        data = c_out.read()
        up += len(data)
        s_in.write(data)
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        data = s_out.read()
        down += len(data)
        c_in.write(data)
        if client_done and server_done and not c_out.pending and not s_out.pending:
            break
    if not (client_done and server_done):
        raise RuntimeError("TLS handshake did not finish")
    return up, down


def measure_tls(runs: int = 15) -> list[dict]:
    if shutil.which("openssl") is None:
        return []
    configs = [
        ("tls-classic", "TLS 1.3 classical", "X25519 + ECDSA P-256 certificates", "ec", True, False, False, 64),
        ("tls-hybrid", "TLS 1.3 hybrid", "X25519MLKEM768 + ECDSA P-256 certificates", "ec", False, True, False, 1248 + 1120),
        ("tls-pq", "TLS 1.3 post-quantum", "X25519MLKEM768 + ML-DSA-65 certificates", "mldsa65", False, True, True, 1248 + 1120),
    ]
    results = []
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder)
        for ident, name, detail, algorithm, x25519_only, pq_conf, pq_auth, key_exchange in configs:
            try:
                gw_crt, gw_key, gw_der = _make_cert(path, "gateway.ward4", algorithm)
                s_crt, s_key, s_der = _make_cert(path, "ward-tank-01", algorithm)
            except (subprocess.CalledProcessError, OSError):
                continue
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            server_ctx.load_cert_chain(gw_crt, gw_key)
            server_ctx.verify_mode = ssl.CERT_REQUIRED
            server_ctx.load_verify_locations(s_crt)
            server_ctx.num_tickets = 0
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            client_ctx.load_verify_locations(gw_crt)
            client_ctx.load_cert_chain(s_crt, s_key)
            if x25519_only:
                server_ctx.set_ecdh_curve("X25519")
                client_ctx.set_ecdh_curve("X25519")
            times = []
            sizes = (0, 0)
            for _ in range(runs):
                started = time.perf_counter()
                sizes = _tls_handshake(server_ctx, client_ctx, "gateway.ward4")
                times.append(time.perf_counter() - started)
            total = sum(sizes)
            signatures = 2 * (ML_DSA_SIGNATURE if pq_auth else ECDSA_P256_SIG)
            parts = {"signatures": signatures, "certificates": gw_der + s_der, "key_exchange": key_exchange}
            parts["framing"] = max(0, total - sum(parts.values()))
            results.append(
                {
                    "id": ident,
                    "name": name,
                    "detail": detail,
                    "pq_confidentiality": pq_conf,
                    "pq_authentication": pq_auth,
                    "up": sizes[0],
                    "down": sizes[1],
                    "total": total,
                    "ms": _median_ms(times),
                    "breakdown": parts,
                }
            )
    return results


def run_bench(data_dir: Path | None = None, runs: int = 40) -> dict:
    protocols = measure_tls() + measure_wardlink(runs)
    for protocol in protocols:
        protocol["radio"] = radio_cost([protocol["up"], protocol["down"]])
    sample = Reading(58.2, 1.638, 0.7, 284, 7.31, 27.4, 33.9, int(time.time()))
    binary_sealed = 4 + READING_BYTES + 16
    json_sealed = 4 + json_bytes(sample) + 16
    result = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "machine": f"{platform.machine()} laptop · Python {platform.python_version()} · {ssl.OPENSSL_VERSION}",
        "runs": runs,
        "links": LINKS,
        "protocols": protocols,
        "record": {
            "binary_sealed": binary_sealed,
            "json_sealed": json_sealed,
            "binary_radio": radio_cost([binary_sealed]),
            "json_radio": radio_cost([json_sealed]),
        },
    }
    if data_dir is not None:
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "bench.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def print_bench(result: dict) -> None:
    print(f"Handshake benchmark on {result['machine']}")
    print(f"{'protocol':<26}{'PQ conf':>8}{'PQ auth':>8}{'bytes':>9}{'ms':>9}{'SF12 frames':>13}{'SF12 air s':>12}")
    for item in result["protocols"]:
        radio = item["radio"]["lora12"]
        print(
            f"{item['name']:<26}{'yes' if item['pq_confidentiality'] else 'no':>8}"
            f"{'yes' if item['pq_authentication'] else 'no':>8}{item['total']:>9,}{item['ms']:>9.2f}"
            f"{radio['frames']:>13}{radio['airtime_s']:>12}"
        )
    record = result["record"]
    print(
        f"Reading: {record['binary_sealed']} B sealed binary ({record['binary_radio']['lora12']['frames']} SF12 frame) vs "
        f"{record['json_sealed']} B sealed JSON ({record['json_radio']['lora12']['frames']} SF12 frames)"
    )
