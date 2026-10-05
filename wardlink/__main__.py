"""WardLink PQ on one laptop.

  python -m wardlink demo            gateway, simulated tank sensor, and dashboard together
  python -m wardlink rigor           run the field-scenario suite and save data/rigor.json
  python -m wardlink bench           handshake bytes, time and radio cost against TLS 1.3
  python -m wardlink check           handshake and refusal checks, no network
  python -m wardlink enroll          create or upgrade the keys in data/
  python -m wardlink gateway         gateway and dashboard only
  python -m wardlink sensor          sensor only, for a gateway started separately
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from wardlink.bench import print_bench, run_bench
from wardlink.channel import lean_accept, lean_derive, lean_hello
from wardlink.crypto import ChannelError, new_identity, new_static_keys
from wardlink.enroll import DEVICE_ID, GatewayKeys, SensorRecord, enroll, load_gateway, load_sensor
from wardlink.office import Controls, Office
from wardlink.record import Reading, encode_reading
from wardlink.service import listen, run_demo, run_sensor, serve_gateway, start_bench, start_page, start_watchdog
from wardlink.store import Store
from wardlink.world import World

DATA = Path("data")
DATABASE = DATA / "wardlink.db"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m wardlink", description="WardLink PQ laptop prototype.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("demo", help="Gateway, simulated sensor and dashboard in one process")
    demo.add_argument("--mode", choices=("lean", "signed"), default="lean")
    demo.add_argument("--pace", type=float, default=6.5, help="Seconds between readings (one reading is 10 tank-minutes)")
    demo.add_argument("--rekey-every", type=int, default=36, help="Readings per session before a fresh handshake")
    demo.add_argument("--fresh", action="store_true", help="Start with an empty reading database")
    rigor = sub.add_parser("rigor", help="Run the field-scenario suite")
    rigor.add_argument("--only", default="", help="Run only scenarios whose id contains this text")
    sub.add_parser("bench", help="Compare handshakes with TLS 1.3 and print radio cost")
    sub.add_parser("check", help="Run the handshake and refusal checks")
    sub.add_parser("enroll", help="Create or upgrade the gateway and sensor keys")
    sub.add_parser("gateway", help="Gateway and dashboard only")
    sensor = sub.add_parser("sensor", help="Sensor only")
    sensor.add_argument("--mode", choices=("lean", "signed"), default="lean")
    sensor.add_argument("--count", type=int, default=0, help="Stop after this many readings are acknowledged")
    args = parser.parse_args(argv)

    if args.cmd == "enroll":
        print(enroll(DATA))
        print(f"Keys are in {DATA}/ . The gateway roster holds public keys only.")
        return 0
    if args.cmd == "check":
        return _check()
    if args.cmd == "bench":
        print_bench(run_bench(DATA))
        print(f"Saved {DATA}/bench.json")
        return 0
    if args.cmd == "rigor":
        from wardlink.rigor import print_report, run_suite, save_report

        report = run_suite(only=args.only, progress=True)
        print_report(report)
        if not args.only:
            save_report(report, DATA)
            print(f"Saved {DATA}/rigor.json")
        return 0 if report["passed"] == report["total"] else 1
    status = enroll(DATA)
    if status != "already enrolled":
        print(f"Keys {status} in {DATA}/")
    if args.cmd == "demo":
        if args.fresh and DATABASE.exists():
            for suffix in ("", "-wal", "-shm"):
                Path(f"{DATABASE}{suffix}").unlink(missing_ok=True)
        keys, roster = load_gateway(DATA)
        store = Store(DATABASE)
        world = World()
        recent = store.recent(DEVICE_ID, 1)
        if recent:
            last, _meta = recent[-1]
            world.resume(last.level_pct, last.tank_time)
            print(f"Resuming the tank from {store.count(DEVICE_ID)} stored readings")
        controls = Controls(mode=args.mode, rekey_every=max(4, args.rekey_every))
        office = Office(keys, roster, world=world, controls=controls, store=store, data_dir=DATA)
        _load_rigor(office)
        print("WardLink PQ demo. Ctrl+C to stop.")
        run_demo(office, load_sensor(DATA), pace=max(1.0, args.pace), data_dir=DATA)
        return 0
    if args.cmd == "gateway":
        keys, roster = load_gateway(DATA)
        office = Office(keys, roster, store=Store(DATABASE), data_dir=DATA)
        _load_rigor(office)
        listener = listen()
        start_page(office)
        start_bench(office, DATA)
        start_watchdog(office)
        serve_gateway(office, listener)
        return 0
    if args.cmd == "sensor":
        sensor_keys = load_sensor(DATA)
        print(f"Sensor for {sensor_keys.label}, {args.mode} handshake")
        run_sensor(sensor_keys, controls=Controls(mode=args.mode), readings=args.count or None, data_dir=DATA)
        return 0
    return 1


def _load_rigor(office: Office) -> None:
    path = DATA / "rigor.json"
    if path.exists():
        try:
            office.rigor = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            office.rigor = None


def _check() -> int:
    print("WardLink PQ check on this laptop. No board, phone, or Pi is involved.")
    gateway = GatewayKeys(new_identity(), new_static_keys())
    sensor_identity, sensor_static = new_identity(), new_static_keys()
    roster = {
        DEVICE_ID: SensorRecord(DEVICE_ID, "Ward 4 overhead tank", sensor_identity.public_key, sensor_static.kem_public, sensor_static.x_public)
    }
    office = Office(gateway, roster)
    offer = lean_hello(sensor_static, DEVICE_ID, gateway.static.kem_public, gateway.static.x_public)
    welcome, gateway_session = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
    sensor_session = offer.finish(welcome)
    print(f"Lean handshake ok: {len(offer.wire)} + {len(welcome)} = {len(offer.wire) + len(welcome)} bytes.")

    reading = Reading(42.0, 2.156, 0.6, 290, 7.3, 27.0, 31.0, int(time.time()))
    first = sensor_session.seal(encode_reading(reading))
    damaged = bytearray(first)
    damaged[10] ^= 0x01
    failures = 0
    try:
        office.receive_reading(gateway_session, bytes(damaged))
        print("Modified capsule was accepted. That is a failure.")
        failures += 1
    except ChannelError as exc:
        print(f"Modified capsule refused: {exc}.")
    shown = office.receive_reading(gateway_session, first).reading
    print(f"Reading accepted and session proven: tank {shown['level_pct']:.0f}%.")
    try:
        office.receive_reading(gateway_session, first)
        print("Replayed capsule was accepted. That is a failure.")
        failures += 1
    except ChannelError as exc:
        print(f"Replayed capsule refused: {exc}.")
    rogue_offer = lean_hello(new_static_keys(), DEVICE_ID, gateway.static.kem_public, gateway.static.x_public)
    rogue_welcome, rogue_gateway_side = lean_accept(rogue_offer.wire, sensor_static.kem_public, sensor_static.x_public, gateway.static)
    rogue_session, _proven = lean_derive(rogue_offer, rogue_welcome)
    try:
        office.receive_reading(rogue_gateway_side, rogue_session.seal(encode_reading(reading)))
        print("Impostor capsule was accepted. That is a failure.")
        failures += 1
    except ChannelError as exc:
        print(f"Impostor claiming {DEVICE_ID} refused at its first capsule: {exc}.")
    unknown = office.unknown_board()
    print(f"Unlisted board: {unknown['text']}")
    if failures:
        return 1
    print("Checks passed. Next: python -m wardlink demo, or python -m wardlink rigor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
