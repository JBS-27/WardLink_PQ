"""Field behaviour: delivery guarantees, lifecycle, sensor faults, standards conformance."""

import hashlib
import io
import json
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

from wardlink.crypto import ChannelError
from wardlink.enroll import DEVICE_ID, enroll, load_gateway, load_sensor
from wardlink.office import Controls, Office, SessionEnded
from wardlink.record import BUFFERED, RECEIPT, Reading, decode_notice, encode_reading
from wardlink.rigor import SCENARIOS, Gateway, ScriptedWorld, office_with, pair, reading, run_suite
from wardlink.rules import assess
from wardlink.store import Store
from wardlink.world import IST, World

VECTORS = Path(__file__).resolve().parent / "vectors" / "acvp_keygen.json"
NOON = datetime(2026, 10, 4, 12, 0, tzinfo=IST)


class StandardsTest(unittest.TestCase):
    def test_library_matches_nist_acvp_keygen_vectors(self) -> None:
        data = json.loads(VECTORS.read_text())
        for case in data["ml_kem_768_keygen"]:
            key = MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(case["d"] + case["z"]))
            self.assertEqual(hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest(), case["ek_sha256"])
        for case in data["ml_dsa_65_keygen"]:
            key = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(case["seed"]))
            self.assertEqual(hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest(), case["pk_sha256"])


class DeliveryTest(unittest.TestCase):
    def test_receipt_names_the_stored_reading_and_resend_is_stored_once(self) -> None:
        office, (board,) = office_with()
        gateway_side, sensor_side = pair(office, board)
        first = reading(0)
        delivery = office.receive_reading(gateway_side, sensor_side.seal(encode_reading(first)))
        kind, tank_time, sequence = decode_notice(sensor_side.open(delivery.receipt))
        self.assertEqual((kind, tank_time, sequence), (RECEIPT, first.tank_time, 1))
        again = office.receive_reading(gateway_side, sensor_side.seal(encode_reading(first)))
        self.assertTrue(again.duplicate)
        self.assertEqual(office.store.count(DEVICE_ID), 1)

    def test_buffered_flag_survives_the_record(self) -> None:
        item = Reading(50.0, 1.9, 0.5, 280, 7.3, 27.0, 31.0, 1_791_000_000, BUFFERED)
        office, (board,) = office_with()
        gateway_side, sensor_side = pair(office, board)
        shown = office.receive_reading(gateway_side, sensor_side.seal(encode_reading(item))).reading
        self.assertTrue(shown["buffered"])

    def test_store_restores_history_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wardlink.db"
            office, (board,) = office_with(store=Store(path))
            gateway_side, sensor_side = pair(office, board)
            for index in range(4):
                office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(index * 10))))
            office.store.close()
            restarted = Office(office.keys, office.roster, store=Store(path))
            self.assertEqual(len(restarted.device().history), 4)
            self.assertEqual(restarted.device().stored, 4)
            restarted.store.close()

    def test_outage_through_real_sockets_loses_nothing(self) -> None:
        with Gateway() as gw:
            controls = Controls()
            world = ScriptedWorld(
                {3: lambda: setattr(controls, "link_down", True), 9: lambda: setattr(controls, "link_down", False)},
                start=NOON,
            )
            result = gw.sensor(12, pace=0.03, world=world, controls=controls)
            self.assertEqual(result["outbox"], 0)
            self.assertEqual(gw.office.store.count(DEVICE_ID), 12)
            self.assertGreaterEqual(gw.office.device().buffered, 6)


class LifecycleTest(unittest.TestCase):
    def test_clone_alarm_then_quarantine(self) -> None:
        office, (board,) = office_with()
        real_gateway, real_sensor = pair(office, board)
        office.receive_reading(real_gateway, real_sensor.seal(encode_reading(reading(0))))
        clone_gateway, clone_sensor = pair(office, board)
        office.receive_reading(clone_gateway, clone_sensor.seal(encode_reading(reading(5))))
        with self.assertRaises(SessionEnded):
            office.receive_reading(real_gateway, real_sensor.seal(encode_reading(reading(10))))
        self.assertIsNotNone(office.device().clone)
        with self.assertRaises(ChannelError):
            pair(office, board)

    def test_revoke_and_reenroll(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            enroll(data)
            keys, roster = load_gateway(data)
            office = Office(keys, roster, store=Store(), data_dir=data)
            old = load_sensor(data)
            office.revoke()
            with self.assertRaises(ChannelError):
                pair(office, old)
            office.reenroll_device()
            fresh = load_sensor(data)
            self.assertNotEqual(fresh.static.kem_public, old.static.kem_public)
            gateway_side, sensor_side = pair(office, fresh)
            office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(0))))
            self.assertEqual(office.device().stored, 1)

    def test_rate_limit(self) -> None:
        office, (board,) = office_with(handshake_limit=3)
        for _ in range(3):
            pair(office, board)
        with self.assertRaises(ChannelError):
            pair(office, board)

    def test_silence_is_flagged_and_cleared(self) -> None:
        office, (board,) = office_with(silent_after=0.2)
        gateway_side, sensor_side = pair(office, board)
        office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(0))))
        time.sleep(0.3)
        office.check_silence()
        self.assertTrue(office.device().silent)
        office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(10))))
        self.assertFalse(office.device().silent)


class SensorFaultTest(unittest.TestCase):
    def test_stuck_no_echo_and_dry_probes(self) -> None:
        stuck_history = [reading(index * 10, distance=1.774) for index in range(5)]
        self.assertIn("stuck", assess(reading(50, distance=1.774), stuck_history, stuck_history)["title"])
        self.assertEqual(assess(reading(0, level=0.0, distance=4.5), [], [])["flag"], "SENSOR")
        dry = assess(reading(0, level=5.0, ntu=40.0), [], [])
        self.assertNotIn("hold", {item["kind"] for item in dry["findings"]})

    def test_world_fault_controls(self) -> None:
        world = World(seed=3, start=NOON)
        world.set_event("noecho")
        self.assertGreater(world.step().distance_m, 4.0)
        world.set_event("normal")
        world.set_event("stuck")
        frozen = {world.step().distance_m for _ in range(4)}
        self.assertEqual(len(frozen), 1)

    def test_world_resume_continues_tank_time(self) -> None:
        world = World(seed=1)
        world.resume(61.0, int((NOON + timedelta(hours=3)).timestamp()))
        self.assertEqual(world.step().tank_time, int((NOON + timedelta(hours=3, minutes=10)).timestamp()))


class ServerlessTest(unittest.TestCase):
    def call(self, app, method, path):
        environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": "0", "wsgi.input": io.BytesIO(b"")}
        captured = {}

        def start(status, headers):
            captured["status"] = status

        body = b"".join(app(environ, start))
        return captured["status"], body

    def test_vercel_entry_serves_page_and_advances_the_tank(self) -> None:
        import app as entry
        from wardlink import serverless

        with tempfile.TemporaryDirectory() as tmp:
            serverless._demo = serverless.ServerlessDemo(data_dir=Path(tmp), pace=0.05)
            status, page = self.call(entry.app, "GET", "/")
            self.assertTrue(status.startswith("200") and b"WardLink" in page)
            for _ in range(4):
                time.sleep(0.06)
                status, body = self.call(entry.app, "GET", "/api/state")
            state = json.loads(body)
            self.assertTrue(state["serverless"])
            self.assertGreaterEqual(state["reading"]["seq"], 2)
            status, body = self.call(entry.app, "POST", "/api/rigor/run")
            self.assertTrue(status.startswith("409"))
            serverless._demo = None


class SuiteTest(unittest.TestCase):
    def test_suite_has_every_category_and_quick_scenarios_pass(self) -> None:
        categories = {category for _ident, category, _title, _fn in SCENARIOS}
        self.assertEqual(len(categories), 8)
        self.assertGreaterEqual(len(SCENARIOS), 40)
        report = run_suite(only="nist")
        self.assertEqual(report["passed"], report["total"])


if __name__ == "__main__":
    unittest.main()
