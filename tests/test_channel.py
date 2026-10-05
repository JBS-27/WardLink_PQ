import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from wardlink.bench import lora_airtime_ms, radio_cost
from wardlink.channel import (
    LEAN_WELCOME,
    ML_DSA_SIGNATURE,
    ML_KEM_PUBLIC,
    lean_accept,
    lean_derive,
    lean_hello,
    sensor_hello,
)
from wardlink.crypto import ChannelError, new_identity, new_static_keys, ratchet_step
from wardlink.enroll import GatewayKeys, SensorRecord, enroll, load_gateway, load_sensor
from wardlink.office import Controls, Office
from wardlink.record import READING_BYTES, Reading, decode_reading, encode_reading, json_bytes
from wardlink.rules import assess
from wardlink.service import handle_sensor, listen, run_sensor
from wardlink.world import IST, World

DEVICE = "ward-tank-01"


def sample(level=55.0, turbidity=0.6, ph=7.3, tds=290, at=None) -> Reading:
    moment = at or datetime(2026, 10, 4, 12, 0, tzinfo=IST)
    return Reading(level, 1.8, turbidity, tds, ph, 27.0, 33.0, int(moment.timestamp()))


def step(index: int) -> datetime:
    return datetime(2026, 10, 4, 12, 0, tzinfo=IST) + timedelta(minutes=10 * index)


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = GatewayKeys(new_identity(), new_static_keys())
        self.sensor_identity = new_identity()
        self.sensor_static = new_static_keys()
        self.roster = {
            DEVICE: SensorRecord(
                DEVICE,
                "Ward 4 overhead tank",
                self.sensor_identity.public_key,
                self.sensor_static.kem_public,
                self.sensor_static.x_public,
            )
        }
        self.office = Office(self.gateway, self.roster)

    def lean_pair(self):
        offer = lean_hello(self.sensor_static, DEVICE, self.gateway.static.kem_public, self.gateway.static.x_public)
        welcome, gateway_side = self.office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
        return offer, welcome, gateway_side, offer.finish(welcome)


class HandshakeTest(Fixture):
    def test_lean_is_half_the_signed_bytes(self) -> None:
        offer, welcome, gateway_side, sensor_side = self.lean_pair()
        self.assertEqual(len(welcome), LEAN_WELCOME)
        self.assertEqual(gateway_side.session_id, sensor_side.session_id)
        signed = sensor_hello(self.sensor_identity, DEVICE, time.time_ns() // 1_000_000)
        signed_welcome, _ = self.office.accept_hello(signed.wire, time.time_ns() // 1_000_000)
        self.assertGreater(len(signed.wire), ML_KEM_PUBLIC + ML_DSA_SIGNATURE)
        lean_total = len(offer.wire) + len(welcome)
        signed_total = len(signed.wire) + len(signed_welcome)
        self.assertLess(lean_total, signed_total * 0.55)
        signed.discard()

    def test_session_goes_live_only_after_first_reading(self) -> None:
        _offer, _welcome, gateway_side, sensor_side = self.lean_pair()
        self.assertIsNone(self.office.session)
        self.office.receive_reading(gateway_side, sensor_side.seal(encode_reading(sample())))
        self.assertIs(self.office.session, gateway_side)

    def test_impostor_with_own_keys_is_refused_and_live_session_kept(self) -> None:
        _offer, _welcome, live_gateway, live_sensor = self.lean_pair()
        self.office.receive_reading(live_gateway, live_sensor.seal(encode_reading(sample())))
        rogue = new_static_keys()
        offer = lean_hello(rogue, DEVICE, self.gateway.static.kem_public, self.gateway.static.x_public)
        welcome, gateway_side = lean_accept(offer.wire, self.sensor_static.kem_public, self.sensor_static.x_public, self.gateway.static)
        rogue_side, gateway_proven = lean_derive(offer, welcome)
        self.assertFalse(gateway_proven)
        with self.assertRaises(ChannelError):
            self.office.receive_reading(gateway_side, rogue_side.seal(encode_reading(sample(level=97))))
        self.assertIs(self.office.session, live_gateway)

    def test_fake_gateway_cannot_prove_itself(self) -> None:
        fake_gateway = new_static_keys()
        offer = lean_hello(self.sensor_static, DEVICE, self.gateway.static.kem_public, self.gateway.static.x_public)
        welcome, _ = lean_accept(offer.wire, self.sensor_static.kem_public, self.sensor_static.x_public, fake_gateway)
        with self.assertRaises(ChannelError):
            offer.finish(welcome)

    def test_replayed_hello_gives_attacker_nothing(self) -> None:
        offer, _welcome, live_gateway, live_sensor = self.lean_pair()
        self.office.receive_reading(live_gateway, live_sensor.seal(encode_reading(sample())))
        _replayed_welcome, replay_gateway_side = self.office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
        self.assertNotEqual(replay_gateway_side.session_id, live_gateway.session_id)
        self.assertIs(self.office.session, live_gateway)

    def test_unknown_board_is_refused(self) -> None:
        result = self.office.unknown_board()
        self.assertIn("not on the ward roster", result["text"])

    def test_signed_impostor_is_refused(self) -> None:
        self.office.controls = Controls(mode="signed")
        result = self.office.impostor()
        self.assertIn("did not match", result["text"])


class RatchetTest(Fixture):
    def test_tamper_replay_and_skip(self) -> None:
        _offer, _welcome, gateway_side, sensor_side = self.lean_pair()
        frames = [sensor_side.seal(encode_reading(sample(level=50 + index, at=step(index)))) for index in range(3)]
        self.office.receive_reading(gateway_side, frames[0])
        self.office.arm_tamper()
        with self.assertRaises(ChannelError):
            self.office.receive_reading(gateway_side, frames[1])
        shown = self.office.receive_reading(gateway_side, frames[2]).reading
        self.assertEqual(shown["seq"], 3)
        with self.assertRaises(ChannelError):
            self.office.receive_reading(gateway_side, frames[2])
        self.assertIn("refused", self.office.replay_last()["text"])

    def test_stolen_chain_opens_only_later_readings(self) -> None:
        _offer, _welcome, gateway_side, sensor_side = self.lean_pair()
        for index in range(4):
            self.office.receive_reading(gateway_side, sensor_side.seal(encode_reading(sample(level=40 + index, at=step(index)))))
        result = self.office.capture_board()
        self.assertEqual(self.office.captured["opened_past"], 0)
        self.assertIn("opened 0", result["text"])
        self.office.receive_reading(gateway_side, sensor_side.seal(encode_reading(sample(level=44, at=step(4)))))
        self.assertEqual(self.office.captured["exposed"], [5])

    def test_chain_is_one_way(self) -> None:
        chain = b"\x07" * 32
        key_one, chain_two = ratchet_step(chain)
        key_two, _ = ratchet_step(chain_two)
        self.assertNotEqual(key_one, key_two)
        self.assertNotEqual(chain, chain_two)


class RecordTest(unittest.TestCase):
    def test_round_trip_and_size(self) -> None:
        reading = sample(level=63.4, turbidity=12.3, ph=6.41, tds=944)
        body = encode_reading(reading)
        self.assertEqual(len(body), READING_BYTES)
        self.assertEqual(decode_reading(body), reading)
        self.assertGreater(json_bytes(reading), 150)

    def test_out_of_range_level_refused(self) -> None:
        with self.assertRaises(ChannelError):
            encode_reading(sample(level=120))


class RulesTest(unittest.TestCase):
    def test_turbidity_bands_follow_is_10500(self) -> None:
        self.assertEqual(assess(sample(turbidity=0.7), [])["flag"], "LOG")
        self.assertEqual(assess(sample(turbidity=3.0), [])["flag"], "CHECK")
        spike = assess(sample(turbidity=12.0), [])
        self.assertEqual(spike["flag"], "CHECK")
        heavy = assess(sample(turbidity=20.0), [])
        self.assertEqual(heavy["flag"], "SAMPLE")
        self.assertTrue(heavy["required"])

    def test_ph_has_no_relaxation(self) -> None:
        earlier = sample(ph=6.4, at=datetime(2026, 10, 4, 11, 50, tzinfo=IST))
        self.assertEqual(assess(sample(ph=6.3), [earlier], [earlier])["flag"], "SAMPLE")
        self.assertEqual(assess(sample(ph=5.2), [])["flag"], "SAMPLE")

    def test_level_above_overflow_is_a_sensor_problem(self) -> None:
        result = assess(sample(level=99.5), [])
        self.assertEqual(result["flag"], "SENSOR")
        self.assertFalse(result["physics"]["plausible"])

    def test_rise_without_supply_is_implausible(self) -> None:
        noon = datetime(2026, 10, 4, 12, 0, tzinfo=IST)
        before = sample(level=40, at=noon)
        after = sample(level=70, at=noon + timedelta(minutes=10))
        self.assertEqual(assess(after, [before])["flag"], "SENSOR")

    def test_extra_draw_predicts_tanker(self) -> None:
        noon = datetime(2026, 10, 4, 12, 0, tzinfo=IST)
        history = [sample(level=60 - 1.9 * step, at=noon + timedelta(minutes=10 * step)) for step in range(7)]
        result = assess(sample(level=60 - 1.9 * 7, at=noon + timedelta(minutes=70)), history)
        self.assertEqual(result["flag"], "TANKER")
        self.assertIsNotNone(result["projection"]["empty_at"])


class WorldTest(unittest.TestCase):
    def test_spoof_and_contamination_show_in_readings(self) -> None:
        world = World(seed=1)
        world.set_event("spoof")
        self.assertGreater(world.step().level_pct, 98.5)
        world.set_event("normal")
        world.set_event("contaminate")
        self.assertGreater(world.step().turbidity_ntu, 3)

    def test_level_stays_in_tank(self) -> None:
        world = World(seed=2)
        levels = [world.step().level_pct for _ in range(288)]
        self.assertGreaterEqual(min(levels), 0)
        self.assertLessEqual(max(levels), 98.5)


class RadioTest(unittest.TestCase):
    def test_lora_airtime_matches_semtech_formula(self) -> None:
        self.assertAlmostEqual(lora_airtime_ms(51, 12), 2793.5, delta=1)
        self.assertAlmostEqual(lora_airtime_ms(51, 7), 118.0, delta=1)

    def test_frames_split_by_link_payload(self) -> None:
        cost = radio_cost([2320, 2224])
        self.assertEqual(cost["lora12"]["frames"], 46 + 44)
        self.assertEqual(cost["wifi"]["frames"], 2 + 2)


class EndToEndTest(unittest.TestCase):
    def test_enroll_and_socket_session(self) -> None:
        with TemporaryDirectory() as tmp:
            data = Path(tmp)
            self.assertEqual(enroll(data), "enrolled")
            self.assertEqual(enroll(data), "already enrolled")
            keys, roster = load_gateway(data)
            office = Office(keys, roster)
            listener = listen("127.0.0.1", 0)
            port = listener.getsockname()[1]
            thread = threading.Thread(target=handle_sensor, args=(office, listener))
            thread.start()
            run_sensor(load_sensor(data), port=port, readings=2, pace=0.2)
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(office.latest["seq"], 2)
            self.assertEqual(office.session.mode, "lean")


if __name__ == "__main__":
    unittest.main()
