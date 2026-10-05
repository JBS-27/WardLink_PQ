"""The physical tank the sensor sits on. Simulation only; nothing here crosses the channel.

The model follows how a ward overhead tank behaves under intermittent supply:
the main fills it twice a day, homes draw it down, the first water after the
main is recharged is often dirty, and the ultrasonic level sensor needs the
air temperature because sound travels faster in a hot tank.

One step is ten minutes of tank time.
"""

from __future__ import annotations

import math
import random
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from wardlink.record import Reading

IST = timezone(timedelta(hours=5, minutes=30))
STEP_SECONDS = 600
SUPPLY_WINDOWS = ((5 * 60, 7 * 60 + 30), (17 * 60, 18 * 60 + 30))
INFLOW_PCT_PER_STEP = 5.4
OVERFLOW_PCT = 98.0
DEMAND_PCT_PER_STEP = ((0, 0.15), (5, 0.8), (6, 2.0), (9, 0.9), (12, 0.7), (17, 1.0), (18, 1.8), (21, 0.5))
LEAK_PCT_PER_STEP = 0.4
SPOOF_DISTANCE_M = 0.33
NO_ECHO_DISTANCE_M = 4.50
SPIKE_NTU = 6.5


@dataclass(frozen=True)
class Tank:
    column_m: float = 3.2
    headroom_m: float = 0.30
    capacity_kl: float = 120.0

    def distance_for(self, level_pct: float) -> float:
        return self.headroom_m + (1 - level_pct / 100) * self.column_m

    def level_for(self, distance_m: float) -> float:
        level = (self.headroom_m + self.column_m - distance_m) / self.column_m * 100
        return max(0.0, min(100.0, level))


TANK = Tank()


def minute_of_day(moment: datetime) -> int:
    local = moment.astimezone(IST)
    return local.hour * 60 + local.minute


def supplying(moment: datetime) -> bool:
    minute = minute_of_day(moment)
    return any(start <= minute < end for start, end in SUPPLY_WINDOWS)


def demand_for(moment: datetime) -> float:
    hour = moment.astimezone(IST).hour
    rate = DEMAND_PCT_PER_STEP[0][1]
    for start, value in DEMAND_PCT_PER_STEP:
        if hour >= start:
            rate = value
    return rate


def speed_of_sound(air_c: float) -> float:
    return 331.3 + 0.606 * air_c


class World:
    def __init__(self, start: datetime | None = None, level_pct: float = 36.0, seed: int = 4):
        today = datetime.now(IST).replace(hour=4, minute=20, second=0, microsecond=0)
        self.now = start or today
        self.level = level_pct
        self.rng = random.Random(seed)
        self.lock = threading.Lock()
        self.leak = False
        self.spoof = False
        self.contamination = 0
        self.flush = 0
        self.stuck_at: float | None = None
        self.stuck = False
        self.no_echo = False
        self.spike = False
        self._was_supplying = supplying(self.now)
        self._last_distance = TANK.distance_for(self.level)

    def resume(self, level_pct: float, tank_time: int) -> None:
        """Continue from the last stored reading, so a restart does not repeat tank times."""
        with self.lock:
            self.level = max(2.0, min(OVERFLOW_PCT, level_pct))
            self.now = datetime.fromtimestamp(tank_time, IST)
            self._was_supplying = supplying(self.now)
            self._last_distance = TANK.distance_for(self.level)

    def set_event(self, name: str) -> str:
        with self.lock:
            if name == "leak":
                self.leak = True
                return "A pipe joint on the outlet main starts leaking."
            if name == "contaminate":
                self.contamination = 6
                return "Dirty water starts entering the tank through the inlet."
            if name == "spoof":
                self.spoof = True
                return "Someone holds a plate under the level sensor."
            if name == "stuck":
                self.stuck = True
                self.stuck_at = self._last_distance
                return "The level sensor's firmware hangs and keeps repeating its last distance."
            if name == "noecho":
                self.no_echo = True
                return "Condensation covers the ultrasonic transducer; its pulse gets no echo."
            if name == "spike":
                self.spike = True
                return "A bubble crosses the turbidity probe's optics for one reading."
            if name == "normal":
                self.leak = False
                self.spoof = False
                self.contamination = 0
                self.stuck = False
                self.stuck_at = None
                self.no_echo = False
                self.spike = False
                return "Leak fixed, sensors cleaned and restarted, supply clean."
        raise ValueError(name)

    def events(self) -> dict:
        with self.lock:
            return {
                "leak": self.leak,
                "spoof": self.spoof,
                "contamination": self.contamination > 0,
                "stuck": self.stuck,
                "noecho": self.no_echo,
                "supplying": supplying(self.now),
                "tank_time": int(self.now.timestamp()),
            }

    def step(self) -> Reading:
        with self.lock:
            self.now += timedelta(seconds=STEP_SECONDS)
            rng = self.rng
            on_supply = supplying(self.now)
            if on_supply and not self._was_supplying and rng.random() < 0.6:
                self.flush = 3
            self._was_supplying = on_supply

            inflow = INFLOW_PCT_PER_STEP if on_supply else 0.0
            outflow = demand_for(self.now) * rng.uniform(0.85, 1.15)
            if self.leak:
                outflow += LEAK_PCT_PER_STEP
            self.level = max(2.0, min(OVERFLOW_PCT, self.level + inflow - outflow))

            local = self.now.astimezone(IST)
            hour = local.hour + local.minute / 60
            air_c = 31 + 8 * math.sin((hour - 9) / 24 * 2 * math.pi) + rng.gauss(0, 0.3)
            water_c = 27.5 + 1.5 * math.sin((hour - 11) / 24 * 2 * math.pi) + rng.gauss(0, 0.1)

            turbidity = rng.uniform(0.35, 0.85)
            tds = rng.gauss(290, 8)
            ph = rng.gauss(7.32, 0.04)
            if self.flush:
                turbidity += (0.9, 1.6, 2.6)[self.flush - 1]
                self.flush -= 1
            if self.contamination:
                weight = (0.2, 0.4, 0.6, 0.8, 0.95, 1.0)[self.contamination - 1]
                turbidity += 16 * weight
                tds += 650 * weight
                ph -= 0.95 * weight
                self.contamination -= 1
            if self.spike:
                turbidity += SPIKE_NTU
                self.spike = False

            distance = SPOOF_DISTANCE_M if self.spoof else TANK.distance_for(self.level)
            sound = speed_of_sound(air_c)
            echo_s = 2 * distance / sound * (1 + rng.gauss(0, 0.0006))
            measured = sound * echo_s / 2
            if self.no_echo:
                measured = NO_ECHO_DISTANCE_M
            elif self.stuck and self.stuck_at is not None:
                measured = self.stuck_at
            self._last_distance = measured

            return Reading(
                level_pct=round(TANK.level_for(measured), 1),
                distance_m=round(measured, 3),
                turbidity_ntu=round(turbidity, 1),
                tds_mgl=int(round(tds)),
                ph=round(ph, 2),
                water_c=round(water_c, 1),
                air_c=round(air_c, 1),
                tank_time=int(self.now.timestamp()),
            )
