"""What the section office should do about one verified reading.

The channel proves the reading came from the enrolled board and was not
changed. These rules add the two checks the channel cannot make: whether the
water is fit to drink (IS 10500:2012), and whether the level is physically
possible for this tank.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from wardlink.record import Reading
from wardlink.world import (
    DEMAND_PCT_PER_STEP,
    INFLOW_PCT_PER_STEP,
    IST,
    OVERFLOW_PCT,
    STEP_SECONDS,
    SUPPLY_WINDOWS,
    TANK,
    minute_of_day,
)

ACCEPTABLE_NTU = 1.0
PERMISSIBLE_NTU = 5.0
PH_LOW, PH_HIGH = 6.5, 8.5
ACCEPTABLE_TDS = 500
PERMISSIBLE_TDS = 2000
NIGHT_WINDOW = (60, 240)
NIGHT_DRAW_LIMIT_PCT_H = 2.4
FALL_LIMIT_PCT_H = 40.0
TANKER_FLOOR_PCT = 10.0
OVERFLOW_MARGIN = 0.5
BLIND_ZONE_M = 0.22
PROBE_LEVEL_PCT = 8.0
STUCK_READINGS = 6
STUCK_TOLERANCE_M = 0.0005
CONFIRM_FACTOR = 3.0
PH_EXTREME = (5.5, 9.5)

# Typical draw by hour for this ward. In the field this is learned from a few weeks of readings.
USAGE_PROFILE = DEMAND_PCT_PER_STEP

FLAGS = {
    "sensor": "SENSOR",
    "fault": "SENSOR",
    "hold": "SAMPLE",
    "ph": "SAMPLE",
    "leak": "LEAK",
    "tanker": "TANKER",
    "advice": "CHECK",
    "confirm": "CHECK",
    "dry": "CHECK",
}
SENSOR_STEPS = [
    "Do not send a tanker or open valves on this level reading.",
    "Send the line inspector to the tank roof to look at the level sensor.",
    "Keep using the turbidity, TDS and pH readings; they come from other probes.",
]


def _when(reading: Reading) -> datetime:
    return datetime.fromtimestamp(reading.tank_time, IST)


def _in_supply(moment: datetime) -> bool:
    minute = minute_of_day(moment)
    return any(start <= minute < end for start, end in SUPPLY_WINDOWS)


def _profile(moment: datetime) -> float:
    hour = moment.astimezone(IST).hour
    rate = USAGE_PROFILE[0][1]
    for start, value in USAGE_PROFILE:
        if hour >= start:
            rate = value
    return rate


def _next_supply(moment: datetime) -> datetime:
    local = moment.astimezone(IST)
    for day in range(2):
        base = (local + timedelta(days=day)).replace(hour=0, minute=0, second=0, microsecond=0)
        for start, _end in SUPPLY_WINDOWS:
            candidate = base + timedelta(minutes=start)
            if candidate > local:
                return candidate
    return local + timedelta(hours=12)


def _hm(moment: datetime) -> str:
    return moment.astimezone(IST).strftime("%H:%M")


def _duration(minutes: int) -> str:
    hours, rest = divmod(minutes, 60)
    if hours and rest:
        return f"{hours} h {rest} min"
    if hours:
        return f"{hours} h"
    return f"{rest} min"


def physics_check(reading: Reading, trusted: list[Reading]) -> tuple[bool, str, float | None]:
    """Return (plausible, reason, rate in %/hour against the last trusted reading)."""
    if reading.level_pct > OVERFLOW_PCT + OVERFLOW_MARGIN:
        return False, (
            f"The level reads {reading.level_pct:.0f}%, above the overflow pipe at {OVERFLOW_PCT:.0f}%. "
            "Water cannot stand there; something is under the sensor."
        ), None
    if not trusted:
        return True, "First reading of this session; nothing to compare yet.", None
    last = trusted[-1]
    hours = (reading.tank_time - last.tank_time) / 3600
    if hours <= 0:
        return True, "Same tank time as the last reading.", None
    change = reading.level_pct - last.level_pct
    rate = change / hours
    steps = hours * 3600 / STEP_SECONDS
    supply_now = _in_supply(_when(reading)) or _in_supply(_when(last))
    max_rise = (INFLOW_PCT_PER_STEP * 1.15 * steps + 2.0) if supply_now else (0.6 * steps + 1.0)
    if change > max_rise:
        why = "the inlet can add" if supply_now else "with the main closed it can rise"
        return False, (
            f"Level rose {change:.0f} points in {hours * 60:.0f} min; {why} at most {max_rise:.0f}. "
            "Treat the level as untrusted until someone checks the sensor."
        ), rate
    if rate < -FALL_LIMIT_PCT_H:
        return False, (
            f"Level fell {-change:.0f} points in {hours * 60:.0f} min, faster than any normal draw. "
            "Either the outlet main burst or the sensor is faulty."
        ), rate
    return True, f"Change of {change:+.1f} points fits this tank's inlet and draw.", rate


def _finding(kind: str, severity: int, title: str, text: str, steps: list[str], **extra) -> dict:
    return {"kind": kind, "severity": severity, "title": title, "text": text, "steps": steps, **extra}


def sensor_faults(reading: Reading, previous: list[Reading]) -> list[dict]:
    """Faults in the instruments themselves. `level` marks faults that make the level untrustworthy."""
    faults: list[dict] = []
    floor = TANK.headroom_m + TANK.column_m
    if reading.distance_m >= floor + 0.05:
        faults.append(_finding(
            "fault", 3, "Level sensor gets no echo",
            f"The sensor reports {reading.distance_m:.2f} m, below the tank floor at {floor:.2f} m. The pulse "
            "came back with no echo: a wet or iced transducer, foam, a loose cable, or the sensor knocked sideways.",
            SENSOR_STEPS, level=True,
        ))
    elif reading.distance_m < BLIND_ZONE_M:
        faults.append(_finding(
            "fault", 3, "Something is inside the sensor's blind zone",
            f"The sensor reports {reading.distance_m:.2f} m, closer than it can measure ({BLIND_ZONE_M:.2f} m). "
            "An object, a spider's web or condensation is on the transducer.",
            SENSOR_STEPS, level=True,
        ))
    window = [*previous[-(STUCK_READINGS - 1):], reading]
    if len(window) >= STUCK_READINGS and 3.0 < reading.level_pct < 97.0:
        distances = [item.distance_m for item in window]
        if max(distances) - min(distances) <= STUCK_TOLERANCE_M:
            faults.append(_finding(
                "fault", 3, "Level sensor is stuck",
                f"The last {len(window)} readings all report {reading.distance_m:.3f} m. A working tank moves by "
                "millimetres every ten minutes, so the sensor or its firmware has frozen.",
                SENSOR_STEPS + ["Power-cycle the board remotely if possible; replace the sensor if it stays frozen."],
                level=True,
            ))
    if not 0.5 <= reading.ph <= 13.5:
        faults.append(_finding(
            "fault", 2, "pH probe fault",
            f"pH {reading.ph:.2f} is not a value tap water can have. The probe is dry, broken or disconnected.",
            ["Ignore pH until the probe is checked.", "Recalibrate in pH 4 and pH 7 buffers or replace the probe."],
            probe="ph",
        ))
    if reading.turbidity_ntu >= 1000:
        faults.append(_finding(
            "fault", 2, "Turbidity probe fault",
            "The probe reads at the top of its range: fouled optics, out of the water, or disconnected.",
            ["Ignore turbidity until the probe is cleaned and checked."],
            probe="turbidity",
        ))
    return faults


def _quality(reading: Reading, previous: list[Reading], skip: set[str]) -> list[dict]:
    """IS 10500 checks. A single bad reading asks for confirmation unless the value is extreme."""
    findings: list[dict] = []
    last = previous[-1] if previous else None
    if "turbidity" not in skip:
        ntu = reading.turbidity_ntu
        if ntu > PERMISSIBLE_NTU and (ntu > PERMISSIBLE_NTU * CONFIRM_FACTOR or (last and last.turbidity_ntu > PERMISSIBLE_NTU)):
            findings.append(_finding(
                "hold", 3, "Hold the safe-water notice",
                f"Turbidity {ntu:.1f} NTU is above the IS 10500 permissible limit of {PERMISSIBLE_NTU:.0f} NTU.",
                [
                    "Tell the ward office not to declare this water safe.",
                    "Collect a sample at the outlet tap and send it to the lab.",
                    "Ask the pumping station whether the main was just recharged or repaired.",
                ],
            ))
        elif ntu > PERMISSIBLE_NTU:
            findings.append(_finding(
                "confirm", 1, "Turbidity spike, confirming",
                f"Turbidity jumped to {ntu:.1f} NTU in one reading. A bubble or debris on the optics can do that, "
                f"so the office holds the notice only if the next reading is also above {PERMISSIBLE_NTU:.0f} NTU "
                f"(or at once above {PERMISSIBLE_NTU * CONFIRM_FACTOR:.0f} NTU).",
                ["Watch the next reading; no crew yet."],
            ))
        elif ntu > ACCEPTABLE_NTU:
            findings.append(_finding(
                "advice", 1, "Turbidity above the acceptable limit",
                f"Turbidity {ntu:.1f} NTU is above the IS 10500 acceptable 1 NTU but within the 5 NTU permissible "
                "limit. Usual right after the main is recharged.",
                ["Take a confirmatory sample if it stays above 1 NTU after the first flush."],
            ))
    if "ph" not in skip and not PH_LOW <= reading.ph <= PH_HIGH:
        extreme = not PH_EXTREME[0] <= reading.ph <= PH_EXTREME[1]
        repeated = last is not None and not PH_LOW <= last.ph <= PH_HIGH
        if extreme or repeated:
            findings.append(_finding(
                "ph", 2, "pH out of range",
                f"pH {reading.ph:.2f} is outside 6.5 to 8.5. IS 10500 allows no relaxation for pH.",
                ["Collect a sample for a lab pH test before the next supply."],
            ))
        else:
            findings.append(_finding(
                "confirm", 1, "pH out of range once, confirming",
                f"pH {reading.ph:.2f} is outside 6.5 to 8.5 in one reading; the office acts if the next one agrees.",
                ["Watch the next reading."],
            ))
    tds = reading.tds_mgl
    if tds > PERMISSIBLE_TDS and (tds > PERMISSIBLE_TDS * 1.5 or (last and last.tds_mgl > PERMISSIBLE_TDS)):
        findings.append(_finding(
            "hold", 3, "Reject this supply",
            f"TDS {tds} mg/L is above the IS 10500 permissible 2000 mg/L.",
            ["Tell the ward office not to supply this water for drinking."],
        ))
    elif tds > PERMISSIBLE_TDS:
        findings.append(_finding(
            "confirm", 1, "TDS spike, confirming",
            f"TDS jumped to {tds} mg/L in one reading; the office acts if the next one agrees.",
            ["Watch the next reading."],
        ))
    elif tds > ACCEPTABLE_TDS:
        findings.append(_finding(
            "advice", 1, "Dissolved solids above the acceptable limit",
            f"TDS {tds} mg/L is above the acceptable 500 mg/L (permissible 2000).",
            ["Note it in the log and compare with the lab's monthly sample."],
        ))
    return findings


def assess(reading: Reading, trusted: list[Reading], previous: list[Reading] | None = None) -> dict:
    previous = list(previous or [])
    findings: list[dict] = []
    moment = _when(reading)
    faults = sensor_faults(reading, previous)
    level_fault = next((fault for fault in faults if fault.get("level")), None)
    if level_fault:
        plausible, physics_reason, rate = False, level_fault["text"], None
    else:
        plausible, physics_reason, rate = physics_check(reading, trusted)
        if not plausible:
            findings.append(_finding("sensor", 3, "Check the level sensor on site", physics_reason, SENSOR_STEPS))
    findings.extend(faults)

    if plausible and reading.level_pct < PROBE_LEVEL_PCT:
        findings.append(_finding(
            "dry", 1, "Probes are out of the water",
            f"The tank is at {reading.level_pct:.0f}%, below the probes at about {PROBE_LEVEL_PCT:.0f}%. Turbidity, "
            "TDS and pH are measuring air, so no water-quality alarm is raised until the tank refills.",
            ["Do not use this reading's water quality.", "Quality checks resume when the tank refills."],
        ))
    else:
        skip = {fault["probe"] for fault in faults if fault.get("probe")}
        findings.extend(_quality(reading, previous, skip))

    projection = None
    if plausible:
        night = NIGHT_WINDOW[0] <= minute_of_day(moment) < NIGHT_WINDOW[1]
        recent = [item for item in trusted if 0 < reading.tank_time - item.tank_time <= 3600]
        if night and recent and not _in_supply(moment):
            oldest = recent[0]
            hours = (reading.tank_time - oldest.tank_time) / 3600
            draw = (oldest.level_pct - reading.level_pct) / hours if hours else 0.0
            if draw > NIGHT_DRAW_LIMIT_PCT_H:
                findings.append(
                    {
                        "kind": "leak",
                        "severity": 2,
                        "title": "Likely leak on the outlet side",
                        "text": (
                            f"Night draw is {draw:.1f}% per hour between 01:00 and 04:00, when homes use "
                            f"under 1% per hour. This is the minimum-night-flow test water utilities use."
                        ),
                        "steps": [
                            "Walk the outlet main at first light and listen at valves and joints.",
                            "Look for an unauthorised connection near the tank.",
                            "Compare with tomorrow night's draw to confirm.",
                        ],
                    }
                )

        projection = _project(reading, trusted)
        if projection and projection["empty_at"] and not _in_supply(moment):
            findings.append(
                {
                    "kind": "tanker",
                    "severity": 2,
                    "title": "Send a water tanker",
                    "text": (
                        f"At today's draw the tank falls below {TANKER_FLOOR_PCT:.0f}% around "
                        f"{projection['empty_at']}, {_duration(projection['dry_minutes'])} before the "
                        f"{projection['supply_at']} supply."
                    ),
                    "steps": [
                        f"Book a tanker for Ward 4 before {projection['empty_at']}.",
                        "Check the inlet valve schedule with the pumping station.",
                        "If the leak alert is also on, fix the leak first or the tanker water drains the same way.",
                    ],
                }
            )

    findings.sort(key=lambda item: item["severity"], reverse=True)
    if findings:
        head = findings[0]
        steps: list[str] = []
        for finding in findings:
            for step in finding["steps"]:
                if step not in steps:
                    steps.append(step)
        severity = head["severity"]
        result = {
            "required": severity >= 2,
            "severity": severity,
            "flag": FLAGS[head["kind"]],
            "title": head["title"],
            "reason": head["text"],
            "steps": steps,
        }
    else:
        result = {
            "required": False,
            "severity": 0,
            "flag": "LOG",
            "title": "Routine watch",
            "reason": "Level, turbidity, TDS and pH are inside the IS 10500 limits and this tank's physics.",
            "steps": ["No crew needed.", "Mark seen to close the watch in the log."],
        }
    result["findings"] = [{key: item[key] for key in ("kind", "severity", "title", "text")} for item in findings]
    result["physics"] = {"plausible": plausible, "reason": physics_reason, "rate_pct_h": rate}
    result["projection"] = projection
    return result


def _project(reading: Reading, trusted: list[Reading]) -> dict | None:
    """Walk the usual draw forward to the next supply, plus any unusual extra draw seen in the last hour."""
    moment = _when(reading)
    supply_at = _next_supply(moment)
    recent = [item for item in trusted if 0 < reading.tank_time - item.tank_time <= 3600]
    excess = 0.0
    if recent and not _in_supply(moment):
        oldest = recent[0]
        steps = (reading.tank_time - oldest.tank_time) / STEP_SECONDS
        if steps >= 1:
            observed = (oldest.level_pct - reading.level_pct) / steps
            expected = sum(
                _profile(datetime.fromtimestamp(oldest.tank_time + STEP_SECONDS * (index + 1), IST))
                for index in range(int(steps))
            ) / int(steps)
            excess = max(0.0, observed - expected)
    level = reading.level_pct
    cursor = moment
    empty_at = None
    lead_minutes = 0
    while cursor < supply_at:
        cursor += timedelta(seconds=STEP_SECONDS)
        level -= _profile(cursor) + excess
        if level < TANKER_FLOOR_PCT and empty_at is None and cursor < supply_at:
            empty_at = _hm(cursor)
            lead_minutes = int((supply_at - cursor).total_seconds() // 60)
    return {
        "supply_at": _hm(supply_at),
        "level_at_supply": round(max(level, 0.0), 1),
        "empty_at": empty_at,
        "dry_minutes": lead_minutes,
        "extra_draw_pct_step": round(excess, 2),
    }
