import { $, el, post, setText, svgEl } from "./util.js";

const WIRE = [
  {
    id: "tamper",
    title: "Flip one bit in transit",
    attacker: "Changes a single bit of the next capsule somewhere between the tank and the office.",
    layer: "Stopped by the seal",
    button: "Flip a bit in the next capsule",
    url: "/api/attack/tamper",
  },
  {
    id: "replay",
    title: "Replay a recorded capsule",
    attacker: "Records a genuine capsule and sends the copy again, hoping the office logs an old reading as new.",
    layer: "Stopped by the ratchet order",
    button: "Replay the last capsule",
    url: "/api/attack/replay",
  },
  {
    id: "impostor",
    title: "Impostor board",
    attacker: "Builds its own board, names it ward-tank-01, and sends “tank 97%, water clean”.",
    layer: "Stopped by the enrolled keys",
    button: "Send the impostor",
    url: "/api/attack/impostor",
  },
  {
    id: "unknown",
    title: "Unlisted board",
    attacker: "Connects a board that was never enrolled at the ward office.",
    layer: "Stopped by the roster",
    button: "Connect tank-77",
    url: "/api/attack/unknown",
  },
  {
    id: "capture",
    title: "Steal the board",
    attacker: "Unbolts the unit from the roof and dumps its memory to read traffic it recorded earlier.",
    layer: "Limited by the ratchet, healed by re-key",
    button: "Steal the board now",
    url: "/api/attack/capture",
    extras: [{ label: "Re-key now", url: "/api/rekey" }],
  },
  {
    id: "clone",
    title: "Clone the board",
    attacker: "Builds a second board from keys dumped out of a stolen unit. Its capsules are genuine, so cryptography alone cannot tell the two apart.",
    layer: "Caught by the clone alarm, fixed by re-enrolling",
    button: "Connect the clone",
    url: "/api/attack/clone",
    extras: [
      { label: "Revoke", url: "/api/device/revoke" },
      { label: "Re-enroll on site", url: "/api/device/reenroll" },
    ],
    records: ["clone", "revoke", "reenroll"],
  },
  {
    id: "link",
    title: "Radio outage",
    attacker: "Not an attacker: rain fade, a dead repeater or a power cut on the roof takes the link away for a while.",
    layer: "Absorbed by the board's outbox, flagged by the watchdog",
    button: "Cut the radio link",
    url: "/api/link/down",
    extras: [{ label: "Restore the link", url: "/api/link/up" }],
  },
];

const TANK = [
  {
    id: "leak",
    title: "Night leak",
    attacker: "A joint on the outlet main starts leaking (or someone taps the line).",
    layer: "Caught by the tanker forecast and the night-flow test",
    button: "Start the leak",
    url: "/api/world/leak",
    flags: ["LEAK", "TANKER"],
  },
  {
    id: "contaminate",
    title: "Dirty supply",
    attacker: "Muddy water enters through the inlet after a pipe repair upstream.",
    layer: "Caught by the IS 10500 limits",
    button: "Contaminate the supply",
    url: "/api/world/contaminate",
    flags: ["SAMPLE", "CHECK"],
  },
  {
    id: "spoof",
    title: "Plate under the sensor",
    attacker: "Holds a plate under the ultrasonic sensor so the tank looks full. Every capsule stays genuine and correctly sealed.",
    layer: "Caught only by the physics check",
    button: "Block the sensor",
    url: "/api/world/spoof",
    flags: ["SENSOR"],
  },
  {
    id: "stuck",
    title: "Frozen level sensor",
    attacker: "The sensor's firmware hangs and keeps repeating its last distance.",
    layer: "Caught by the stuck-sensor rule after six readings",
    button: "Freeze the sensor",
    url: "/api/world/stuck",
    flags: ["SENSOR"],
  },
  {
    id: "noecho",
    title: "No echo",
    attacker: "Condensation covers the transducer, so its pulse never comes back.",
    layer: "Caught as a sensor fault; no tanker is sent on it",
    button: "Fog the transducer",
    url: "/api/world/noecho",
    flags: ["SENSOR"],
  },
  {
    id: "spike",
    title: "Bubble on the turbidity probe",
    attacker: "One reading jumps above 5 NTU because a bubble crossed the optics.",
    layer: "Waits for a second reading instead of a false alarm",
    button: "Send a bubble",
    url: "/api/world/spike",
    flags: ["CHECK"],
  },
  {
    id: "normal",
    title: "Back to normal",
    attacker: "Fix the leak, remove the plate, clean and restart the sensors, clean supply.",
    layer: "Resets the tank",
    button: "Restore",
    url: "/api/world/normal",
  },
];

const LAYERS = ["Roster", "ML-KEM handshake", "Seal", "Ratchet", "Re-key", "Clone alarm", "Outbox", "Tank physics", "IS 10500"];
const MATRIX = [
  ["Recorded today, decrypted by a future quantum computer", { "ML-KEM handshake": "stops" }],
  ["Flip a bit in transit", { Seal: "stops" }],
  ["Replay a capsule", { Ratchet: "stops" }],
  ["Impostor board", { "ML-KEM handshake": "stops" }],
  ["Unlisted board", { Roster: "stops" }],
  ["Stolen board, past traffic", { Ratchet: "stops" }],
  ["Stolen board, future traffic", { "Re-key": "stops" }],
  ["Clone built from stolen keys", { "Clone alarm": "stops" }],
  ["Radio outage or gateway restart", { Outbox: "absorbs" }],
  ["Plate under the sensor", { "Tank physics": "stops" }],
  ["Frozen sensor or no echo", { "Tank physics": "stops" }],
  ["Dirty water", { "IS 10500": "stops" }],
  ["Bubble on the probe", { "IS 10500": "waits" }],
  ["Leak or illegal tap", { "Tank physics": "stops" }],
];

function card(spec, app, group) {
  const box = el("div", { class: "card", "data-id": spec.id });
  box.append(el("h3", {}, spec.title), el("p", {}, spec.attacker), el("p", { class: "layer" }, spec.layer));
  const result = el("p", { class: "result" });
  box.append(result);
  const actions = el("div", { class: "order-actions" });
  const run = async (url, button) => {
    button.disabled = true;
    const response = await post(url, url === "/api/rekey" ? {} : undefined);
    button.disabled = false;
    if (!response.ok) {
      result.textContent = response.data.error || "The gateway refused the request.";
      result.className = "result pending";
    } else if (response.data.text) {
      result.textContent = response.data.text;
      result.className = "result pending";
    }
    app.refresh();
  };
  const button = el("button", { type: "button", class: "secondary-dark" }, spec.button);
  button.addEventListener("click", () => run(spec.url, button));
  actions.append(button);
  for (const extra of spec.extras || []) {
    const other = el("button", { type: "button", class: "secondary-dark" }, extra.label);
    other.addEventListener("click", () => run(extra.url, other));
    actions.append(other);
  }
  box.append(actions);
  return box;
}

function drawMatrix() {
  const table = el("table", { class: "data matrix" });
  const head = el("tr");
  head.append(el("th", {}, "Attack or fault"));
  LAYERS.forEach((layer) => head.append(el("th", {}, layer)));
  table.append(head);
  MATRIX.forEach(([attack, cells]) => {
    const row = el("tr");
    row.append(el("td", {}, attack));
    LAYERS.forEach((layer) => row.append(el("td", cells[layer] ? { class: "stop" } : {}, cells[layer] || "")));
    table.append(row);
  });
  $("#matrix").replaceChildren(table);
}

function latestRecord(attacks, names) {
  return names.map((name) => attacks[name]).filter(Boolean).sort((a, b) => (a.at < b.at ? 1 : -1))[0];
}

function drawTape(snap) {
  const svg = $("#tape");
  svg.replaceChildren();
  const history = snap.history.slice(-24);
  if (!history.length) return;
  const captured = snap.captured;
  const width = 1000 / 24;
  const stolenAt = captured
    ? (snap.history.find((h) => h.session_id === captured.session_id && h.seq === captured.seq) || { tank_time: 0 }).tank_time
    : 0;
  let previousSession = null;
  history.forEach((item, index) => {
    const x = index * width + 2;
    let cls = "cell-sealed";
    if (captured) {
      if (item.session_id === captured.session_id && captured.exposed.includes(item.seq)) cls = "cell-exposed";
      else if (item.session_id !== captured.session_id && item.tank_time > stolenAt) cls = "cell-new";
    }
    svgEl("rect", { class: cls, x, y: 40, width: width - 4, height: 40, rx: 3, opacity: item.buffered ? 0.7 : 1 }, svg);
    const label = svgEl("text", { class: "cell-text", x: x + (width - 4) / 2, y: 65 }, svg);
    label.textContent = String(item.seq);
    if (previousSession !== null && item.session_id !== previousSession) {
      svgEl("line", { class: "tape-mark", x1: x - 2, y1: 26, x2: x - 2, y2: 94 }, svg);
      const text = svgEl("text", { class: "tape-label", x: Math.min(x + 2, 820), y: 20 }, svg);
      text.textContent = `new session ${item.session_id}`;
    }
    if (captured && item.session_id === captured.session_id && item.seq === captured.seq) {
      svgEl("line", { class: "tape-mark", x1: x + width - 2, y1: 30, x2: x + width - 2, y2: 110 }, svg);
      const text = svgEl("text", { class: "tape-label", x: Math.min(x + width + 2, 860), y: 108 }, svg);
      text.textContent = "board stolen here";
    }
    previousSession = item.session_id;
  });
  if (!captured) {
    setText("#tape-note", "Each cell is one reading, sealed with its own key; faded cells were buffered on the board during an outage. Steal the board to see which readings its memory can open.");
  } else if (captured.healed) {
    setText("#tape-note", `Stolen after reading ${captured.seq}: none of the ${captured.tried.length} earlier capsules opened. ${captured.exposed.length} later capsule(s) were readable until the re-key; the new session is sealed again.`);
  } else {
    setText("#tape-note", `Stolen after reading ${captured.seq}: none of the ${captured.tried.length} earlier capsules opened. Later capsules stay readable to the thief (${captured.exposed.length} so far) until you re-key.`);
  }
}

export function init(app) {
  $("#wire-cards").replaceChildren(...WIRE.map((spec) => card(spec, app, "wire")));
  $("#tank-cards").replaceChildren(...TANK.map((spec) => card(spec, app, "tank")));
  drawMatrix();
}

export function render(snap) {
  const delivery = snap.delivery || {};
  for (const spec of WIRE) {
    const box = $(`#wire-cards .card[data-id="${spec.id}"]`);
    const result = box.querySelector(".result");
    if (spec.id === "link") {
      box.querySelectorAll("button").forEach((button) => { button.disabled = !snap.demo; });
      const down = snap.controls && snap.controls.link_down;
      box.classList.toggle("on", Boolean(down));
      if (!snap.demo) {
        result.textContent = "The radio switch needs the demo: python -m wardlink demo";
        result.className = "result pending";
      } else if (down) {
        result.textContent = `Radio off. The board has ${snap.controls.outbox} reading(s) waiting in its outbox${delivery.silent ? "; the watchdog has flagged the silence" : ""}.`;
        result.className = "result pending";
      } else if (delivery.buffered) {
        result.textContent = `Link up. ${delivery.buffered} reading(s) were buffered on the board and delivered in order with their original tank times; ${delivery.duplicates} resend(s) were recognised and ignored.`;
        result.className = "result";
      }
      continue;
    }
    const attack = latestRecord(snap.attacks, spec.records || [spec.id]);
    if (attack) {
      result.textContent = `${attack.text} (${attack.at})`;
      result.className = attack.done ? "result" : "result pending";
    }
    if (spec.id === "clone") box.classList.toggle("on", Boolean(snap.clone));
  }
  const world = snap.world;
  const reading = snap.reading;
  for (const spec of TANK) {
    const box = $(`#tank-cards .card[data-id="${spec.id}"]`);
    const result = box.querySelector(".result");
    box.querySelector("button").disabled = !snap.demo;
    if (!snap.demo) {
      result.textContent = "Tank controls need the demo: python -m wardlink demo";
      result.className = "result pending";
      continue;
    }
    const states = { leak: world && world.leak, spoof: world && world.spoof, contaminate: world && world.contamination, stuck: world && world.stuck, noecho: world && world.noecho };
    const spiked = spec.id === "spike" && reading && reading.assessment.title.includes("spike");
    const on = Boolean(states[spec.id]) || spiked;
    box.classList.toggle("on", on);
    if (on && reading && spec.flags) {
      const a = reading.assessment;
      const answered = spec.flags.includes(a.flag);
      result.textContent = answered ? `Office response: ${a.title}. ${a.reason}` : `Active in the tank. Latest reading: ${a.title.toLowerCase()}.`;
      result.className = answered ? "result" : "result pending";
    }
  }
  drawTape(snap);
}
