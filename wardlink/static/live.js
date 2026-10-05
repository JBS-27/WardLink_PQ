import {
  $, $$, FLAG_COLOURS, animate, clamp, ease, el, fmt, lerp, ntuBand, phBand, post, setText, svgEl, tdsBand, waterColour,
} from "./util.js";

const CHAMBER_TOP = 96;
const CHAMBER_H = 260;
const FACE_Y = 112;
const CAPSULE_FROM = 424;
const CAPSULE_TO = 596;
const FLAG_DOWN = 392;
const FLAG_UP = 150;
const MARKS = [["sensing", 0.2], ["securing", 0.38], ["transit", 0.62], ["verify", 0.82], ["action", 1]];

let latest = null;
let playing = null;
let lastKey = null;
let lastSeen = null;
let primed = false;
let lastRefused = null;
let paintedKey = "";
let shownLevel = 40;
let targetLevel = 40;
let flagY = FLAG_DOWN;
let holdUntil = 0;
const HOLD_MS = 25000;

const machine = () => $("#machine");

function surfaceY(level) {
  return CHAMBER_TOP + CHAMBER_H - (CHAMBER_H * clamp(level, 0, 100)) / 100;
}

function placeWater(level, ntu) {
  const y = surfaceY(level);
  const water = $("#water");
  water.setAttribute("y", y);
  water.setAttribute("height", CHAMBER_TOP + CHAMBER_H - y);
  water.style.fill = waterColour(ntu);
  $("#surface").setAttribute("y1", y);
  $("#surface").setAttribute("y2", y);
}

function setStage(stage) {
  $$("#rail button").forEach((button) => button.classList.toggle("active", button.dataset.stage === stage));
  machine().setAttribute("class", stage ? `focus-${stage}` : "");
}

function stageAt(progress) {
  let start = 0;
  for (const [name, end] of MARKS) {
    if (progress <= end) return { name, t: clamp((progress - start) / (end - start), 0, 1) };
    start = end;
  }
  return { name: "action", t: 1 };
}

function lamp(id, state) {
  const node = $(`#${id} .lamp`);
  node.setAttribute("class", `lamp${state ? ` ${state}` : ""}`);
}

function spin(id, degrees) {
  $(`#${id} .spin`).setAttribute("transform", `rotate(${degrees})`);
}

function placeFlag(y, data) {
  flagY = y;
  $("#flag").setAttribute("transform", `translate(960 ${y})`);
  if (data) {
    $("#flag-cloth").style.fill = FLAG_COLOURS[data.assessment.flag] || FLAG_COLOURS.LOG;
    setText("#flag-word", data.assessment.flag);
  }
}

function pulses(t) {
  const path = $("#cable");
  const group = $("#pulses");
  const length = path.getTotalLength();
  while (group.childNodes.length < 3) svgEl("circle", { r: 4, class: "pulse" }, group);
  [...group.childNodes].forEach((dot, index) => {
    const point = path.getPointAtLength(((t + index / 3) % 1) * length);
    dot.setAttribute("cx", point.x);
    dot.setAttribute("cy", point.y);
    dot.setAttribute("opacity", t > 0 && t < 1 ? 1 : 0);
  });
}

function narrate(stage, data) {
  const a = data.assessment;
  const lines = {
    sensing: `Sensing. The ultrasonic pulse came back in ${data.echo_ms} ms, so the water is ${data.distance_m.toFixed(2)} m below the sensor and the tank is ${data.level_pct.toFixed(0)}% full. Turbidity, TDS and pH probes read the same water.`,
    securing: `Securing. The 20-byte reading is sealed with reading key ${data.seq}. Then the ratchet turns one tooth and that key is gone; a thief who steals the board later cannot get it back.`,
    transit: `Transmission. Only this ${data.capsule_bytes}-byte capsule crosses the network. Someone recording it gets random-looking bytes, not the tank level.`,
    verify: `Receiving. The gateway checks the seal, that this is the next key in the chain and not a copy, and that the tank could physically do this. ${a.physics.reason}`,
    action: `${a.reason} Action: ${a.title}.`,
  };
  setText("#narration", lines[stage]);
}

function flagTarget(data) {
  if (data.assessment.required) return FLAG_UP;
  return data.assessment.severity === 1 ? 270 : FLAG_DOWN;
}

function pose(progress, data, flagFrom = flagY) {
  const { name, t } = stageAt(progress);
  setStage(name);
  narrate(name, data);
  const y = surfaceY(shownLevel);

  const ping = $("#ping");
  const echo = $("#echo");
  if (name === "sensing") {
    if (t < 0.5) {
      ping.setAttribute("opacity", 1);
      echo.setAttribute("opacity", 0);
      ping.setAttribute("transform", `translate(0 ${lerp(FACE_Y, y, t / 0.5)})`);
    } else {
      ping.setAttribute("opacity", 0);
      echo.setAttribute("opacity", 1);
      echo.setAttribute("transform", `translate(0 ${lerp(y, FACE_Y, (t - 0.5) / 0.5)})`);
    }
  } else {
    ping.setAttribute("opacity", 0);
    echo.setAttribute("opacity", 0);
  }
  ["probe-t", "probe-d", "probe-p"].forEach((id, index) => {
    const lit = name === "sensing" && t > 0.25 + index * 0.2;
    $(`#${id}`).setAttribute("class", lit ? "probe lit" : "probe");
  });

  pulses(name === "securing" ? t : 0);
  const turn = name === "securing" ? ease(clamp((t - 0.35) / 0.65, 0, 1)) : name === "sensing" ? 0 : 1;
  $("#ratchet").setAttribute("transform", `rotate(${(data.seq - 1 + turn) * 30})`);
  $("#key").setAttribute("transform", `translate(352 300) rotate(${name === "securing" ? Math.sin(t * Math.PI) * -35 : 0})`);
  setText("#ratchet-count", `reading key ${name === "sensing" ? data.seq - 1 : data.seq}`);

  const x = name === "sensing" || name === "securing" ? CAPSULE_FROM : name === "transit" ? lerp(CAPSULE_FROM, CAPSULE_TO, ease(t)) : CAPSULE_TO;
  $("#capsule").setAttribute("transform", `translate(${x} 252)`);

  const verifying = name === "verify" ? t : name === "action" ? 1 : 0;
  spin("chk-seal", clamp(verifying / 0.33, 0, 1) * 240);
  spin("chk-order", clamp((verifying - 0.33) / 0.33, 0, 1) * 240);
  spin("chk-physics", clamp((verifying - 0.66) / 0.34, 0, 1) * 240);
  lamp("chk-seal", verifying >= 0.33 ? "pass" : "");
  lamp("chk-order", verifying >= 0.66 ? "pass" : "");
  lamp("chk-physics", verifying >= 1 ? (data.assessment.physics.plausible ? "pass" : "fail") : "");
  if (verifying >= 1) paintBoard(data);

  if (name === "action") placeFlag(lerp(flagFrom, flagTarget(data), ease(t)), data);
}

function playCycle(data) {
  if (playing) playing();
  targetLevel = data.level_pct;
  const flagFrom = flagY;
  playing = animate(4400, (t) => pose(t, data, flagFrom), () => {
    playing = null;
    placeFlag(flagTarget(data), data);
    paintBoard(data);
  });
}

function playRefusal() {
  setStage("verify");
  setText("#narration", "Refused. The capsule failed a gateway check, so it drops through the hatch and no tank number reaches the office.");
  lamp("chk-seal", "fail");
  animate(1500, (t) => {
    const drop = Math.sin(t * Math.PI) * 22;
    $("#hatch").setAttribute("transform", `translate(756 ${372 + drop})`);
  }, () => lamp("chk-seal", ""));
}

function playAck() {
  const ack = $("#ack-capsule");
  animate(1300, (t) => {
    ack.setAttribute("transform", `translate(${lerp(680, 440, ease(t))} 394)`);
    ack.setAttribute("opacity", t < 0.92 ? 1 : 1 - (t - 0.92) / 0.08);
  });
  setText("#narration", "The engineer marked the reading seen. A sealed note travels back to the board on the return rail.");
}

function paintBoard(data) {
  const key = `${data.seq}|${data.seen_at || ""}`;
  if (paintedKey === key) return;
  paintedKey = key;
  const a = data.assessment;
  setText("#level", data.level_pct.toFixed(0));
  const rows = [
    ["#r-ntu", `${data.turbidity_ntu.toFixed(1)} NTU`, "#r-ntu-band", ntuBand(data.turbidity_ntu)],
    ["#r-tds", `${fmt(data.tds_mgl)} mg/L`, "#r-tds-band", tdsBand(data.tds_mgl)],
    ["#r-ph", data.ph.toFixed(2), "#r-ph-band", phBand(data.ph)],
  ];
  for (const [valueId, value, bandId, band] of rows) {
    setText(valueId, value);
    setText(bandId, band.text);
    $(bandId).className = `band ${band.cls}`;
  }
  setText("#r-temp", `${data.water_c.toFixed(1)} °C · ${data.air_c.toFixed(1)} °C`);
  setText("#times", `Reading ${data.seq} · tank ${data.tank_clock} · office ${data.received_at}${data.seen_at ? ` · seen ${data.seen_at}` : ""}`);
  setText("#order-kicker", a.severity >= 2 ? "Crew required" : a.severity === 1 ? "Advisory" : "Routine watch");
  setText("#order-title", a.title);
  setText("#order-reason", a.reason);
  const steps = $("#order-steps");
  steps.replaceChildren(...a.steps.map((step) => el("li", {}, step)));
  $("#order").classList.toggle("required", a.required);
}

function drawSpark(history) {
  const poly = $("#spark");
  if (history.length < 2) {
    poly.setAttribute("points", "");
    return;
  }
  const points = history.map((item, index) => {
    const x = 4 + (index / (history.length - 1)) * 192;
    const y = 66 - (item.level_pct / 100) * 60;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  poly.setAttribute("points", points.join(" "));
}

function drawChannel(snap) {
  const session = snap.session;
  const reading = snap.reading;
  setText("#c-session", session ? `${session.session_id} · ${session.mode_label}` : "waiting for the first proven reading");
  const handshake = session ? snap.handshakes.find((item) => item.session_id === session.session_id) : snap.handshakes[0];
  setText(
    "#c-handshake",
    handshake ? `${fmt(handshake.hello_bytes)} B in · ${fmt(handshake.welcome_bytes)} B out${handshake.proven ? " · proven" : " · not proven yet"}` : "—",
  );
  setText("#c-key", session ? `#${session.recv_seq} · chain ${session.chain_fp}` : "—");
  setText("#c-capsule", reading ? `${reading.capsule_bytes} B sealed · as JSON it would be ${reading.json_bytes} B` : "—");
  const delivery = snap.delivery || {};
  setText(
    "#c-delivery",
    `${fmt(delivery.stored || 0)} stored · ${fmt(delivery.buffered || 0)} buffered · ${fmt(delivery.duplicates || 0)} resends ignored`,
  );
  const controls = snap.controls;
  setText(
    "#c-outbox",
    controls
      ? `${controls.link_down ? "radio off · " : ""}${controls.outbox} waiting for a receipt${controls.dropped ? ` · ${controls.dropped} dropped` : ""}`
      : "not visible from a separate gateway",
  );
  if (reading) {
    setText("#live-echo", `echo ${reading.echo_ms} ms · ${reading.distance_m.toFixed(2)} m`);
    setText("#capsule-label", `${reading.capsule_bytes} B sealed`);
    setText("#capsule-hex", reading.capsule_hex.slice(0, 44).replace(/(..)/g, "$1 ").trim());
  }
}

function drawLog(events) {
  const log = $("#log");
  log.replaceChildren(
    ...events.slice(0, 14).map((event) => {
      const item = el("li", { class: event.kind });
      item.append(el("time", {}, event.at), el("span", {}, event.text));
      return item;
    }),
  );
}

export function init(app) {
  setInterval(() => {
    shownLevel += (targetLevel - shownLevel) * 0.1;
    placeWater(shownLevel, latest ? latest.turbidity_ntu : 0.5);
  }, 40);
  placeFlag(FLAG_DOWN);

  $("#seen").addEventListener("click", async () => {
    $("#seen").disabled = true;
    await post("/api/ack");
    app.refresh();
  });
  $("#replay-cycle").addEventListener("click", () => {
    holdUntil = 0;
    if (latest) playCycle(latest);
  });
  $$("#rail button").forEach((button) => {
    button.addEventListener("click", () => {
      if (!latest) return;
      if (playing) {
        playing();
        playing = null;
      }
      holdUntil = performance.now() + HOLD_MS;
      const point = { sensing: 0.12, securing: 0.32, transit: 0.5, verify: 0.8, action: 1 }[button.dataset.stage];
      pose(point, latest);
    });
  });
}

export function render(snap) {
  drawChannel(snap);
  drawLog(snap.events);
  drawSpark(snap.history);
  const reading = snap.reading;
  $("#seen").disabled = !reading || Boolean(reading.seen_at);
  $("#replay-cycle").disabled = !reading;
  if (lastRefused !== null && snap.counters.refused > lastRefused) playRefusal();
  lastRefused = snap.counters.refused;
  const delivery = snap.delivery || {};
  if (!playing && (delivery.silent || snap.clone || (snap.controls && snap.controls.link_down))) {
    if (snap.clone) setText("#narration", "Clone alarm. Two boards proved the same keys, so the office stopped trusting this tank. Revoke and re-enroll it on site from the Attack bench.");
    else if (snap.controls && snap.controls.link_down) setText("#narration", `The radio link is down. The board keeps measuring; ${snap.controls.outbox} readings are waiting in its outbox for the link to return.`);
    else setText("#narration", `No reading for ${Math.round(delivery.quiet_s || 0)} s. The watchdog flags the tank; check power and radio. Readings taken meanwhile stay on the board.`);
  }
  if (!reading) {
    if (!playing) setText("#narration", snap.connected ? "Handshake done. Waiting for the first sealed reading to prove the board." : "Waiting for the sensor to connect.");
    return;
  }
  latest = reading;
  const key = `${reading.session_id}:${reading.seq}`;
  if (key !== lastKey) {
    const first = lastKey === null;
    lastKey = key;
    if (first) {
      targetLevel = shownLevel = reading.level_pct;
      $("#ratchet").setAttribute("transform", `rotate(${reading.seq * 30})`);
      setText("#ratchet-count", `reading key ${reading.seq}`);
      paintBoard(reading);
      placeFlag(flagTarget(reading), reading);
      lamp("chk-seal", "pass");
      lamp("chk-order", "pass");
      lamp("chk-physics", reading.assessment.physics.plausible ? "pass" : "fail");
      setText("#narration", `${reading.assessment.reason} Action: ${reading.assessment.title}.`);
    } else if (performance.now() < holdUntil) {
      targetLevel = reading.level_pct;
      paintBoard(reading);
    } else {
      playCycle(reading);
    }
  } else if (!playing) {
    paintBoard(reading);
  }
  if (!primed) {
    primed = true;
    lastSeen = reading.seen_at;
  } else if (reading.seen_at && reading.seen_at !== lastSeen) {
    lastSeen = reading.seen_at;
    playAck();
  }
}
