import { $, $$, animate, clamp, ease, istHour, lerp, ntuBand, phBand, setText, svgEl, tdsBand, waterColour } from "./util.js";

const PX_PER_M = 61.7;
const FACE_Y = 406;
const TANK_FLOOR = 604;
const STEP_MS = 560;
const LINK_PAYLOAD = { wifi: 1460, ble: 244, lora7: 242, lora12: 51 };
const LINK_NAME = { wifi: "Wi-Fi", ble: "BLE", lora7: "LoRa SF7", lora12: "LoRa SF12" };

const PARTS = {
  ultrasonic: {
    kicker: "Level sensor",
    title: "Waterproof ultrasonic sensor",
    what: "A JSN-SR04T-class transducer fixed under the roof. It never touches the water.",
    how: "It sends a 40 kHz pulse down and times the echo from the water surface. Distance is speed of sound × echo time ÷ 2, and the level follows from the tank's depth.",
    security: "A plate held under it produces a perfectly sealed, perfectly wrong reading. Cryptography cannot catch that; the gateway's physics check can.",
    live: (r) => `Echo ${r.echo_ms} ms at ${r.sound_mps} m/s → ${r.distance_m.toFixed(3)} m → ${r.level_pct.toFixed(1)}% full.`,
  },
  airtemp: {
    kicker: "Level correction",
    title: "Air thermometer beside the transducer",
    what: "Measures the air the ultrasonic pulse travels through.",
    how: "Sound moves about 0.6 m/s faster for every °C. A rooftop tank in an Indian summer warms by well over 10 °C between dawn and afternoon, enough to move the level by several points.",
    security: "",
    live: (r) => `Air ${r.air_c.toFixed(1)} °C → ${r.sound_mps} m/s. Assuming 343 m/s would read ${r.uncompensated_pct.toFixed(1)}% instead of ${r.level_pct.toFixed(1)}%.`,
  },
  turbidity: {
    kicker: "Water quality",
    title: "Turbidity probe (optical)",
    what: "Two arms: an infrared LED on one side, a photodiode on the other.",
    how: "Particles in the gap scatter the light, so muddy water lets less of it through. The board turns the photodiode voltage into NTU.",
    security: "IS 10500 sets 1 NTU acceptable and 5 NTU permissible. Low-cost probes catch dirty-water events but cannot resolve 1 NTU precisely, so the lab confirms.",
    live: (r) => `${r.turbidity_ntu.toFixed(1)} NTU, ${ntuBand(r.turbidity_ntu).text}.`,
  },
  tds: {
    kicker: "Water quality",
    title: "TDS probe (conductivity)",
    what: "Two metal pins that measure how well the water conducts electricity.",
    how: "An alternating current between the pins stops them plating. Conductivity becomes dissolved solids in mg/L, corrected to 25 °C with the water thermometer.",
    security: "IS 10500: 500 mg/L acceptable, 2000 mg/L permissible. A jump together with turbidity often means sewage or groundwater got into the pipe.",
    live: (r) => `${r.tds_mgl} mg/L, ${tdsBand(r.tds_mgl).text}.`,
  },
  ph: {
    kicker: "Water quality",
    title: "pH probe (glass electrode)",
    what: "A thin glass bulb that develops a small voltage depending on how acidic the water is.",
    how: "About 59 mV per pH unit at 25 °C. It drifts, so it needs regular calibration in pH 4 and pH 7 buffer solutions.",
    security: "IS 10500 allows 6.5 to 8.5, with no relaxation.",
    live: (r) => `pH ${r.ph.toFixed(2)}, ${phBand(r.ph).text}.`,
  },
  watertemp: {
    kicker: "Correction",
    title: "Water thermometer (DS18B20)",
    what: "A sealed digital thermometer on a one-wire bus.",
    how: "Conductivity rises roughly 2% per °C, so the TDS reading is corrected to 25 °C with this temperature.",
    security: "",
    live: (r) => `Water ${r.water_c.toFixed(1)} °C.`,
  },
  isolator: {
    kicker: "Signal integrity",
    title: "Analog signal isolator",
    what: "Keeps the probes' electrical grounds apart.",
    how: "TDS and pH probes in the same water disturb each other. The board powers one probe at a time, and the isolator stops their currents mixing.",
    security: "",
    live: () => "The probes are read one after another in the cycle below.",
  },
  mcu: {
    kicker: "Computer",
    title: "ESP32-S3 board",
    what: "Dual-core 240 MHz microcontroller with Wi-Fi and Bluetooth LE. It reads the probes, packs the 20-byte record and runs the cryptography.",
    how: "Lean handshake: ML-KEM-768 and X25519 only, no signature code on the board. Each reading is sealed with ChaCha20-Poly1305 under a fresh key from the ratchet wheel drawn on the board.",
    security: "Secure Boot V2 lets only signed firmware run. Flash encryption keeps the 64-byte ML-KEM seed unreadable on a stolen board. The hardware random number generator is truly random only while the radio or its internal entropy source is on, and every ML-KEM key needs it.",
    live: (r, snap) => (snap && snap.session ? `Session ${snap.session.session_id}, ${snap.session.mode_label}. Reading key ${snap.session.recv_seq}, chain ${snap.session.chain_fp}.` : ""),
  },
  battery: {
    kicker: "Power",
    title: "Li-ion cell and solar charger",
    what: "An 18650 cell, charged by the roof panel through a charge controller.",
    how: "The radio is the biggest energy cost on a field node. Fewer and shorter transmissions mean longer life, which is why the handshake size matters.",
    security: "",
    live: () => "",
  },
  solar: {
    kicker: "Power",
    title: "Solar panel",
    what: "Charges the cell by day, so the unit needs no mains power on the roof.",
    how: "The sun on the drawing follows tank time; the charge bar fills while it is up.",
    security: "",
    live: () => "",
  },
  antenna: {
    kicker: "Radio",
    title: "Antenna",
    what: "Wi-Fi in this prototype. In the field: a LoRa module on the IN865 band, or NB-IoT.",
    how: "Each sealed reading is 40 bytes. Pick a radio on the right to see how many frames a reading and a handshake need.",
    security: "Everything leaving this antenna is ciphertext. The handshake is the expensive part; on LoRa SF12 it is minutes of airtime, so the board re-keys rarely and ratchets in between.",
    live: () => "",
  },
};

const STEPS = [
  { label: "Wake", part: "mcu", text: () => "The deep-sleep timer wakes the board. Radio off, probes still unpowered." },
  { label: "Air °C", part: "airtemp", text: (r) => `The air beside the transducer is ${r.air_c.toFixed(1)} °C, so sound travels at ${r.sound_mps} m/s in this tank.` },
  { label: "Ping", part: "ultrasonic", text: (r) => `A 40 kHz pulse goes down and its echo returns after ${r.echo_ms} ms: water ${r.distance_m.toFixed(2)} m below, tank ${r.level_pct.toFixed(1)}% full.` },
  { label: "Turbidity", part: "turbidity", text: (r) => `Infrared light crosses the probe gap: ${r.turbidity_ntu.toFixed(1)} NTU, ${ntuBand(r.turbidity_ntu).text}.` },
  { label: "TDS", part: "tds", text: (r) => `Alternating current between the pins: ${r.tds_mgl} mg/L at 25 °C.` },
  { label: "pH", part: "ph", text: (r) => `Glass bulb voltage: pH ${r.ph.toFixed(2)}.` },
  { label: "Water °C", part: "watertemp", text: (r) => `Water ${r.water_c.toFixed(1)} °C, used to correct the TDS reading.` },
  { label: "Encode", part: "mcu", text: () => "Everything packs into 20 bytes: level, distance, turbidity, TDS, pH, two temperatures and tank time." },
  { label: "Seal", part: "mcu", text: (r) => `Sealed with reading key ${r.seq} into ${r.capsule_bytes} bytes. The ratchet turns one tooth and that key is deleted.` },
  { label: "Radio", part: "antenna", text: (r) => radioLine(r) },
  { label: "Sleep", part: "battery", text: () => "Radio off. Back to deep sleep until the next reading, ten minutes later." },
];

let bench = null;
let link = "lora12";
let reading = null;
let snapshot = null;
let selected = "ultrasonic";
let following = true;
let lastKey = null;
let stepIndex = -1;
let cancel = null;
let cycleTimer = null;

function frames(bytes) {
  return Math.ceil(bytes / LINK_PAYLOAD[link]);
}

function radioLine(r) {
  const record = bench && bench.record;
  const sealed = r ? r.capsule_bytes : 40;
  const binary = record ? record.binary_radio[link] : { frames: frames(sealed), airtime_s: null };
  const json = record ? record.json_radio[link] : { frames: frames(r ? r.json_bytes : 189), airtime_s: null };
  const air = binary.airtime_s !== null && binary.airtime_s !== undefined ? `, ${binary.airtime_s} s on air` : "";
  return `Radio on: ${binary.frames} ${LINK_NAME[link]} frame${binary.frames === 1 ? "" : "s"}${air}. The same reading as JSON would need ${json.frames}.`;
}

function surfaceY(level) {
  return Math.min(TANK_FLOOR, 392 + (0.3 + (1 - level / 100) * 3.2) * PX_PER_M);
}

function drawScene(r) {
  const y = surfaceY(r.level_pct);
  const water = $("#u-water");
  water.setAttribute("y", y);
  water.setAttribute("height", Math.max(0, TANK_FLOOR - y));
  water.style.fill = waterColour(r.turbidity_ntu);
  $("#u-surface").setAttribute("y1", y);
  $("#u-surface").setAttribute("y2", y);
  setText("#u-level-tag", `water ${r.level_pct.toFixed(1)}% · ${r.distance_m.toFixed(2)} m below the sensor`);
  const hour = istHour(r.tank_time);
  const day = hour >= 6 && hour < 18;
  $("#u-sun").setAttribute("opacity", day ? 1 : 0);
  $("#u-charge").setAttribute("width", day ? 120 : 60);
  const particles = $("#u-particles");
  const count = clamp(Math.round(r.turbidity_ntu * 1.6), 1, 30);
  if (particles.childNodes.length !== count) {
    particles.replaceChildren();
    for (let index = 0; index < count; index += 1) {
      svgEl("circle", { class: "particle", cx: 614 + ((index * 37) % 12), cy: 572 + ((index * 53) % 20), r: 1.4 }, particles);
    }
  }
  $("#u-beam").style.opacity = String(clamp(1 - r.turbidity_ntu / 25, 0.15, 1));
}

function showPart(name) {
  const part = PARTS[name];
  if (!part) return;
  $$("#unit .part").forEach((node) => node.classList.toggle("selected", node.dataset.part === name));
  setText("#part-kicker", part.kicker);
  setText("#part-title", part.title);
  setText("#part-what", part.what);
  setText("#part-how", part.how);
  setText("#part-security", part.security);
  setText("#part-live", reading ? part.live(reading, snapshot) : "");
}

function highlight(name) {
  $$("#unit .part").forEach((node) => node.classList.toggle("active", node.dataset.part === name));
}

function drawCycleList() {
  const list = $("#cycle");
  list.replaceChildren(
    ...STEPS.map((step, index) => {
      const item = document.createElement("li");
      item.dataset.index = String(index);
      const title = document.createElement("b");
      title.textContent = `${index + 1}`;
      item.append(title, document.createTextNode(step.label));
      item.addEventListener("click", () => {
        following = false;
        $("#cycle-follow").checked = false;
        stopCycle();
        runStep(index, null);
      });
      return item;
    }),
  );
}

function markStep(index) {
  stepIndex = index;
  $$("#cycle li").forEach((item, position) => {
    item.classList.toggle("active", position === index);
    item.classList.toggle("done", position < index);
  });
}

function resetEffects() {
  $("#u-ping").setAttribute("opacity", 0);
  $("#u-echo").setAttribute("opacity", 0);
  $("#u-ac").setAttribute("opacity", 0);
  $("#u-bulb").setAttribute("class", "bulb");
  $("#u-led").setAttribute("class", "led");
  $("#u-frags").replaceChildren();
}

function runStep(index, next) {
  if (!reading) return;
  const step = STEPS[index];
  markStep(index);
  highlight(step.part);
  if (selected === null || following) showPart(step.part);
  setText("#cycle-text", step.text(reading));
  resetEffects();
  const label = step.label;
  let effect = () => {};
  if (label === "Wake") effect = (t) => $("#u-led").setAttribute("class", t % 0.5 < 0.25 ? "led on" : "led");
  if (label === "Ping") {
    const surface = surfaceY(reading.level_pct);
    effect = (t) => {
      if (t < 0.5) {
        $("#u-ping").setAttribute("opacity", 1);
        $("#u-ping").setAttribute("transform", `translate(0 ${lerp(FACE_Y, surface, t / 0.5)})`);
        $("#u-echo").setAttribute("opacity", 0);
      } else {
        $("#u-ping").setAttribute("opacity", 0);
        $("#u-echo").setAttribute("opacity", 1);
        $("#u-echo").setAttribute("transform", `translate(0 ${lerp(surface, FACE_Y, (t - 0.5) / 0.5)})`);
      }
    };
  }
  if (label === "Turbidity") effect = (t) => { $("#u-beam").style.strokeWidth = String(2 + Math.sin(t * Math.PI * 4) * 1.5); };
  if (label === "TDS") effect = (t) => $("#u-ac").setAttribute("opacity", Math.round(t * 8) % 2 ? 1 : 0.3);
  if (label === "pH") effect = () => $("#u-bulb").setAttribute("class", "bulb lit");
  if (label === "Encode") {
    const cells = [...$("#u-bytes").childNodes];
    effect = (t) => cells.forEach((cell, position) => cell.setAttribute("class", position < Math.round(t * 20) ? "byte on" : "byte"));
  }
  if (label === "Seal") {
    effect = (t) => $("#u-ratchet").setAttribute("transform", `rotate(${(reading.seq - 1 + ease(t)) * 30})`);
  }
  if (label === "Radio") {
    const count = Math.min(12, frames(reading.capsule_bytes));
    const group = $("#u-frags");
    const boxes = Array.from({ length: count }, () => svgEl("rect", { class: "frag", width: 9, height: 9 }, group));
    effect = (t) => boxes.forEach((box, position) => {
      const local = clamp(t * 1.6 - position * (0.6 / Math.max(count, 1)), 0, 1);
      box.setAttribute("x", lerp(388, 930, local));
      box.setAttribute("y", 52 - Math.sin(local * Math.PI) * 10);
      box.setAttribute("opacity", local > 0 && local < 1 ? 1 : 0);
    });
  }
  if (label === "Sleep") effect = () => $$("#u-bytes rect").forEach((cell) => cell.setAttribute("class", "byte"));
  const duration = label === "Ping" || label === "Radio" ? STEP_MS * 1.6 : STEP_MS;
  cancel = animate(duration, effect, () => {
    cancel = null;
    if (next) next();
  });
}

function stopCycle() {
  if (cancel) cancel();
  cancel = null;
  clearTimeout(cycleTimer);
}

function playCycle() {
  stopCycle();
  const go = (index) => {
    if (index >= STEPS.length) {
      highlight(null);
      return;
    }
    runStep(index, () => {
      cycleTimer = setTimeout(() => go(index + 1), 40);
    });
  };
  go(0);
}

export function setBench(data) {
  bench = data;
  updateRadioNote();
}

function updateRadioNote() {
  if (!bench || !bench.protocols) {
    setText("#radio-note", "Benchmark still running.");
    return;
  }
  const lean = bench.protocols.find((item) => item.id === "wl-lean");
  const signed = bench.protocols.find((item) => item.id === "wl-signed");
  const air = (item) => (item.radio[link].airtime_s !== null ? `, ${item.radio[link].airtime_s} s on air` : "");
  setText(
    "#radio-note",
    `${LINK_NAME[link]}: one reading ${bench.record.binary_radio[link].frames} frame. Lean handshake ${lean.radio[link].frames} frames${air(lean)}; signed ${signed.radio[link].frames} frames${air(signed)}.`,
  );
}

export function init() {
  const bytes = $("#u-bytes");
  for (let index = 0; index < 20; index += 1) {
    svgEl("rect", { class: "byte", x: (index % 5) * 14, y: Math.floor(index / 5) * 9, width: 12, height: 7 }, bytes);
  }
  drawCycleList();
  $$("#unit .part").forEach((node) => {
    node.addEventListener("click", () => {
      selected = node.dataset.part;
      following = false;
      $("#cycle-follow").checked = false;
      showPart(selected);
    });
  });
  $$("#radio-pick button").forEach((button) => {
    button.addEventListener("click", () => {
      link = button.dataset.link;
      $$("#radio-pick button").forEach((other) => other.classList.toggle("active", other === button));
      updateRadioNote();
      if (reading && stepIndex === 9) setText("#cycle-text", radioLine(reading));
    });
  });
  $("#cycle-play").addEventListener("click", () => {
    following = true;
    $("#cycle-follow").checked = true;
    playCycle();
  });
  $("#cycle-follow").addEventListener("change", (event) => {
    following = event.target.checked;
  });
  showPart(selected);
}

export function render(snap) {
  snapshot = snap;
  if (!snap.reading) {
    setText("#unit-narration", "Waiting for the first verified reading from the roof unit.");
    return;
  }
  reading = snap.reading;
  drawScene(reading);
  const key = `${reading.session_id}:${reading.seq}`;
  if (key !== lastKey) {
    const first = lastKey === null;
    lastKey = key;
    $("#u-ratchet").setAttribute("transform", `rotate(${reading.seq * 30})`);
    if (following || first) playCycle();
  }
  if (selected && !cancel) showPart(selected);
  setText("#unit-narration", "The sensor unit on the tank roof, opened up. Click any part to see what it is, how it measures, and what it does for security.");
}
