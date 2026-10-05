import { $, animate, el, fmt, lerp, post, setText, svgEl } from "./util.js";

const CRATE_BYTES = 256;
const PER_ROW = 48;
const CATEGORIES = [
  { key: "key_exchange", label: "Key exchange (ML-KEM / X25519)", colour: "#3e7f96", swatch: "water" },
  { key: "signatures", label: "Handshake signatures", colour: "#c4543c", swatch: "alarm" },
  { key: "certificates", label: "Certificates", colour: "#8a6d4f", swatch: "cert" },
  { key: "framing", label: "Framing, ids, MACs", colour: "#5c656d", swatch: "frame" },
];
const ORDER = ["tls-classic", "tls-hybrid", "wl-lean", "wl-signed", "tls-pq"];

let lastHandshake = null;
let stopConveyor = null;
let latestHandshake = null;

function crateCounts(protocol) {
  const total = Math.ceil(protocol.total / CRATE_BYTES);
  const counts = CATEGORIES.map((category) => Math.round((protocol.breakdown[category.key] || 0) / CRATE_BYTES));
  let sum = counts.reduce((a, b) => a + b, 0);
  const largest = counts.indexOf(Math.max(...counts));
  counts[largest] += total - sum;
  sum = total;
  return counts;
}

function crateSvg(protocol) {
  const counts = crateCounts(protocol);
  const total = counts.reduce((a, b) => a + b, 0);
  const rows = Math.max(1, Math.ceil(total / PER_ROW));
  const svg = svgEl("svg", { class: "crate-svg", viewBox: `0 0 ${PER_ROW * 16} ${rows * 16}`, role: "img" });
  let index = 0;
  counts.forEach((count, category) => {
    for (let n = 0; n < count; n += 1) {
      svgEl("rect", {
        class: "crate",
        x: (index % PER_ROW) * 16,
        y: Math.floor(index / PER_ROW) * 16,
        width: 14,
        height: 14,
        rx: 2,
        fill: CATEGORIES[category].colour,
      }, svg);
      index += 1;
    }
  });
  const title = svgEl("title", {}, svg);
  title.textContent = CATEGORIES.map((category) => `${category.label}: ${fmt(protocol.breakdown[category.key] || 0)} B`).join(" · ");
  return svg;
}

function badge(ok, text) {
  return el("span", { class: `badge ${ok ? "yes" : "no"}` }, `${text}: ${ok ? "quantum-safe" : "classical"}`);
}

function drawStats(data) {
  const get = (id) => data.protocols.find((item) => item.id === id);
  const lean = get("wl-lean");
  const signed = get("wl-signed");
  const pq = get("tls-pq");
  const saving = Math.round((1 - lean.total / signed.total) * 100);
  const stats = [
    { lead: true, value: `−${saving}%`, text: `bytes for the lean handshake: ${fmt(lean.total)} against ${fmt(signed.total)} signed, same quantum-safe mutual authentication` },
    { value: `${lean.ms.toFixed(2)} ms`, text: `lean, both sides on this laptop, against ${signed.ms.toFixed(2)} ms signed` },
    { value: `${lean.radio.lora12.airtime_s} s`, text: `of LoRa SF12 airtime per lean handshake. A fully post-quantum TLS handshake needs ${pq ? pq.radio.lora12.airtime_s : "—"} s` },
    { value: `${data.record.binary_radio.lora12.frames} frame`, text: `per reading on LoRa SF12 (${data.record.binary_sealed} B sealed). The same reading as JSON needs ${data.record.json_radio.lora12.frames} frames` },
  ];
  $("#lab-stats").replaceChildren(
    ...stats.map((stat) => {
      const box = el("div", { class: `stat${stat.lead ? " lead" : ""}` });
      box.append(el("b", {}, stat.value), el("span", {}, stat.text));
      return box;
    }),
  );
}

function drawCrates(data) {
  $("#crate-legend").replaceChildren(
    ...CATEGORIES.map((category) => {
      const item = el("li");
      item.append(el("i", { class: `swatch ${category.swatch}` }), document.createTextNode(category.label));
      return item;
    }),
  );
  const protocols = ORDER.map((id) => data.protocols.find((item) => item.id === id)).filter(Boolean);
  $("#crates").replaceChildren(
    ...protocols.map((protocol) => {
      const row = el("div", { class: `crate-row${protocol.id === "wl-lean" ? " highlight" : ""}` });
      const name = el("div", { class: "crate-name" });
      name.append(el("b", {}, protocol.name), el("span", {}, protocol.detail));
      const badges = el("div", { class: "badges" });
      badges.append(badge(protocol.pq_confidentiality, "secrecy"), badge(protocol.pq_authentication, "identity"));
      name.append(badges);
      const total = el("div", { class: "crate-total" });
      total.append(el("b", {}, `${fmt(protocol.total)} B`), el("span", {}, `${fmt(protocol.up)} up · ${fmt(protocol.down)} down`));
      row.append(name, crateSvg(protocol), total);
      return row;
    }),
  );
  setText(
    "#lab-source",
    `Measured ${data.generated_at} on ${data.machine}. TLS: real in-memory TLS 1.3 handshakes, mutual authentication, one self-signed certificate per side (a real PKI chain adds an intermediate). WardLink: the gateway's own code, median of ${data.runs} runs.`,
  );
}

function drawRadio(data) {
  const links = data.links;
  const table = el("table", { class: "data" });
  const head = el("tr");
  head.append(el("th", {}, "Handshake"));
  links.forEach((link) => head.append(el("th", {}, link.sf ? `${link.name.replace("LoRaWAN IN865 ", "")} frames · air` : `${link.name} frames`)));
  table.append(head);
  ORDER.map((id) => data.protocols.find((item) => item.id === id)).filter(Boolean).forEach((protocol) => {
    const row = el("tr", protocol.id === "wl-lean" ? { class: "highlight" } : {});
    row.append(el("td", {}, protocol.name));
    links.forEach((link) => {
      const cost = protocol.radio[link.id];
      const text = cost.airtime_s !== null ? `${fmt(cost.frames)} · ${fmt(cost.airtime_s)} s` : fmt(cost.frames);
      row.append(el("td", cost.airtime_s !== null && cost.airtime_s > 300 ? { class: "bad" } : {}, text));
    });
    table.append(row);
  });
  $("#radio-table").replaceChildren(table);

  const record = el("table", { class: "data" });
  const recordHead = el("tr");
  recordHead.append(el("th", {}, "One reading"));
  links.forEach((link) => recordHead.append(el("th", {}, link.name.replace("LoRaWAN IN865 ", ""))));
  record.append(recordHead);
  [["Binary, " + data.record.binary_sealed + " B sealed", data.record.binary_radio], ["JSON, " + data.record.json_sealed + " B sealed", data.record.json_radio]].forEach(([label, radio], index) => {
    const row = el("tr", index === 0 ? { class: "highlight" } : {});
    row.append(el("td", {}, label));
    links.forEach((link) => {
      const cost = radio[link.id];
      row.append(el("td", {}, cost.airtime_s !== null ? `${cost.frames} · ${cost.airtime_s} s` : `${cost.frames}`));
    });
    record.append(row);
  });
  $("#record-table").replaceChildren(record);
  setText(
    "#radio-source",
    "Frames use each link's largest payload: TCP segment 1,460 B, BLE 244 B, LoRaWAN IN865 242 B at SF7 and 51 B at SF12 (LoRa Alliance RP002). Airtime: Semtech time-on-air formula, 125 kHz, coding rate 4/5, 13-byte LoRaWAN header. Red cells exceed five minutes.",
  );
}

export function setBench(data) {
  if (data.error) {
    setText("#lab-source", `Benchmark failed: ${data.error}`);
    return;
  }
  drawStats(data);
  drawCrates(data);
  drawRadio(data);
}

function playConveyor(handshake) {
  if (!handshake) return;
  if (stopConveyor) stopConveyor();
  const group = $("#conveyor-crates");
  group.replaceChildren();
  const up = Math.ceil(handshake.hello_bytes / CRATE_BYTES);
  const down = Math.ceil(handshake.welcome_bytes / CRATE_BYTES);
  const colour = handshake.mode === "lean" ? "#3e7f96" : "#c4543c";
  const hello = Array.from({ length: up }, () => svgEl("rect", { class: "crate", width: 16, height: 16, rx: 2, fill: colour }, group));
  const welcome = Array.from({ length: down }, () => svgEl("rect", { class: "crate", width: 16, height: 16, rx: 2, fill: "#7d8b96" }, group));
  setText(
    "#conveyor-label",
    `${handshake.mode === "lean" ? "Lean" : "Signed"} handshake ${handshake.session_id}: ${fmt(handshake.hello_bytes)} B → (${up} crates), ${fmt(handshake.welcome_bytes)} B ← (${down} crates)`,
  );
  stopConveyor = animate(4200, (t) => {
    hello.forEach((box, index) => {
      const local = Math.min(1, Math.max(0, t * 2.1 - index * (1 / Math.max(up, 1)) * 0.9));
      box.setAttribute("x", lerp(112, 512, local));
      box.setAttribute("y", 64);
      box.setAttribute("opacity", local > 0 && local < 1 ? 1 : 0);
    });
    welcome.forEach((box, index) => {
      const local = Math.min(1, Math.max(0, (t - 0.5) * 2.1 - index * (1 / Math.max(down, 1)) * 0.9));
      box.setAttribute("x", lerp(512, 112, local));
      box.setAttribute("y", 108);
      box.setAttribute("opacity", local > 0 && local < 1 ? 1 : 0);
    });
  });
}

export function init(app) {
  const rekey = async (mode) => {
    const result = await post("/api/rekey", { mode });
    if (!result.ok) setText("#conveyor-label", result.data.error || "Re-key failed.");
    app.refresh();
  };
  $("#rekey-lean").addEventListener("click", () => rekey("lean"));
  $("#rekey-signed").addEventListener("click", () => rekey("signed"));
  $("#conveyor-play").addEventListener("click", () => playConveyor(latestHandshake));
}

export function render(snap) {
  const demo = snap.demo;
  $("#rekey-lean").disabled = !demo;
  $("#rekey-signed").disabled = !demo;
  latestHandshake = snap.handshakes[0] || null;
  if (latestHandshake && latestHandshake.session_id !== lastHandshake) {
    const first = lastHandshake === null;
    lastHandshake = latestHandshake.session_id;
    playConveyor(latestHandshake);
    if (first) setTimeout(() => playConveyor(latestHandshake), 50);
  }
  $("#handshake-log").replaceChildren(
    ...snap.handshakes.slice(0, 6).map((item) => {
      const row = el("li");
      row.append(
        el("time", {}, item.at),
        el("span", {}, `${item.mode === "lean" ? "Lean" : "Signed"} · ${fmt(item.hello_bytes)} + ${fmt(item.welcome_bytes)} = ${fmt(item.total_bytes)} B · gateway ${item.gateway_ms} ms · ${item.proven ? "proven" : "not proven"}`),
      );
      return row;
    }),
  );
}
