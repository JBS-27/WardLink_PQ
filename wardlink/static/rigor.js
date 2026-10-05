import { $, el, post, setText } from "./util.js";

const CATEGORY_NOTES = {
  Standards: "The cryptography matches the published standard, byte for byte.",
  "Protocol attacks": "Someone on the network tries to forge, replay or read readings.",
  "Transport faults": "Bad links and hostile connections must never freeze the gateway.",
  Delivery: "Outages, lost receipts and restarts must not lose a single reading.",
  Lifecycle: "Stolen keys, clones and dead boards over the life of a deployment.",
  "Sensor faults": "Instruments fail; the office must not act on a broken reading.",
  "Physics and water": "The tank's physics and IS 10500 decide what the crew does.",
  Load: "A ward has many tanks reporting at the same time.",
};

let report = null;
let running = false;
let polling = null;

function drawStats() {
  if (!report || report.error) {
    $("#rigor-stats").replaceChildren();
    setText("#rigor-status", report && report.error ? `Last run failed: ${report.error}` : "No saved run yet. Run the scenarios to fill this page.");
    return;
  }
  const categories = new Set(report.results.map((item) => item.category));
  const failed = report.total - report.passed;
  const stats = [
    { value: `${report.passed} / ${report.total}`, text: failed ? `${failed} scenario(s) failed; see the red rows` : "field scenarios passed", lead: failed === 0 },
    { value: `${report.seconds} s`, text: "to run the whole suite" },
    { value: String(categories.size), text: "categories, from NIST vectors to a 20-tank load test" },
    { value: report.finished_at.replace(" UTC", ""), text: `last run (UTC) · ${report.machine || ""}` },
  ];
  $("#rigor-stats").replaceChildren(
    ...stats.map((stat) => {
      const box = el("div", { class: `stat${stat.lead ? " lead" : ""}` });
      box.append(el("b", {}, stat.value), el("span", {}, stat.text));
      return box;
    }),
  );
}

function drawResults() {
  const host = $("#rigor-results");
  if (!report || !report.results) {
    host.replaceChildren();
    return;
  }
  const groups = new Map();
  for (const item of report.results) {
    if (!groups.has(item.category)) groups.set(item.category, []);
    groups.get(item.category).push(item);
  }
  host.replaceChildren(
    ...[...groups.entries()].map(([category, items]) => {
      const panel = el("section", { class: "panel rigor-group" });
      const passed = items.filter((item) => item.passed).length;
      const head = el("div", { class: "panel-head" });
      head.append(el("p", { class: "kicker" }, `${category} · ${passed}/${items.length}`), el("p", { class: "muted small" }, CATEGORY_NOTES[category] || ""));
      const table = el("table", { class: "data rigor-table" });
      const header = el("tr");
      ["", "Scenario", "What happened", "Time"].forEach((title) => header.append(el("th", {}, title)));
      table.append(header);
      for (const item of items) {
        const row = el("tr", item.passed ? {} : { class: "failed" });
        row.append(
          el("td", { class: item.passed ? "verdict pass" : "verdict fail" }, item.passed ? "pass" : "FAIL"),
          el("td", {}, item.title),
          el("td", { class: "detail" }, item.detail),
          el("td", {}, `${(item.ms / 1000).toFixed(item.ms < 1000 ? 2 : 1)} s`),
        );
        table.append(row);
      }
      panel.append(head, table);
      return panel;
    }),
  );
}

async function load() {
  const data = await (await fetch("/api/rigor")).json();
  running = data.running;
  if (data.report) report = data.report;
  const live = data.live_runs !== false;
  $("#rigor-run").disabled = running || !live;
  if (!live) setText("#rigor-status", data.note || "Live runs are not available on this host.");
  else setText("#rigor-status", running ? "Running all scenarios against throwaway gateways… about 20 seconds." : report ? "" : "No saved run yet.");
  drawStats();
  drawResults();
  if (running && !polling) {
    polling = setInterval(async () => {
      const next = await (await fetch("/api/rigor")).json();
      if (!next.running) {
        clearInterval(polling);
        polling = null;
        load();
      }
    }, 1500);
  }
}

export function init() {
  $("#rigor-run").addEventListener("click", async () => {
    $("#rigor-run").disabled = true;
    await post("/api/rigor/run");
    load();
  });
}

export function render(snap) {
  const changed = snap.rigor && (!report || report.finished_at !== snap.rigor.finished_at);
  if (changed || (snap.rigor_running !== running) || report === null) load();
}
