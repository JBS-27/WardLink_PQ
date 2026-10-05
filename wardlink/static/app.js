import { $, $$, setText } from "./util.js";
import * as live from "./live.js";
import * as unit from "./unit.js";
import * as lab from "./lab.js";
import * as bench from "./bench.js";
import * as rigor from "./rigor.js";

const views = { live, unit, lab, bench, rigor };
const app = { snap: null, bench: null, view: "live", refresh };

function route() {
  const name = (location.hash || "#live").slice(1);
  app.view = views[name] ? name : "live";
  for (const key of Object.keys(views)) $(`#view-${key}`).hidden = key !== app.view;
  $$("#tabs a").forEach((link) => link.classList.toggle("active", link.dataset.view === app.view));
  if (app.snap) views[app.view].render(app.snap, app);
}

function header(snap) {
  const reading = snap.reading;
  setText("#site-title", snap.device ? snap.device.label : "Ward 4 overhead tank");
  setText("#tank-clock", reading ? reading.tank_clock : "—");
  setText("#host-note", snap.serverless ? "Serverless demo: the tank advances while this page is open and restarts when the host sleeps" : "");
  const state = $("#link-state");
  const delivery = snap.delivery || {};
  if (snap.clone) {
    state.textContent = "Clone alarm · re-enroll on site";
    state.className = "state alarm";
  } else if (snap.device && snap.device.status === "revoked") {
    state.textContent = "Board revoked";
    state.className = "state alarm";
  } else if (delivery.silent) {
    state.textContent = `Sensor silent ${Math.round(delivery.quiet_s || 0)} s`;
    state.className = "state alarm";
  } else if (snap.controls && snap.controls.link_down) {
    state.textContent = `Radio down · ${snap.controls.outbox} buffered on the board`;
    state.className = "state wait";
  } else if (!snap.connected && snap.waiting) {
    state.textContent = "Sensor offline";
    state.className = "state wait";
  } else if (reading && reading.assessment.required) {
    state.textContent = "Action required";
    state.className = "state alarm";
  } else if (reading) {
    state.textContent = snap.connected ? "Live · within limits" : "Sensor reconnecting";
    state.className = snap.connected ? "state live" : "state wait";
  } else {
    state.textContent = "Sensor connected";
    state.className = "state live";
  }
}

async function refresh() {
  try {
    const snap = await (await fetch("/api/state")).json();
    app.snap = snap;
    header(snap);
    views[app.view].render(snap, app);
  } catch {
    setText("#link-state", "Gateway unreachable");
    $("#link-state").className = "state alarm";
  }
}

async function loadBench() {
  try {
    const data = await (await fetch("/api/bench")).json();
    if (data.pending) {
      setTimeout(loadBench, 1200);
      return;
    }
    app.bench = data;
    lab.setBench(data, app);
    unit.setBench(data, app);
  } catch {
    setTimeout(loadBench, 2000);
  }
}

function clock() {
  setText(
    "#clock",
    new Date().toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      day: "2-digit",
      month: "short",
    }),
  );
}

for (const view of Object.values(views)) view.init(app);
window.addEventListener("hashchange", route);
route();
refresh();
setInterval(refresh, 1000);
loadBench();
clock();
setInterval(clock, 1000);
