export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const NS = "http://www.w3.org/2000/svg";

export function svgEl(tag, attrs = {}, parent = null) {
  const el = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  if (parent) parent.append(el);
  return el;
}

export function el(tag, attrs = {}, text = "") {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text) node.textContent = text;
  return node;
}

export function setText(selector, text) {
  const node = typeof selector === "string" ? $(selector) : selector;
  if (node && node.textContent !== text) node.textContent = text;
}

export const fmt = (value) => Number(value).toLocaleString("en-IN");
export const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
export const lerp = (a, b, t) => a + (b - a) * t;
export const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

export async function post(url, body) {
  const options = { method: "POST" };
  if (body) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  return { ok: response.ok, data };
}

/** setInterval-driven tween; keeps running in background tabs and headless capture. */
export function animate(duration, step, done) {
  const started = performance.now();
  let stopped = false;
  const timer = setInterval(() => {
    if (stopped) return;
    const t = clamp((performance.now() - started) / duration, 0, 1);
    step(t);
    if (t >= 1) {
      clearInterval(timer);
      stopped = true;
      if (done) done();
    }
  }, 30);
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

export function hm(epoch) {
  return new Date(epoch * 1000).toLocaleTimeString("en-IN", {
    timeZone: "Asia/Kolkata",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

export function istHour(epoch) {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", hour: "numeric", minute: "numeric", hour12: false })
    .formatToParts(new Date(epoch * 1000));
  const hour = Number(parts.find((p) => p.type === "hour").value);
  const minute = Number(parts.find((p) => p.type === "minute").value);
  return hour + minute / 60;
}

export function ntuBand(ntu) {
  if (ntu > 5) return { text: "above 5 NTU permissible", cls: "bad" };
  if (ntu > 1) return { text: "above 1 NTU acceptable", cls: "warn" };
  return { text: "within IS 10500", cls: "" };
}

export function tdsBand(tds) {
  if (tds > 2000) return { text: "above 2000 permissible", cls: "bad" };
  if (tds > 500) return { text: "above 500 acceptable", cls: "warn" };
  return { text: "within IS 10500", cls: "" };
}

export function phBand(ph) {
  if (ph < 6.5 || ph > 8.5) return { text: "outside 6.5 to 8.5", cls: "bad" };
  return { text: "within IS 10500", cls: "" };
}

export function waterColour(ntu) {
  const t = clamp(ntu / 18, 0, 1);
  const from = [62, 127, 150];
  const to = [122, 92, 52];
  const mix = from.map((value, index) => Math.round(lerp(value, to[index], t)));
  return `rgb(${mix[0]}, ${mix[1]}, ${mix[2]})`;
}

export const FLAG_COLOURS = { LOG: "#5c4634", CHECK: "#8a6d3b", TANKER: "#c4543c", LEAK: "#c4543c", SAMPLE: "#c4543c", SENSOR: "#c4543c" };
