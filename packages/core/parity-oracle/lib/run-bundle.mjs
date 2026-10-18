// Child process: runs ONE PDPP host-v1 pageshim bundle the way the mobile
// thin host (unity-surfaces apps/mobile-shell/lib/connect/page_shim.dart,
// as re-implemented by data-connectors scripts/pageshim/harness.mjs) does,
// but in plain Node: the bundle runs as
//   new AsyncFunction('page','process','initialState', <transformed source>)
// with a `page` exposing exactly the PageShim method set (+ `input`, so the
// bundle uses the streamed result protocol, as on the phone). page.evaluate
// strings run against the fake provider tab (lib/host.mjs TargetPage).
//
// usage: node lib/run-bundle.mjs <chatgpt|claude> <out.json>
//   env PDPP_CHATGPT_JS / PDPP_CLAUDE_JS, INPUTS_DIR
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";
import { installFrozenClock, TargetPage, runConnectorSource, FIXED_NOW_MS } from "./host.mjs";
import { chatgptUpstream } from "./chatgpt-upstream.mjs";
import { claudeUpstream } from "./claude-upstream.mjs";

installFrozenClock();
const [which, outPath] = process.argv.slice(2);
const inputs = process.env.INPUTS_DIR;
const log = [];
const requestLog = [];
const data = {};
const stateMessages = [];
const streamed = new Map(); // scope -> { chunks: [], done: false }
let streamDone = null;
let legacyResult = null;
let openScope = null;

let upstream, scriptPath, scopes, target, env = {};
if (which === "chatgpt") {
  scriptPath = process.env.PDPP_CHATGPT_JS;
  upstream = chatgptUpstream(join(inputs, "chatgpt"));
  scopes = ["chatgpt.conversations", "chatgpt.messages", "chatgpt.memories"];
  target = new TargetPage(upstream, { cookie: "oai-did=synthetic-device-0001; other=1", requestLog });
  // Same pacing override the data-connectors golden capture uses, so the
  // run is not throttled by wall-clock pacing (does not change records).
  env = { PDPP_CHATGPT_PACING_INITIAL_INTERVAL_MS: "1", PDPP_CHATGPT_PACING_MIN_INTERVAL_MS: "1" };
} else if (which === "claude") {
  scriptPath = process.env.PDPP_CLAUDE_JS;
  upstream = claudeUpstream(join(inputs, "claude"));
  scopes = ["claude.account_profile", "claude.conversations", "claude.messages", "claude.projects", "claude.project_documents"];
  target = new TargetPage(upstream, { requestLog });
} else throw new Error(`unknown connector ${which}`);
// The provider tab starts on the login URL, like the harness / phone.
target.goto(which === "chatgpt" ? "https://chatgpt.com/auth/login" : "https://claude.ai/login");
globalThis.__pageshimEnv = env;

// ── page_shim.dart captureDownload / extractZipEntries / readZipEntryChunk,
// as modelled by data-connectors scripts/pageshim/harness.mjs exportArchive().
let stash = null;
let extracted = null;
let mintedKeys = new Set();
const signedUrls = new Map();
function readZipJsonEntries(bytes, include) {
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 0xffff); i--)
    if (bytes.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return { ok: false, error: "not a zip (no EOCD)" };
  const count = bytes.readUInt16LE(eocd + 10);
  let off = bytes.readUInt32LE(eocd + 16);
  const names = [], entries = [], entryTexts = new Map();
  for (let n = 0; n < count; n++) {
    if (bytes.readUInt32LE(off) !== 0x02014b50) break;
    const method = bytes.readUInt16LE(off + 10);
    const compSize = bytes.readUInt32LE(off + 20);
    const nameLen = bytes.readUInt16LE(off + 28);
    const extraLen = bytes.readUInt16LE(off + 30);
    const commentLen = bytes.readUInt16LE(off + 32);
    const local = bytes.readUInt32LE(off + 42);
    const name = bytes.toString("utf8", off + 46, off + 46 + nameLen);
    off += 46 + nameLen + extraLen + commentLen;
    names.push(name);
    if (name.endsWith("/") || !name.endsWith(".json")) continue;
    if (include && !include.some((needle) => name.includes(needle))) continue;
    if (method !== 0 && method !== 8) continue;
    const start = local + 30 + bytes.readUInt16LE(local + 26) + bytes.readUInt16LE(local + 28);
    const raw = bytes.subarray(start, start + compSize);
    let text;
    try { text = (method === 0 ? raw : inflateRawSync(raw)).toString("utf8"); } catch { return { ok: false, error: "noinflate" }; }
    try { JSON.parse(text); entries.push({ name, size: text.length }); entryTexts.set(name, text); } catch {}
  }
  return { ok: true, handle: "run", names, entries, entryTexts };
}
const terminal = (outcome) => {
  const message = `The Claude export could not be downloaded (${outcome}).`;
  data.error = message;
  return { __shimError: message };
};
async function captureDownload(url) {
  const m = /\/export\/([^/]+)\/download\/([^/?#]+)/.exec(url);
  if (!m) return terminal("badurl");
  const key = `${m[1]}/${m[2]}`;
  let signedUrl = signedUrls.get(key);
  if (!signedUrl) {
    if (mintedKeys.has(key)) return terminal("consumed");
    let mint = null;
    try {
      mint = await target.evaluate(`(async () => {
        const r = await fetch("/api/organizations/" + ${JSON.stringify(encodeURIComponent(m[1]))} +
          "/export_signed_url/" + ${JSON.stringify(encodeURIComponent(m[2]))},
          { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: "{}" });
        const body = await r.text();
        let j = null; try { j = JSON.parse(body); } catch {}
        return { status: r.status, ok: r.ok, body: body.slice(0, 4096), url: j && (j.signed_url || j.signedUrl || j.url) };
      })()`);
    } catch {}
    if (!mint) return { ok: false, ready: false, error: "export not ready" };
    if (mint.status === 401 || mint.status === 403) return terminal("auth");
    if (!mint.ok) return mint.body.toLowerCase().includes("consumed") ? terminal("consumed") : { ok: false, ready: false, error: "export not ready" };
    mintedKeys.add(key);
    if (typeof mint.url !== "string" || !mint.url) return { ok: false, ready: false, error: "export not ready" };
    signedUrl = mint.url;
    signedUrls.set(key, signedUrl);
  }
  const res = upstream.resolve(signedUrl, { method: "GET" });
  requestLog.push({ method: "HOST-FETCH", url: signedUrl, status: res.status });
  if (res.status >= 500) return { ok: false, ready: false, error: "export not ready" };
  if (res.status < 200 || res.status >= 300) return terminal("httpfail");
  const bytes = Buffer.from(res.body);
  if (bytes.length < 2 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) return { ok: false, ready: false, error: "export not ready" };
  stash = bytes;
  return { ok: true, ready: true, path: null, name: "claude-export.zip", size: bytes.length };
}

const call = async (fn) => {
  const r = await fn();
  if (r && typeof r === "object" && typeof r.__shimError === "string") throw new Error(r.__shimError);
  return r;
};
const impl = {
  requestedScopes: () => scopes.slice(),
  // TIME_RANGE_SINCE models connector-policy.json scopeTimeWindows (the phone
  // asks chatgpt.* / claude.* for the last 30 days); unset = no window.
  requestedScopeEntries: () => scopes.map((name) => (process.env.TIME_RANGE_SINCE ? { name, time_range: { since: process.env.TIME_RANGE_SINCE } } : { name })),
  input: () => null,
  evaluate: (code) => call(async () => {
    try { return await target.evaluate(String(code)); } catch (e) { log.push(`evaluate failed: ${e?.message ?? e}`); return null; }
  }),
  goto: (url) => call(async () => { if (url) target.goto(url); return null; }),
  sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(Number(ms) || 0, 5))),
  setData: (key, value) => call(async () => {
    if (key === "result") { legacyResult = JSON.parse(JSON.stringify(value)); return null; }
    if (key === "result:begin") { openScope = value.scope; streamed.set(value.scope, { chunks: [], done: false }); return { accepted: true, nextSequence: 0 }; }
    if (key === "result:chunk") {
      const entry = streamed.get(value.scope);
      if (!entry || openScope !== value.scope || value.sequence !== entry.chunks.length) throw new Error("oracle: chunk protocol violation");
      entry.chunks.push(value.text);
      return { accepted: true, nextSequence: entry.chunks.length };
    }
    if (key === "result:scope-done") { const e = streamed.get(value.scope); if (value.chunkCount !== e.chunks.length) throw new Error("oracle: chunk count mismatch"); e.done = true; openScope = null; return { accepted: true }; }
    if (key === "result:done") { streamDone = JSON.parse(JSON.stringify(value)); return { accepted: true }; }
    if (key === "STATE") { stateMessages.push(JSON.parse(JSON.stringify(value))); return null; }
    data[key] = value;
    log.push(`setData ${key}: ${typeof value === "string" ? value.slice(0, 300) : JSON.stringify(value).slice(0, 300)}`);
    return null;
  }),
  setProgress: (p) => call(async () => { log.push(`progress: ${String(p?.message ?? "").slice(0, 200)}`); return null; }),
  showBrowser: () => call(async () => ({ headed: true })),
  goHeadless: () => call(async () => null),
  closeBrowser: () => call(async () => null),
  httpFetch: (url, opts) => call(async () => {
    const res = upstream.resolve(String(url), { method: opts?.method || "GET", body: opts?.body ?? null });
    requestLog.push({ method: `HTTPFETCH ${opts?.method || "GET"}`, url: String(url), status: res.status });
    const text = String(res.body ?? "");
    let json = null; try { json = JSON.parse(text); } catch {}
    return { ok: res.status >= 200 && res.status < 300, status: res.status, text, json, headers: { "content-type": res.contentType }, error: null };
  }),
  url: () => call(async () => target.url),
  html: () => call(async () => target.evaluate("document.documentElement.outerHTML")),
  click: () => call(async () => ({ __shimError: "oracle: page.click not implemented" })),
  fill: () => call(async () => ({ __shimError: "oracle: page.fill not implemented" })),
  press: () => call(async () => ({ __shimError: "oracle: page.press not implemented" })),
  waitForSelector: async (selector) => {
    const ok = await target.evaluate(`!!document.querySelector(${JSON.stringify(String(selector))})`).catch(() => false);
    if (!ok) throw new Error(`waitForSelector timed out: ${selector}`);
  },
  captureNetwork: () => call(async () => ({ __shimError: "oracle: page.captureNetwork not implemented" })),
  clearNetworkCaptures: () => call(async () => null),
  getCapturedResponse: () => call(async () => null),
  hasCapturedResponse: () => false,
  captureDownload: (u) => call(() => captureDownload(String(u))),
  extractZipEntries: async (_h, o) => {
    if (!stash) return { ok: false, error: "no captured download in this run" };
    const bytes = stash; stash = null;
    extracted = readZipJsonEntries(bytes, Array.isArray(o?.include) ? o.include.map(String) : null);
    return extracted.ok ? { ok: true, handle: extracted.handle, names: extracted.names, entries: extracted.entries } : extracted;
  },
  readZipEntryChunk: (h, name, offset, length) => call(async () => {
    if (h !== "run") return { ok: false, error: "zip entry is not available" };
    if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 1 || length > 120 * 1024)
      return { ok: false, error: "readZipEntryChunk requires a non-negative offset and length <= 122880" };
    const text = extracted?.entryTexts.get(name);
    if (text == null) return { ok: false, error: "zip entry is not available" };
    let end = Math.min(offset + length, text.length);
    if (end < text.length) { const next = text.charCodeAt(end); if (next >= 0xdc00 && next <= 0xdfff) end--; }
    return { ok: true, text: text.slice(offset, end) };
  }),
  promptUser: async () => { throw new Error("oracle: login prompt requested; fixture should be logged in"); },
};
const page = new Proxy(impl, {
  get(t, k) {
    if (typeof k === "symbol" || k === "then") return undefined;
    if (!Object.hasOwn(t, k)) throw new Error(`page.${k} is not part of the PageShim API`);
    return t[k];
  },
});

const origLog = console.log, origInfo = console.info;
console.log = (...a) => log.push(`[bundle] ${a.join(" ").slice(0, 400)}`);
console.info = console.log;
console.warn = console.log;
let threw = null;
try {
  await runConnectorSource(readFileSync(scriptPath, "utf8"), {
    page, process: Object.freeze({ env: Object.freeze({ ...env }) }), initialState: {},
  });
} catch (e) {
  threw = String(e?.stack ?? e);
}
console.log = origLog; console.info = origInfo;

const scopesOut = {};
for (const [scope, entry] of streamed) scopesOut[scope] = { complete: entry.done, value: JSON.parse(entry.chunks.join("")) };
writeFileSync(outPath, JSON.stringify({
  script: scriptPath,
  requestedScopes: scopes,
  timeRangeSince: process.env.TIME_RANGE_SINCE ?? null,
  clockNowMs: FIXED_NOW_MS,
  threw,
  streamedScopes: scopesOut,
  streamDone,
  legacyResult,
  stateMessages,
  data,
  log,
  requestLog,
  unknownUpstreamRequests: upstream.unknown,
}, null, 2));
origLog(`bundle ${which}: threw=${!!threw} scopes=${Object.keys(scopesOut).join(",")} done=${!!streamDone} error=${data.error ?? ""} unknown=${upstream.unknown.length}`);
