// Child process: runs ONE frozen legacy connector script (desktop/mobile
// playwright-runner page API) against a fake upstream, and writes what the
// script delivered via page.setData('result', ...) to argv[3].
//
// usage: node lib/run-legacy.mjs <chatgpt|claude> <out.json>
//   env LEGACY_CHATGPT_JS / LEGACY_CLAUDE_JS, INPUTS_DIR
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { installFrozenClock, TargetPage, runConnectorSource } from "./host.mjs";
import { chatgptUpstream } from "./chatgpt-upstream.mjs";
import { claudeUpstream } from "./claude-upstream.mjs";

installFrozenClock();
const require = createRequire(import.meta.url);
const [which, outPath] = process.argv.slice(2);
const inputs = process.env.INPUTS_DIR;

const data = {};
const log = [];
const requestLog = [];
let result = null;
let upstream, scriptPath, requestedScopes, target;
const extra = {};

if (which === "chatgpt") {
  scriptPath = process.env.LEGACY_CHATGPT_JS;
  upstream = chatgptUpstream(join(inputs, "chatgpt"));
  requestedScopes = ["chatgpt.conversations", "chatgpt.memories"];
  target = new TargetPage(upstream, { cookie: "oai-did=synthetic-device-0001; other=1", requestLog });
} else if (which === "claude") {
  scriptPath = process.env.LEGACY_CLAUDE_JS;
  upstream = claudeUpstream(join(inputs, "claude"));
  requestedScopes = ["claude.conversations", "claude.projects"];
  target = new TargetPage(upstream, { requestLog });
  // DataConnect playwright-runner captureDownload / extractZipEntries
  // (data-connect playwright-runner/index.cjs). The runner navigates to the
  // URL and saves the browser download; here the navigation is answered by
  // the fake upstream and the bytes are written to a scratch file. The ZIP is
  // then read with the runner's OWN zip-reader.cjs (vendored, unmodified).
  const { readZipJsonEntries } = require("./vendor/zip-reader.cjs");
  extra.captureDownload = async (url) => {
    const res = upstream.resolve(url, { method: "GET", body: null });
    requestLog.push({ method: "DOWNLOAD", url, status: res.status });
    const bytes = Buffer.isBuffer(res.body) ? res.body : null;
    if (res.status !== 200 || !bytes) return { ok: false, ready: false, error: "no download within timeout" };
    const dir = join(dirname(outPath), "legacy-downloads");
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, "claude-export.zip");
    writeFileSync(dest, bytes);
    return { ok: true, ready: true, path: dest, name: "claude-export.zip", size: bytes.length };
  };
  extra.extractZipEntries = async (zipPath, options = {}) => {
    try {
      const { names, json } = readZipJsonEntries(readFileSync(zipPath), options.include || null);
      return { ok: true, names, json };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  };
} else throw new Error(`unknown connector ${which}`);

const page = {
  requestedScopes: async () => requestedScopes,
  goto: async (url) => { target.goto(url); },
  sleep: async () => {},
  evaluate: async (code) => target.evaluate(code),
  setData: async (key, value) => {
    if (key === "result") result = JSON.parse(JSON.stringify(value));
    else { data[key] = value; log.push(`setData ${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`); }
  },
  setProgress: async (p) => { log.push(`progress: ${p?.message ?? ""}`); },
  showBrowser: async () => ({ headed: false }),
  goHeadless: async () => {},
  closeBrowser: async () => {},
  promptUser: async () => { throw new Error("oracle: login prompt requested; fixture should be logged in"); },
  ...extra,
};

const source = readFileSync(scriptPath, "utf8");
let returned;
try {
  returned = await runConnectorSource(source, { page });
} catch (e) {
  log.push(`script threw: ${e?.stack ?? e}`);
}
writeFileSync(outPath, JSON.stringify({
  script: scriptPath,
  requestedScopes,
  result,
  returnedSameAsResult: JSON.stringify(returned ?? null) === JSON.stringify(result),
  data,
  log,
  requestLog,
  unknownUpstreamRequests: upstream.unknown,
}, null, 2));
console.log(`legacy ${which}: result=${result ? "yes" : "NO"} unknown=${upstream.unknown.length}`);
