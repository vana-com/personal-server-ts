// Shared host plumbing for the parity oracle.
//
// - installFrozenClock(): makes `Date.now()` and `new Date()` deterministic.
// - TargetPage: a model of the provider tab (chatgpt.com / claude.ai). It holds
//   the current URL and a DOM parsed (linkedom) from the HTML the upstream
//   fixture serves for that URL. `evaluate(code)` runs a code string in a
//   fresh-per-navigation vm context whose `fetch` is served by the upstream
//   fixture (no network). The return value crosses a JSON boundary, like the
//   real Playwright / WebView bridges.
import vm from "node:vm";
import { parseHTML } from "linkedom";

export const FIXED_NOW_ISO = "2026-10-01T00:00:00.000Z";
export const FIXED_NOW_MS = Date.parse(FIXED_NOW_ISO);

export function installFrozenClock(nowMs = FIXED_NOW_MS) {
  const RealDate = Date;
  class FrozenDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) super(nowMs);
      else super(...args);
    }
    static now() {
      return nowMs;
    }
  }
  FrozenDate.parse = RealDate.parse;
  FrozenDate.UTC = RealDate.UTC;
  globalThis.Date = FrozenDate;
  return FrozenDate;
}

/**
 * upstream.resolve(url, {method, body, headers}) -> {status, contentType, body, headers?}
 * Every request is appended to `requestLog`.
 */
export function makeFetch(upstream, requestLog, baseUrlRef) {
  return async function fetch(input, init = {}) {
    const raw = typeof input === "string" ? input : input?.url ?? String(input);
    const url = new URL(raw, baseUrlRef()).href;
    const method = (init.method || "GET").toUpperCase();
    const body = init.body == null ? null : String(init.body);
    if (init.signal?.aborted) throw new Error("The operation was aborted.");
    const res = upstream.resolve(url, { method, body });
    requestLog.push({ method, url, status: res.status });
    const headers = new Headers({ "content-type": res.contentType || "application/json", ...(res.headers || {}) });
    return new Response(res.status === 204 ? null : res.body, { status: res.status, headers });
  };
}

export class TargetPage {
  constructor(upstream, { cookie = "", requestLog = [] } = {}) {
    this.upstream = upstream;
    this.cookie = cookie;
    this.requestLog = requestLog;
    this.navigations = [];
    this.url = "about:blank";
    this.context = null;
  }

  goto(url) {
    this.navigations.push(url);
    const res = this.upstream.resolve(url, { method: "GET", body: null });
    this.requestLog.push({ method: "NAVIGATE", url, status: res.status });
    this.url = url;
    const html = (res.contentType || "").includes("html") ? String(res.body) : "<!doctype html><html><body></body></html>";
    this.#buildContext(html);
  }

  #buildContext(html) {
    const { window, document } = parseHTML(html);
    const cookie = this.cookie;
    Object.defineProperty(document, "cookie", { get: () => cookie, set: () => {}, configurable: true });
    const loc = new URL(this.url);
    const self = this;
    const g = {
      document,
      location: { href: loc.href, origin: loc.origin, pathname: loc.pathname, host: loc.host, hostname: loc.hostname, protocol: loc.protocol, search: loc.search },
      navigator: { userAgent: "Mozilla/5.0 (parity-oracle)", language: "en-US" },
      fetch: makeFetch(this.upstream, this.requestLog, () => self.url),
      Response, Headers, Request, AbortController, AbortSignal, URL, URLSearchParams,
      TextEncoder, TextDecoder, Blob, atob, btoa, crypto: globalThis.crypto, performance: globalThis.performance,
      setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, structuredClone,
      console, Date: globalThis.Date,
      Event: window.Event, HTMLElement: window.HTMLElement, Node: window.Node,
      // No IndexedDB on this target: the legacy ChatGPT/Claude checkpoint code
      // treats an unavailable store as "fresh run, nothing checkpointed".
    };
    g.window = g;
    g.self = g;
    g.globalThis = g;
    this.context = vm.createContext(g);
  }

  /** Runs `code` like Playwright `page.evaluate(string)` / page_shim evaluate:
   * first as an expression (awaited), then as a function body. Throws on a
   * page error; result is JSON-cloned. */
  async evaluate(code) {
    if (!this.context) this.#buildContext("<!doctype html><html><body></body></html>");
    const trimmed = String(code).trim();
    let script;
    try {
      script = new vm.Script(`(async () => { return await (${trimmed}\n); })()`);
    } catch {
      script = new vm.Script(`(async () => { ${trimmed}\n })()`);
    }
    const value = await script.runInContext(this.context);
    return value === undefined ? null : JSON.parse(JSON.stringify(value));
  }
}

export function html(body) {
  return { status: 200, contentType: "text/html; charset=utf-8", body: `<!doctype html><html><head></head><body>${body}</body></html>` };
}
export function json(value, status = 200) {
  return { status, contentType: "application/json", body: JSON.stringify(value) };
}

/** Runs a connector source the way both runners do: the LAST line-leading
 * `(async () => {` IIFE is turned into a `return`, and the script runs as an
 * AsyncFunction with the given named arguments. */
export async function runConnectorSource(source, args) {
  const re = /(?:^|\n)\(async\s*\(\)\s*=>\s*\{/g;
  const matches = [...source.matchAll(re)];
  if (matches.length === 0) throw new Error("no main IIFE found in connector source");
  const last = matches.at(-1);
  const lead = last[0].startsWith("\n") ? "\n" : "";
  const code = `${source.slice(0, last.index)}${lead}return (async () => {${source.slice(last.index + last[0].length)}`;
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  const names = Object.keys(args);
  return await new AsyncFunction(...names, code)(...names.map((n) => args[n]));
}
