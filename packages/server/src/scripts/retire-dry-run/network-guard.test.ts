import http, { ClientRequest, createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import https from "node:https";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installNetworkGuard, NetworkGuardError } from "./network-guard.js";

// Declared before any guard installs: a subclass of the real class, as a
// library could hold one from its import time.
class EarlySub extends http.ClientRequest {}

let guard: ReturnType<typeof installNetworkGuard> | null = null;
const servers: Server[] = [];
afterEach(async () => {
  guard?.uninstall();
  guard = null;
  vi.unstubAllGlobals();
  for (const server of servers.splice(0)) {
    await new Promise((r) => server.close(r));
  }
});

/** A loopback server; `hits` counts the requests it receives. */
async function listen(
  reply: (res: http.ServerResponse) => void,
): Promise<{ port: number; hits: () => number }> {
  let hits = 0;
  const server = createServer((_req, res) => {
    hits += 1;
    reply(res);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as AddressInfo).port, hits: () => hits };
}

describe("network guard", () => {
  it("passes a GET to an allowed host and refuses everything else", async () => {
    const base = vi.fn(async () => new Response("ok"));
    vi.stubGlobal("fetch", base);
    guard = installNetworkGuard({ allowedHosts: ["gateway.test"] });

    await expect(fetch("https://gateway.test/v1/data")).resolves.toBeInstanceOf(
      Response,
    );
    await expect(
      fetch("https://gateway.test/v1/data", { method: "POST" }),
    ).rejects.toMatchObject({
      violation: { reason: "method_not_get" },
    });
    await expect(
      fetch("https://gateway.test/x", { method: "delete" }),
    ).rejects.toBeInstanceOf(NetworkGuardError);
    await expect(fetch("https://other.test/v1/data")).rejects.toMatchObject({
      violation: { reason: "host_not_allowed" },
    });
    await expect(
      fetch(
        new Request("https://gateway.test/v1", { method: "PUT", body: "x" }),
      ),
    ).rejects.toBeInstanceOf(NetworkGuardError);
    expect(base).toHaveBeenCalledTimes(1);
    expect(guard.violations).toHaveLength(4);
    expect(() => guard!.assertNoViolations()).toThrow(NetworkGuardError);
  });

  it("covers http and https request and get", () => {
    guard = installNetworkGuard({ allowedHosts: ["gateway.test"] });
    expect(() =>
      https.request("https://gateway.test/x", { method: "POST" }),
    ).toThrow(NetworkGuardError);
    expect(() =>
      http.request({ hostname: "other.test", method: "GET" }),
    ).toThrow(NetworkGuardError);
    expect(() => https.get("https://other.test/")).toThrow(NetworkGuardError);
    expect(guard.violations).toHaveLength(3);
  });

  it("checks the host Node connects to: options hostname over the URL, a port, a socket", () => {
    guard = installNetworkGuard({ allowedHosts: ["gateway.test"] });
    // Node merges the options over the URL, and `hostname` wins over `host`.
    expect(() =>
      https.get("https://gateway.test/x", { hostname: "other.test" }),
    ).toThrow(NetworkGuardError);
    expect(() =>
      https.get("https://gateway.test/x", { hostname: undefined }),
    ).toThrow(NetworkGuardError); // falls to localhost
    expect(() => http.get({ host: "other.test" })).toThrow(NetworkGuardError);
    expect(() => http.get({ host: "other.test", hostname: "" })).toThrow(
      NetworkGuardError,
    );
    expect(() => https.get("https://gateway.test/x", { port: 8443 })).toThrow(
      NetworkGuardError,
    );
    expect(() =>
      http.get({ hostname: "gateway.test", socketPath: "/tmp/x.sock" }),
    ).toThrow(NetworkGuardError);
    expect(guard.violations).toHaveLength(6);
  });

  it("covers a ClientRequest built directly (http, and https through its agent)", async () => {
    const ok = await listen((res) => res.end("ok"));
    guard = installNetworkGuard({
      allowedHosts: ["gateway.test", `127.0.0.1:${ok.port}`],
    });
    expect(() => new http.ClientRequest("http://other.test/")).toThrow(
      NetworkGuardError,
    );
    expect(
      () =>
        new http.ClientRequest({
          hostname: "gateway.test",
          method: "POST",
        }),
    ).toThrow(NetworkGuardError);
    // An https request is a ClientRequest with the https agent and protocol.
    expect(
      () =>
        new http.ClientRequest({
          protocol: "https:",
          agent: https.globalAgent,
          hostname: "other.test",
        }),
    ).toThrow(NetworkGuardError);
    expect(
      () =>
        new ClientRequest({
          protocol: "https:",
          agent: https.globalAgent,
          hostname: "gateway.test",
          method: "PUT",
        }),
    ).toThrow(NetworkGuardError);
    // A subclass reaches the guard through super().
    class Sub extends http.ClientRequest {}
    expect(() => new Sub("http://other.test/")).toThrow(NetworkGuardError);
    expect(guard.violations).toHaveLength(5);
    // A subclass declared before the guard installed is checked too.
    expect(() => new EarlySub("http://other.test/")).toThrow(NetworkGuardError);
    expect(guard.violations).toHaveLength(6);

    // An allowed GET still works, and is a real ClientRequest.
    const request = new http.ClientRequest(`http://127.0.0.1:${ok.port}/`);
    const body = await new Promise<string>((resolve, reject) => {
      request.on("response", (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve(text));
      });
      request.on("error", reject);
      request.end();
    });
    expect(body).toBe("ok");
    expect(request).toBeInstanceOf(http.ClientRequest);
  });

  it("checks the agent's own host and port, which Node connects to instead", async () => {
    const ok = await listen((res) => res.end("ok"));
    guard = installNetworkGuard({ allowedHosts: ["gateway.test"] });
    // The request names an allowed host; the agent sends it to loopback.
    expect(() =>
      http.get("http://gateway.test/x", {
        agent: new http.Agent({ host: "127.0.0.1", port: ok.port }),
      }),
    ).toThrow(NetworkGuardError);
    expect(() =>
      http.get("http://gateway.test/x", {
        agent: new http.Agent({ hostname: "127.0.0.1" }),
      }),
    ).toThrow(NetworkGuardError);
    // A port the agent names, on the allowed host, is not an allowed port.
    expect(() =>
      http.get("http://gateway.test/x", {
        agent: new http.Agent({ port: ok.port }),
      }),
    ).toThrow(NetworkGuardError);
    expect(guard.violations.map((v) => v.host)).toEqual([
      "127.0.0.1",
      "127.0.0.1",
      "gateway.test",
    ]);
    expect(ok.hits()).toBe(0);
  });

  it("allows a host:port entry for that port only", async () => {
    const ok = await listen((res) => res.end("ok"));
    guard = installNetworkGuard({ allowedHosts: [`127.0.0.1:${ok.port}`] });
    const body = await new Promise<string>((resolve, reject) => {
      http
        .get(`http://127.0.0.1:${ok.port}/`, (res) => {
          let text = "";
          res.on("data", (c) => (text += c));
          res.on("end", () => resolve(text));
        })
        .on("error", reject);
    });
    expect(body).toBe("ok");
    expect(() => http.get(`http://127.0.0.1:${ok.port + 1}/`)).toThrow(
      NetworkGuardError,
    );
  });

  it("asks fetch not to follow a redirect", async () => {
    const base = vi.fn(async (_t: unknown, _i?: RequestInit) => new Response());
    vi.stubGlobal("fetch", base);
    guard = installNetworkGuard({ allowedHosts: ["gateway.test"] });
    await fetch("https://gateway.test/x");
    await fetch(new Request("https://gateway.test/y"), { redirect: "follow" });
    expect(base.mock.calls.map((c) => c[1]?.redirect)).toEqual([
      "error",
      "error",
    ]);
  });

  it("does not follow a redirect from an allowed host to another (fetch)", async () => {
    const target = await listen((res) => res.end("other host"));
    const first = await listen((res) => {
      res.writeHead(302, { location: `http://127.0.0.1:${target.port}/` });
      res.end();
    });
    guard = installNetworkGuard({ allowedHosts: [`127.0.0.1:${first.port}`] });
    await expect(fetch(`http://127.0.0.1:${first.port}/`)).rejects.toThrow();
    expect(first.hits()).toBe(1);
    expect(target.hits()).toBe(0);
  });

  it("returns a redirect from http.get as it is, with no second request", async () => {
    const target = await listen((res) => res.end("other host"));
    const first = await listen((res) => {
      res.writeHead(302, { location: `http://127.0.0.1:${target.port}/` });
      res.end();
    });
    guard = installNetworkGuard({ allowedHosts: [`127.0.0.1:${first.port}`] });
    const status = await new Promise<number>((resolve, reject) => {
      http
        .get(`http://127.0.0.1:${first.port}/`, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        })
        .on("error", reject);
    });
    expect(status).toBe(302);
    expect(target.hits()).toBe(0);
  });

  it("uninstall restores the originals", () => {
    const originals = () => [
      globalThis.fetch,
      http.request,
      https.get,
      http.ClientRequest,
      http.Agent.prototype.addRequest,
    ];
    const before = originals();
    guard = installNetworkGuard({ allowedHosts: [] });
    expect(globalThis.fetch).not.toBe(before[0]);
    expect(http.Agent.prototype.addRequest).not.toBe(before[4]);
    guard.uninstall();
    guard = null;
    expect(originals()).toEqual(before);
  });
});
