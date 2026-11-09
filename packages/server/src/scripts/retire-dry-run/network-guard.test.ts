import http from "node:http";
import https from "node:https";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installNetworkGuard, NetworkGuardError } from "./network-guard.js";

let guard: ReturnType<typeof installNetworkGuard> | null = null;
afterEach(() => {
  guard?.uninstall();
  guard = null;
  vi.unstubAllGlobals();
});

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

  it("uninstall restores the originals", () => {
    const before = [globalThis.fetch, http.request, https.get];
    guard = installNetworkGuard({ allowedHosts: [] });
    expect(globalThis.fetch).not.toBe(before[0]);
    guard.uninstall();
    guard = null;
    expect([globalThis.fetch, http.request, https.get]).toEqual(before);
  });
});
