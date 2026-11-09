import { describe, expect, it } from "vitest";
import { DEV_GATEWAY_URL, DEV_STORAGE_URL, pinHosts } from "./hosts.js";

const refused = { code: "host_not_pinned" };

describe("pinned Dev hosts", () => {
  it("defaults to the Dev gateway and storage", () => {
    const pinned = pinHosts({ gatewayUrl: undefined, storageUrl: undefined });
    expect(pinned.gatewayUrl).toBe(DEV_GATEWAY_URL);
    expect(pinned.storageUrl).toBe(DEV_STORAGE_URL);
    expect(pinned.allowed).toEqual([
      "data-gateway-env-dev-opendatalabs.vercel.app",
      "storage-dev.vana.org",
    ]);
  });

  it("refuses every other host, scheme, port and userinfo", () => {
    for (const gatewayUrl of [
      "https://gateway.evil.test",
      "http://data-gateway-env-dev-opendatalabs.vercel.app",
      "https://data-gateway-env-dev-opendatalabs.vercel.app:8443",
      "https://user:pw@data-gateway-env-dev-opendatalabs.vercel.app",
      "https://data-gateway-env-dev-opendatalabs.vercel.app.evil.test",
      "not a url",
    ]) {
      expect(
        () => pinHosts({ gatewayUrl, storageUrl: undefined }),
        gatewayUrl,
      ).toThrow(expect.objectContaining(refused));
    }
    for (const storageUrl of [
      "https://storage.vana.org",
      "https://storage-dev.vana.org.evil.test",
    ]) {
      expect(
        () => pinHosts({ gatewayUrl: undefined, storageUrl }),
        storageUrl,
      ).toThrow(expect.objectContaining(refused));
    }
  });

  it("allows loopback only with the test-only switch, and with an explicit port", () => {
    const url = "http://127.0.0.1:4321";
    expect(() => pinHosts({ gatewayUrl: url, storageUrl: undefined })).toThrow(
      expect.objectContaining(refused),
    );
    expect(() =>
      pinHosts({
        gatewayUrl: "http://127.0.0.1",
        storageUrl: url,
        testOnlyAllowLoopback: true,
      }),
    ).toThrow(expect.objectContaining(refused));
    expect(
      pinHosts({
        gatewayUrl: url,
        storageUrl: url,
        testOnlyAllowLoopback: true,
      }).allowed,
    ).toEqual(["127.0.0.1:4321", "127.0.0.1:4321"]);
  });
});
