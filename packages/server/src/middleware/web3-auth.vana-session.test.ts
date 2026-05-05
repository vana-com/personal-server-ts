// Tests for the vana-session auth mechanism in web3-auth.ts.
//
// PS calls account.vana.org's /api/oauth/introspect proxy to verify Vana
// session tokens. The proxy forwards to Hydra admin and enriches the
// response with the user's linked_wallets[]. PS validates audience against
// its own public URL, then sets auth.signer to the primary EVM wallet.

import { describe, expect, it, beforeEach, vi } from "vitest";
import { Hono } from "hono";
import {
  __clearVanaIntrospectionCacheForTests,
  createWeb3AuthMiddleware,
} from "./web3-auth.js";

const PS_PUBLIC_URL = "https://0xfake.myvana.app";
const INTROSPECT_URL = "https://account-dev.vana.org/api/oauth/introspect";
const PRIMARY_WALLET = "0x4Ed00B8ceEF2B05d3Ee798a778a1E92A79f8a549";

function buildApp(introspectFetch: typeof fetch) {
  const app = new Hono();
  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: PS_PUBLIC_URL,
    serverPublicUrl: PS_PUBLIC_URL,
    vanaIntrospectionUrl: INTROSPECT_URL,
    serverOwner: "0xC3E895d1279bF0Bf2Ae25A8964c79595484cd6e8" as `0x${string}`,
  });
  app.use("*", web3Auth);
  app.get("/probe", (c) => {
    const auth = (c as unknown as { get: (k: string) => unknown }).get(
      "auth",
    ) as { signer?: string } | undefined;
    const mech = (c as unknown as { get: (k: string) => unknown }).get(
      "authMechanism",
    ) as string | undefined;
    return c.json({ signer: auth?.signer, mechanism: mech });
  });
  // Stub global fetch for the introspection round-trip.
  vi.stubGlobal("fetch", introspectFetch);
  return app;
}

beforeEach(() => {
  __clearVanaIntrospectionCacheForTests();
  vi.unstubAllGlobals();
});

describe("vana-session mechanism", () => {
  it("accepts a valid Vana access token; signer = primary linked wallet", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: "vana_user_" + "0".repeat(32),
          aud: ["account.vana.org", PS_PUBLIC_URL],
          exp: Math.floor(Date.now() / 1000) + 600,
          linked_wallets: [
            {
              vana_wallet_id: "vana_wallet_x",
              address: PRIMARY_WALLET,
              chain_type: "evm",
              is_primary: true,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.mechanism).toBe("vana-session");
    expect(body.signer).toBe(PRIMARY_WALLET);
  });

  it("rejects when audience does not include the PS URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: "vana_user_" + "0".repeat(32),
          aud: ["account.vana.org"], // does NOT include PS URL
          linked_wallets: [
            { address: PRIMARY_WALLET, chain_type: "evm", is_primary: true },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    // Falls through to web3-signed; no Web3Signed prefix → 401.
    expect(res.status).toBe(401);
  });

  it("rejects when introspection returns active=false", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects when no linked_wallets in response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: "vana_user_" + "0".repeat(32),
          aud: [PS_PUBLIC_URL],
          linked_wallets: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    expect(res.status).toBe(401);
  });

  it("falls back when introspection round-trip fails", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValue(new Error("network down")) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    expect(res.status).toBe(401);
  });

  it("caches introspection results within 30s window", async () => {
    let calls = 0;
    const fetchMock = vi.fn().mockImplementation(async () => {
      calls++;
      return new Response(
        JSON.stringify({
          active: true,
          sub: "vana_user_" + "0".repeat(32),
          aud: [PS_PUBLIC_URL],
          linked_wallets: [
            { address: PRIMARY_WALLET, chain_type: "evm", is_primary: true },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    await app.request("/probe", {
      headers: { authorization: "Bearer same_token" },
    });
    await app.request("/probe", {
      headers: { authorization: "Bearer same_token" },
    });
    await app.request("/probe", {
      headers: { authorization: "Bearer same_token" },
    });
    expect(calls).toBe(1);
  });

  it("uses non-primary wallet if no primary is marked", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: "vana_user_" + "0".repeat(32),
          aud: [PS_PUBLIC_URL],
          linked_wallets: [
            {
              address: PRIMARY_WALLET,
              chain_type: "evm",
              is_primary: false,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.signer).toBe(PRIMARY_WALLET);
  });

  it("does not fire when vanaIntrospectionUrl is unset", async () => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const app = new Hono();
    const web3Auth = createWeb3AuthMiddleware({
      serverOrigin: PS_PUBLIC_URL,
      // vanaIntrospectionUrl intentionally omitted
      serverOwner:
        "0xC3E895d1279bF0Bf2Ae25A8964c79595484cd6e8" as `0x${string}`,
    });
    app.use("*", web3Auth);
    app.get("/probe", (c) => c.json({}));
    vi.stubGlobal("fetch", fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    // Falls through to Web3Signed verification → 401.
    expect(res.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
