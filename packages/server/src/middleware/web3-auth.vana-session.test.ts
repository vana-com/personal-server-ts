// Tests for the vana-session auth mechanism in web3-auth.ts.
//
// PS calls account.vana.org's /api/oauth/introspect proxy to verify Vana
// session tokens. Authorization is two-step:
//   1. Hydra-side: aud must include the stable PS-family identifier
//      "vana-personal-server".
//   2. Resource-side: one of the user's linked wallets must equal the PS's
//      configured serverOwner. This is the load-bearing check that
//      prevents user A's token being usable on user B's PS.

import { describe, expect, it, beforeEach, vi } from "vitest";
import { Hono } from "hono";
import {
  __clearVanaIntrospectionCacheForTests,
  createWeb3AuthMiddleware,
} from "./web3-auth.js";

const VANA_PS_AUDIENCE = "vana-personal-server";
const INTROSPECT_URL = "https://account-dev.vana.org/api/oauth/introspect";
const SERVER_OWNER = "0x4Ed00B8ceEF2B05d3Ee798a778a1E92A79f8a549";
const PS_PUBLIC_URL = "https://0xfake.myvana.app";

function buildApp(introspectFetch: typeof fetch) {
  const app = new Hono();
  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: PS_PUBLIC_URL,
    vanaIntrospectionUrl: INTROSPECT_URL,
    serverOwner: SERVER_OWNER as `0x${string}`,
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
  vi.stubGlobal("fetch", introspectFetch);
  return app;
}

beforeEach(() => {
  __clearVanaIntrospectionCacheForTests();
  vi.unstubAllGlobals();
});

describe("vana-session mechanism", () => {
  it("accepts a valid Vana access token whose linked_wallets include this PS's owner", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: `vana_user_${"0".repeat(32)}`,
          aud: ["account.vana.org", VANA_PS_AUDIENCE],
          exp: Math.floor(Date.now() / 1000) + 600,
          linked_wallets: [
            {
              vana_wallet_id: "vana_wallet_x",
              address: SERVER_OWNER,
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
    expect(body.signer.toLowerCase()).toBe(SERVER_OWNER.toLowerCase());
  });

  it("matches owner against any linked wallet, not just the primary", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: `vana_user_${"0".repeat(32)}`,
          aud: [VANA_PS_AUDIENCE],
          linked_wallets: [
            {
              address: "0x1111111111111111111111111111111111111111",
              chain_type: "evm",
              is_primary: true,
            },
            {
              address: SERVER_OWNER,
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
    expect(body.signer.toLowerCase()).toBe(SERVER_OWNER.toLowerCase());
  });

  it("matches owner case-insensitively", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: `vana_user_${"0".repeat(32)}`,
          aud: [VANA_PS_AUDIENCE],
          linked_wallets: [
            {
              address: SERVER_OWNER.toLowerCase(),
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
  });

  it("rejects when audience does not include vana-personal-server", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: `vana_user_${"0".repeat(32)}`,
          aud: ["account.vana.org"], // missing vana-personal-server
          linked_wallets: [
            { address: SERVER_OWNER, chain_type: "evm", is_primary: true },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ) as unknown as typeof fetch;
    const app = buildApp(fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    // Falls through to Web3Signed verification → 401.
    expect(res.status).toBe(401);
  });

  it("rejects when no linked_wallets entry matches this PS's owner", async () => {
    // The user is signed in but doesn't own this PS.
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: `vana_user_${"0".repeat(32)}`,
          aud: [VANA_PS_AUDIENCE],
          linked_wallets: [
            {
              address: "0x1111111111111111111111111111111111111111",
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

  it("rejects when linked_wallets is empty", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          active: true,
          sub: `vana_user_${"0".repeat(32)}`,
          aud: [VANA_PS_AUDIENCE],
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
          sub: `vana_user_${"0".repeat(32)}`,
          aud: [VANA_PS_AUDIENCE],
          linked_wallets: [
            { address: SERVER_OWNER, chain_type: "evm", is_primary: true },
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

  it("does not fire when vanaIntrospectionUrl is unset", async () => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const app = new Hono();
    const web3Auth = createWeb3AuthMiddleware({
      serverOrigin: PS_PUBLIC_URL,
      // vanaIntrospectionUrl intentionally omitted
      serverOwner: SERVER_OWNER as `0x${string}`,
    });
    app.use("*", web3Auth);
    app.get("/probe", (c) => c.json({}));
    vi.stubGlobal("fetch", fetchMock);

    const res = await app.request("/probe", {
      headers: { authorization: "Bearer vana_access_tok" },
    });
    expect(res.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
