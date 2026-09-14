import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { requireLoopbackListener } from "./local-listener.js";

// Simulates what @hono/node-server puts in `c.env` for a real request:
// the Node IncomingMessage, whose socket tells us which listener received
// the connection. The tunnel (frpc) forwards to the main server port, so
// `localPort` is the one property a remote caller can never influence.
function socketEnv(socket: Record<string, unknown> | undefined) {
  return socket ? { incoming: { socket } } : { incoming: {} };
}

function makeApp(
  localApprovalPort: number | undefined,
  serverPort: number = 4000,
) {
  const app = new Hono();
  const gate = requireLoopbackListener({ localApprovalPort, serverPort });
  app.use("/ui", gate);
  app.use("/ui/*", gate);
  app.get("/ui", (c) => c.text("ui"));
  app.get("/ui/api/bootstrap", (c) => c.text("bootstrap"));
  app.get("/health", (c) => c.text("ok"));
  return app;
}

describe("requireLoopbackListener", () => {
  const LOOPBACK_PORT = 4001;
  const MAIN_PORT = 4000;

  it("allows a request that arrived on the loopback auth listener", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui",
      {},
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ui");
  });

  it("allows IPv6 loopback on the auth listener", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui/api/bootstrap",
      {},
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "::1" }),
    );
    expect(res.status).toBe(200);
  });

  // The exploit path: a tunneled request. frpc connects from 127.0.0.1 to
  // the MAIN server port, so remote traffic looks local by peer address —
  // the listener port is what distinguishes it.
  it("404s a request that arrived on the main (tunneled) server port", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui",
      {},
      socketEnv({
        localPort: MAIN_PORT,
        localAddress: "127.0.0.1",
        remoteAddress: "127.0.0.1",
      }),
    );
    expect(res.status).toBe(404);
  });

  it("404s subpaths on the main port too", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui/api/bootstrap",
      {},
      socketEnv({ localPort: MAIN_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  it("404s when the listener address is not loopback even on the right port", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui",
      {},
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "10.0.0.5" }),
    );
    expect(res.status).toBe(404);
  });

  it("fails closed when there is no socket information", async () => {
    const app = makeApp(LOOPBACK_PORT);
    expect((await app.request("/ui", {}, socketEnv(undefined))).status).toBe(
      404,
    );
    expect((await app.request("/ui")).status).toBe(404);
  });

  it("fails closed when no loopback listener is configured (cloud mode)", async () => {
    const app = makeApp(undefined);
    const res = await app.request(
      "/ui",
      {},
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  // Misconfiguration guard: if LOCAL_AUTH_PORT collides with the main server
  // port, the loopback bind fails (EADDRINUSE) but the port value is still
  // set — every tunneled request on the main port would then match it.
  it("fails closed when the loopback port equals the main server port", async () => {
    const app = makeApp(MAIN_PORT, MAIN_PORT);
    const res = await app.request(
      "/ui",
      {},
      socketEnv({ localPort: MAIN_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  // Drive-by guard: the app's global CORS is `*`, so a hostile web page in
  // the user's browser can fetch the loopback listener directly (in browsers
  // without Private Network Access enforcement). Cross-origin fetches always
  // carry an Origin header naming the hostile site; reject those.
  it("404s a request carrying a non-loopback Origin header", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui",
      { headers: { origin: "https://evil.example" } },
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  it("404s a cross-origin preflight for the bootstrap endpoint", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/ui/api/bootstrap",
      {
        method: "OPTIONS",
        headers: {
          origin: "https://evil.example",
          "access-control-request-headers": "authorization",
        },
      },
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  it("allows the page's own origin (same-origin fetch)", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      `http://127.0.0.1:${LOOPBACK_PORT}/ui/api/bootstrap`,
      { headers: { origin: `http://127.0.0.1:${LOOPBACK_PORT}` } },
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(200);
  });

  // Hostname heuristics are bypassable: these are PUBLIC DNS names that a
  // `startsWith("127.")` check would have waved through.
  it("404s public origins that merely look like loopback", async () => {
    const app = makeApp(LOOPBACK_PORT);
    for (const origin of [
      "https://127.attacker.example",
      "https://127.0.0.1.attacker.example",
      "http://localhost.attacker.example",
    ]) {
      const res = await app.request(
        `http://127.0.0.1:${LOOPBACK_PORT}/ui`,
        { headers: { origin } },
        socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
      );
      expect(res.status, origin).toBe(404);
    }
  });

  // Another local dev server in the same browser is still a foreign origin.
  it("404s a different local origin", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      `http://127.0.0.1:${LOOPBACK_PORT}/ui`,
      { headers: { origin: "http://localhost:12345" } },
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  // DNS rebinding: the attacker points a name they control at 127.0.0.1 and
  // fetches it from their page. Host and Origin then AGREE, and the browser
  // treats the response as same-origin — so the request's own hostname must
  // itself be loopback, regardless of Origin.
  it("404s a DNS-rebound hostname even when Origin matches it", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const withOrigin = await app.request(
      `http://attacker.example:${LOOPBACK_PORT}/ui`,
      { headers: { origin: `http://attacker.example:${LOOPBACK_PORT}` } },
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(withOrigin.status).toBe(404);
    // A same-origin fetch may omit Origin entirely; Host alone must fail.
    const withoutOrigin = await app.request(
      `http://attacker.example:${LOOPBACK_PORT}/ui/api/bootstrap`,
      {},
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(withoutOrigin.status).toBe(404);
  });

  it("404s a *.localhost subdomain (only the exact name is trusted)", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      `http://evil.localhost:${LOOPBACK_PORT}/ui`,
      {},
      socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
    );
    expect(res.status).toBe(404);
  });

  it("accepts loopback request hosts in every spelling", async () => {
    const app = makeApp(LOOPBACK_PORT);
    for (const host of ["localhost", "127.0.0.1", "127.1.2.3", "[::1]"]) {
      const res = await app.request(
        `http://${host}:${LOOPBACK_PORT}/ui`,
        {},
        socketEnv({ localPort: LOOPBACK_PORT, localAddress: "127.0.0.1" }),
      );
      expect(res.status, host).toBe(200);
    }
  });

  it("accepts loopback socket addresses in every spelling", async () => {
    const app = makeApp(LOOPBACK_PORT);
    for (const localAddress of [
      "127.0.0.1",
      "127.1.2.3",
      "::1",
      "::ffff:127.0.0.1",
    ]) {
      const res = await app.request(
        "/ui",
        {},
        socketEnv({ localPort: LOOPBACK_PORT, localAddress }),
      );
      expect(res.status, localAddress).toBe(200);
    }
  });

  it("does not affect routes outside /ui", async () => {
    const app = makeApp(LOOPBACK_PORT);
    const res = await app.request(
      "/health",
      {},
      socketEnv({ localPort: MAIN_PORT, localAddress: "0.0.0.0" }),
    );
    expect(res.status).toBe(200);
  });
});
