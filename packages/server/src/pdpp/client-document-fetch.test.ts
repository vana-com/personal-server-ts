/**
 * The bounded production fetcher, against a REAL local HTTPS server —
 * not a mocked transport. The bounds this module claims (HTTPS-only, no
 * redirect traversal, one timeout across headers+body, a streamed byte cap,
 * connect-time address validation) are only proven by making Node actually
 * dial a socket and hitting them.
 *
 * `isBlockedAddress` is exercised directly for the address-range table, and
 * through the real fetcher for the connect-time integration: a hostname that
 * resolves (via a stubbed DNS) to a blocked literal must never reach the
 * server, proving the guard runs where the task requires — at connection
 * time, not just as a string check on the requested hostname.
 */

import {
  createServer as createHttpServer,
  type Server as HttpServer,
} from "node:http";
import {
  createServer as createHttpsServer,
  type Server as HttpsServer,
} from "node:https";
import type { AddressInfo } from "node:net";
import type * as NodeDns from "node:dns";
import tls from "node:tls";
import * as forge from "node-forge";
import { afterEach, describe, expect, it, vi } from "vitest";

// Stubs the real DNS resolution path the guard calls, so the rebinding test
// below proves the guard reacts to what `dns.lookup` actually answers with —
// not to a fetcher-level override that would bypass the guard's own logic.
const EMPTY_ANSWERS = Symbol("empty-dns-answers");
let stubbedLookupAddress: string | typeof EMPTY_ANSWERS | undefined;
vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeDns>();
  const lookup: typeof actual.lookup = ((
    hostname: string,
    options: unknown,
    callback: (
      err: null,
      addresses: { address: string; family: number }[],
    ) => void,
  ) => {
    if (stubbedLookupAddress === EMPTY_ANSWERS) {
      return callback(null, []);
    }
    if (stubbedLookupAddress) {
      return callback(null, [{ address: stubbedLookupAddress, family: 4 }]);
    }
    return (actual.lookup as (...args: unknown[]) => void)(
      hostname,
      options,
      callback,
    );
  }) as typeof actual.lookup;
  return { ...actual, lookup, default: { ...actual, lookup } };
});

const {
  FETCH_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  isBlockedAddress,
  boundedClientDocumentFetcher,
  __testing,
} = await import("./client-document-fetch.js");

const { createBoundedFetcher, buildGuardedAgent } = __testing;

/** A short-lived self-signed cert for `localhost`, trusted only by the test agent. */
function issueLocalCert() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: "localhost" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    {
      name: "subjectAltName",
      altNames: [
        { type: 2, value: "localhost" }, // DNS
        { type: 7, ip: "127.0.0.1" }, // IP — lets a literal-IP URL validate too
      ],
    },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

const { cert, key } = issueLocalCert();

let server: HttpsServer | HttpServer | undefined;

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
  vi.useRealTimers();
});

/** Boots a real HTTPS server on loopback and returns its base URL. */
async function startHttpsServer(
  handler: Parameters<typeof createHttpsServer>[1],
): Promise<string> {
  server = createHttpsServer({ cert, key }, handler);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `https://localhost:${port}`;
}

async function startHttpServer(
  handler: Parameters<typeof createHttpServer>[1],
): Promise<string> {
  server = createHttpServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

/**
 * A fetcher that trusts the test CA and allows loopback, otherwise identical
 * to production: the DNS lookup, the redirect refusal, the timeout, and the
 * byte cap all still run for real. The address guard's refusal of loopback
 * is proven directly (`isBlockedAddress`) and end-to-end against a stubbed
 * DNS answer below, so relaxing it here — for tests checking something
 * else — does not leave that behavior unverified.
 */
function testFetcher() {
  const agent = buildGuardedAgent({ ca: cert, isBlocked: () => false });
  return createBoundedFetcher(agent);
}

describe("isBlockedAddress: the connect-time address table", () => {
  it.each([
    ["127.0.0.1", true],
    ["10.1.2.3", true],
    ["172.16.0.1", true],
    ["172.31.255.255", true],
    ["172.32.0.1", false],
    ["192.168.1.1", true],
    ["169.254.169.254", true], // cloud metadata
    ["8.8.8.8", false],
    ["::1", true],
    ["fd00::1", true],
    ["fe80::1", true],
    ["2001:4860:4860::8888", false],
    // IPv4-mapped IPv6: a hostname-only check would miss this form.
    ["::ffff:169.254.169.254", true],
    ["::ffff:8.8.8.8", false],
    // Hex IPv4-mapped form (not dotted) — same address as ::ffff:127.0.0.1.
    ["::ffff:7f00:1", true],
    // Fully-expanded loopback, equivalent to "::1".
    ["0:0:0:0:0:0:0:1", true],
    // Shared address space / CGNAT (RFC6598), used by some cloud metadata
    // services and easy to miss if only 10/8, 172.16/12, 192.168/16 are listed.
    ["100.100.100.200", true],
    ["100.63.255.255", false],
    ["100.128.0.1", false],
  ])("%s -> blocked=%s", (address, expected) => {
    expect(isBlockedAddress(address)).toBe(expected);
  });

  describe("an empty DNS answer list", () => {
    afterEach(() => {
      stubbedLookupAddress = undefined;
    });

    it("is refused instead of reading addresses[0]", async () => {
      stubbedLookupAddress = EMPTY_ANSWERS;
      const fetcher = boundedFetcherUnderRealGuard();
      await expect(
        fetcher("https://no-answers.test/pdpp-client"),
      ).rejects.toMatchObject({
        cause: { message: expect.stringMatching(/no addresses/i) },
      });
    });
  });
});

describe("a literal IP in the URL bypasses dns.lookup entirely", () => {
  // `net`/`tls` dial a literal-IP hostname directly; the guarded `lookup`
  // passed to the dispatcher never runs for it. So the production fetcher
  // must reject on the URL's hostname itself, before ever attempting
  // tls.connect — proven here by spying on tls.connect and asserting it is
  // never called, using the real, unrelaxed production guard.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    "https://127.0.0.1/pdpp-client",
    "https://[::1]/pdpp-client",
    "https://[::ffff:127.0.0.1]/pdpp-client", // dotted IPv4-mapped
    "https://[::ffff:7f00:1]/pdpp-client", // hex IPv4-mapped
    "https://169.254.169.254/pdpp-client", // cloud metadata
    "https://100.100.100.200/pdpp-client", // CGNAT metadata
  ])("rejects %s before dialing", async (url) => {
    const connectSpy = vi.spyOn(tls, "connect");
    await expect(boundedClientDocumentFetcher(url)).rejects.toThrow(/blocked/i);
    expect(connectSpy).not.toHaveBeenCalled();
  });

  it("still allows a literal IP through the relaxed test guard", async () => {
    const hostnameUrl = await startHttpsServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ client_id: "https://example.com/x" }));
    });
    // Same server, addressed by its literal loopback IP instead of
    // `localhost` — proves the pre-dial literal-IP check doesn't interfere
    // with an address the guard permits, only with one it blocks (the
    // production guard's real blocking of loopback is proven above; this
    // uses the relaxed test guard since 127.0.0.1 is intentionally the
    // address under test here, not the thing being blocked).
    const literalUrl = hostnameUrl.replace("localhost", "127.0.0.1");
    const fetcher = testFetcher();
    const result = await fetcher(literalUrl);
    expect(result?.status).toBe(200);
  });
});

describe("HTTPS only", () => {
  it("refuses a plain-http URL without connecting", async () => {
    const url = await startHttpServer((_req, res) => res.end("should not run"));
    const fetcher = testFetcher();
    await expect(fetcher(url.replace("https", "http"))).rejects.toThrow(
      /https/i,
    );
  });
});

describe("no redirect traversal", () => {
  it("reports a redirect as a failure instead of following it", async () => {
    const url = await startHttpsServer((_req, res) => {
      res.writeHead(302, { location: "https://attacker.example/elsewhere" });
      res.end();
    });
    const fetcher = testFetcher();
    await expect(fetcher(url)).rejects.toThrow(/redirect/i);
  });
});

describe("one timeout spans headers and body", () => {
  it("aborts a response whose headers never arrive", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const url = await startHttpsServer(() => {
      // Never call res.end() / never send headers.
    });
    const fetcher = testFetcher();
    const pending = fetcher(url);
    pending.catch(() => {}); // asserted below; suppress the fake-timer race warning
    await vi.advanceTimersByTimeAsync(FETCH_TIMEOUT_MS + 100);
    await expect(pending).rejects.toThrow();
  });

  it("aborts a response whose body trickles forever", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const url = await startHttpsServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write("{");
      // Body never completes: headers already sent, so a headers-only
      // deadline would not catch this.
    });
    const fetcher = testFetcher();
    const pending = fetcher(url);
    pending.catch(() => {}); // asserted below; suppress the fake-timer race warning
    await vi.advanceTimersByTimeAsync(FETCH_TIMEOUT_MS + 100);
    await expect(pending).rejects.toThrow();
  });

  it("still aborts a redirect whose declared body never actually arrives", async () => {
    // A redirect's body is discarded before returning; if the deadline
    // were cleared before that discard (as it previously was), a hostile
    // server could hold the connection open past the nominal timeout by
    // stalling that drain instead of the initial response.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const url = await startHttpsServer((_req, res) => {
      res.writeHead(302, {
        location: "https://attacker.example/elsewhere",
        "content-length": "10",
      });
      res.write("x");
      // Never finishes the declared 10-byte body.
    });
    const fetcher = testFetcher();
    const pending = fetcher(url);
    pending.catch(() => {}); // asserted below; suppress the fake-timer race warning
    await vi.advanceTimersByTimeAsync(FETCH_TIMEOUT_MS + 100);
    await expect(pending).rejects.toThrow();
  });
}, 15_000);

describe("the body is capped before allocation", () => {
  it("does not return an oversized body even without Content-Length", async () => {
    const url = await startHttpsServer((_req, res) => {
      res.writeHead(200);
      // No content-length: a lying/omitting host must still be capped by
      // the streamed read, not by trusting the header.
      res.end("x".repeat(MAX_RESPONSE_BYTES + 1));
    });
    const fetcher = testFetcher();
    const result = await fetcher(url);
    expect(result?.body.length ?? 0).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
  });

  it("reports the declared-Content-Length early return without buffering the body", async () => {
    const url = await startHttpsServer((_req, res) => {
      const body = "x".repeat(MAX_RESPONSE_BYTES + 1);
      res.writeHead(200, { "content-length": String(body.length) });
      res.end(body);
    });
    const fetcher = testFetcher();
    const result = await fetcher(url);
    expect(result?.body).toBe("");
  });

  it("passes through a body at or under the cap", async () => {
    const body = JSON.stringify({
      client_id: "https://example.com/pdpp-client",
    });
    const url = await startHttpsServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    const fetcher = testFetcher();
    const result = await fetcher(url);
    expect(result?.status).toBe(200);
    expect(result?.body).toBe(body);
    expect(result?.finalUrl).toBe(`${url}/`);
  });
});

describe("connect-time address validation runs on every DNS answer", () => {
  afterEach(() => {
    stubbedLookupAddress = undefined;
  });

  it("blocks a fetch whose hostname resolves to a private address", async () => {
    // A real hostname-based SSRF: the requested URL's hostname string is
    // innocuous ("rebinds-to-loopback.test"), but the DNS answer this
    // process actually receives is a blocked literal. Stubbing `node:dns`
    // (rather than the fetcher's own `lookup` option) proves the real guard
    // runs on the real resolution path, not merely on the URL string.
    stubbedLookupAddress = "127.0.0.1";
    const fetcher = boundedFetcherUnderRealGuard();
    await expect(
      fetcher("https://rebinds-to-loopback.test/pdpp-client"),
    ).rejects.toMatchObject({
      cause: { message: expect.stringMatching(/blocked address/i) },
    });
  });
});

/** The real production guard (`isBlockedAddress`), with the test CA trusted. */
function boundedFetcherUnderRealGuard() {
  return createBoundedFetcher(buildGuardedAgent({ ca: cert }));
}

describe("no forwarded credentials", () => {
  it("sends no cookie and no stored authorization header", async () => {
    let seenHeaders: Record<string, string | string[] | undefined> = {};
    const url = await startHttpsServer((req, res) => {
      seenHeaders = req.headers;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ client_id: `${url}/` }));
    });
    const fetcher = testFetcher();
    await fetcher(url);
    expect(seenHeaders.cookie).toBeUndefined();
    expect(seenHeaders.authorization).toBeUndefined();
  });
});
