import forge from "node-forge";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRustlsPsLiteRelayTlsFactory } from "./relay-tls.js";

const CONTROL_URL = "wss://control.psrelay.test:8443";
const SESSION_ID = "abc123session";

// A parseable cert with long validity so the persisted-identity read path
// (which checks the certificate's notAfter) accepts it. Small key: this is
// parsing fixture material, not crypto under test.
const ISSUED_CERT_PEM = (() => {
  const keys = forge.pki.rsa.generateKeyPair(512);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: `${SESSION_ID}.psrelay.test` }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
})();

function createMemoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (key: string) => map.get(key) ?? null,
    key: (index: number) => [...map.keys()][index] ?? null,
    removeItem: (key: string) => {
      map.delete(key);
    },
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
  } as Storage;
}

describe("createRustlsPsLiteRelayTlsFactory identity resolution", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let storage: Storage;
  let logs: string[];

  beforeEach(() => {
    fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ certPem: ISSUED_CERT_PEM }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    storage = createMemoryStorage();
    logs = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function createFactory() {
    return createRustlsPsLiteRelayTlsFactory({
      controlUrl: CONTROL_URL,
      publicSuffix: "psrelay.test",
      storage,
      logger: (line) => logs.push(line),
    });
  }

  it("does not memoize a self-signed fallback: a later tokened attempt mints ACME (BUI-664)", async () => {
    const factory = createFactory();

    await factory.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(logs.join("\n")).toContain("self-signed");

    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "fresh" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.issueToken).toBe("fresh");

    // Trusted identity is memoized: a token-less follow-up neither re-issues
    // nor falls back to self-signed again.
    const selfSignedLogs = logs.filter((l) => l.includes("self-signed")).length;
    await factory.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logs.filter((l) => l.includes("self-signed")).length).toBe(
      selfSignedLogs,
    );
  });

  it("a tokened caller does not join a stale token-less in-flight attempt", async () => {
    const factory = createFactory();

    // First attempt starts without a token (still generating keys / pending).
    const first = factory.prepare?.({ sessionId: SESSION_ID });
    // A reconnect delivers a fresh issueToken while the first attempt is
    // in flight. It must start its own issuance instead of awaiting the
    // no-token attempt's self-signed fallback.
    const second = factory.prepare?.({
      sessionId: SESSION_ID,
      issueToken: "fresh",
    });
    await Promise.all([first, second]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.issueToken).toBe("fresh");

    // The trusted result won: no further issuance or self-signed fallback.
    const selfSignedLogs = logs.filter((l) => l.includes("self-signed")).length;
    await factory.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logs.filter((l) => l.includes("self-signed")).length).toBe(
      selfSignedLogs,
    );
  });

  it("coalesces concurrent callers carrying the same token onto one issuance", async () => {
    const factory = createFactory();

    await Promise.all([
      factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" }),
      factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" }),
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the issued ACME identity when the cache write throws (quota)", async () => {
    storage.setItem = () => {
      throw new DOMException("quota exceeded", "QuotaExceededError");
    };
    const factory = createFactory();

    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // Issuance succeeded, so the identity is trusted and memoized: no
    // self-signed fallback, no re-issuance on the next stream.
    expect(logs.join("\n")).not.toContain("self-signed");
    await factory.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logs.join("\n")).toContain("failed to persist issued certificate");
  });

  it("falls back to self-signed when the issuer hangs, then recovers (BUI-666)", async () => {
    // Observed live: the relay's /issue-cert accepts the POST and never
    // responds while relay-side ACME is wedged. Without a timeout the
    // identity promise never settles and every incoming TLS handshake
    // awaits it forever — the public endpoint serves zero bytes while the
    // control session looks healthy.
    fetchMock.mockImplementation(() => new Promise(() => {}));
    const factory = createRustlsPsLiteRelayTlsFactory({
      controlUrl: CONTROL_URL,
      publicSuffix: "psrelay.test",
      storage,
      logger: (line) => logs.push(line),
      issueCertTimeoutMs: 40,
    });

    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logs.join("\n")).toContain("did not respond within 40ms");
    expect(logs.join("\n")).toContain("self-signed");

    // The timed-out attempt is not memoized: once the issuer recovers, a
    // tokened retry mints the trusted ACME identity.
    fetchMock.mockImplementation(
      async () =>
        new Response(JSON.stringify({ certPem: ISSUED_CERT_PEM }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok2" });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Trusted identity is now memoized: no further issuance.
    await factory.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("persists the issued ACME identity for reuse across factories", async () => {
    const factory = createFactory();
    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // A brand-new factory (fresh boot) resolves from the persisted cache
    // without re-issuing.
    const rebooted = createFactory();
    await rebooted.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logs.join("\n")).not.toContain("ACME issuer unavailable");
  });
});
