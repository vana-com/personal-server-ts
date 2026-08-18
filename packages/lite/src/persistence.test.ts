/**
 * Public-contract tests for the injectable PS Lite persistence bundle
 * (Slice 01 / objective A).
 *
 * These prove a caller can construct PS Lite entirely from injected stores —
 * no direct browser storage dependency — and that state, server identity,
 * tokens, access logs, relay TLS identity, and MCP records all round-trip and
 * survive a runtime "restart" (a fresh runtime built over the SAME stores).
 *
 * They also guard that runtime/composition code contains no hidden
 * IndexedDB/OPFS/localStorage access, and that the encrypted server-identity
 * record shape + plaintext-at-rest behavior are preserved.
 */

import forge from "node-forge";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  assertCompletePsLitePersistenceBundle,
  psLitePersistenceRuntimeOptions,
  type PsLitePersistenceBundle,
} from "./persistence.js";
import {
  createRustlsPsLiteRelayTlsFactory,
  createLocalStoragePsLiteRelayTlsIdentityStore,
  type PsLiteRelayTlsIdentity,
  type PsLiteRelayTlsIdentityStore,
} from "./relay-tls.js";
import { startPersonalServer } from "./client.js";
import {
  loadOrCreatePsLiteServerIdentity,
  loadPsLiteRelayState,
} from "./state.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";

const ownerAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const SERVER_OWNER = ownerAccount.address;
let OWNER_SIGNATURE: `0x${string}`;

beforeAll(async () => {
  OWNER_SIGNATURE = await ownerAccount.signMessage({
    message: buildPersonalServerLiteOwnerBindingMessage(SERVER_OWNER),
  });
});

function ownerAuth() {
  return createBearerTokenPsLiteAuth({
    ownerToken: "owner-token",
    builderToken: "builder-token",
  });
}

function memoryRelayTlsIdentityStore(): PsLiteRelayTlsIdentityStore {
  const identities = new Map<string, PsLiteRelayTlsIdentity>();
  return {
    read(hostname) {
      return identities.get(hostname) ?? null;
    },
    write(identity) {
      identities.set(identity.hostname, identity);
    },
  };
}

/** A fresh bundle built entirely from in-memory (non-browser) stores. */
function memoryBundle(
  overrides: Partial<PsLitePersistenceBundle> = {},
): PsLitePersistenceBundle {
  const accessLog = createMemoryPsLiteAccessLogStore();
  return {
    storage: createMemoryPsLiteStorage(),
    state: createMemoryPsLiteStateStore(),
    tokens: createMemoryPsLiteTokenStore(),
    accessLog,
    mcpConnections: createInMemoryMcpConnectionStore(),
    mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
    relayTlsIdentity: memoryRelayTlsIdentityStore(),
    ...overrides,
  };
}

type RuntimeOptions = Parameters<typeof createPsLiteRuntime>[0];

async function runtimeOverBundle(
  bundle: PsLitePersistenceBundle,
  options: Partial<RuntimeOptions> = {},
) {
  const { config: configDefaults, ...runtimeOverrides } = options;
  return createPsLiteRuntime({
    ...(await psLitePersistenceRuntimeOptions(bundle, configDefaults)),
    auth: ownerAuth(),
    gateway: createMockPsLiteGateway(),
    serverOwner: SERVER_OWNER,
    active: true,
    now: () => new Date("2026-05-08T00:00:00.000Z"),
    ...runtimeOverrides,
  });
}

async function registrationRuntimeOverBundle(bundle: PsLitePersistenceBundle) {
  return runtimeOverBundle(bundle, {
    identity: {
      address: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
    },
    config: {
      server: { origin: "https://ps.local" },
      gateway: {
        url: "https://gateway.local",
        chainId: 14800,
        contracts: {
          dataRegistry: "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
          dataPortabilityPermissions:
            "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF",
          dataPortabilityServer: "0x1483B1F634DBA75AeaE60da7f01A679aabd5ee2c",
          dataPortabilityGrantees: "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
        },
      },
    },
  });
}

function startServerOverBundle(
  bundle: PsLitePersistenceBundle,
  options: Partial<Parameters<typeof startPersonalServer>[0]> = {},
) {
  return startPersonalServer({
    ownerAddress: SERVER_OWNER,
    ownerSignature: OWNER_SIGNATURE,
    persistence: bundle,
    gateway: createMockPsLiteGateway(),
    auth: ownerAuth(),
    configDefaults: {
      server: { origin: "https://ps.local" },
      gateway: { url: "https://gateway.local" },
      sync: { enabled: false },
    },
    ...options,
  });
}

async function writeOwnerScope(
  runtime: ReturnType<typeof createPsLiteRuntime>,
  scope: string,
) {
  return runtime.fetch(
    new Request(`https://ps.local/v1/data/${scope}`, {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username: "test_user" }),
    }),
  );
}

describe("PS Lite persistence bundle — injected state + data continuity", () => {
  it("rejects a partial bundle through the public composition helper", async () => {
    await expect(
      psLitePersistenceRuntimeOptions({
        storage: createMemoryPsLiteStorage(),
      } as PsLitePersistenceBundle),
    ).rejects.toThrow(
      "PS Lite persistence bundle must be complete; missing state, tokens, accessLog, mcpConnections, mcpOAuthAuthorizations, relayTlsIdentity",
    );
  });

  it("rejects incomplete bundles at the JavaScript boundary", () => {
    expect(() =>
      assertCompletePsLitePersistenceBundle({
        storage: createMemoryPsLiteStorage(),
      } as PsLitePersistenceBundle),
    ).toThrow(
      "PS Lite persistence bundle must be complete; missing state, tokens, accessLog, mcpConnections, mcpOAuthAuthorizations, relayTlsIdentity",
    );
  });

  it("constructs a runtime from a fully in-memory bundle (no browser storage)", async () => {
    const bundle = memoryBundle();
    const runtime = await runtimeOverBundle(bundle);
    const health = await runtime.fetch(new Request("https://ps.local/health"));
    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toMatchObject({
      status: "healthy",
      runtime: "ps-lite",
    });
  });

  it("persists data + access logs through injected stores across a runtime restart", async () => {
    const bundle = memoryBundle();

    const first = await runtimeOverBundle(bundle);
    expect((await writeOwnerScope(first, "instagram.profile")).status).toBe(
      201,
    );

    // Builder read writes an access-log entry through the injected writer.
    const read = await first.fetch(
      new Request(
        "https://ps.local/v1/data/instagram.profile?grantId=grant-1",
        { headers: { Authorization: "Bearer builder-token" } },
      ),
    );
    expect(read.status).toBe(200);

    // A brand-new runtime over the SAME bundle sees the persisted data + logs:
    // durability comes from the injected stores, not the runtime instance.
    const rebooted = await runtimeOverBundle(bundle);

    const scopes = await rebooted.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(scopes.status).toBe(200);
    await expect(scopes.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
      total: 1,
    });

    const logs = await rebooted.fetch(
      new Request("https://ps.local/v1/access-logs", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(logs.status).toBe(200);
    const logsBody = (await logs.json()) as { total: number };
    expect(logsBody.total).toBe(1);
  });

  it("routes config writes into the injected state store", async () => {
    const bundle = memoryBundle();
    const runtime = await runtimeOverBundle(bundle, {
      config: {
        server: { origin: "https://ps.local" },
        gateway: { url: "https://gateway.local" },
      },
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/ui/api/config", {
        method: "PUT",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          server: { origin: "https://moved.local" },
          gateway: { url: "https://gateway.local" },
        }),
      }),
    );
    expect(res.status).toBe(200);

    // The write landed in the injected state store (plaintext, key "config-v1").
    const stored = await bundle.state.get<{ server: { origin: string } }>(
      "config-v1",
    );
    expect(stored?.server.origin).toBe("https://moved.local");

    const current = await runtime.fetch(
      new Request("https://ps.local/ui/api/config", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(current.status).toBe(200);
    await expect(current.json()).resolves.toMatchObject({
      server: { origin: "https://moved.local" },
    });

    const rebooted = await runtimeOverBundle(bundle, {
      config: {
        server: { origin: "https://ps.local" },
        gateway: { url: "https://gateway.local" },
      },
    });
    const restored = await rebooted.fetch(
      new Request("https://ps.local/ui/api/config", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(restored.status).toBe(200);
    await expect(restored.json()).resolves.toMatchObject({
      server: { origin: "https://moved.local" },
    });
  });
});

describe("PS Lite persistence bundle — injected token continuity", () => {
  it("provisions and revokes device tokens through the injected token store", async () => {
    const bundle = memoryBundle();
    const controlPlane = { accessToken: "control-plane-secret" };

    const first = await runtimeOverBundle(bundle, controlPlane);
    const provision = await first.fetch(
      new Request("https://ps.local/auth/device/token", {
        method: "POST",
        headers: {
          Authorization: "Bearer control-plane-secret",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ token: "vana_ps_injected" }),
      }),
    );
    expect(provision.status).toBe(201);
    // Writing went through the injected store.
    expect(await bundle.tokens.isValid("vana_ps_injected")).toBe(true);

    // A fresh runtime over the same token store still sees + can revoke it.
    const rebooted = await runtimeOverBundle(bundle, controlPlane);
    const revoke = await rebooted.fetch(
      new Request("https://ps.local/auth/device/token", {
        method: "DELETE",
        headers: { Authorization: "Bearer vana_ps_injected" },
      }),
    );
    expect(revoke.status).toBe(200);
    expect(await bundle.tokens.isValid("vana_ps_injected")).toBe(false);
  });
});

describe("PS Lite persistence bundle — injected server identity", () => {
  it("preserves the AES-GCM record shape, plaintext-at-rest, and reload continuity", async () => {
    const state = createMemoryPsLiteStateStore();

    const first = await loadOrCreatePsLiteServerIdentity({
      store: state,
      ownerSignature: OWNER_SIGNATURE,
    });

    // Encrypted server-identity record shape is unchanged.
    expect(first.persisted).toMatchObject({
      version: 1,
      address: first.account.address,
      publicKey: first.account.publicKey,
      encryptedPrivateKey: {
        algorithm: "AES-GCM",
        iv: expect.any(String),
        ciphertext: expect.any(String),
      },
    });

    // At rest: only the private key is wrapped (AES-GCM). The record has no
    // cleartext `privateKey`, and no application-level encryption is layered
    // over the record itself (address/publicKey stay plaintext).
    const raw = await state.get<{
      encryptedPrivateKey: { algorithm: string };
      address: string;
    }>("server-identity-v1");
    expect(raw).not.toBeNull();
    expect(raw?.encryptedPrivateKey.algorithm).toBe("AES-GCM");
    expect(raw).not.toHaveProperty("privateKey");
    expect(raw?.address).toBe(first.account.address);

    // Reload from the same store decrypts + reuses the same identity.
    const second = await loadOrCreatePsLiteServerIdentity({
      store: state,
      ownerSignature: OWNER_SIGNATURE,
    });
    expect(second.account.address).toBe(first.account.address);
  });

  it("keeps injected config plaintext at rest", async () => {
    const bundle = memoryBundle();
    const runtime = await runtimeOverBundle(bundle, {
      config: { server: { origin: "https://ps.local" } },
    });
    await runtime.fetch(
      new Request("https://ps.local/ui/api/config", {
        method: "PUT",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ server: { origin: "https://plain.local" } }),
      }),
    );
    const stored = await bundle.state.get<Record<string, unknown>>("config-v1");
    // Plaintext: readable JSON with the origin, not an AES-GCM envelope.
    expect(JSON.stringify(stored)).toContain("https://plain.local");
    expect(stored).not.toHaveProperty("algorithm");
  });
});

describe("PS Lite persistence bundle — injected MCP stores", () => {
  it("persists MCP connection + OAuth authorization records across a restart", async () => {
    const mcpConnections = createInMemoryMcpConnectionStore();
    const mcpOAuthAuthorizations = createInMemoryMcpOAuthAuthorizationStore();
    const bundle = memoryBundle({ mcpConnections, mcpOAuthAuthorizations });
    const mcpOptions = {
      mcpOAuthApprovalUrl: "https://app.local/mcp/approve",
    };

    const first = await runtimeOverBundle(bundle, mcpOptions);

    // Owner creates a connection — written to the injected connection store.
    const created = await first.fetch(
      new Request("https://ps.local/v1/mcp/connections", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ displayName: "Claude" }),
      }),
    );
    expect(created.status).toBe(201);
    const connection = (await created.json()) as { connectionId: string };

    // Drive the OAuth authorize route — writes an authorization record.
    const authorize = await first.fetch(
      new Request(
        "https://ps.local/mcp/oauth/authorize?" +
          new URLSearchParams({
            response_type: "code",
            client_id: "claude",
            redirect_uri: "https://claude.ai/callback",
            code_challenge: "challenge-value",
            code_challenge_method: "S256",
            scope: "vana:read",
          }).toString(),
        { redirect: "manual" },
      ),
    );
    expect(authorize.status).toBe(302);
    const approveUrl = new URL(authorize.headers.get("location") ?? "");
    const authorizationId = approveUrl.searchParams.get("mcp_authorization");
    expect(authorizationId).toBeTruthy();

    // A fresh runtime over the SAME stores still lists the connection and can
    // read the authorization back — both MCP stores are injected + durable.
    const rebooted = await runtimeOverBundle(bundle, mcpOptions);

    const list = await rebooted.fetch(
      new Request("https://ps.local/v1/mcp/connections", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(list.status).toBe(200);
    const listBody = (await list.json()) as {
      connections: Array<{ id: string }>;
    };
    expect(
      listBody.connections.some((c) => c.id === connection.connectionId),
    ).toBe(true);

    const authView = await rebooted.fetch(
      new Request(
        `https://ps.local/v1/mcp/oauth/authorizations/${authorizationId}`,
        { headers: { Authorization: "Bearer owner-token" } },
      ),
    );
    expect(authView.status).toBe(200);
    await expect(authView.json()).resolves.toMatchObject({
      id: authorizationId,
    });
  });
});

describe("relay TLS identity — injected store vs browser localStorage default", () => {
  const SESSION_ID = "session-persist";
  const SUFFIX = "psrelay.test";
  const HOSTNAME = `${SESSION_ID}.${SUFFIX}`;

  const CERT_PEM = (() => {
    const keys = forge.pki.rsa.generateKeyPair(512);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date(Date.now() - 60_000);
    cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    const attrs = [{ name: "commonName", value: HOSTNAME }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    return forge.pki.certificateToPem(cert);
  })();
  const KEY_PEM = forge.pki.privateKeyToPem(
    forge.pki.rsa.generateKeyPair(512).privateKey,
  );

  function memoryIdentityStore(): PsLiteRelayTlsIdentityStore & {
    saved: PsLiteRelayTlsIdentity[];
  } {
    const map = new Map<string, PsLiteRelayTlsIdentity>();
    const saved: PsLiteRelayTlsIdentity[] = [];
    return {
      saved,
      read(hostname) {
        return map.get(hostname) ?? null;
      },
      write(identity) {
        map.set(identity.hostname, identity);
        saved.push(identity);
      },
    };
  }

  function memoryStorage(): Storage {
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

  function certResponse() {
    return new Response(
      JSON.stringify({ certPem: CERT_PEM, keyPem: KEY_PEM }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves the issued identity through an injected store, not globalThis", async () => {
    const fetchMock = vi.fn(async () => certResponse());
    vi.stubGlobal("fetch", fetchMock);
    // Guard: if the resolution reached for globalThis.localStorage it would
    // throw here (undefined in Node) instead of using the injected store.
    vi.stubGlobal("localStorage", undefined);
    const identityStore = memoryIdentityStore();

    const factory = createRustlsPsLiteRelayTlsFactory({
      controlUrl: "wss://control.psrelay.test:8443",
      publicSuffix: SUFFIX,
      identityStore,
    });
    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(identityStore.saved).toHaveLength(1);
    expect(identityStore.saved[0]).toMatchObject({
      hostname: HOSTNAME,
      source: "acme",
      trusted: true,
    });

    // A fresh factory over the same injected store resolves from cache.
    const rebooted = createRustlsPsLiteRelayTlsFactory({
      controlUrl: "wss://control.psrelay.test:8443",
      publicSuffix: SUFFIX,
      identityStore,
    });
    await rebooted.prepare?.({ sessionId: SESSION_ID });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps relay factory construction free of eager localStorage access", () => {
    const original = Object.getOwnPropertyDescriptor(
      globalThis,
      "localStorage",
    );
    let accessed = false;
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      get() {
        accessed = true;
        throw new Error("localStorage must not be read while composing TLS");
      },
    });
    try {
      createRustlsPsLiteRelayTlsFactory({
        controlUrl: "wss://control.psrelay.test:8443",
        publicSuffix: SUFFIX,
      });
      expect(accessed).toBe(false);
    } finally {
      if (original) {
        Object.defineProperty(globalThis, "localStorage", original);
      } else {
        delete (globalThis as { localStorage?: Storage }).localStorage;
      }
    }
  });

  it("browser default persists to localStorage when no store is injected", async () => {
    const fetchMock = vi.fn(async () => certResponse());
    vi.stubGlobal("fetch", fetchMock);
    const storage = memoryStorage();
    vi.stubGlobal("localStorage", storage);

    // No identityStore, no storage option: falls back to the localStorage
    // browser default — the same behavior PS Lite has always had on the web.
    const factory = createRustlsPsLiteRelayTlsFactory({
      controlUrl: "wss://control.psrelay.test:8443",
      publicSuffix: SUFFIX,
    });
    await factory.prepare?.({ sessionId: SESSION_ID, issueToken: "tok" });

    expect(storage.length).toBe(1);
    const persisted = JSON.parse(
      storage.getItem(`personal-server-lite-tls-identity-v1:${HOSTNAME}`) ?? "",
    ) as PsLiteRelayTlsIdentity;
    expect(persisted).toMatchObject({
      certPem: CERT_PEM,
      keyPem: KEY_PEM,
      hostname: HOSTNAME,
      source: "acme",
    });
  });

  it("localStorage adapter round-trips an identity", () => {
    const storage = memoryStorage();
    const store = createLocalStoragePsLiteRelayTlsIdentityStore(storage);
    const identity: PsLiteRelayTlsIdentity = {
      certPem: CERT_PEM,
      keyPem: KEY_PEM,
      hostname: HOSTNAME,
      source: "acme",
      trusted: true,
    };
    store.write(identity);
    expect(store.read(HOSTNAME)).toEqual(identity);
    expect(store.read("other.host")).toBeNull();
  });
});

describe("startPersonalServer relay persistence wiring", () => {
  it("rejects a prebuilt runtime beside a complete persistence bundle", async () => {
    const bundle = memoryBundle();

    await expect(
      startPersonalServer({
        runtime: await registrationRuntimeOverBundle(bundle),
        persistence: bundle,
        relay: false,
      }),
    ).rejects.toThrow(
      "runtime cannot be supplied with a complete persistence bundle",
    );
  });

  it("rejects a relay-state override beside a complete persistence bundle", async () => {
    await expect(
      startPersonalServer({
        persistence: memoryBundle(),
        relayStateStore: createMemoryPsLiteStateStore(),
        relay: { sessionId: "conflicting-relay-state" },
      }),
    ).rejects.toThrow(
      "relayStateStore cannot be supplied with a complete persistence bundle",
    );
  });

  it("passes the bundle's TLS identity store to the default relay factory", async () => {
    const identityStore: PsLiteRelayTlsIdentityStore = {
      read: vi.fn().mockReturnValue(null),
      write: vi.fn(),
    };
    const bundle = memoryBundle({ relayTlsIdentity: identityStore });
    const socket = {
      binaryType: "arraybuffer",
      readyState: 1,
      OPEN: 1,
      CONNECTING: 0,
      onopen: null as (() => void) | null,
      onmessage: null as
        ((event: { data: string | ArrayBuffer | Uint8Array }) => void) | null,
      onclose: null,
      onerror: null,
      send: vi.fn(),
      close: vi.fn(),
    };
    const server = await startServerOverBundle(bundle, {
      relay: {
        sessionId: "native-session",
        webSocketFactory: () => socket,
      },
    });

    socket.onmessage?.({ data: JSON.stringify({ type: "session.ready" }) });
    await vi.waitFor(() =>
      expect(identityStore.read).toHaveBeenCalledWith(
        "native-session.34.16.49.200.sslip.io",
      ),
    );
    await server.stop();
  });

  it("persists and restores relay registration through the bundle state store", async () => {
    const bundle = memoryBundle();
    const webSocketFactory = vi.fn((_url: string) => ({
      binaryType: "arraybuffer",
      readyState: 1,
      OPEN: 1,
      CONNECTING: 0,
      onopen: null,
      onmessage: null,
      onclose: null,
      onerror: null,
      send: vi.fn(),
      close: vi.fn(),
    }));
    const relay = { publicSuffix: "relay.example", webSocketFactory };

    const first = await startServerOverBundle(bundle, {
      relay,
    });
    const firstInfo = await first.info();
    await first.submitRegistration({ signature: "0xregistration" });
    await expect(loadPsLiteRelayState(bundle.state)).resolves.toMatchObject({
      publicUrl: firstInfo.urls.public,
    });
    await first.stop();

    const restarted = await startServerOverBundle(bundle, {
      relay,
    });
    await expect(restarted.info()).resolves.toMatchObject({
      urls: { public: firstInfo.urls.public },
    });
    await restarted.stop();
  });

  it("keeps a prebuilt runtime free of implicit browser relay-state persistence", async () => {
    vi.stubGlobal("indexedDB", undefined);
    const server = await startPersonalServer({
      runtime: await registrationRuntimeOverBundle(memoryBundle()),
      relay: {
        sessionId: "browser-session",
        webSocketFactory: () => ({
          binaryType: "arraybuffer",
          readyState: 1,
          OPEN: 1,
          CONNECTING: 0,
          onopen: null,
          onmessage: null,
          onclose: null,
          onerror: null,
          send: vi.fn(),
          close: vi.fn(),
        }),
      },
      gateway: createMockPsLiteGateway(),
    });
    try {
      await expect(
        server.submitRegistration({ signature: "0xregistration" }),
      ).resolves.toEqual({ alreadyRegistered: false });
    } finally {
      await server.stop();
      vi.unstubAllGlobals();
    }
  });
});
