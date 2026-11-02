import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Builder, GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createTestReplicaRoster } from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import Database from "better-sqlite3";
import { startPersonalServer } from "./client.js";
import {
  enableReplicaTestIdentity,
  replicaTestAuthority,
} from "./storage/pdpp-replica-writer-identity.test-utils.js";
import {
  currentReplicaWriterIdentity,
  enableReplicaWriterIdentity,
} from "./storage/pdpp-replica-writer-identity.js";

const ownerWallet = createTestWallet(8);
let cleanupFns: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(cleanupFns.map((cleanup) => cleanup()));
  cleanupFns = [];
});

function createGateway(overrides: Partial<GatewayClient> = {}): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(false),
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0xschema1",
      ownerAddress: ownerWallet.address,
      name: "instagram.profile",
      definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
      scope: "instagram.profile",
      addedAt: "2026-05-08T00:00:00.000Z",
    }),
    getServer: vi.fn().mockResolvedValue(null),
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({
      alreadyRegistered: false,
      serverId: "server-1",
    }),
    registerFile: vi.fn().mockResolvedValue({ fileId: "file-1" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: "grant-1" }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

async function createOwnerSignature(): Promise<`0x${string}`> {
  return ownerWallet.signMessage("vana-master-key-v1");
}

async function getFreePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => {
    server.close((err?: Error) => {
      if (err) reject(err);
      else resolve();
    });
  });
  if (!address || typeof address === "string") {
    throw new Error("Could not allocate a test port");
  }
  return address.port;
}

async function startTestServer(gateway = createGateway()) {
  const rootPath = await mkdtemp(join(tmpdir(), "ps-client-"));
  const port = await getFreePort();
  const config = ServerConfigSchema.parse({
    server: { port, origin: `http://localhost:${port}` },
    logging: { level: "fatal", pretty: false },
    devUi: { enabled: false },
    sync: { enabled: false, lastProcessedTimestamp: null },
    tunnel: { enabled: false },
  });
  const ps = await startPersonalServer({
    rootPath,
    config,
    ownerSignature: await createOwnerSignature(),
    gatewayClient: gateway,
    localApproval: false,
    startBackgroundServices: false,
  });
  cleanupFns.push(async () => {
    await ps.stop();
    await rm(rootPath, { recursive: true, force: true });
  });
  return { ps, gateway, port };
}

describe("startPersonalServer node handle", () => {
  it("rejects port 0 because public handle URLs must be concrete", async () => {
    await expect(startPersonalServer({ port: 0 })).rejects.toThrow(
      "port: 0 is not supported",
    );
  });

  it("passes mcpGrantTtlSeconds to the server and rejects a bad one at startup", async () => {
    const rootPath = await mkdtemp(join(tmpdir(), "ps-client-"));
    cleanupFns.push(() => rm(rootPath, { recursive: true, force: true }));
    const port = await getFreePort();
    const config = ServerConfigSchema.parse({
      server: { port, origin: `http://localhost:${port}` },
      logging: { level: "fatal", pretty: false },
      devUi: { enabled: false },
      sync: { enabled: false, lastProcessedTimestamp: null },
      tunnel: { enabled: false },
    });
    await expect(
      startPersonalServer({
        config,
        rootPath,
        ownerSignature: await createOwnerSignature(),
        gatewayClient: createGateway(),
        localApproval: false,
        startBackgroundServices: false,
        mcpGrantTtlSeconds: -1,
      }),
    ).rejects.toThrow(/mcpGrantTtlSeconds/);
  });

  it("starts, reports identity, and prepares registration", async () => {
    const { ps, port } = await startTestServer();

    const info = await ps.ready();
    expect(info).toMatchObject({
      kind: "node",
      status: "ready",
      ownerAddress: ownerWallet.address,
      urls: {
        local: `http://127.0.0.1:${port}`,
        apiOrigin: `http://localhost:${port}`,
        registration: `http://localhost:${port}`,
        loopback: null,
      },
    });
    expect(info.server?.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(info.server?.publicKey).toMatch(/^0x04/);

    const registration = await ps.prepareRegistration();
    expect(registration.candidate).toMatchObject({
      ownerAddress: ownerWallet.address,
      serverAddress: info.server?.address,
      publicKey: info.server?.publicKey,
      serverUrl: `http://localhost:${port}`,
    });
  });

  it("submits registration through the configured gateway", async () => {
    const gateway = createGateway();
    const { ps } = await startTestServer(gateway);
    const registration = await ps.prepareRegistration();

    await expect(
      ps.submitRegistration({ signature: "0xregistration" }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("submits the exact prepared registration request when a public server URL is provided", async () => {
    const gateway = createGateway();
    const { ps, port } = await startTestServer(gateway);
    const registration = await ps.prepareRegistration({
      serverUrl: "https://node-public.example",
    });

    await expect(
      ps.submitRegistration({
        request: registration,
        signature: "0xregistration",
      }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(registration.candidate.serverUrl).toBe(
      "https://node-public.example",
    );
    expect(registration.candidate.serverUrl).not.toBe(
      `http://localhost:${port}`,
    );
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("submits the most recently prepared registration request when no request is passed", async () => {
    const gateway = createGateway();
    const { ps } = await startTestServer(gateway);
    const registration = await ps.prepareRegistration({
      serverUrl: "https://node-public.example",
    });

    await expect(
      ps.submitRegistration({ signature: "0xregistration" }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("posts data through the public handle", async () => {
    const { ps } = await startTestServer();

    await expect(
      ps.postData(
        "instagram.profile",
        { username: "vana_debug" },
        { signMessage: ownerWallet.signMessage },
      ),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      status: "stored",
    });
  });

  it("exposes typed data and sync helpers through the public handle", async () => {
    const { ps } = await startTestServer();
    const auth = { signMessage: ownerWallet.signMessage };

    await ps.postData("instagram.profile", { username: "vana_debug" }, auth);

    await expect(ps.listData({ auth, limit: 10 })).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
    });
    await expect(
      ps.listVersions("instagram.profile", { auth, limit: 1 }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      versions: [{ fileId: null }],
    });
    await expect(
      ps.readData("instagram.profile", { auth }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      data: { username: "vana_debug" },
    });
    await expect(ps.syncStatus({ auth })).resolves.toMatchObject({
      enabled: false,
      running: false,
    });
    await expect(ps.syncNow({ auth })).resolves.toMatchObject({
      status: "disabled",
    });
  });

  it("exposes grant helpers through the public handle", async () => {
    const builderAddress = createTestWallet(9).address;
    const grantId =
      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const gateway = createGateway({
      getBuilder: vi.fn().mockResolvedValue({
        id: `0x${"bb".repeat(32)}`,
        ownerAddress: "0xOwner",
        granteeAddress: builderAddress,
        publicKey: "0x04key",
        appUrl: "https://app.example.com",
        addedAt: "2026-01-21T10:00:00.000Z",
      } satisfies Builder),
      createGrant: vi.fn().mockResolvedValue({ grantId }),
      listGrantsByUser: vi.fn().mockResolvedValue([
        {
          id: grantId,
          grantorAddress: ownerWallet.address,
          granteeId: `0x${"bb".repeat(32)}`,
          scopes: ["instagram.*"],
          status: "confirmed",
          addedAt: "2026-01-21T10:00:00.000Z",
          expiresAt: null,
          expired: false,
          revokedAt: null,
          revocationSignature: null,
          paymentStatus: "paid",
          paidAt: "2026-01-21T10:00:05.000Z",
          paidBy: ownerWallet.address,
          grantVersion: "1",
          settleTxHash: null,
          settleSubmittedAt: null,
          revocationTxHash: null,
          revocationSubmittedAt: null,
          fee: {
            asset: "0x0000000000000000000000000000000000000000",
            registrationFee: "0",
            dataAccessFee: "0",
            totalDue: "0",
          },
        },
      ]),
      // revokeGrantContract reads the live grantVersion before signing.
      getGrant: vi.fn().mockResolvedValue({
        id: grantId,
        grantorAddress: ownerWallet.address,
        granteeId: `0x${"bb".repeat(32)}`,
        scopes: ["instagram.*"],
        status: "confirmed",
        addedAt: "2026-01-21T10:00:00.000Z",
        expiresAt: null,
        expired: false,
        revokedAt: null,
        revocationSignature: null,
        paymentStatus: "paid",
        paidAt: "2026-01-21T10:00:05.000Z",
        paidBy: ownerWallet.address,
        grantVersion: "1",
        settleTxHash: null,
        settleSubmittedAt: null,
        revocationTxHash: null,
        revocationSubmittedAt: null,
        fee: {
          asset: "0x0000000000000000000000000000000000000000",
          registrationFee: "0",
          dataAccessFee: "0",
          totalDue: "0",
        },
      }),
    });
    const { ps } = await startTestServer(gateway);
    const auth = { signMessage: ownerWallet.signMessage };

    await expect(
      ps.createGrant({
        auth,
        granteeAddress: builderAddress,
        scopes: ["instagram.*"],
      }),
    ).resolves.toEqual({ grantId });
    await expect(ps.listGrants({ auth })).resolves.toMatchObject({
      grants: [{ id: grantId }],
    });
    await expect(ps.revokeGrant(grantId, { auth })).resolves.toEqual({
      status: "revoked",
      grantId,
    });
    expect(gateway.revokeGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        grantorAddress: ownerWallet.address,
        grantId,
      }),
    );
  });

  it("preserves Request method and body when fetch applies init overrides", async () => {
    const { ps, port } = await startTestServer();
    const origin = `http://localhost:${port}`;
    const body = new TextEncoder().encode(
      JSON.stringify({ username: "vana_debug" }),
    );
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: origin,
      method: "POST",
      uri: "/v1/data/instagram.profile",
      body,
    });

    const response = await ps.fetch(
      new Request("https://ignored.example/v1/data/instagram.profile", {
        method: "POST",
        body,
      }),
      {
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
      },
    );

    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toMatchObject({
      scope: "instagram.profile",
    });
  });

  it("reports the replication door at ready, and a refused boot is still ready", async () => {
    const rootPath = await mkdtemp(join(tmpdir(), "ps-client-"));
    cleanupFns.push(() => rm(rootPath, { recursive: true, force: true }));
    const boot = async (enabled: boolean) => {
      const port = await getFreePort();
      const ps = await startPersonalServer({
        rootPath,
        config: ServerConfigSchema.parse({
          server: { port, origin: `http://localhost:${port}` },
          logging: { level: "fatal", pretty: false },
          devUi: { enabled: false },
          sync: { enabled: false, lastProcessedTimestamp: null },
          tunnel: { enabled: false },
          replication: { enabled },
        }),
        ownerSignature: await createOwnerSignature(),
        gatewayClient: createGateway(),
        localApproval: false,
        startBackgroundServices: false,
      });
      try {
        await expect(ps.ready()).resolves.toMatchObject({ status: "ready" });
        expect((await fetch(`http://127.0.0.1:${port}/health`)).status).toBe(
          200,
        );
        return ps.replication?.status();
      } finally {
        await ps.stop();
      }
    };

    expect(await boot(false)).toEqual({ state: "never" });
    expect(await boot(true)).toEqual({ state: "on" });
    expect(await boot(true)).toEqual({ state: "on" });
    expect(await boot(false)).toEqual({ state: "off" });
    expect(await boot(true)).toEqual({
      state: "refused",
      refusal: "reenable_refused",
    });
  }, 30_000);

  it("rotates the writer identity at boot only when the host asks and replication runs", async () => {
    const rootPath = await mkdtemp(join(tmpdir(), "ps-client-"));
    cleanupFns.push(() => rm(rootPath, { recursive: true, force: true }));
    const boot = async (enabled: boolean, rotate?: boolean) => {
      const port = await getFreePort();
      const ps = await startPersonalServer({
        rootPath,
        config: ServerConfigSchema.parse({
          server: { port, origin: `http://localhost:${port}` },
          logging: { level: "fatal", pretty: false },
          devUi: { enabled: false },
          sync: { enabled: false, lastProcessedTimestamp: null },
          tunnel: { enabled: false },
          replication: { enabled },
        }),
        ownerSignature: await createOwnerSignature(),
        gatewayClient: createGateway(),
        localApproval: false,
        startBackgroundServices: false,
        ...(rotate !== undefined && { rotateReplicaWriterIdentity: rotate }),
      });
      try {
        return ps.replication?.writerRotation?.();
      } finally {
        await ps.stop();
      }
    };
    const identities = () => {
      const db = new Database(join(rootPath, "index.db"));
      try {
        const rows = db
          .prepare("SELECT COUNT(*) AS n FROM pdpp_replica_writer_identity")
          .get() as { n: number };
        return { rows: rows.n, current: currentReplicaWriterIdentity(db) };
      } finally {
        db.close();
      }
    };

    // First enable: no identity yet, so a rotation request has nothing to do.
    expect(await boot(true, true)).toBe("no_identity");
    expect(identities().rows).toBe(0);

    // The worker's first enable establishes the identity.
    const db = new Database(join(rootPath, "index.db"));
    const original = enableReplicaTestIdentity(db, {
      owner: ownerWallet.address.toLowerCase(),
      roster: createTestReplicaRoster(),
      authority: replicaTestAuthority(createTestReplicaRoster()),
    });
    db.close();

    // A normal restart keeps it.
    expect(await boot(true)).toBe("not_requested");
    expect(await boot(true, false)).toBe("not_requested");
    expect(identities().current).toEqual(original);

    // A host that suspects a copy: same registration, new nonce.
    expect(await boot(true, true)).toBe("rotated");
    const rotated = identities().current!;
    expect(rotated.incarnation).toBe(original.incarnation + 1);
    expect(rotated.seed).toEqual({
      ...original.seed,
      writerNonce: rotated.seed.writerNonce,
    });
    expect(rotated.seed.writerNonce).not.toBe(original.seed.writerNonce);
    expect(rotated.transportWriter).not.toBe(original.transportWriter);
    expect(rotated.operationWriter).not.toBe(original.operationWriter);

    // The runtime's first step after that boot reads the same registration
    // from the roster and keeps the rotated identity.
    const stepDb = new Database(join(rootPath, "index.db"));
    try {
      const { owner, server, serverId } = original.seed;
      await expect(
        enableReplicaWriterIdentity({
          db: stepDb,
          owner,
          server,
          roster: {
            server: async () => ({ owner, id: serverId, revokedAt: null }),
          },
        }),
      ).resolves.toEqual({ tag: "ready", identity: rotated });
    } finally {
      stepDb.close();
    }

    // Flag off, then a refused re-enable: nothing to rotate, nothing written.
    expect(await boot(false, true)).toBe("replication_off");
    expect(await boot(true, true)).toBe("replication_off");
    expect(identities()).toEqual({ rows: 2, current: rotated });
  }, 30_000);

  it("stops idempotently", async () => {
    const { ps } = await startTestServer();

    await ps.stop();
    await ps.stop();

    await expect(ps.info()).resolves.toMatchObject({ status: "stopped" });
  });
});
