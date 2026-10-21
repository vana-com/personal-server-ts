/**
 * A TEE job reads its body through the grantee read port, over real Node
 * storage and the real worker. These tests hold the port to three limits:
 *
 * - Memory: a valid large legacy envelope streams through. The heap that
 *   the read keeps alive stays far below the document size.
 * - Input cap: an index row that under-reports the size does not let the
 *   read take more stored bytes than the job's byte budget.
 * - Pinned bytes: bytes that change after the row was authorized are not
 *   sealed and uploaded.
 *
 * The only fakes are the chain gateway, the result upload endpoint and a
 * pass-through hook on the stored file stream that counts bytes and samples
 * memory.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Readable } from "node:stream";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BUILDER_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  NodeECIESProvider,
  builderRegistrationDomain,
  grantRegistrationDomain,
  type Builder,
  type DataFileEnvelope,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import { canonicalJobRequestBytes } from "@opendatalabs/vana-sdk/crypto/envelope/job";
import type { JobRequestEnvelope } from "@opendatalabs/vana-sdk/protocol/jobs";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  DataStoragePort,
  ProtocolGatewayPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import { deriveBuilderId } from "@opendatalabs/personal-server-ts-core/policy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { privateKeyToAccount } from "viem/accounts";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { executeJob, JobFailure, type JobWorkerDeps } from "./worker.js";

setFlagsFromString("--expose-gc");
const gc = runInNewContext("gc") as () => void;

const MIB = 1024 * 1024;
const NOW = new Date("2026-09-03T12:00:00.000Z");
const DEADLINE = "2026-09-03T12:05:00.000Z";
/** A scope with no legacy binding, so its body is served as stored. */
const SCOPE = "acme.notes";
/** A scope the legacy projection serves from stored `{records}` rows. */
const PROJECTED = "chatgpt.conversations";
const AT = "2026-09-03T11:00:00.000Z";
const AUTH_AUDIENCE = "http://localhost:8080";
const GRANT_ID = `0x${"55".repeat(32)}` as const;
const JOB_ID = "123e4567-e89b-42d3-a456-426614174000";
const owner = createTestWallet(20);
const builder = createTestWallet(21);
const builderOwner = createTestWallet(22);
const server = privateKeyToAccount(createTestWallet(23).privateKey);
const builderAccount = privateKeyToAccount(builder.privateKey);
const gatewayConfig = {
  chainId: 14_800,
  contracts: {
    dataRegistry: owner.address,
    dataPortabilityPermissions: owner.address,
    dataPortabilityServer: owner.address,
    dataPortabilityGrantees: owner.address,
    dataPortabilityEscrow: owner.address,
    feeRegistry: owner.address,
  },
} satisfies DataPortabilityGatewayConfig;
const BUILDER_APP_URL = "https://builder.example";
const GRANTEE_ID = deriveBuilderId(
  {
    ownerAddress: builderOwner.address,
    granteeAddress: builder.address,
    publicKey: builderAccount.publicKey,
    appUrl: BUILDER_APP_URL,
  },
  gatewayConfig,
);

async function chainGateway(): Promise<ProtocolGatewayPort> {
  const builderRecord: Builder & { signature?: string } = {
    id: GRANTEE_ID,
    ownerAddress: builderOwner.address,
    granteeAddress: builder.address,
    publicKey: builderAccount.publicKey,
    appUrl: BUILDER_APP_URL,
    addedAt: NOW.toISOString(),
  };
  builderRecord.signature = await builderOwner.signTypedData({
    domain: builderRegistrationDomain(gatewayConfig),
    types: BUILDER_REGISTRATION_TYPES,
    primaryType: "BuilderRegistration",
    message: {
      ownerAddress: builderRecord.ownerAddress,
      granteeAddress: builderRecord.granteeAddress,
      publicKey: builderRecord.publicKey,
      appUrl: builderRecord.appUrl,
    },
  });
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: GRANTEE_ID,
    scopes: [SCOPE, PROJECTED],
    status: "confirmed",
    addedAt: NOW.toISOString(),
    expiresAt: "0",
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: NOW.toISOString(),
    paidBy: owner.address,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: owner.address,
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  } as GatewayGrantResponse & { signature?: string };
  grant.signature = await owner.signTypedData({
    domain: grantRegistrationDomain(gatewayConfig),
    types: GRANT_REGISTRATION_TYPES,
    primaryType: "GrantRegistration",
    message: {
      grantorAddress: grant.grantorAddress,
      granteeId: grant.granteeId,
      scopes: grant.scopes,
      grantVersion: grant.grantVersion,
      expiresAt: grant.expiresAt,
    },
  });
  return {
    getBuilder: vi.fn().mockResolvedValue(builderRecord),
    getGrant: vi.fn().mockResolvedValue(grant),
    getServer: vi.fn().mockResolvedValue({
      id: "server-1",
      ownerAddress: owner.address,
      serverAddress: server.address,
      publicKey: server.publicKey,
      serverUrl: AUTH_AUDIENCE,
      addedAt: NOW.toISOString(),
      revokedAt: null,
    }),
    getSchemaForScope: vi.fn(),
    getDataPoint: vi.fn(),
    listDataPointsByOwner: vi.fn(),
  } as unknown as ProtocolGatewayPort;
}

async function jobRequest(scope = SCOPE): Promise<JobRequestEnvelope> {
  const request = {
    v: 1 as const,
    jobId: JOB_ID,
    owner: owner.address,
    builder: builder.address,
    builderPublicKey: builderAccount.publicKey,
    grantId: GRANT_ID,
    scope,
    operation: "raw_read" as const,
    pinnedVersion: null,
    deadline: DEADLINE,
  };
  const auth = await buildWeb3SignedHeader({
    wallet: builder,
    aud: AUTH_AUDIENCE,
    method: "POST",
    uri: "/v1/jobs/execute",
    body: canonicalJobRequestBytes(request),
    iat: Math.floor(NOW.getTime() / 1_000) - 1,
    exp: Math.floor(NOW.getTime() / 1_000) + 300,
  });
  return { request, auth };
}

/** A legacy envelope of about `bytes` stored bytes, many small strings. */
function legacyEnvelope(bytes: number, marker = "a"): DataFileEnvelope {
  const text = marker.repeat(1_000);
  return {
    version: "1.0",
    scope: SCOPE,
    collectedAt: AT,
    data: {
      notes: Array.from({ length: Math.ceil(bytes / 1_050) }, (_, i) => ({
        id: i,
        text,
      })),
    },
  } as DataFileEnvelope;
}

/** What the stored-file hook saw: bytes delivered and post-GC samples. */
interface StreamProbe {
  opens: number;
  bytes: number;
  /** Stored bytes taken by whole-envelope reads, outside the stream. */
  wholeBytes: number;
  baseline: number;
  peak: number;
  samples: number;
  /** Runs once, before the first stored stream opens. */
  beforeOpen?: (open: number) => Promise<void>;
}

/** Heap kept alive, after full collections: JS heap plus Buffers. */
function retained(): number {
  gc();
  gc();
  const usage = process.memoryUsage();
  return usage.heapUsed + usage.external;
}

/** The retained heap once garbage from setup, and its finalizers, are gone. */
async function settledBaseline(): Promise<number> {
  let last = Number.POSITIVE_INFINITY;
  for (let round = 0; round < 10; round += 1) {
    await new Promise((resolve) => setImmediate(resolve));
    const now = retained();
    if (Math.abs(last - now) < 256 * 1024) return now;
    last = now;
  }
  return last;
}

let dataDir: string;
let indexManager: IndexManager;
let raw: DataStoragePort;
let probe: StreamProbe;

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "worker-grantee-stream-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  raw = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
  probe = {
    opens: 0,
    bytes: 0,
    wholeBytes: 0,
    baseline: 0,
    peak: 0,
    samples: 0,
  };
  const readWhole = raw.readEnvelope.bind(raw);
  raw.readEnvelope = async (scope, collectedAt) => {
    const envelope = await readWhole(scope, collectedAt);
    probe.wholeBytes += JSON.stringify(envelope).length;
    return envelope;
  };
  const readBytes = raw.readEnvelopeBytes!.bind(raw);
  raw.readEnvelopeBytes = async (scope, collectedAt) => {
    const bytes = await readBytes(scope, collectedAt);
    probe.wholeBytes += bytes.byteLength;
    return bytes;
  };
  // Count and sample every stored byte the read takes, without changing it.
  const openStored = raw.readEnvelopeStream!.bind(raw);
  raw.readEnvelopeStream = async (scope, collectedAt) => {
    probe.opens += 1;
    await probe.beforeOpen?.(probe.opens);
    let chunks = 0;
    return (await openStored(scope, collectedAt)).pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          probe.bytes += chunk.byteLength;
          if (++chunks % 16 === 0) {
            probe.peak = Math.max(probe.peak, retained());
            probe.samples += 1;
          }
          controller.enqueue(chunk);
        },
      }),
    );
  };
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

/** Publish and index a version as sync does: storage derives the row. */
async function publish(envelope: DataFileEnvelope, sizeBytes?: number) {
  const written = await raw.writeEnvelope(envelope);
  await raw.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes: sizeBytes ?? written.sizeBytes,
  });
  return written;
}

interface Upload {
  fetch: ReturnType<typeof vi.fn>;
  uploadedBytes(): number;
}

function resultUpload(): Upload {
  let uploaded = 0;
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({ authorization: "Web3Signed result-signature" }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    )
    .mockImplementationOnce(async (_url: string, init: RequestInit) => {
      for await (const chunk of init.body as unknown as Readable) {
        uploaded += (chunk as Buffer).byteLength;
      }
      return new Response(null, { status: 201 });
    });
  return { fetch, uploadedBytes: () => uploaded };
}

async function workerDeps(
  upload: Upload,
  resultMaxBytes: number,
): Promise<JobWorkerDeps> {
  return {
    serverOwner: owner.address,
    serverAddress: server.address,
    serverPublicKey: server.publicKey,
    authAudience: AUTH_AUDIENCE,
    gateway: await chainGateway(),
    gatewayConfig,
    // The served port, as bootstrap builds it; the worker derives the
    // grantee view itself.
    storage: withLegacyProjection(raw),
    ecies: new NodeECIESProvider(),
    now: () => NOW,
    logger: { info: vi.fn(), warn: vi.fn() },
    accessLogWriter: { write: vi.fn().mockResolvedValue(undefined) },
    resultMaxBytes,
    resultTempDir: dataDir,
    resultUpload: {
      storageEndpoint: "https://storage.example",
      agentEndpoint: "http://agent:8787",
      accessToken: "sandbox-token",
      chainId: gatewayConfig.chainId,
      fetch: upload.fetch,
    },
  } as unknown as JobWorkerDeps;
}

describe("a TEE job read through the grantee read port", () => {
  it("streams a 48 MiB legacy envelope with bounded retained memory", async () => {
    const written = await publish(legacyEnvelope(50 * MIB));
    expect(written.sizeBytes).toBeGreaterThanOrEqual(48 * MIB);
    const upload = resultUpload();
    const deps = await workerDeps(upload, 64 * MIB);
    const request = await jobRequest();
    probe.baseline = await settledBaseline();
    probe.peak = Number.NEGATIVE_INFINITY;

    const result = await executeJob(request, deps);

    const growth = probe.peak - probe.baseline;
    if (process.env.GRANTEE_STREAM_MEASURE) {
      console.log(
        JSON.stringify({
          documentBytes: written.sizeBytes,
          storedBytesRead: probe.bytes,
          storedStreamOpens: probe.opens,
          samples: probe.samples,
          baselineRetainedBytes: probe.baseline,
          peakRetainedBytes: probe.peak,
          retainedGrowthBytes: growth,
          retainedGrowthMiB: Number((growth / MIB).toFixed(2)),
          sealedBytes: result.resultSize,
        }),
      );
    }
    expect(upload.fetch).toHaveBeenCalledTimes(2);
    expect(upload.uploadedBytes()).toBe(result.resultSize);
    expect(result.resultSize).toBeGreaterThan(written.sizeBytes / 2);
    expect(probe.samples).toBeGreaterThanOrEqual(50);
    // The document is about 50 MiB. Holding it once would add at least
    // that; a streamed read keeps a few chunks.
    expect(growth).toBeLessThan(16 * MIB);
  }, 120_000);

  it("stops reading at the byte budget when the row under-reports the size", async () => {
    const written = await publish(legacyEnvelope(4 * MIB), 100);
    expect(written.sizeBytes).toBeGreaterThan(4 * MIB);
    const upload = resultUpload();

    await expect(
      executeJob(await jobRequest(), await workerDeps(upload, MIB)),
    ).rejects.toMatchObject({ code: "RESULT_TOO_LARGE", retryable: false });

    expect(upload.fetch).not.toHaveBeenCalled();
    // Stopped at the cap: the rest of the 4 MiB file was never read.
    expect(probe.bytes).toBeLessThanOrEqual(MIB + 512 * 1024);
  });

  it("serves a row from before digests, then records its digest", async () => {
    const envelope = legacyEnvelope(256 * 1024);
    const written = await raw.writeEnvelope(envelope);
    // A row indexed before content digests: no digest, no generation.
    indexManager.insert({
      fileId: null,
      path: written.relativePath,
      scope: SCOPE,
      collectedAt: AT,
      sizeBytes: written.sizeBytes,
    });
    const upload = resultUpload();

    await executeJob(await jobRequest(), await workerDeps(upload, 64 * MIB));

    expect(upload.fetch).toHaveBeenCalledTimes(2);
    expect(indexManager.findLatestByScope(SCOPE)?.contentDigest).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it("never fast-paths a backfilled row whose bytes became PDPP", async () => {
    const legacy = legacyEnvelope(64 * 1024);
    const written = await raw.writeEnvelope(legacy);
    // A row from before generations and digests, indexed as legacy.
    const row = indexManager.insert({
      fileId: null,
      path: written.relativePath,
      scope: SCOPE,
      collectedAt: AT,
      sizeBytes: written.sizeBytes,
      pdppOrigin: false,
    });
    // The bytes at the path become PDPP before anything backfills the row.
    await writeFile(
      written.path,
      JSON.stringify({
        ...legacy,
        data: {
          notes: ["pdpp-only"],
          $pdpp: { version: 1, sourceId: "https://registry.pdpp.dev/acme" },
        },
      }),
    );
    await raw.backfillGeneration!(row);
    const upload = resultUpload();

    const failure = await executeJob(
      await jobRequest(),
      await workerDeps(upload, 64 * MIB),
    ).then(
      () => undefined,
      (error: unknown) => error,
    );

    expect(failure).toBeInstanceOf(JobFailure);
    expect(failure).toMatchObject({ code: "GRANT_INVALID" });
    expect(upload.fetch).not.toHaveBeenCalled();
    // The identity recorded is the bytes' whole identity, provenance too.
    expect(indexManager.findByPath(written.relativePath)).toMatchObject({
      pdppOrigin: true,
      generation: expect.any(String),
      contentDigest: expect.any(String),
    });
  });

  describe("a projected scope", () => {
    const at = AT;
    function records(title: string, count: number) {
      return {
        version: "1.0",
        scope: PROJECTED,
        collectedAt: at,
        data: {
          records: Array.from({ length: count }, (_, i) => ({
            id: `conv-${i}`,
            title,
            create_time: "2026-09-01T10:00:00Z",
            update_time: "2026-09-01T10:05:00Z",
            current_node: null,
            message_count_on_current_branch: 0,
          })),
        },
      } as DataFileEnvelope;
    }

    it("stops reading its stored input at the byte budget", async () => {
      const written = await publish(records("x".repeat(200), 16_000), 100);
      expect(written.sizeBytes).toBeGreaterThan(4 * MIB);
      const upload = resultUpload();

      await expect(
        executeJob(await jobRequest(PROJECTED), await workerDeps(upload, MIB)),
      ).rejects.toMatchObject({ code: "RESULT_TOO_LARGE" });

      expect(upload.fetch).not.toHaveBeenCalled();
      expect(probe.bytes + probe.wholeBytes).toBeLessThanOrEqual(
        MIB + 512 * 1024,
      );
    });

    it("refuses stored rows changed after the row was authorized", async () => {
      const written = await publish(records("authorized", 3));
      await writeFile(
        written.path,
        JSON.stringify(records("replaced", 3), null, 2),
      );
      const upload = resultUpload();

      const failure = await executeJob(
        await jobRequest(PROJECTED),
        await workerDeps(upload, 64 * MIB),
      ).then(
        () => undefined,
        (error: unknown) => error,
      );

      expect(failure).toMatchObject({ code: "VERSION_MISMATCH" });
      expect(upload.fetch).not.toHaveBeenCalled();
    });

    it("still serves the projected rows of the authorized version", async () => {
      await publish(records("authorized", 3));
      const upload = resultUpload();

      const result = await executeJob(
        await jobRequest(PROJECTED),
        await workerDeps(upload, 64 * MIB),
      );

      expect(upload.fetch).toHaveBeenCalledTimes(2);
      expect(result.resultSize).toBeGreaterThan(0);
    });
  });

  describe("bytes changed after the row was authorized", () => {
    async function swapAt(open: number) {
      const written = await publish(legacyEnvelope(256 * 1024, "a"));
      const other = Buffer.from(
        JSON.stringify(legacyEnvelope(256 * 1024, "b"), null, 2),
      );
      probe.beforeOpen = async (current) => {
        if (current === open) await writeFile(written.path, other);
      };
      const upload = resultUpload();
      const failure = await executeJob(
        await jobRequest(),
        await workerDeps(upload, 64 * MIB),
      ).then(
        () => undefined,
        (error: unknown) => error,
      );
      return { failure, upload, other };
    }

    it("refuses bytes changed before the first read", async () => {
      const { failure, upload } = await swapAt(1);

      expect(failure).toBeInstanceOf(JobFailure);
      expect(failure).toMatchObject({
        code: "VERSION_MISMATCH",
        retryable: true,
      });
      expect(upload.fetch).not.toHaveBeenCalled();
    });

    it("does not upload bytes changed between the scan and the seal", async () => {
      const { failure, upload, other } = await swapAt(2);

      expect(failure).toBeInstanceOf(JobFailure);
      expect(failure).toMatchObject({
        code: "VERSION_MISMATCH",
        retryable: true,
      });
      expect(upload.fetch).not.toHaveBeenCalled();
      // The changed file really was read: the refusal came from the digest.
      expect(probe.bytes).toBeGreaterThan(other.byteLength);
    });
  });
});
