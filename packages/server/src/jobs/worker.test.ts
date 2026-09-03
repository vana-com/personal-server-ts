import { createHash } from "node:crypto";
import { pino } from "pino";
import { describe, expect, it, vi } from "vitest";
import {
  BUILDER_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  NodeECIESProvider,
  builderRegistrationDomain,
  grantRegistrationDomain,
  parseWeb3SignedHeader,
  verifyWeb3Signed,
  type Builder,
  type DataFileEnvelope,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import {
  canonicalJobRequestBytes,
  openJobResult,
} from "@opendatalabs/vana-sdk/crypto/envelope/job";
import {
  MAX_INLINE_RESULT_BYTES,
  type JobRequest,
  type JobRequestEnvelope,
} from "@opendatalabs/vana-sdk/protocol/jobs";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  DataStoragePort,
  ProtocolGatewayPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import { privateKeyToAccount } from "viem/accounts";
import { executeJob, JobFailure, type JobWorkerDeps } from "./worker.js";

const NOW = new Date("2026-09-03T12:00:00.000Z");
const DEADLINE = "2026-09-03T12:05:00.000Z";
const SCOPE = "instagram.profile";
const RECORD_VALUE = "TOP_SECRET_RECORD";
const GRANTEE_ID = `0x${"44".repeat(32)}` as const;
const GRANT_ID = `0x${"55".repeat(32)}` as const;
// SDK jobs.test.ts fixture: builderPublicKey is the literal "0x1234".
const VECTOR_PUBLIC_KEY = "0x1234" as const;
const VECTOR_HASH =
  "0xc610d7c24e7a8b952db6e7f2ce902fec090016e44bf30a8908021432678d81a0";
const VECTOR_REQUEST = {
  v: 1,
  jobId: "00000000-0000-4000-8000-000000000001",
  owner: "0x0000000000000000000000000000000000000001",
  builder: "0x0000000000000000000000000000000000000002",
  builderPublicKey: VECTOR_PUBLIC_KEY,
  grantId: `0x${"00".repeat(32)}`,
  scope: "profile.email",
  operation: "raw_read",
  pinnedVersion: null,
  deadline: "2026-01-01T00:00:00.000Z",
} satisfies JobRequest;
const VECTOR_CANONICAL_JSON =
  '{"builder":"0x0000000000000000000000000000000000000002","builderPublicKey":"0x1234","deadline":"2026-01-01T00:00:00.000Z","grantId":"0x0000000000000000000000000000000000000000000000000000000000000000","jobId":"00000000-0000-4000-8000-000000000001","operation":"raw_read","owner":"0x0000000000000000000000000000000000000001","pinnedVersion":null,"scope":"profile.email","v":1}';
const owner = createTestWallet(20);
const builder = createTestWallet(21);
const builderOwner = createTestWallet(22);
const server = privateKeyToAccount(createTestWallet(23).privateKey);
const builderAccount = privateKeyToAccount(builder.privateKey);
const other = createTestWallet(24);
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

type SignedGrant = GatewayGrantResponse & { signature?: string };
type SignedBuilder = Builder & { signature?: string };

interface Fixture {
  envelope: JobRequestEnvelope;
  deps: JobWorkerDeps;
  grant: SignedGrant;
  builderRecord: SignedBuilder;
  gateway: ProtocolGatewayPort;
  storage: DataStoragePort;
}

async function createFixture(): Promise<Fixture> {
  const builderRecord: SignedBuilder = {
    id: GRANTEE_ID,
    ownerAddress: builderOwner.address,
    granteeAddress: builder.address,
    publicKey: builderAccount.publicKey,
    appUrl: "https://builder.example",
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

  const grant: SignedGrant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: GRANTEE_ID,
    scopes: [SCOPE],
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
  };
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

  const entry = {
    id: 1,
    fileId: "file-1",
    schemaId: null,
    path: "instagram.profile/record.json",
    scope: SCOPE,
    collectedAt: "2026-09-03T11:00:00.000Z",
    createdAt: "2026-09-03T11:00:01.000Z",
    sizeBytes: 100,
    version: 7,
    dataPointId: null,
  } satisfies IndexEntry;
  const dataEnvelope: DataFileEnvelope = {
    version: "1.0",
    scope: SCOPE,
    collectedAt: entry.collectedAt,
    data: {
      name: RECORD_VALUE,
      $writtenBy: {
        builder: builder.address,
        grantId: GRANT_ID,
        signature: "private-attribution",
      },
    },
  };
  const storage = {
    kind: "custom",
    findEntry: vi.fn().mockReturnValue(entry),
    readEnvelope: vi.fn().mockResolvedValue(dataEnvelope),
    findLatestVersionByScope: vi.fn().mockResolvedValue(entry.version),
  } as unknown as DataStoragePort;
  const gateway = {
    getBuilder: vi.fn().mockResolvedValue(builderRecord),
    getGrant: vi.fn().mockResolvedValue(grant),
    getServer: vi.fn().mockResolvedValue({
      id: "server-1",
      ownerAddress: owner.address,
    }),
    getSchemaForScope: vi.fn(),
    getDataPoint: vi.fn(),
    listDataPointsByOwner: vi.fn(),
  } as unknown as ProtocolGatewayPort;
  const eciesProvider = new NodeECIESProvider();
  const accessLogWriter = {
    write: vi.fn().mockResolvedValue(undefined),
  } satisfies AccessLogWriter;
  const request = {
    v: 1 as const,
    jobId: "job-1",
    owner: owner.address,
    builder: builder.address,
    builderPublicKey: builderAccount.publicKey,
    grantId: GRANT_ID,
    scope: SCOPE,
    operation: "raw_read" as const,
    pinnedVersion: null,
    deadline: DEADLINE,
  };
  const envelope = { request, auth: await signRequest(request) };
  const deps: JobWorkerDeps = {
    serverOwner: owner.address,
    serverAddress: server.address,
    serverPublicKey: server.publicKey,
    gateway,
    gatewayConfig,
    storage,
    ecies: eciesProvider,
    now: () => NOW,
    logger: pino({ level: "silent" }),
    accessLogWriter,
  };

  return { envelope, deps, grant, builderRecord, gateway, storage };
}

async function signRequest(
  request: JobRequestEnvelope["request"],
  signer = builder,
): Promise<string> {
  return buildWeb3SignedHeader({
    wallet: signer,
    aud: "http://localhost:8080",
    method: "POST",
    uri: "/v1/jobs/execute",
    body: canonicalJobRequestBytes(request),
    iat: Math.floor(NOW.getTime() / 1_000) - 1,
    exp: Math.floor(NOW.getTime() / 1_000) + 300,
  });
}

async function expectFailure(
  fixture: Fixture,
  code: JobFailure["code"],
  retryable = false,
): Promise<void> {
  try {
    await executeJob(fixture.envelope, fixture.deps);
    throw new Error("expected executeJob to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(JobFailure);
    expect(error).toMatchObject({ code, retryable });
    expect((error as Error).message).not.toContain(RECORD_VALUE);
  }
}

describe("executeJob", () => {
  it("verifies builder auth over the SDK canonical request hash", async () => {
    const bytes = canonicalJobRequestBytes(VECTOR_REQUEST);
    const hash = createHash("sha256").update(bytes).digest("hex");
    const auth = await buildWeb3SignedHeader({
      wallet: builder,
      aud: "http://localhost:8080",
      method: "POST",
      uri: "/v1/jobs/execute",
      body: bytes,
      iat: Math.floor(NOW.getTime() / 1_000) - 1,
      exp: Math.floor(NOW.getTime() / 1_000) + 300,
    });
    const verified = await verifyWeb3Signed({
      headerValue: auth,
      expectedOrigin: "http://localhost:8080",
      expectedMethod: "POST",
      expectedPath: "/v1/jobs/execute",
      bodyBytes: bytes,
      now: Math.floor(NOW.getTime() / 1_000),
    });

    expect(new TextDecoder().decode(bytes)).toBe(VECTOR_CANONICAL_JSON);
    expect(new TextDecoder().decode(bytes)).not.toContain("\n");
    expect(`0x${hash}`).toBe(VECTOR_HASH);
    expect(parseWeb3SignedHeader(auth).payload.bodyHash).toBe(`sha256:${hash}`);
    expect(verified.signer.toLowerCase()).toBe(builder.address.toLowerCase());
  });

  it("redacts and encrypts a raw-read result to the builder key", async () => {
    const fixture = await createFixture();
    const response = await executeJob(fixture.envelope, fixture.deps);
    const result = await openJobResult(
      response.resultCiphertext,
      builder.privateKey,
      new NodeECIESProvider(),
      { jobId: "job-1", scope: SCOPE, version: "7" },
    );
    const redacted = JSON.parse(Buffer.from(result.body, "base64").toString());

    expect(result).toMatchObject({
      v: 1,
      jobId: "job-1",
      scope: SCOPE,
      version: "7",
      contentType: "application/json",
    });
    expect(redacted.data).toEqual({ name: RECORD_VALUE });
    expect(response.resultSize).toBe(
      Buffer.from(response.resultCiphertext, "base64").byteLength,
    );
    expect(response.resultHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(fixture.deps.accessLogWriter.write).toHaveBeenCalledWith(
      expect.objectContaining({ grantId: GRANT_ID, scope: SCOPE }),
    );
  });

  it("reports every contract failure code with the required retryability", async () => {
    const scenarios: Array<{
      code: JobFailure["code"];
      retryable?: boolean;
      mutate(fixture: Fixture): void | Promise<void>;
    }> = [
      {
        code: "AUTH_INVALID",
        mutate({ envelope }) {
          envelope.auth = "invalid";
        },
      },
      {
        code: "BUILDER_MISMATCH",
        async mutate({ envelope }) {
          envelope.auth = await signRequest(envelope.request, other);
        },
      },
      {
        code: "OWNER_MISMATCH",
        async mutate({ envelope }) {
          envelope.request.owner = other.address;
          envelope.auth = await signRequest(envelope.request);
        },
      },
      {
        code: "GRANT_REVOKED",
        mutate({ grant }) {
          grant.revokedAt = NOW.toISOString();
        },
      },
      {
        code: "GRANT_INVALID",
        mutate({ gateway }) {
          vi.mocked(gateway.getGrant).mockResolvedValue(null);
        },
      },
      {
        code: "SIGNED_ARTIFACT_MISSING",
        mutate({ grant }) {
          delete grant.signature;
        },
      },
      {
        code: "SIGNED_ARTIFACT_INVALID",
        mutate({ builderRecord }) {
          builderRecord.signature = `0x${"00".repeat(65)}`;
        },
      },
      {
        code: "SERVER_NOT_REGISTERED",
        mutate({ gateway }) {
          vi.mocked(gateway.getServer).mockResolvedValue(null);
        },
      },
      {
        code: "SCOPE_NOT_FOUND",
        mutate({ storage }) {
          vi.mocked(storage.findEntry).mockReturnValue(undefined);
        },
      },
      {
        code: "VERSION_MISMATCH",
        retryable: true,
        async mutate({ envelope }) {
          envelope.request.pinnedVersion = "8";
          envelope.auth = await signRequest(envelope.request);
        },
      },
      {
        code: "DEADLINE_PASSED",
        async mutate({ envelope }) {
          envelope.request.deadline = "2026-09-03T11:59:59.000Z";
          envelope.auth = await signRequest(envelope.request);
        },
      },
      {
        code: "RESULT_TOO_LARGE",
        mutate({ deps }) {
          vi.spyOn(deps.ecies, "encrypt").mockResolvedValue({
            iv: new Uint8Array(16),
            ephemPublicKey: new Uint8Array(65),
            ciphertext: new Uint8Array(MAX_INLINE_RESULT_BYTES),
            mac: new Uint8Array(32),
          });
        },
      },
      {
        code: "INTERNAL",
        async mutate({ envelope }) {
          envelope.request.operation = "inference";
          envelope.auth = await signRequest(envelope.request);
        },
      },
    ];

    for (const scenario of scenarios) {
      const fixture = await createFixture();
      await scenario.mutate(fixture);
      await expectFailure(fixture, scenario.code, scenario.retryable ?? false);
    }
  });
});
