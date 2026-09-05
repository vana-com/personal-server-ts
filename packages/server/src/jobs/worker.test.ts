import { createHash } from "node:crypto";
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
import type {
  JobRequest,
  JobRequestEnvelope,
} from "@opendatalabs/vana-sdk/protocol/jobs";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { redactEnvelopeForGrantee } from "@opendatalabs/personal-server-ts-core/api";
import type {
  DataStoragePort,
  ProtocolGatewayPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import { deriveBuilderId } from "@opendatalabs/personal-server-ts-core/policy";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import { privateKeyToAccount } from "viem/accounts";
import { executeJob, JobFailure, type JobWorkerDeps } from "./worker.js";

const NOW = new Date("2026-09-03T12:00:00.000Z");
const DEADLINE = "2026-09-03T12:05:00.000Z";
const SCOPE = "instagram.profile";
const AUTH_AUDIENCE = "http://localhost:8080";
const RECORD_VALUE = "TOP_SECRET_RECORD";
const GRANT_ID = `0x${"55".repeat(32)}` as const;
const JOB_ID = "123e4567-e89b-42d3-a456-426614174000";
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

type SignedGrant = GatewayGrantResponse & { signature?: string };
type SignedBuilder = Builder & { signature?: string };

interface Fixture {
  envelope: JobRequestEnvelope;
  deps: JobWorkerDeps;
  grant: SignedGrant;
  builderRecord: SignedBuilder;
  gateway: ProtocolGatewayPort;
  storage: DataStoragePort;
  dataEnvelope: DataFileEnvelope;
  resultUploadFetch: ReturnType<typeof vi.fn>;
}

async function createFixture(): Promise<Fixture> {
  const builderRecord: SignedBuilder = {
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
    readEnvelopeBytes: vi
      .fn()
      .mockResolvedValue(
        new TextEncoder().encode(JSON.stringify(dataEnvelope, null, 2)),
      ),
    findLatestVersionByScope: vi.fn().mockResolvedValue(entry.version),
  } as unknown as DataStoragePort;
  const gateway = {
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
  const eciesProvider = new NodeECIESProvider();
  const accessLogWriter = {
    write: vi.fn().mockResolvedValue(undefined),
  } satisfies AccessLogWriter;
  const resultUploadFetch = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({ authorization: "Web3Signed result-signature" }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    )
    .mockResolvedValueOnce(new Response(null, { status: 201 }));
  const request = {
    v: 1 as const,
    jobId: JOB_ID,
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
  const deps = {
    serverOwner: owner.address,
    serverAddress: server.address,
    serverPublicKey: server.publicKey,
    authAudience: AUTH_AUDIENCE,
    gateway,
    gatewayConfig,
    storage,
    ecies: eciesProvider,
    now: () => NOW,
    logger: { info: vi.fn(), warn: vi.fn() },
    accessLogWriter,
    resultUpload: {
      storageEndpoint: "https://storage.example",
      agentEndpoint: "http://agent:8787",
      accessToken: "sandbox-token",
      chainId: gatewayConfig.chainId,
      fetch: resultUploadFetch,
    },
  } as unknown as JobWorkerDeps;

  return {
    envelope,
    deps,
    grant,
    builderRecord,
    gateway,
    storage,
    dataEnvelope,
    resultUploadFetch,
  };
}

async function signRequest(
  request: JobRequestEnvelope["request"],
  signer = builder,
  audience = AUTH_AUDIENCE,
): Promise<string> {
  return buildWeb3SignedHeader({
    wallet: signer,
    aud: audience,
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

  it("stores raw sealed bytes and returns their object metadata", async () => {
    const fixture = await createFixture();
    const response = await executeJob(fixture.envelope, fixture.deps);
    expect(fixture.resultUploadFetch).toHaveBeenCalledTimes(2);
    const [signingUrl, signingInit] = fixture.resultUploadFetch.mock
      .calls[0] as [string, RequestInit];
    const [url, init] = fixture.resultUploadFetch.mock.calls[1] as [
      string,
      RequestInit,
    ];
    const sealedBytes = init.body as Uint8Array;
    const result = await openJobResult(
      sealedBytes,
      builder.privateKey,
      new NodeECIESProvider(),
      { jobId: JOB_ID, scope: SCOPE, version: "7" },
    );
    expect(result.body).toBeInstanceOf(Uint8Array);
    const bodyText = new TextDecoder().decode(result.body);
    const redacted = JSON.parse(bodyText);

    expect(result).toMatchObject({
      v: 1,
      jobId: JOB_ID,
      scope: SCOPE,
      version: "7",
      contentType: "application/json",
    });
    expect(redacted.data).toEqual({ name: RECORD_VALUE });
    expect(bodyText).toBe(
      JSON.stringify(redactEnvelopeForGrantee(fixture.dataEnvelope)),
    );
    expect(fixture.storage.readEnvelope).not.toHaveBeenCalled();
    for (const event of ["read", "seal", "sign", "upload", "done"]) {
      expect(fixture.deps.logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          jobId: JOB_ID,
          stage: "execute",
          event,
          elapsedMs: expect.any(Number),
          rssMiB: expect.any(Number),
          heapUsedMiB: expect.any(Number),
          arrayBuffersMiB: expect.any(Number),
        }),
        "Enclave job execution progress",
      );
    }
    expect(fixture.deps.logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: "read",
        payloadBytes: result.body.byteLength,
      }),
      "Enclave job execution progress",
    );
    expect(fixture.deps.logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: "seal",
        sealedBytes: sealedBytes.byteLength,
      }),
      "Enclave job execution progress",
    );
    const expectedHash = `0x${createHash("sha256")
      .update(sealedBytes)
      .digest("hex")}`;
    expect(signingUrl).toBe("http://agent:8787/agent/v1/job-results/sign");
    expect(signingInit).toMatchObject({
      method: "POST",
      headers: {
        Authorization: "Bearer sandbox-token",
        "Content-Type": "application/json",
      },
    });
    expect(JSON.parse(signingInit.body as string)).toEqual({
      jobId: JOB_ID,
      chainId: 14800,
      owner: owner.address,
      byteLength: sealedBytes.byteLength,
      bodyHash: `sha256:${expectedHash.slice(2)}`,
    });
    expect(signingInit.body).not.toContain(
      Buffer.from(sealedBytes).toString("base64"),
    );
    expect(url).toBe(
      `https://storage.example/v1/job-results/14800/${owner.address.toLowerCase()}/${JOB_ID}`,
    );
    expect(init).toMatchObject({
      method: "PUT",
      headers: {
        Authorization: "Web3Signed result-signature",
        "Content-Type": "application/octet-stream",
      },
      body: sealedBytes,
    });
    expect(response).toEqual({
      resultObjectKey: `jobresults/14800/${JOB_ID}`,
      resultHash: expectedHash,
      resultSize: sealedBytes.byteLength,
    });
    expect(fixture.deps.accessLogWriter.write).toHaveBeenCalledWith(
      expect.objectContaining({ grantId: GRANT_ID, scope: SCOPE }),
    );
  });

  it("rejects an over-budget result before reading the stored bytes", async () => {
    const fixture = await createFixture();
    fixture.deps.resultMaxBytes = 99;

    await expect(
      executeJob(fixture.envelope, fixture.deps),
    ).rejects.toMatchObject({
      code: "RESULT_TOO_LARGE",
      message: "job result is 100 bytes; limit is 99 bytes",
      retryable: false,
    });

    expect(fixture.storage.readEnvelopeBytes).not.toHaveBeenCalled();
    expect(fixture.storage.readEnvelope).not.toHaveBeenCalled();
    expect(fixture.resultUploadFetch).not.toHaveBeenCalled();
  });

  it("reads and seals a result at the byte budget", async () => {
    const fixture = await createFixture();
    fixture.deps.resultMaxBytes = 100;

    await expect(executeJob(fixture.envelope, fixture.deps)).resolves.toEqual(
      expect.objectContaining({ resultSize: expect.any(Number) }),
    );

    expect(fixture.storage.readEnvelopeBytes).toHaveBeenCalledOnce();
  });

  it("normalizes an uppercase job id before building result paths", async () => {
    const fixture = await createFixture();
    fixture.envelope.request.jobId = JOB_ID.toUpperCase();
    fixture.envelope.auth = await signRequest(fixture.envelope.request);

    const response = await executeJob(fixture.envelope, fixture.deps);
    const signingBody = JSON.parse(
      fixture.resultUploadFetch.mock.calls[0]?.[1]?.body as string,
    );
    const uploadUrl = fixture.resultUploadFetch.mock.calls[1]?.[0];

    expect(signingBody.jobId).toBe(JOB_ID);
    expect(uploadUrl).toBe(
      `https://storage.example/v1/job-results/14800/${owner.address.toLowerCase()}/${JOB_ID}`,
    );
    expect(response.resultObjectKey).toBe(`jobresults/14800/${JOB_ID}`);
  });

  it("rejects a traversal job id before building result paths", async () => {
    const fixture = await createFixture();
    fixture.envelope.request.jobId = "../../chains/14800/owner/scope";
    fixture.envelope.auth = await signRequest(fixture.envelope.request);

    await expectFailure(fixture, "INTERNAL");
    expect(fixture.resultUploadFetch).not.toHaveBeenCalled();
  });

  it("rejects builder auth for another audience", async () => {
    const fixture = await createFixture();
    fixture.envelope.auth = await signRequest(
      fixture.envelope.request,
      builder,
      "https://other.example",
    );

    await expectFailure(fixture, "AUTH_INVALID");
  });

  it("rejects a revoked server registration", async () => {
    const fixture = await createFixture();
    vi.mocked(fixture.gateway.getServer).mockResolvedValue({
      id: "server-1",
      ownerAddress: owner.address,
      serverAddress: server.address,
      publicKey: server.publicKey,
      serverUrl: AUTH_AUDIENCE,
      addedAt: NOW.toISOString(),
      revokedAt: NOW.toISOString(),
    });

    await expectFailure(fixture, "SERVER_NOT_REGISTERED");
  });

  it("retries transport failures while reading the grant", async () => {
    const fixture = await createFixture();
    vi.mocked(fixture.gateway.getGrant).mockRejectedValue(
      new Error("Gateway error: 503"),
    );

    await expectFailure(fixture, "INTERNAL", true);
  });

  it("retries transport failures while reading the builder", async () => {
    const fixture = await createFixture();
    vi.mocked(fixture.gateway.getBuilder).mockRejectedValue(
      new Error("Gateway error: 503"),
    );

    await expectFailure(fixture, "INTERNAL", true);
  });

  it("rejects a registration for another server public key", async () => {
    const fixture = await createFixture();
    vi.mocked(fixture.gateway.getServer).mockResolvedValue({
      id: "server-1",
      ownerAddress: owner.address,
      serverAddress: server.address,
      publicKey: builderAccount.publicKey,
      serverUrl: AUTH_AUDIENCE,
      addedAt: NOW.toISOString(),
      revokedAt: null,
    });

    await expectFailure(fixture, "SERVER_NOT_REGISTERED");
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

  it.each([
    [413, "RESULT_TOO_LARGE", false],
    [500, "RESULT_UPLOAD_FAILED", true],
    [403, "RESULT_UPLOAD_FAILED", false],
  ] as const)(
    "maps storage status %i to %s (retryable=%s)",
    async (status, code, retryable) => {
      const fixture = await createFixture();
      fixture.resultUploadFetch.mockReset();
      fixture.resultUploadFetch
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ authorization: "Web3Signed result-signature" }),
            { status: 200 },
          ),
        )
        .mockResolvedValueOnce(new Response(null, { status }));

      await expectFailure(fixture, code, retryable);
    },
  );

  it("does not retry an agent signing refusal", async () => {
    const fixture = await createFixture();
    fixture.resultUploadFetch.mockReset();
    fixture.resultUploadFetch.mockResolvedValueOnce(
      new Response(null, { status: 403 }),
    );

    await expectFailure(fixture, "RESULT_SIGNING_REFUSED", false);
  });

  it.each([500, 503])(
    "retries an agent signing failure with status %i",
    async (status) => {
      const fixture = await createFixture();
      fixture.resultUploadFetch.mockReset();
      fixture.resultUploadFetch.mockResolvedValueOnce(
        new Response(null, { status }),
      );

      await expectFailure(fixture, "RESULT_UPLOAD_FAILED", true);
    },
  );

  it("retries a storage network failure", async () => {
    const fixture = await createFixture();
    fixture.resultUploadFetch.mockReset();
    fixture.resultUploadFetch
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ authorization: "Web3Signed result-signature" }),
          { status: 200 },
        ),
      )
      .mockRejectedValueOnce(new Error("network unavailable"));

    await expectFailure(fixture, "RESULT_UPLOAD_FAILED", true);
  });

  it("times out result signing as a retryable failure", async () => {
    vi.useFakeTimers();
    const timeout = fakeAbortSignalTimeout();
    try {
      const fixture = await createFixture();
      fixture.resultUploadFetch.mockReset();
      fixture.resultUploadFetch.mockImplementationOnce(hangUntilAborted);

      const outcome = executeJob(fixture.envelope, fixture.deps).catch(
        (error: unknown) => error,
      );
      await vi.waitFor(() =>
        expect(fixture.resultUploadFetch).toHaveBeenCalledOnce(),
      );
      expect(
        fixture.resultUploadFetch.mock.calls[0]?.[1]?.signal,
      ).toBeDefined();
      await vi.advanceTimersByTimeAsync(15_000);

      await expect(outcome).resolves.toMatchObject({
        code: "RESULT_UPLOAD_FAILED",
        retryable: true,
        message: "result signing request timed out after 15000ms",
      });
    } finally {
      timeout.mockRestore();
      vi.useRealTimers();
    }
  });

  it("times out result upload as a retryable failure", async () => {
    vi.useFakeTimers();
    const timeout = fakeAbortSignalTimeout();
    try {
      const fixture = await createFixture();
      fixture.resultUploadFetch.mockReset();
      fixture.resultUploadFetch
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ authorization: "Web3Signed result-signature" }),
            { status: 200 },
          ),
        )
        .mockImplementationOnce(hangUntilAborted);

      const outcome = executeJob(fixture.envelope, fixture.deps).catch(
        (error: unknown) => error,
      );
      await vi.waitFor(() =>
        expect(fixture.resultUploadFetch).toHaveBeenCalledTimes(2),
      );
      expect(
        fixture.resultUploadFetch.mock.calls[1]?.[1]?.signal,
      ).toBeDefined();
      await vi.advanceTimersByTimeAsync(120_000);

      await expect(outcome).resolves.toMatchObject({
        code: "RESULT_UPLOAD_FAILED",
        retryable: true,
        message: "result upload timed out after 120000ms",
      });
    } finally {
      timeout.mockRestore();
      vi.useRealTimers();
    }
  });
});

function fakeAbortSignalTimeout(): ReturnType<
  typeof vi.spyOn<typeof AbortSignal, "timeout">
> {
  return vi.spyOn(AbortSignal, "timeout").mockImplementation((milliseconds) => {
    const controller = new AbortController();
    setTimeout(
      () =>
        controller.abort(new DOMException("request timed out", "TimeoutError")),
      milliseconds,
    );

    return controller.signal;
  });
}

function hangUntilAborted(
  _input: string | URL | Request,
  init?: RequestInit,
): Promise<Response> {
  return new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), {
      once: true,
    });
  });
}
