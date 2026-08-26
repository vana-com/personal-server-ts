import { describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { verifyMessage } from "viem";

import { createGatewayDeleteDataPort } from "./delete-data-port.js";
import { computeDataPointId } from "./data-point-id.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "./tombstone.js";
import type { DataPointFeedPort, DataPointFeedRecord } from "../ports/index.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12" as const;
const SCOPE = "instagram.profile";
const DATA_POINT_ID = computeDataPointId(OWNER, SCOPE);
const GATEWAY = "https://gateway.test";
const STORAGE = "https://storage.test";
const CHAIN_ID = 14800;
const serverAccount = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);

function liveRecord(
  overrides?: Partial<DataPointFeedRecord>,
): DataPointFeedRecord {
  return {
    id: DATA_POINT_ID,
    ownerAddress: OWNER,
    scope: SCOPE,
    dataHash: "0x" + "11".repeat(32),
    metadataHash: "0x" + "22".repeat(32),
    expectedVersion: "3",
    addedAt: "2026-08-01T00:00:00.000Z",
    deletedAt: null,
    ...overrides,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makePort(
  feedRecord: DataPointFeedRecord | null,
  fetchImpl: typeof fetch,
) {
  const dataPointFeed: DataPointFeedPort = {
    getDataPoint: vi.fn(async () => feedRecord),
    listDataPointsByOwner: vi.fn(),
  };
  const signAddData = vi.fn(async () => "0xaddsig" as `0x${string}`);
  const port = createGatewayDeleteDataPort({
    gatewayUrl: `${GATEWAY}/`,
    dataPointFeed,
    serverOwner: OWNER,
    signer: { signAddData },
    storage: {
      endpoint: STORAGE,
      chainId: CHAIN_ID,
      signMessage: (message) => serverAccount.signMessage({ message }),
    },
    fetch: fetchImpl,
  });
  return { port, dataPointFeed, signAddData };
}

describe("createGatewayDeleteDataPort.tombstone", () => {
  it("signs AddData with the tombstone hashes at current+1 and sends DELETE /v1/data/:id", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, {
        data: {
          dataPointId: DATA_POINT_ID,
          expectedVersion: "4",
          deletedAt: "2026-08-25T10:00:00.000Z",
        },
      }),
    );
    const { port, signAddData, dataPointFeed } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.tombstone(SCOPE);

    expect(dataPointFeed.getDataPoint).toHaveBeenCalledWith({
      ownerAddress: OWNER,
      scope: SCOPE,
    });
    expect(signAddData).toHaveBeenCalledWith({
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      expectedVersion: 4n,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${GATEWAY}/v1/data/${DATA_POINT_ID}`);
    expect(init.method).toBe("DELETE");
    expect(init.headers).toEqual({
      "Content-Type": "application/json",
      Authorization: "Web3Signed 0xaddsig",
    });
    expect(JSON.parse(init.body as string)).toEqual({
      ownerAddress: OWNER,
      scope: SCOPE,
      expectedVersion: "4",
      signature: "0xaddsig",
    });
    expect(outcome).toEqual({
      status: "tombstoned",
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: "2026-08-25T10:00:00.000Z",
    });
  });

  it("skips the gateway call when the point was never registered", async () => {
    const fetchImpl = vi.fn();
    const { port, signAddData } = makePort(
      null,
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.tombstone(SCOPE);

    expect(outcome).toEqual({
      status: "not-registered",
      dataPointId: DATA_POINT_ID,
    });
    expect(signAddData).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("does not re-sign a point the feed already reports as deleted", async () => {
    const fetchImpl = vi.fn();
    const { port, signAddData } = makePort(
      liveRecord({
        deletedAt: "2026-08-20T00:00:00.000Z",
        expectedVersion: "4",
      }),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.tombstone(SCOPE);

    expect(outcome).toEqual({
      status: "already-deleted",
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: "2026-08-20T00:00:00.000Z",
    });
    expect(signAddData).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("re-signs once against nextExpectedVersion on a 409", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(409, {
          error: "Stale expectedVersion",
          currentExpectedVersion: "7",
          nextExpectedVersion: "8",
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, { data: { expectedVersion: "8", deletedAt: null } }),
      );
    const { port, signAddData } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.tombstone(SCOPE);

    expect(signAddData).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ expectedVersion: 4n }),
    );
    expect(signAddData).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ expectedVersion: 8n }),
    );
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(outcome).toMatchObject({ status: "tombstoned", version: "8" });
  });

  it("treats a 410 from the gateway as already-deleted", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(410, {
        error: "Gone",
        deletedAt: "2026-08-24T00:00:00.000Z",
      }),
    );
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.tombstone(SCOPE);

    expect(outcome).toEqual({
      status: "already-deleted",
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: "2026-08-24T00:00:00.000Z",
    });
  });

  it("throws on other gateway errors so the caller keeps the local copy", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(503, { error: "Service Unavailable" }),
    );
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    await expect(port.tombstone(SCOPE)).rejects.toThrow(
      "Gateway error: 503 Service Unavailable",
    );
  });
});

describe("createGatewayDeleteDataPort.deleteBlobs", () => {
  it("sends a Web3Signed DELETE to the chain-scoped owner/scope blob prefix", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, { deleted: 3 }));
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.deleteBlobs("chatgpt.conversations");

    expect(outcome).toEqual({ blobsDeleted: 3 });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    const expectedPath = `/v1/chains/${CHAIN_ID}/blobs/${OWNER.toLowerCase()}/chatgpt.conversations`;
    expect(url).toBe(`${STORAGE}${expectedPath}`);
    expect(init.method).toBe("DELETE");
    expect(init.body).toBeUndefined();

    // The header is the SDK's Web3Signed shape, signed by the server
    // account over (aud = storage origin, method DELETE, uri = path,
    // empty-body hash).
    const header = (init.headers as Record<string, string>).authorization;
    expect(header.startsWith("Web3Signed ")).toBe(true);
    const [payloadB64, signature] = header
      .slice("Web3Signed ".length)
      .split(".");
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    );
    expect(payload).toMatchObject({
      aud: STORAGE,
      method: "DELETE",
      uri: expectedPath,
      bodyHash:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });
    expect(payload.exp - payload.iat).toBe(300);
    expect(
      await verifyMessage({
        address: serverAccount.address,
        message: payloadB64,
        signature: signature as `0x${string}`,
      }),
    ).toBe(true);
  });

  it("treats 404 as nothing-to-delete and fails loudly on other statuses", async () => {
    const notFound = vi.fn(async () => new Response(null, { status: 404 }));
    const { port: p1 } = makePort(
      liveRecord(),
      notFound as unknown as typeof fetch,
    );
    expect(await p1.deleteBlobs(SCOPE)).toEqual({ blobsDeleted: 0 });

    const boom = vi.fn(
      async () =>
        new Response(null, { status: 502, statusText: "Bad Gateway" }),
    );
    const { port: p2 } = makePort(
      liveRecord(),
      boom as unknown as typeof fetch,
    );
    await expect(p2.deleteBlobs(SCOPE)).rejects.toThrow(
      "vana-storage delete failed: 502 Bad Gateway",
    );
  });
});
