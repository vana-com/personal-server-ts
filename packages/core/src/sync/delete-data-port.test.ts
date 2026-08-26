import { describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";

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

  it("takes the winning tombstone's version from a 410 body, not the version it attempted", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(410, {
        data: { expectedVersion: "9", deletedAt: "2026-08-25T10:00:00.000Z" },
      }),
    );
    const { port } = makePort(
      liveRecord({ expectedVersion: "4" }),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.tombstone(SCOPE);

    expect(outcome).toEqual({
      status: "already-deleted",
      dataPointId: computeDataPointId(OWNER, SCOPE),
      version: "9",
      deletedAt: "2026-08-25T10:00:00.000Z",
    });
  });

  it("re-reads the feed for the winning tombstone when the 410 body carries no version", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(null, { status: 410, statusText: "Gone" }),
    );
    const { port, dataPointFeed } = makePort(
      liveRecord({ expectedVersion: "4" }),
      fetchImpl as unknown as typeof fetch,
    );
    const getDataPoint = dataPointFeed.getDataPoint as ReturnType<typeof vi.fn>;
    getDataPoint
      .mockReset()
      .mockResolvedValueOnce(liveRecord({ expectedVersion: "4" }))
      .mockResolvedValueOnce({
        ...liveRecord({ expectedVersion: "7" }),
        deletedAt: "2026-08-25T10:00:00.000Z",
      });

    const outcome = await port.tombstone(SCOPE);

    expect(getDataPoint).toHaveBeenCalledTimes(2);
    expect(outcome).toMatchObject({
      status: "already-deleted",
      version: "7",
      deletedAt: "2026-08-25T10:00:00.000Z",
    });
  });

  it("reports an unknown version when neither the 410 body nor the feed say", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(null, { status: 410, statusText: "Gone" }),
    );
    const { port, dataPointFeed } = makePort(
      liveRecord({ expectedVersion: "4" }),
      fetchImpl as unknown as typeof fetch,
    );
    (dataPointFeed.getDataPoint as ReturnType<typeof vi.fn>)
      .mockReset()
      .mockResolvedValueOnce(liveRecord({ expectedVersion: "4" }))
      .mockRejectedValueOnce(new Error("gateway down"));

    const outcome = await port.tombstone(SCOPE);

    expect(outcome).toMatchObject({
      status: "already-deleted",
      version: null,
      deletedAt: null,
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

describe("createGatewayDeleteDataPort.deleteBlobVersions", () => {
  it("sends one Web3Signed DELETE per exact version key, never the scope prefix", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, { deleted: true }));
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.deleteBlobVersions("chatgpt.conversations", [
      "1",
      "2",
    ]);

    expect(outcome).toEqual({ deleted: ["1", "2"], missing: [], failed: [] });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    const calls = fetchImpl.mock.calls as unknown as [string, RequestInit][];
    const prefix = `/v1/chains/${CHAIN_ID}/blobs/${OWNER.toLowerCase()}/chatgpt.conversations`;
    expect(calls.map(([url]) => url)).toEqual([
      `${STORAGE}${prefix}/1`,
      `${STORAGE}${prefix}/2`,
    ]);
    for (const [, init] of calls) {
      expect(init.method).toBe("DELETE");
      expect(init.body).toBeUndefined();
    }

    // The header is the SDK's Web3Signed shape, signed by the server
    // account over (aud = storage origin, method DELETE, uri = the exact
    // blob path, empty-body hash).
    const header = (calls[0][1].headers as Record<string, string>)
      .authorization;
    expect(header.startsWith("Web3Signed ")).toBe(true);
    const [payloadB64] = header.slice("Web3Signed ".length).split(".");
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    );
    expect(payload).toMatchObject({
      aud: STORAGE,
      method: "DELETE",
      uri: `${prefix}/1`,
      bodyHash:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });
    expect(payload.exp - payload.iat).toBe(300);
  });

  it("URI-encodes the scope and version segments the way the storage provider does", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, { deleted: true }));
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    await port.deleteBlobVersions("weird scope/with slash", ["3"]);

    const [url] = fetchImpl.mock.calls[0] as unknown as [string];
    expect(url.endsWith("/weird%20scope%2Fwith%20slash/3")).toBe(true);
  });

  it("treats 404 as already gone, reports other statuses per key and keeps going", async () => {
    const statuses: Record<string, number> = { "1": 404, "2": 502, "3": 200 };
    const fetchImpl = vi.fn(async (url: string) => {
      const version = url.slice(url.lastIndexOf("/") + 1);
      const status = statuses[version];
      return status === 200
        ? jsonResponse(200, { deleted: true })
        : new Response(null, {
            status,
            statusText: status === 404 ? "Not Found" : "Bad Gateway",
          });
    });
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.deleteBlobVersions(SCOPE, ["1", "2", "3"]);

    expect(outcome).toEqual({
      deleted: ["3"],
      missing: ["1"],
      failed: [
        { version: "2", error: "vana-storage delete failed: 502 Bad Gateway" },
      ],
    });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("reports a network error per key instead of throwing", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNRESET");
    });
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );

    const outcome = await port.deleteBlobVersions(SCOPE, ["1"]);

    expect(outcome).toEqual({
      deleted: [],
      missing: [],
      failed: [{ version: "1", error: "ECONNRESET" }],
    });
  });

  it("sends nothing for an empty key list", async () => {
    const fetchImpl = vi.fn();
    const { port } = makePort(
      liveRecord(),
      fetchImpl as unknown as typeof fetch,
    );
    expect(await port.deleteBlobVersions(SCOPE, [])).toEqual({
      deleted: [],
      missing: [],
      failed: [],
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
