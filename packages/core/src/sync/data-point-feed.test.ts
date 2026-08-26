import { describe, expect, it, vi } from "vitest";

import {
  createGatewayDataPointFeed,
  feedFromGatewayClient,
} from "./data-point-feed.js";
import { computeDataPointId } from "./data-point-id.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "./tombstone.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCOPE = "instagram.profile";
const GATEWAY = "https://gateway.test";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("createGatewayDataPointFeed", () => {
  it("lists with includeDeleted=true and normalises deletedAt", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, {
        data: {
          dataPoints: [
            { id: "0x1", scope: "a.b", expectedVersion: "1" },
            {
              id: "0x2",
              scope: "c.d",
              expectedVersion: "5",
              deletedAt: "2026-08-25T10:00:00.000Z",
            },
          ],
        },
        pagination: { hasMore: true, nextCursor: "next-1" },
      }),
    );
    const feed = createGatewayDataPointFeed({
      gatewayUrl: `${GATEWAY}/`,
      fetch: fetchImpl as unknown as typeof fetch,
    });

    const result = await feed.listDataPointsByOwner(OWNER, "cur-0", {
      includeDeleted: true,
      limit: 100,
    });

    const url = new URL(fetchImpl.mock.calls[0][0] as unknown as string);
    expect(url.origin + url.pathname).toBe(`${GATEWAY}/v1/data`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      user: OWNER,
      cursor: "cur-0",
      limit: "100",
      includeDeleted: "true",
    });
    expect(result.cursor).toBe("next-1");
    expect(result.dataPoints.map((p) => [p.id, p.deletedAt])).toEqual([
      ["0x1", null],
      ["0x2", "2026-08-25T10:00:00.000Z"],
    ]);
  });

  it("looks up a single point by derived id and returns null on 404", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 404 }));
    const feed = createGatewayDataPointFeed({
      gatewayUrl: GATEWAY,
      fetch: fetchImpl as unknown as typeof fetch,
    });

    expect(await feed.getDataPoint({ ownerAddress: OWNER, scope: SCOPE })).toBe(
      null,
    );
    expect(fetchImpl.mock.calls[0][0]).toBe(
      `${GATEWAY}/v1/data/${computeDataPointId(OWNER, SCOPE)}?includeDeleted=true`,
    );
  });

  it("normalises a 410 into a deleted record (body deletedAt, or now as a floor)", async () => {
    const now = new Date("2026-08-25T12:00:00.000Z");
    const withBody = createGatewayDataPointFeed({
      gatewayUrl: GATEWAY,
      now: () => now,
      fetch: (async () =>
        jsonResponse(410, {
          data: { deletedAt: "2026-08-24T00:00:00.000Z", expectedVersion: "9" },
        })) as unknown as typeof fetch,
    });
    expect(
      await withBody.getDataPoint({ ownerAddress: OWNER, scope: SCOPE }),
    ).toMatchObject({
      id: computeDataPointId(OWNER, SCOPE),
      ownerAddress: OWNER,
      scope: SCOPE,
      expectedVersion: "9",
      deletedAt: "2026-08-24T00:00:00.000Z",
    });

    const bare = createGatewayDataPointFeed({
      gatewayUrl: GATEWAY,
      now: () => now,
      fetch: (async () =>
        new Response(null, { status: 410 })) as unknown as typeof fetch,
    });
    expect(
      await bare.getDataPoint({ ownerAddress: OWNER, scope: SCOPE }),
    ).toMatchObject({
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      expectedVersion: "0",
      deletedAt: now.toISOString(),
    });
  });
});

describe("feedFromGatewayClient", () => {
  it("preserves the SDK call shape and passes deletedAt through when present", async () => {
    const gateway = {
      listDataPointsByOwner: vi.fn(async () => ({
        dataPoints: [{ id: "0x1", deletedAt: "2026-08-25T10:00:00.000Z" }],
        cursor: null,
      })),
      getDataPoint: vi.fn(async () => ({ id: "0x1" })),
    };
    const feed = feedFromGatewayClient(gateway);

    const listed = await feed.listDataPointsByOwner(OWNER, "c", {
      includeDeleted: true,
    });
    expect(gateway.listDataPointsByOwner).toHaveBeenCalledWith(OWNER, "c");
    expect(listed.dataPoints[0].deletedAt).toBe("2026-08-25T10:00:00.000Z");

    const single = await feed.getDataPoint({
      ownerAddress: OWNER,
      scope: SCOPE,
    });
    expect(gateway.getDataPoint).toHaveBeenCalledWith(
      computeDataPointId(OWNER, SCOPE),
    );
    expect(single?.deletedAt).toBe(null);
  });
});
