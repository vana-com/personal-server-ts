import { describe, expect, it, vi } from "vitest";

import type { DataPointFeedRecord } from "../ports/index.js";
import {
  createScopeDeletionTracker,
  deletionTimestamp,
  isEntryCoveredByTombstone,
  tombstoneVersion,
} from "./scope-deletions.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "./tombstone.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCOPE = "instagram.profile";
const DELETED_AT = "2026-08-25T10:00:00.000Z";
const TOMB = { deletedAt: DELETED_AT, version: "3" };

function record(
  overrides: Partial<DataPointFeedRecord> = {},
): DataPointFeedRecord {
  return {
    id: "0xdp",
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

function makeTracker(options: {
  remote?: DataPointFeedRecord | null | Error;
  maxStalenessMs?: number;
  gatewayRetryMs?: number;
  maxLiveEntries?: number;
  owner?: string | undefined;
}) {
  let nowMs = Date.parse("2026-08-26T12:00:00.000Z");
  const getDataPoint = vi.fn(async () => {
    if (options.remote instanceof Error) throw options.remote;
    return options.remote ?? null;
  });
  const logger = { warn: vi.fn() };
  const tracker = createScopeDeletionTracker({
    feed: { getDataPoint, listDataPointsByOwner: vi.fn() },
    serverOwner: "owner" in options ? options.owner : OWNER,
    maxStalenessMs: options.maxStalenessMs,
    gatewayRetryMs: options.gatewayRetryMs,
    maxLiveEntries: options.maxLiveEntries,
    now: () => new Date(nowMs),
    logger,
  });
  return {
    tracker,
    getDataPoint,
    logger,
    advance(ms: number) {
      nowMs += ms;
    },
  };
}

describe("scope deletion tracker", () => {
  it("answers a known tombstone synchronously, without a gateway lookup", async () => {
    const { tracker, getDataPoint } = makeTracker({ remote: record() });
    tracker.markDeleted(SCOPE, TOMB);

    expect(tracker.knownDeletion(SCOPE)).toEqual(TOMB);
    await expect(tracker.resolve(SCOPE)).resolves.toEqual({
      deleted: true,
      deletedAt: DELETED_AT,
      version: "3",
      source: "feed",
      verified: true,
    });
    expect(getDataPoint).not.toHaveBeenCalled();

    // The delete worker names itself as the source of its own tombstone.
    tracker.markDeleted("other.scope", TOMB, "local-delete");
    await expect(tracker.resolve("other.scope")).resolves.toMatchObject({
      deleted: true,
      source: "local-delete",
    });
  });

  it("trusts a fresh feed pass for local hits and asks the gateway once it is stale", async () => {
    const { tracker, getDataPoint, advance } = makeTracker({
      remote: record(),
      maxStalenessMs: 1_000,
    });
    tracker.noteFeedSynced();

    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: false,
      source: "feed",
      verified: true,
    });
    expect(getDataPoint).not.toHaveBeenCalled();
    expect(tracker.feedAgeMs()).toBe(0);

    advance(1_001);
    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: false,
      source: "gateway",
      verified: true,
    });
    expect(getDataPoint).toHaveBeenCalledTimes(1);

    // The per-scope live verdict is cached for maxStalenessMs.
    await tracker.resolve(SCOPE);
    expect(getDataPoint).toHaveBeenCalledTimes(1);
    advance(1_001);
    await tracker.resolve(SCOPE);
    expect(getDataPoint).toHaveBeenCalledTimes(2);
  });

  it("consults the gateway for a local miss even when the feed is fresh", async () => {
    const { tracker, getDataPoint } = makeTracker({
      remote: record({ deletedAt: DELETED_AT }),
    });
    tracker.noteFeedSynced();

    await expect(
      tracker.resolve(SCOPE, { consultGateway: "always" }),
    ).resolves.toEqual({
      deleted: true,
      deletedAt: DELETED_AT,
      version: "3",
      source: "gateway",
      verified: true,
    });
    expect(getDataPoint).toHaveBeenCalledWith({
      ownerAddress: OWNER,
      scope: SCOPE,
    });
    // A gateway verdict is remembered: the next read needs no lookup.
    await tracker.resolve(SCOPE, { consultGateway: "always" });
    expect(getDataPoint).toHaveBeenCalledTimes(1);
  });

  it("recognises a tombstone row by its hash pair when the gateway omits deletedAt", async () => {
    const { tracker } = makeTracker({
      remote: record({
        dataHash: TOMBSTONE_DATA_HASH,
        metadataHash: TOMBSTONE_METADATA_HASH,
        addedAt: DELETED_AT,
      }),
    });

    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: true,
      deletedAt: DELETED_AT,
    });
  });

  it("serves last known state and backs off when the gateway is unreachable", async () => {
    const { tracker, getDataPoint, logger, advance } = makeTracker({
      remote: new Error("ECONNREFUSED"),
      gatewayRetryMs: 5_000,
    });

    await expect(tracker.resolve(SCOPE)).resolves.toEqual({
      deleted: false,
      source: "assumed-live",
      verified: false,
    });
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE, error: "ECONNREFUSED" }),
      expect.any(String),
    );

    // Inside the retry window every read is answered without a lookup.
    await tracker.resolve("other.scope");
    expect(getDataPoint).toHaveBeenCalledTimes(1);

    advance(5_000);
    await tracker.resolve("other.scope");
    expect(getDataPoint).toHaveBeenCalledTimes(2);

    // A known tombstone is still refused while offline.
    tracker.markDeleted(SCOPE, TOMB);
    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: true,
    });
  });

  it("re-validates a tombstone once it is older than maxStalenessMs, so a remote re-add is picked up", async () => {
    // Delete on this replica, then a re-add on another replica while sync
    // is off: the registry row is live again at a later version.
    const { tracker, getDataPoint, advance } = makeTracker({
      remote: record({ expectedVersion: "5" }),
      maxStalenessMs: 1_000,
    });
    tracker.markDeleted(SCOPE, TOMB, "local-delete");

    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: true,
      verified: true,
    });
    expect(getDataPoint).not.toHaveBeenCalled();

    advance(1_001);
    await expect(tracker.resolve(SCOPE)).resolves.toEqual({
      deleted: false,
      source: "gateway",
      verified: true,
    });
    expect(getDataPoint).toHaveBeenCalledTimes(1);
    expect(tracker.knownDeletion(SCOPE)).toBeNull();
  });

  it("keeps refusing a stale tombstone when the re-check cannot reach the gateway", async () => {
    const { tracker, getDataPoint, advance } = makeTracker({
      remote: new Error("ECONNREFUSED"),
      maxStalenessMs: 1_000,
      gatewayRetryMs: 500,
    });
    tracker.markDeleted(SCOPE, TOMB);
    advance(1_001);

    await expect(tracker.resolve(SCOPE)).resolves.toEqual({
      deleted: true,
      deletedAt: DELETED_AT,
      version: "3",
      source: "feed",
      verified: false,
    });
    expect(getDataPoint).toHaveBeenCalledTimes(1);
    // Inside the back-off the stale tombstone is still served, no lookup.
    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: true,
      verified: false,
    });
    expect(getDataPoint).toHaveBeenCalledTimes(1);
  });

  it("treats a complete feed pass as re-validation of every remembered tombstone", async () => {
    const { tracker, getDataPoint, advance } = makeTracker({
      remote: record(),
      maxStalenessMs: 1_000,
    });
    tracker.markDeleted(SCOPE, TOMB);
    advance(900);
    // The pass listed no live row for SCOPE (else markLive would have run).
    tracker.noteFeedSynced();
    advance(900);

    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: true,
      verified: true,
    });
    expect(getDataPoint).not.toHaveBeenCalled();
  });

  it("is assumed-live without a feed or owner to ask", async () => {
    const noOwner = makeTracker({ remote: record(), owner: undefined });
    await expect(noOwner.tracker.resolve(SCOPE)).resolves.toEqual({
      deleted: false,
      source: "assumed-live",
      verified: false,
    });
    expect(noOwner.getDataPoint).not.toHaveBeenCalled();

    const bare = createScopeDeletionTracker();
    await expect(bare.resolve(SCOPE)).resolves.toMatchObject({
      deleted: false,
      verified: false,
    });
  });

  it("forgets a tombstone once the scope is live again (re-add)", async () => {
    const { tracker, getDataPoint } = makeTracker({ remote: record() });
    tracker.markDeleted(SCOPE, TOMB);
    tracker.markLive(SCOPE);

    expect(tracker.knownDeletion(SCOPE)).toBeNull();
    await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
      deleted: false,
      verified: true,
    });
    expect(getDataPoint).not.toHaveBeenCalled();
  });

  it("coalesces concurrent lookups of one scope into a single request", async () => {
    const { tracker, getDataPoint } = makeTracker({ remote: record() });

    const verdicts = await Promise.all([
      tracker.resolve(SCOPE),
      tracker.resolve(SCOPE),
      tracker.resolve(SCOPE),
    ]);

    expect(getDataPoint).toHaveBeenCalledTimes(1);
    expect(verdicts.every((verdict) => verdict.deleted === false)).toBe(true);
  });

  it("bounds the number of remembered live verdicts", async () => {
    const { tracker, getDataPoint } = makeTracker({
      remote: record(),
      maxLiveEntries: 2,
    });

    await tracker.resolve("a.one");
    await tracker.resolve("a.two");
    await tracker.resolve("a.three");
    expect(getDataPoint).toHaveBeenCalledTimes(3);

    // The oldest verdict was evicted; the newest two are still cached.
    await tracker.resolve("a.one");
    expect(getDataPoint).toHaveBeenCalledTimes(4);
    await tracker.resolve("a.three");
    expect(getDataPoint).toHaveBeenCalledTimes(4);
  });
});

describe("deletion helpers", () => {
  it("isEntryCoveredByTombstone decides by registry version and ingest marker, never by clocks", () => {
    const tombstone = { version: "4" };
    // Synced rows: covered at or below the tombstone version.
    expect(
      isEntryCoveredByTombstone({ version: 4, dataPointId: "0xdp" }, tombstone),
    ).toBe(true);
    expect(
      isEntryCoveredByTombstone({ version: 5, dataPointId: "0xdp" }, tombstone),
    ).toBe(false);
    // Unsynced rows: covered unless ingested on top of this tombstone (or a
    // later one), whatever their local version or wall-clock stamp says.
    expect(
      isEntryCoveredByTombstone({ version: 9, dataPointId: null }, tombstone),
    ).toBe(true);
    expect(
      isEntryCoveredByTombstone(
        { version: 9, dataPointId: null, afterTombstoneVersion: null },
        tombstone,
      ),
    ).toBe(true);
    expect(
      isEntryCoveredByTombstone(
        { version: 1, dataPointId: null, afterTombstoneVersion: 3 },
        tombstone,
      ),
    ).toBe(true);
    expect(
      isEntryCoveredByTombstone(
        { version: 1, dataPointId: null, afterTombstoneVersion: 4 },
        tombstone,
      ),
    ).toBe(false);
    expect(
      isEntryCoveredByTombstone(
        { version: 1, dataPointId: null, afterTombstoneVersion: 7 },
        tombstone,
      ),
    ).toBe(false);
    // Unknown tombstone version covers everything.
    expect(
      isEntryCoveredByTombstone(
        { version: 1, dataPointId: null, afterTombstoneVersion: 9 },
        { version: null },
      ),
    ).toBe(true);
  });

  it("tombstoneVersion normalises the registry version and rejects the synthesised 0", () => {
    expect(tombstoneVersion(null)).toBeNull();
    expect(tombstoneVersion({ expectedVersion: "0" })).toBeNull();
    expect(tombstoneVersion({ expectedVersion: "007" })).toBe("7");
    expect(tombstoneVersion({ expectedVersion: "x" })).toBeNull();
    expect(tombstoneVersion({ expectedVersion: "18446744073709551617" })).toBe(
      "18446744073709551617",
    );
  });

  it("deletionTimestamp prefers deletedAt, falls back to the tombstone hash pair, else null", () => {
    expect(deletionTimestamp(null)).toBeNull();
    expect(deletionTimestamp(record())).toBeNull();
    expect(deletionTimestamp(record({ deletedAt: DELETED_AT }))).toBe(
      DELETED_AT,
    );
    expect(
      deletionTimestamp(
        record({
          dataHash: TOMBSTONE_DATA_HASH,
          metadataHash: TOMBSTONE_METADATA_HASH,
          addedAt: DELETED_AT,
        }),
      ),
    ).toBe(DELETED_AT);
    // A plain SDK record without the deletedAt field at all.
    const { deletedAt: _ignored, ...sdkRecord } = record();
    expect(deletionTimestamp(sdkRecord)).toBeNull();
  });
});
