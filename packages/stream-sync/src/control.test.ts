import { describe, expect, it } from "vitest";
import { classifyControl, runDeletedSince, sameControl } from "./control.js";
import { InvalidArgumentError } from "./errors.js";
import { controlHashes } from "./namespace.js";
import { keccak256 } from "./test-support/ports.js";

describe("runDeletedSince", async () => {
  const hashes = await controlHashes(keccak256, "0123456789abcdef");
  const live = {
    found: true as const,
    version: 1,
    dataHash: hashes.activeData,
    metadataHash: hashes.activeMetadata,
    deleted: false,
  };
  const tombstone = {
    found: true as const,
    version: 2,
    dataHash: hashes.tombstoneData,
    metadataHash: hashes.tombstoneMetadata,
    deleted: true,
  };
  const active = { kind: "active", generation: 1 } as const;
  const deleted = { kind: "deleted", version: 2 } as const;

  it("control arm: a connection active at start and deleted now is deleted", () => {
    expect(
      runDeletedSince({ control: active }, { control: deleted, hashes }),
    ).toBe(true);
  });

  it("control arm: a run that started with the connection absent or unknown is not deleted", () => {
    expect(
      runDeletedSince(
        { control: { kind: "absent" } },
        { control: deleted, hashes },
      ),
    ).toBe(false);
    expect(
      runDeletedSince(
        { control: { kind: "unknown" } },
        { control: deleted, hashes },
      ),
    ).toBe(false);
  });

  it("stream arm: a stream row tombstoned now and not at start is deleted", () => {
    expect(
      runDeletedSince(
        { control: { kind: "unknown" }, streamTombstoned: false },
        { stream: tombstone, hashes },
      ),
    ).toBe(true);
  });

  it("stream arm: a row already a tombstone at start predates the run", () => {
    expect(
      runDeletedSince(
        { control: { kind: "unknown" }, streamTombstoned: true },
        { stream: tombstone, hashes },
      ),
    ).toBe(false);
  });

  it("stream arm: an unstamped run is not deleted by the stream row", () => {
    expect(
      runDeletedSince(
        { control: { kind: "unknown" } },
        { stream: tombstone, hashes },
      ),
    ).toBe(false);
  });

  it("a live stream row and a live control row are not deleted", () => {
    expect(
      runDeletedSince(
        { control: active, streamTombstoned: false },
        { control: active, stream: live, hashes },
      ),
    ).toBe(false);
  });
});

describe("classifyControl", async () => {
  const mine = await controlHashes(keccak256, "0123456789abcdef");
  const theirs = await controlHashes(keccak256, "fedcba9876543210");
  const row = (dataHash: string, deleted = false, version = 4) => ({
    found: true as const,
    version,
    dataHash,
    metadataHash: mine.activeMetadata,
    deleted,
  });

  it("tells own, foreign and deleted rows apart", () => {
    expect(classifyControl({ found: false }, mine)).toEqual({ kind: "absent" });
    expect(classifyControl(row(mine.activeData), mine)).toEqual({
      kind: "active",
      generation: 4,
    });
    expect(classifyControl(row(theirs.activeData), mine)).toEqual({
      kind: "foreign",
      version: 4,
    });
    expect(classifyControl(row(theirs.activeData, true), mine)).toEqual({
      kind: "deleted",
      version: 4,
    });
  });

  it("rejects a non-positive version", () => {
    expect(() => classifyControl(row(mine.activeData, false, 0), mine)).toThrow(
      InvalidArgumentError,
    );
  });

  it("compares states", () => {
    expect(
      sameControl(
        { kind: "active", generation: 1 },
        { kind: "active", generation: 1 },
      ),
    ).toBe(true);
    expect(
      sameControl(
        { kind: "deleted", version: 1 },
        { kind: "foreign", version: 1 },
      ),
    ).toBe(false);
  });
});
