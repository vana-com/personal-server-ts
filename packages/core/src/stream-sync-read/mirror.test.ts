import { describe, expect, it, vi } from "vitest";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import { RegistryMirror, type MirrorFeedRow } from "./mirror.js";

// Scope parsing is independent of the mirror's publication boundary.
vi.mock("@opendatalabs/personal-server-ts-stream-sync", () => ({
  parseScope: (scope: string) =>
    scope === "test-stream"
      ? {
          kind: "stream",
          connector: "test-connector",
          ns: "test-ns",
          stream: "test-stream",
        }
      : null,
}));

const page = { fromStart: false, lastPage: true } as const;
const row = (version: number): MirrorFeedRow => ({
  scope: "test-stream",
  expectedVersion: String(version),
  dataHash: "a".repeat(64),
  metadataHash: "b".repeat(64),
});

function version(mirror: RegistryMirror): number | undefined {
  return mirror
    .rowsFor("test-connector")
    .streams.get("test-ns")
    ?.get("test-stream")?.version;
}

async function fixture(listed: boolean) {
  const memory = createMemoryStreamSyncReadFiles();
  await memory.write(
    "mirror.json",
    new TextEncoder().encode(JSON.stringify({ format: 1, listed, rows: {} })),
  );
  let failNext = false;
  const files = {
    ...memory,
    write: vi.fn(async (path: string, bytes: Uint8Array) => {
      if (path === "mirror.json" && failNext) {
        failNext = false;
        throw new Error("mirror write failed");
      }
      await memory.write(path, bytes);
    }),
  };
  return {
    files,
    mirror: await RegistryMirror.open(files),
    failNextWrite: () => {
      failNext = true;
    },
  };
}

describe("RegistryMirror durable publication", () => {
  it("retries an identical page after a failed write and reports its connector", async () => {
    const { files, mirror, failNextWrite } = await fixture(true);
    const rows = [row(7)];
    failNextWrite();

    await expect(mirror.observe(rows, page)).rejects.toThrow(
      "mirror write failed",
    );
    expect(await mirror.observe(rows, page)).toEqual(["test-connector"]);
    expect(files.write).toHaveBeenCalledTimes(2);
    expect(version(mirror)).toBe(7);
    expect(version(await RegistryMirror.open(files))).toBe(7);
  });

  it("does not publish listed after a failed final full-listing page", async () => {
    const { files, mirror, failNextWrite } = await fixture(false);
    failNextWrite();

    await expect(
      mirror.observe([], { fromStart: true, lastPage: true }),
    ).rejects.toThrow("mirror write failed");

    expect(mirror.needsFullListing()).toBe(true);
    expect(mirror.wantsListingFromStart()).toBe(true);
    expect((await RegistryMirror.open(files)).needsFullListing()).toBe(true);

    expect(
      await mirror.observe([], { fromStart: true, lastPage: true }),
    ).toEqual([]);
    expect(mirror.needsFullListing()).toBe(false);
    expect((await RegistryMirror.open(files)).needsFullListing()).toBe(false);
  });

  it("does not publish rows or full-listing progress after a failed first page", async () => {
    const { files, mirror, failNextWrite } = await fixture(false);
    failNextWrite();

    await expect(
      mirror.observe([row(1)], { fromStart: true, lastPage: false }),
    ).rejects.toThrow("mirror write failed");

    expect(mirror.wantsListingFromStart()).toBe(true);
    expect(version(mirror)).toBeUndefined();
    expect(version(await RegistryMirror.open(files))).toBeUndefined();
  });

  it("raises and persists the deletion floor from a tombstone the kept row outranks, and reports the connector", async () => {
    const { files, mirror } = await fixture(true);
    expect(await mirror.observe([row(3)], page)).toEqual(["test-connector"]);

    const tombstone: MirrorFeedRow = {
      ...row(2),
      deletedAt: "2026-11-01T00:00:00.000Z",
    };
    expect(await mirror.observe([tombstone], page)).toEqual(["test-connector"]);

    expect(version(mirror)).toBe(3);
    expect(mirror.deletionFloor("test-stream")).toBe(2);
    const reopened = await RegistryMirror.open(files);
    expect(version(reopened)).toBe(3);
    expect(reopened.deletionFloor("test-stream")).toBe(2);
    expect(await mirror.observe([tombstone], page)).toEqual([]);
  });

  it("serializes overlapping writes and exposes only persisted rows", async () => {
    const memory = createMemoryStreamSyncReadFiles();
    await memory.write(
      "mirror.json",
      new TextEncoder().encode(
        JSON.stringify({ format: 1, listed: true, rows: {} }),
      ),
    );
    let releaseFirst!: () => void;
    let enteredFirst!: () => void;
    let enteredSecond!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const firstEntered = new Promise<void>((resolve) => {
      enteredFirst = resolve;
    });
    const secondEntered = new Promise<void>((resolve) => {
      enteredSecond = resolve;
    });
    let writes = 0;
    const files = {
      ...memory,
      async write(path: string, bytes: Uint8Array) {
        writes += 1;
        if (writes === 1) {
          enteredFirst();
          await firstGate;
        } else {
          enteredSecond();
        }
        await memory.write(path, bytes);
      },
    };
    const mirror = await RegistryMirror.open(files);
    const first = mirror.observe([row(1)], page);
    await firstEntered;
    const second = mirror.observe([row(2)], page);
    // Flush queue continuations without waiting for a second write to begin.
    await Promise.resolve();
    await Promise.resolve();
    const writesBeforeRelease = writes;
    const versionBeforeRelease = version(mirror);
    releaseFirst();
    const changed = await Promise.all([first, second]);
    await secondEntered;

    expect(writesBeforeRelease).toBe(1);
    expect(versionBeforeRelease).toBeUndefined();
    expect(changed).toEqual([["test-connector"], ["test-connector"]]);
    expect(version(mirror)).toBe(2);
    expect(version(await RegistryMirror.open(files))).toBe(2);
  });

  it("keeps the registry time of the delete next to its version, and none when no row gave it (DELETE_TIME)", async () => {
    const { files, mirror } = await fixture(true);
    const at = "2026-11-01T00:00:10.000Z";
    await mirror.observe([{ ...row(2), deletedAt: at, addedAt: at }], page);
    expect(mirror.deletionTime("test-stream")).toBe(Date.parse(at));
    expect((await RegistryMirror.open(files)).deletionTime("test-stream")).toBe(
      Date.parse(at),
    );

    // A tombstone row without a time gives a floor and no time.
    const bare = await fixture(true);
    await bare.mirror.observe([{ ...row(2), deletedAt: at }], page);
    expect(bare.mirror.deletionFloor("test-stream")).toBe(2);
    expect(bare.mirror.deletionTime("test-stream")).toBeNull();
  });

  it("a delete learned from a head has no time until a listed tombstone of that version gives it (HEAD_FLOOR_HAS_NO_TIME)", async () => {
    const { files, mirror } = await fixture(true);
    await mirror.recordDelete("test-stream", 2);
    expect(mirror.deletionFloor("test-stream")).toBe(2);
    expect(mirror.deletionTime("test-stream")).toBeNull();

    const at = "2026-11-01T00:00:10.000Z";
    await mirror.observe([{ ...row(2), deletedAt: at, addedAt: at }], page);
    expect(mirror.deletionTime("test-stream")).toBe(Date.parse(at));

    // A later delete replaces the version; the old time must not stay on it.
    await mirror.recordDelete("test-stream", 4);
    expect(mirror.deletionFloor("test-stream")).toBe(4);
    expect(mirror.deletionTime("test-stream")).toBeNull();
    expect(
      (await RegistryMirror.open(files)).deletionTime("test-stream"),
    ).toBeNull();
  });
});
