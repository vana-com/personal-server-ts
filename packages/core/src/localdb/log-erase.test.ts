import { describe, expect, it } from "vitest";
import {
  LOG_FORMAT,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  digestSegment,
  digestSnapshotPart,
  encodeSegment,
  encodeSnapshotPart,
  logScope,
  parseScope,
  segmentBlobName,
  type ControlRead,
  type LogStreamMeta,
  type SegmentRef,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import {
  eraseDeletedConnectionLogs,
  type LogErasureDeps,
} from "./log-erase.js";

const keccak = keccakOf(undefined);
const keys = {
  namespaceHmac: async () => new Uint8Array(32).fill(7),
  decrypt: async (_scope: string, bytes: Uint8Array) => bytes,
};
const keyCheck = await deriveKeyCheck(keys.namespaceHmac);
const hashes = await controlHashes(keccak, keyCheck);

const NS = "00000000000000aa";
const OTHER_NS = "00000000000000bb";
const meta: LogStreamMeta = {
  stream: "s",
  primaryKey: ["id"],
  profile: { key: null, version: "1" },
  complete: true,
};
const hex64 = (n: number) => n.toString(16).padStart(64, "0");

/** A body piece named by `n`, as an upsert that carries it out of line. */
const upsertWithPieces = (...pieces: number[]): WireOperation[] =>
  pieces.map((n) => ({
    kind: "upsert-ref" as const,
    stream: "s",
    pkHash: hex64(1000 + n),
    stamp: { o: 1, r: "r" },
    firstSeen: null,
    body: {
      sha256: hex64(n),
      bytes: 1,
      pieces: [`0x${hex64(n)}` as const],
    },
  }));

/**
 * An in-memory world: the registry's control and log rows, its version
 * inventory, storage, and an owner-signed delete that can be made to fail.
 */
function world() {
  const store = new Map<string, Uint8Array>();
  const reads = new Map<string, ControlRead>();
  const inventory = new Map<string, { version: number; dataHash: string }[]>();
  const calls: string[][] = [];
  const failing = new Set<string>();
  let finalized: string | null = "99";
  let rolledBack: unknown = null;
  const hooks: { afterDelete?: (batchNo: number) => Promise<void> } = {};
  const logger = { info() {}, warn() {} };

  const setControl = (
    connector: string,
    ns: string,
    version: number,
    deleted: boolean,
  ) =>
    reads.set(controlScope(connector, ns), {
      found: true,
      version,
      dataHash: deleted ? hashes.tombstoneData : hashes.activeData,
      metadataHash: deleted ? hashes.tombstoneMetadata : hashes.activeMetadata,
      deleted,
    });

  const put = (scope: string, name: string, bytes = new Uint8Array([1])) =>
    store.set(`${scope}/${name}`, bytes);

  /** Put one segment of the log at `position` and move the log row to it. */
  async function segment(
    connector: string,
    ns: string,
    s: {
      position: number;
      generation?: number;
      base?: number;
      refs?: SegmentRef[];
      snapshotParts?: { dataHash: `0x${string}`; bytes: number }[];
      pieces?: number[];
      keyCheck?: string;
    },
  ): Promise<SegmentRef> {
    const scope = logScope(connector, ns);
    const base = s.base ?? 0;
    const clear = encodeSegment({
      format: LOG_FORMAT,
      connector,
      ns,
      generation: s.generation ?? 1,
      keyCheck: s.keyCheck ?? keyCheck,
      position: s.position,
      observedAt: 1,
      base,
      snapshot: s.snapshotParts
        ? { position: base, parts: s.snapshotParts }
        : null,
      refs: s.refs ?? [],
      streams: [meta],
      operations: upsertWithPieces(...(s.pieces ?? [])),
    });
    const { dataHash, blobName } = await digestSegment(keccak, clear);
    put(scope, blobName, clear);
    for (const n of s.pieces ?? []) put(scope, `v-${hex64(n)}`);
    const list = inventory.get(scope) ?? [];
    list.push({ version: s.position, dataHash });
    inventory.set(scope, list);
    reads.set(scope, {
      found: true,
      version: s.position,
      dataHash,
      metadataHash: hashes.activeMetadata,
      deleted: false,
    });
    return { position: s.position, dataHash, bytes: clear.length };
  }

  async function part(
    connector: string,
    ns: string,
    p: { position: number; pieces: number[] },
  ) {
    const scope = logScope(connector, ns);
    const clear = encodeSnapshotPart({
      format: LOG_FORMAT,
      connector,
      ns,
      generation: 1,
      keyCheck,
      position: p.position,
      index: 0,
      streams: [meta],
      entries: upsertWithPieces(...p.pieces) as never,
    });
    const { dataHash, blobName } = await digestSnapshotPart(keccak, clear);
    put(scope, blobName, clear);
    for (const n of p.pieces) put(scope, `v-${hex64(n)}`);
    return { dataHash: dataHash as `0x${string}`, bytes: clear.length };
  }

  /**
   * One connection's log: segments 1 and 2, a compaction at 2 into a part
   * (holding the piece `c`), segments 3 and 4 above it. Pieces a, b, d on the
   * segments.
   */
  async function compactedLog(connector: string, ns: string, tag = 0) {
    const [a, b, c, d] = [tag + 1, tag + 2, tag + 3, tag + 4];
    const s1 = await segment(connector, ns, { position: 1, pieces: [a] });
    const s2 = await segment(connector, ns, {
      position: 2,
      refs: [s1],
      pieces: [b],
    });
    const parts = [await part(connector, ns, { position: 2, pieces: [c] })];
    const s3 = await segment(connector, ns, {
      position: 3,
      base: 2,
      snapshotParts: parts,
      pieces: [d],
    });
    await segment(connector, ns, {
      position: 4,
      base: 2,
      snapshotParts: parts,
      refs: [s3],
    });
    void s2;
    return `${logScope(connector, ns)}/`;
  }

  const deps: LogErasureDeps = {
    registry: {
      read: async (scope) => reads.get(scope) ?? { found: false },
      listControlRows: async () =>
        [...reads]
          .filter(([scope]) => parseScope(scope)?.kind === "control")
          .map(([scope, read]) => ({ scope, read })),
    },
    versions: {
      list: async (scope) => ({
        complete: true,
        versions: (inventory.get(scope) ?? []).map((v) => ({
          expectedVersion: String(v.version),
          dataHash: v.dataHash,
          isTombstone: false,
        })),
      }),
    },
    finality: {
      tombstoneState: async () => ({ finalized, rolledBack }),
    },
    blobs: { get: async (key) => store.get(key) ?? null },
    keys,
    objects: {
      deleteBlobVersions: async (scope, names) => {
        calls.push([...names]);
        const out = {
          deleted: [] as string[],
          missing: [] as string[],
          failed: [] as { version: string; error: string }[],
        };
        for (const name of names) {
          if (failing.has(name)) {
            out.failed.push({ version: name, error: "503" });
          } else if (store.delete(`${scope}/${name}`)) out.deleted.push(name);
          else out.missing.push(name);
        }
        await hooks.afterDelete?.(calls.length - 1);
        return out;
      },
    },
    logger,
  };

  return {
    store,
    reads,
    calls,
    failing,
    hooks,
    deps,
    setControl,
    segment,
    part,
    compactedLog,
    put,
    setFinality(f: string | null, r: unknown = null) {
      finalized = f;
      rolledBack = r;
    },
    /** The names of every object stored under a log scope. */
    objects(connector: string, ns: string) {
      const prefix = `${logScope(connector, ns)}/`;
      return [...store.keys()]
        .filter((key) => key.startsWith(prefix))
        .map((key) => key.slice(prefix.length));
    },
  };
}

describe("eraseDeletedConnectionLogs", () => {
  it("deletes every segment, part and piece of a deleted connection and nothing of another", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    await w.compactedLog("alpha", OTHER_NS, 10);
    await w.compactedLog("beta", NS, 20);
    w.setControl("alpha", NS, 2, true);
    w.setControl("alpha", OTHER_NS, 1, false);
    w.setControl("beta", NS, 1, false);
    // 4 segments + 1 part + 4 pieces (a, b, c, d).
    expect(w.objects("alpha", NS)).toHaveLength(9);

    const report = await eraseDeletedConnectionLogs(w.deps, {
      connector: "alpha",
    });

    expect(w.objects("alpha", NS)).toEqual([]);
    expect(w.objects("alpha", OTHER_NS)).toHaveLength(9);
    expect(w.objects("beta", NS)).toHaveLength(9);
    expect(report.pending).toBe(false);
    expect(report.connections).toEqual([
      {
        connector: "alpha",
        ns: NS,
        outcome: { kind: "erased", deleted: 9, unenumerated: 0 },
      },
    ]);
  });

  it("leaves a connection that is not deleted alone, whatever the filter", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 1, false);
    const report = await eraseDeletedConnectionLogs(w.deps);
    expect(report.connections).toEqual([]);
    expect(w.calls).toEqual([]);
    expect(w.objects("alpha", NS)).toHaveLength(9);
  });

  it("deletes pieces, then parts, then segments, and the newest segment last", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 2, true);
    const scope = logScope("alpha", NS);
    const head = (w.reads.get(scope) as { dataHash: string }).dataHash;

    await eraseDeletedConnectionLogs(w.deps);

    const kinds = w.calls.flat().map((name) => name[0]);
    expect(kinds).toEqual(["v", "v", "v", "v", "q", "s", "s", "s", "s"]);
    expect(w.calls.at(-1)).toEqual([`s-${head.slice(2)}`]);
  });

  it("waits for the control tombstone to be final, and deletes nothing before", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 2, true);
    w.setFinality(null);

    const waiting = await eraseDeletedConnectionLogs(w.deps);
    expect(waiting.pending).toBe(true);
    expect(waiting.connections[0]!.outcome).toEqual({
      kind: "pending",
      why: "finality",
    });
    expect(w.calls).toEqual([]);

    w.setFinality("2");
    const done = await eraseDeletedConnectionLogs(w.deps);
    expect(done.pending).toBe(false);
    expect(w.objects("alpha", NS)).toEqual([]);
  });

  it("erases nothing of a tombstone the gateway rolled back", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 2, true);
    w.setFinality(null, { tombstoneVersion: "2" });
    const report = await eraseDeletedConnectionLogs(w.deps);
    expect(report.connections[0]!.outcome).toEqual({
      kind: "stopped",
      why: "rolled-back",
    });
    expect(w.calls).toEqual([]);
  });

  describe("a re-add of the same connection", () => {
    /**
     * The re-add commits the control row again (version 3) and a segment of the
     * new lifetime at the next log position, and re-collects a record whose
     * body piece has the same name as one of the old lifetime's.
     */
    async function reAdd(w: ReturnType<typeof world>, sharedPiece: number) {
      w.setControl("alpha", NS, 3, false);
      const scope = logScope("alpha", NS);
      const old = w.reads.get(scope) as { version: number };
      await w.segment("alpha", NS, {
        position: old.version + 1,
        generation: 2,
        base: old.version,
        pieces: [sharedPiece],
      });
    }

    it("is not erased when it lands before the pass starts", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      await reAdd(w, 1);
      const before = [...w.store.keys()].sort();
      const report = await eraseDeletedConnectionLogs(w.deps);
      expect(report.connections).toEqual([]);
      expect([...w.store.keys()].sort()).toEqual(before);
    });

    it("is not erased when it lands while the inventory is read", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const list = w.deps.versions.list;
      let reAdded = false;
      const deps: LogErasureDeps = {
        ...w.deps,
        versions: {
          list: async (scope, options) => {
            const listed = await list(scope, options);
            if (!reAdded) {
              reAdded = true;
              await reAdd(w, 1);
            }
            return listed;
          },
        },
      };
      const report = await eraseDeletedConnectionLogs(deps);
      expect(report.connections[0]!.outcome).toEqual({
        kind: "stopped",
        why: "re-added",
      });
      expect(w.calls).toEqual([]);
      // The new lifetime's segment and the piece it shares with the old one.
      expect(w.objects("alpha", NS)).toContain(`v-${hex64(1)}`);
      expect(w.objects("alpha", NS)).toHaveLength(10);
    });

    it("keeps the piece it shares with the erased lifetime when it lands between two batches", async () => {
      const w = world();
      // 20 pieces on one segment: two batches of pieces (15, then 5).
      const pieces = Array.from({ length: 20 }, (_, i) => i + 1);
      await w.segment("alpha", NS, { position: 1, pieces });
      w.setControl("alpha", NS, 2, true);
      // The new lifetime re-collects the record of piece 20 (second batch),
      // right after the first batch is deleted.
      w.hooks.afterDelete = async (batchNo) => {
        if (batchNo === 0) await reAdd(w, 20);
      };

      const report = await eraseDeletedConnectionLogs(w.deps);

      expect(report.connections[0]!.outcome).toEqual({
        kind: "stopped",
        why: "re-added",
      });
      expect(w.objects("alpha", NS)).toContain(`v-${hex64(20)}`);
      // Only the first batch (pieces 1-15) was sent.
      expect(w.calls).toHaveLength(1);
      expect(w.calls[0]).toHaveLength(15);
    });
  });

  describe("failure and retry", () => {
    it("stops at the first failed batch, keeps the segments that name what is left, and a repeat finishes", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const part = w
        .objects("alpha", NS)
        .find((name) => name.startsWith("q-"))!;
      w.failing.add(part);

      const first = await eraseDeletedConnectionLogs(w.deps);

      expect(first.pending).toBe(true);
      expect(first.connections[0]!.outcome).toMatchObject({
        kind: "pending",
        why: "storage",
      });
      // Pieces are gone; the part failed; every segment is still there.
      expect(w.objects("alpha", NS).filter((n) => n[0] === "v")).toEqual([]);
      expect(w.objects("alpha", NS).filter((n) => n[0] === "s")).toHaveLength(
        4,
      );

      w.failing.clear();
      const second = await eraseDeletedConnectionLogs(w.deps);
      expect(second.pending).toBe(false);
      expect(w.objects("alpha", NS)).toEqual([]);
    });

    it("a failed segment delete never reaches the newest segment, and a repeat finds every object again", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const segments = w.objects("alpha", NS).filter((n) => n[0] === "s");
      const head = `s-${(w.reads.get(logScope("alpha", NS)) as { dataHash: string }).dataHash.slice(2)}`;
      const other = segments.find((n) => n !== head)!;
      w.failing.add(other);

      await eraseDeletedConnectionLogs(w.deps);
      expect(w.objects("alpha", NS)).toContain(head);
      expect(w.objects("alpha", NS)).toContain(other);

      w.failing.clear();
      // A new pass with nothing remembered: a restart.
      const report = await eraseDeletedConnectionLogs({ ...w.deps });
      expect(report.pending).toBe(false);
      expect(w.objects("alpha", NS)).toEqual([]);
    });

    it("a delete that throws is a failed batch, not a failed pass", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const deps: LogErasureDeps = {
        ...w.deps,
        objects: {
          deleteBlobVersions: async () => {
            throw new Error("offline");
          },
        },
      };
      const report = await eraseDeletedConnectionLogs(deps);
      expect(report.connections[0]!.outcome).toMatchObject({
        kind: "pending",
        why: "storage",
      });
      expect(w.objects("alpha", NS)).toHaveLength(9);
    });

    it("an object storage already lacks (404) counts as deleted", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      // The pieces went in an earlier pass that stopped.
      for (const name of w.objects("alpha", NS))
        if (name[0] === "v") w.store.delete(`${logScope("alpha", NS)}/${name}`);

      const report = await eraseDeletedConnectionLogs(w.deps);

      expect(report.pending).toBe(false);
      expect(w.objects("alpha", NS)).toEqual([]);
    });

    it("a verified complete pass remains erased without further deletes", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const first = await eraseDeletedConnectionLogs(w.deps);
      expect(first.connections[0]!.outcome).toEqual({
        kind: "erased",
        deleted: 9,
        unenumerated: 0,
      });
      w.calls.length = 0;
      let inventories = 0;
      const original = w.deps.versions;
      const again = await eraseDeletedConnectionLogs({
        ...w.deps,
        versions: {
          list: async (scope, options) => {
            inventories += 1;
            return original.list(scope, options);
          },
        },
      });
      expect(inventories).toBe(1);

      expect(again.connections[0]!.outcome).toEqual({
        kind: "erased",
        deleted: 0,
        unenumerated: 0,
      });
      expect(w.calls).toEqual([]);
    });

    it("a registry that cannot list the deleted connections is pending, not a throw", async () => {
      const w = world();
      const deps: LogErasureDeps = {
        ...w.deps,
        registry: {
          ...w.deps.registry,
          listControlRows: async () => {
            throw new Error("gateway down");
          },
        },
      };
      await expect(eraseDeletedConnectionLogs(deps)).resolves.toEqual({
        connections: [],
        pending: true,
      });
    });
  });

  it("keeps discovery objects until the complete inventory is readable", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 2, true);
    const scope = logScope("alpha", NS);
    const before = w.objects("alpha", NS);
    const incomplete = await eraseDeletedConnectionLogs({
      ...w.deps,
      versions: { list: async () => ({ complete: false, versions: [] }) },
    });
    expect(incomplete.connections[0]!.outcome).toMatchObject({
      kind: "pending",
      why: "inventory",
    });
    expect(w.calls).toEqual([]);
    expect(w.objects("alpha", NS)).toEqual(before);

    const part = before.find((n) => n[0] === "q")!;
    const bytes = w.store.get(`${scope}/${part}`)!;
    w.store.set(`${scope}/${part}`, new TextEncoder().encode("not json"));
    const unreadable = await eraseDeletedConnectionLogs(w.deps);
    expect(unreadable.connections[0]!.outcome).toMatchObject({
      kind: "pending",
      why: "inventory",
    });
    expect(w.calls).toEqual([]);
    expect(w.objects("alpha", NS)).toEqual(before);

    w.store.set(`${scope}/${part}`, bytes);
    const readable = await eraseDeletedConnectionLogs(w.deps);
    expect(readable.connections[0]!.outcome).toEqual({
      kind: "erased",
      deleted: before.length,
      unenumerated: 0,
    });
  });

  it("keeps listed segments when the head is unavailable", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 2, true);
    const scope = logScope("alpha", NS);
    const current = await w.deps.registry.read(scope);
    if (!current.found) throw new Error("fixture expected a log head");
    const head = `${scope}/s-${current.dataHash.replace(/^0x/, "")}`;
    const before = w.objects("alpha", NS);
    const report = await eraseDeletedConnectionLogs({
      ...w.deps,
      blobs: {
        get: async (name) => (name === head ? null : w.deps.blobs.get(name)),
      },
    });
    expect(report.connections[0]!.outcome).toMatchObject({
      kind: "pending",
      why: "inventory",
    });
    expect(w.calls).toEqual([]);
    expect(w.objects("alpha", NS)).toEqual(before);
  });

  it("does not advance a phase without every requested name acknowledged", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    w.setControl("alpha", NS, 2, true);
    const before = w.objects("alpha", NS);
    const batches: string[][] = [];
    const partial = await eraseDeletedConnectionLogs({
      ...w.deps,
      objects: {
        deleteBlobVersions: async (scope, names) => {
          batches.push([...names]);
          return w.deps.objects.deleteBlobVersions(scope, names.slice(0, -1));
        },
      },
    });
    expect(partial.connections[0]!.outcome).toMatchObject({
      kind: "pending",
      why: "storage",
    });
    expect(batches).toHaveLength(1);
    expect(batches[0]!.every((name) => name.startsWith("v-"))).toBe(true);
    expect(
      w.objects("alpha", NS).filter((name) => !name.startsWith("v-")),
    ).toEqual(before.filter((name) => !name.startsWith("v-")));
  });

  it("does not delete a log whose newest segment is not under this key", async () => {
    const w = world();
    await w.compactedLog("alpha", NS);
    // Replace the log's head with a segment another key wrote.
    const scope = logScope("alpha", NS);
    await w.segment("alpha", NS, {
      position: 5,
      base: 4,
      keyCheck: "0000000000000001",
    });
    void scope;
    w.setControl("alpha", NS, 2, true);
    const report = await eraseDeletedConnectionLogs(w.deps);
    expect(report.connections[0]!.outcome).toEqual({
      kind: "stopped",
      why: "head-unreadable",
    });
    expect(w.calls).toEqual([]);
  });
});

/** A well-formed segment of this key and log, built to be served under another name. */
const forgedSegment = (connector: string, ns: string, pieces: number[]) =>
  encodeSegment({
    format: LOG_FORMAT,
    connector,
    ns,
    generation: 1,
    keyCheck,
    position: 1,
    observedAt: 1,
    base: 0,
    snapshot: null,
    refs: [],
    streams: [meta],
    operations: upsertWithPieces(...pieces),
  });

const forgedPart = (connector: string, ns: string, pieces: number[]) =>
  encodeSnapshotPart({
    format: LOG_FORMAT,
    connector,
    ns,
    generation: 1,
    keyCheck,
    position: 2,
    index: 0,
    streams: [meta],
    entries: upsertWithPieces(...pieces) as never,
  });

describe("what the erasure refuses to act on", () => {
  describe("a tombstone that is not final at the version being erased", () => {
    it("deletes nothing when the finalized version is below the tombstone", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 5, true);
      const before = w.objects("alpha", NS);
      // A newer tombstone (5) is still settling; the adapter reports 4.
      w.setFinality("4");
      const report = await eraseDeletedConnectionLogs(w.deps);
      expect(report.connections[0]!.outcome).toEqual({
        kind: "pending",
        why: "finality",
      });
      expect(w.calls).toEqual([]);
      expect(w.objects("alpha", NS)).toEqual(before);
    });

    it("deletes nothing when the finalized version is not a version", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 5, true);
      w.setFinality("final");
      const report = await eraseDeletedConnectionLogs(w.deps);
      expect(report.connections[0]!.outcome).toMatchObject({
        kind: "pending",
        why: "finality",
      });
      expect(w.calls).toEqual([]);
    });

    it.each(["5", "6"])(
      "erases once the finalized version is %s, at or above the tombstone",
      async (finalized) => {
        const w = world();
        await w.compactedLog("alpha", NS);
        w.setControl("alpha", NS, 5, true);
        w.setFinality(finalized);
        const report = await eraseDeletedConnectionLogs(w.deps);
        expect(report.connections[0]!.outcome).toMatchObject({
          kind: "erased",
        });
        expect(w.objects("alpha", NS)).toEqual([]);
      },
    );
  });

  describe("a log whose newest segment cannot be found", () => {
    /** Two ways the head is absent: gone from storage, or no log row at all. */
    const absent = {
      "the head object is gone from storage": (
        w: ReturnType<typeof world>,
        scope: string,
      ) => {
        const row = w.reads.get(scope);
        if (!row?.found) throw new Error("fixture expected a log head");
        w.store.delete(`${scope}/s-${row.dataHash.replace(/^0x/, "")}`);
      },
      "the registry has no log row": (
        w: ReturnType<typeof world>,
        scope: string,
      ) => {
        w.reads.delete(scope);
      },
    };
    it.each(Object.entries(absent))(
      "is not erased while an older segment that names a body piece survives (%s)",
      async (_name, lose) => {
        const w = world();
        await w.compactedLog("alpha", NS);
        w.setControl("alpha", NS, 2, true);
        const scope = logScope("alpha", NS);
        lose(w, scope);
        const surviving = w.objects("alpha", NS);
        // Segment 1 names piece 1; it is still in storage.
        expect(surviving).toContain(`v-${hex64(1)}`);
        expect(
          surviving.filter((n) => n.startsWith("s-")).length,
        ).toBeGreaterThan(0);

        const report = await eraseDeletedConnectionLogs(w.deps);

        expect(report.connections[0]!.outcome).toMatchObject({
          kind: "pending",
          why: "inventory",
        });
        expect(report.pending).toBe(true);
        expect(w.calls).toEqual([]);
        expect(w.objects("alpha", NS)).toEqual(surviving);
      },
    );
  });

  describe("an object served under a name its bytes do not hash to", () => {
    const FOREIGN_PIECE = 99;
    const hashOfPosition = async (
      w: ReturnType<typeof world>,
      scope: string,
      position: number,
    ) => {
      const listed = await w.deps.versions.list(scope);
      return listed.versions.find(
        (v) => Number(v.expectedVersion) === position,
      )!.dataHash;
    };

    it("does not report a log erased when an older segment is another's bytes, and deletes nothing it names", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const scope = logScope("alpha", NS);
      // A valid segment of this key and log, under the name of segment 1.
      const name = segmentBlobName(await hashOfPosition(w, scope, 1));
      w.store.set(
        `${scope}/${name}`,
        forgedSegment("alpha", NS, [FOREIGN_PIECE]),
      );
      w.put(scope, `v-${hex64(FOREIGN_PIECE)}`);
      const before = w.objects("alpha", NS);

      const report = await eraseDeletedConnectionLogs(w.deps);

      expect(report.connections[0]!.outcome).toMatchObject({
        kind: "pending",
        why: "inventory",
      });
      expect(w.calls).toEqual([]);
      expect(w.objects("alpha", NS)).toEqual(before);
    });

    it("does not report a log erased when the newest segment is another's bytes", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const scope = logScope("alpha", NS);
      const name = segmentBlobName(await hashOfPosition(w, scope, 4));
      w.store.set(
        `${scope}/${name}`,
        forgedSegment("alpha", NS, [FOREIGN_PIECE]),
      );
      w.put(scope, `v-${hex64(FOREIGN_PIECE)}`);
      const before = w.objects("alpha", NS);

      const report = await eraseDeletedConnectionLogs(w.deps);

      expect(report.connections[0]!.outcome).toEqual({
        kind: "stopped",
        why: "head-unreadable",
      });
      expect(w.calls).toEqual([]);
      expect(w.objects("alpha", NS)).toEqual(before);
    });

    it("does not report a log erased when a snapshot part is another's bytes, and deletes nothing it names", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const scope = logScope("alpha", NS);
      const partName = w.objects("alpha", NS).find((n) => n.startsWith("q-"))!;
      w.store.set(
        `${scope}/${partName}`,
        forgedPart("alpha", NS, [FOREIGN_PIECE]),
      );
      w.put(scope, `v-${hex64(FOREIGN_PIECE)}`);
      const before = w.objects("alpha", NS);

      const report = await eraseDeletedConnectionLogs(w.deps);

      expect(report.connections[0]!.outcome).toMatchObject({
        kind: "pending",
        why: "inventory",
      });
      expect(w.calls).toEqual([]);
      expect(w.objects("alpha", NS)).toEqual(before);
    });

    it("does not hide a descendant: a segment served under the head's name cannot make the real refs unreachable", async () => {
      const w = world();
      await w.compactedLog("alpha", NS);
      w.setControl("alpha", NS, 2, true);
      const scope = logScope("alpha", NS);
      // The head's name serves a valid segment with no refs and no pieces.
      const name = segmentBlobName(await hashOfPosition(w, scope, 4));
      w.store.set(`${scope}/${name}`, forgedSegment("alpha", NS, []));
      const report = await eraseDeletedConnectionLogs(w.deps);
      expect(report.connections[0]!.outcome.kind).not.toBe("erased");
      expect(w.calls).toEqual([]);
    });
  });

  describe("a delete answer that does not account for every name once", () => {
    const answers: Record<
      string,
      (names: string[]) => {
        deleted: string[];
        missing: string[];
        failed: never[];
      }
    > = {
      "a name acknowledged twice, another not at all": (names) => ({
        deleted: [names[0]!, names[0]!, ...names.slice(2)],
        missing: [],
        failed: [],
      }),
      "a name acknowledged as both deleted and missing": (names) => ({
        deleted: names,
        missing: [names[0]!],
        failed: [],
      }),
      "a name that was not asked for": (names) => ({
        deleted: [...names.slice(0, -1), `v-${hex64(777)}`],
        missing: [],
        failed: [],
      }),
    };
    it.each(Object.entries(answers))(
      "does not advance past %s",
      async (_name, answer) => {
        const w = world();
        await w.compactedLog("alpha", NS);
        w.setControl("alpha", NS, 2, true);
        const batches: string[][] = [];
        const report = await eraseDeletedConnectionLogs({
          ...w.deps,
          objects: {
            deleteBlobVersions: async (_scope, names) => {
              batches.push([...names]);
              return answer(names);
            },
          },
        });
        expect(report.connections[0]!.outcome).toMatchObject({
          kind: "pending",
          why: "storage",
        });
        expect(batches).toHaveLength(1);
      },
    );
  });
});
