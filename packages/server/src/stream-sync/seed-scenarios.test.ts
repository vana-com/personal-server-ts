import { describe, expect, it } from "vitest";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import {
  controlHashes,
  controlScope,
  decodeHead,
  deriveKeyCheck,
  linesOfParts,
  parseScope,
  partBlobName,
  streamScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  streamSyncHashes,
  StreamSyncWriter,
  type SignedRegistryPost,
  type StreamSyncFiles,
  type StreamSyncRegistry,
  type StreamSyncSeedSource,
  type StreamSyncWriterOptions,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createSeedStaging, type SeedStaging } from "./seed-staging.js";

// Extends the writer-overlay in-memory rig, without the oracle rig's HTTP store.
// oracle.test.ts M7 already covers phone-first WITH new Desktop records. Here
// the Desktop's entire run is empty. Staging/route tests already pin upload
// validation and stable install IDs, not these multi-device orderings.
// Identity encryption and a dummy signer are intentional test ports; the real
// writer, planner, head/part codecs and hash verification perform publication.
const OWNER = `0x${"11".repeat(20)}` as const;
const OTHER_OWNER = `0x${"22".repeat(20)}` as const;
const C = "seed-scenarios";
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };
// A newer connector version that changes the primary key: an empty base.
const V2_SHAPE = {
  primaryKey: ["n"],
  profile: { key: null, version: "2.0.0" },
};
type Shape = {
  readonly primaryKey: readonly string[];
  readonly profile: { readonly key: string | null; readonly version: string };
  readonly incremental?: boolean;
};
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const receipt = (install: string, stream: string) =>
  `${install}|${C}||${stream}`;
// Retained rows carry non-key data; the published values are compared whole.
type Row = {
  id: string;
  text?: string;
  n?: number;
  nested?: { tags: string[] };
};
const rich = (id: string): Row => ({
  id,
  text: `${id} text`,
  n: id.length,
  nested: { tags: [id, "retained"] },
});
const byId = (a: Row, b: Row) => (a.id < b.id ? -1 : 1);

function retained(installId: string, rows: Record<string, readonly Row[]>) {
  const reads: string[] = [];
  const source: StreamSyncSeedSource = {
    installId,
    async streams(connector) {
      return connector === C
        ? Object.keys(rows).map((stream) => ({ stream, ...SHAPE }))
        : [];
    },
    async *records(connector, stream) {
      reads.push(`${connector}/${stream}`);
      if (connector === C) for (const row of rows[stream] ?? []) yield row;
    },
  };
  return { source, reads };
}

async function fixture(generation = 1) {
  const rows = new Map<string, ControlRead>();
  const objects = new Map<string, Uint8Array>();
  const mac = async (m: Uint8Array) =>
    hmac(sha256, new Uint8Array(32).fill(4), m);
  const hashes = await controlHashes(
    streamSyncHashes.keccak256,
    await deriveKeyCheck(mac),
  );
  // Pre-existing active gen 2 is version 2. No delete/reconnect operation runs.
  rows.set(controlScope(C, ""), {
    found: true,
    version: generation,
    dataHash: hashes.activeData,
    metadataHash: hashes.activeMetadata,
    deleted: false,
  });
  let beforePost: ((request: SignedRegistryPost) => Promise<void>) | undefined;
  const registry: StreamSyncRegistry = {
    async read(scope) {
      return rows.get(scope) ?? { found: false };
    },
    async listControlRows() {
      return [...rows]
        .filter(([scope]) => parseScope(scope)?.kind === "control")
        .map(([scope, read]) => ({ scope, read }));
    },
    async listStreamRows(connector) {
      return [...rows]
        .filter(([scope]) => {
          const parsed = parseScope(scope);
          return parsed?.kind === "stream" && parsed.connector === connector;
        })
        .map(([scope, read]) => ({ scope, read }));
    },
    async post(request) {
      await beforePost?.(request);
      const old = rows.get(request.scope);
      const current = old?.found ? old.version : 0;
      const version = Number(request.expectedVersion);
      if (
        old?.found &&
        version === current &&
        old.dataHash === request.dataHash &&
        old.metadataHash === request.metadataHash
      )
        return { kind: "committed" };
      if (version !== current + 1)
        return { kind: "conflict", latestVersion: String(current) };
      rows.set(request.scope, {
        found: true,
        version,
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
        deleted: false,
      });
      return { kind: "committed" };
    },
  };
  const blobs = {
    async put(key: string, bytes: Uint8Array) {
      objects.set(key, bytes.slice());
    },
    async get(key: string) {
      return objects.get(key)?.slice() ?? null;
    },
  };
  const device = (
    seed?: StreamSyncSeedSource,
    files: StreamSyncFiles = createMemoryStreamSyncFiles(7),
    owner: typeof OWNER = OWNER,
  ) => {
    const home = bindStreamSyncHome({
      ownerAddress: owner,
      network: "test",
      open: () => files,
    });
    const open = (source = seed, fault?: StreamSyncWriterOptions["fault"]) =>
      new StreamSyncWriter({
        ownerAddress: owner,
        home,
        registry,
        blobs,
        seed: source,
        fault,
        now: () => 1000,
        keys: {
          namespaceHmac: mac,
          encrypt: async (_s, b) => b,
          encryptPart: async (_s, b) => b,
          decrypt: async (_s, b) => b,
        },
        signer: { signAddData: async () => "0x00" },
      });
    return { writer: open(), open, files };
  };
  // A third device has only readonly registry/blob ports, never a writer home,
  // outbox, retained seed source or overlay. Decode the published object graph.
  const reader = () => ({
    async read(stream: string) {
      const scope = streamScope(C, "", stream);
      const row = await registry.read(scope);
      if (!row.found) return null;
      const bytes = await blobs.get(
        `${scope}/h-${row.dataHash.replace(/^0x/, "").toLowerCase()}`,
      );
      if (!bytes) throw new Error("published head missing");
      const decoded = decodeHead(bytes);
      if (decoded.kind !== "ok")
        throw new Error(`invalid head: ${decoded.kind}`);
      const lines = [];
      // linesOfParts reads format 1 and format 2 parts alike and checks size,
      // SHA-256, key order, prefix and frame counts of every part it loads.
      for await (const line of linesOfParts(
        streamSyncHashes.sha256,
        decoded.head,
        async (part) => {
          const body = await blobs.get(
            `${scope}/${partBlobName(decoded.head.generation, part.hash)}`,
          );
          if (!body) throw new Error("published part missing");
          return body;
        },
      )) {
        lines.push(line);
      }
      const values = lines.map((line) => line.v as Row).sort(byId);
      return {
        head: decoded.head,
        lines,
        values,
        ids: values.map((row) => row.id),
      };
    },
  });
  return {
    device,
    reader,
    beforePost: (hook: NonNullable<typeof beforePost>) => {
      beforePost = hook;
    },
  };
}

let observedAt = 1000;
async function collect(
  writer: StreamSyncWriter,
  runId: string,
  streams: Record<string, readonly Row[]>,
  generation?: number,
  shape: Shape = SHAPE,
) {
  await writer.refreshControls();
  await writer.beginRun({
    runId,
    connector: C,
    observedAt: ++observedAt,
    identity: "none",
    userConnect: false,
    checkpointUsed: generation === undefined ? null : { ns: "", generation },
  });
  for (const [stream, records] of Object.entries(streams)) {
    await writer.declareStream(runId, stream, shape);
    for (const record of records) await writer.append(runId, stream, record);
  }
  await writer.finishRun(runId, { checkpointCandidate: { cursor: runId } });
}

/** Stage one upload of `rows` as the sidecar's seed route does. */
async function stageRows(
  staging: SeedStaging,
  connector: string,
  stream: string,
  rows: readonly Row[],
) {
  async function* body() {
    yield encoder.encode(
      [
        JSON.stringify({ ...SHAPE, records: rows.length }),
        ...rows.map((row) => JSON.stringify(row)),
        "",
      ].join("\n"),
    );
  }
  await staging.stage(connector, stream, body());
}

// Checked at 5ad1d563: baseline passes; each A-E mutation below independently
// produces the named assertion failure with `vitest --maxWorkers=2`, then the
// original writer is restored. Component run uses exact allowed writer/rules
// plus a publicationMetadataHash seam (not seed logic); full host run is unrun.
// The evidence artifact contains exact mutation diffs, runner and full logs.
describe("U2 retained Desktop seed scenarios (no network)", () => {
  it("a: phone-first retains Desktop-only rows with an entirely empty Desktop run", async () => {
    // Mutant A: an existing gen-1 stream head makes prepareSeed record skipped.
    const f = await fixture();
    const phone = f.device().writer;
    await collect(phone, "phone-first", { s: [{ id: "p1" }] });
    await phone.publishPending();
    const seed = retained("desktop", { s: [rich("d1")] });
    const desktop = f.device(seed.source);
    await collect(desktop.writer, "empty-desktop", {});
    await desktop.writer.publishPending();
    const third = await f.reader().read("s");
    expect(third?.ids).toEqual(["d1", "p1"]);
    expect(third?.values).toEqual([rich("d1"), { id: "p1" }]);
    expect(third?.head).toMatchObject({ generation: 1, complete: true });
    expect(
      third?.lines.find((line) => (line.v as Row).id === "d1"),
    ).toMatchObject({ o: 0, r: "seed", v: rich("d1") });
    expect(
      (await desktop.open().status()).receipts[receipt("desktop", "s")],
    ).toBe("merged");
    expect(seed.reads).toEqual([`${C}/s`]);
  });

  it("b: publishes an undeclared zero-emission stream and checkpoints only after all seed receipts", async () => {
    // Mutant B: prepareSeed skips retained streams absent from host.streams.
    const f = await fixture();
    const seed = retained("desktop", {
      s1: [rich("d1")],
      s2: [rich("d2")],
    });
    const files = createMemoryStreamSyncFiles(7);
    const writes: Pick<
      Awaited<ReturnType<StreamSyncWriter["status"]>>,
      "checkpoints" | "receipts"
    >[] = [];
    const monitored: StreamSyncFiles = {
      ...files,
      async write(path, bytes) {
        if (path === "state.json")
          writes.push(JSON.parse(decoder.decode(bytes)));
        await files.write(path, bytes);
      },
    };
    const desktop = f.device(seed.source, monitored);
    let sawUnreceiptedS2 = false;
    f.beforePost(async (request) => {
      if (request.scope !== streamScope(C, "", "s2")) return;
      const status = await desktop.writer.status();
      expect(status.receipts[receipt("desktop", "s1")]).toBe("merged");
      expect(status.receipts[receipt("desktop", "s2")]).toBeUndefined();
      expect(status.checkpoints[C]).toBeUndefined();
      sawUnreceiptedS2 = true;
    });
    await collect(desktop.writer, "zero-emission", { s1: [{ id: "n1" }] });
    await desktop.writer.publishPending();
    expect((await f.reader().read("s2"))?.values).toEqual([rich("d2")]);
    expect((await f.reader().read("s1"))?.values).toEqual([
      rich("d1"),
      { id: "n1" },
    ]);
    expect(sawUnreceiptedS2).toBe(true);
    const durable = await desktop.open().status();
    expect(durable.receipts[receipt("desktop", "s2")]).toBe("merged");
    expect(durable.checkpoints[C]).toMatchObject({
      value: { cursor: "zero-emission" },
    });
    const checkpointWrites = writes.filter(
      (state) => state.checkpoints?.[C] !== undefined,
    );
    expect(checkpointWrites.length).toBeGreaterThan(0);
    for (const state of checkpointWrites) {
      expect(state.receipts[receipt("desktop", "s1")]).toBe("merged");
      expect(state.receipts[receipt("desktop", "s2")]).toBe("merged");
    }
  });

  it("c: Desktop-first survives later phone publication and a restarted Desktop never reseeds", async () => {
    // Mutant C: ignore the existing receipt in prepareSeed (records read twice).
    // After the seed, the Desktop's retained row is edited. A receipt-respecting
    // restart must keep the published seed value; a replayed seed would publish
    // the edited value, because nothing else in this stream has a newer row for d1.
    const f = await fixture();
    const data: Record<string, readonly Row[]> = { s: [rich("d1")] };
    const seed = retained("desktop", data);
    const desktop = f.device(seed.source);
    await collect(desktop.writer, "desktop-first", { s: [{ id: "n1" }] });
    await desktop.writer.publishPending();
    expect((await f.reader().read("s"))?.values).toEqual([
      rich("d1"),
      { id: "n1" },
    ]);
    data.s = [{ ...rich("d1"), text: "d1 edited after seed" }];
    const phone = f.device().writer;
    await collect(phone, "phone-later", { s: [{ id: "p1" }] }, 1);
    await phone.publishPending();
    expect((await f.reader().read("s"))?.ids).toEqual(["d1", "n1", "p1"]);
    const restarted = desktop.open();
    expect((await restarted.status()).receipts[receipt("desktop", "s")]).toBe(
      "merged",
    );
    await collect(restarted, "desktop-again", { s: [{ id: "n2" }] }, 1);
    await restarted.publishPending();
    expect((await f.reader().read("s"))?.values).toEqual([
      rich("d1"),
      { id: "n1" },
      { id: "n2" },
      { id: "p1" },
    ]);
    expect(seed.reads).toEqual([`${C}/s`]);
  });

  it("d: generation two records a durable skipped receipt and never reads retained rows", async () => {
    // Mutant D: remove the host.target !== 1 guard, seeding every generation.
    const f = await fixture(2);
    const seed = retained("desktop", { s: [{ id: "old-desktop" }] });
    const desktop = f.device(seed.source);
    await collect(desktop.writer, "generation-two", { s: [{ id: "fresh" }] });
    await desktop.writer.publishPending();
    expect((await f.reader().read("s"))?.ids).toEqual(["fresh"]);
    expect((await f.reader().read("s"))?.head.generation).toBe(2);
    const restarted = desktop.open();
    expect((await restarted.status()).receipts[receipt("desktop", "s")]).toBe(
      "skipped",
    );
    await collect(
      restarted,
      "generation-two-again",
      { s: [{ id: "later" }] },
      2,
    );
    await restarted.publishPending();
    expect((await f.reader().read("s"))?.ids).toEqual(["fresh", "later"]);
    expect(seed.reads).toEqual([]);
    expect(
      (await desktop.open().status()).receipts[receipt("desktop", "s")],
    ).toBe("skipped");
  });

  it("e: foreign rows stay isolated and foreign-install receipts cannot suppress own seed", async () => {
    {
      // Provenance is selected by the retained source, not a field on seed rows.
      // The install-key mutant is checked by the collision half of this same case.
      const own = createSeedStaging(createMemoryStreamSyncFiles(7));
      const foreign = createSeedStaging(createMemoryStreamSyncFiles(7));
      await stageRows(own, C, "s", [{ id: "own" }]);
      await stageRows(own, "other-connector", "s", [
        { id: "foreign-connector" },
      ]);
      await stageRows(foreign, C, "s", [{ id: "foreign-install" }]);
      const ownId = await own.installId();
      expect(await foreign.installId()).not.toBe(ownId);
      const f = await fixture();
      const desktop = f.device(own.source(ownId, async () => ({}))).writer;
      await collect(desktop, "own-only", {});
      await desktop.publishPending();
      expect((await f.reader().read("s"))?.ids).toEqual(["own"]);
      expect(Object.keys(await own.staged("other-connector"))).toEqual(["s"]);
      expect(Object.keys(await foreign.staged(C))).toEqual(["s"]);
    }

    // Mutant E: remove installId from every writer receipt key. The data assertion
    // fails before the key-shape assertion: install B's own row disappears.
    const f = await fixture();
    const a = retained("install-a", { s: [{ id: "a" }] });
    const b = retained("install-b", { s: [{ id: "b" }] });
    const device = f.device(a.source);
    await collect(device.writer, "install-a", {});
    await device.writer.publishPending();
    // Restore a home containing the other install's receipt; no concurrent writer.
    const restored = device.open(b.source);
    await collect(restored, "install-b", {}, 1);
    await restored.publishPending();
    expect((await f.reader().read("s"))?.ids).toEqual(["a", "b"]);
    expect(b.reads).toEqual([`${C}/s`]);
    const receipts = (await device.open(b.source).status()).receipts;
    expect(receipts[receipt("install-a", "s")]).toBe("merged");
    expect(receipts[receipt("install-b", "s")]).toBe("merged");
  });

  it("f: a pending run from owner A restored into owner B's home never publishes under B", async () => {
    // Mutant F: drop the `bound.owner !== now.owner` disjunct in publishEntry.
    // The key check still matches (same key material), so only the owner guard
    // separates A's pending data from B's publication.
    const f = await fixture();
    const aFiles = createMemoryStreamSyncFiles(7);
    const a = f.device(undefined, aFiles, OWNER);
    await collect(a.writer, "owner-a-run", { s: [{ id: "a-marker" }] });
    // Owner A never publishes. Its durable pending run is copied into B's home.
    const bFiles = createMemoryStreamSyncFiles(7);
    for (const path of aFiles.paths()) {
      await bFiles.write(path, (await aFiles.read(path))!);
    }
    const bSeed = retained("desktop-b", { s: [rich("b-seed")] });
    const b = f.device(bSeed.source, bFiles, OTHER_OWNER);
    await collect(b.writer, "owner-b-run", { s: [{ id: "b-live" }] });
    await b.writer.publishPending();
    const head = await f.reader().read("s");
    expect(head?.ids).toEqual(["b-live", "b-seed"]);
    expect(head?.values).not.toContainEqual({ id: "a-marker" });
    expect(bSeed.reads).toEqual([`${C}/s`]);
  });

  it("g: retained rows staged on disk survive a sidecar reopen before their first publish", async () => {
    // Mutant G: a startup cleanup in createSeedStaging's installId() (bootstrap
    // calls it on every start) removes staged pointers and uploads that hold no
    // receipt. The retained row is then the only copy and is lost.
    const f = await fixture();
    const stagingFiles = createMemoryStreamSyncFiles(7);
    const before = createSeedStaging(stagingFiles);
    await stageRows(before, C, "s", [rich("d1")]);
    // Sidecar restarts over the same durable staging files.
    const after = createSeedStaging(stagingFiles);
    const installId = await after.installId();
    const homeFiles = createMemoryStreamSyncFiles(7);
    const desktop = f.device(
      after.source(
        installId,
        async (connector) =>
          (await desktop.writer.seedStatus(connector)).receipts,
      ),
      homeFiles,
    );
    const writer = desktop.writer;
    await collect(writer, "desktop-reopened", {});
    await writer.publishPending();
    expect((await f.reader().read("s"))?.values).toEqual([rich("d1")]);
    expect((await writer.status()).receipts[receipt(installId, "s")]).toBe(
      "merged",
    );
  });

  it("h: a crash after the POST and before the local receipt re-merges the staged rows exactly once", async () => {
    // Crash point after_post_reply: the registry has accepted the head, but the
    // writer has not persisted its receipt. Reopen both sides and retry.
    const f = await fixture();
    const stagingFiles = createMemoryStreamSyncFiles(7);
    const homeFiles = createMemoryStreamSyncFiles(7);
    const first = createSeedStaging(stagingFiles);
    const installId = await first.installId();
    await stageRows(first, C, "s", [rich("d1")]);

    let writer: StreamSyncWriter | undefined;
    let fired = false;
    const sidecar = async (crash: boolean) => {
      const staging = createSeedStaging(stagingFiles);
      await staging.installId();
      const source = staging.source(installId, async (connector) =>
        writer ? (await writer.seedStatus(connector)).receipts : {},
      );
      const desktop = f.device(source, homeFiles);
      writer = desktop.open(source, (point) => {
        if (crash && point === "after_post_reply") {
          fired = true;
          throw new Error("injected crash after POST reply");
        }
      });
      return writer;
    };

    const crashed = await sidecar(true);
    await collect(crashed, "crash-run", {});
    await crashed.publishPending().catch(() => undefined);
    // The crash must have happened, or the retry below proves nothing.
    expect(fired).toBe(true);

    const restarted = await sidecar(false);
    await restarted.publishPending();
    expect((await f.reader().read("s"))?.values).toEqual([rich("d1")]);
    expect((await restarted.status()).receipts[`${installId}|${C}||s`]).toBe(
      "merged",
    );
  });

  it("i: a newer connector key change empties the base; a restart must not reseed the removed row", async () => {
    // Mutant I: ignore the seed receipt on restart (writer.ts prepareSeed).
    // Same generation is not enough to keep rows: a v2 run whose primary key
    // changed meets writerCompatibility's empty_base (head.ts), which replaces
    // the head (publish-plan.ts replacesBase). The retained row is then gone,
    // and a restart with the old retained source must not bring it back.
    const f = await fixture();
    const seed = retained("desktop", { s: [rich("d1")] });
    const desktop = f.device(seed.source);
    await collect(desktop.writer, "desktop-first", { s: [{ id: "n1" }] });
    await desktop.writer.publishPending();
    expect((await f.reader().read("s"))?.ids).toEqual(["d1", "n1"]);
    const phone = f.device().writer;
    await collect(
      phone,
      "phone-v2",
      { s: [{ id: "v2a", n: 100 }] },
      1,
      V2_SHAPE,
    );
    await phone.publishPending();
    const replaced = await f.reader().read("s");
    expect(replaced?.head).toMatchObject({ generation: 1, primaryKey: ["n"] });
    expect(replaced?.values).toEqual([{ id: "v2a", n: 100 }]);
    const restarted = desktop.open();
    expect((await restarted.status()).receipts[receipt("desktop", "s")]).toBe(
      "merged",
    );
    await collect(
      restarted,
      "desktop-v2",
      { s: [{ id: "desk-2", n: 200 }] },
      1,
      V2_SHAPE,
    );
    await restarted.publishPending();
    expect((await f.reader().read("s"))?.values).toEqual([
      { id: "desk-2", n: 200 },
      { id: "v2a", n: 100 },
    ]);
    expect(seed.reads).toEqual([`${C}/s`]);
  });
});
