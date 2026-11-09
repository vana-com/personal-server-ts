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
import {
  createMemoryImportAuthority,
  LegacyImporter,
  RetireLedger,
  type ImportStream,
  type MemoryImportAuthority,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createSeedImportSink } from "./legacy-import-sink.js";
import { createSeedStaging } from "./seed-staging.js";

// Extends the writer-overlay in-memory rig, without the oracle rig's HTTP store.
// oracle.test.ts M7 already covers phone-first WITH new Desktop records. Here
// the Desktop's entire run is empty. Staging/route tests already pin upload
// validation and stable install IDs, not these multi-device orderings.
// Identity encryption and a dummy signer are intentional test ports; the real
// writer, planner, head/part codecs and hash verification perform publication.
const OWNER = `0x${"11".repeat(20)}` as const;
const C = "seed-scenarios";
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };
const receipt = (install: string, stream: string) =>
  `${install}|${C}||${stream}`;
type Row = {
  id: string;
  text?: string;
  n?: number;
  nested?: { tags: string[] };
};
const byId = (a: Row, b: Row) => (a.id < b.id ? -1 : 1);

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
    const open = (
      source = seed,
      fault?: StreamSyncWriterOptions["fault"],
      importDone?: StreamSyncWriterOptions["importDone"],
    ) =>
      new StreamSyncWriter({
        ownerAddress: owner,
        home,
        registry,
        blobs,
        seed: source,
        fault,
        ...(importDone ? { importDone } : {}),
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

const CONNECTOR = C;

const importStream = (stream: string, ids: string[]): ImportStream => ({
  stream,
  primaryKey: ["id"],
  profile: SHAPE.profile,
  async *records() {
    for (const id of ids) yield { id };
  },
});

/** What survives a restart of the host. */
const durableFiles = () => ({
  staging: createMemoryStreamSyncFiles(7),
  home: createMemoryStreamSyncFiles(7),
  ledger: createMemoryStreamSyncFiles(7),
  authority: createMemoryImportAuthority() as MemoryImportAuthority,
});

/**
 * One run of the host process, as the server wires it: the real seed
 * staging, the real writer reading the staged rows through it, and the
 * importer publishing through that writer. Only `durable` outlives it.
 */
async function boot(
  f: Awaited<ReturnType<typeof fixture>>,
  durable: ReturnType<typeof durableFiles>,
  options: {
    streams: ImportStream[];
    crashAfterPostReply?: { fired: boolean };
  },
) {
  const staging = createSeedStaging(durable.staging);
  const installId = await staging.installId();
  // eslint-disable-next-line prefer-const -- bound below; the callbacks read it late
  let writer: StreamSyncWriter | undefined;
  const source = staging.source(installId, async (connector) =>
    writer ? (await writer.seedStatus(connector)).receipts : {},
  );
  const ledger = new RetireLedger(durable.ledger, OWNER, durable.authority);
  const stages: string[] = [];
  const sink = createSeedImportSink(staging);
  const importer = new LegacyImporter({
    source: {
      owner: OWNER,
      connectors: async () => [CONNECTOR],
      streams: async () => options.streams,
    },
    sink: {
      stage: (connector, stream, rows) => {
        stages.push(stream.stream);
        return sink.stage(connector, stream, rows);
      },
    },
    ledger,
    owner: OWNER,
    mode: () => "switched" as const,
    publish: (connector, streams) => {
      if (!writer) throw new Error("the writer is not open");
      return writer.publishSeed(connector, streams);
    },
  });
  const crash = options.crashAfterPostReply;
  writer = f.device(source, durable.home).open(
    source,
    (point) => {
      if (crash && !crash.fired && point === "after_post_reply") {
        crash.fired = true;
        throw new Error("injected crash after POST reply");
      }
    },
    importer.importDone,
  );
  return { importer, ledger, writer, stages, installId };
}

describe("the import through the real seed staging and writer", () => {
  it("names a stream the writer skipped though the staging source no longer lists it, and does not call it published (SKIPPED_COUNTED_AS_PUBLISHED)", async () => {
    // Generation two is already active: the seed cannot merge (§2.9).
    const f = await fixture(2);
    const durable = durableFiles();
    const p = await boot(f, durable, {
      streams: [importStream("s", ["a", "b"])],
    });
    await p.importer.run(); // stages, asks for the publish
    await p.writer.publishPending(); // the import run binds generation two
    expect((await p.writer.status()).receipts[receipt(p.installId, "s")]).toBe(
      "skipped",
    );
    // The staging source drops a receipted stream from its list.
    expect(
      await createSeedStaging(durable.staging)
        .source(p.installId, async () => ({ s: "skipped" as const }))
        .streams(CONNECTOR),
    ).toEqual([]);
    await p.importer.run(); // sees the receipt
    const status = await p.importer.status();
    expect(status.connectors[0]).toMatchObject({
      state: "imported",
      staged: 2,
      stayed: 2,
      excluded: [{ reason: "seed_skipped", rows: 2 }],
    });
    expect(status.stayed).toBe(2);
    expect((await p.ledger.read()).imported[CONNECTOR]).not.toHaveProperty(
      "published",
    );
    expect(await p.ledger.importProven(CONNECTOR)).toBe(false);
  });

  it("repeats the whole import for the same owner with no duplicate rows, no lost rows and the right counts, after a crash mid-publish (IMPORT_RERUN_RESTAGES_PUBLISHED)", async () => {
    const f = await fixture();
    const durable = durableFiles();
    const streams = [importStream("s1", ["a", "b"]), importStream("s2", ["c"])];
    // First process: stages both streams, asks for the publish, and dies
    // after the registry accepted a head and before the receipt was saved.
    const crash = { fired: false };
    const first = await boot(f, durable, {
      streams,
      crashAfterPostReply: crash,
    });
    await first.importer.run();
    expect(first.stages).toEqual(["s1", "s2"]);
    await first.writer.publishPending().catch(() => undefined);
    expect(crash.fired).toBe(true);
    expect(durable.authority.doneCalls).toEqual([]);

    // Second process, same owner, same files: the import repeats.
    const second = await boot(f, durable, { streams });
    await second.importer.run();
    await second.writer.publishPending();
    await second.importer.run();
    expect(second.stages).toEqual([]); // staged rows are not staged again
    const read = f.reader();
    const rows = async (stream: string) =>
      ((await read.read(stream))?.values ?? []).map((v) => v.id);
    expect(await rows("s1")).toEqual(["a", "b"]);
    expect(await rows("s2")).toEqual(["c"]);
    const receipts = (await second.writer.status()).receipts;
    expect(receipts[receipt(second.installId, "s1")]).toBe("merged");
    expect(receipts[receipt(second.installId, "s2")]).toBe("merged");
    expect(await second.importer.status()).toEqual({
      complete: true,
      abandoned: false,
      stayed: 0,
      connectors: [
        {
          connector: CONNECTOR,
          state: "published",
          attempts: 0,
          staged: 3,
          stayed: 0,
          excluded: [],
        },
      ],
    });
    expect(durable.authority.doneCalls).toEqual([OWNER.toLowerCase()]);

    // A third process: the authority says done, so nothing runs again.
    const third = await boot(f, durable, { streams });
    expect(await third.importer.run()).toMatchObject({ ran: false });
    expect(third.stages).toEqual([]);
    expect(await rows("s1")).toEqual(["a", "b"]);
    expect(await rows("s2")).toEqual(["c"]);
    expect(durable.authority.doneCalls).toEqual([OWNER.toLowerCase()]);
  });
});
