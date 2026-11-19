import { afterEach, expect, it } from "vitest";
import {
  foldLog,
  partitionFold,
  encodeSnapshotPart,
  encodeSegment,
  digestSegment,
  segmentBlobName,
  logScope,
  type Segment,
  type LogOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { planCompaction } from "../../../core/dist/localdb/log-compact.js";
import {
  world,
  closeWorldDrivers,
  CONNECTION_ID,
  idHash,
} from "./log-world.test-utils.js";
import { keccakOf } from "../../../core/src/stream-sync/crypto-port.js";
afterEach(closeWorldDrivers);

it.each([0x12345678, 0xaabbccdd, 0x13579bdf])(
  "compaction bytes equal the pure oracle while admitting one history unit at a time (%i)",
  async (seed) => {
    const w = await world({ streams: 1 });
    const d = await w.device("fold");
    await d.run("seed", [{ stream: "s0", id: 99 }]);
    await d.cycle();
    const template = [...(await w.segments()).values()][0]!;
    let random = seed;
    const next = () =>
      (random = (Math.imul(random, 1664525) + 1013904223) >>> 0);
    const hashes = await Promise.all([0, 1, 2, 3].map(idHash));
    const history: Segment[] = [];
    for (let i = 0; i < 40; i++) {
      const id = next() % 4,
        kind = (next() >>> 16) % 3,
        stamp = { o: 100 + Math.floor(i / 3), r: "r" };
      const op: LogOperation =
        kind === 0
          ? {
              kind: "delete",
              stream: "s0",
              pkHash: hashes[id]!,
              key: [id],
              stamp,
            }
          : kind === 1
            ? {
                kind: "complete",
                stream: "s0",
                cutoff: stamp,
                omitted: [{ pkHash: hashes[id]!, key: [id] }],
              }
            : {
                kind: "upsert",
                stream: "s0",
                pkHash: hashes[id]!,
                stamp,
                ordinal: i % 2,
                firstSeen: i % 2 ? null : i,
                value: { id, v: i, text: 'é\\"' },
              };
      history.push({
        ...template,
        position: i + 1,
        refs: Array.from({ length: i }, (_, j) => ({
          position: j + 1,
          dataHash: `0x${"00".repeat(32)}` as `0x${string}`,
          bytes: 100,
        })),
        operations: [op],
        snapshot: null,
        base: 0,
      });
    }
    const scope = logScope(template.connector, template.ns);
    const refs = [];
    for (const segment of history) {
      const bytes = encodeSegment(segment),
        { dataHash } = await digestSegment(
          keccakOf(d.deps.streamCrypto),
          bytes,
        );
      await d.deps.blobs.put(
        `${scope}/${segmentBlobName(dataHash)}`,
        await d.deps.keys.encryptPart(scope, bytes),
      );
      refs.push({ position: segment.position, dataHash, bytes: bytes.length });
    }
    let active = 0,
      peak = 0,
      gets = 0;
    const blobs = {
      ...d.deps.blobs,
      async get(key: string) {
        active++;
        gets++;
        peak = Math.max(peak, active);
        try {
          return await d.deps.blobs.get(key);
        } finally {
          active--;
        }
      },
    };
    const log = { position: 40, base: 0, refs, snapshot: null };
    const plan = await planCompaction(
      { ...d.deps, blobs },
      {
        connector: template.connector,
        ns: template.ns,
        keyCheck: template.keyCheck,
        generation: template.generation,
        scope,
        log,
      },
    );
    expect(plan).not.toBeNull();
    const expected = partitionFold(
      foldLog({ snapshot: [], segments: history }),
      {
        connector: template.connector,
        ns: template.ns,
        generation: template.generation,
        keyCheck: template.keyCheck,
        position: 40,
      },
      d.deps.partTargetBytes,
    );
    const clear = [];
    for (const object of plan!.objects)
      if (object.name.startsWith("q-"))
        clear.push(await d.deps.keys.decrypt(scope, object.cipher));
    expect(clear).toEqual(expected.map(encodeSnapshotPart));
    expect(gets).toBe(40);
    expect(peak).toBe(1);
  },
  60000,
);

it("disk cells preserve independent maxima, nullable winner checkpoints, metadata order and deletion before resurrection", async () => {
  const w = await world({ streams: 1 }),
    d = await w.device("vectors");
  await d.run("seed", [{ stream: "s0", id: 99 }]);
  await d.cycle();
  const template = [...(await w.segments()).values()][0]!;
  const { openDiskFold } =
    await import("../../../core/dist/localdb/log-disk-fold.js");
  const fold = await openDiskFold(
    d.deps,
    CONNECTION_ID,
    template.keyCheck,
    "vectors",
    template.generation,
  );
  const hash = await idHash('é\\"');
  const up = (
    o: number,
    ordinal: number,
    value: number,
    firstSeen: number | null,
  ): LogOperation => ({
    kind: "upsert",
    stream: "s0",
    pkHash: hash,
    stamp: { o, r: "r" },
    ordinal,
    firstSeen,
    value: { id: 'é\\"', value },
  });
  const ops: LogOperation[] = [
    up(1, 0, 0, 10),
    up(1, 1, 0, 20),
    up(1, 1, 1, null),
    {
      kind: "complete",
      stream: "s0",
      cutoff: { o: 1, r: "r" },
      omitted: [{ pkHash: hash, key: ['é\\"'] }],
    },
    {
      kind: "delete",
      stream: "s0",
      pkHash: hash,
      key: ['é\\"'],
      stamp: { o: 2, r: "r" },
    },
    up(3, 0, 3, null),
  ];
  const history: Segment[] = [];
  try {
    // Multiple changes of the same key within a unit must read the staged maximum.
    for (let i = 0; i < 3; i++) {
      const segment = {
        ...template,
        position: i + 1,
        streams: template.streams.map((m) => ({ ...m, complete: i === 2 })),
        operations: ops.slice(i * 2, i * 2 + 2),
      };
      history.push(segment);
      await fold.ingest(
        `unit${i}`,
        `hash${i}`,
        i,
        segment,
        LOG_SCOPE(template),
      );
      const expected = foldLog({ snapshot: [], segments: history });
      const actual = [];
      for await (const entry of fold.entries(false)) actual.push(entry);
      const metadata = [];
      for await (const meta of fold.metadata()) metadata.push(meta);
      const context = {
        format: template.format,
        connector: template.connector,
        ns: template.ns,
        generation: template.generation,
        keyCheck: template.keyCheck,
        position: i + 1,
        index: 0,
      };
      expect(
        encodeSnapshotPart({ ...context, streams: metadata, entries: actual }),
      ).toEqual(encodeSnapshotPart({ ...context, ...expected }));
    }
    const final = [];
    for await (const entry of fold.entries(false)) final.push(entry);
    expect(final).toMatchObject([
      { kind: "delete" },
      { kind: "upsert", firstSeen: null },
    ]);
  } finally {
    await fold.close();
  }
});
function LOG_SCOPE(template: Segment) {
  return logScope(template.connector, template.ns);
}

it("oversized referenced records leave a durable retryable failure without a piece GET or fold receipt", async () => {
  const w = await world({ streams: 1 }),
    d = await w.device("admission");
  await d.run("seed", [{ stream: "s0", id: 99 }]);
  await d.cycle();
  const template = [...(await w.segments()).values()][0]!;
  const hash = `0x${"00".repeat(32)}` as const;
  const scope = LOG_SCOPE(template),
    refs = [];
  for (let i = 0; i < 40; i++) {
    const segment = {
      ...template,
      position: i + 1,
      refs: [...refs],
      operations:
        i === 0
          ? [
              {
                kind: "upsert-ref" as const,
                stream: "s0",
                pkHash: await idHash(1),
                stamp: { o: 1, r: "r" },
                firstSeen: null,
                body: {
                  bytes: 32 * 1024 * 1024,
                  sha256: "00".repeat(32),
                  pieces: [hash, hash],
                },
              },
            ]
          : [],
    };
    const bytes = encodeSegment(segment),
      { dataHash } = await digestSegment(keccakOf(d.deps.streamCrypto), bytes);
    await d.deps.blobs.put(
      `${scope}/${segmentBlobName(dataHash)}`,
      await d.deps.keys.encryptPart(scope, bytes),
    );
    refs.push({ position: i + 1, dataHash, bytes: bytes.length });
  }
  let pieceGets = 0;
  const blobs = {
    ...d.deps.blobs,
    async get(key: string) {
      if (key.includes("/v-")) pieceGets++;
      return d.deps.blobs.get(key);
    },
  };
  await expect(
    planCompaction(
      { ...d.deps, blobs },
      {
        connector: template.connector,
        ns: template.ns,
        keyCheck: template.keyCheck,
        generation: template.generation,
        scope,
        log: { position: 40, base: 0, refs, snapshot: null },
      },
    ),
  ).rejects.toThrow("workspace_record_admission");
  expect(pieceGets).toBe(0);
  expect(await d.position()).toBe(1);
  expect(await d.db.query("SELECT unit FROM workspace_receipts")).toEqual([]);
  expect(await d.db.query("SELECT phase,position FROM workspaces")).toEqual([
    { phase: "aborted", position: 0 },
  ]);
  expect(
    await d.db.query(
      "SELECT reason,state FROM workspace_attempts WHERE unit='fold' AND action='admission'",
    ),
  ).toEqual([{ reason: "admission", state: "failed" }]);
});

it("a stale caller generation cannot acquire a fold for the current connection", async () => {
  const w = await world({ streams: 1 }),
    d = await w.device("generation");
  await d.run("seed", [{ stream: "s0", id: 99 }]);
  await d.cycle();
  const template = [...(await w.segments()).values()][0]!;
  const { openDiskFold } =
    await import("../../../core/dist/localdb/log-disk-fold.js");
  let unexpected: Awaited<ReturnType<typeof openDiskFold>> | undefined;
  try {
    const attempt = openDiskFold(
      d.deps,
      CONNECTION_ID,
      template.keyCheck,
      "stale",
      template.generation + 1,
    ).then((fold) => {
      unexpected = fold;
      return fold;
    });
    await expect(attempt).rejects.toThrow("workspace_stale_generation");
  } finally {
    await unexpected?.close();
  }
});

it("cursor compaction preserves every output byte and piece-before-part order across part boundaries", async () => {
  const w = await world({ streams: 1 }),
    d = await w.device("output");
  await d.run("seed", [{ stream: "s0", id: 99 }]);
  await d.cycle();
  const template = [...(await w.segments()).values()][0]!,
    scope = logScope(template.connector, template.ns),
    target = 8192;
  const hashes = await Promise.all([0, 1, 2, 3].map(idHash));
  const byHash = [0, 1, 2, 3].sort((a, b) =>
    hashes[a]! < hashes[b]! ? -1 : 1,
  );
  const history: Segment[] = [],
    refs = [];
  for (let i = 0; i < 40; i++) {
    const operations: LogOperation[] =
      i < 4
        ? [
            {
              kind: "upsert",
              stream: "s0",
              pkHash: hashes[i]!,
              stamp: { o: i + 10, r: "r" },
              firstSeen: null,
              value: {
                id: i,
                pad: [byHash[0], byHash[3]].includes(i)
                  ? "é".repeat(7000)
                  : "x".repeat(6000),
                text: 'é\\"',
              },
            },
          ]
        : [];
    const segment = {
      ...template,
      position: i + 1,
      refs: [...refs],
      operations,
    };
    history.push(segment);
    const bytes = encodeSegment(segment),
      { dataHash } = await digestSegment(keccakOf(d.deps.streamCrypto), bytes);
    await d.deps.blobs.put(
      `${scope}/${segmentBlobName(dataHash)}`,
      await d.deps.keys.encryptPart(scope, bytes),
    );
    refs.push({ position: i + 1, dataHash, bytes: bytes.length });
  }
  const { putBodiesOutOfLine } =
    await import("../../../core/dist/localdb/log-bodies.js");
  const { digestSnapshotPart, snapshotPartBlobName } =
    await import("@opendatalabs/personal-server-ts-stream-sync");
  const fold = foldLog({ snapshot: [], segments: history }),
    out = await putBodiesOutOfLine(d.deps, scope, fold.entries, target);
  const parts = partitionFold(
    { streams: fold.streams, entries: out.ops },
    {
      connector: template.connector,
      ns: template.ns,
      generation: template.generation,
      keyCheck: template.keyCheck,
      position: 40,
    },
    target,
  );
  const expected = [...out.pieces];
  for (const part of parts) {
    const bytes = encodeSnapshotPart(part),
      { dataHash } = await digestSnapshotPart(
        keccakOf(d.deps.streamCrypto),
        bytes,
      );
    expected.push({
      name: snapshotPartBlobName(dataHash),
      cipher: await d.deps.keys.encryptPart(scope, bytes),
    });
  }
  expect(parts.length).toBeGreaterThan(1);
  expect(out.pieces.length).toBeGreaterThan(0);
  // Eligibility-only override: verify the real stored units, using a cheap cost estimate.
  const plan = await planCompaction(
    { ...d.deps, partTargetBytes: target },
    {
      connector: template.connector,
      ns: template.ns,
      generation: template.generation,
      keyCheck: template.keyCheck,
      scope,
      log: {
        position: 40,
        base: 0,
        snapshot: null,
        refs: refs.map((ref) => ({ ...ref, bytes: 1 })),
      },
    },
  );
  expect(plan?.objects).toEqual(expected);
}, 60000);

it("an adapter must advertise borrowed-lease sealing before any fold input is fetched", async () => {
  const w = await world({ streams: 1 }),
    d = await w.device("capability");
  await d.run("seed", [{ stream: "s0", id: 99 }]);
  await d.cycle();
  const template = [...(await w.segments()).values()][0]!;
  const { openDiskFold } =
    await import("../../../core/dist/localdb/log-disk-fold.js");
  const db = {
    ...d.db,
    boundedValues: { ...d.db.boundedValues!, supportsBorrowedSeal: undefined },
  };
  let unexpected: Awaited<ReturnType<typeof openDiskFold>> | undefined;
  try {
    await expect(
      openDiskFold(
        { ...d.deps, db },
        CONNECTION_ID,
        template.keyCheck,
        "capability",
        template.generation,
      ).then((fold) => {
        unexpected = fold;
        return fold;
      }),
    ).rejects.toThrow("workspace_requires_borrowed_seal");
  } finally {
    await unexpected?.close();
  }
});
