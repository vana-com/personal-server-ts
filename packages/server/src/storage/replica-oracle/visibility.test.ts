/**
 * Node, Lite and the visibility engine judged against each other on the
 * whole state a reader can observe.
 *
 * Each scenario is a set of steps: batch deliveries, repeated deliveries,
 * late bytes, late declarations, late provisioning and local writes. Every
 * round shuffles the steps and, after each one, compares each host's state:
 * live rows and tombstones from point reads, list pages, pending markers,
 * referenced blob bytes and completion listings, for the owner and a grant
 * reader; stored completions; and which connections are withdrawn or
 * deleted. It requires:
 * - Node's state to equal Lite's, except connection state where the hosts
 *   map different connections (Lite refuses a mapping its retained evidence
 *   contradicts; Node maps it and records the binding conflict);
 * - each host's state to equal the engine fed the same changes one by one
 *   (incremental);
 * - the incremental engine to equal the engine fed all of the host's
 *   evidence at once (full history) on connections, rows and completions.
 *
 * The engine is fed each host's own local journal, since local writes mint
 * host-specific revisions. PR CI runs a few orders per scenario;
 * REPLICA_ORACLE_NIGHTLY=1 runs many more.
 */
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { operationDigest } from "@opendatalabs/personal-server-ts-core/replication/completion";
import {
  completionId,
  createMemoryVisibilityCommitter,
  EMPTY_PROJECTION,
  evaluate,
  INITIAL_VISIBILITY_EPOCH,
  type ConnectionMapping,
  type EvidenceChange,
  type VisibilityProjection,
  type VisibilityWorld,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-engine";
import { liveSnapshotDigest } from "../pdpp-stream-completion.js";
import { BINDINGS, blobOf, type BindingName } from "./generator.test-utils.js";
import {
  contextOf,
  liteDriver,
  liteMemoryPersistence,
  METHOD,
  nodeDriver,
  OWNER,
  SOURCE,
  type PortSnapshot,
  type ReplicaPortDriver,
} from "./ports.test-utils.js";

const nightly = process.env.REPLICA_ORACLE_NIGHTLY === "1";
const ORDERS = nightly ? 120 : 4;
const TIMEOUT = nightly ? 900_000 : 60_000;
const MAPPING: ConnectionMapping = { sourceId: SOURCE, methodId: METHOD };
const CONNECTIONS = ["c1", "c2"] as const;
const KEYS = ["k0", "k1", "k2"] as const;
const STREAMS = ["messages", "events"] as const;

type Data = Record<string, unknown>;
type Step =
  | { k: "batch"; id: string; ops: ReplicaOperation[] }
  /** Deliver a delivered batch again, optionally with named blob bytes. */
  | { k: "again"; id: string; bytes?: string[] }
  | { k: "declare"; bindings: BindingName[] }
  | { k: "provision"; connection: string }
  | { k: "local"; key: string; text: string };

const at = (connectionId: string, methodId = METHOD) => ({
  owner: OWNER,
  sourceId: SOURCE,
  connectionId,
  methodId,
  generation: 1,
});
const rev = (counter: number, operationId: string) => ({
  counter,
  writerId: "w-a",
  operationId,
});
const put = (
  c: string,
  key: string,
  data: Data,
  counter: number,
  operationId = `${c}-${key}-${counter}`,
  methodId = METHOD,
): Extract<ReplicaOperation, { kind: "upsert" }> => ({
  ...at(c, methodId),
  kind: "upsert",
  declaration: BINDINGS.m,
  recordKey: key,
  emittedAt: "2026-10-27T00:00:00Z",
  data: { id: key, ...data },
  blobs: [],
  revision: rev(counter, operationId),
});
const complete = (
  c: string,
  dependencies: ReplicaOperation[],
  rows: Record<string, Data>,
  counter: number,
): ReplicaOperation => {
  const digest = liveSnapshotDigest(
    {
      sourceId: SOURCE,
      instance: c,
      method: METHOD,
      generation: 1,
      stream: "messages",
    },
    ["id"],
    Object.entries(rows).map(([recordKey, data]) => ({
      recordKey,
      dataJson: canonicalJson({ id: recordKey, ...data }),
    })),
  );
  return {
    ...at(c),
    kind: "stream-complete",
    declaration: BINDINGS.m,
    sourceCollectedAt: "2026-10-27T00:00:00Z",
    liveCount: Object.keys(rows).length,
    snapshotSha256: `sha256:${digest}`,
    proof: {
      kind: "native",
      snapshotSha256: `sha256:${digest}`,
      collectionTimeBasis: "host_run_finished",
    },
    dependencies: dependencies.map((op) => ({
      writerId: op.revision.writerId,
      operationId: op.revision.operationId,
      digest: operationDigest(op),
    })),
    revision: rev(counter, `done-${c}-${counter}`),
  };
};

const k0 = put("c1", "k0", { text: "zero" }, 2);
const k1 = put("c1", "k1", { text: "one" }, 3);
const done01 = complete(
  "c1",
  [k0, k1],
  { k0: { text: "zero" }, k1: { text: "one" } },
  5,
);
const blob = blobOf("b0").descriptor;
const claim: ReplicaOperation = {
  ...at("c1"),
  kind: "blob-claim",
  blob,
  revision: rev(6, "claim-b0"),
};
const del1: ReplicaOperation = {
  ...at("c1"),
  kind: "delete",
  declaration: BINDINGS.m,
  recordKey: "k1",
  emittedAt: "2026-10-27T00:00:00Z",
  deletedAt: "2026-10-27T00:00:02Z",
  revision: rev(9, "c1-k1-delete"),
};
const withBlob = {
  ...put("c1", "k2", { blob_ref: { blob_id: blob.blobId } }, 7),
  blobs: [blob],
};

const SCENARIOS: Record<
  string,
  { declared: BindingName[]; provisioned: string[]; steps: Step[] }
> = {
  "reordered and repeated delivery": {
    declared: ["m", "a"],
    provisioned: ["c1"],
    steps: [
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
      { k: "again", id: "done" },
      { k: "again", id: "k0" },
    ],
  },
  "a late declaration": {
    declared: ["a"],
    provisioned: ["c1"],
    steps: [
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
      { k: "declare", bindings: ["m", "a"] },
    ],
  },
  "late bytes": {
    declared: ["m", "a"],
    provisioned: ["c1"],
    steps: [
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "blob", ops: [claim, withBlob] },
      {
        k: "batch",
        id: "done",
        ops: [
          complete(
            "c1",
            [k0, withBlob],
            {
              k0: { text: "zero" },
              k2: { blob_ref: { blob_id: blob.blobId } },
            },
            8,
          ),
        ],
      },
      { k: "again", id: "blob", bytes: ["b0"] },
    ],
  },
  "cross-connection equivocation": {
    declared: ["m", "a"],
    provisioned: ["c1", "c2"],
    steps: [
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
      {
        k: "batch",
        id: "twin",
        // k0's revision under another connection, with other content.
        ops: [put("c2", "k0", { text: "twin" }, 2, k0.revision.operationId)],
      },
    ],
  },
  "equivocation from a connection with a binding conflict": {
    declared: ["m", "a"],
    provisioned: ["c1"],
    // Written order: Node maps c2 over its contradicting evidence before c1
    // holds the twin's revision, so no sticky quarantine hides the variant.
    steps: [
      {
        k: "batch",
        id: "twin",
        // k0's revision under c2, whose evidence names another method than
        // its local mapping, with other content.
        ops: [
          put(
            "c2",
            "k0",
            { text: "twin" },
            2,
            k0.revision.operationId,
            "other",
          ),
        ],
      },
      { k: "provision", connection: "c2" },
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
    ],
  },
  "a record deletion": {
    declared: ["m", "a"],
    provisioned: ["c1"],
    steps: [
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
      { k: "batch", id: "delete", ops: [del1] },
      { k: "again", id: "k1" },
    ],
  },
  "a connection deletion that names another binding": {
    declared: ["m", "a"],
    provisioned: ["c1"],
    // Delivered before c2 is provisioned, the deletion names another method
    // than c2's mapping. It withdraws c2 on Node and deletes nothing.
    steps: [
      { k: "batch", id: "c2", ops: [put("c2", "k0", { text: "c2" }, 2)] },
      {
        k: "batch",
        id: "foreign-delete",
        ops: [
          {
            ...at("c2", "other"),
            kind: "connection-delete",
            revision: rev(4, "c2-delete"),
          },
        ],
      },
      { k: "provision", connection: "c2" },
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
    ],
  },
  "local writes interleaved with delivery": {
    declared: ["m", "a"],
    provisioned: ["c1"],
    steps: [
      { k: "batch", id: "k0", ops: [k0] },
      { k: "batch", id: "k1", ops: [k1] },
      { k: "batch", id: "done", ops: [done01] },
      { k: "local", key: "k1", text: "edited" },
      { k: "local", key: "k2", text: "added" },
    ],
  },
};

/** One host and the engine fed that host's changes. */
interface Run {
  driver: ReplicaPortDriver;
  committer: ReturnType<typeof createMemoryVisibilityCommitter>;
  world: VisibilityWorld;
  evidence: ReplicaOperation[];
}
async function feed(run: Run, change: EvidenceChange) {
  if (change.kind === "evidence") {
    const known = new Set(run.evidence.map((op) => canonicalJson(op)));
    const fresh = change.operations.filter(
      (op) => !known.has(canonicalJson(op)),
    );
    change = { ...change, operations: fresh };
  }
  const { epoch, projection } = run.committer.read();
  await run.committer.commit(
    epoch,
    evaluate(
      { epoch, projection, world: run.world, evidence: run.evidence },
      change,
    ),
    {},
  );
  if (change.kind === "evidence") {
    run.evidence = [...run.evidence, ...change.operations];
    run.world = {
      ...run.world,
      verifiedBlobs: new Set([
        ...run.world.verifiedBlobs,
        ...(change.verifiedBlobs ?? []),
      ]),
    };
  } else
    run.world = {
      ...run.world,
      declarations: change.declarations ?? run.world.declarations,
      mappings: new Map([
        ...run.world.mappings,
        ...Object.entries(change.provision ?? {}),
      ]),
    };
}
/** New entries of the host's own journal since the engine last saw it. */
async function feedJournal(run: Run) {
  await feed(run, {
    kind: "evidence",
    operations: await run.driver.localOperations(),
  });
}
const shape = (op: ReplicaOperation | undefined) =>
  op?.kind === "stream-complete"
    ? {
        generation: op.generation,
        liveCount: op.liveCount,
        snapshotSha256: op.snapshotSha256.slice("sha256:".length),
      }
    : undefined;
function engineCompletions(projection: VisibilityProjection) {
  return Object.fromEntries(
    STREAMS.flatMap((stream) => {
      const found = projection.completions[completionId("c1", stream)];
      return found ? [[stream, shape(found.operation)]] : [];
    }),
  );
}
/** Rows a reader of the projection sees. */
function engineRows(projection: VisibilityProjection) {
  const rows: Record<string, Data> = {};
  for (const [id, row] of Object.entries(projection.rows))
    if (row.state === "live") rows[id] = row.winner.data;
  return rows;
}
/**
 * Keys the projection holds and does not show: a deleted row, or one a
 * withdrawal hid after it was shown.
 */
const engineTombstones = (projection: VisibilityProjection) =>
  Object.entries(projection.rows)
    .filter(([, row]) => row.state !== "live")
    .map(([id]) => id)
    .sort();
type ConnectionState = "readable" | "withdrawn" | "deleted";
function engineConnections(run: Run, projection: VisibilityProjection) {
  return Object.fromEntries(
    [...run.world.mappings.keys()].sort().map((c) => {
      const status = projection.connections[c]?.status;
      return [
        c,
        status === "withdrawn" || status === "deleted" ? status : "readable",
      ];
    }),
  ) as Record<string, ConnectionState>;
}

interface ReaderState {
  /** Live rows from point reads. */
  point: Record<string, Data>;
  /** Live rows from full list pagination. */
  list: Record<string, Data>;
  pending: string[];
  blobs: Record<string, string | null>;
  /** Streams with a completion listed to this reader, by connection. */
  completions: Record<string, string[]>;
}
interface HostState {
  owner: ReaderState;
  grant: ReaderState;
  /** Stored tombstones. */
  tombstones: string[];
  /** Stored completions of c1, by stream. */
  completions: Record<string, ReturnType<typeof shape>>;
  /** Mapped connections only. */
  connections: Record<string, ConnectionState>;
}
const UNIVERSE = {
  connections: CONNECTIONS,
  streams: STREAMS.map((stream) => ({ stream })),
  keys: KEYS,
};
type NodeHost = ReturnType<typeof nodeDriver>;
type LiteHost = Awaited<ReturnType<typeof liteDriver>>;
const tombstonesOf = (snapshot: PortSnapshot) =>
  Object.entries(snapshot.stored)
    .filter(([, row]) => row.deleted)
    .map(([id]) => id)
    .sort();
/**
 * The state each host shows its readers, and what it stores. Node and Lite
 * expose the same facts through different APIs. Node's reads skip
 * tombstones, so the oracle reads them from its table; Lite's grant reads
 * return canonical rows, tombstones included. Lite keeps no deletion
 * marker, so its deleted connection shows only as tombstones.
 */
async function nodeState(node: NodeHost, run: Run): Promise<HostState> {
  const snapshot = await node.snapshot(UNIVERSE);
  const quarantined = new Set(
    (
      node.db
        .prepare("SELECT instance FROM pdpp_replica_quarantined_connections")
        .all() as { instance: string }[]
    ).map((row) => row.instance),
  );
  const reader = (kind: "owner" | "grant"): ReaderState => {
    const read = node.receiver.readStore({ reader: kind });
    return {
      ...snapshot[kind],
      completions: Object.fromEntries(
        CONNECTIONS.map((c) => [
          c,
          read.listStreamCompletions(c).map((receipt) => receipt.stream),
        ]),
      ),
    };
  };
  return {
    owner: reader("owner"),
    grant: reader("grant"),
    tombstones: tombstonesOf(snapshot),
    completions: storedCompletions(node),
    connections: Object.fromEntries(
      [...run.world.mappings.keys()]
        .sort()
        .map((c) => [
          c,
          node.store.getInstanceBinding(c).deletedAt !== null
            ? "deleted"
            : quarantined.has(c) || node.store.replicaBindingConflict(c)
              ? "withdrawn"
              : "readable",
        ]),
    ),
  };
}
async function liteState(lite: LiteHost, run: Run): Promise<HostState> {
  const snapshot = await lite.snapshot(UNIVERSE);
  const reader = async (kind: "owner" | "grant"): Promise<ReaderState> => {
    const completions: Record<string, string[]> = {};
    for (const c of CONNECTIONS)
      completions[c] = (
        await lite.store.readStreamCompletions(c, { reader: kind })
      ).map((op) => op.declaration.stream);
    return { ...snapshot[kind], completions };
  };
  const connections: Record<string, ConnectionState> = {};
  for (const c of [...run.world.mappings.keys()].sort())
    connections[c] = (await lite.store.isConnectionQuarantined(c))
      ? "withdrawn"
      : "readable";
  return {
    owner: await reader("owner"),
    grant: await reader("grant"),
    tombstones: tombstonesOf(snapshot),
    completions: Object.fromEntries(
      (await lite.store.readStreamCompletions("c1")).map((op) => [
        op.declaration.stream,
        shape(op),
      ]),
    ),
    connections,
  };
}
function storedCompletions(node: NodeHost) {
  return Object.fromEntries(
    (
      node.db
        .prepare(
          "SELECT stream, generation, live_count, snapshot_sha256 FROM pdpp_stream_completion WHERE instance = 'c1'",
        )
        .all() as {
        stream: string;
        generation: number;
        live_count: number;
        snapshot_sha256: string;
      }[]
    ).map((row) => [
      row.stream,
      {
        generation: row.generation,
        liveCount: row.live_count,
        snapshotSha256: row.snapshot_sha256,
      },
    ]),
  );
}
/**
 * The state the engine's projection implies for a host. No scenario stages
 * a pending batch or writes locally on a conflicted connection, so the
 * owner sees the rows a grant reader sees. The owner reads the pending
 * preview, so it is listed no completion; a grant reader is listed the
 * stored ones.
 */
function expectedState(
  run: Run,
  projection: VisibilityProjection,
  host: HostState,
): HostState {
  const point = engineRows(projection);
  const reader: ReaderState = {
    point,
    list: point,
    pending: [],
    // Each blob a live row references; the bytes are compared across hosts
    // and checked readable separately.
    blobs: Object.fromEntries(
      Object.values(point).flatMap((data) => {
        const id = (data.blob_ref as { blob_id?: string } | undefined)?.blob_id;
        return id ? [[id, host.grant.blobs[id]]] : [];
      }),
    ),
    completions: Object.fromEntries(
      CONNECTIONS.map((c) => [
        c,
        c === "c1" ? Object.keys(engineCompletions(projection)) : [],
      ]),
    ),
  };
  const owner: ReaderState = {
    ...reader,
    completions: Object.fromEntries(CONNECTIONS.map((c) => [c, []])),
  };
  const connections = engineConnections(run, projection);
  // Lite keeps no deletion marker: its deleted connection reads as readable.
  if (run.driver.name === "lite")
    for (const c of Object.keys(connections))
      if (connections[c] === "deleted") connections[c] = "readable";
  return {
    owner,
    grant: reader,
    tombstones: engineTombstones(projection),
    completions: engineCompletions(projection),
    connections,
  };
}
/**
 * The full-history projection hides a withdrawn key by leaving it out; the
 * incremental one marks it withdrawn. Both hide it from every reader.
 */
const comparable = (run: Run, projection: VisibilityProjection) => ({
  connections: Object.fromEntries(
    [...run.world.mappings.keys()]
      .sort()
      .map((c) => [c, projection.connections[c]]),
  ),
  rows: engineRows(projection),
  tombstones: Object.entries(projection.rows)
    .filter(([, row]) => row.state === "deleted")
    .map(([id]) => id)
    .sort(),
  completions: engineCompletions(projection),
});

const seen = new Set<string>();
describe("visibility differential: Node, Lite and the engine", () => {
  for (const [name, scenario] of Object.entries(SCENARIOS))
    it(
      `${name}: every prefix of ${ORDERS} orders`,
      async () => {
        let random = 11;
        for (let round = 0; round < ORDERS; round++) {
          const order = [...scenario.steps];
          // Round 0 keeps the written order; later rounds shuffle it.
          for (let i = order.length - 1; round && i > 0; i--) {
            random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
            const j = random % (i + 1);
            [order[i], order[j]] = [order[j], order[i]];
          }
          const declarations = scenario.declared.map((b) => BINDINGS[b]);
          const node = nodeDriver({
            declarations,
            provisioned: scenario.provisioned,
          });
          const lite = await liteDriver({
            persistence: liteMemoryPersistence(),
            name: "lite",
            declarations,
            provisioned: scenario.provisioned,
          });
          const runs: Run[] = [node, lite].map((driver) => ({
            driver,
            committer: createMemoryVisibilityCommitter(),
            world: {
              owner: OWNER,
              declarations: contextOf(declarations).declarations,
              mappings: new Map(
                scenario.provisioned.map((c) => [c, MAPPING] as const),
              ),
              verifiedBlobs: new Set(),
              terminal: new Set(),
            },
            evidence: [],
          }));
          try {
            for (const run of runs) await feedJournal(run);
            const delivered = new Map<string, ReplicaOperation[]>();
            for (const [index, step] of order.entries()) {
              const where = { round, index, step: canonicalJson(step) };
              for (const run of runs) {
                if (step.k === "batch" || step.k === "again") {
                  const ops =
                    step.k === "batch" ? step.ops : delivered.get(step.id);
                  if (!ops) continue;
                  const names = step.k === "again" ? (step.bytes ?? []) : [];
                  // Node refuses evidence that contradicts a mapping it
                  // already holds; a refused batch is not evidence.
                  const refused = await run.driver
                    .importBatch(`${step.id}-${index}`, ops, names.map(blobOf))
                    .then(
                      () => false,
                      (error: Error) => {
                        expect({ ...where, error: error.message }).toEqual({
                          ...where,
                          error: "replica connection source or method mismatch",
                        });
                        return true;
                      },
                    );
                  if (!refused)
                    await feed(run, {
                      kind: "evidence",
                      operations: ops,
                      verifiedBlobs: names.map(
                        (n) => blobOf(n).descriptor.blobId,
                      ),
                    });
                } else if (step.k === "declare") {
                  const bindings = step.bindings.map((b) => BINDINGS[b]);
                  await run.driver.declare(bindings);
                  await feed(run, {
                    kind: "host",
                    declarations: contextOf(bindings).declarations,
                  });
                } else if (step.k === "provision") {
                  const ok = await run.driver.provision(step.connection);
                  // Platform difference, as in the runner: Lite refuses a
                  // mapping its retained evidence contradicts; Node maps it
                  // and records the binding conflict.
                  if (run.driver.name === "lite")
                    expect({ ...where, ok }).toEqual({
                      ...where,
                      ok: !run.evidence.some(
                        (op) =>
                          op.connectionId === step.connection &&
                          op.methodId !== METHOD,
                      ),
                    });
                  if (ok)
                    await feed(run, {
                      kind: "host",
                      provision: { [step.connection]: MAPPING },
                    });
                } else {
                  await run.driver
                    .local({
                      requestId: `local-${index}`,
                      connection: "c1",
                      generation: 1,
                      binding: BINDINGS.m,
                      key: step.key,
                      data: { id: step.key, text: step.text },
                      emittedAt: "2026-10-27T00:00:01Z",
                    })
                    .catch(() => undefined);
                }
                await feedJournal(run);
              }
              if (step.k === "batch") delivered.set(step.id, step.ops);

              const [nodeRun, liteRun] = runs;
              const states = {
                node: await nodeState(node, nodeRun),
                lite: await liteState(lite, liteRun),
              };
              seen.add(
                `${name}:${Object.keys(states.node.completions).length}`,
              );
              for (const [c, state] of Object.entries(states.node.connections))
                seen.add(`${name}:${c}:${state}`);
              if (states.node.tombstones.length) seen.add(`${name}:tombstone`);
              // Connection state is compared where both hosts map the
              // connection; everything else always.
              const shared = (state: HostState) => ({
                ...state,
                connections: Object.fromEntries(
                  Object.entries(state.connections).filter(
                    ([c]) =>
                      nodeRun.world.mappings.has(c) &&
                      liteRun.world.mappings.has(c),
                  ),
                ),
              });
              expect({ ...where, lite: shared(states.lite) }).toEqual({
                ...where,
                lite: shared(states.node),
              });
              for (const run of runs) {
                const host = run.driver.name as "node" | "lite";
                const incremental = run.committer.read().projection;
                const full = evaluate(
                  {
                    epoch: INITIAL_VISIBILITY_EPOCH,
                    projection: EMPTY_PROJECTION,
                    world: run.world,
                    evidence: [],
                  },
                  { kind: "evidence", operations: run.evidence },
                );
                expect({ ...where, host, state: states[host] }).toEqual({
                  ...where,
                  host,
                  state: expectedState(run, incremental, states[host]),
                });
                // Every blob a live row references is readable.
                for (const reader of ["owner", "grant"] as const)
                  expect({
                    ...where,
                    host,
                    reader,
                    unreadable: Object.entries(states[host][reader].blobs)
                      .filter(([, bytes]) => bytes === null)
                      .map(([id]) => id),
                  }).toEqual({ ...where, host, reader, unreadable: [] });
                expect({
                  ...where,
                  host,
                  full: comparable(run, {
                    ...EMPTY_PROJECTION,
                    connections: full.connections,
                    rows: full.rows,
                    completions: full.completions,
                  } as VisibilityProjection),
                }).toEqual({
                  ...where,
                  host,
                  full: comparable(run, incremental),
                });
              }
            }
          } finally {
            node.close();
            lite.close();
          }
        }
      },
      TIMEOUT,
    );
  it("saw available and unavailable completions in every scenario", () => {
    for (const name of Object.keys(SCENARIOS)) {
      expect({ name, unavailable: seen.has(`${name}:0`) }).toEqual({
        name,
        unavailable: true,
      });
      // That scenario's written order holds the twin before any completion;
      // only some shuffled orders reach one.
      if (name !== "equivocation from a connection with a binding conflict")
        expect({ name, available: seen.has(`${name}:1`) }).toEqual({
          name,
          available: true,
        });
    }
  });
  it("reached a tombstone and a binding conflict over a foreign deletion", () => {
    expect(seen.has("a record deletion:tombstone")).toBe(true);
    const foreign = "a connection deletion that names another binding";
    expect(seen.has(`${foreign}:c2:withdrawn`)).toBe(true);
    expect(seen.has(`${foreign}:c2:deleted`)).toBe(false);
  });
});
