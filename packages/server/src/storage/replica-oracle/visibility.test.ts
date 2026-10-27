/**
 * Node, Lite and the visibility engine judged against each other on
 * completion availability and visible rows.
 *
 * Each scenario is a set of steps: batch deliveries, repeated deliveries,
 * late bytes, late declarations, late provisioning and local writes. Every
 * round shuffles the steps and, after each one, requires:
 * - Node's stored completions to equal Lite's certified completions;
 * - both to equal the engine fed the same changes one by one (incremental),
 *   and the engine fed all of the host's evidence at once (full history);
 * - Node's and Lite's grant-visible rows to equal the incremental engine's.
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
function engineRows(projection: VisibilityProjection) {
  const rows: Record<string, Data> = {};
  for (const [id, row] of Object.entries(projection.rows))
    if (row.state === "live") rows[id] = row.winner.data;
  return rows;
}

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
              const nodeStored = Object.fromEntries(
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
              const liteStored = Object.fromEntries(
                (await lite.store.readStreamCompletions("c1")).map((op) => [
                  op.declaration.stream,
                  shape(op),
                ]),
              );
              // Reader gating: a reader that sees the pending preview gets
              // no completion on either host; others get the stored ones.
              for (const reader of ["owner", "grant"] as const)
                expect({
                  ...where,
                  reader,
                  lite: (
                    await lite.store.readStreamCompletions("c1", { reader })
                  ).map((op) => op.declaration.stream),
                }).toEqual({
                  ...where,
                  reader,
                  lite: node.receiver
                    .readStore({ reader })
                    .listStreamCompletions("c1")
                    .map((receipt) => receipt.stream),
                });
              seen.add(`${name}:${Object.keys(nodeStored).length}`);
              expect({ ...where, lite: liteStored }).toEqual({
                ...where,
                lite: nodeStored,
              });
              for (const [run, stored] of [
                [nodeRun, nodeStored],
                [liteRun, liteStored],
              ] as const) {
                const host = run.driver.name;
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
                expect({ ...where, host, stored }).toEqual({
                  ...where,
                  host,
                  stored: engineCompletions(incremental),
                });
                expect({
                  ...where,
                  host,
                  full: engineCompletions({
                    ...EMPTY_PROJECTION,
                    completions: full.completions,
                  } as VisibilityProjection),
                }).toEqual({
                  ...where,
                  host,
                  full: engineCompletions(incremental),
                });
                const visible = (
                  await run.driver.snapshot({
                    connections: CONNECTIONS,
                    streams: STREAMS.map((stream) => ({ stream })),
                    keys: KEYS,
                  })
                ).grant.point;
                expect({ ...where, host, visible }).toEqual({
                  ...where,
                  host,
                  visible: engineRows(incremental),
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
});
