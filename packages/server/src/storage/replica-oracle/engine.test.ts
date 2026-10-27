/**
 * The core visibility engine judged by the frozen reference model, and its
 * completion decisions judged by the Node receiver.
 *
 * Part 1 replays generated command sequences as pure facts (no store) and
 * requires `evaluate` deltas, committed one by one, to equal `refProject`
 * after every prefix: rows, winners, applied generations and connection
 * status. Pending custody (stage/promote/drop) feeds the canonical facts only
 * when promoted; the preview is not part of the engine yet.
 *
 * Part 2 imports the events of a completion scenario into the Node receiver in
 * shuffled orders and requires the engine to make the same completion
 * decision after every prefix.
 *
 * PR CI runs fixed seeds and orders; REPLICA_ORACLE_NIGHTLY=1 runs more.
 */
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  type RecordOperation,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { operationDigest } from "@opendatalabs/personal-server-ts-core/replication/completion";
import {
  applyChange,
  completionId,
  createMemoryVisibilityCommitter,
  evaluate,
  type ConnectionMapping,
  type EvidenceChange,
  type VisibilityProjection,
  type VisibilityWorld,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-engine";
import { liveSnapshotDigest } from "../pdpp-stream-completion.js";
import {
  BINDINGS,
  blobOf,
  generateCommands,
  PROVISIONED_AT_START,
  type BindingName,
  type Command,
} from "./generator.test-utils.js";
import {
  contextOf,
  METHOD,
  nodeDriver,
  OWNER,
  SOURCE,
} from "./ports.test-utils.js";
import {
  emptyRefState,
  refConnectionStatus,
  refLocalWritable,
  refProject,
  revisionId,
  type RefState,
  type RefWorld,
} from "./reference.test-utils.js";

const nightly = process.env.REPLICA_ORACLE_NIGHTLY === "1";
const SEEDS = nightly ? 512 : 48;
const LENGTH = nightly ? 64 : 24;
const ORDERS = nightly ? 200 : 8;
const TIMEOUT = nightly ? 900_000 : 60_000;
const MAPPING: ConnectionMapping = { sourceId: SOURCE, methodId: METHOD };

/** Shared facts after each command, as the runner's reference sees them. */
interface Facts {
  confirmed: Map<string, ReplicaOperation>;
  local: ReplicaOperation[];
  bytes: Set<string>;
  declared: Set<BindingName>;
  terminal: Set<string>;
  mappings: Map<string, ConnectionMapping>;
  batches: Map<string, { ops: ReplicaOperation[]; blobs: string[] }>;
  pending: Map<string, { ops: ReplicaOperation[]; blobs: string[] }>;
}
const evidenceOf = (facts: Facts) => [
  ...facts.confirmed.values(),
  ...facts.local,
];
const refWorld = (facts: Facts): RefWorld => ({
  owner: OWNER,
  mappings: facts.mappings,
  declarations: [...facts.declared].map((b) => ({
    sourceId: SOURCE,
    binding: BINDINGS[b],
  })),
  bytes: facts.bytes,
  terminal: facts.terminal,
});
const engineWorld = (facts: Facts): VisibilityWorld => ({
  owner: OWNER,
  declarations: contextOf([...facts.declared].map((b) => BINDINGS[b]))
    .declarations,
  mappings: new Map(facts.mappings),
  verifiedBlobs: new Set(facts.bytes),
  terminal: new Set(facts.terminal),
});
const admissible = (facts: Facts, ops: readonly ReplicaOperation[]) =>
  ops.every((op) => {
    const mapping = facts.mappings.get(op.connectionId);
    return (
      !mapping ||
      (mapping.sourceId === op.sourceId && mapping.methodId === op.methodId)
    );
  });

/** Apply one command to the facts; return the engine change it amounts to. */
function step(
  facts: Facts,
  command: Command,
  counter: number,
): EvidenceChange[] {
  const accept = (ops: ReplicaOperation[], blobs: string[]) => {
    if (!admissible(facts, ops)) return [];
    for (const op of ops) facts.confirmed.set(canonicalJson(op), op);
    const ids = blobs.map((name) => blobOf(name).descriptor.blobId);
    for (const id of ids) facts.bytes.add(id);
    return [{ kind: "evidence", operations: ops, verifiedBlobs: ids } as const];
  };
  switch (command.k) {
    case "import":
      facts.batches.set(command.id, { ops: command.ops, blobs: command.blobs });
      return accept(command.ops, command.blobs);
    case "dup": {
      const batch = facts.batches.get(command.id);
      return batch ? accept(batch.ops, batch.blobs) : [];
    }
    case "bytes": {
      const batch = facts.batches.get(command.id);
      if (!batch) return [];
      const claimed = batch.ops.flatMap((op) =>
        op.kind === "blob-claim" ? [op.blob.blobId] : [],
      );
      const known = new Set(
        ["b0", "b1", "b2"].map((n) => blobOf(n).descriptor.blobId),
      );
      const ids = [
        ...batch.blobs.map((name) => blobOf(name).descriptor.blobId),
        ...claimed.filter((id) => known.has(id)),
      ];
      if (!admissible(facts, batch.ops)) return [];
      for (const op of batch.ops) facts.confirmed.set(canonicalJson(op), op);
      for (const id of ids) facts.bytes.add(id);
      return [{ kind: "evidence", operations: batch.ops, verifiedBlobs: ids }];
    }
    case "declare":
      facts.declared.add(command.binding);
      return [
        {
          kind: "host",
          declarations: contextOf([BINDINGS[command.binding]]).declarations,
        },
      ];
    case "quarantine":
      facts.terminal.add(command.connection);
      return [{ kind: "host", terminal: [command.connection] }];
    case "provision":
      facts.mappings.set(command.connection, MAPPING);
      return [{ kind: "host", provision: { [command.connection]: MAPPING } }];
    case "local": {
      const world = refWorld(facts);
      const evidence = evidenceOf(facts);
      const { generation } = refConnectionStatus(
        world,
        evidence,
        command.connection,
      );
      const op: RecordOperation = {
        owner: OWNER,
        sourceId: SOURCE,
        connectionId: command.connection,
        methodId: METHOD,
        generation,
        kind: "upsert",
        declaration: BINDINGS[command.binding],
        recordKey: command.key,
        emittedAt: "2026-10-22T00:00:00Z",
        data: { id: command.key, text: command.text },
        blobs: [],
        revision: { counter, writerId: "w-local", operationId: command.id },
      };
      if (!refLocalWritable(world, evidence, op)) return [];
      facts.local.push(op);
      return [{ kind: "evidence", operations: [op] }];
    }
    case "stage":
      if (admissible(facts, command.ops))
        facts.pending.set(command.id, {
          ops: command.ops,
          blobs: command.blobs,
        });
      return [];
    case "promote": {
      const batch = facts.pending.get(command.id);
      facts.pending.delete(command.id);
      return batch ? accept(batch.ops, batch.blobs) : [];
    }
    case "drop":
      facts.pending.delete(command.id);
      return [];
    case "retry":
    case "reopen":
      return [];
  }
}

/** The reference state the engine projection stands for. */
function asRef(projection: VisibilityProjection) {
  const rows: Record<string, unknown> = {};
  const winners: Record<string, string> = {};
  for (const [id, row] of Object.entries(projection.rows)) {
    rows[id] =
      row.state === "live"
        ? { deleted: false, data: row.winner.data }
        : { deleted: true };
    if (row.state !== "withdrawn") winners[id] = revisionId(row.winner);
  }
  return { rows, winners };
}
const fromRef = (state: RefState) => ({
  rows: Object.fromEntries(state.rows),
  winners: Object.fromEntries(state.winners),
});

describe(`engine against the frozen reference (${SEEDS} seeds × ${LENGTH} commands)`, () => {
  it(
    "agrees after every prefix",
    async () => {
      for (let i = 0; i < SEEDS; i++) {
        const seed = (0x9e3779b9 * (i + 1)) >>> 0;
        const commands = generateCommands(seed, { length: LENGTH });
        const facts: Facts = {
          confirmed: new Map(),
          local: [],
          bytes: new Set(),
          declared: new Set(["m", "a"]),
          terminal: new Set(),
          mappings: new Map(PROVISIONED_AT_START.map((c) => [c, MAPPING])),
          batches: new Map(),
          pending: new Map(),
        };
        let ref = emptyRefState();
        const committer = createMemoryVisibilityCommitter();
        let world = engineWorld(facts);
        let evidence: readonly ReplicaOperation[] = [];
        for (const [prefix, command] of commands.entries()) {
          for (const change of step(facts, command, 1000 + prefix)) {
            const { epoch, projection } = committer.read();
            const delta = evaluate(
              { epoch, projection, world, evidence },
              change,
            );
            await committer.commit(epoch, delta, {});
            ({ world, evidence } = applyChange({ world, evidence }, change));
          }
          ref = refProject(ref, refWorld(facts), evidenceOf(facts));
          const projection = committer.read().projection;
          const where = { seed, prefix, command };
          expect({ ...where, ...asRef(projection) }).toEqual({
            ...where,
            ...fromRef(ref),
          });
          for (const [connection] of facts.mappings) {
            const expected = refConnectionStatus(
              refWorld(facts),
              evidenceOf(facts),
              connection,
            );
            const actual = projection.connections[connection];
            expect({
              ...where,
              connection,
              status: actual?.status ?? "held",
            }).toEqual({
              ...where,
              connection,
              status: expected.status === "unmapped" ? "held" : expected.status,
            });
            expect({
              ...where,
              connection,
              generation: actual?.generation ?? 1,
            }).toEqual({
              ...where,
              connection,
              generation: ref.generations.get(connection) ?? 1,
            });
          }
        }
      }
    },
    TIMEOUT,
  );
});

// ------------------------------------------------- completions against Node

const at = (connectionId: string) => ({
  owner: OWNER,
  sourceId: SOURCE,
  connectionId,
  methodId: METHOD,
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
  text: string,
  counter: number,
): ReplicaOperation => ({
  ...at(c),
  kind: "upsert",
  declaration: BINDINGS.m,
  recordKey: key,
  emittedAt: "2026-10-27T00:00:00Z",
  data: { id: key, text },
  blobs: [],
  revision: rev(counter, `${c}-${key}-${counter}`),
});
const complete = (
  c: string,
  dependencies: ReplicaOperation[],
  rows: Record<string, string>,
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
    Object.entries(rows).map(([recordKey, text]) => ({
      recordKey,
      dataJson: canonicalJson({ id: recordKey, text }),
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

describe("completion decisions against the Node receiver", () => {
  const k0 = put("c1", "k0", "zero", 2);
  const k1 = put("c1", "k1", "one", 3);
  const k1b = put("c1", "k1", "one again", 7);
  const scenarios: Record<string, ReplicaOperation[]> = {
    "dependencies, a later write and a later completion": [
      k0,
      k1,
      complete("c1", [k0, k1], { k0: "zero", k1: "one" }, 5),
      k1b,
      complete("c1", [k0, k1b], { k0: "zero", k1: "one again" }, 8),
    ],
    "invalidation, a wrong digest and append-only evidence": [
      k0,
      complete("c1", [k0], { k0: "zero" }, 5),
      complete("c1", [k0], { k0: "wrong" }, 6),
      {
        ...at("c1"),
        kind: "stream-invalidate",
        declaration: BINDINGS.m,
        revision: rev(9, "invalidate"),
      },
      {
        ...put("c1", "k2", "append", 4),
        declaration: BINDINGS.a,
      },
    ],
    "a dependency only an unprovisioned connection holds": [
      k0,
      put("c3", "x", "elsewhere", 4),
      complete("c1", [k0, put("c3", "x", "elsewhere", 4)], { k0: "zero" }, 5),
    ],
  };
  const seen = new Set<boolean>();
  for (const [name, events] of Object.entries(scenarios))
    it(
      `${name}: every prefix of ${ORDERS} orders`,
      async () => {
        let random = 7;
        for (let round = 0; round < ORDERS; round++) {
          const order = [...events];
          for (let i = order.length - 1; i > 0; i--) {
            random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
            const j = random % (i + 1);
            [order[i], order[j]] = [order[j], order[i]];
          }
          const node = nodeDriver({
            declarations: [BINDINGS.m, BINDINGS.a],
            provisioned: ["c1"],
          });
          try {
            const world: VisibilityWorld = {
              owner: OWNER,
              declarations: contextOf([BINDINGS.m, BINDINGS.a]).declarations,
              mappings: new Map([["c1", MAPPING]]),
              verifiedBlobs: new Set(),
              terminal: new Set(),
            };
            const committer = createMemoryVisibilityCommitter();
            // Node's own journal registers each provisioned connection.
            let evidence = await node.localOperations();
            await committer.commit(
              committer.read().epoch,
              evaluate(
                { ...committer.read(), world, evidence: [] },
                { kind: "evidence", operations: evidence },
              ),
              {},
            );
            for (const [index, op] of order.entries()) {
              await node.importBatch(`b${index}`, [op], []);
              const { epoch, projection } = committer.read();
              const change: EvidenceChange = {
                kind: "evidence",
                operations: [op],
              };
              await committer.commit(
                epoch,
                evaluate({ epoch, projection, world, evidence }, change),
                {},
              );
              evidence = [...evidence, op];
              const engine =
                committer.read().projection.completions[
                  completionId("c1", "messages")
                ];
              const stored = node.store.listStreamCompletions("c1");
              seen.add(stored.length === 1);
              expect({ round, index, available: engine !== undefined }).toEqual(
                {
                  round,
                  index,
                  available: stored.length === 1,
                },
              );
              if (engine && stored[0])
                expect(stored[0]).toMatchObject({
                  generation: engine.operation.generation,
                  liveCount: engine.operation.liveCount,
                });
            }
          } finally {
            node.close();
          }
        }
      },
      TIMEOUT,
    );
  it("saw both available and unavailable completions", () => {
    expect([...seen].sort()).toEqual([false, true]);
  });
});
