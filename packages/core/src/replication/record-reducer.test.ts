import { describe, expect, it } from "vitest";
import { createReplicaRecordReducer } from "./record-reducer.js";
import { planReplicaMerge, type MergeContext } from "./merge-plan.js";
import {
  binding,
  identity,
  registration,
  mutableVectors,
  upsert,
} from "./fixtures.js";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { encodeLiveSnapshotDigestInput } from "../storage/pdpp-records/completion.js";
import { operationDigest } from "./completion.js";
import {
  canonicalJson,
  type DeclarationBinding,
  type ReplicaOperation,
  type RecordOperation,
} from "./envelope.js";
import {
  applyChange,
  blobReady,
  completionAvailability,
  completionId,
  connectionFromFacts,
  createMemoryVisibilityCommitter,
  EMPTY_PROJECTION,
  evaluate,
  evidenceDigest,
  recordRow,
  rowId,
  stepConnectionRows,
  type CompletionProjection,
  type ConnectionFacts,
  type EvidenceChange,
  type RowProjection,
  type VisibilityProjection,
  type VisibilityWorld,
} from "./visibility-engine.js";

const visible = (
  record: ReturnType<typeof planReplicaMerge>["records"][number] | undefined,
) =>
  record
    ? {
        identity: record.identity,
        winner: record.winner,
        quarantined: record.quarantined,
      }
    : undefined;
for (const semantics of ["mutable_state", "append_only"] as const)
  describe(`${semantics} bounded record reducer`, () => {
    it("matches the complete shared planner across deterministic permutations", () => {
      const declaration = { ...binding, semantics };
      const alternate = {
        ...declaration,
        version: "2",
        digest: `sha256:${"c".repeat(64)}`,
      };
      const context: MergeContext = {
        owner: identity.owner,
        declarations: [declaration, alternate].map((binding) => ({
          sourceId: identity.sourceId,
          binding,
          validateData: (data) => typeof data.id === "string",
        })),
      };
      const records: RecordOperation[] = mutableVectors.map((op) => ({
        ...op,
        declaration,
      }));
      records.push({ ...upsert("alternate", 3), declaration: alternate });
      records.push({
        ...upsert("invalid", 20),
        data: { wrong: "key" },
        declaration,
      });
      records.push({ ...upsert("future", 21), generation: 2, declaration });
      const lifecycles: ReplicaOperation[][] = [
        [],
        [registration],
        [
          registration,
          {
            ...identity,
            kind: "connection-reset",
            generation: 2,
            previousGeneration: 1,
            revision: { counter: 7, writerId: "writer", operationId: "reset2" },
          },
        ],
        [
          registration,
          {
            ...identity,
            kind: "connection-reset",
            generation: 3,
            previousGeneration: 2,
            revision: { counter: 7, writerId: "writer", operationId: "reset3" },
          },
        ],
        [
          registration,
          {
            ...identity,
            kind: "connection-delete",
            revision: { counter: 9, writerId: "writer", operationId: "delete" },
          },
        ],
      ];
      let random = 17;
      for (let round = 0; round < 100; round++) {
        const ordered = [...records];
        for (let i = ordered.length - 1; i > 0; i--) {
          random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
          const j = random % (i + 1);
          [ordered[i], ordered[j]] = [ordered[j], ordered[i]];
        }
        const lifecycle = lifecycles[round % lifecycles.length];
        const reducer = createReplicaRecordReducer(context, lifecycle);
        for (const operation of ordered) {
          reducer.push(operation);
          reducer.push(operation);
        }
        expect(visible(reducer.record)).toEqual(
          visible(
            planReplicaMerge(context, [...lifecycle, ...ordered]).records[0],
          ),
        );
      }
    }, 30000);
  });

// ---------------------------------------------------------------------------
// Bounded evaluation against the full-history oracle.
//
// A bounded engine sees one key at a time through the reducer, plus the
// per-connection facts its durable indexes hold (`ConnectionFacts`). These
// families deliver every event in shuffled order, each operation twice, and
// after EVERY prefix require the bounded projection, the reference
// projection (planReplicaMerge over all evidence) and the committed sequence
// of `evaluate` deltas to agree. PR runs a fixed sample; nightly
// (REPLICA_ORACLE_NIGHTLY=1) runs many more orders.

const nightly = process.env.REPLICA_ORACLE_NIGHTLY === "1";
const ORDERS = nightly ? 1500 : 24;

type Event =
  | { k: "op"; op: ReplicaOperation }
  | { k: "declare"; binding: DeclarationBinding }
  | { k: "bytes"; blobId: string }
  | { k: "provision"; connectionId: string }
  | { k: "terminal"; connectionId: string };

const MAPPING = { sourceId: identity.sourceId, methodId: identity.methodId };
const declared = (binding: DeclarationBinding) => ({
  sourceId: identity.sourceId,
  binding,
  validateData: (data: Record<string, unknown>) => typeof data.id === "string",
});
const at = (connectionId: string) => ({ ...identity, connectionId });
const rev = (counter: number, operationId: string, writerId = "w") => ({
  counter,
  writerId,
  operationId,
});
const register = (c: string, id = `reg-${c}`): ReplicaOperation => ({
  ...at(c),
  kind: "connection-register",
  revision: rev(1, id),
});
const reset = (c: string, generation: number, counter: number) =>
  ({
    ...at(c),
    kind: "connection-reset",
    generation,
    previousGeneration: generation - 1,
    revision: rev(counter, `reset-${c}-${generation}`),
  }) satisfies ReplicaOperation;
const removeConnection = (c: string, counter: number): ReplicaOperation => ({
  ...at(c),
  kind: "connection-delete",
  revision: rev(counter, `delete-${c}`),
});
const put = (
  c: string,
  key: string,
  text: string,
  revision: ReturnType<typeof rev>,
  extra: Partial<Extract<RecordOperation, { kind: "upsert" }>> = {},
): RecordOperation => ({
  ...at(c),
  kind: "upsert",
  declaration: binding,
  recordKey: key,
  emittedAt: "2026-10-27T00:00:00Z",
  data: { id: key, text },
  blobs: [],
  revision,
  ...extra,
});
const tombstone = (
  c: string,
  key: string,
  revision: ReturnType<typeof rev>,
  generation = 1,
): RecordOperation => ({
  ...at(c),
  generation,
  kind: "delete",
  declaration: binding,
  recordKey: key,
  emittedAt: "2026-10-27T00:00:00Z",
  deletedAt: "2026-10-27T00:00:00Z",
  revision,
});
const snapshotDigest = (
  c: string,
  rows: Record<string, Record<string, unknown>>,
) =>
  `sha256:${bytesToHex(
    sha256(
      encodeLiveSnapshotDigestInput(
        {
          sourceId: identity.sourceId,
          instance: c,
          method: identity.methodId,
          generation: 1,
          stream: binding.stream,
        },
        binding.primaryKey,
        Object.entries(rows).map(([recordKey, data]) => ({
          recordKey,
          dataJson: canonicalJson(data),
        })),
      ),
    ),
  )}`;
const complete = (
  c: string,
  dependencies: readonly ReplicaOperation[],
  rows: Record<string, Record<string, unknown>>,
  revision: ReturnType<typeof rev>,
): ReplicaOperation => ({
  ...at(c),
  kind: "stream-complete",
  declaration: binding,
  sourceCollectedAt: "2026-10-27T00:00:00Z",
  liveCount: Object.keys(rows).length,
  snapshotSha256: snapshotDigest(c, rows),
  proof: {
    kind: "producer-asserted",
    snapshotSha256: null,
    collectionTimeBasis: null,
  },
  dependencies: dependencies.map((op) => ({
    writerId: op.revision.writerId,
    operationId: op.revision.operationId,
    digest: operationDigest(op),
  })),
  revision,
});

const ops = (...list: ReplicaOperation[]): Event[] =>
  list.map((op) => ({ k: "op", op }));
const alternate: DeclarationBinding = {
  ...binding,
  version: "2.0.0",
  digest: `sha256:${"d".repeat(64)}`,
};
const blob = {
  blobId: `sha256:${"e".repeat(64)}`,
  sha256: `sha256:${"e".repeat(64)}`,
  mimeType: "text/plain",
  sizeBytes: 3,
};
const k1 = put("c-a", "k1", "one", rev(2, "p1"));
const k2 = put("c-a", "k2", "two", rev(3, "p2"));
const FAMILIES: { name: string; events: Event[] }[] = [
  {
    name: "cross-key operation-id collisions",
    events: [
      ...ops(register("c-a"), register("c-b"), register("c-u"), k1, k2),
      // Same (writerId, operationId) as k1, another key: withdraws c-a.
      ...ops(put("c-a", "k2", "other", rev(2, "p1"))),
      // Cross-connection: reuses c-b's revision id with other bytes on c-u,
      // which is unmapped until provisioned.
      ...ops(
        put("c-b", "k1", "b", rev(4, "pb")),
        put("c-u", "k9", "u", rev(4, "pb")),
      ),
      { k: "provision", connectionId: "c-u" },
    ],
  },
  {
    name: "reset and deletion",
    events: [
      ...ops(
        register("c-a"),
        k1,
        k2,
        tombstone("c-a", "k2", rev(5, "t2")),
        reset("c-a", 2, 6),
        put("c-a", "k1", "gen2", rev(7, "p1g2"), { generation: 2 }),
        // Generation 3 needs reset 3; without it the connection is held.
        put("c-a", "k2", "gen3", rev(9, "p2g3"), { generation: 3 }),
        reset("c-a", 3, 8),
        register("c-b"),
        put("c-b", "k1", "b", rev(2, "pb1")),
        tombstone("c-b", "k1", rev(3, "tb1")),
        put("c-b", "k1", "resurrected", rev(4, "pb2")),
        removeConnection("c-b", 9),
      ),
    ],
  },
  {
    name: "missing declarations",
    events: [
      ...ops(
        register("c-a"),
        put("c-a", "k1", "v1", rev(2, "p1"), { declaration: alternate }),
        put("c-a", "k2", "v2", rev(3, "p2"), { declaration: alternate }),
        put("c-a", "k2", "v1", rev(4, "p3")),
        put("c-a", "k3", "x", rev(5, "p4"), { data: { wrong: "key" } }),
        complete("c-a", [], {}, rev(6, "c0")),
        register("c-b"),
        // Evidence that disagrees with the local mapping of c-b.
        { ...put("c-b", "k1", "m", rev(7, "pm")), methodId: "other-method" },
      ),
      { k: "declare", binding: alternate },
    ],
  },
  {
    name: "completion dependencies",
    events: [
      ...ops(
        register("c-a"),
        register("c-b"),
        k1,
        k2,
        complete(
          "c-a",
          [k1, k2],
          {
            k1: k1.kind === "upsert" ? k1.data : {},
            k2: k2.kind === "upsert" ? k2.data : {},
          },
          rev(10, "done"),
        ),
        // Depends on a c-b operation that later equivocates with c-u.
        put("c-b", "k1", "b", rev(2, "pb")),
        complete(
          "c-b",
          [put("c-b", "k1", "b", rev(2, "pb"))],
          { k1: { id: "k1", text: "b" } },
          rev(5, "done-b"),
        ),
        put("c-u", "k1", "u", rev(2, "pb")),
        {
          ...at("c-a"),
          kind: "stream-invalidate",
          declaration: binding,
          revision: rev(11, "invalidate"),
        },
      ),
    ],
  },
  {
    name: "blob references",
    events: [
      ...ops(
        register("c-a"),
        put("c-a", "k1", "with bytes", rev(2, "p1"), {
          data: { id: "k1", text: "b", blob_ref: { blob_id: blob.blobId } },
          blobs: [blob],
        }),
        { ...at("c-a"), kind: "blob-claim", blob, revision: rev(3, "claim") },
        put("c-a", "k1", "plain", rev(4, "p2")),
        register("c-b"),
        put("c-b", "k1", "b", rev(2, "pb")),
      ),
      { k: "bytes", blobId: blob.blobId },
      { k: "terminal", connectionId: "c-b" },
    ],
  },
];

/** Indexes a bounded host keeps, from which it derives `ConnectionFacts`. */
function boundedProject(
  prior: VisibilityProjection,
  world: VisibilityWorld,
  evidence: readonly ReplicaOperation[],
): VisibilityProjection {
  const context = { owner: world.owner, declarations: world.declarations };
  const owned = evidence.filter((op) => op.owner === world.owner);
  const revisionId = (op: ReplicaOperation) =>
    canonicalJson([op.revision.writerId, op.revision.operationId]);
  const variants = new Map<string, Set<string>>();
  for (const op of owned)
    variants.set(
      revisionId(op),
      (variants.get(revisionId(op)) ?? new Set()).add(operationDigest(op)),
    );
  const unique = (op: ReplicaOperation) =>
    variants.get(revisionId(op))!.size === 1;
  const mappedVariants = new Map<string, Set<string>>();
  for (const op of owned)
    if (world.mappings.has(op.connectionId))
      mappedVariants.set(
        revisionId(op),
        (mappedVariants.get(revisionId(op)) ?? new Set()).add(
          operationDigest(op),
        ),
      );
  const connections = { ...prior.connections };
  const rows: Record<string, RowProjection> = { ...prior.rows };
  const streams = new Map<
    string,
    { quarantined: boolean; unresolved: boolean }
  >();
  for (const [id, mapping] of world.mappings) {
    const mine = owned.filter((op) => op.connectionId === id);
    const facts: ConnectionFacts = {
      mapping,
      terminal: world.terminal.has(id),
      equivocated: mine.some((op) => !unique(op)),
      bindings: mine.map(({ sourceId, methodId }) => ({ sourceId, methodId })),
      lifecycle: mine.filter(
        (op) => op.kind.startsWith("connection-") && unique(op),
      ),
      appliedGeneration: prior.connections[id]?.generation ?? 1,
    };
    const connection = connectionFromFacts(context, facts);
    connections[id] = connection;
    stepConnectionRows(rows, id, facts.appliedGeneration, connection);
    if (connection.status !== "active") continue;
    const partitions = new Map<string, RecordOperation[]>();
    for (const op of mine)
      if (op.kind === "upsert" || op.kind === "delete") {
        const key = rowId(id, op.declaration.stream, op.recordKey);
        partitions.set(key, [...(partitions.get(key) ?? []), op]);
      }
    for (const [key, partition] of partitions) {
      const stream = completionId(id, op0(partition).declaration.stream);
      const state = streams.get(stream) ?? {
        quarantined: false,
        unresolved: false,
      };
      streams.set(stream, state);
      // Per-key issues, from the same partition the reducer sees.
      const issues = planReplicaMerge(context, [
        ...facts.lifecycle,
        ...partition,
      ]);
      state.unresolved ||= [
        ...issues.pending,
        ...issues.conflicts,
        ...issues.rejected,
      ].some((issue) => issue.reason !== "missing_declaration");
      const reducer = createReplicaRecordReducer(context, facts.lifecycle);
      for (const op of partition) reducer.push(op);
      const record = reducer.record;
      if (!record) continue;
      state.quarantined ||= record.quarantined;
      const ready = (op: Extract<RecordOperation, { kind: "upsert" }>) =>
        blobReady(op, mine, world.verifiedBlobs);
      if (record.winner?.kind === "upsert" && !ready(record.winner))
        state.unresolved = true;
      const row = recordRow(rows[key], record, ready);
      if (row) rows[key] = row;
    }
  }
  const completions: Record<string, CompletionProjection> = {};
  const events = new Map<
    string,
    Extract<
      ReplicaOperation,
      { kind: "stream-complete" | "stream-invalidate" }
    >[]
  >();
  for (const op of owned)
    if (
      (op.kind === "stream-complete" || op.kind === "stream-invalidate") &&
      connections[op.connectionId]?.generation === op.generation
    ) {
      const key = completionId(op.connectionId, op.declaration.stream);
      events.set(key, [...(events.get(key) ?? []), op]);
    }
  for (const [key, list] of events) {
    const [connectionId, stream] = JSON.parse(key) as string[];
    const state = streams.get(key) ?? { quarantined: false, unresolved: false };
    const available = completionAvailability({
      connection: connections[connectionId],
      connectionId,
      events: list,
      declarations: world.declarations,
      quarantinedKey: state.quarantined,
      unresolved: state.unresolved,
      variantDigests: (writerId, operationId) => [
        ...(mappedVariants.get(canonicalJson([writerId, operationId])) ?? []),
      ],
      liveRows: Object.entries(rows).flatMap(([id, row]) => {
        const [c, s, recordKey] = JSON.parse(id) as string[];
        return c === connectionId && s === stream && row.state === "live"
          ? [{ recordKey, dataJson: canonicalJson(row.winner.data) }]
          : [];
      }),
    });
    if (available) completions[key] = available;
  }
  return { connections, rows, completions };
}
const op0 = (partition: RecordOperation[]) => partition[0];

/** What every order must end at, beyond agreement. */
const live = (projection: VisibilityProjection) =>
  Object.fromEntries(
    Object.entries(projection.rows).flatMap(([id, row]) =>
      row.state === "live" ? [[id, row.winner.data.text]] : [],
    ),
  );
const statuses = (projection: VisibilityProjection) =>
  Object.fromEntries(
    Object.entries(projection.connections).map(([id, c]) => [
      id,
      c.status === "withdrawn" || c.status === "held"
        ? `${c.status}:${c.reason}`
        : `${c.status}:${c.generation}`,
    ]),
  );
const DESTINATIONS: Record<string, { live: object; statuses: object }> = {
  "cross-key operation-id collisions": {
    live: {},
    statuses: {
      "c-a": "withdrawn:operation_id_equivocation",
      "c-b": "withdrawn:operation_id_equivocation",
      "c-u": "withdrawn:operation_id_equivocation",
    },
  },
  "reset and deletion": {
    live: { [rowId("c-a", "messages", "k2")]: "gen3" },
    statuses: { "c-a": "active:3", "c-b": "deleted:1" },
  },
  "missing declarations": {
    live: { [rowId("c-a", "messages", "k1")]: "v1" },
    statuses: { "c-a": "active:1", "c-b": "withdrawn:local_mapping_conflict" },
  },
  "completion dependencies": {
    live: {},
    statuses: {
      "c-a": "active:1",
      "c-b": "withdrawn:operation_id_equivocation",
    },
  },
  "blob references": {
    live: { [rowId("c-a", "messages", "k1")]: "plain" },
    statuses: { "c-a": "active:1", "c-b": "withdrawn:terminal_quarantine" },
  },
};
DESTINATIONS["completion dependencies"].live = {
  [rowId("c-a", "messages", "k1")]: "one",
  [rowId("c-a", "messages", "k2")]: "two",
};

describe("bounded visibility evaluation matches the full-history planner", () => {
  for (const family of FAMILIES)
    it(`${family.name}: every prefix of ${ORDERS} delivery orders`, async () => {
      let random = 29;
      const seen = { completion: false, attach: false, fence: false };
      for (let round = 0; round < ORDERS; round++) {
        const order = [...family.events];
        for (let i = order.length - 1; i > 0; i--) {
          random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
          const j = random % (i + 1);
          [order[i], order[j]] = [order[j], order[i]];
        }
        let world: VisibilityWorld = {
          owner: identity.owner,
          declarations: [declared(binding)],
          mappings: new Map([
            ["c-a", MAPPING],
            ["c-b", MAPPING],
          ]),
          verifiedBlobs: new Set(),
          terminal: new Set(),
        };
        let evidence: ReplicaOperation[] = [];
        let bounded = EMPTY_PROJECTION;
        const committer = createMemoryVisibilityCommitter();
        let receipt;
        for (const event of order) {
          const change: EvidenceChange =
            event.k === "op"
              ? { kind: "evidence", operations: [event.op, event.op] }
              : event.k === "bytes"
                ? {
                    kind: "evidence",
                    operations: [],
                    verifiedBlobs: [event.blobId],
                  }
                : event.k === "declare"
                  ? { kind: "host", declarations: [declared(event.binding)] }
                  : event.k === "terminal"
                    ? { kind: "host", terminal: [event.connectionId] }
                    : {
                        kind: "host",
                        provision: { [event.connectionId]: MAPPING },
                      };
          const { epoch, projection } = committer.read();
          // The reference: planReplicaMerge over all evidence, as deltas.
          const delta = evaluate(
            { epoch, projection, world, evidence },
            change,
          );
          receipt = await committer.commit(epoch, delta, {});
          ({ world, evidence } = applyChange({ world, evidence }, change));
          bounded = boundedProject(bounded, world, evidence);
          expect(bounded).toEqual(committer.read().projection);
          seen.completion ||= Object.values(delta.completions).some(Boolean);
          seen.attach ||= delta.blobs.attach.length > 0;
          seen.fence ||= delta.fences.length > 0;
        }
        expect(receipt!.evidenceDigest).toBe(evidenceDigest(world, evidence));
        expect(live(bounded)).toEqual(DESTINATIONS[family.name].live);
        expect(statuses(bounded)).toEqual(DESTINATIONS[family.name].statuses);
      }
      expect(seen.fence).toBe(true);
      if (family.name === "completion dependencies")
        expect(seen.completion).toBe(true);
      if (family.name === "blob references") expect(seen.attach).toBe(true);
    }, 120000);
});
