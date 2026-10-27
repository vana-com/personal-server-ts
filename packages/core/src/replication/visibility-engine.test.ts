import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import { encodeLiveSnapshotDigestInput } from "../storage/pdpp-records/completion.js";
import { operationDigest } from "./completion.js";
import {
  canonicalJson,
  type RecordOperation,
  type ReplicaOperation,
} from "./envelope.js";
import { binding, identity, registration, upsert } from "./fixtures.js";
import {
  applyChange,
  blobReady,
  checkpointDigest,
  commitRequestDigest,
  completionAvailability,
  completionId,
  connectionVisibilityState,
  createMemoryVisibilityCommitter,
  deltaDigest,
  diffProjection,
  EMPTY_PROJECTION,
  evaluate,
  evidenceDigest,
  INITIAL_VISIBILITY_EPOCH,
  rowId,
  visibilityEpoch,
  VisibilityEpochConflict,
  type CompletionFacts,
  type EvidenceChange,
  type VisibilityProjection,
  type VisibilityWorld,
} from "./visibility-engine.js";
import { replicaStateVisible } from "./visibility-policy.js";

const C = identity.connectionId;
const world: VisibilityWorld = {
  owner: identity.owner,
  declarations: [
    {
      sourceId: identity.sourceId,
      binding,
      validateData: (data) => typeof data.id === "string",
    },
  ],
  mappings: new Map([
    [C, { sourceId: identity.sourceId, methodId: identity.methodId }],
  ]),
  verifiedBlobs: new Set(),
  terminal: new Set(),
};
const key = (recordKey: string, text: string, counter: number) => ({
  ...upsert(`${recordKey}-${counter}`, counter, text),
  recordKey,
  data: { id: recordKey, text },
});
const a = key("a", "A", 2);
const b = key("b", "B", 3);
const digestOf = (rows: Record<string, unknown>[]) =>
  `sha256:${bytesToHex(
    sha256(
      encodeLiveSnapshotDigestInput(
        {
          sourceId: identity.sourceId,
          instance: C,
          method: identity.methodId,
          generation: 1,
          stream: binding.stream,
        },
        binding.primaryKey,
        rows.map((data) => ({
          recordKey: String(data.id),
          dataJson: canonicalJson(data),
        })),
      ),
    ),
  )}`;
const completion = (
  dependencies: readonly ReplicaOperation[],
  rows: Record<string, unknown>[],
  counter = 10,
) =>
  ({
    ...identity,
    kind: "stream-complete",
    declaration: binding,
    sourceCollectedAt: "2026-10-27T00:00:00Z",
    liveCount: rows.length,
    snapshotSha256: digestOf(rows),
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
    revision: { counter, writerId: "device-a", operationId: `done-${counter}` },
  }) satisfies ReplicaOperation;

/** Feed changes through evaluate and the reference committer. */
async function run(changes: EvidenceChange[], start = world) {
  const committer = createMemoryVisibilityCommitter();
  let facts = { world: start, evidence: [] as ReplicaOperation[] };
  const deltas = [];
  for (const change of changes) {
    const { epoch, projection } = committer.read();
    const delta = evaluate({ epoch, projection, ...facts }, change);
    await committer.commit(epoch, delta, {});
    facts = {
      ...applyChange(facts, change),
      evidence: [...applyChange(facts, change).evidence],
    };
    deltas.push(delta);
  }
  return { ...committer.read(), deltas, facts };
}
const evidence = (...operations: ReplicaOperation[]): EvidenceChange => ({
  kind: "evidence",
  operations,
});

describe("completion availability", () => {
  const done = completion([registration, a, b], [a.data, b.data]);
  const facts: CompletionFacts = {
    connection: { status: "active", generation: 1 },
    connectionId: C,
    events: [done],
    declarations: world.declarations,
    quarantinedKey: false,
    unresolved: false,
    variantDigests: (writerId, operationId) =>
      [registration, a, b]
        .filter(
          (op) =>
            op.revision.writerId === writerId &&
            op.revision.operationId === operationId,
        )
        .map(operationDigest),
    liveRows: [a, b].map((op) => ({
      recordKey: op.recordKey,
      dataJson: canonicalJson(op.data),
    })),
  };
  it("is available only when every condition holds", () => {
    expect(completionAvailability(facts)).toEqual({ operation: done });
  });
  const refusals: [string, Partial<CompletionFacts>][] = [
    ["a dependency is missing", { variantDigests: () => [] }],
    [
      "a dependency has two variants",
      {
        variantDigests: (w, o) => [
          ...facts.variantDigests(w, o),
          `sha256:${"0".repeat(64)}`,
        ],
      },
    ],
    [
      "a dependency digest differs",
      { variantDigests: () => [`sha256:${"0".repeat(64)}`] },
    ],
    ["the live count differs", { liveRows: facts.liveRows.slice(1) }],
    [
      "the snapshot digest differs",
      {
        liveRows: [
          facts.liveRows[0],
          {
            ...facts.liveRows[1],
            dataJson: canonicalJson({ id: "b", text: "changed" }),
          },
        ],
      },
    ],
    ["a key of the stream is quarantined", { quarantinedKey: true }],
    ["an operation of the stream is unresolved", { unresolved: true }],
    [
      "the connection is held",
      {
        connection: {
          status: "held",
          reason: "missing_generation_reset",
          generation: 1,
        },
      },
    ],
    [
      "the connection is on another generation",
      { connection: { status: "active", generation: 2 } },
    ],
    ["the declaration is not trusted", { declarations: [] }],
    [
      "a newer invalidation exists",
      {
        events: [
          done,
          {
            ...identity,
            kind: "stream-invalidate",
            declaration: binding,
            revision: { counter: 11, writerId: "device-a", operationId: "inv" },
          },
        ],
      },
    ],
    ["it has no dependencies", { events: [completion([], [a.data, b.data])] }],
    [
      "the events name two declarations",
      {
        events: [
          done,
          {
            ...completion([a], [a.data], 4),
            declaration: { ...binding, version: "2" },
          },
        ],
      },
    ],
    [
      "a native proof disagrees",
      {
        events: [
          {
            ...done,
            proof: {
              kind: "native",
              snapshotSha256: `sha256:${"0".repeat(64)}`,
              collectionTimeBasis: "host_run_finished",
            },
          },
        ],
      },
    ],
  ];
  for (const [name, change] of refusals)
    it(`is unavailable when ${name}`, () => {
      expect(completionAvailability({ ...facts, ...change })).toBeNull();
    });

  it("never counts a dependency held only by an unmapped connection", async () => {
    const elsewhere = { ...key("x", "X", 4), connectionId: "unmapped" };
    const result = await run([
      evidence(
        registration,
        a,
        elsewhere,
        completion([a, elsewhere], [a.data]),
      ),
    ]);
    expect(result.projection.completions).toEqual({});
  });

  it("is withdrawn by evaluate when a later record changes the snapshot", async () => {
    const result = await run([
      evidence(registration, a, b, done),
      evidence(key("b", "B2", 12)),
    ]);
    expect(result.deltas[0].completions).toEqual({
      [completionId(C, binding.stream)]: { operation: done },
    });
    expect(result.deltas[1].completions).toEqual({
      [completionId(C, binding.stream)]: null,
    });
  });
});

describe("blob references", () => {
  const blob = {
    blobId: `sha256:${"e".repeat(64)}`,
    sha256: `sha256:${"e".repeat(64)}`,
    mimeType: "text/plain",
    sizeBytes: 3,
  };
  const withBlob = {
    ...key("a", "A", 2),
    data: { id: "a", blob_ref: { blob_id: blob.blobId, size_bytes: 3 } },
    blobs: [blob],
  } as Extract<RecordOperation, { kind: "upsert" }>;
  const claim: ReplicaOperation = {
    ...identity,
    kind: "blob-claim",
    blob,
    revision: { counter: 3, writerId: "device-a", operationId: "claim" },
  };
  const verified = new Set([blob.blobId]);
  it("needs agreeing blob_ref, a same-generation claim and verified bytes", () => {
    expect(blobReady(withBlob, [claim], verified)).toBe(true);
    expect(blobReady(withBlob, [claim], new Set())).toBe(false);
    expect(blobReady(withBlob, [], verified)).toBe(false);
    expect(
      blobReady(
        withBlob,
        [{ ...claim, generation: 2 } as ReplicaOperation],
        verified,
      ),
    ).toBe(false);
    expect(
      blobReady(withBlob, [{ ...claim, methodId: "other" }], verified),
    ).toBe(false);
    expect(
      blobReady(
        {
          ...withBlob,
          data: { id: "a", blob_ref: { blob_id: blob.blobId, size_bytes: 4 } },
        },
        [claim],
        verified,
      ),
    ).toBe(false);
    expect(blobReady({ ...withBlob, blobs: [] }, [claim], verified)).toBe(
      false,
    );
  });
  it("attaches the reference when the bytes are verified, and releases it when the row changes", async () => {
    const result = await run([
      evidence(registration, withBlob, claim),
      { kind: "evidence", operations: [], verifiedBlobs: [blob.blobId] },
      evidence(key("a", "plain", 9)),
    ]);
    const ref = { blobId: blob.blobId, connectionId: C, generation: 1 };
    expect(result.deltas[0].rows).toEqual({});
    expect(result.deltas[1].blobs).toEqual({ attach: [ref], release: [] });
    expect(result.deltas[1].rows[rowId(C, binding.stream, "a")]).toEqual({
      state: "live",
      winner: withBlob,
    });
    expect(result.deltas[2].blobs).toEqual({ attach: [], release: [ref] });
  });
});

describe("fences", () => {
  it("fence a reset, a deletion and a new key quarantine, not a newer winner", async () => {
    const appendBinding = { ...binding, semantics: "append_only" as const };
    const appendWorld = {
      ...world,
      declarations: [{ ...world.declarations[0], binding: appendBinding }],
    };
    const first = { ...key("a", "A", 2), declaration: appendBinding };
    const other = { ...key("a", "other", 3), declaration: appendBinding };
    const quarantine = await run(
      [evidence(registration, first), evidence(other)],
      appendWorld,
    );
    expect(quarantine.deltas[0].fences).toEqual([C]);
    expect(quarantine.deltas[1].fences).toEqual([C]);
    expect(quarantine.deltas[1].rows[rowId(C, binding.stream, "a")]).toEqual({
      state: "withdrawn",
      reason: "quarantined",
    });

    const result = await run([
      evidence(registration, a),
      evidence(key("a", "A2", 5)),
      evidence({
        ...identity,
        kind: "connection-reset",
        generation: 2,
        previousGeneration: 1,
        revision: { counter: 6, writerId: "device-a", operationId: "reset" },
      }),
      evidence({
        ...identity,
        kind: "connection-delete",
        revision: { counter: 7, writerId: "device-a", operationId: "delete" },
      }),
    ]);
    expect(result.deltas.map((d) => d.fences)).toEqual([[C], [], [C], [C]]);
    expect(result.deltas[2].rows[rowId(C, binding.stream, "a")]).toEqual({
      state: "withdrawn",
      reason: "superseded_generation",
    });
    expect(result.projection.connections[C]).toEqual({
      status: "deleted",
      generation: 2,
    });
  });
});

describe("host authority", () => {
  it("never shows evidence of an unmapped connection; only a host change provisions it", async () => {
    const other = { ...a, connectionId: "unmapped" };
    const otherRegistration = {
      ...registration,
      connectionId: "unmapped",
      revision: { ...registration.revision, operationId: "register-u" },
    };
    const before = await run([evidence(otherRegistration, other)]);
    expect(before.projection.rows).toEqual({});
    expect(Object.keys(before.projection.connections)).toEqual([C]);
    const after = await run([
      evidence(otherRegistration, other),
      {
        kind: "host",
        provision: {
          unmapped: {
            sourceId: identity.sourceId,
            methodId: identity.methodId,
          },
        },
      },
    ]);
    expect(Object.keys(after.projection.rows)).toEqual([
      rowId("unmapped", binding.stream, "a"),
    ]);
  });
  it("keeps the owner's local rows visible, marked, under a binding conflict only", () => {
    const conflicted = connectionVisibilityState({
      status: "withdrawn",
      reason: "local_mapping_conflict",
      generation: 1,
    });
    expect(conflicted).toBe("conflicted");
    expect(replicaStateVisible(conflicted, "owner", undefined, "local")).toBe(
      true,
    );
    expect(
      replicaStateVisible(conflicted, "owner", undefined, "received"),
    ).toBe(false);
    expect(replicaStateVisible(conflicted, "grant", undefined, "local")).toBe(
      false,
    );
    const equivocated = connectionVisibilityState({
      status: "withdrawn",
      reason: "operation_id_equivocation",
      generation: 1,
    });
    expect(replicaStateVisible(equivocated, "owner", undefined, "local")).toBe(
      false,
    );
  });
});

describe("host-chosen keys", () => {
  // Connection ids and checkpoint keys are host strings. None may reach an
  // inherited object property.
  const HOSTILE = ["__proto__", "constructor", "toString", "hasOwnProperty"];
  const mapping = { sourceId: identity.sourceId, methodId: identity.methodId };
  const at = (id: string, op: ReplicaOperation): ReplicaOperation => ({
    ...op,
    connectionId: id,
    revision: {
      ...op.revision,
      operationId: `${id}:${op.revision.operationId}`,
    },
  });
  it.each(HOSTILE)("treats connection id %s as an ordinary id", async (id) => {
    const result = await run(
      [
        { kind: "host", provision: { [id]: mapping } },
        evidence(at(id, registration), at(id, a)),
      ],
      { ...world, mappings: new Map() },
    );
    expect(Object.keys(result.deltas[0].connections)).toEqual([id]);
    expect(Object.keys(result.projection.connections)).toEqual([id]);
    expect(Object.hasOwn(result.projection.connections, id)).toBe(true);
    expect(result.projection.connections[id]).toEqual({
      status: "active",
      generation: 1,
    });
    expect(Object.keys(result.projection.rows)).toEqual([
      rowId(id, binding.stream, "a"),
    ]);
  });
  it("treats every checkpoint key as an ordinary key", async () => {
    const committer = createMemoryVisibilityCommitter();
    const empty = evaluate(
      {
        epoch: INITIAL_VISIBILITY_EPOCH,
        projection: EMPTY_PROJECTION,
        world: { ...world, mappings: new Map() },
        evidence: [],
      },
      { kind: "host" },
    );
    const keys = Object.fromEntries(HOSTILE.map((key) => [key, key]));
    await committer.commit(INITIAL_VISIBILITY_EPOCH, empty, keys);
    expect(Object.keys(committer.read().checkpoint).sort()).toEqual(
      [...HOSTILE].sort(),
    );
    await committer.commit(INITIAL_VISIBILITY_EPOCH, empty, {
      ["__proto__"]: null,
      constructor: null,
    });
    expect(Object.keys(committer.read().checkpoint).sort()).toEqual([
      "hasOwnProperty",
      "toString",
    ]);
  });

  // `canonicalJson`'s zod parse drops an own `__proto__` key, so a digest
  // built with it cannot tell these values apart.
  const proto = <T>(value: T) => Object.fromEntries([["__proto__", value]]);
  const empty = () =>
    evaluate(
      {
        epoch: INITIAL_VISIBILITY_EPOCH,
        projection: EMPTY_PROJECTION,
        world: { ...world, mappings: new Map() },
        evidence: [],
      },
      { kind: "host" },
    );
  it("stores two writes in a row of a __proto__ checkpoint key", async () => {
    const committer = createMemoryVisibilityCommitter();
    await committer.commit(INITIAL_VISIBILITY_EPOCH, empty(), {});
    const first = await committer.commit(
      INITIAL_VISIBILITY_EPOCH,
      empty(),
      proto("1"),
    );
    expect(Object.entries(committer.read().checkpoint)).toEqual([
      ["__proto__", "1"],
    ]);
    const second = await committer.commit(
      INITIAL_VISIBILITY_EPOCH,
      empty(),
      proto("2"),
    );
    expect(second).not.toBe(first);
    expect(second.checkpointDigest).not.toBe(first.checkpointDigest);
    expect(Object.entries(committer.read().checkpoint)).toEqual([
      ["__proto__", "2"],
    ]);
  });
  it("deletes a __proto__ checkpoint key", async () => {
    const committer = createMemoryVisibilityCommitter();
    await committer.commit(INITIAL_VISIBILITY_EPOCH, empty(), proto("1"));
    await committer.commit(INITIAL_VISIBILITY_EPOCH, empty(), proto(null));
    expect(Object.entries(committer.read().checkpoint)).toEqual([]);
  });
  it("tells apart connection deltas that differ only under __proto__", async () => {
    const active = {
      ...empty(),
      connections: proto({ status: "active", generation: 1 } as const),
    };
    const withdrawn = {
      ...empty(),
      connections: proto({
        status: "withdrawn",
        reason: "terminal_quarantine",
        generation: 1,
      } as const),
    };
    expect(deltaDigest(active)).not.toBe(deltaDigest(withdrawn));
    expect(deltaDigest(active)).not.toBe(deltaDigest(empty()));
    expect(commitRequestDigest(INITIAL_VISIBILITY_EPOCH, active, {})).not.toBe(
      commitRequestDigest(INITIAL_VISIBILITY_EPOCH, withdrawn, {}),
    );
    const committer = createMemoryVisibilityCommitter();
    expect(
      (await committer.commit(INITIAL_VISIBILITY_EPOCH, active, {})).epoch,
    ).toBe(1);
    await expect(
      committer.commit(INITIAL_VISIBILITY_EPOCH, withdrawn, {}),
    ).rejects.toBeInstanceOf(VisibilityEpochConflict);
  });
  it("tells apart rows and evidence that differ only under a __proto__ data key", () => {
    // The planner's operation parse drops the key before rows exist, so this
    // states the engine's own comparison and digest directly.
    const withData = (value: string) =>
      ({
        ...a,
        data: Object.fromEntries([
          ["id", "a"],
          ["__proto__", value],
        ]),
      }) as typeof a;
    const id = rowId(C, binding.stream, "a");
    const projection = (value: string): VisibilityProjection => ({
      ...EMPTY_PROJECTION,
      rows: { [id]: { state: "live", winner: withData(value) } },
    });
    expect(
      Object.keys(
        diffProjection(
          INITIAL_VISIBILITY_EPOCH,
          projection("x"),
          projection("y"),
          "digest",
        ).rows,
      ),
    ).toEqual([id]);
    expect(evidenceDigest(world, [registration, withData("x")])).not.toBe(
      evidenceDigest(world, [registration, withData("y")]),
    );
  });
});

describe("commit", () => {
  const change = evidence(registration, a);
  const delta = evaluate(
    {
      epoch: INITIAL_VISIBILITY_EPOCH,
      projection: EMPTY_PROJECTION,
      world,
      evidence: [],
    },
    change,
  );
  it("advances the epoch only when the projection changes", async () => {
    const committer = createMemoryVisibilityCommitter();
    const receipt = await committer.commit(INITIAL_VISIBILITY_EPOCH, delta, {
      cursor: "1",
    });
    expect(receipt.epoch).toBe(1);
    expect(receipt.previous).toBe(0);
    expect(receipt.evidenceDigest).toBe(
      evidenceDigest(world, [registration, a]),
    );
    const empty = evaluate(
      {
        epoch: receipt.epoch,
        projection: committer.read().projection,
        world,
        evidence: [registration, a],
      },
      change,
    );
    const second = await committer.commit(receipt.epoch, empty, {
      cursor: "2",
    });
    expect(second.epoch).toBe(1);
    expect(committer.read().checkpoint).toEqual({ cursor: "2" });
  });
  it("returns the original receipt for a lost acknowledgement and changes nothing", async () => {
    const committer = createMemoryVisibilityCommitter();
    const receipt = await committer.commit(INITIAL_VISIBILITY_EPOCH, delta, {
      cursor: "1",
    });
    const state = committer.read();
    expect(
      await committer.commit(INITIAL_VISIBILITY_EPOCH, delta, { cursor: "1" }),
    ).toBe(receipt);
    expect(committer.read()).toEqual(state);
  });
  /** A committer at epoch 1 with the visible commit and its receipt. */
  async function visible() {
    const committer = createMemoryVisibilityCommitter();
    const receipt = await committer.commit(INITIAL_VISIBILITY_EPOCH, delta, {
      cursor: "1",
    });
    const empty = evaluate(
      {
        epoch: receipt.epoch,
        projection: committer.read().projection,
        world,
        evidence: [registration, a],
      },
      change,
    );
    return { committer, receipt, empty };
  }
  it("binds the receipt to the delta and checkpoint digests", async () => {
    const { receipt } = await visible();
    expect(receipt.deltaDigest).toBe(deltaDigest(delta));
    expect(receipt.checkpointDigest).toBe(checkpointDigest({ cursor: "1" }));
  });
  it("replays an earlier checkpoint-only commit without moving the checkpoint back", async () => {
    const { committer, empty } = await visible();
    const first = await committer.commit(visibilityEpoch(1), empty, {
      cursor: "2",
    });
    await committer.commit(visibilityEpoch(1), empty, { cursor: "3" });
    const state = committer.read();
    expect(
      await committer.commit(visibilityEpoch(1), empty, { cursor: "2" }),
    ).toBe(first);
    expect(committer.read()).toEqual(state);
    expect(state.checkpoint).toEqual({ cursor: "3" });
  });
  it("replays a visible commit after a later checkpoint-only commit", async () => {
    const { committer, receipt, empty } = await visible();
    await committer.commit(visibilityEpoch(1), empty, { cursor: "2" });
    const state = committer.read();
    expect(
      await committer.commit(INITIAL_VISIBILITY_EPOCH, delta, { cursor: "1" }),
    ).toBe(receipt);
    expect(committer.read()).toEqual(state);
  });
  it("refuses a retry whose delta was altered", async () => {
    const { committer } = await visible();
    const state = committer.read();
    for (const altered of [
      { ...delta, rows: {} },
      { ...delta, evidenceDigest: `sha256:${"0".repeat(64)}` },
    ])
      await expect(
        committer.commit(INITIAL_VISIBILITY_EPOCH, altered, { cursor: "1" }),
      ).rejects.toBeInstanceOf(VisibilityEpochConflict);
    expect(committer.read()).toEqual(state);
  });
  it("refuses a stale or mismatched epoch atomically", async () => {
    const committer = createMemoryVisibilityCommitter();
    await committer.commit(INITIAL_VISIBILITY_EPOCH, delta, { cursor: "1" });
    const state = committer.read();
    await expect(
      committer.commit(INITIAL_VISIBILITY_EPOCH, delta, { cursor: "other" }),
    ).rejects.toBeInstanceOf(VisibilityEpochConflict);
    await expect(
      committer.commit(visibilityEpoch(1), delta, { cursor: "other" }),
    ).rejects.toBeInstanceOf(VisibilityEpochConflict);
    expect(committer.read()).toEqual(state);
    expect(() => visibilityEpoch(-1)).toThrow(RangeError);
    expect(() => visibilityEpoch(1.5)).toThrow(RangeError);
  });
  it("digests the evidence set, not its order or duplication", () => {
    const ops = [registration, a, b];
    expect(evidenceDigest(world, [...ops].reverse())).toBe(
      evidenceDigest(world, [...ops, ...ops]),
    );
    expect(evidenceDigest(world, ops)).not.toBe(
      evidenceDigest(world, [registration, a]),
    );
    expect(evidenceDigest(world, ops)).not.toBe(
      evidenceDigest({ ...world, terminal: new Set([C]) }, ops),
    );
  });
  it("starts from the empty projection", () => {
    const projection: VisibilityProjection = EMPTY_PROJECTION;
    expect(projection).toEqual({ connections: {}, rows: {}, completions: {} });
  });
});
