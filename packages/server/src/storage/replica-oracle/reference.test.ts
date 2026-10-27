/**
 * Handwritten expected vectors for the frozen reference (oracle design §1).
 * Each expectation is written out by hand, not computed, so the reference,
 * the full-history planner and the ports cannot agree on a defect by sharing
 * code. The planner checks pin the policy the ports are built on.
 */
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  type DeclarationBinding,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { planReplicaMerge } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  emptyRefState,
  refLocalWritable,
  refProject,
  rowId,
  type RefRow,
  type RefState,
  type RefWorld,
} from "./reference.test-utils.js";

const owner = "owner-a";
const source = "https://example.test/source";
const mutable: DeclarationBinding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1.0.0",
  stream: "messages",
  semantics: "mutable_state",
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const appendOnly: DeclarationBinding = {
  ...mutable,
  digest: `sha256:${"c".repeat(64)}`,
  stream: "events",
  semantics: "append_only",
};
const mutableV2: DeclarationBinding = {
  ...mutable,
  digest: `sha256:${"d".repeat(64)}`,
  version: "2.0.0",
};
const base = (connectionId = "c1", generation = 1) => ({
  owner,
  sourceId: source,
  connectionId,
  methodId: "export",
  generation,
});
const rev = (counter: number, writerId: string, operationId: string) => ({
  counter,
  writerId,
  operationId,
});
const register = (connectionId = "c1", writer = "w-a"): ReplicaOperation => ({
  ...base(connectionId),
  kind: "connection-register",
  generation: 1,
  revision: rev(1, writer, `register-${connectionId}`),
});
const put = (
  opId: string,
  counter: number,
  key: string,
  text: string,
  options: {
    connection?: string;
    writer?: string;
    binding?: DeclarationBinding;
    generation?: number;
  } = {},
): ReplicaOperation => ({
  ...base(options.connection, options.generation),
  kind: "upsert",
  declaration: options.binding ?? mutable,
  recordKey: key,
  emittedAt: "2026-10-20T00:00:00Z",
  data: { id: key, text },
  blobs: [],
  revision: rev(counter, options.writer ?? "w-a", opId),
});
const remove = (
  opId: string,
  counter: number,
  key: string,
  writer = "w-a",
): ReplicaOperation => ({
  ...base(),
  kind: "delete",
  declaration: mutable,
  recordKey: key,
  emittedAt: "2026-10-20T00:00:00Z",
  deletedAt: "2026-10-20T00:00:00Z",
  revision: rev(counter, writer, opId),
});
const reset = (
  opId: string,
  counter: number,
  previousGeneration: number,
  generation: number,
): ReplicaOperation => ({
  ...base("c1", generation),
  kind: "connection-reset",
  previousGeneration,
  revision: rev(counter, "w-a", opId),
});

function world(overrides: Partial<RefWorld> = {}): RefWorld {
  return {
    owner,
    mappings: new Map([
      ["c1", { sourceId: source, methodId: "export" }],
      ["c2", { sourceId: source, methodId: "export" }],
    ]),
    declarations: [
      { sourceId: source, binding: mutable },
      { sourceId: source, binding: appendOnly },
    ],
    bytes: new Set(),
    terminal: new Set(),
    ...overrides,
  };
}
const live = (text: string, key = "k1"): RefRow => ({
  deleted: false,
  data: { id: key, text },
});
const tomb: RefRow = { deleted: true };
function rows(state: RefState) {
  return Object.fromEntries(state.rows);
}
const at = (key: string, stream = "messages", connection = "c1") =>
  rowId(connection, stream, key);
function project(
  evidence: ReplicaOperation[],
  w = world(),
  prior = emptyRefState(),
) {
  return refProject(prior, w, evidence);
}
const winnerText = (evidence: ReplicaOperation[], w = world()) =>
  planReplicaMerge(
    {
      owner,
      declarations: w.declarations.map((d) => ({
        ...d,
        validateData: (data: Record<string, unknown>) =>
          typeof data.id === "string",
      })),
    },
    evidence,
  ).records.map((record) =>
    record.winner?.kind === "upsert"
      ? record.winner.data.text
      : (record.winner?.kind ?? "quarantined"),
  );

describe("frozen reference vectors", () => {
  it("mutable: the highest Lamport revision wins; a later upsert resurrects a delete", () => {
    const evidence = [
      register(),
      put("a", 2, "k1", "offline A"),
      put("b", 2, "k1", "offline B", { writer: "w-b" }),
      remove("del", 3, "k1"),
      put("again", 4, "k1", "resurrected"),
    ];
    expect(rows(project(evidence))).toEqual({
      [at("k1")]: live("resurrected"),
    });
    expect(rows(project(evidence.slice(0, 4)))).toEqual({ [at("k1")]: tomb });
    // Equal counters: writer id breaks the tie by code unit, w-b > w-a.
    expect(rows(project(evidence.slice(0, 3)))).toEqual({
      [at("k1")]: live("offline B"),
    });
    expect(winnerText(evidence)).toEqual(["resurrected"]);
    expect(winnerText(evidence.slice(0, 3))).toEqual(["offline B"]);
  });

  it("a delete winner creates a tombstone even for a never-seen key", () => {
    expect(rows(project([register(), remove("d", 2, "k9")]))).toEqual({
      [at("k9")]: tomb,
    });
  });

  it("append-only: differing content for one key withdraws it in every order", () => {
    const one = put("one", 2, "e1", "first", { binding: appendOnly });
    const two = put("two", 3, "e1", "second", { binding: appendOnly });
    const prior = project([register(), one]);
    expect(rows(prior)).toEqual({ [at("e1", "events")]: live("first", "e1") });
    expect(rows(project([register(), one, two], world(), prior))).toEqual({
      [at("e1", "events")]: tomb,
    });
    expect(rows(project([two, register(), one]))).toEqual({});
    expect(winnerText([register(), two, one])).toEqual(["quarantined"]);
    // Equal content from another writer is not a conflict.
    const same = put("same", 5, "e1", "first", {
      binding: appendOnly,
      writer: "w-b",
    });
    expect(rows(project([register(), one, same]))).toEqual({
      [at("e1", "events")]: live("first", "e1"),
    });
  });

  it("an append-only delete and invalid data never enter winner selection", () => {
    const prior = project([register(), put("p", 2, "k1", "kept")]);
    const badKey: ReplicaOperation = {
      ...(put("bad", 9, "k1", "x") as Extract<
        ReplicaOperation,
        { kind: "upsert" }
      >),
      data: { id: "other", text: "x" },
    };
    expect(
      rows(
        project(
          [register(), put("p", 2, "k1", "kept"), badKey],
          world(),
          prior,
        ),
      ),
    ).toEqual({ [at("k1")]: live("kept") });
  });

  it("missing registration holds the connection's current rows", () => {
    const prior = project([register(), put("p", 2, "k1", "kept")]);
    expect(
      rows(
        project(
          [put("p", 2, "k1", "kept"), put("q", 3, "k1", "new")],
          world(),
          prior,
        ),
      ),
    ).toEqual({ [at("k1")]: live("kept") });
    expect(rows(project([put("q", 3, "k1", "new")]))).toEqual({});
  });

  it("a reset gap holds; filling it withdraws old rows and applies the new generation", () => {
    const g1 = [
      register(),
      put("p", 2, "k1", "gen1"),
      put("o", 3, "k2", "old", {}),
    ];
    const prior = project(g1);
    const gap = [
      ...g1,
      reset("r3", 5, 2, 3),
      put("n", 6, "k1", "gen3", { generation: 3 }),
    ];
    const held = project(gap, world(), prior);
    expect(rows(held)).toEqual({
      [at("k1")]: live("gen1"),
      [at("k2")]: live("old", "k2"),
    });
    const filled = project([...gap, reset("r2", 4, 1, 2)], world(), held);
    expect(rows(filled)).toEqual({
      [at("k1")]: live("gen3"),
      [at("k2")]: tomb,
    });
    expect(filled.generations.get("c1")).toBe(3);
  });

  it("an invalid reset withdraws the connection", () => {
    const prior = project([register(), put("p", 2, "k1", "x")]);
    expect(
      rows(
        project(
          [register(), put("p", 2, "k1", "x"), reset("bad", 3, 1, 1)],
          world(),
          prior,
        ),
      ),
    ).toEqual({ [at("k1")]: tomb });
  });

  it("operation-id equivocation withdraws every connection it touches, across keys and connections", () => {
    const original = put("same-id", 2, "k1", "original");
    const crossKey = put("same-id", 2, "k2", "changed");
    const prior = project([
      register(),
      register("c2"),
      original,
      put("c2", 3, "k1", "c2", { connection: "c2" }),
    ]);
    const next = project(
      [
        register(),
        register("c2"),
        original,
        put("c2", 3, "k1", "c2", { connection: "c2" }),
        crossKey,
      ],
      world(),
      prior,
    );
    expect(rows(next)).toEqual({
      [at("k1")]: tomb,
      [at("k1", "messages", "c2")]: live("c2"),
    });
    const crossConnection = put("same-id", 2, "k1", "other", {
      connection: "c3",
    });
    // c3 is not provisioned here; the variant still blocks c1.
    expect(
      rows(project([register(), original, crossConnection], world(), prior)),
    ).toEqual({
      [at("k1")]: tomb,
      [at("k1", "messages", "c2")]: live("c2"),
    });
  });

  it("blob rows need a same-generation claim, a matching reference and verified bytes", () => {
    const blob = {
      blobId: `sha256:${"e".repeat(64)}`,
      sha256: `sha256:${"e".repeat(64)}`,
      mimeType: "text/plain",
      sizeBytes: 3,
    };
    const claim: ReplicaOperation = {
      ...base(),
      kind: "blob-claim",
      blob,
      revision: rev(2, "w-a", "claim"),
    };
    const withBlob: ReplicaOperation = {
      ...(put("b", 3, "k1", "x") as Extract<
        ReplicaOperation,
        { kind: "upsert" }
      >),
      data: { id: "k1", blob_ref: { blob_id: blob.blobId } },
      blobs: [blob],
    };
    expect(rows(project([register(), claim, withBlob]))).toEqual({});
    const bytes = world({ bytes: new Set([blob.blobId]) });
    expect(rows(project([register(), claim, withBlob], bytes))).toEqual({
      [at("k1")]: {
        deleted: false,
        data: { id: "k1", blob_ref: { blob_id: blob.blobId } },
      },
    });
    expect(rows(project([register(), withBlob], bytes))).toEqual({});
    const wrongSize = {
      ...withBlob,
      data: { id: "k1", blob_ref: { blob_id: blob.blobId, size_bytes: 4 } },
    } as ReplicaOperation;
    expect(rows(project([register(), claim, wrongSize], bytes))).toEqual({});
  });

  it("missing declarations hold a key; a later declaration applies or conflicts", () => {
    const prior = project([register(), put("p", 2, "k1", "v1")]);
    const v2 = put("q", 3, "k1", "v2", { binding: mutableV2 });
    const held = project(
      [register(), put("p", 2, "k1", "v1"), v2],
      world(),
      prior,
    );
    expect(rows(held)).toEqual({ [at("k1")]: live("v1") });
    const both = world({
      declarations: [
        ...world().declarations,
        { sourceId: source, binding: mutableV2 },
      ],
    });
    expect(
      rows(project([register(), put("p", 2, "k1", "v1"), v2], both, held)),
    ).toEqual({
      [at("k1")]: tomb,
    });
    expect(winnerText([register(), put("p", 2, "k1", "v1"), v2], both)).toEqual(
      ["quarantined"],
    );
  });

  it("terminal quarantine and connection deletion withdraw; local writes are refused", () => {
    const evidence = [register(), put("p", 2, "k1", "x")];
    const prior = project(evidence);
    expect(
      rows(project(evidence, world({ terminal: new Set(["c1"]) }), prior)),
    ).toEqual({
      [at("k1")]: tomb,
    });
    const deletion: ReplicaOperation = {
      ...base(),
      kind: "connection-delete",
      revision: rev(3, "w-a", "remove"),
    };
    expect(rows(project([...evidence, deletion], world(), prior))).toEqual({
      [at("k1")]: tomb,
    });
    const write = put("w", 9, "k1", "late") as Extract<
      ReplicaOperation,
      { kind: "upsert" }
    >;
    expect(refLocalWritable(world(), evidence, write)).toBe(true);
    expect(
      refLocalWritable(world({ terminal: new Set(["c1"]) }), evidence, write),
    ).toBe(false);
    expect(refLocalWritable(world(), [...evidence, deletion], write)).toBe(
      false,
    );
    expect(refLocalWritable(world(), [put("p", 2, "k1", "x")], write)).toBe(
      false,
    );
  });

  it("evidence for an unprovisioned connection is retained but never shown", () => {
    expect(
      rows(
        project([register("c3"), put("p", 2, "k1", "x", { connection: "c3" })]),
      ),
    ).toEqual({});
    expect(canonicalJson(mutable)).not.toBe(canonicalJson(mutableV2));
  });
});
