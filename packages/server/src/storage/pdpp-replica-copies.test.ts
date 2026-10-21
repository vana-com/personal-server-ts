import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import type { Predecessor } from "@opendatalabs/personal-server-ts-core/replication/transport";
import { replicaChainCommitment } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  replicaCopyKey,
  type FinalizedFact,
  type Hex,
} from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { CursorExpiredError } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { ReplicaCopyRefused } from "./pdpp-replica-copies.js";

/**
 * Batch-copy transitions on Node SQLite, contract v3.1
 * (replica-copy-promotion-contract-1021-v3.md §3, §5, amendments A–I).
 */

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-21T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const credential = "replica-secret";
const directories: string[] = [];
const devices: { close(): void }[] = [];
afterEach(() => {
  for (const d of devices.splice(0)) d.close();
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});

function device() {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-copies-"));
  directories.push(directory);
  const path = join(directory, "db.sqlite");
  let db = new Database(path);
  let store = createSqliteRecordStore(db);
  for (const instance of ["conn_x", "conn_y", "conn_z", "conn_u", "conn_o"])
    store.registerConnection({
      instance,
      sourceId,
      method: "collector",
      label: instance,
    });
  store.replication.beginBaseline({
    owner: "owner",
    declarations: [{ sourceId, binding }],
  });
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: "owner",
      enabled: true,
      authenticate: (c: unknown) => (c === credential ? "owner" : undefined),
      declarations: () => declarations,
    });
  let current = receiver();
  const d = {
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    get receiver() {
      return current;
    },
    reopen() {
      store.close();
      db = new Database(path);
      store = createSqliteRecordStore(db);
      current = receiver();
    },
    close() {
      if (db.open) store.close();
    },
    /** Rows a reader sees for a connection, canonical plus any preview. */
    read(connectionId: string, reader: "owner" | "grant" = "grant") {
      return current
        .readVisibleRecords({ reader, connectionId, stream: "messages" })
        .map((r) => r.data.text);
    },
    changes(table: string) {
      return db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as {
        n: number;
      };
    },
  };
  devices.push(d);
  return d;
}

const registration = (
  connectionId: string,
  writer: string,
): ReplicaOperation => ({
  kind: "connection-register",
  owner: "owner",
  sourceId,
  connectionId,
  methodId: "collector",
  generation: 1,
  revision: {
    counter: 1,
    writerId: writer,
    operationId: `register-${connectionId}`,
  },
});
const upsert = (
  connectionId: string,
  text: string,
  counter: number,
  writer: string,
): ReplicaOperation => ({
  kind: "upsert",
  owner: "owner",
  sourceId,
  connectionId,
  methodId: "collector",
  generation: 1,
  revision: { counter, writerId: writer, operationId: `op-${writer}-${text}` },
  declaration: binding,
  recordKey: "a",
  emittedAt: at,
  data: { id: "a", text },
  blobs: [],
});
const hex = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as Hex;

/** One copy of batch (writer, batch). `seed` distinguishes copies. */
function copy(input: {
  writer?: string;
  batch: string;
  sequence?: number;
  previous?: Predecessor | null;
  connection?: string;
  text: string;
  seed: number;
  fragments?: number;
}) {
  const writer = input.writer ?? "w1";
  const connection = input.connection ?? "conn_x";
  const envelope = {
    format: "vana-pdpp-replica" as const,
    version: 1 as const,
    owner: "owner",
    batchId: input.batch,
    operations: [
      registration(connection, writer),
      upsert(connection, input.text, 10 + input.seed, writer),
    ],
  };
  const fragments = Array.from({ length: input.fragments ?? 2 }, (_, i) => ({
    dataHash: hex(input.seed * 1000 + i * 2 + 1),
    metadataHash: hex(input.seed * 1000 + i * 2 + 2),
  }));
  return {
    id: canonicalJson([writer, input.batch]),
    writer,
    batch: input.batch,
    sequence: input.sequence ?? 1,
    previous: input.previous ?? null,
    envelopeDigest: `sha256:${createHash("sha256").update(canonicalJson(envelope)).digest("hex")}`,
    envelope,
    fragments,
    copyKey: replicaCopyKey(
      fragments.map(
        (f) =>
          replicaChainCommitment(
            f.dataHash,
            f.metadataHash,
          ).toLowerCase() as Hex,
      ),
    ),
  };
}
type Copy = ReturnType<typeof copy>;
const stage = (d: ReturnType<typeof device>, c: Copy) =>
  d.receiver.copies.stage({
    credential,
    copy: {
      id: c.id,
      writer: c.writer,
      batch: c.batch,
      sequence: c.sequence,
      previous: c.previous,
      envelopeDigest: c.envelopeDigest,
      envelope: c.envelope,
      fragments: c.fragments,
    },
  });
let block = 100n;
/** A verified fact proving (or, with `of`, disproving) every fragment of `c`. */
function prove(
  d: ReturnType<typeof device>,
  c: Copy,
  options: { eligible?: boolean; of?: Copy; version?: string } = {},
) {
  const source = options.of ?? c;
  source.fragments.forEach((f, index) => {
    block += 1n;
    const fact: FinalizedFact = {
      chainId: 1,
      registry: hex(0xabc),
      owner: "owner",
      currentVersion: options.version ?? "1",
      status: options.eligible === false ? "Inactive" : "Active",
      commitment:
        options.version === "0"
          ? hex(0)
          : (replicaChainCommitment(f.dataHash, f.metadataHash) as Hex),
      blockNumber: block,
      blockHash: hex(Number(block) + 0xb10c),
      eligible: options.eligible !== false && options.version !== "0",
    };
    d.receiver.copies.recordFact({
      credential,
      id: c.id,
      scope: `${c.id}#${index}`,
      fragmentIndex: index,
      fact,
    });
  });
}
const promote = (d: ReturnType<typeof device>, c: Copy) =>
  d.receiver.copies.promote({ credential, id: c.id, copyKey: c.copyKey });
const states = (d: ReturnType<typeof device>, c: Copy) =>
  Object.fromEntries(
    d.receiver.copies
      .list(c.id)
      .map((row) => [row.copyKey, `${row.state}:${row.reason ?? ""}`]),
  );

describe("copy staging and the pending preview (§3, §7.2, B)", () => {
  it("one valid copy waits for finality and is the owner preview; grants never see it", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    expect(stage(d, a).decision).toMatchObject({
      kind: "wait",
      quarantine: [],
    });
    expect(d.read("conn_x", "owner")).toEqual(["A"]);
    expect(d.read("conn_x", "grant")).toEqual([]);
    expect(d.receiver.copies.disposition(a.id)).toEqual({ state: "open" });
  });

  it("a second valid copy quarantines both as copy_conflict and withdraws the preview in the same transaction", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    const b = copy({ batch: "b1", text: "B", seed: 2 });
    stage(d, a);
    expect(stage(d, b).decision).toMatchObject({ kind: "wait" });
    expect(states(d, a)).toEqual({
      [a.copyKey]: "quarantined:copy_conflict",
      [b.copyKey]: "quarantined:copy_conflict",
    });
    expect(d.read("conn_x", "owner")).toEqual([]);
    expect(d.read("conn_x", "grant")).toEqual([]);
  });

  it("a bare promote with two retained copies is refused", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    stage(d, copy({ batch: "b1", text: "B", seed: 2 }));
    prove(d, a);
    expect(() => d.receiver.promote({ credential, id: a.id })).toThrow(
      ReplicaCopyRefused,
    );
    expect(d.read("conn_x", "grant")).toEqual([]);
  });

  it("the legacy stage path is refused for a batch with retained copies", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    expect(() =>
      d.receiver.stage({ credential, id: a.id, envelope: a.envelope }),
    ).toThrow(ReplicaCopyRefused);
  });

  it("an input failing a validity check is a reject and never reserves a copy key (C)", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    const corrupt = {
      ...a,
      fragments: [{ dataHash: "0xZZ", metadataHash: "0x00" }],
    };
    // Corrupt first, then valid, gives the same result as the reverse order.
    expect(stage(d, corrupt).copyKey).toBeUndefined();
    expect(stage(d, a).copyKey).toBe(a.copyKey);
    expect(stage(d, corrupt).copyKey).toBeUndefined();
    expect(states(d, a)).toEqual({ [a.copyKey]: "pending:" });
    expect(d.changes("pdpp_replica_copy_rejects").n).toBe(1);
    expect(d.read("conn_x", "owner")).toEqual(["A"]);
  });
  it("the same copy key with different content (a keccak collision) is terminal", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    const other = copy({ batch: "b1", text: "Z", seed: 1 });
    expect(other.copyKey).toBe(a.copyKey);
    expect(stage(d, other).decision.kind).toBe("terminal");
    expect(d.receiver.copies.disposition(a.id).state).toBe("terminal");
    expect(d.read("conn_x", "owner")).toEqual([]);
  });
});

describe("promotion (§3 promote, E, F)", () => {
  it("promotes exactly the proven copy, quarantines the rest, writes one receipt; replay changes nothing", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    const b = copy({ batch: "b1", text: "B", seed: 2 });
    stage(d, a);
    stage(d, b);
    prove(d, b);
    expect(
      d.receiver.copies.decide(a.id, { attempts: 0, budget: 5 }),
    ).toMatchObject({
      kind: "promote",
      copyKey: b.copyKey,
    });
    expect(promote(d, b)).toMatchObject({ kind: "promoted", replay: false });
    expect(d.read("conn_x", "grant")).toEqual(["B"]);
    expect(states(d, a)).toEqual({
      [a.copyKey]: "quarantined:copy_conflict",
      [b.copyKey]: "confirmed:",
    });
    const history = d.changes("pdpp_record_changes").n;
    expect(promote(d, b)).toMatchObject({ kind: "promoted", replay: true });
    expect(d.changes("pdpp_record_changes").n).toBe(history);
    expect(d.changes("pdpp_replica_promotion_receipts").n).toBe(1);
  });

  it("a copy that is not proven cannot be promoted", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    expect(() => promote(d, a)).toThrow(ReplicaCopyRefused);
    expect(d.read("conn_x", "grant")).toEqual([]);
  });

  it("an import that aborts leaves the batch open and promotable (crash point inside the import)", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    d.db.exec(
      "CREATE TEMP TRIGGER interrupt BEFORE INSERT ON pdpp_records BEGIN SELECT RAISE(ABORT,'interrupt'); END",
    );
    expect(() => promote(d, a)).toThrow("interrupt");
    expect(d.receiver.copies.disposition(a.id)).toEqual({ state: "open" });
    expect(states(d, a)).toEqual({ [a.copyKey]: "pending:" });
    expect(d.changes("pdpp_replica_promotion_receipts").n).toBe(0);
    d.db.exec("DROP TRIGGER interrupt");
    expect(promote(d, a)).toMatchObject({ kind: "promoted" });
    expect(d.read("conn_x", "grant")).toEqual(["A"]);
  });

  it("survives a restart between stage and promote", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    d.reopen();
    expect(d.read("conn_x", "owner")).toEqual(["A"]);
    expect(promote(d, a)).toMatchObject({ kind: "promoted" });
    expect(d.read("conn_x", "grant")).toEqual(["A"]);
  });

  it("a late copy after promotion is quarantined; the confirmed copy and canonical data are untouched", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    promote(d, a);
    const history = d.changes("pdpp_record_changes").n;
    const late = copy({ batch: "b1", text: "B", seed: 2 });
    expect(stage(d, late).decision).toMatchObject({
      kind: "reconcile_promoted",
      copyKey: a.copyKey,
    });
    expect(states(d, a)).toEqual({
      [a.copyKey]: "confirmed:",
      [late.copyKey]: "quarantined:copy_conflict",
    });
    expect(d.read("conn_x", "owner")).toEqual(["A"]);
    expect(d.changes("pdpp_record_changes").n).toBe(history);
    // A duplicate stage of the promoted key is a no-op.
    stage(d, a);
    expect(d.changes("pdpp_record_changes").n).toBe(history);
    expect(states(d, a)[a.copyKey]).toBe("confirmed:");
  });

  it("an ineligible (Inactive) commitment never promotes; after promotion it does not demote (D)", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a, { eligible: false });
    expect(
      d.receiver.copies.decide(a.id, { attempts: 0, budget: 5 }),
    ).toMatchObject({
      kind: "wait",
    });
    expect(() => promote(d, a)).toThrow(ReplicaCopyRefused);
    const b = copy({ batch: "b2", text: "B", seed: 2, connection: "conn_y" });
    stage(d, b);
    prove(d, b);
    promote(d, b);
    prove(d, b, { eligible: false });
    expect(
      d.receiver.copies.decide(b.id, { attempts: 0, budget: 5 }),
    ).toMatchObject({
      kind: "reconcile_promoted",
    });
    expect(d.read("conn_y", "grant")).toEqual(["B"]);
  });

  it("a receipt for another copy key is an invariant violation: terminal commits, nothing is imported", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    d.db
      .prepare("INSERT INTO pdpp_replica_promotion_receipts VALUES (?,?,?)")
      .run(a.id, hex(9), "sha256:other");
    expect(promote(d, a)).toEqual({
      kind: "terminal",
      reason: "receipt_conflict",
    });
    expect(d.receiver.copies.disposition(a.id)).toEqual({
      state: "terminal",
      reason: "receipt_conflict",
    });
    expect(d.read("conn_x", "owner")).toEqual([]);
    expect(d.changes("pdpp_records").n).toBe(0);
  });
});

describe("predecessor identity inside promote (E)", () => {
  it("a successor waits for its predecessor, then promotes", () => {
    const d = device();
    const p = copy({ batch: "p", text: "P", seed: 1 });
    const s = copy({
      batch: "s",
      sequence: 2,
      previous: { batch: "p", digest: p.envelopeDigest },
      text: "S",
      seed: 2,
      connection: "conn_y",
    });
    stage(d, s);
    prove(d, s);
    expect(promote(d, s)).toEqual({
      kind: "wait_predecessor",
      predecessor: p.id,
    });
    expect(d.read("conn_y", "grant")).toEqual([]);
    stage(d, p);
    prove(d, p);
    promote(d, p);
    expect(promote(d, s)).toMatchObject({ kind: "promoted" });
    expect(d.read("conn_y", "grant")).toEqual(["S"]);
  });

  it("a predecessor digest mismatch never promotes", () => {
    const d = device();
    const p = copy({ batch: "p", text: "P", seed: 1 });
    const s = copy({
      batch: "s",
      sequence: 2,
      previous: { batch: "p", digest: "sha256:wrong" },
      text: "S",
      seed: 2,
      connection: "conn_y",
    });
    stage(d, p);
    prove(d, p);
    promote(d, p);
    stage(d, s);
    prove(d, s);
    expect(promote(d, s)).toMatchObject({ kind: "terminal" });
    expect(d.read("conn_y", "grant")).toEqual([]);
  });
});

describe("terminal batches (A, D, H)", () => {
  it("a later verified contradiction after promotion is terminal: data, history pages, changes and cursors are withdrawn, across retry and restart", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    promote(d, a);
    const read = (reader: "owner" | "grant") =>
      d.receiver.readStore({ reader });
    const options = { instanceIds: ["conn_x"], limit: 100 };
    const session = read("grant").changesSince(
      "messages",
      options,
    ).nextChangesSince;
    expect(session).toBeDefined();
    const epoch = d.store.replicaIntegrityEpoch("conn_x");
    // A then B: two different version-1 commitments at one scope.
    prove(d, a, { of: copy({ batch: "b1", text: "B", seed: 2 }) });
    const decision = d.receiver.copies.decide(a.id, { attempts: 0, budget: 5 });
    expect(decision.kind).toBe("terminal");
    d.receiver.copies.apply({ credential, id: a.id, decision });
    expect(d.receiver.copies.disposition(a.id).state).toBe("terminal");
    expect(states(d, a)).toEqual({
      [a.copyKey]: "quarantined:finalized_conflict",
    });
    expect(d.store.replicaIntegrityEpoch("conn_x")).toBeGreaterThan(epoch);
    for (const reader of ["owner", "grant"] as const) {
      expect(d.read("conn_x", reader)).toEqual([]);
      expect(() =>
        read(reader).changesSince("messages", {
          ...options,
          changesSince: session,
        }),
      ).toThrow(CursorExpiredError);
    }
    d.reopen();
    d.receiver.retry({ credential });
    expect(d.receiver.copies.disposition(a.id).state).toBe("terminal");
    expect(d.read("conn_x", "owner")).toEqual([]);
    expect(() => promote(d, a)).not.toThrow();
    expect(promote(d, a)).toMatchObject({ kind: "terminal" });
  });

  it("a verified version 1, then a later verified version 0, is terminal (D)", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    prove(d, a, { version: "0" });
    expect(
      d.receiver.copies.decide(a.id, { attempts: 0, budget: 5 }).kind,
    ).toBe("terminal");
  });

  it("a writer chain P→S→T on X, Y, Z: a contradiction on P makes all three terminal and withdraws X, Y and Z; a later U is terminal on staging; another writer's batches stay", () => {
    const d = device();
    const p = copy({ batch: "p", text: "P", seed: 1, connection: "conn_x" });
    const s = copy({
      batch: "s",
      sequence: 2,
      previous: { batch: "p", digest: p.envelopeDigest },
      text: "S",
      seed: 2,
      connection: "conn_y",
    });
    const t = copy({
      batch: "t",
      sequence: 3,
      previous: { batch: "s", digest: s.envelopeDigest },
      text: "T",
      seed: 3,
      connection: "conn_z",
    });
    const other = copy({
      writer: "w2",
      batch: "o",
      text: "O",
      seed: 4,
      connection: "conn_o",
    });
    for (const c of [p, s, t, other]) {
      stage(d, c);
      prove(d, c);
      expect(promote(d, c)).toMatchObject({ kind: "promoted" });
    }
    const epochs = ["conn_x", "conn_y", "conn_z"].map((c) =>
      d.store.replicaIntegrityEpoch(c),
    );
    prove(d, p, { of: copy({ batch: "p", text: "Q", seed: 9 }) });
    d.receiver.copies.apply({
      credential,
      id: p.id,
      decision: d.receiver.copies.decide(p.id, { attempts: 0, budget: 5 }),
    });
    for (const c of [p, s, t])
      expect(d.receiver.copies.disposition(c.id).state).toBe("terminal");
    expect(d.receiver.copies.disposition(s.id)).toEqual({
      state: "terminal",
      reason: "predecessor_terminal",
    });
    ["conn_x", "conn_y", "conn_z"].forEach((c, i) => {
      expect(d.store.replicaIntegrityEpoch(c)).toBeGreaterThan(epochs[i]!);
      expect(d.read(c, "owner")).toEqual([]);
      expect(d.read(c, "grant")).toEqual([]);
    });
    const u = copy({
      batch: "u",
      sequence: 4,
      previous: { batch: "t", digest: t.envelopeDigest },
      text: "U",
      seed: 5,
      connection: "conn_u",
    });
    expect(stage(d, u).decision.kind).toBe("terminal");
    expect(d.receiver.copies.disposition(u.id).state).toBe("terminal");
    expect(d.read("conn_u", "owner")).toEqual([]);
    expect(d.receiver.copies.disposition(other.id).state).toBe("promoted");
    expect(d.read("conn_o", "grant")).toEqual(["O"]);
  });

  it("reasons never lower: a terminal copy_conflict copy rises to finalized_conflict and stays there", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    const b = copy({ batch: "b1", text: "B", seed: 2 });
    stage(d, a);
    stage(d, b);
    prove(d, a);
    prove(d, a, { of: b });
    d.receiver.copies.apply({
      credential,
      id: a.id,
      decision: d.receiver.copies.decide(a.id, { attempts: 0, budget: 5 }),
    });
    expect(Object.values(states(d, a))).toEqual([
      "quarantined:finalized_conflict",
      "quarantined:finalized_conflict",
    ]);
    stage(d, a);
    stage(d, copy({ batch: "b1", text: "C", seed: 3 }));
    expect(
      Object.values(states(d, a)).every(
        (v) => v === "quarantined:finalized_conflict",
      ),
    ).toBe(true);
  });
});

describe("refetch and owner (rule 5, F4)", () => {
  it("every copy disproved: refetch below the budget, owner at the budget", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a, { of: copy({ batch: "b1", text: "B", seed: 2 }) });
    expect(
      d.receiver.copies.decide(a.id, { attempts: 4, budget: 5 }).kind,
    ).toBe("refetch");
    expect(
      d.receiver.copies.decide(a.id, { attempts: 5, budget: 5 }),
    ).toMatchObject({
      kind: "owner",
      reason: "copy_conflict_unresolved",
    });
    // A matching copy staged later promotes.
    const b = copy({ batch: "b1", text: "B", seed: 2 });
    expect(stage(d, b).decision).toMatchObject({
      kind: "promote",
      copyKey: b.copyKey,
    });
  });
});

describe("evidence authority (F2)", () => {
  it("a fact from another owner is refused, never recorded", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    expect(() =>
      d.receiver.copies.recordFact({
        credential,
        id: a.id,
        scope: "s",
        fragmentIndex: 0,
        fact: {
          chainId: 1,
          registry: hex(0xabc),
          owner: "someone-else",
          currentVersion: "1",
          status: "Active",
          commitment: hex(1),
          blockNumber: 1n,
          blockHash: hex(2),
          eligible: true,
        },
      }),
    ).toThrow(ReplicaCopyRefused);
    expect(d.changes("pdpp_replica_finalized_facts").n).toBe(0);
  });

  it("facts are append-only", () => {
    const d = device();
    const a = copy({ batch: "b1", text: "A", seed: 1 });
    stage(d, a);
    prove(d, a);
    expect(() => d.db.exec("DELETE FROM pdpp_replica_finalized_facts")).toThrow(
      "append-only",
    );
  });
});
