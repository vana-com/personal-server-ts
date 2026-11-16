import { afterEach, describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  canonicalJson,
  toHex,
  upsertAfter,
  type LogUpsert,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  openLocalDb,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { replaceOwnRunRows } from "../../../core/src/localdb/admit.js";
import { mergeIncoming, withOrigin } from "../../../core/src/localdb/merge.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

/**
 * The scenario of `docs/formal/log-protocol/SqlRank.tla`, run on the real SQL.
 *
 * One key, one stamp. A database applies observations one at a time: pulled
 * ones through `mergeIncoming` (origin `remote`), its own run's through
 * `replaceOwnRunRows` and `mergeIncoming` (origin `local`), as `admitUpserts`
 * does. A pulled operation is in the log. An own batch is in the log only when
 * it changed the row (publish sends changes). The stored row must be the one a
 * reader gets by folding that log with the stream-sync comparator
 * (`upsertAfter`), whatever order the operations came in.
 */
const CONNECTION = "c1";
const STAMP = { o: 1000, r: "run-a" };
const bodyOf = (v: number) => canonicalJson({ id: "K", v });

type Step =
  | { readonly kind: "pull"; readonly ord: number; readonly v: number }
  | { readonly kind: "intake"; readonly v: number };

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function database() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "equal-stamp",
  });
  drivers.push(db);
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [CONNECTION],
    },
  ]);
  return db;
}

const stage = (op: string, ord: number, v: number) => {
  const body = bodyOf(v);
  return {
    sql: "INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, stamp_n, body, body_sha256) VALUES (?, 's', 'aa01', 'K', ?, ?, ?, ?, ?)",
    params: [
      op,
      STAMP.o,
      STAMP.r,
      ord,
      body,
      toHex(sha256(new TextEncoder().encode(body))),
    ],
  };
};

async function run(db: SqlDriver, steps: readonly Step[]) {
  const log: LogUpsert[] = [];
  let nextOrd = 0;
  const op = (i: number) => `op-${i}`;
  const row = async () =>
    (
      await db.query<{ body: string; stamp_n: number }>(
        "SELECT body, stamp_n FROM records",
      )
    )[0] ?? null;
  const entry = (ord: number, v: number): LogUpsert => ({
    kind: "upsert",
    stream: "s",
    pkHash: "aa01",
    stamp: STAMP,
    ordinal: ord,
    firstSeen: null,
    value: { id: "K", v },
  });
  for (const [i, step] of steps.entries()) {
    if (step.kind === "pull") {
      await db.batch(
        withOrigin("remote", [
          stage(op(i), step.ord, step.v),
          ...mergeIncoming(op(i), CONNECTION, { firstSeenOfWinner: true }),
        ]),
      );
      log.push(entry(step.ord, step.v));
    } else {
      const before = await row();
      const ord = nextOrd++;
      await db.batch(
        withOrigin("local", [
          stage(op(i), ord, step.v),
          replaceOwnRunRows(op(i), CONNECTION, STAMP.r, STAMP.o),
          ...mergeIncoming(op(i), CONNECTION),
        ]),
      );
      const after = await row();
      if (JSON.stringify(after) !== JSON.stringify(before))
        log.push(entry(ord, step.v));
    }
  }
  return { log, row: await row() };
}

/** What a reader that folds the log holds: the greatest upsert by the one order. */
function folded(log: readonly LogUpsert[]) {
  let best: LogUpsert | null = null;
  for (const u of log) if (best === null || upsertAfter(u, best)) best = u;
  return best === null
    ? null
    : { body: canonicalJson(best.value), stamp_n: best.ordinal ?? 0 };
}

function describeSteps(steps: readonly Step[]) {
  return steps
    .map((s) =>
      s.kind === "pull" ? `pull(n${s.ord},v${s.v})` : `intake(v${s.v})`,
    )
    .join(" ");
}

describe("equal-stamp order: the stored row is the fold of the log", () => {
  it("the trace of an identical body at a higher ordinal, then a lower ordinal of another body", async () => {
    const db = await database();
    // A/n0, A/n2 (a clone), then B/n1 (another clone): the fold keeps A/n2.
    const steps: Step[] = [
      { kind: "pull", ord: 0, v: 1 },
      { kind: "pull", ord: 2, v: 1 },
      { kind: "pull", ord: 1, v: 2 },
    ];
    const { log, row } = await run(db, steps);
    expect(row).toEqual({ body: bodyOf(1), stamp_n: 2 });
    expect(row).toEqual(folded(log));
  });

  it("a pulled higher ordinal of another body is not replaced by this run's lower ordinal", async () => {
    const db = await database();
    // The clone's n2 arrives while this run is collecting; this run's own
    // first batch (n0) is another body with a lower rank.
    const steps: Step[] = [
      { kind: "pull", ord: 2, v: 1 },
      { kind: "intake", v: 2 },
    ];
    const { log, row } = await run(db, steps);
    expect(row).toEqual({ body: bodyOf(1), stamp_n: 2 });
    expect(row).toEqual(folded(log));
  });

  it("an own batch at the same ordinal and a lower body hash does not replace the greater one", async () => {
    const db = await database();
    const hash = (v: number) =>
      toHex(sha256(new TextEncoder().encode(bodyOf(v))));
    const [low, high] = hash(1) < hash(2) ? [1, 2] : [2, 1];
    const { log, row } = await run(db, [
      { kind: "pull", ord: 0, v: high },
      { kind: "intake", v: low },
    ]);
    expect(row).toEqual({ body: bodyOf(high), stamp_n: 0 });
    expect(row).toEqual(folded(log));
  });

  it("every order of up to three observations ends on the fold", async () => {
    const db = await database();
    const actions: Step[] = [];
    for (const ord of [0, 1, 2])
      for (const v of [1, 2, 3]) actions.push({ kind: "pull", ord, v });
    for (const v of [1, 2, 3]) actions.push({ kind: "intake", v });
    const sequences: Step[][] = [[]];
    let layer: Step[][] = [[]];
    for (let depth = 0; depth < 3; depth++) {
      layer = layer.flatMap((s) => actions.map((a) => [...s, a]));
      sequences.push(...layer);
    }
    const failures: string[] = [];
    for (const steps of sequences) {
      await db.batch([
        { sql: "DELETE FROM records", params: [] },
        { sql: "DELETE FROM incoming", params: [] },
      ]);
      const { log, row } = await run(db, steps);
      if (JSON.stringify(row) !== JSON.stringify(folded(log)))
        failures.push(describeSteps(steps));
    }
    expect(failures.slice(0, 5)).toEqual([]);
    expect(failures).toHaveLength(0);
  }, 120_000);

  it("random longer sequences end on the fold", async () => {
    const db = await database();
    let seed = 20261116;
    const next = (n: number) => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed % n;
    };
    const failures: string[] = [];
    for (let i = 0; i < 150; i++) {
      const steps: Step[] = Array.from({ length: 8 }, () =>
        next(4) === 0
          ? { kind: "intake", v: 1 + next(3) }
          : { kind: "pull", ord: next(4), v: 1 + next(3) },
      );
      await db.batch([
        { sql: "DELETE FROM records", params: [] },
        { sql: "DELETE FROM incoming", params: [] },
      ]);
      const { log, row } = await run(db, steps);
      if (JSON.stringify(row) !== JSON.stringify(folded(log)))
        failures.push(describeSteps(steps));
    }
    expect(failures.slice(0, 3)).toEqual([]);
  }, 120_000);
});
