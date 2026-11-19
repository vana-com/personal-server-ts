import { afterEach, expect, it } from "vitest";
import type { LogOperation } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  closeWorldDrivers,
  CONNECTION_ID,
  sName,
  world,
} from "./log-world.test-utils.js";
afterEach(closeWorldDrivers);

// Keep the former all-key query as a small, independent reference. Production
// must never use this query shape to materialize a source's operation bodies.
it.each([7, 19, 43])(
  "cursor operations equal the all-key reference for generated source %i",
  async (seed) => {
    const w = await world({ streams: 1, partTargetBytes: 65536 });
    const a = await w.device("a");
    const stream = sName(0);
    const ids = Array.from({ length: 24 }, (_, i) =>
      i % 2 ? `key:${seed}:${i}:\\"\n雪😀` : seed * 100 + i,
    );
    await a.run(
      "first",
      ids.map((id) => ({ stream, id, v: 1 })),
    );
    await a.cycle();
    const before = await a.position();
    const kept = ids.filter((_, i) => (i * seed) % 5 < 3);
    const deleted = ids.filter((_, i) => (i * seed) % 5 === 3);
    await a.run(
      "next",
      [
        ...kept.map((id) => ({ stream, id, v: 2 })),
        ...deleted.map((id) => ({ stream, id, remove: true })),
        ...Array.from({ length: 5 }, (_, i) => ({
          stream,
          id: `new:${seed}:${i}`,
          v: 3,
        })),
      ],
      { observedAt: 5000 },
    );
    const [state] = await a.db.query<{ publish_watermark: number }>(
      "SELECT publish_watermark FROM stream_state WHERE connection_id=? AND stream=?",
      [CONNECTION_ID, stream],
    );
    const window = [CONNECTION_ID, stream, state!.publish_watermark];
    const rows = await a.db.query<{
      pk_hash: string;
      stamp_o: number;
      stamp_r: string;
      stamp_n: number;
      first_o: number | null;
      body: string;
    }>(
      `SELECT pk_hash,stamp_o,stamp_r,stamp_n,first_o,body FROM records WHERE connection_id=? AND stream=? AND pk_hash IN
      (SELECT pk_hash FROM record_changes WHERE connection_id=? AND stream=? AND seq>?)`,
      [CONNECTION_ID, stream, ...window],
    );
    const deletes = await a.db.query<{
      pk_hash: string;
      pk_values: string;
      stamp_o: number;
      stamp_r: string;
    }>(
      `SELECT pk_hash,pk_values,stamp_o,stamp_r,MAX(seq) FROM record_changes WHERE connection_id=? AND stream=? AND seq>? AND explicit_delete=1
      AND NOT EXISTS(SELECT 1 FROM records r WHERE r.connection_id=record_changes.connection_id AND r.stream=record_changes.stream AND r.pk_hash=record_changes.pk_hash) GROUP BY pk_hash`,
      window,
    );
    const omitted = await a.db.query<{ pk_hash: string; body: string }>(
      `SELECT pk_hash,body FROM records WHERE connection_id=? AND stream=? AND (COALESCE(seen_o,stamp_o),COALESCE(seen_r,stamp_r)) < (5000,'next') ORDER BY pk_hash`,
      [CONNECTION_ID, stream],
    );
    const expected: LogOperation[] = [
      ...rows
        .sort((a, b) => a.pk_hash.localeCompare(b.pk_hash))
        .map((r) => ({
          kind: "upsert" as const,
          stream,
          pkHash: r.pk_hash,
          stamp: { o: r.stamp_o, r: r.stamp_r },
          ...(r.stamp_n ? { ordinal: r.stamp_n } : {}),
          firstSeen: r.first_o,
          value: JSON.parse(r.body),
        })),
      ...deletes
        .sort((a, b) => a.pk_hash.localeCompare(b.pk_hash))
        .map((r) => ({
          kind: "delete" as const,
          stream,
          pkHash: r.pk_hash,
          stamp: { o: r.stamp_o, r: r.stamp_r },
          key: JSON.parse(r.pk_values),
        })),
      {
        kind: "complete",
        stream,
        cutoff: { o: 5000, r: "next" },
        omitted: omitted.map((r) => ({
          pkHash: r.pk_hash,
          key: [JSON.parse(r.body).id],
        })),
      },
    ];
    await a.cycle();
    const emitted = [...(await w.segments()).values()]
      .filter((s) => s.position > before)
      .sort((a, b) => a.position - b.position)
      .flatMap((s) => s.operations);
    expect(emitted).toEqual(expected);
    const b = await w.device("b");
    await b.cycle();
    expect(await b.rows()).toEqual(await a.rows());
  },
  120000,
);

it("replaces reference-backed history with an admitted oversized record and truthful completion", async () => {
  const w = await world({ streams: 1, partTargetBytes: 4096 });
  const stream = sName(0),
    a = await w.device("a");
  await a.run("first", [
    { stream, id: "keep", v: 1, pad: 8192 },
    { stream, id: "drop", v: 1, pad: 8192 },
  ]);
  await a.cycle();
  expect(
    [...(await w.segments()).values()]
      .flatMap((s) => s.operations)
      .some((op) => op.kind === "upsert-ref"),
  ).toBe(true);
  const b = await w.device("b");
  await b.cycle();
  await b.run("next", [{ stream, id: "keep", v: 2, pad: 8192 }], {
    observedAt: 5000,
  });
  await b.cycle();
  const c = await w.device("c");
  await c.cycle();
  expect(await c.rows()).toEqual(await b.rows());
  expect(await c.records()).toHaveLength(1);
  expect((await c.records())[0]).toContain('"v":2');
}, 120000);
