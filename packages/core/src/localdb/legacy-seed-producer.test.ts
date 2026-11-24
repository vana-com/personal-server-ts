import { describe, expect, it } from "vitest";
import {
  seedLegacyStore,
  type LegacySeedStream,
} from "./legacy-seed-producer.js";
import type { FoldLayer } from "./legacy-fold.js";
import type { SeedIntake } from "./seed.js";

// The producer reads a host's legacy store twice: once to count the rows the
// upload will carry, once to write them. It must stop on abort in either pass,
// close every reader it opened, and keep each upload chunk within its bound.

const CHUNK_BYTES = 256 * 1024;

/** A complete v1-full envelope of the `items` stream (what a delete needs). */
const envelopeOf = (
  sourceId: string,
  record: { key: unknown; op: string },
  stream = "items",
) => ({
  version: 1,
  sourceId,
  declaration: { digest: "digest", version: "1" },
  stream: { name: stream, scope: stream, primaryKey: ["id"] },
  record,
});

/** An intake that drains the body as the real one does, and keeps what it saw. */
function intake() {
  const chunks: Uint8Array[] = [];
  const puts: string[] = [];
  const port: SeedIntake = {
    async status() {
      return { targetKnown: true, streams: {} };
    },
    async put(_connector, stream, body) {
      for await (const chunk of body) chunks.push(chunk);
      puts.push(stream);
      return { state: "staged", records: 0, invalid: 0 };
    },
  };
  return { port, chunks, puts };
}

const stream = (layers: FoldLayer[]): LegacySeedStream => ({
  connector: "fixture",
  stream: "items",
  primaryKey: ["id"],
  version: "1",
  layers,
});
const store = (...streams: LegacySeedStream[]) => ({
  async *streams() {
    yield* streams;
  },
});

/** A layer that notes each open and close of its reader. */
function watched(rows: () => AsyncIterable<unknown>, log: string[]): FoldLayer {
  return {
    async *records() {
      log.push("open");
      try {
        yield* rows();
      } finally {
        log.push("close");
      }
    },
  };
}

describe("seedLegacyStore abort", () => {
  it("closes the reader when the counting pass is aborted", async () => {
    const abort = new AbortController();
    const log: string[] = [];
    const layer = watched(async function* () {
      for (let i = 0; i < 10; i++) {
        if (i === 3) abort.abort();
        yield { id: `k${i}` };
      }
    }, log);
    const { port, puts } = intake();
    await expect(
      seedLegacyStore(port, store(stream([layer])), { signal: abort.signal }),
    ).rejects.toThrow();
    expect(log).toEqual(["open", "close"]);
    expect(puts).toEqual([]);
  });

  it("stops the upload pass, rows the fold skips included, and imports nothing", async () => {
    const abort = new AbortController();
    const log: string[] = [];
    let pass = 0;
    const layer = watched(async function* () {
      pass++;
      yield { id: "a" };
      // Rows the fold leaves out (no key): the second pass reaches the abort
      // only here, after the last row it would write.
      for (let i = 0; i < 5; i++) {
        if (pass === 2 && i === 2) abort.abort();
        yield { nope: i };
      }
    }, log);
    const { port, puts } = intake();
    await expect(
      seedLegacyStore(port, store(stream([layer])), { signal: abort.signal }),
    ).rejects.toThrow();
    expect(pass).toBe(2);
    expect(log).toEqual(["open", "close", "open", "close"]);
    expect(puts).toEqual([]);
  });
});

describe("seedLegacyStore chunks", () => {
  it("bounds each chunk by UTF-8 bytes, not UTF-16 code units", async () => {
    // Each row is about 90 KB as UTF-8 and 30 KB as UTF-16 code units.
    const wide = "日".repeat(30_000);
    const layer: FoldLayer = {
      async *records() {
        for (let i = 0; i < 12; i++) yield { id: `k${i}`, wide };
      },
    };
    const { port, chunks } = intake();
    await seedLegacyStore(port, store(stream([layer])));
    expect(chunks.length).toBeGreaterThan(1);
    for (const chunk of chunks)
      expect(chunk.byteLength).toBeLessThanOrEqual(CHUNK_BYTES);
    // Nothing is lost to the flush rule: the lines add back up to every row.
    const text = chunks.map((c) => new TextDecoder().decode(c)).join("");
    expect(text.trimEnd().split("\n")).toHaveLength(1 + 12);
  });

  it("sends a line larger than the bound alone", async () => {
    const layer: FoldLayer = {
      async *records() {
        yield { id: "small" };
        yield { id: "huge", wide: "日".repeat(100_000) };
        yield { id: "small-2" };
      },
    };
    const { port, chunks } = intake();
    await seedLegacyStore(port, store(stream([layer])));
    const lines = chunks.map(
      (c) => new TextDecoder().decode(c).trimEnd().split("\n").length,
    );
    expect(lines.reduce((a, b) => a + b, 0)).toBe(1 + 3);
    expect(chunks.some((c) => c.byteLength > CHUNK_BYTES)).toBe(true);
    expect(chunks.filter((c) => c.byteLength > CHUNK_BYTES)).toHaveLength(1);
    const big = chunks.find((c) => c.byteLength > CHUNK_BYTES)!;
    expect(new TextDecoder().decode(big).trimEnd().split("\n")).toHaveLength(1);
  });
});

describe("seedLegacyStore counts", () => {
  it("counts a malformed stored delete envelope in the quarantine totals", async () => {
    const SOURCE = "urn:fixture";
    const envelope = (id: unknown, claim: unknown, op = "delete") => ({
      id,
      $pdpp: envelopeOf(SOURCE, { key: claim, op }),
    });
    const layer: FoldLayer = {
      async *records() {
        yield { id: "kept", $pdpp: { sourceId: SOURCE } };
        yield envelope("a", "not-a-key");
        yield envelope("b", { id: "other" });
        yield envelope("c", { nope: 1 });
        yield envelope("d", { id: "d" }, "patch");
      },
    };
    const { port } = intake();
    const report = await seedLegacyStore(
      port,
      store({ ...stream([layer]), sourceId: SOURCE }),
    );
    expect(report.rows).toBe(1);
    expect(report.quarantine).toEqual({
      deletion_envelope_incomplete: 1,
      deletion_record_key_mismatch: 1,
      deletion_missing_key_field: 1,
      unknown_op: 1,
    });
    expect(report.streams[0]!.quarantine).toEqual(report.quarantine);
  });

  it("reports a stream another writer finished first as merged, not staged", async () => {
    const put: string[] = [];
    const port: SeedIntake = {
      async status() {
        // Not final yet when the producer asks.
        return { targetKnown: true, streams: {} };
      },
      async put(_connector, name) {
        // A final receipt appeared in between: the body is never consumed.
        put.push(name);
        return { state: "merged" };
      },
    };
    const layer: FoldLayer = {
      async *records() {
        yield { id: "a" };
        yield { nope: 1 };
      },
    };
    const report = await seedLegacyStore(port, store(stream([layer])));
    expect(put).toEqual(["items"]);
    expect(report.streams).toEqual([
      {
        connector: "fixture",
        stream: "items",
        outcome: "merged",
        rows: 0,
        quarantine: {},
        invalid: 0,
      },
    ]);
    expect(report.rows).toBe(0);
    expect(report.quarantine).toEqual({});
  });
});

describe("seedLegacyStore deletes", () => {
  const tag = { sourceId: "urn:fixture" };
  const del = (id: string, stream = "items") => ({
    id,
    $pdpp: envelopeOf(tag.sourceId, { key: { id }, op: "delete" }, stream),
  });
  const row = (id: string) => ({ id, $pdpp: tag });
  const layer = (...records: unknown[]): FoldLayer => ({
    async *records() {
      yield* records;
    },
  });

  it("counts a layer of valid delete envelopes, and one a live row shadows", async () => {
    const { port, puts } = intake();
    const report = await seedLegacyStore(port, {
      async *streams() {
        yield {
          ...stream([layer(del("a"), del("b"))]),
          sourceId: tag.sourceId,
        };
        yield {
          ...stream([layer(row("k"), del("k", "shadowed"))]),
          stream: "shadowed",
          sourceId: tag.sourceId,
        };
      },
    });
    // The delete-only stream imports nothing, and says what its records were.
    expect(report.streams[0]).toMatchObject({
      outcome: "empty",
      rows: 0,
      quarantine: { delete_envelope: 2 },
    });
    // A live row of the same layer outranks its delete; the delete still counts.
    expect(report.streams[1]).toMatchObject({
      outcome: "staged",
      rows: 1,
      quarantine: { delete_envelope: 1 },
    });
    expect(report.quarantine).toEqual({ delete_envelope: 3 });
    expect(puts).toEqual(["shadowed"]);
  });
});

describe("seedLegacyStore conflicts", () => {
  it("refuses a stream whose layer repeats a key with different bodies, and carries on", async () => {
    const { port, puts } = intake();
    const repeat: FoldLayer = {
      async *records() {
        yield { id: "a", v: 1 };
        yield { id: "a", v: 2 };
      },
    };
    const fine: FoldLayer = {
      async *records() {
        yield { id: "b" };
      },
    };
    const report = await seedLegacyStore(port, {
      async *streams() {
        yield stream([repeat]);
        yield { ...stream([fine]), stream: "other" };
      },
    });
    expect(report.streams[0]).toMatchObject({
      outcome: "refused",
      reason: "invalid_record",
      rows: 0,
    });
    expect(report.streams[1]).toMatchObject({ outcome: "staged", rows: 1 });
    expect(puts).toEqual(["other"]);
  });
});

describe("seedLegacyStore drift", () => {
  /** A layer whose Nth read yields `passes[N]`. */
  const drifting = (...passes: unknown[][]): FoldLayer => {
    let read = 0;
    return {
      async *records() {
        yield* passes[Math.min(read++, passes.length - 1)]!;
      },
    };
  };

  it("refuses a stream whose rows changed between the passes with the same count, and carries on", async () => {
    const { port, puts } = intake();
    const steady = { ...stream([drifting([{ id: "z" }])]), stream: "steady" };
    const report = await seedLegacyStore(
      port,
      store(
        stream([
          drifting(
            [
              { id: "a", v: 1 },
              { id: "b", v: 1 },
            ],
            [
              { id: "a", v: 1 },
              { id: "b", v: 2 },
            ],
          ),
        ]),
        steady,
      ),
    );
    expect(report.streams).toMatchObject([
      { stream: "items", outcome: "refused", reason: "source_changed" },
      { stream: "steady", outcome: "staged" },
    ]);
    // The drifting stream's body never ended cleanly, so nothing was imported
    // for it, and its rows are not counted.
    expect(puts).toEqual(["steady"]);
    expect(report.rows).toBe(1);
  });

  it("refuses a stream whose left-out rows changed between the passes", async () => {
    const { port, puts } = intake();
    const report = await seedLegacyStore(
      port,
      store(
        stream([
          // The same importable row; a different row is left out each time.
          drifting([{ id: "a" }, { nope: 1 }], [{ id: "a" }, 5]),
        ]),
      ),
    );
    expect(report.streams).toMatchObject([
      { outcome: "refused", reason: "source_changed" },
    ]);
    expect(puts).toEqual([]);
  });

  it("stages a stream that did not change", async () => {
    const { port, puts } = intake();
    const same = [{ id: "a", v: 1 }, { nope: 1 }];
    const report = await seedLegacyStore(
      port,
      store(stream([drifting(same, same)])),
    );
    expect(report.streams).toMatchObject([
      { outcome: "staged", rows: 1, quarantine: { missing_key_field: 1 } },
    ]);
    expect(puts).toEqual(["items"]);
  });
});
