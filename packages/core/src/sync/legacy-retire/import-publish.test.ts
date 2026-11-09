/**
 * What the import does after it stages: it publishes its own run, so a
 * connector that never runs again is still readable; it never stalls a
 * connector's writes for ever; and it says what it left behind. The titles
 * name the mutants `__mutants__/run-mutants.mjs` applies.
 */

import { describe, expect, it } from "vitest";
import type { DeclarationSnapshot } from "../../pdpp/types.js";
import { createCanonicalImportSource } from "./canonical-source.js";
import { createMemoryImportAuthority } from "./import-authority.js";
import { CONNECTOR, flow, OWNER, raw, STREAM } from "./retire-rig.js";

type Flow = Awaited<ReturnType<typeof flow>>;

/** One sync cycle of the writer: the controls are read, then every ready run publishes. */
const publish = async (f: Flow) => {
  await f.rig.writer.refreshControls();
  return f.rig.publish();
};

const SOURCE_ID = `https://registry.example.test/connectors/${CONNECTOR}`;
const INSTANCE = `${CONNECTOR}:${OWNER}`;

const DECLARED = [
  {
    source_id: SOURCE_ID,
    source_kind: "connector",
    version: "9.9.9",
    digest: "sha256:test",
    streams: [
      {
        name: STREAM,
        fields: [],
        required_fields: [],
        primary_key: ["id"],
      },
    ],
  },
] as unknown as DeclarationSnapshot[];

/** A canonical store holding `rows` of the stream, plus `extras` of an undeclared one. */
function store(rows: Record<string, unknown>[], extras = 0) {
  const all: Record<string, Record<string, unknown>[]> = {
    [`${INSTANCE}|${STREAM}`]: rows,
  };
  if (extras > 0) {
    all[`${INSTANCE}|extras`] = Array.from({ length: extras }, (_, i) => ({
      id: `x${i}`,
    }));
  }
  return {
    listConnections: () => [{ instance: INSTANCE, deletedAt: null }],
    listStreams: () =>
      Object.entries(all).map(([key, list]) => ({
        stream: key.split("|")[1]!,
        recordCount: list.length,
        lastUpdated: null,
      })),
    listRecords: (stream: string) => ({
      data: (all[`${INSTANCE}|${stream}`] ?? []).map((data) => ({ data })),
      hasMore: false,
    }),
  };
}

const sourceOf = (rows: Record<string, unknown>[], extras = 0) =>
  createCanonicalImportSource({
    owner: OWNER,
    deps: () => ({ store: store(rows, extras), declarations: DECLARED }),
  });

describe("a staged connector that never runs again is still readable (SEED_WAITS_FOR_CONNECTOR_RUN)", () => {
  it("publishes the staged rows with no connector run, then a later run adds to them", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")]),
      owner: OWNER,
    });
    await f.importer.run();
    // No connector run anywhere: the import's own run is the only one.
    const published = await publish(f);
    expect(published).toHaveLength(1);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(2);
    await f.rig.sync();
    // The stream reader holds both rows, so the legacy file's rows are readable.
    expect((await f.retire()).files[0]?.readback).toBe("pass");
    // A real run afterwards layers onto the seeded head.
    // (The rig's writer clock is fixed, so the later run is stamped just after the import run.)
    await f.rig.collect({
      runId: "later",
      full: true,
      key: "id",
      version: "1.0.0",
      stream: STREAM,
      rows: [raw("e2")],
      at: 3_600_500,
    });
    await publish(f);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(3);
  });

  it("saves no checkpoint, so the first real run is a full run (IMPORT_RUN_SAVES_CHECKPOINT)", async () => {
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
    });
    await f.importer.run();
    await publish(f);
    const plan = await f.rig.writer.runPlan(CONNECTOR);
    expect(plan.checkpoint).toBeNull();
    const start = await f.rig.writer.issueStart(CONNECTOR, false);
    expect(start.full).toBe(true);
  });

  it("asks again on each pass until the writer says it published (PUBLISH_NEVER_RETRIED)", async () => {
    let calls = 0;
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
      publishSeed: async (connector, streams) => {
        calls += 1;
        if (calls === 1) throw new Error("the writer is busy");
        return f.rig.writer.publishSeed(connector, streams);
      },
    });
    await f.importer.run();
    expect(await f.importer.importDone(CONNECTOR)).toBe(true); // staged: writes may go
    expect(calls).toBe(1);
    await publish(f);
    expect(await f.rig.registeredHead(STREAM)).toBeNull();
    await f.importer.run(); // queues the run
    expect(calls).toBe(2);
    await publish(f);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(1);
    await f.importer.run(); // sees the receipt
    expect(calls).toBe(3);
    await f.importer.run();
    expect(calls).toBe(3); // done: not asked again
  });

  it("needs the streams it was asked about (SEED_ASKED_DEFAULTED)", async () => {
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
    });
    await f.importer.run();
    // A missing argument is a type error; were it defaulted to empty, a
    // stream the writer skipped would be reported as published.
    await expect(
      // @ts-expect-error `asked` is required
      f.rig.writer.publishSeed(CONNECTOR),
    ).rejects.toThrow();
  });

  it("does not queue a second run while the first one waits (DUPLICATE_IMPORT_RUNS)", async () => {
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
    });
    await f.importer.run();
    expect(await f.rig.writer.publishSeed(CONNECTOR, [STREAM])).toEqual({
      state: "waiting",
    });
    expect(await f.rig.writer.publishSeed(CONNECTOR, [STREAM])).toEqual({
      state: "waiting",
    });
    await f.rig.writer.refreshControls();
    expect(await f.rig.publish()).toHaveLength(1);
  });
});

describe("a run admitted before the switch cannot skip the seed (SEED_BOUND_BEFORE_IMPORT)", () => {
  it("holds the run until the import is done, then merges the seed", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")]),
      owner: OWNER,
      switched: false,
    });
    // Unswitched: nothing waits for an import, the run is admitted.
    await f.run("early", ["e2"]);
    f.setSwitched(true);
    // The switch landed before the run published. It must not bind the first
    // generation without the seed.
    await publish(f);
    expect(await f.rig.registeredHead(STREAM)).toBeNull();
    expect((await f.rig.writer.seedStatus(CONNECTOR)).receipts).toEqual({});
    await f.importer.run();
    await publish(f);
    await publish(f);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(3);
    expect(
      Object.values((await f.rig.writer.seedStatus(CONNECTOR)).receipts),
    ).toEqual(["merged"]);
  });
});

describe("a connector whose import cannot finish does not stall for ever (PERMANENT_FAILURE_STALLS_WRITES)", () => {
  it("gives the connector up after the bound, lets new runs through, and keeps its file (FAILED_IMPORT_RETIRES)", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")]),
      owner: OWNER,
      sinkThrows: STREAM,
      maxAttempts: 3,
    });
    for (const attempt of [1, 2]) {
      expect(await f.importer.run()).toMatchObject({ failed: 1 });
      expect(await f.importer.importDone(CONNECTOR)).toBe(false);
      expect((await f.ledger.read()).failures[CONNECTOR]).toMatchObject({
        attempts: attempt,
        gaveUp: false,
      });
    }
    expect(await f.importer.run()).toMatchObject({ failed: 1 });
    expect((await f.ledger.read()).failures[CONNECTOR]).toMatchObject({
      attempts: 3,
      gaveUp: true,
    });
    // New runs proceed.
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    await f.run("a", ["e0", "e1"]);
    await publish(f);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(2);
    // The pass is over: it does not try the connector again.
    const calls = f.stagings;
    await f.importer.run();
    expect(f.stagings).toBe(calls);
    // The legacy file is kept even though the published view holds it (FAILED_IMPORT_RETIRES).
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]?.decision).toBe("no_import");
    // And the owner read says so.
    expect(await f.importer.status()).toMatchObject({
      complete: true,
      connectors: [{ connector: CONNECTOR, state: "failed", attempts: 3 }],
    });
  });

  it("gives the source up when it cannot be listed, keeping every file (LISTING_FAILURE_STALLS_FOR_EVER, ABANDONED_SOURCE_RETIRES)", async () => {
    const f = await flow({
      local: ["e0"],
      source: {
        owner: OWNER,
        connectors: async () => {
          throw new Error("the store is corrupt");
        },
        streams: async () => [],
      },
      owner: OWNER,
      maxAttempts: 2,
    });
    await f.importer.run();
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    await f.importer.run();
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    expect(await f.importer.status()).toMatchObject({
      complete: true,
      abandoned: true,
    });
    await f.run("a", ["e0"]);
    await publish(f);
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]?.decision).toBe("no_import");
  });
});

describe("what the import left behind is one owner read (STATUS_HIDES_EXCLUDED)", () => {
  it("counts rows by connector and reason, with no row content", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1"), { content: "no key at all" }], 2),
      owner: OWNER,
    });
    expect(await f.importer.status()).toMatchObject({
      complete: false,
      connectors: [],
    });
    await f.importer.run();
    await publish(f);
    await f.importer.run();
    const status = await f.importer.status();
    expect(status).toEqual({
      complete: true,
      abandoned: false,
      givenUp: 0,
      stayed: 3,
      connectors: [
        {
          connector: CONNECTOR,
          state: "published",
          attempts: 0,
          staged: 2,
          stayed: 3,
          excluded: [
            { reason: "unkeyed_row", rows: 1 },
            { reason: "unmapped_stream", rows: 2 },
          ],
        },
      ],
    });
    expect(JSON.stringify(status)).not.toContain("no key at all");
  });
});

describe("the status shows a stalled publish (STATUS_REPORTS_PUBLISHED_UNPUBLISHED)", () => {
  it("reports imported, not published, and tells the authority nothing, until the writer merges the seed", async () => {
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
    });
    await f.importer.run(); // staged; the publish is only queued
    expect(await f.importer.status()).toMatchObject({
      complete: false,
      // What stayed is pending until the writer answers for the staged rows.
      stayed: null,
      connectors: [
        { connector: CONNECTOR, state: "imported", staged: 1, stayed: null },
      ],
    });
    expect(f.authority.doneCalls).toEqual([]);
    await publish(f);
    await f.importer.run(); // sees the receipt
    expect(await f.importer.status()).toMatchObject({
      complete: true,
      connectors: [{ connector: CONNECTOR, state: "published" }],
    });
    expect(f.authority.doneCalls).toEqual([OWNER.toLowerCase()]);
  });

  it("does not tell the authority the import is done while the publish is held (DONE_BEFORE_PUBLISHED)", async () => {
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
      publishSeed: async () => ({ state: "waiting" }),
    });
    await f.importer.run();
    await f.importer.run();
    expect(f.authority.doneCalls).toEqual([]);
    expect(await f.ledger.importPending()).toBe(true);
    expect((await f.importer.status()).connectors[0]?.state).toBe("imported");
  });
});

describe("rows that stayed in legacy are counted for a failed connector (FAILED_STAYED_NOT_COUNTED)", () => {
  it("counts the connector's rows, with no row content, when its import is given up", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")], 2),
      owner: OWNER,
      sinkThrows: STREAM,
      maxAttempts: 2,
    });
    await f.importer.run();
    expect(await f.importer.status()).toMatchObject({
      stayed: 4,
      connectors: [{ connector: CONNECTOR, state: "pending", stayed: 4 }],
    });
    await f.importer.run();
    const status = await f.importer.status();
    expect(status).toMatchObject({
      stayed: 4,
      connectors: [{ connector: CONNECTOR, state: "failed", stayed: 4 }],
    });
    // A source that cannot be listed leaves the count unknown, not zero.
  });

  it("leaves the count unknown, not zero, when the source was abandoned", async () => {
    const f = await flow({
      local: ["e0"],
      source: {
        owner: OWNER,
        connectors: async () => {
          throw new Error("the store is corrupt");
        },
        streams: async () => [],
      },
      owner: OWNER,
      maxAttempts: 1,
    });
    await f.importer.run();
    expect(await f.importer.status()).toMatchObject({
      abandoned: true,
      stayed: null,
    });
  });
});

describe("a seed the writer skipped is not published (SKIPPED_SEED_MARKED_PUBLISHED)", () => {
  it("counts the streams as left behind, reports no publish, and keeps the legacy file", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")]),
      owner: OWNER,
      publishSeed: async () => ({ state: "done", skipped: [STREAM] }),
    });
    await f.importer.run();
    await f.importer.run();
    const status = await f.importer.status();
    expect(status.connectors[0]).toMatchObject({
      state: "imported",
      staged: 2,
      stayed: 2,
      excluded: [{ reason: "seed_skipped", rows: 2 }],
    });
    expect((await f.ledger.read()).imported[CONNECTOR]).not.toHaveProperty(
      "published",
    );
    // Final: the authority is told; but the file is never retired.
    expect(f.authority.doneCalls).toEqual([OWNER.toLowerCase()]);
    expect(await f.ledger.importProven(CONNECTOR)).toBe(false);
  });
});

describe("the import names the connection it chose (CHOICE_NOT_SURFACED, TIE_NOT_FLAGGED)", () => {
  /** Two live connections of the connector, each with its own rows and latest write. */
  const twoConnections = (latest: [string, string]) => {
    const A = `${CONNECTOR}:${OWNER}:a`;
    const B = `${CONNECTOR}:${OWNER}:b`;
    const rows: Record<string, Record<string, unknown>[]> = {
      [A]: [raw("a0"), raw("a1")],
      [B]: [raw("b0")],
    };
    const stamp: Record<string, string> = { [A]: latest[0], [B]: latest[1] };
    return createCanonicalImportSource({
      owner: OWNER,
      deps: () => ({
        store: {
          listConnections: () => [
            { instance: A, deletedAt: null },
            { instance: B, deletedAt: null },
          ],
          listStreams: (instances: string[]) =>
            instances.flatMap((instance) => [
              {
                stream: STREAM,
                recordCount: rows[instance]!.length,
                lastUpdated: stamp[instance] ?? null,
              },
            ]),
          listRecords: (
            _stream: string,
            options: { instanceIds: string[] },
          ) => ({
            data: rows[options.instanceIds[0]!]!.map((data) => ({ data })),
            hasMore: false,
          }),
        },
        declarations: DECLARED,
      }),
    });
  };

  it("surfaces which connection was chosen and how many were passed over, as truncated hashes", async () => {
    const f = await flow({
      local: ["a0", "a1"],
      source: twoConnections(["2026-01-01T00:00:02Z", "2026-01-01T00:00:01Z"]),
      owner: OWNER,
    });
    await f.importer.run();
    const status = await f.importer.status();
    const choice = status.connectors[0]?.connection;
    expect(choice).toMatchObject({ passedOver: 1, tied: false });
    expect(choice?.chosen).toMatch(/^[0-9a-f]{12}$/);
    expect(JSON.stringify(status)).not.toContain(`${CONNECTOR}:${OWNER}`);
    expect(status.connectors[0]).toMatchObject({
      staged: 2,
      excluded: [{ reason: "other_connection", rows: 1 }],
    });
  });

  it("says so when the top two connections tie on their latest write", async () => {
    const same = "2026-01-01T00:00:05Z";
    const f = await flow({
      local: ["a0", "a1"],
      source: twoConnections([same, same]),
      owner: OWNER,
    });
    await f.importer.run();
    expect((await f.importer.status()).connectors[0]?.connection).toMatchObject(
      { passedOver: 1, tied: true },
    );
  });
});

describe("the authority owns done (AUTHORITY_PENDING_IGNORED)", () => {
  it("does nothing once the authority says the import is done", async () => {
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
      authority: createMemoryImportAuthority({ pending: false }),
    });
    expect(await f.importer.run()).toMatchObject({ ran: false });
    expect(f.staged.size).toBe(0);
    expect(f.authority.doneCalls).toEqual([]);
    // The writer's gate is open for every connector.
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
  });
});

describe("an excluded row keeps its connector's legacy file (EXCLUDED_ROWS_RETIRE)", () => {
  it("retires when nothing was left behind and refuses when something was", async () => {
    const clean = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")]),
      owner: OWNER,
    });
    await clean.importer.run();
    await publish(clean);
    expect((await clean.retire()).deleted).toBe(1);

    const left = await flow({
      local: ["e0", "e1"],
      source: sourceOf([raw("e0"), raw("e1")], 1),
      owner: OWNER,
    });
    await left.importer.run();
    await publish(left);
    const report = await left.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]?.decision).toBe("no_import");
  });
});
