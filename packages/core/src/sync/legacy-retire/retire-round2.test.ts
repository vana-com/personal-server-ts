/**
 * The delete gates of a retire pass, on the real writer, registry fake and
 * read service (see `retire-rig.ts`). Every test runs the production
 * `retireLegacyFiles`; the names in the titles are the mutants the committed
 * runner applies (`__mutants__/run-mutants.mjs`).
 *
 * Timeline of the rig's registry for the one stream: version 1 is at T0
 * (2026-11-01T00:00:00Z), each later version one second after the one before.
 * A legacy file that predates the delete is `collectedAt` T0 and stored at the
 * epoch (the memory store's default); a file written after the delete is
 * dated the next day.
 */

import { describe, expect, it } from "vitest";
import { entityHashes } from "../../storage/legacy-entity-key-sets.js";
import { createMemoryStreamSyncFiles } from "../../stream-sync/memory-files.js";
import { createRetireHost } from "./host.js";
import { RetireLedger } from "./ledger.js";
import { predatesEveryDelete, readbackVersion } from "./readback.js";
import { retireLegacyFiles, type RetireHost } from "./retire.js";
import { AT, CONNECTOR, flow, legacy, raw, STREAM } from "./retire-rig.js";

const AFTER_DELETE = "2026-11-02T00:00:00.000Z";

type Flow = Awaited<ReturnType<typeof flow>>;

/** Collected, published, then deleted on another device, and the mirror saw it. */
async function deleted(f: Flow, ids = ["e0", "e1"]): Promise<void> {
  await f.importer.run();
  await f.run("a", ids);
  await f.rig.publish();
  await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
  await f.rig.sync();
}

/**
 * The source is reconnected: a full run collects only `ids` and publishes. A
 * run collected before the delete was seen is discarded by the fence, so one
 * such run goes first to let this device learn the delete.
 */
async function reconnected(f: Flow, ids: string[]): Promise<void> {
  await f.run("learn", ["x"]);
  await f.rig.publish();
  await f.run("live", ids);
  await f.rig.publish();
}

describe("a stored pass never deletes on its own (STALE_PASS_DELETES)", () => {
  it("reads the version back again in the same pass, and keeps the file when the published view moved on", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    expect((await f.retire(false)).files[0]).toMatchObject({
      readback: "pass",
    });

    // The published view changes after the pass was stored.
    await f.runRows("b", [raw("e0"), { ...raw("e1"), content: "edited" }]);
    await f.rig.publish();

    const report = await f.retire(true);
    expect(report.deleted).toBe(0);
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      decision: "readback_failed",
    });
    expect(f.storage.entries).toHaveLength(1);
  });

  it("still deletes when the fresh readback passes too", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    await f.retire(false);
    expect((await f.retire(true)).deleted).toBe(1);
  });
});

describe("a dry run stores no readback a real pass trusts (DRYRUN_READBACK_USABLE)", () => {
  it("marks the stored record dry and reads the version back again in the next real pass", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();

    const dry = await f.retire(true, true);
    expect(dry.deleted).toBe(0);
    const stored = Object.values((await f.ledger.read()).readbacks);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ pass: true, dry: true });
    expect(await f.ledger.readback(stored[0]!.scope, stored[0]!.version)).toBe(
      null,
    );

    await f.runRows("b", [raw("e0"), { ...raw("e1"), content: "edited" }]);
    await f.rig.publish();
    const real = await f.retire(false);
    expect(real.files[0]).toMatchObject({ readback: "fail" });
  });
});

describe("a readback made before the import finished is never trusted (PREIMPORT_READBACK_USABLE)", () => {
  it("is stored tagged, and the next real pass reads the version back again", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    await f.rig.sync();
    const row = f.storage.entries[0]!;
    const host = createRetireHost({
      reader: f.rig.service,
      writer: f.rig.writer,
      ledger: f.ledger,
    });
    const made = await readbackVersion(
      { storage: f.storage, view: host, ledger: f.ledger, preImport: true },
      row.scope,
      row,
    );
    expect(made).toMatchObject({ pass: true, preImport: true });
    expect(await f.ledger.readback(row.scope, made.version)).toBe(null);

    await f.runRows("b", [raw("e0"), { ...raw("e1"), content: "edited" }]);
    await f.rig.publish();
    const real = await f.retire(false);
    expect(real.files[0]).toMatchObject({ readback: "fail" });
  });
});

describe("the delete fence excuses only a file written before the delete (FENCE_AFTER_DELETE_WRITE)", () => {
  it("allowed: a pre-delete file after a whole-source delete passes its readback, and stays until the source is reconnected and re-collected", async () => {
    const f = await flow({ local: ["e0", "e1"], imported: true });
    await deleted(f);
    const early = await f.retire();
    expect(early.files[0]).toMatchObject({
      readback: "pass",
      decision: "fence_not_recollected",
    });
    expect(early.deleted).toBe(0);

    // The person reconnected the source. A full run collected only e5.
    // Deleting the pre-delete e0 and e1 is intended: the owner deleted the
    // source, and the old file on this device goes with it.
    await reconnected(f, ["e5"]);
    const done = await f.retire();
    expect(done.files[0]).toMatchObject({ decision: "ready" });
    expect(done.deleted).toBe(1);
  });

  it("allowed: a pre-delete file with a changed entity after a reconnect", async () => {
    const f = await flow({
      local: [],
      localRows: [legacy("e0"), { ...legacy("e1"), content: "older text" }],
      imported: true,
    });
    await deleted(f);
    await reconnected(f, ["e0", "e1"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({ readback: "pass" });
    expect(Object.values((await f.ledger.read()).readbacks)[0]).toMatchObject({
      fenced: 1,
    });
    expect(report.deleted).toBe(1);
  });

  it.each([
    ["the view is null (the source is still deleted)", false],
    ["the view lacks the entity (the source was reconnected)", true],
  ])(
    "never excuses a file collected after the delete when %s",
    async (_n, reconnect) => {
      const f = await flow({ local: ["e0", "e1"], collectedAt: AFTER_DELETE });
      await deleted(f);
      if (reconnect) await reconnected(f, ["e5"]);
      const report = await f.retire();
      expect(report.files[0]).toMatchObject({
        readback: "fail",
        decision: "readback_failed",
      });
      expect(report.deleted).toBe(0);
      expect(f.storage.entries).toHaveLength(1);
    },
  );

  it("a failed read of the published view is no deleted source (FENCE_NULL_VIEW_PASSES)", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      wrapHost: (host) => ({ ...host, publishedBody: async () => null }),
    });
    await deleted(f);
    await reconnected(f, ["e5"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      readbackReason: "no_published_view",
    });
    expect(report.deleted).toBe(0);
  });

  it.each([
    ["the source is deleted whole", false],
    ["the source was reconnected", true],
  ])(
    "a throwing read of the published view passes nothing when %s (FENCE_PASSES_WITHOUT_VIEW)",
    async (_n, reconnect) => {
      const f = await flow({
        local: ["e0", "e1"],
        wrapHost: (host) => ({
          ...host,
          publishedBody: async () => {
            throw new Error("storage 503");
          },
        }),
      });
      await deleted(f);
      if (reconnect) await reconnected(f, ["e5"]);
      const report = await f.retire();
      expect(report.files[0]).toMatchObject({
        readback: "fail",
        readbackReason: "no_published_view",
      });
      expect(report.deleted).toBe(0);
      expect(f.storage.entries).toHaveLength(1);
    },
  );

  it("never excuses a changed entity of a file collected after the delete (FENCE_CHANGED_PASSES)", async () => {
    const f = await flow({
      local: [],
      localRows: [legacy("e0"), { ...legacy("e1"), content: "newer text" }],
      collectedAt: AFTER_DELETE,
    });
    await deleted(f);
    await reconnected(f, ["e0", "e1"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      readbackReason: "mismatch",
    });
    expect(report.deleted).toBe(0);
  });

  it("never excuses a file this device stored after the delete, whatever its collectedAt says", async () => {
    const f = await flow({ local: ["e0", "e1"], createdAt: AFTER_DELETE });
    await deleted(f);
    await reconnected(f, ["e5"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({ readback: "fail" });
    expect(report.deleted).toBe(0);
  });

  it("never excuses a file when the time of the delete is unknown (UNKNOWN_DELETE_TIME_EXCUSES)", async () => {
    // The delete and the reconnect both happen before this device lists the
    // registry: the mirror learns the delete from the new head, which carries
    // its version and no time.
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
    await reconnected(f, ["e5"]);
    const report = await f.retire();
    expect(
      f.rig.service.retireBasis("chatgpt.memories")!.streams[0],
    ).toMatchObject({ deleteVersion: 2, deleteAtMs: null });
    expect(report.files[0]).toMatchObject({ readback: "fail" });
    expect(report.deleted).toBe(0);
  });

  it("keeps a file of rows that were never streamed when the owner deleted on another device (EMPTY_IMPORT_FENCE_DELETES)", async () => {
    // Nothing is wired to import: the import is vacuously done. Ten rows
    // were written after the delete and never published.
    const ids = Array.from({ length: 10 }, (_, i) => `n${i}`);
    const f = await flow({ local: ids, collectedAt: AFTER_DELETE });
    await deleted(f, ["x0"]);
    await reconnected(f, ["x1"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      importDone: true,
      readback: "fail",
    });
    expect(report.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);
  });

  it("keeps a pre-delete file whose rows were never published when nothing is wired to import (VACUOUS_IMPORT_FENCE_DELETES)", async () => {
    // Production's import source is empty, so the import is vacuously done
    // for every connector. Ten rows were never staged or published; the
    // owner deleted the stream on another device; this device reconnected
    // and a full run collected one row. The fence would excuse all ten, but
    // this device never staged its rows, so nothing proves they were
    // delivered. Reviewer's probe, kept as the red-first test.
    const ids = Array.from({ length: 10 }, (_, i) => `n${i}`);
    const f = await flow({ local: ids }); // collectedAt AT = T0, predates the delete
    await f.importer.run(); // vacuous: no connectors
    await f.run("a", ["x0"]);
    await f.rig.publish();
    await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
    await f.rig.sync();
    await reconnected(f, ["x1"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({ importDone: true });
    expect(report.files.map((r) => r.wouldDelete)).not.toContain(true);
    expect(report.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);
  });

  it("keeps a file after a delete that was not followed by a full run, whatever the readback says", async () => {
    const f = await flow({ local: ["e0", "e1"], imported: true });
    await deleted(f);
    // A run that resumes from a checkpoint is no re-collect.
    await f.rig.collect({
      runId: "partial",
      full: false,
      key: "id",
      version: "1.0.0",
      stream: STREAM,
      rows: [raw("e5")],
    });
    await f.rig.publish();
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);
    expect(report.files.map((r) => r.wouldDelete)).not.toContain(true);
  });
});

describe("the registry must be an authority for the scope (UNCOVERED_RETIRES)", () => {
  async function withBasis(basis: {
    covered: boolean;
    ambiguous: boolean;
    deleted: boolean;
  }) {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    const body = { memories: ["e0", "e1"].map(legacy), total: 2 };
    const reader = {
      publishedBody: async () => body,
      retireBasis: () => ({
        ...basis,
        throughMs: 0,
        streams: [
          {
            connector: CONNECTOR,
            stream: STREAM,
            deleteVersion: 0,
            deleteAtMs: null,
          },
        ],
      }),
    };
    const host = createRetireHost({
      reader,
      writer: { fullRunSince: async () => true },
      ledger: f.ledger,
    });
    const report = await retireLegacyFiles({
      storage: f.storage,
      host,
      ledger: f.ledger,
      deleteEnabled: true,
    });
    return { f, report };
  }

  it.each([
    ["uncovered", { covered: false, ambiguous: false, deleted: false }],
    ["ambiguous", { covered: true, ambiguous: true, deleted: false }],
    [
      "uncovered and ambiguous",
      { covered: false, ambiguous: true, deleted: false },
    ],
  ])("is no fence and no pass when the basis is %s", async (_n, basis) => {
    const { f, report } = await withBasis(basis);
    expect(report.files).toEqual([]);
    expect(report.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);
    expect((await f.ledger.read()).readbacks).toEqual({});
  });

  it("retires when the same body is covered and not ambiguous", async () => {
    const { report } = await withBasis({
      covered: true,
      ambiguous: false,
      deleted: false,
    });
    expect(report.deleted).toBe(1);
  });
});

describe("a body with data the key table does not cover is never proven (UNLISTED_TOP_LEVEL_IGNORED, UNLISTED_SCALAR_IGNORED)", () => {
  const body = (extra: Record<string, unknown>) => ({
    memories: [legacy("e0")],
    total: 1,
    ...extra,
  });

  it("fails closed on an unlisted top-level array or object", () => {
    expect(entityHashes("chatgpt.memories", body({}))).not.toBeNull();
    expect(
      entityHashes("chatgpt.memories", body({ extra: [{ a: 1 }] })),
    ).toBeNull();
    expect(entityHashes("chatgpt.memories", body({ extra: [] }))).toBeNull();
    expect(
      entityHashes("chatgpt.memories", body({ profile: { a: 1 } })),
    ).toBeNull();
  });

  it("compares an unlisted scalar or null instead of ignoring it, and skips only a count derived from a compared collection", () => {
    const keys = (b: Record<string, unknown>) =>
      [...entityHashes("chatgpt.memories", b)!.keys()].sort();
    expect(keys(body({}))).toEqual(["$.memories"]); // `total` equals the length
    expect(keys(body({ note: "x" }))).toEqual(["$.memories", "$scalar.note"]);
    expect(keys(body({ gone: null }))).toEqual(["$.memories", "$scalar.gone"]);
    expect(keys(body({ total: 7 }))).toEqual(["$.memories", "$scalar.total"]);
    expect(
      entityHashes("chatgpt.memories", body({ n: 1 }))!.get("$scalar.n"),
    ).not.toEqual(
      entityHashes("chatgpt.memories", body({ n: 2 }))!.get("$scalar.n"),
    );
  });

  it("keeps a file whose entities all match but whose unlisted scalar the stream data does not hold", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      extraBody: { totalContributionsLastYear: 412 },
    });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      readbackReason: "mismatch",
    });
    expect(report.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);
  });

  it("keeps a file whose other entities all match but whose unlisted array was never compared", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      extraBody: { saved_searches: [{ q: "never streamed" }] },
    });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      readbackReason: "unkeyed",
    });
    expect(report.deleted).toBe(0);
  });

  it("still retires an older snapshot whose derived total the collection outgrew", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1", "e2"]); // the stream grew: published total is 3
    await f.rig.publish();
    expect((await f.retire()).deleted).toBe(1);
  });
});

describe("a fence needs rows this device staged (VACUOUS_IMPORT_FENCE_DELETES)", () => {
  it("retires a pre-delete file once the import staged the connector", async () => {
    const f = await flow({ local: ["e0", "e1"], imported: true });
    await deleted(f);
    await reconnected(f, ["e5"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({ decision: "ready" });
    expect(report.deleted).toBe(1);
  });

  it("names the missing import when the source staged nothing", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await deleted(f);
    await reconnected(f, ["e5"]);
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      readback: "pass",
      decision: "fence_not_imported",
    });
    expect(report.deleted).toBe(0);
  });

  it("does not ask for a staged import when the fence is not used", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    expect((await f.retire()).deleted).toBe(1);
  });
});

describe("the file read back is the file deleted (FILE_CHANGED_BEFORE_DELETE)", () => {
  it("skips the delete when the file changed after the fresh readback", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    // The first read of the file in a pass is the readback; the next one is
    // the recheck. The storage answers the recheck with other content.
    let reads = 0;
    const real = f.storage.readEnvelope.bind(f.storage);
    f.storage.readEnvelope = async (scope, collectedAt) => {
      const envelope = await real(scope, collectedAt);
      reads += 1;
      return reads > 2
        ? { ...envelope, data: { ...(envelope.data as object), edited: 1 } }
        : envelope;
    };
    const report = await f.retire();
    expect(report.files[0]).toMatchObject({
      decision: "file_changed",
      wouldDelete: false,
    });
    expect(report.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);
  });
});

describe("no view passes only when the read said none serves the scope (VIEWGONE_WITHOUT_NULL_BODY)", () => {
  it("does not read a served body that cannot be keyed as a deleted source", async () => {
    const f = await flow({ local: ["e0", "e1"], imported: true });
    await deleted(f);
    const basis = {
      streams: [
        {
          connector: CONNECTOR,
          stream: STREAM,
          deleteVersion: 2,
          deleteAtMs: Date.parse("2026-11-01T00:00:10Z"),
        },
      ],
      viewDeleted: true,
      allTargetsKnown: true,
    };
    const [row] = f.storage.entries;
    const record = await readbackVersion(
      {
        storage: f.storage,
        ledger: f.ledger,
        view: {
          // A body was served, but its collection is not an array.
          publishedBody: async () => ({ memories: "oops", total: 1 }),
          deleteBasis: () => basis,
        },
      },
      "chatgpt.memories",
      row!,
    );
    expect(record).toMatchObject({ pass: false, reason: "no_published_view" });
  });
});

describe("a scope with a connector the registry never saw is never fenced (UNKNOWN_ALTERNATE_FENCES)", () => {
  const stream = (at: number) => ({
    connector: CONNECTOR,
    stream: STREAM,
    deleteVersion: 2,
    deleteAtMs: at,
  });
  const row = { collectedAt: AT, createdAt: AT };
  it("excuses a pre-delete file only when every target is known", () => {
    const at = Date.parse(AT) + 10_000;
    const basis = { streams: [stream(at)], viewDeleted: false };
    expect(predatesEveryDelete({ ...basis, allTargetsKnown: true }, row)).toBe(
      true,
    );
    expect(predatesEveryDelete({ ...basis, allTargetsKnown: false }, row)).toBe(
      false,
    );
  });
});

describe("host wiring", () => {
  it("does not expose a basis the host cannot name (a host without delete basis)", async () => {
    const ledger = new RetireLedger(createMemoryStreamSyncFiles());
    const host: RetireHost = createRetireHost({
      reader: { publishedBody: async () => null, retireBasis: () => null },
      writer: { fullRunSince: async () => true },
      ledger,
    });
    expect(host.deleteBasis("chatgpt.memories")).toBeNull();
  });
});
