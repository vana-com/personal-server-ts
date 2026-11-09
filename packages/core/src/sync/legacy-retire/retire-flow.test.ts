/**
 * Import, publish, readback and retire against the REAL writer, registry fake
 * and read service (the writer-parity rig), for one bound connector. The legacy
 * file is a made-up `chatgpt.memories` body.
 */

import { describe, expect, it } from "vitest";
import { ImportPendingError } from "../../stream-sync/writer.js";
import { CONNECTOR, flow, STREAM } from "./retire-rig.js";

describe("a stream run of a connector waits for its import (RUN_BEFORE_IMPORT)", () => {
  it("refuses to begin a run until the import finished, then accepts it", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await expect(f.run("early", ["e2"])).rejects.toBeInstanceOf(
      ImportPendingError,
    );
    await f.importer.run();
    await f.run("late", ["e2"]);
  });

  it("merges the imported rows into the first publish", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("first", ["e2"]);
    await f.rig.publish();
    const head = await f.rig.registeredHead(STREAM);
    expect(head?.recordCount).toBe(3);
  });
});

describe("retire reads the published heads only (RETIRE_ON_SPOOL, READBACK_ON_SPOOL)", () => {
  it("keeps the file while the stream copy exists only in this device's unpublished run", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0"]);
    await f.rig.publish();
    await f.run("b", ["e1"]); // collected, not published: overlay only
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      readbackReason: "mismatch",
      wouldDelete: false,
    });
    expect(f.storage.entries).toHaveLength(1);
  });

  it("deletes the file once the run is published and the heads hold it", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0"]);
    await f.rig.publish();
    await f.run("b", ["e1"]);
    expect((await f.retire()).deleted).toBe(0);
    await f.rig.publish();
    const report = await f.retire();
    expect(report.deleted).toBe(1);
    expect(f.storage.entries).toHaveLength(0);
  });
});

describe("the delete fence (IMPORT_IGNORES_FENCE, DEVICE_ONLY_RETIRED_EARLY)", () => {
  it("does not import rows of a stream that was deleted", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
    await f.importer.run();
    await f.run("learn", ["x"]);
    await f.rig.publish();
    await f.run("live", ["e9"]);
    await f.rig.publish();
    const head = await f.rig.registeredHead(STREAM);
    expect(head?.recordCount).toBe(1);
    const lines = (await f.rig.publications())
      .at(-1)!
      .lines.map((l) => (l.v as { id: string }).id);
    expect(lines).toEqual(["e9"]);
  });

  it("keeps a file the fence dropped until this device re-collected the stream", async () => {
    const f = await flow({ local: ["e0", "e1"], imported: true });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    // A run collected before the delete is seen, published after it: the fence
    // discards it, so it is no re-collect.
    await f.run("stale", ["s"]);
    await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
    const published = await f.rig.publish();
    expect(published.find((s) => s.runId === "stale")?.outcome).toMatchObject({
      kind: "discarded",
    });

    const early = await f.retire();
    expect(early.files[0]).toMatchObject({
      readback: "pass",
      decision: "fence_not_recollected",
    });
    expect(early.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);

    // A full run that begins after the delete and commits re-collects it.
    await f.run("live", ["e5"]);
    await f.rig.publish();
    const done = await f.retire();
    expect(done.files[0]).toMatchObject({ decision: "ready" });
    expect(done.deleted).toBe(1);
  });
});

describe("unswitched accounts are unchanged (UNSWITCHED_CHANGED)", () => {
  it("stages nothing, gates no run, and leaves the ledger empty", async () => {
    const f = await flow({ seed: ["e0"], local: ["e0"], switched: false });
    expect(await f.importer.run()).toEqual({
      ran: false,
      connectorsStaged: 0,
      failed: 0,
    });
    expect(f.staged.size).toBe(0);
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    await f.run("any", ["e1"]);
    expect(await f.ledger.read()).toEqual({
      importComplete: false,
      imported: {},
      readbacks: {},
    });
  });
});
