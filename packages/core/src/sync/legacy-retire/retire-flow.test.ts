/**
 * Import, publish, readback and retire against the REAL writer, registry fake
 * and read service (the writer-parity rig), for one bound connector. The legacy
 * file is a made-up `chatgpt.memories` body.
 */

import { describe, expect, it } from "vitest";
import { ImportPendingError } from "../../stream-sync/writer.js";
import { CONNECTOR, flow, OWNER, STREAM } from "./retire-rig.js";

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
    // The connection is live (control row written) before the delete.
    await f.run("pre", ["e0"], true, true);
    await f.rig.other.deleteConnection(CONNECTOR);
    await f.importer.run();
    // The explicit connect is the first run after the delete. Its first
    // collection predates this device's read of the delete, so the publish
    // fence discards it; the next run collects after the delete.
    await f.run("live", ["e9"], false, true);
    await f.rig.publish();
    await f.importer.run();
    await f.run("again", ["e9"]);
    await f.rig.publish();
    const head = await f.rig.registeredHead(STREAM);
    expect(head?.recordCount).toBe(1);
    const lines = (await f.rig.publications())
      .at(-1)!
      .lines.map((l) => (l.v as { id: string }).id);
    expect(lines).toEqual(["e9"]);
  });

  it("import after deleteConnection must not bring the connection's rows back", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.run("pre", ["e0"], true, true);
    await f.rig.other.deleteConnection(CONNECTOR);
    await f.importer.run();
    expect(f.staged.size).toBe(0);
    await f.rig.publish();
    expect((await f.rig.registeredHead(STREAM))?.recordCount ?? 0).toBe(0);
  });

  it("crash after the delete tombstones but before eraseLegacy, then import: nothing comes back", async () => {
    // The legacy erase is the last step of a connection delete. A crash before
    // it leaves the legacy rows on the device; the import must not stage them,
    // and the seed of the connector must not publish.
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.run("pre", ["e0"], true, true);
    f.rig.eraseLegacyHook = async () => {
      throw new Error("crash before eraseLegacy");
    };
    await expect(f.rig.other.deleteConnection(CONNECTOR)).rejects.toThrow(
      "crash before eraseLegacy",
    );
    await f.importer.run();
    await f.rig.sync();
    await f.rig.publish();
    expect(f.staged.size).toBe(0);
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    expect((await f.rig.registeredHead(STREAM))?.recordCount ?? 0).toBe(0);
  });

  it("a new connection after a completed delete collects fresh and imports no old legacy rows", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.run("pre", ["e0"], true, true);
    await f.rig.other.deleteConnection(CONNECTOR);
    await f.importer.run();
    // The first connect collection is discarded by the fence (see above).
    await f.run("live", ["x"], false, true);
    await f.rig.publish();
    await f.importer.run();
    await f.run("again", ["e9"]);
    await f.rig.publish();
    expect(f.staged.size).toBe(0);
    // Only the new record: no e0 or e1 from the legacy file.
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(1);
  });

  it("keeps a file the fence dropped until this device re-collected the stream", async () => {
    const f = await flow({ local: ["e0", "e1"], seed: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    // A run collected before the delete is seen, published after it: the fence
    // discards it, so it is no re-collect.
    await f.run("stale", ["s"]);
    await f.rig.other.deleteConnection(CONNECTOR);
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
    await f.run("live", ["e5"], false, true);
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
      owner: OWNER,
      excluded: {},
      failures: {},
      listAttempts: 0,
      abandoned: false,
      importComplete: false,
      imported: {},
      readbacks: {},
    });
  });
});
