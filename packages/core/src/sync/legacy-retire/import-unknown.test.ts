/**
 * An `unknown` mode is no
 * decision: it never opens the writer's gate, never imports, and never
 * reports a count of zero. The titles name the mutants
 * `__mutants__/run-mutants.mjs` applies.
 */

import { describe, expect, it } from "vitest";
import type { ImportStream, LegacyImportSource } from "./import.js";
import { CONNECTOR, flow, OWNER, raw, STREAM } from "./retire-rig.js";

type Flow = Awaited<ReturnType<typeof flow>>;

const publish = async (f: Flow) => {
  await f.rig.writer.refreshControls();
  return f.rig.publish();
};

/** A source holding two rows of one stream (and nothing else). */
const twoRows = (): LegacyImportSource => {
  const stream: ImportStream = {
    stream: STREAM,
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
    rows: 2,
    async *records() {
      yield raw("e0");
      yield raw("e1");
    },
  };
  return {
    owner: OWNER,
    connectors: async () => [CONNECTOR],
    streams: async () => [stream],
  };
};

describe("the writer's gate under an unknown mode (IMPORT_GATE_OPEN_ON_UNKNOWN)", () => {
  it("is open for an unswitched account, closed for an unknown one, and the import does not act", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      mode: "unknown",
    });
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    expect(await f.importer.run()).toMatchObject({ ran: false });
    expect(f.staged.size).toBe(0);
    expect(await f.ledger.importPending()).toBe(true);
    f.setMode("unswitched");
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
  });

  it("refuses a run at beginRun (WRITER_BEGIN_RUN_GATE_REMOVED)", async () => {
    const f = await flow({
      local: ["e0"],
      source: twoRows(),
      owner: OWNER,
      mode: "unknown",
    });
    await expect(f.run("r1", ["e0"])).rejects.toThrow(
      /import of this connector is not finished/,
    );
  });

  it("holds a run admitted earlier at the publish that binds generation 1 (UNKNOWN_PUBLISH_GATE_REMOVED)", async () => {
    const f = await flow({
      local: ["e0"],
      source: twoRows(),
      owner: OWNER,
      mode: "unswitched",
    });
    await f.run("early", ["e0"]); // admitted while the account was unswitched
    f.setMode("unknown"); // then the account mode becomes unknown
    await publish(f);
    expect(await f.rig.registeredHead(STREAM)).toBeNull();
    f.setMode("unswitched");
    await publish(f);
    expect(await f.rig.registeredHead(STREAM)).not.toBeNull();
  });
});

describe("the status never reports zero for rows it did not count (STATUS_UNKNOWN_MODE_COUNTS_ZERO)", () => {
  it("reports null while the mode is unknown, with two legacy rows and nothing staged", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      mode: "unknown",
    });
    await f.importer.run();
    expect(await f.importer.status()).toEqual({
      complete: false,
      abandoned: false,
      givenUp: 0,
      stayed: null,
      connectors: [],
    });
  });

  it("reports null again when the mode turns unknown after a pass counted", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
    });
    await f.importer.run();
    await publish(f);
    await f.importer.run();
    expect((await f.importer.status()).stayed).toBe(0);
    f.setMode("unknown");
    expect((await f.importer.status()).stayed).toBeNull();
  });

  it("reports null before the source was ever listed (STATUS_UNLISTED_COUNTS_ZERO)", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
    });
    expect((await f.importer.status()).stayed).toBeNull();
    await f.importer.run();
    expect((await f.importer.status()).stayed).toBeNull(); // staged, pending
    await publish(f);
    await f.importer.run();
    expect((await f.importer.status()).stayed).toBe(0);
  });
});

describe("a host with no publish bound cannot finish the import over staged rows (IMPORT_DONE_WITHOUT_PUBLISH)", () => {
  it("does not complete the import while a connector holds staged rows", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      publishSeed: false,
    });
    await f.importer.run();
    await f.importer.run();
    expect(f.staged.size).toBe(1); // staged, and nobody will publish it
    expect(await f.ledger.importPending()).toBe(true);
  });

  it("still finishes when the source lists no connector", async () => {
    const f = await flow({
      local: [],
      source: {
        owner: OWNER,
        connectors: async () => [],
        streams: async () => [],
      },
      owner: OWNER,
      publishSeed: false,
    });
    await f.importer.run();
    expect(await f.ledger.importPending()).toBe(false);
  });
});
