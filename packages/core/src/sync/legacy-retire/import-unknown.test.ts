/**
 * An `unknown` mode, or an authority that does not know the owner, is no
 * decision: it never opens the writer's gate, never imports, and never
 * reports a count of zero. The titles name the mutants
 * `__mutants__/run-mutants.mjs` applies.
 */

import { describe, expect, it } from "vitest";
import {
  createMemoryImportAuthority,
  type ImportAuthority,
} from "./import-authority.js";
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
    expect(f.authority.doneCalls).toEqual([]);
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
    f.setMode("unknown"); // then the authority stops knowing the owner
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
      stayed: null,
      connectors: [],
    });
  });

  it("reports null again when the mode turns unknown after a pass counted", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      publishSeed: false,
    });
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
    expect((await f.importer.status()).stayed).toBe(0);
  });
});

describe("an authority that does not know the owner is no decision (AUTHORITY_REJECTION_READ_AS_DONE)", () => {
  it("reads as pending: the gate is closed, nothing imports, nothing is complete", async () => {
    const authority = createMemoryImportAuthority({ unknown: true });
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      authority,
    });
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    expect(await f.ledger.importPending()).toBe(true);
    expect(await f.ledger.importProven(CONNECTOR)).toBe(false);
    expect(await f.importer.run()).toMatchObject({ ran: false });
    expect(f.staged.size).toBe(0);
    expect(await f.importer.status()).toMatchObject({
      complete: false,
      stayed: null,
    });
  });
});

describe("the importer's own seed publish goes through the authority (IMPORT_SEED_BYPASSES_AUTHORITY)", () => {
  it("asks commitImportSeed for the owner before every publish, and publishes only when it admits", async () => {
    let admit = false;
    const base = createMemoryImportAuthority();
    const asked: { owner: string; operationId: string }[] = [];
    const authority: ImportAuthority = {
      ...base,
      commitImportSeed: (owner, operationId, write) => {
        asked.push({ owner, operationId });
        return admit
          ? base.commitImportSeed(owner, operationId, write)
          : Promise.resolve({ kind: "refuse" });
      },
    };
    let published = 0;
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      authority,
      publishSeed: async (connector, streams) => {
        published += 1;
        return f.rig.writer.publishSeed(connector, streams);
      },
    });
    await f.importer.run();
    expect(published).toBe(0); // refused: retried, not published
    expect(asked).toEqual([
      { owner: OWNER.toLowerCase(), operationId: `import-seed:${CONNECTOR}` },
    ]);
    admit = true;
    await f.importer.run();
    expect(published).toBe(1);
  });
});

describe("the seed publish runs inside the authority's seal (IMPORT_SEED_PUBLISHED_OUTSIDE_SEAL)", () => {
  it("publishes only while the authority holds its lock, and never after the call returns", async () => {
    const base = createMemoryImportAuthority();
    let sealed = false;
    const outside: string[] = [];
    const authority: ImportAuthority = {
      ...base,
      commitImportSeed: (owner, operationId, write) =>
        base.commitImportSeed(owner, operationId, async () => {
          sealed = true;
          try {
            return await write();
          } finally {
            sealed = false;
          }
        }),
    };
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      authority,
      publishSeed: async (connector, streams) => {
        if (!sealed) outside.push(connector);
        return f.rig.writer.publishSeed(connector, streams);
      },
    });
    await f.importer.run();
    await publish(f);
    await f.importer.run();
    await f.importer.run();
    expect(base.seedCommits.length).toBeGreaterThan(0);
    expect(outside).toEqual([]);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(2);
  });

  it("publishes nothing when the authority runs no write", async () => {
    const base = createMemoryImportAuthority();
    let calls = 0;
    const authority: ImportAuthority = {
      ...base,
      commitImportSeed: () => Promise.resolve({ kind: "refuse" }),
    };
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      authority,
      publishSeed: async (connector, streams) => {
        calls += 1;
        return f.rig.writer.publishSeed(connector, streams);
      },
    });
    await f.importer.run();
    await f.importer.run();
    expect(calls).toBe(0);
    expect(f.authority.doneCalls).toEqual([]);
  });
});

describe("a host with no publish bound cannot finish the import over staged rows (IMPORT_DONE_WITHOUT_PUBLISH)", () => {
  it("does not tell the authority the import is done while a connector holds staged rows", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      publishSeed: false,
    });
    await f.importer.run();
    await f.importer.run();
    expect(f.staged.size).toBe(1); // staged, and nobody will publish it
    expect(f.authority.doneCalls).toEqual([]);
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
    expect(f.authority.doneCalls).toEqual([OWNER.toLowerCase()]);
  });
});

describe("the authority's importDone is awaited (IMPORT_DONE_NOT_AWAITED)", () => {
  it("returns from the pass only after the save landed", async () => {
    let saved = false;
    const base = createMemoryImportAuthority();
    const authority: ImportAuthority = {
      ...base,
      importDone: async (owner) => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        saved = true;
        return base.importDone(owner);
      },
    };
    const f = await flow({
      local: ["e0", "e1"],
      source: twoRows(),
      owner: OWNER,
      authority,
    });
    await f.importer.run();
    await publish(f);
    await f.importer.run();
    expect(saved).toBe(true);
  });
});
