/**
 * Round 6: a sealed write never calls the authority (NESTED_AUTHORITY_IN_SEAL),
 * and what the import gave up is not forgotten (ABANDONED_NEVER_RETRIED). The
 * titles name the mutants `__mutants__/run-mutants.mjs` applies.
 */

import { describe, expect, it } from "vitest";
import type { DeclarationSnapshot } from "../../pdpp/types.js";
import { createCanonicalImportSource } from "./canonical-source.js";
import {
  createMemoryImportAuthority,
  type ImportAuthority,
} from "./import-authority.js";
import type { LegacyImportSource } from "./import.js";
import { CONNECTOR, flow, OWNER, raw, STREAM } from "./retire-rig.js";

type Flow = Awaited<ReturnType<typeof flow>>;

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

const sourceOf = (rows: Record<string, unknown>[]): LegacyImportSource =>
  createCanonicalImportSource({
    owner: OWNER,
    deps: () => ({
      store: {
        listConnections: () => [{ instance: INSTANCE, deletedAt: null }],
        listStreams: () => [
          { stream: STREAM, recordCount: rows.length, lastUpdated: null },
        ],
        listRecords: (stream: string) => ({
          data: (stream === STREAM ? rows : []).map((data) => ({ data })),
          hasMore: false,
        }),
      } as never,
      declarations: DECLARED,
    }),
  });

describe("the seal's write never calls the authority (NESTED_AUTHORITY_IN_SEAL)", () => {
  it("queues the seed run inside the seal and asks the authority only after it returns", async () => {
    const inner = createMemoryImportAuthority({ deadlockMs: 300 });
    let inSeal = false;
    const nested: string[] = [];
    const authority: ImportAuthority = {
      importPending: (owner) => {
        if (inSeal) nested.push("importPending");
        return inner.importPending(owner);
      },
      importDone: (owner) => {
        if (inSeal) nested.push("importDone");
        return inner.importDone(owner);
      },
      commitImportSeed: (owner, operationId, write) =>
        inner.commitImportSeed(owner, operationId, async () => {
          inSeal = true;
          try {
            return await write();
          } finally {
            inSeal = false;
          }
        }),
    };
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
      authority,
    });
    await f.importer.run();
    expect(nested).toEqual([]);
    expect(inner.seedCommits).toHaveLength(1);
    // The queued run publishes: the head is readable.
    await publish(f);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(1);
  });

  it("a serializing authority does not hang the import: a nested call would never return", async () => {
    const authority = createMemoryImportAuthority({ deadlockMs: 300 });
    const f = await flow({
      local: ["e0"],
      source: sourceOf([raw("e0")]),
      owner: OWNER,
      authority,
    });
    const started = Date.now();
    await f.importer.run();
    expect(Date.now() - started).toBeLessThan(250);
    await publish(f);
    await f.importer.run();
    expect(await f.importer.status()).toMatchObject({
      complete: true,
      connectors: [{ state: "published" }],
    });
  });

  it("the memory authority rejects a call made from inside a sealed write", async () => {
    const authority = createMemoryImportAuthority({ deadlockMs: 100 });
    await expect(
      authority.commitImportSeed("0xabc", "op", () =>
        authority.importPending("0xabc"),
      ),
    ).rejects.toThrow(/blocked by an open seal/);
  });
});

describe("what the import gave up is tried again on a later boot (ABANDONED_NEVER_RETRIED)", () => {
  const rows = [raw("e0"), raw("e1")];

  it("gives a connector's receipts after it failed the bound and a later boot succeeds", async () => {
    const options = {
      local: ["e0", "e1"],
      source: sourceOf(rows),
      owner: OWNER,
      sinkThrows: STREAM as string | undefined,
      maxAttempts: 2,
    };
    const f = await flow(options);
    await f.importer.run();
    await f.importer.run(); // given up; the authority is told (writes proceed)
    expect(f.authority.doneCalls).toHaveLength(1);
    expect(await f.ledger.importProven(CONNECTOR)).toBe(false);
    expect(await f.importer.status()).toMatchObject({
      complete: true,
      givenUp: 1,
      connectors: [{ connector: CONNECTOR, state: "failed", attempts: 2 }],
    });
    // The same boot does not try again.
    const calls = f.stagings;
    await f.importer.run();
    expect(f.stagings).toBe(calls);

    // A later boot: the cause is gone. A new importer over the same ledger.
    options.sinkThrows = undefined;
    const boot2 = f.importerFor({ source: sourceOf(rows), owner: OWNER });
    expect(await boot2.importDone(CONNECTOR)).toBe(true); // the gate stays open
    expect(await boot2.run()).toMatchObject({
      ran: true,
      connectorsStaged: 1,
      failed: 0,
    });
    expect(await boot2.importDone(CONNECTOR)).toBe(true);
    await publish(f);
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(2);
    expect(
      Object.values((await f.rig.writer.seedStatus(CONNECTOR)).receipts),
    ).toEqual(["merged"]);
    await boot2.run(); // sees the receipt
    expect(await boot2.status()).toMatchObject({
      givenUp: 0,
      stayed: 0,
      connectors: [{ connector: CONNECTOR, state: "published", staged: 2 }],
    });
    expect((await f.ledger.read()).failures[CONNECTOR]).toBeUndefined();
    expect(await f.ledger.importProven(CONNECTOR)).toBe(true);
    // Done is not told twice.
    expect(f.authority.doneCalls).toHaveLength(1);
  });

  it("keeps the file while the connector is still failing, and retires nothing it did not prove", async () => {
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf(rows),
      owner: OWNER,
      sinkThrows: STREAM,
      maxAttempts: 1,
    });
    await f.importer.run();
    const boot2 = f.importerFor({ source: sourceOf(rows), owner: OWNER });
    expect(await boot2.run()).toMatchObject({ ran: true, failed: 1 });
    expect(await boot2.status()).toMatchObject({ givenUp: 1 });
    await f.run("a", ["e0", "e1"]);
    await publish(f);
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]?.decision).toBe("no_import");
  });

  it("lists a source again that could not be listed, and imports it", async () => {
    let listing = false;
    const good = sourceOf(rows);
    const f = await flow({
      local: ["e0", "e1"],
      source: {
        owner: OWNER,
        connectors: async () => {
          if (!listing) throw new Error("the store is corrupt");
          return good.connectors();
        },
        streams: (c) => good.streams(c),
        excluded: (c) => good.excluded?.(c) ?? Promise.resolve([]),
      },
      owner: OWNER,
      maxAttempts: 2,
    });
    await f.importer.run();
    await f.importer.run();
    expect(await f.importer.status()).toMatchObject({
      complete: true,
      abandoned: true,
    });
    listing = true;
    const boot2 = f.importerFor({
      source: {
        owner: OWNER,
        connectors: () => good.connectors(),
        streams: (c) => good.streams(c),
        excluded: (c) => good.excluded?.(c) ?? Promise.resolve([]),
      },
      owner: OWNER,
    });
    expect(await boot2.run()).toMatchObject({ connectorsStaged: 1 });
    await publish(f);
    await boot2.run();
    expect(await boot2.status()).toMatchObject({
      abandoned: false,
      givenUp: 0,
      connectors: [{ connector: CONNECTOR, state: "published" }],
    });
    expect(await f.ledger.importProven(CONNECTOR)).toBe(true);
  });

  it("does not import a connector that was never part of the first import", async () => {
    const f = await flow({
      local: ["e0"],
      source: {
        owner: OWNER,
        connectors: async () => [],
        streams: async () => [],
      },
      owner: OWNER,
    });
    await f.importer.run();
    expect(f.authority.doneCalls).toHaveLength(1);
    const boot2 = f.importerFor({ source: sourceOf(rows), owner: OWNER });
    expect(await boot2.run()).toMatchObject({ ran: false });
    expect(f.stagings).toBe(0);
  });
});
