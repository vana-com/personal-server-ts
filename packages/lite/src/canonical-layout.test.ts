import { describe, expect, it } from "vitest";
import { sha256, toBytes } from "viem";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  createLiteCanonicalStore,
  type LiteOperationDraft,
} from "./canonical-store.js";
import { createFakeCanonicalPersistence } from "./test-support/canonical-persistence.js";

const draft = (op: ReplicaOperation): LiteOperationDraft => {
  const { revision: _, ...value } = op;
  return value;
};
const record = (key: string, text: string): LiteOperationDraft => ({
  ...draft(upsert("unused", 1)),
  recordKey: key,
  data: { id: key, text },
});

const LAYOUT = [
  "journal/",
  "outbox/",
  "mutations/",
  "log/",
  "canonical-layout-version",
];

function device() {
  const adapter = createFakeCanonicalPersistence();
  let next = 0;
  const make = () =>
    createLiteCanonicalStore({
      persistence: adapter.port,
      enabled: true,
      context: () => ({
        owner: identity.owner,
        declarations: [
          { sourceId: identity.sourceId, binding, validateData: () => true },
        ],
      }),
      authenticateReplica: (credential) =>
        credential === "replica" ? identity.owner : undefined,
      newId: () => `id-${++next}`,
    });
  return { adapter, make };
}
async function provisioned() {
  const { adapter, make } = device();
  const store = make();
  await store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  await store.commitLocal("reg", [draft(registration)]);
  await store.commitLocal("b1", [record("k0", "zero"), record("k1", "one")]);
  return { adapter, make, store };
}

/**
 * One fixed sequence of local writes, imports, outbox reads and
 * acknowledgments. Ids and data are deterministic, so the transcript is too.
 */
async function transcript() {
  const { adapter, make } = device();
  let store = make();
  const out: unknown[] = [];
  const pages = async (after: number) => {
    let sequence = after;
    for (;;) {
      const page = await store.readOutboxPage(sequence);
      out.push(page);
      sequence = page.nextAfterSequence;
      if (!page.hasMore) return;
    }
  };
  await store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  out.push(await store.commitLocal("reg", [draft(registration)]));
  // More than one native scan page (100 entries) of outbox pointers.
  const first = Array.from({ length: 130 }, (_, i) =>
    record(`k${i}`, `text ${i} ${"x".repeat(i * 7)}`),
  );
  out.push(await store.commitLocal("b1", first));
  out.push(await store.commitLocal("b1", first));
  out.push(
    await store.commitLocal("b2", [
      record("k0", "changed"),
      {
        ...identity,
        kind: "delete",
        declaration: binding,
        recordKey: "k1",
        emittedAt: "2026-10-21T00:00:00Z",
        deletedAt: "2026-10-21T00:00:00Z",
      },
      record("k2", `text 2 ${"x".repeat(14)}`),
    ]),
  );
  out.push(
    await store.import({
      id: "import-1",
      credential: "replica",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: "import-1",
        operations: [
          {
            ...registration,
            revision: { ...registration.revision, writerId: "device-b" },
          },
          upsert("remote", 900, "remote", "device-b"),
        ],
      },
    }),
  );
  await pages(0);
  await store.acknowledgeOutbox(0, 50);
  await pages(0);
  await pages(49);
  await pages(60);
  await store.acknowledgeOutbox(0, 50);
  store = make();
  await pages(0);
  out.push(await store.commitLocal("b3", [record("k3", "after ack")]));
  await store.acknowledgeOutbox(50, 133);
  await pages(0);
  await pages(133);
  await pages(500);
  // Every entry outside the history and outbox layout: retained operation
  // bytes, rows, indexes, receipts and the acknowledgment.
  const kept = [...adapter.disk.rows]
    .filter(([key]) => !LAYOUT.some((prefix) => key.startsWith(prefix)))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return { out, kept };
}

describe("Lite canonical outbox", () => {
  it("returns byte-identical publisher pages for a fixed write sequence", async () => {
    const { out, kept } = await transcript();
    const pages = JSON.stringify(out);
    const entries = JSON.stringify(kept);
    // Recorded on the journal/outbox/mutations layout (main 6a00d328). The
    // pages must never change; the entries change only with a layout bump.
    expect({
      pages: { bytes: pages.length, digest: sha256(toBytes(pages)) },
      entries: {
        count: kept.length,
        bytes: entries.length,
        digest: sha256(toBytes(entries)),
      },
    }).toEqual({
      pages: {
        bytes: 544507,
        digest:
          "0x2ce1204ad90d6ed2abde340ce650d4df8c76a1ec8013e80b6ebbbcee70c82ea4",
      },
      entries: {
        count: 681,
        bytes: 385449,
        digest:
          "0xf99ea08fcd5897f2a37386fdae7c5238471f152913faaa868f7c447efa331dce",
      },
    });
  });

  it("keeps one log entry per local write and acknowledges without deleting", async () => {
    const { adapter, store } = await provisioned();
    const keys = () =>
      [...adapter.disk.rows.keys()].filter((key) =>
        /^(log|journal|outbox|mutations)\//.test(key),
      );
    expect(keys()).toEqual([
      "log/0000000000000001",
      "log/0000000000000002",
      "log/0000000000000003",
    ]);
    const entries = [...adapter.disk.rows]
      .filter(([key]) => key.startsWith("log/"))
      .map(([, value]) => JSON.parse(value));
    expect(entries.map((entry) => Object.keys(entry).sort())).toEqual([
      ["batchId", "operationKey", "sequence"],
      ["batchId", "operationKey", "rowVersion", "sequence"],
      ["batchId", "operationKey", "rowVersion", "sequence"],
    ]);
    // The pointer names the retained operation; the log holds no record bytes.
    for (const entry of entries)
      expect(adapter.disk.rows.has(entry.operationKey)).toBe(true);
    await store.acknowledgeOutbox(0, 2);
    expect(keys()).toHaveLength(3);
    expect(
      (await store.readOutboxPage()).entries.map((e) => e.sequence),
    ).toEqual([3]);
    const log = await store.readLogPage();
    expect(
      log.entries.map((e) => [e.sequence, e.batchId, e.rowVersion]),
    ).toEqual([
      [1, "reg", undefined],
      [2, "b1", 1],
      [3, "b1", 1],
    ]);
    await expect(store.readLogPage(-1)).rejects.toThrow("invalid log offset");
    await expect(store.readOutboxPage(-1)).rejects.toThrow(
      "invalid outbox offset",
    );
  });
  it("fails closed on a store written with another layout", async () => {
    for (const [layout, message] of [
      [undefined, "canonical layout 1 is no longer supported"],
      ["3", "canonical layout 3 is newer than this build (2)"],
    ] as const) {
      const { adapter, make } = await provisioned();
      if (layout === undefined) {
        // A layout 1 store: no version key, history under the old prefixes.
        adapter.disk.rows.delete("canonical-layout-version");
        adapter.disk.rows.set("journal/0000000000000001", "{}");
      } else adapter.disk.rows.set("canonical-layout-version", layout);
      const before = new Map(adapter.disk.rows);
      const store = make();
      for (const call of [
        () => store.readOutboxPage(),
        () => store.readLogPage(),
        () => store.acknowledgeOutbox(0, 1),
        () => store.readRecord(identity.connectionId, binding.stream, "k0"),
        () => store.commitLocal("b2", [record("k2", "two")]),
      ])
        await expect(call()).rejects.toThrow(message);
      expect(adapter.disk.rows).toEqual(before);
    }
  });
});
