import { describe, expect, it } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  LITE_CANONICAL_MAX_OPERATION_BYTES,
  LITE_CANONICAL_MAX_VALUE_BYTES,
} from "./canonical-persistence.js";
import {
  createLiteCanonicalStore,
  type LiteOperationDraft,
} from "./canonical-store.js";
import {
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
  storagePage,
} from "./test-support/canonical-persistence.js";

const draft = (op: ReplicaOperation): LiteOperationDraft => {
  const { revision: _, ...value } = op;
  return value;
};
const record = (key: string, bytes: number): LiteOperationDraft => ({
  ...draft(upsert("unused", 1)),
  recordKey: key,
  data: { id: key, text: "x".repeat(bytes) },
});

async function provisioned() {
  const disk = fakeCanonicalDisk();
  let next = 0;
  const store = createLiteCanonicalStore({
    persistence: createFakeCanonicalPersistence(disk).port,
    enabled: true,
    context: () => ({
      owner: identity.owner,
      declarations: [
        { sourceId: identity.sourceId, binding, validateData: () => true },
      ],
    }),
    authenticateReplica: () => undefined,
    newId: () => `id-${++next}`,
  });
  await store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  await store.commitLocal("reg", [draft(registration)]);
  return { disk, store };
}

describe("Lite canonical size limits", () => {
  it("commits one operation over 192 KiB alone, but not beside another", async () => {
    const { disk, store } = await provisioned();
    await expect(
      store.commitLocal("pair", [record("small", 10), record("big", 300_000)]),
    ).rejects.toThrow("192 KiB");
    await store.commitLocal("big", [record("big", 3_000_000)]);
    const rows = [...disk.rows].filter(([key]) => key.startsWith("rows/"));
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0]![1]).data.text).toHaveLength(3_000_000);
  });

  it("refuses one operation over 17 MiB", async () => {
    const { store } = await provisioned();
    await expect(
      store.commitLocal("huge", [
        record("huge", LITE_CANONICAL_MAX_OPERATION_BYTES),
      ]),
    ).rejects.toThrow("split before commit");
  });

  it("pages the outbox past an operation over 512 KiB", async () => {
    const { store } = await provisioned();
    await store.commitLocal("a", [record("a", 10)]);
    await store.commitLocal("big", [record("big", 700_000)]);
    await store.commitLocal("b", [record("b", 10)]);
    const sequences: number[] = [];
    for (let after = 0, pages = 0; pages < 10; pages++) {
      const page = await store.readOutboxPage(after);
      sequences.push(...page.entries.map((entry) => entry.sequence));
      if (!page.hasMore) break;
      after = page.nextAfterSequence;
    }
    expect(sequences).toEqual([1, 2, 3, 4]);
  });

  it("gives a value over 512 KiB a page of its own and refuses one over 18 MiB", () => {
    const entries = [
      { key: "a", value: "1" },
      { key: "b", value: "x".repeat(600_000) },
      { key: "c", value: "2" },
    ];
    expect(storagePage(entries).entries.map((entry) => entry.key)).toEqual([
      "a",
    ]);
    expect(storagePage(entries, "a")).toEqual({
      entries: [entries[1]],
      after: "b",
    });
    expect(() =>
      storagePage([
        { key: "a", value: "x".repeat(LITE_CANONICAL_MAX_VALUE_BYTES + 1) },
      ]),
    ).toThrow("18 MiB");
  });
});
