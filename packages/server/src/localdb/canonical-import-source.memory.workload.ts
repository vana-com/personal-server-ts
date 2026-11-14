import {
  createCanonicalImportSource,
  type CanonicalImportPageReader,
} from "./canonical-import-source.js";

/** Observe ownership at the page handoff, not eventual collection at EOF. */
export async function releasedSourcePage(): Promise<boolean> {
  let first: WeakRef<object>;
  const reader: CanonicalImportPageReader = {
    declarations: [
      {
        source_id: "urn:fixture",
        source_kind: "connector",
        version: "1",
        digest: "fixture",
        streams: [
          {
            name: "items",
            primary_key: ["id"],
            fields: ["id"],
            required_fields: ["id"],
          },
        ],
      } as CanonicalImportPageReader["declarations"][number],
    ],
    async *inventory() {
      yield {
        sourceId: "urn:fixture",
        instance: "fixture",
        stream: "items",
        rows: 2,
      };
    },
    async connections() {
      return [{ instance: "fixture", deleted: false, lastActive: 1 }];
    },
    async assertRevision() {},
    async page(_instance, _stream, after) {
      if (after !== null) return { rows: [], next: null };
      const row = { id: "first" };
      first = new WeakRef(row);
      return { rows: [row, { id: "last" }], next: "next" };
    },
  };
  const inventory = createCanonicalImportSource({
    owner: "owner",
    network: "network",
    revision: "revision",
    reader,
    bindings: new Map([
      ["fixture.items", { connector: "fixture-source", streams: ["items"] }],
    ]),
    resolveTarget: async () => ({
      connectionId: "fixture-control",
      connector: "fixture-source",
      stream: "items",
      primaryKey: ["id"],
      semantics: "mutable_state",
      incremental: true,
    }),
  });
  const entry = await inventory.next();
  if (entry.done || "kind" in entry.value)
    throw new Error("fixture_source_missing");
  const records = entry.value.records()[Symbol.asyncIterator]();
  if ((await records.next()).value?.id !== "first")
    throw new Error("fixture_first_row_missing");
  if ((await records.next()).value?.id !== "last")
    throw new Error("fixture_last_row_missing");
  const released = new Promise<boolean>((resolve) =>
    setTimeout(() => {
      (globalThis as { gc?: () => void }).gc!();
      resolve(first.deref() === undefined);
    }, 0),
  );
  const next = records.next();
  const result = await released;
  await next;
  return result;
}
