import { describe, expect, it } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { createLiteCanonicalStore } from "./canonical-store.js";
import { createFakeCanonicalPersistence } from "./test-support/canonical-persistence.js";

function device() {
  const adapter = createFakeCanonicalPersistence();
  const make = (enabled = true) =>
    createLiteCanonicalStore({
      persistence: adapter.port,
      enabled,
      context: () => ({
        owner: identity.owner,
        declarations: [
          { sourceId: identity.sourceId, binding, validateData: () => true },
        ],
      }),
      authenticateReplica: (credential) =>
        credential === "replica" ? identity.owner : undefined,
    });
  return { adapter, make };
}
const pending = (text = "pending", counter = 100) => ({
  id: "pending-batch",
  credential: "replica",
  envelope: {
    format: "vana-pdpp-replica",
    version: 1,
    owner: identity.owner,
    batchId: "pending-batch",
    operations: [registration, upsert(text, counter)],
  },
});
const read = (
  store: ReturnType<typeof createLiteCanonicalStore>,
  reader: "owner" | "grant" = "grant",
) =>
  store.readRecord(identity.connectionId, binding.stream, "same-key", {
    reader,
  });
async function provision(store: ReturnType<typeof createLiteCanonicalStore>) {
  await store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
}

describe("Lite pending visibility", () => {
  it("isolates pending from grants and counters, survives reopen, and atomically promotes", async () => {
    const { adapter, make } = device();
    let store = make();
    await provision(store);
    const before = await store.readOutboxPage();
    const staged = await store.stagePending(pending());
    expect(await store.readOutboxPage()).toEqual(before);
    expect(await read(store)).toBeUndefined();
    expect(await read(store, "owner")).toMatchObject({
      data: { text: "pending" },
      confirmation: "not yet confirmed",
    });
    store = make();
    expect(await read(store, "owner")).toMatchObject({
      data: { text: "pending" },
    });
    adapter.crashAt("record");
    await expect(
      store.promotePending({
        id: pending().id,
        credential: "replica",
        fingerprint: staged.fingerprint,
      }),
    ).rejects.toThrow("interrupted");
    expect(await read(make())).toBeUndefined();
    expect(await read(make(), "owner")).toMatchObject({
      confirmation: "not yet confirmed",
    });
    await store.promotePending({
      id: pending().id,
      credential: "replica",
      fingerprint: staged.fingerprint,
    });
    expect(await read(make())).toMatchObject({ data: { text: "pending" } });
    expect(await read(make(), "owner")).not.toHaveProperty("confirmation");
  });
});

it.each([
  ["confirmed-only", "confirmed-only", false, false],
  ["include-pending", "confirmed-only", true, false],
  ["confirmed-only", "include-pending", false, true],
  ["include-pending", "include-pending", true, true],
] as const)(
  "applies owner %s and grant %s to records and pages",
  async (owner, grant, ownerVisible, grantVisible) => {
    const { adapter } = device();
    const store = createLiteCanonicalStore({
      persistence: adapter.port,
      enabled: true,
      visibilityPolicy: { owner, grant },
      context: () => ({
        owner: identity.owner,
        declarations: [
          { sourceId: identity.sourceId, binding, validateData: () => true },
        ],
      }),
      authenticateReplica: () => identity.owner,
    });
    await provision(store);
    await store.stagePending(pending());
    for (const [reader, visible] of [
      ["owner", ownerVisible],
      ["grant", grantVisible],
    ] as const) {
      expect(!!(await read(store, reader))).toBe(visible);
      expect(
        (
          await store.readConnectionPage(identity.connectionId, undefined, {
            reader,
          })
        ).rows.length,
      ).toBe(visible ? 1 : 0);
    }
  },
);

it("quarantines divergent finalized evidence durably without changing confirmed data", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  await store.import({ ...pending("confirmed", 2), id: "confirmed" });
  const staged = await store.stagePending(pending());
  await expect(
    store.promotePending({
      id: pending().id,
      credential: "replica",
      fingerprint: "divergent",
    }),
  ).rejects.toThrow("divergent");
  for (const reader of ["owner", "grant"] as const)
    expect(await read(make(), reader)).toMatchObject({
      data: { text: "confirmed" },
    });
  await expect(
    store.promotePending({
      id: pending().id,
      credential: "replica",
      fingerprint: staged.fingerprint,
    }),
  ).rejects.toThrow("quarantined");
  await expect(store.stagePending(pending("replacement"))).rejects.toThrow(
    "different content",
  );
});

it("keeps local Lamport allocation unchanged and merges concurrent local edits", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  await store.import({ ...pending("confirmed", 2), id: "confirmed" });
  await store.stagePending(pending());
  const { revision: _, ...local } = upsert("local", 3);
  await store.commitLocal("local", [local]);
  expect(
    (await store.readOutboxPage()).entries.at(-1)?.operation.revision.counter,
  ).toBe(3);
  expect(await read(store)).toMatchObject({ data: { text: "local" } });
  expect(await read(store, "owner")).toMatchObject({
    data: { text: "pending" },
    confirmation: "not yet confirmed",
  });
});

it.each(["connection-reset", "connection-delete"] as const)(
  "does not resurrect pending records after local %s",
  async (kind) => {
    const { make } = device();
    const store = make();
    await provision(store);
    await store.import({ ...pending("confirmed", 2), id: "confirmed" });
    await store.stagePending(pending());
    await store.commitLocal("lifecycle", [
      {
        ...identity,
        kind,
        generation: kind === "connection-reset" ? 2 : 1,
        ...(kind === "connection-reset" ? { previousGeneration: 1 } : {}),
      },
    ]);
    expect(await read(make(), "owner")).toMatchObject({ deleted: true });
    expect(await read(make())).toMatchObject({ deleted: true });
  },
);

it("keeps pending hooks and reads disabled with the replication flag off", async () => {
  const { make } = device();
  const store = make(false);
  await expect(store.stagePending(pending())).rejects.toThrow("disabled");
  await expect(
    store.promotePending({
      id: "pending",
      credential: "replica",
      fingerprint: "x",
    }),
  ).rejects.toThrow("disabled");
  await expect(read(store, "owner")).rejects.toThrow("disabled");
});

it("keeps pending blob bytes behind the same policy and hides quarantined bytes", async () => {
  const { sha256 } = await import("viem");
  const { make } = device();
  const store = make();
  await provision(store);
  const bytes = new TextEncoder().encode("pending bytes");
  const hash = `sha256:${sha256(bytes).slice(2)}`;
  const blob = {
    blobId: hash,
    sha256: hash,
    mimeType: "text/plain",
    sizeBytes: bytes.length,
  };
  const stagingId = await store.stageBlob(
    blob,
    (async function* () {
      yield bytes;
    })(),
  );
  const request = pending();
  const record = upsert("blob", 3);
  record.blobs = [blob];
  record.data.blob_ref = { blob_id: hash };
  request.envelope.operations = [
    registration,
    {
      ...identity,
      kind: "blob-claim",
      revision: { counter: 2, writerId: "device-a", operationId: "claim" },
      blob,
    },
    record,
  ];
  const staged = await store.stagePending({
    ...request,
    blobs: [{ stagingId, descriptor: blob }],
  });
  const collect = async (reader: "owner" | "grant") => {
    const parts: Uint8Array[] = [];
    for await (const part of store.readBlob(hash, { reader })) parts.push(part);
    return parts;
  };
  await expect(collect("grant")).rejects.toThrow("missing committed blob");
  expect(await collect("owner")).toEqual([bytes]);
  expect(await read(store, "owner")).toMatchObject({
    data: { blob_ref: { blob_id: hash } },
    confirmation: "not yet confirmed",
  });
  await store.quarantinePending({
    id: request.id,
    credential: "replica",
    reason: "later finalized version",
  });
  await expect(collect("owner")).rejects.toThrow("missing committed blob");
  await expect(
    store.promotePending({
      id: request.id,
      credential: "replica",
      fingerprint: staged.fingerprint,
    }),
  ).rejects.toThrow("quarantined");
});

it("atomically exposes pending blob bytes to grants on promotion", async () => {
  const { sha256 } = await import("viem");
  const { make } = device();
  const store = make();
  await provision(store);
  const bytes = new TextEncoder().encode("promoted bytes");
  const hash = `sha256:${sha256(bytes).slice(2)}`;
  const blob = {
    blobId: hash,
    sha256: hash,
    mimeType: "text/plain",
    sizeBytes: bytes.length,
  };
  const stagingId = await store.stageBlob(
    blob,
    (async function* () {
      yield bytes;
    })(),
  );
  const request = pending();
  const record = upsert("blob", 3);
  record.blobs = [blob];
  record.data.blob_ref = { blob_id: hash };
  request.envelope.operations = [
    registration,
    {
      ...identity,
      kind: "blob-claim",
      revision: { counter: 2, writerId: "device-a", operationId: "claim" },
      blob,
    },
    record,
  ];
  const staged = await store.stagePending({
    ...request,
    blobs: [{ stagingId, descriptor: blob }],
  });
  await store.promotePending({
    id: request.id,
    credential: "replica",
    fingerprint: staged.fingerprint,
  });
  const parts: Uint8Array[] = [];
  for await (const part of make().readBlob(hash)) parts.push(part);
  expect(parts).toEqual([bytes]);
  expect(await read(make())).toMatchObject({
    data: { blob_ref: { blob_id: hash } },
  });
});

it("paginates mixed confirmed and pending records without gaps or duplicates", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  const records = Array.from({ length: 105 }, (_, index) => {
    const key = `key-${index}`;
    return {
      ...upsert(key, index + 2),
      recordKey: key,
      data: { id: key, text: key },
    };
  });
  await store.import({
    ...pending(),
    id: "confirmed",
    envelope: {
      ...pending().envelope,
      operations: [registration, ...records.slice(0, 51)],
    },
  });
  await store.stagePending({
    ...pending(),
    envelope: {
      ...pending().envelope,
      operations: [registration, ...records.slice(51)],
    },
  });
  const keys: string[] = [];
  let after: string | undefined;
  do {
    const page = await store.readConnectionPage(identity.connectionId, after, {
      reader: "owner",
    });
    keys.push(...page.rows.map((row) => row.recordKey));
    after = page.after;
  } while (after !== undefined);
  expect(keys.length).toBe(105);
  expect(new Set(keys)).toEqual(
    new Set(records.map((record) => record.recordKey)),
  );
});
