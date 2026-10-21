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

it.each(["delete", "equivocation"] as const)(
  "serves pending blob bytes only while a visible pending record references them (%s)",
  async (later) => {
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
    const record = upsert("record", 3);
    record.blobs = [blob];
    record.data.blob_ref = { blob_id: hash };
    const batch = (id: string, operations: unknown[]) => ({
      id,
      credential: "replica",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: id,
        operations,
      },
    });
    await store.stagePending({
      ...batch("first", [
        registration,
        {
          ...identity,
          kind: "blob-claim",
          revision: {
            counter: 2,
            writerId: "device-a",
            operationId: "claim",
          },
          blob,
        },
        record,
      ]),
      blobs: [{ stagingId, descriptor: blob }],
    });
    const owner = async () => {
      const parts: Uint8Array[] = [];
      for await (const part of store.readBlob(hash, { reader: "owner" }))
        parts.push(part);
      return parts;
    };
    expect(await owner()).toEqual([bytes]);
    // A winning pending deletion, or an operation-ID variant that hides the
    // record, leaves the blob batch active but removes its only reference.
    await store.stagePending(
      batch("second", [
        later === "delete"
          ? {
              ...identity,
              kind: "delete",
              declaration: binding,
              recordKey: "same-key",
              emittedAt: record.emittedAt,
              deletedAt: record.emittedAt,
              revision: {
                counter: 4,
                writerId: "device-a",
                operationId: "delete",
              },
            }
          : {
              ...record,
              data: { id: "same-key", text: "variant" },
              blobs: [],
            },
      ]),
    );
    await expect(owner(), later).rejects.toThrow("missing committed blob");
    // Withdrawing the later batch restores the reference and the bytes.
    await store.quarantinePending({
      id: "second",
      credential: "replica",
      reason: "later finalized version",
    });
    expect(await owner(), later).toEqual([bytes]);
  },
);

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

it.each([1, 120])(
  "bounds point and page reads with %i pending batches",
  async (count) => {
    const { adapter } = device();
    const scans: { prefix: string; rows: number }[] = [];
    const port = {
      ...adapter.port,
      transaction: ((run) =>
        adapter.port.transaction((tx) =>
          run({
            ...tx,
            scan: async (prefix, after) => {
              const page = await tx.scan(prefix, after);
              scans.push({ prefix, rows: page.entries.length });
              return page;
            },
          }),
        )) as typeof adapter.port.transaction,
    };
    const store = createLiteCanonicalStore({
      persistence: port,
      enabled: true,
      context: () => ({
        owner: identity.owner,
        declarations: [
          { sourceId: identity.sourceId, binding, validateData: () => true },
        ],
      }),
      authenticateReplica: () => identity.owner,
    });
    await provision(store);
    for (let index = 0; index < count; index++) {
      const request = pending(`pending-${index}`, index + 2);
      request.id = `batch-${index}`;
      request.envelope.batchId = request.id;
      if (index > 0) {
        const op = upsert(`pending-${index}`, index + 2);
        op.recordKey = `unrelated-${index}`;
        op.data.id = op.recordKey;
        request.envelope.operations = [op];
      }
      await store.stagePending(request);
    }
    scans.length = 0;
    expect(await read(store, "owner")).toMatchObject({
      data: { text: "pending-0" },
    });
    expect(scans).toEqual([]);
    scans.length = 0;
    expect(
      (
        await store.readConnectionPage(identity.connectionId, undefined, {
          reader: "owner",
        })
      ).rows.length,
    ).toBe(Math.min(100, count));
    expect(
      scans.every(
        ({ prefix }) =>
          prefix.startsWith("rows/") || prefix.startsWith("preview/rows/"),
      ),
    ).toBe(true);
    expect(scans.reduce((sum, { rows }) => sum + rows, 0)).toBeLessThanOrEqual(
      200,
    );
  },
);

it.each(["delete", "connection-reset", "connection-delete"] as const)(
  "marks provisional %s tombstones and restores canonical rows on quarantine",
  async (kind) => {
    const { make } = device();
    const store = make();
    await provision(store);
    await store.import({ ...pending("confirmed", 2), id: "confirmed" });
    const op =
      kind === "delete"
        ? {
            ...identity,
            kind,
            declaration: binding,
            recordKey: "same-key",
            emittedAt: "2026-10-20T01:00:00Z",
            deletedAt: "2026-10-20T01:00:00Z",
            revision: { counter: 100, writerId: "device-b", operationId: kind },
          }
        : {
            ...identity,
            kind,
            generation: kind === "connection-reset" ? 2 : 1,
            ...(kind === "connection-reset" ? { previousGeneration: 1 } : {}),
            revision: { counter: 100, writerId: "device-b", operationId: kind },
          };
    const request = {
      ...pending(),
      envelope: { ...pending().envelope, operations: [op] },
    };
    await store.stagePending(request);
    const tombstone = {
      deleted: true,
      confirmation: "not yet confirmed",
      visibility: "pending",
    };
    expect(await read(make(), "owner")).toMatchObject(tombstone);
    expect(
      (
        await make().readConnectionPage(identity.connectionId, undefined, {
          reader: "owner",
        })
      ).rows,
    ).toEqual([expect.objectContaining(tombstone)]);
    expect(await read(make())).toMatchObject({
      deleted: false,
      data: { text: "confirmed" },
    });
    await store.quarantinePending({
      id: request.id,
      credential: "replica",
      reason: "invalid finality",
    });
    expect(await read(make(), "owner")).toMatchObject({
      deleted: false,
      data: { text: "confirmed" },
    });
    expect(await read(make(), "owner")).not.toHaveProperty("confirmation");
  },
);

it("preserves tuple ordering across two devices, reverse arrival and reopen", async () => {
  for (const reverse of [false, true]) {
    const { make } = device();
    let store = make();
    await provision(store);
    await store.import({ ...pending("confirmed", 2), id: "confirmed" });
    const requests = ["device-a", "device-b"].map((writerId) => ({
      ...pending(),
      id: writerId,
      envelope: {
        ...pending().envelope,
        batchId: writerId,
        operations: [upsert(writerId, 100, writerId, writerId)],
      },
    }));
    for (const request of reverse ? [...requests].reverse() : requests) {
      await store.stagePending(request);
      store = make();
    }
    expect(await read(store, "owner")).toMatchObject({
      data: { text: "device-b" },
      visibility: "pending",
    });
    await store.quarantinePending({
      id: "device-b",
      credential: "replica",
      reason: "withdrawn",
    });
    expect(await read(make(), "owner")).toMatchObject({
      data: { text: "device-a" },
    });
    const staged = await store.stagePending(requests[0]);
    await store.promotePending({
      id: "device-a",
      credential: "replica",
      fingerprint: staged.fingerprint,
    });
    expect(await read(make(), "owner")).toMatchObject({
      data: { text: "device-a" },
    });
    expect(await read(make(), "owner")).not.toHaveProperty("confirmation");
  }
});

it("keeps shared pending operations until their last batch is withdrawn", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  await store.stagePending(pending());
  await store.stagePending({ ...pending(), id: "duplicate" });
  await store.quarantinePending({
    id: pending().id,
    credential: "replica",
    reason: "withdrawn",
  });
  expect(await read(make(), "owner")).toMatchObject({
    data: { text: "pending" },
  });
  await store.quarantinePending({
    id: "duplicate",
    credential: "replica",
    reason: "withdrawn",
  });
  expect(await read(make(), "owner")).toBeUndefined();
});

it.each(["canonical", "stage", "promotion", "quarantine"] as const)(
  "explicitly expires page cursors after a %s write",
  async (change) => {
    const { make } = device();
    const store = make();
    await provision(store);
    const records = Array.from({ length: 101 }, (_, index) => ({
      ...upsert(`record-${index}`, index + 2),
      recordKey: `key-${index}`,
      data: { id: `key-${index}`, text: "confirmed" },
    }));
    await store.import({
      ...pending(),
      id: "confirmed",
      envelope: {
        ...pending().envelope,
        operations: [registration, ...records],
      },
    });
    const staged = await store.stagePending(pending("preview", 200));
    const page = await store.readConnectionPage(
      identity.connectionId,
      undefined,
      { reader: "owner" },
    );
    expect(page.after).toBeDefined();
    if (change === "canonical")
      await store.import({ ...pending("update", 300), id: "update" });
    if (change === "stage")
      await store.stagePending({ ...pending("next", 300), id: "next" });
    if (change === "promotion")
      await store.promotePending({
        id: pending().id,
        credential: "replica",
        fingerprint: staged.fingerprint,
      });
    if (change === "quarantine")
      await store.quarantinePending({
        id: pending().id,
        credential: "replica",
        reason: "withdrawn",
      });
    await expect(
      make().readConnectionPage(identity.connectionId, page.after, {
        reader: "owner",
      }),
    ).rejects.toThrow("cursor expired");
  },
);

it("rolls back pending indexes and preview rows on interrupted stage and quarantine", async () => {
  const { make, adapter } = device();
  const store = make();
  await provision(store);
  adapter.crashAt("before-commit");
  await expect(store.stagePending(pending())).rejects.toThrow("interrupted");
  expect(await read(make(), "owner")).toBeUndefined();
  await store.stagePending(pending());
  adapter.crashAt("before-commit");
  await expect(
    store.quarantinePending({
      id: pending().id,
      credential: "replica",
      reason: "withdrawn",
    }),
  ).rejects.toThrow("interrupted");
  expect(await read(make(), "owner")).toMatchObject({
    data: { text: "pending" },
  });
});

it("requires write-side reconciliation of older pending databases without rebuilding on reads", async () => {
  const { make, adapter } = device();
  const store = make();
  await provision(store);
  await store.stagePending(pending());
  for (const key of adapter.disk.rows.keys())
    if (
      key.startsWith("pending-index/") ||
      key.startsWith("pending-refs/") ||
      key.startsWith("pending-bindings/") ||
      key.startsWith("pending-blob-active/") ||
      key.startsWith("preview/") ||
      key === "pending-index-version" ||
      key === "preview-revision" ||
      key.startsWith("preview-revision/") ||
      key.startsWith("canonical-view-revision/")
    )
      adapter.disk.rows.delete(key);
  await expect(read(make(), "owner")).rejects.toThrow(
    "requires reconciliation",
  );
  expect(await read(make())).toBeUndefined();
  let after: string | undefined;
  do {
    ({ after } = await make().retry({ credential: "replica", after }));
  } while (after !== undefined);
  expect(await read(make(), "owner")).toMatchObject({
    data: { text: "pending" },
    visibility: "pending",
  });
  expect(adapter.disk.rows.get("pending-index-version")).toBe("2");
  for (const prefix of ["preview-revision/", "canonical-view-revision/"])
    expect(
      [...adapter.disk.rows].some(
        ([key, value]) => key.startsWith(prefix) && Number(value) > 0,
      ),
    ).toBe(true);
});

it("restores another connection when a pending cross-connection operation-id conflict is quarantined", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  const other = "connection-b";
  await store.provisionConnection(other, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  await store.import({ ...pending("confirmed", 2), id: "confirmed" });
  const first = upsert("shared", 100);
  const second = { ...upsert("shared", 100), connectionId: other };
  await store.stagePending({
    ...pending(),
    id: "first",
    envelope: { ...pending().envelope, operations: [first] },
  });
  await store.stagePending({
    ...pending(),
    id: "second",
    envelope: {
      ...pending().envelope,
      operations: [
        {
          ...registration,
          connectionId: other,
          revision: { ...registration.revision, operationId: "register-b" },
        },
        second,
      ],
    },
  });
  expect(await read(make(), "owner")).toMatchObject({
    deleted: true,
    visibility: "pending",
  });
  await store.quarantinePending({
    id: "second",
    credential: "replica",
    reason: "withdrawn",
  });
  expect(await read(make(), "owner")).toMatchObject({
    deleted: false,
    data: { text: "shared" },
    visibility: "pending",
  });
});

it("keeps grant cursors valid through pending-only stage and quarantine", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  const records = Array.from({ length: 101 }, (_, i) => ({
    ...upsert(`canonical-${i}`, i + 2),
    recordKey: `key-${i}`,
    data: { id: `key-${i}`, text: "canonical" },
  }));
  await store.import({
    ...pending(),
    id: "canonical",
    envelope: { ...pending().envelope, operations: [registration, ...records] },
  });
  const page = await store.readConnectionPage(identity.connectionId);
  expect(page.after).toBeDefined();
  await store.stagePending(pending("preview", 200));
  expect(
    (await make().readConnectionPage(identity.connectionId, page.after)).rows,
  ).toHaveLength(1);
  await store.quarantinePending({
    id: pending().id,
    credential: "replica",
    reason: "withdrawn",
  });
  expect(
    (await make().readConnectionPage(identity.connectionId, page.after)).rows,
  ).toHaveLength(1);
  await store.import({ ...pending("canonical update", 300), id: "update" });
  await expect(
    make().readConnectionPage(identity.connectionId, page.after),
  ).rejects.toThrow("cursor expired");
});

it.each([
  ["connection-reset", 1],
  ["connection-delete", 1],
  ["connection-reset", 2],
  ["connection-delete", 2],
] as const)(
  "derives pending-only %s removals from active generation %i source evidence",
  async (kind, sourceGeneration) => {
    for (const quarantine of ["source", "removal"]) {
      const { make } = device();
      const store = make();
      await provision(store);
      await store.import({
        ...pending(),
        id: "registration",
        envelope: { ...pending().envelope, operations: [registration] },
      });
      await store.stagePending({
        ...pending(),
        id: "source",
        envelope: {
          ...pending().envelope,
          operations: [
            ...(sourceGeneration === 2
              ? [
                  {
                    ...identity,
                    kind: "connection-reset",
                    generation: 2,
                    previousGeneration: 1,
                    revision: {
                      counter: 99,
                      writerId: "device-b",
                      operationId: "source-reset",
                    },
                  },
                ]
              : []),
            { ...upsert("pending source", 100), generation: sourceGeneration },
          ],
        },
      });
      await store.stagePending({
        ...pending(),
        id: "removal",
        envelope: {
          ...pending().envelope,
          operations: [
            {
              ...identity,
              kind,
              generation:
                kind === "connection-reset"
                  ? sourceGeneration + 1
                  : sourceGeneration,
              ...(kind === "connection-reset"
                ? { previousGeneration: sourceGeneration }
                : {}),
              revision: {
                counter: 200,
                writerId: "device-b",
                operationId: kind,
              },
            },
          ],
        },
      });
      const tombstone = {
        deleted: true,
        confirmation: "not yet confirmed",
        visibility: "pending",
      };
      expect(await read(make(), "owner")).toMatchObject(tombstone);
      expect(
        (
          await make().readConnectionPage(identity.connectionId, undefined, {
            reader: "owner",
          })
        ).rows,
      ).toEqual([expect.objectContaining(tombstone)]);
      expect(await read(make())).toBeUndefined();
      await store.quarantinePending({
        id: quarantine,
        credential: "replica",
        reason: "withdrawn",
      });
      if (quarantine === "source") {
        expect(await read(make(), "owner")).toBeUndefined();
        expect(
          (
            await make().readConnectionPage(identity.connectionId, undefined, {
              reader: "owner",
            })
          ).rows,
        ).toEqual([]);
      } else
        expect(await read(make(), "owner")).toMatchObject({
          deleted: false,
          data: { text: "pending source" },
          visibility: "pending",
        });
    }
  },
);

it("clears a withdrawn connection's marker while two other equivocation variants remain", async () => {
  const { make } = device();
  const store = make();
  const y = "connection-y",
    z = "connection-z";
  for (const id of [identity.connectionId, y, z])
    await store.provisionConnection(id, {
      sourceId: identity.sourceId,
      methodId: identity.methodId,
    });
  const shared = upsert("shared", 2);
  const canonicalY = { ...upsert("canonical-y", 3), connectionId: y };
  await store.import({
    ...pending(),
    id: "canonical",
    envelope: {
      ...pending().envelope,
      operations: [
        registration,
        shared,
        {
          ...registration,
          connectionId: y,
          revision: { ...registration.revision, operationId: "register-y" },
        },
        canonicalY,
        {
          ...registration,
          connectionId: z,
          revision: { ...registration.revision, operationId: "register-z" },
        },
      ],
    },
  });
  for (const id of [y, z])
    await store.stagePending({
      ...pending(),
      id,
      envelope: {
        ...pending().envelope,
        operations: [{ ...shared, connectionId: id }],
      },
    });
  const readY = () =>
    make().readRecord(y, binding.stream, "same-key", { reader: "owner" });
  expect(await readY()).toMatchObject({ deleted: true, visibility: "pending" });
  await store.quarantinePending({
    id: y,
    credential: "replica",
    reason: "withdrawn",
  });
  expect(await readY()).toMatchObject({
    deleted: false,
    data: { text: "canonical-y" },
  });
  expect(await readY()).not.toHaveProperty("confirmation");
  await store.quarantinePending({
    id: z,
    credential: "replica",
    reason: "withdrawn",
  });
  expect(await readY()).toMatchObject({
    deleted: false,
    data: { text: "canonical-y" },
  });
});

it.each(["connection-reset", "connection-delete"] as const)(
  "does not label canonical %s suppression of pending-only data as provisional",
  async (kind) => {
    const { make } = device();
    const store = make();
    await provision(store);
    const lifecycle = {
      ...identity,
      kind,
      generation: kind === "connection-reset" ? 2 : 1,
      ...(kind === "connection-reset" ? { previousGeneration: 1 } : {}),
      revision: {
        counter: 10,
        writerId: "device-b",
        operationId: "canonical-removal",
      },
    };
    await store.import({
      ...pending(),
      id: "canonical",
      envelope: {
        ...pending().envelope,
        operations: [registration, lifecycle],
      },
    });
    await store.stagePending({
      ...pending(),
      id: "source",
      envelope: {
        ...pending().envelope,
        operations: [upsert("old pending", 100)],
      },
    });
    await store.stagePending({
      ...pending(),
      id: "pending-removal",
      envelope: {
        ...pending().envelope,
        operations: [
          {
            ...identity,
            kind: "connection-delete",
            revision: {
              counter: 200,
              writerId: "device-b",
              operationId: "pending-removal",
            },
          },
        ],
      },
    });
    expect(await read(make(), "owner")).toBeUndefined();
  },
);

it("uses one captured declaration context throughout a pending write", async () => {
  const { adapter } = device();
  await provision(
    createLiteCanonicalStore({
      persistence: adapter.port,
      enabled: true,
      context: () => ({ owner: identity.owner, declarations: [] }),
      authenticateReplica: () => identity.owner,
    }),
  );
  let calls = 0;
  const store = createLiteCanonicalStore({
    persistence: adapter.port,
    enabled: true,
    context: () => ({
      owner: identity.owner,
      declarations:
        ++calls === 1
          ? [{ sourceId: identity.sourceId, binding, validateData: () => true }]
          : [],
    }),
    authenticateReplica: () => identity.owner,
  });
  await store.stagePending(pending());
  expect(calls).toBe(1);
  expect(await read(store, "owner")).toMatchObject({
    data: { text: "pending" },
    visibility: "pending",
  });
});

it.each(["owner", "grant"] as const)(
  "keeps %s cursors across every unrelated connection write",
  async (reader) => {
    const { make } = device();
    const store = make();
    await provision(store);
    const other = "unrelated-connection";
    await store.provisionConnection(other, {
      sourceId: identity.sourceId,
      methodId: identity.methodId,
    });
    const records = Array.from({ length: 101 }, (_, i) => ({
      ...upsert(`stable-${i}`, i + 2),
      recordKey: `key-${i}`,
      data: { id: `key-${i}`, text: "stable" },
    }));
    await store.import({
      ...pending(),
      id: "canonical",
      envelope: {
        ...pending().envelope,
        operations: [registration, ...records],
      },
    });
    const first = await store.readConnectionPage(
      identity.connectionId,
      undefined,
      { reader },
    );
    const next = () =>
      make().readConnectionPage(identity.connectionId, first.after, { reader });
    const otherOp = { ...upsert("other", 200), connectionId: other };
    const request = {
      ...pending(),
      id: "other",
      envelope: {
        ...pending().envelope,
        operations: [
          {
            ...registration,
            connectionId: other,
            revision: {
              ...registration.revision,
              operationId: "other-registration",
            },
          },
          otherOp,
        ],
      },
    };
    await store.stagePending(request);
    expect((await next()).rows).toHaveLength(1);
    await store.quarantinePending({
      id: request.id,
      credential: "replica",
      reason: "withdrawn",
    });
    expect((await next()).rows).toHaveLength(1);
    await store.import({ ...request, id: "other-canonical" });
    expect((await next()).rows).toHaveLength(1);
  },
);

function observedDevice() {
  const { adapter } = device();
  const scans: { prefix: string; count: number; bytes: number }[] = [];
  const rowWork: string[] = [];
  const recordKeys = new Set<string>();
  const port = {
    ...adapter.port,
    transaction: ((run) =>
      adapter.port.transaction((tx) =>
        run({
          ...tx,
          get: async (key) => {
            if (key.startsWith("rows/") || key.startsWith("preview/rows/"))
              rowWork.push(key);
            return tx.get(key);
          },
          put: async (key, value) => {
            if (key.startsWith("rows/") || key.startsWith("preview/rows/"))
              rowWork.push(key);
            return tx.put(key, value);
          },
          delete: async (key) => {
            if (key.startsWith("rows/") || key.startsWith("preview/rows/"))
              rowWork.push(key);
            return tx.delete(key);
          },
          scan: async (prefix, after) => {
            const page = await tx.scan(prefix, after);
            scans.push({
              prefix,
              count: page.entries.length,
              bytes: page.entries.reduce(
                (sum, entry) =>
                  sum + new TextEncoder().encode(entry.value).length,
                0,
              ),
            });
            if (prefix.includes("/records/"))
              for (const entry of page.entries)
                recordKeys.add(JSON.parse(entry.value).recordKey);
            return page;
          },
        }),
      )) as typeof adapter.port.transaction,
  };
  const store = createLiteCanonicalStore({
    persistence: port,
    enabled: true,
    context: () => ({
      owner: identity.owner,
      declarations: [
        { sourceId: identity.sourceId, binding, validateData: () => true },
      ],
    }),
    authenticateReplica: () => identity.owner,
  });
  return {
    store,
    scans,
    rowWork,
    recordKeys,
    reset() {
      scans.length = 0;
      rowWork.length = 0;
      recordKeys.clear();
    },
  };
}

it.each([20, 6000])(
  "bounds mixed canonical/preview native inputs and visible output at %i payload bytes",
  async (size) => {
    const { store, scans, rowWork, reset } = observedDevice();
    await provision(store);
    const records = Array.from({ length: 120 }, (_, i) => ({
      ...upsert(`mixed-${i}`, i + 2),
      recordKey: `key-${i}`,
      data: { id: `key-${i}`, text: "x".repeat(size) },
    }));
    for (let offset = 0; offset < records.length; offset += 20) {
      await store.import({
        ...pending(),
        id: `canonical-${offset}`,
        envelope: {
          ...pending().envelope,
          operations: [
            ...(offset ? [] : [registration]),
            ...records.slice(offset, offset + 20),
          ],
        },
      });
      await store.stagePending({
        ...pending(),
        id: `preview-${offset}`,
        envelope: {
          ...pending().envelope,
          operations: records.slice(offset, offset + 20).map((op) => ({
            ...op,
            data: { ...op.data, text: "y".repeat(size) },
            revision: {
              ...op.revision,
              counter: op.revision.counter + 200,
              operationId: `preview-${op.recordKey}`,
            },
          })),
        },
      });
    }
    reset();
    const page = await store.readConnectionPage(
      identity.connectionId,
      undefined,
      { reader: "owner" },
    );
    expect(scans).toHaveLength(2);
    expect(rowWork).toEqual([]);
    expect(
      scans.every((scan) => scan.count <= 100 && scan.bytes <= 512 * 1024),
    ).toBe(true);
    expect(
      scans.every(
        ({ prefix }) =>
          prefix.startsWith("rows/") || prefix.startsWith("preview/rows/"),
      ),
    ).toBe(true);
    expect(scans.reduce((sum, scan) => sum + scan.count, 0)).toBeGreaterThan(
      100,
    );
    expect(
      scans.reduce((sum, scan) => sum + scan.count, 0),
    ).toBeLessThanOrEqual(200);
    expect(
      scans.reduce((sum, scan) => sum + scan.bytes, 0),
    ).toBeLessThanOrEqual(1024 * 1024);
    expect(page.rows.length).toBeLessThanOrEqual(100);
    expect(
      new TextEncoder().encode(JSON.stringify(page.rows)).length,
    ).toBeLessThanOrEqual(512 * 1024);
    expect(
      page.rows.every(
        (row) => !row.deleted && row.data.text === "y".repeat(size),
      ),
    ).toBe(true);
    const keys = page.rows.map((row) => row.recordKey);
    let after = page.after;
    while (after !== undefined) {
      const next = await store.readConnectionPage(
        identity.connectionId,
        after,
        { reader: "owner" },
      );
      keys.push(...next.rows.map((row) => row.recordKey));
      after = next.after;
    }
    expect(keys.length).toBe(120);
    expect(new Set(keys).size).toBe(120);
  },
  15000,
);

it.each(["stage", "commit"] as const)(
  "bounds ordinary one-key %s row work independently of unrelated pending keys",
  async (kind) => {
    const work: { rows: number; scanned: number; scanCalls: number }[] = [];
    for (const count of [1, 120]) {
      const { store, scans, rowWork, recordKeys, reset } = observedDevice();
      await provision(store);
      await store.import({ ...pending("canonical", 2), id: "canonical" });
      for (let i = 0; i < count; i++) {
        const op = {
          ...upsert(`backlog-${i}`, i + 3),
          recordKey: `backlog-${i}`,
          data: { id: `backlog-${i}`, text: "pending" },
        };
        await store.stagePending({
          ...pending(),
          id: `backlog-${i}`,
          envelope: { ...pending().envelope, operations: [op] },
        });
      }
      reset();
      if (kind === "stage")
        await store.stagePending({
          ...pending("target", 1000),
          id: "target",
          envelope: {
            ...pending().envelope,
            operations: [upsert("target", 1000)],
          },
        });
      else {
        const { revision: _, ...draft } = upsert("target", 1000);
        await store.commitLocal("target", [draft]);
      }
      expect(recordKeys).toEqual(new Set(["same-key"]));
      expect(new Set(rowWork).size).toBeLessThanOrEqual(2);
      expect(
        scans.some(
          ({ prefix }) =>
            prefix.startsWith("keys/") ||
            prefix.startsWith("pending-index/keys/"),
        ),
      ).toBe(false);
      work.push({
        rows: rowWork.length,
        scanned: scans.reduce((sum, scan) => sum + scan.count, 0),
        scanCalls: scans.length,
      });
      expect(await read(store, "owner")).toMatchObject({
        data: { text: "target" },
      });
    }
    expect(work[1]).toEqual(work[0]);
  },
  15000,
);

it("invalidates only affected modes and connections for a global operation-id collision", async () => {
  const { make } = device();
  const store = make();
  await provision(store);
  const other = "collision-connection";
  await store.provisionConnection(other, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  const records = Array.from({ length: 101 }, (_, i) => ({
    ...upsert(`shared-${i}`, i + 2),
    recordKey: `key-${i}`,
    data: { id: `key-${i}`, text: "canonical" },
  }));
  await store.import({
    ...pending(),
    id: "canonical",
    envelope: {
      ...pending().envelope,
      operations: [
        registration,
        ...records,
        {
          ...registration,
          connectionId: other,
          revision: { ...registration.revision, operationId: "register-other" },
        },
      ],
    },
  });
  const owner = await store.readConnectionPage(
    identity.connectionId,
    undefined,
    { reader: "owner" },
  );
  const grant = await store.readConnectionPage(identity.connectionId);
  const collision = {
    ...pending(),
    id: "collision",
    envelope: {
      ...pending().envelope,
      operations: [{ ...records[0], connectionId: other }],
    },
  };
  await store.stagePending(collision);
  await expect(
    make().readConnectionPage(identity.connectionId, owner.after, {
      reader: "owner",
    }),
  ).rejects.toThrow("cursor expired");
  expect(
    (await make().readConnectionPage(identity.connectionId, grant.after)).rows,
  ).toHaveLength(1);
  const blocked = await store.readConnectionPage(
    identity.connectionId,
    undefined,
    { reader: "owner" },
  );
  await store.quarantinePending({
    id: collision.id,
    credential: "replica",
    reason: "withdrawn",
  });
  await expect(
    make().readConnectionPage(identity.connectionId, blocked.after, {
      reader: "owner",
    }),
  ).rejects.toThrow("cursor expired");
  expect(
    (await make().readConnectionPage(identity.connectionId, grant.after)).rows,
  ).toHaveLength(1);
  await store.import({ ...collision, id: "canonical-collision" });
  await expect(
    make().readConnectionPage(identity.connectionId, grant.after),
  ).rejects.toThrow("cursor expired");
});

it("upgrades version-one derived indexes and global revisions to connection snapshot receipts", async () => {
  const { adapter, make } = device();
  const store = make();
  await provision(store);
  await store.stagePending(pending());
  for (const key of adapter.disk.rows.keys())
    if (
      key.startsWith("preview-revision/") ||
      key.startsWith("canonical-view-revision/")
    )
      adapter.disk.rows.delete(key);
  adapter.disk.rows.set("pending-index-version", "1");
  adapter.disk.rows.set("preview-revision", "17");
  adapter.disk.rows.set("canonical-view-revision", "9");
  await expect(read(make(), "owner")).rejects.toThrow(
    "requires reconciliation",
  );
  expect((await make().readConnectionPage(identity.connectionId)).rows).toEqual(
    [],
  );
  await make().retry({ credential: "replica" });
  expect(adapter.disk.rows.get("pending-index-version")).toBe("2");
  expect(await read(make(), "owner")).toMatchObject({
    data: { text: "pending" },
  });
  for (const prefix of ["preview-revision/", "canonical-view-revision/"])
    expect(
      [...adapter.disk.rows].some(
        ([key, value]) => key.startsWith(prefix) && Number(value) > 0,
      ),
    ).toBe(true);
  await make().quarantinePending({
    id: pending().id,
    credential: "replica",
    reason: "withdrawn",
  });
  expect(await read(make(), "owner")).toBeUndefined();
});

it.each(["canonical", "preview", "both"] as const)(
  "continues bounded native empty %s pages without skipping rows",
  async (empty) => {
    const { adapter } = device();
    let reading = false;
    let scans = 0;
    const persistence = {
      ...adapter.port,
      transaction: ((run) =>
        adapter.port.transaction((tx) =>
          run({
            ...tx,
            scan: async (prefix, after) => {
              if (
                reading &&
                (prefix.startsWith("rows/") ||
                  prefix.startsWith("preview/rows/"))
              ) {
                scans++;
                const mode = prefix.startsWith("preview/")
                  ? "preview"
                  : "canonical";
                if (after === undefined && (empty === "both" || empty === mode))
                  return { entries: [], after: prefix };
              }
              return tx.scan(prefix, after);
            },
          }),
        )) as typeof adapter.port.transaction,
    };
    const store = createLiteCanonicalStore({
      persistence,
      enabled: true,
      context: () => ({
        owner: identity.owner,
        declarations: [
          { sourceId: identity.sourceId, binding, validateData: () => true },
        ],
      }),
      authenticateReplica: () => identity.owner,
    });
    await provision(store);
    await store.import({ ...pending("confirmed", 2), id: "confirmed" });
    await store.stagePending(pending());
    reading = true;
    const first = await store.readConnectionPage(
      identity.connectionId,
      undefined,
      { reader: "owner" },
    );
    expect(first.rows).toEqual([]);
    expect(first.after).toBeDefined();
    expect(scans).toBe(2);
    const second = await store.readConnectionPage(
      identity.connectionId,
      first.after,
      { reader: "owner" },
    );
    expect(second.rows).toEqual([
      expect.objectContaining({
        recordKey: "same-key",
        data: { id: "same-key", text: "pending" },
        visibility: "pending",
      }),
    ]);
    expect(second.after).toBeUndefined();
    expect(scans).toBe(4);
  },
);

it.each([undefined, 1])(
  "serves old-db grant pages before index version %s upgrade and expires their revision-zero cursors afterwards",
  async (version) => {
    const { adapter, make } = device();
    const store = make();
    await provision(store);
    const records = Array.from({ length: 101 }, (_, i) => ({
      ...upsert(`legacy-${i}`, i + 2),
      recordKey: i ? `key-${i}` : "same-key",
      data: { id: i ? `key-${i}` : "same-key", text: "canonical" },
    }));
    await store.import({
      ...pending(),
      id: "canonical",
      envelope: {
        ...pending().envelope,
        operations: [registration, ...records],
      },
    });
    await store.stagePending(pending("preview", 500));
    for (const key of adapter.disk.rows.keys()) {
      if (
        key.startsWith("preview-revision/") ||
        key.startsWith("canonical-view-revision/") ||
        (version === undefined &&
          (key.startsWith("pending-index/") ||
            key.startsWith("pending-refs/") ||
            key.startsWith("pending-bindings/") ||
            key.startsWith("preview/")))
      )
        adapter.disk.rows.delete(key);
    }
    if (version === undefined)
      adapter.disk.rows.delete("pending-index-version");
    else
      adapter.disk.rows.set("pending-index-version", JSON.stringify(version));
    await expect(read(make(), "owner")).rejects.toThrow(
      "requires reconciliation",
    );
    await expect(
      make().readConnectionPage(identity.connectionId, undefined, {
        reader: "owner",
      }),
    ).rejects.toThrow("requires reconciliation");
    const first = await make().readConnectionPage(identity.connectionId);
    expect(first.rows).toHaveLength(100);
    expect(first.after).toContain("/v2/0/canonical/");
    const second = await make().readConnectionPage(
      identity.connectionId,
      first.after,
    );
    expect(second.rows).toHaveLength(1);
    const rows = [...first.rows, ...second.rows];
    expect(new Set(rows.map((row) => row.recordKey)).size).toBe(101);
    expect(
      rows.every(
        (row) =>
          !row.deleted &&
          row.data.text === "canonical" &&
          row.confirmation === undefined,
      ),
    ).toBe(true);
    await make().retry({ credential: "replica" });
    await expect(
      make().readConnectionPage(identity.connectionId, first.after),
    ).rejects.toThrow("cursor expired");
    expect(await read(make())).toMatchObject({ data: { text: "canonical" } });
    expect(await read(make(), "owner")).toMatchObject({
      data: { text: "preview" },
      visibility: "pending",
    });
  },
);
