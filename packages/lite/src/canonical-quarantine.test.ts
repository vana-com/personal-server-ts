import { expect, it } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { createLiteCanonicalStore } from "./canonical-store.js";
import { createFakeCanonicalPersistence } from "./test-support/canonical-persistence.js";

/**
 * Lite connection quarantine, owned by the write side: one predicate,
 * `isConnectionQuarantined`, over reconcile's whole blocking decision plus
 * the terminal-batch fact, and one write call, `quarantineConnection`, that
 * records that fact (contract v3.1 A, H, I).
 */

function device() {
  const adapter = createFakeCanonicalPersistence();
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
    });
  return { adapter, make };
}
type Store = ReturnType<typeof createLiteCanonicalStore>;
const envelope = (batchId: string, operations: unknown[]) => ({
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId,
  operations,
});
async function provision(store: Store) {
  await store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
}
/** A provisioned connection with one confirmed blob-backed row. */
async function confirmedBlobRow(
  make: () => Store,
  bytes = new TextEncoder().encode("quarantined blob"),
) {
  const { sha256 } = await import("viem");
  const store = make();
  await provision(store);
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
      for (let offset = 0; offset < bytes.length; offset += 128 * 1024)
        yield bytes.slice(offset, offset + 128 * 1024);
    })(),
  );
  await store.import({
    id: "confirmed",
    credential: "replica",
    envelope: envelope("confirmed", [
      registration,
      {
        ...identity,
        kind: "blob-claim",
        revision: { counter: 2, writerId: "device-a", operationId: "claim" },
        blob,
      },
      {
        ...upsert("a", 3),
        blobs: [blob],
        data: { id: "same-key", blob_ref: { blob_id: hash } },
      },
    ]),
    blobs: [{ stagingId, descriptor: blob }],
  });
  const collect = async (reader: "owner" | "grant") => {
    const parts: Uint8Array[] = [];
    for await (const part of make().readBlob(hash, { reader }))
      parts.push(part);
    return parts;
  };
  for (const reader of ["owner", "grant"] as const)
    expect(
      Uint8Array.from((await collect(reader)).flatMap((part) => [...part])),
    ).toEqual(bytes);
  return { store, collect, hash, bytes };
}
async function hiddenFromBoth(
  make: () => Store,
  collect: (r: "owner" | "grant") => Promise<Uint8Array[]>,
) {
  for (const reader of ["owner", "grant"] as const) {
    const fresh = make();
    const row = await fresh.readRecord(
      identity.connectionId,
      binding.stream,
      "same-key",
      { reader },
    );
    expect(!row || row.deleted).toBe(true);
    const page = await fresh.readConnectionPage(
      identity.connectionId,
      undefined,
      {
        reader,
      },
    );
    expect(page.rows.every((r) => r.deleted)).toBe(true);
    await expect(collect(reader)).rejects.toThrow("missing committed blob");
  }
}

it("a healthy provisioned connection is not quarantined", async () => {
  const { make } = device();
  await confirmedBlobRow(make);
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    false,
  );
});

it("A6 race: stops the next blob chunk when quarantine moves visibility", async () => {
  const { make } = device();
  const bytes = new Uint8Array(256 * 1024 + 7).fill(0x6d);
  const { store, hash } = await confirmedBlobRow(make, bytes);
  const readers = (["owner", "grant"] as const).map((reader) =>
    make().readBlob(hash, { reader })[Symbol.asyncIterator](),
  );

  for (const reader of readers) {
    const first = await reader.next();
    expect(first.done).toBe(false);
    expect(first.value).toHaveLength(128 * 1024);
  }

  await store.quarantineConnection({
    credential: "replica",
    connectionId: identity.connectionId,
    reason: "race test",
  });

  for (const reader of readers) {
    let nextError: unknown;
    try {
      await reader.next();
    } catch (error) {
      nextError = error;
    }
    expect(nextError).toMatchObject({
      message: "visibility changed during blob read",
    });
  }
});

it.each(["connection-delete", "delete", "connection-reset"] as const)(
  "A6 blob visibility: fresh read after %s requires a current reference",
  async (kind) => {
    const { make } = device();
    const { store, collect, bytes, hash } = await confirmedBlobRow(make);
    const operation =
      kind === "delete"
        ? {
            ...identity,
            kind,
            declaration: binding,
            recordKey: upsert("a", 3).recordKey,
            emittedAt: "2026-10-21T00:00:00.000Z",
            deletedAt: "2026-10-21T00:00:00.000Z",
            revision: {
              counter: 100,
              writerId: "device-a",
              operationId: "delete-row-review",
            },
          }
        : {
            ...identity,
            kind,
            ...(kind === "connection-reset"
              ? { generation: 2, previousGeneration: 1 }
              : {}),
            revision: {
              counter: 100,
              writerId: "device-a",
              operationId: "remove-review",
            },
          };
    await store.import({
      id: "review-remove",
      credential: "replica",
      envelope: envelope("review-remove", [operation]),
    });
    for (const reader of ["owner", "grant"] as const) {
      const row = await make().readRecord(
        identity.connectionId,
        binding.stream,
        upsert("a", 3).recordKey,
        { reader },
      );
      expect(!row || row.deleted).toBe(true);
      await expect(collect(reader)).rejects.toThrow("missing committed blob");
    }
    expect(bytes).toBeDefined();
    expect(hash).toBeTruthy();
  },
);

it("A6 blob visibility: keeps bytes while another live record references them", async () => {
  const { make } = device();
  const { store, collect, bytes, hash } = await confirmedBlobRow(make);
  const descriptor = {
    blobId: hash,
    sha256: hash,
    mimeType: "text/plain",
    sizeBytes: bytes.length,
  };
  await store.provisionConnection("connection-b", {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  await store.import({
    id: "second-live-reference",
    credential: "replica",
    envelope: envelope("second-live-reference", [
      {
        ...registration,
        connectionId: "connection-b",
        revision: {
          counter: 1,
          writerId: "device-a",
          operationId: "register-second-reference",
        },
      },
      {
        ...identity,
        connectionId: "connection-b",
        kind: "blob-claim",
        revision: {
          counter: 5,
          writerId: "device-a",
          operationId: "claim-second-reference",
        },
        blob: descriptor,
      },
      {
        ...upsert("b", 4),
        connectionId: "connection-b",
        recordKey: "other-key",
        blobs: [descriptor],
        data: { id: "other-key", blob_ref: { blob_id: hash } },
      },
    ]),
  });
  expect(
    await make().readRecord("connection-b", binding.stream, "other-key", {
      reader: "owner",
    }),
  ).toMatchObject({ deleted: false });
  const deletion = {
    ...identity,
    kind: "delete" as const,
    declaration: binding,
    recordKey: upsert("a", 3).recordKey,
    emittedAt: "2026-10-21T00:00:00.000Z",
    deletedAt: "2026-10-21T00:00:00.000Z",
    revision: {
      counter: 100,
      writerId: "device-a",
      operationId: "delete-original-review",
    },
  };
  await store.import({
    id: "delete-original-reference",
    credential: "replica",
    envelope: envelope("delete-original-reference", [deletion]),
  });
  for (const reader of ["owner", "grant"] as const) {
    const chunks = await collect(reader);
    expect(Uint8Array.from(chunks.flatMap((part) => [...part]))).toEqual(bytes);
  }
});

// The #438 lane's reproduction (3eaec57d, it.fails there): reconcile blocks
// the connection on a lifecycle-plan conflict, so the confirmed-blob gate must too.
it("a lifecycle conflict (generation-3 reset after generation 1, fresh operation ID) quarantines the connection, including confirmed blob bytes, after reopen", async () => {
  const { make } = device();
  const { store, collect } = await confirmedBlobRow(make);
  await store.import({
    id: "bad-reset",
    credential: "replica",
    envelope: envelope("bad-reset", [
      {
        ...identity,
        kind: "connection-reset",
        generation: 3,
        previousGeneration: 1,
        revision: {
          counter: 4,
          writerId: "device-a",
          operationId: "bad-reset",
        },
      },
    ]),
  });
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    true,
  );
  await hiddenFromBoth(make, collect);
});

// A binding conflict cancels deletion in the engine: evidence that names
// another binding is not about this connection.
it("deletion evidence that names another binding withdraws an unprovisioned connection instead of deleting it", async () => {
  const { make } = device();
  await make().import({
    id: "foreign-delete",
    credential: "replica",
    envelope: envelope("foreign-delete", [
      registration,
      {
        ...identity,
        methodId: "other",
        kind: "connection-delete",
        revision: { counter: 2, writerId: "device-a", operationId: "delete" },
      },
    ]),
  });
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    true,
  );
  await expect(provision(make())).rejects.toThrow(
    "retained connection source or method mismatch",
  );
});

it("quarantineConnection records the terminal fact for a provisioned connection and withdraws it in the same transaction, across reopen and retry", async () => {
  const { make } = device();
  const { collect } = await confirmedBlobRow(make);
  const before = await make().readConnectionPage(identity.connectionId);
  await expect(
    make().quarantineConnection({
      credential: "wrong",
      connectionId: identity.connectionId,
      reason: "finalized_conflict",
    }),
  ).rejects.toThrow();
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    false,
  );
  await make().quarantineConnection({
    credential: "replica",
    connectionId: identity.connectionId,
    reason: "finalized_conflict",
  });
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    true,
  );
  await hiddenFromBoth(make, collect);
  // The view revision moved, so an open page cursor expires.
  if (before.after !== undefined)
    await expect(
      make().readConnectionPage(identity.connectionId, before.after),
    ).rejects.toThrow("expired");
  // Absorbing: a retry and a reopen do not lift it.
  await make().retry({ credential: "replica" });
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    true,
  );
  await hiddenFromBoth(make, collect);
});

it("an interrupted quarantineConnection leaves nothing behind", async () => {
  const { adapter, make } = device();
  const { collect } = await confirmedBlobRow(make);
  adapter.crashAt("before-commit");
  await expect(
    make().quarantineConnection({
      credential: "replica",
      connectionId: identity.connectionId,
      reason: "finalized_conflict",
    }),
  ).rejects.toThrow("interrupted");
  expect(await make().isConnectionQuarantined(identity.connectionId)).toBe(
    false,
  );
  expect(await collect("grant")).toHaveLength(1);
});

it.each(["connection-delete", "blob-claim"] as const)(
  "refuses local %s mutations after connection quarantine without changing canonical state",
  async (kind) => {
    const { adapter, make } = device();
    const store = make();
    await provision(store);
    if (kind === "blob-claim")
      await store.import({
        id: "registration",
        credential: "replica",
        envelope: envelope("registration", [registration]),
      });
    await store.quarantineConnection({
      credential: "replica",
      connectionId: identity.connectionId,
      reason: "finalized_conflict",
    });
    const before = structuredClone({
      rows: adapter.disk.rows,
      blobs: adapter.disk.blobs,
    });
    const operation =
      kind === "connection-delete"
        ? { ...identity, kind }
        : {
            ...identity,
            kind,
            blob: {
              blobId: `sha256:${"c".repeat(64)}`,
              sha256: `sha256:${"c".repeat(64)}`,
              mimeType: "application/octet-stream",
              sizeBytes: 2 * 1024 * 1024,
            },
          };

    await expect(
      store.commitLocal(`quarantined-${kind}`, [operation]),
    ).rejects.toThrow("local connection is quarantined");
    expect(adapter.disk.rows).toEqual(before.rows);
    expect(adapter.disk.blobs).toEqual(before.blobs);
  },
);
