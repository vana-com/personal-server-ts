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
async function confirmedBlobRow(make: () => Store) {
  const { sha256 } = await import("viem");
  const store = make();
  await provision(store);
  const bytes = new TextEncoder().encode("quarantined blob");
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
    expect(await collect(reader)).toEqual([bytes]);
  return { store, collect };
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
