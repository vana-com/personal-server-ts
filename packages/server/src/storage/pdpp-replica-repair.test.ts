import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

/**
 * A repair write of valid bytes over a blob whose published manifest is
 * malformed (size not a safe non-negative integer) must clear that manifest
 * in the same transaction. Readers veto on any malformed manifest, legacy
 * row or not (#438 1da8fee7), so otherwise the repair never takes effect.
 */

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-21T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const credential = "replica-secret";
const directories: string[] = [];
const closers: (() => void)[] = [];
afterEach(() => {
  for (const close of closers.splice(0)) close();
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});

const bytes = new TextEncoder().encode("attachment bytes");
const blobId = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const blob = {
  blobId,
  sha256: blobId,
  mimeType: "text/plain",
  sizeBytes: bytes.length,
};
const base = {
  owner: "owner",
  sourceId,
  connectionId: "conn_a",
  methodId: "collector",
  generation: 1,
};
const operations: ReplicaOperation[] = [
  {
    ...base,
    kind: "connection-register",
    revision: { counter: 1, writerId: "remote", operationId: "register" },
  },
  {
    ...base,
    kind: "blob-claim",
    blob,
    revision: { counter: 2, writerId: "remote", operationId: "claim" },
  },
  {
    ...base,
    kind: "upsert",
    revision: { counter: 3, writerId: "remote", operationId: "upsert" },
    declaration: binding,
    recordKey: "a",
    emittedAt: at,
    data: {
      id: "a",
      blob_ref: { blob_id: blobId, mime_type: "text/plain", size_bytes: 16 },
    },
    blobs: [blob],
  },
];

function device() {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-repair-"));
  directories.push(directory);
  const db = new Database(join(directory, "db.sqlite"));
  const store = createReplicaRecordStore(db);
  store.registerConnection({
    instance: "conn_a",
    sourceId,
    method: "collector",
    label: "A",
  });
  store.replication.beginBaseline({
    owner: "owner",
    declarations: [{ sourceId, binding }],
  });
  const receiver = createReplicaReceiver({
    db,
    store,
    owner: "owner",
    authenticate: (c: unknown) => (c === credential ? "owner" : undefined),
    declarations: () => declarations,
  });
  closers.push(() => db.open && store.close());
  const importWithBytes = () =>
    receiver.import({
      credential,
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: "owner",
        batchId: "batch",
        operations,
      },
      blobs: [{ blobId, bytes }],
    });
  const served = () =>
    (["owner", "grant"] as const).map((reader) => {
      const value = receiver.readStore({ reader }).getBlobBytes(blobId);
      return value ? Buffer.from(value).toString() : undefined;
    });
  const malformed = () =>
    db
      .prepare(
        "SELECT namespace, size_bytes FROM pdpp_binary_manifests WHERE blob_id=? AND NOT (typeof(size_bytes)='integer' AND size_bytes BETWEEN 0 AND 9007199254740991)",
      )
      .all(blobId);
  return { db, store, importWithBytes, served, malformed };
}
const text = Buffer.from(bytes).toString();

describe("repair clears a malformed manifest atomically", () => {
  for (const size of [-1, 1.5, 2 ** 53])
    for (const namespace of ["received", "canonical"] as const)
      it(`${namespace} manifest size ${size}: the repair write serves the bytes again`, () => {
        const d = device();
        d.importWithBytes();
        expect(d.served()).toEqual([text, text]);
        d.db
          .prepare(
            "INSERT OR REPLACE INTO pdpp_binary_manifests VALUES (?,?,?)",
          )
          .run(namespace, blobId, size);
        // The read side vetoes the malformed copy.
        expect(d.served()).toEqual([undefined, undefined]);
        if (namespace === "received") d.importWithBytes();
        else
          d.store.storeBlobBytesForInstance({
            instance: "conn_a",
            method: "collector",
            generation: 1,
            bytes,
            mimeType: "text/plain",
          });
        expect(d.malformed()).toEqual([]);
        expect(d.served()).toEqual([text, text]);
      });

  it("a repair that aborts leaves the malformed manifest in place", () => {
    const d = device();
    d.importWithBytes();
    d.db
      .prepare("INSERT OR REPLACE INTO pdpp_binary_manifests VALUES (?,?,?)")
      .run("received", blobId, -1);
    d.db.exec(
      "CREATE TEMP TRIGGER interrupt BEFORE INSERT ON pdpp_replica_received BEGIN SELECT RAISE(ABORT,'interrupt'); END",
    );
    expect(() => d.importWithBytes()).toThrow("interrupt");
    expect(d.malformed()).toEqual([{ namespace: "received", size_bytes: -1 }]);
  });
});
