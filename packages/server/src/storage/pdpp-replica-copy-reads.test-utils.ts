import Database from "better-sqlite3";
import { afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  replicaCopyKey,
  type Hex,
} from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { replicaChainCommitment } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  binding,
  registration,
  upsert,
  identity,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

const closers: (() => void)[] = [];
afterEach(() => {
  while (closers.length) closers.pop()!();
});
const hex = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as Hex;

export type ReplicaTestCopy = ReturnType<typeof makeCopy>;
export interface CopyReadFixture {
  readonly db: Database.Database;
  readonly store: ReturnType<typeof createSqliteRecordStore>;
  readonly receiver: ReturnType<typeof createReplicaReceiver>;
  reopen(): void;
  copy: typeof makeCopy;
  stage(
    copy: ReplicaTestCopy,
    blobs?: { blobId: string; bytes: Uint8Array }[],
  ): ReturnType<ReturnType<typeof createReplicaReceiver>["copies"]["stage"]>;
  prove(copy: ReplicaTestCopy, version?: string, blockNumber?: bigint): void;
}

function makeCopy(
  text: string,
  seed: number,
  operations?: ReplicaOperation[],
  batch = "conflict",
) {
  const record = {
    ...upsert(`record-${text}`, seed + 10),
    data: { id: "a", text },
    recordKey: "a",
  };
  const envelope = {
    format: "vana-pdpp-replica" as const,
    version: 1 as const,
    owner: identity.owner,
    batchId: batch,
    operations: operations ?? [registration, record],
  };
  const fragments = [{ dataHash: hex(seed), metadataHash: hex(seed + 1000) }];
  const commitment = replicaChainCommitment(
    fragments[0].dataHash,
    fragments[0].metadataHash,
  ) as Hex;
  return {
    id: canonicalJson(["writer", batch]),
    writer: "writer",
    batch,
    sequence: 1,
    previous: null,
    envelope,
    envelopeDigest: `sha256:${createHash("sha256").update(canonicalJson(envelope)).digest("hex")}`,
    fragments,
    copyKey: replicaCopyKey([commitment]),
    commitment,
    record,
  };
}

export function copyReadFixture(
  options: { declarations?: MergeContext["declarations"] } = {},
): CopyReadFixture {
  const declarations = options.declarations ?? [
    { sourceId: identity.sourceId, binding, validateData: () => true },
  ];
  const root = mkdtempSync(join(tmpdir(), "copy-reads-"));
  const path = join(root, "db.sqlite");
  let db = new Database(path);
  let store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: identity.connectionId,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "copy test",
  });
  store.replication.beginBaseline({
    owner: identity.owner,
    declarations: [...declarations],
  });
  const open = () =>
    createReplicaReceiver({
      db,
      store,
      owner: identity.owner,
      enabled: true,
      visibilityPolicy: { owner: "include-pending", grant: "include-pending" },
      authenticate: () => identity.owner,
      declarations: () => declarations,
    });
  let receiver = open();
  const f: CopyReadFixture = {
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    get receiver() {
      return receiver;
    },
    reopen() {
      store.close();
      db = new Database(path);
      store = createSqliteRecordStore(db);
      receiver = open();
    },
    copy: makeCopy,
    stage(
      copy: ReplicaTestCopy,
      blobs?: { blobId: string; bytes: Uint8Array }[],
    ) {
      return receiver.copies.stage({ credential: "test", copy, blobs });
    },
    prove(copy: ReplicaTestCopy, version = "1", blockNumber = 100n) {
      receiver.copies.recordFact({
        credential: "test",
        id: copy.id,
        scope: `${copy.id}#0`,
        fragmentIndex: 0,
        fact: {
          chainId: 1,
          registry: hex(123),
          owner: identity.owner,
          currentVersion: version,
          status: "Active",
          commitment: copy.commitment,
          blockNumber,
          blockHash: hex(Number(blockNumber)),
          eligible: true,
        },
      });
    },
  };
  closers.push(() => {
    if (db.open) store.close();
    rmSync(root, { recursive: true, force: true });
  });
  return f;
}
