import { afterEach, expect, it } from "vitest";
import { sha256 } from "viem";
import {
  REPLICA_COPY_MIGRATION,
  replicaCopies,
  type StagedCopy,
} from "@opendatalabs/personal-server-ts-core/replication/copies";
import type { Hex } from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { replicaChainCommitment } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import { runEffectAsync } from "@opendatalabs/personal-server-ts-core/replication/effects";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  LITE_REPLICA_SQL_BYTES,
  type LiteReplicaTransaction,
} from "@opendatalabs/personal-server-ts-lite";
import { createSqliteLiteReplicaPersistence } from "./lite-replica-sqlite.test-utils.js";

/**
 * Core copy custody (`core/replication/copies.ts`) over the phone's bounded
 * SQL bridge: every call carries and returns at most LITE_REPLICA_SQL_BYTES.
 */

const opened: { close(): void }[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) store.close();
});

const hex = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as Hex;

it("stages and promotes a copy whose blob descriptors are above one phone SQL call", async () => {
  const native = createSqliteLiteReplicaPersistence();
  opened.push(native);
  native.db.exec(REPLICA_COPY_MIGRATION);
  const imported: StagedCopy["blobs"][] = [];
  const shown: string[] = [];
  const released: string[][] = [];
  const copies = replicaCopies<LiteReplicaTransaction>({
    owner: "owner",
    *importEnvelope(_envelope, blobs) {
      imported.push(blobs);
    },
    *quarantineConnection() {},
    preview: {
      *show(_id, _envelope, blobsJson) {
        shown.push(blobsJson);
      },
      *hide() {},
    },
    *releaseBytes(_id, blobIds) {
      released.push([...blobIds]);
    },
    savepoint: (effect) => effect,
    now: () => 0,
  });
  const run = <T>(
    effect: Parameters<typeof runEffectAsync<T, LiteReplicaTransaction>>[0],
  ) => native.port.transaction((tx) => runEffectAsync(effect, tx));

  // A batch of many small blobs: its descriptors alone exceed one call.
  const blobs = Array.from({ length: 14_000 }, (_, index) => ({
    blobId: `sha256:${sha256(new TextEncoder().encode(`blob ${index}`)).slice(2)}`,
    size: index,
  }));
  expect(new TextEncoder().encode(canonicalJson(blobs)).length).toBeGreaterThan(
    LITE_REPLICA_SQL_BYTES,
  );
  const fragment = { dataHash: hex(1), metadataHash: hex(2) };
  const copy: StagedCopy = {
    id: canonicalJson(["writer", "batch"]),
    writer: "writer",
    batch: "batch",
    sequence: 1,
    previous: null,
    envelopeDigest: `sha256:${"e".repeat(64)}`,
    envelope: {
      format: "vana-pdpp-replica",
      version: 1,
      owner: "owner",
      batchId: "batch",
      operations: [],
    },
    fragments: [fragment],
    blobs,
  };
  const staged = await run(copies.stage(copy, { attempts: 0, budget: 1 }));
  expect(staged.copyKey).toBeDefined();
  // The single pending copy is previewed with every descriptor.
  expect(JSON.parse(shown.at(-1)!)).toEqual(blobs);

  await run(
    copies.recordFact({
      id: copy.id,
      scope: `${copy.id}#0`,
      fragmentIndex: 0,
      fact: {
        chainId: 1,
        registry: hex(0xabc),
        owner: "owner",
        version: "1",
        currentVersion: "1",
        status: "Active",
        commitment: replicaChainCommitment(
          fragment.dataHash,
          fragment.metadataHash,
        ) as Hex,
        blockNumber: 101n,
        blockHash: hex(0xb10c),
        eligible: true,
      },
    }),
  );
  expect(
    await run(copies.promote({ id: copy.id, copyKey: staged.copyKey })),
  ).toMatchObject({ kind: "promoted", replay: false });
  expect(imported).toEqual([blobs]);
  expect(released).toEqual([blobs.map((blob) => blob.blobId)]);
}, 60_000);
