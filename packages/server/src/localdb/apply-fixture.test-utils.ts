/**
 * A registry, a blob store and an author for Node composition and read tests.
 *
 * `head` is the other device of the owner: it collects the values as a full
 * run and publishes them through the connection log, with the real publisher
 * (a real database, the real intake, the real batch commit), so what the
 * device under test reads is what a real remote device wrote.
 */
import { endRequest } from "@opendatalabs/personal-server-ts-core/test-utils";
import { afterEach } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
  streamScope,
  type ControlRead,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import { createMemoryStreamSyncBlobs } from "../../../core/src/stream-sync/index.js";
import type {
  RegistryBatchPolicy,
  RegistryBatchResult,
  RegistryBatchRow,
  SignedRegistryBatch,
  StreamSyncKeyPorts,
  StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openLogTestDatabase } from "./log-database.test-utils.js";

const authorDrivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of authorDrivers.splice(0)) await db.close();
});

export async function remoteFixture(
  keys: StreamSyncKeyPorts,
  connector = "fixture-source",
  ns = "",
) {
  const keyCheck = await deriveKeyCheck((m) => keys.namespaceHmac(m));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const reads = new Map<string, ControlRead>();
  const blobs = new Map<string, Uint8Array>();
  const control = controlScope(connector, ns);
  const setControl = (generation: number, deleted = false) =>
    reads.set(control, {
      found: true,
      version: generation,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      deleted,
    });
  setControl(1);
  const versionOf = (scope: string) => {
    const row = reads.get(scope);
    return row?.found ? row.version : 0;
  };
  // The bounds the gateway derives and advertises in `Batch-Policy`.
  const policy: RegistryBatchPolicy = {
    rows: 31,
    requires: 1952,
    bytes: 3_606_546,
  };
  const registry: StreamSyncRegistry = {
    batchPolicy: () => policy,
    readBatchPolicy: async () => policy,
    read: async (scope) => reads.get(scope) ?? { found: false },
    listControlRows: async () =>
      [...reads]
        .filter(([scope]) => scope === control)
        .map(([scope, read]) => ({ scope, read })),
    listStreamRows: async (key) =>
      [...reads]
        .filter(([scope]) => key === connector && scope !== control)
        .map(([scope, read]) => ({ scope, read })),
    listOwnerRows: async () =>
      [...reads].map(([scope, read]) => ({ scope, read })),
    post: async (post) => {
      if (String(versionOf(post.scope) + 1) !== post.expectedVersion)
        return {
          kind: "conflict",
          latestVersion: String(versionOf(post.scope)),
        };
      reads.set(post.scope, {
        found: true,
        version: versionOf(post.scope) + 1,
        dataHash: post.dataHash,
        metadataHash: post.metadataHash,
        deleted: false,
      });
      return { kind: "committed" };
    },
    /**
     * The gateway's batch route: one all-or-nothing transaction. A row that
     * loses refuses the request; the conditions are judged after the writes.
     */
    postBatch: async (request: SignedRegistryBatch) => {
      const lost = request.rows.map((row) => {
        const prior = reads.get(row.scope);
        const fence = row.expectedHeadDataHash;
        return (
          String(versionOf(row.scope) + 1) !== row.expectedVersion ||
          (fence !== undefined &&
            (!prior?.found ||
              prior.dataHash.toLowerCase() !== fence.toLowerCase()))
        );
      });
      if (lost.some(Boolean))
        return {
          kind: "refused",
          rows: request.rows.map((row, at): RegistryBatchRow => {
            if (!lost[at]) return { kind: "not_written" };
            const prior = reads.get(row.scope);
            return {
              kind: "conflict",
              latestVersion: String(versionOf(row.scope)),
              latestDataHash: prior?.found ? prior.dataHash : null,
            };
          }),
        } satisfies RegistryBatchResult;
      const before = new Map(reads);
      for (const row of request.rows)
        reads.set(row.scope, {
          found: true,
          version: versionOf(row.scope) + 1,
          dataHash: row.dataHash,
          metadataHash: row.metadataHash,
          deleted: row.dataHash.toLowerCase() === hashes.tombstoneData,
        });
      for (const need of request.requires) {
        const row = reads.get(need.scope);
        const reason = !row?.found
          ? ("absent" as const)
          : String(row.version) !== need.expectedVersion
            ? ("version-mismatch" as const)
            : need.expectedDataHash !== undefined &&
                row.dataHash.toLowerCase() !==
                  need.expectedDataHash.toLowerCase()
              ? ("data-hash-mismatch" as const)
              : undefined;
        if (reason === undefined) continue;
        reads.clear();
        for (const [scope, read] of before) reads.set(scope, read);
        return {
          kind: "precondition_failed",
          failure: {
            scope: need.scope,
            reason,
            latestVersion: row?.found ? String(row.version) : null,
            deleted: false,
          },
        } satisfies RegistryBatchResult;
      }
      return { kind: "committed" } satisfies RegistryBatchResult;
    },
  };
  const storage = {
    governor: createMemoryStreamSyncBlobs().governor,
    get: async (key: string) => blobs.get(key) ?? null,
    exists: async (key: string) => blobs.has(key),
    put: async (key: string, bytes: Uint8Array) => {
      blobs.set(key, bytes);
    },
  };

  // The author: another device of the owner, made on the first `head`.
  const declared = new Map<string, readonly string[]>();
  let author: Awaited<ReturnType<typeof createAuthor>> | undefined;
  async function createAuthor() {
    const db = await openLocalDb(await openLogTestDatabase(), {
      owner: `0x${"22".repeat(20)}`,
      network: "test",
      deviceId: "remote-author",
    });
    authorDrivers.push(db);
    let op = 0;
    const sync = createLocalSync(
      {
        db,
        queue: connectionQueue(),
        registry,
        blobs: storage,
        keys,
        ownerAddress: `0x${"22".repeat(20)}`,
        signer: { signAddData: async () => "0x00" },
        logger: { info() {}, warn() {} },
        now: () => 100,
        newOp: () => `author-${++op}`,
      },
      {
        resolveArtifact: () => ({
          connector,
          version: "1",
          streams: [...declared].map(([name, primaryKey]) => ({
            name,
            primaryKey: [...primaryKey],
            coverageStrategy: "full_inventory" as const,
            semantics: "mutable_state" as const,
          })),
        }),
      },
    );
    return { sync, runs: 0 };
  }

  /**
   * Publish `values` as the whole of `stream`, observed at `options.o`: one
   * full run, then one cycle that writes the log.
   */
  async function head(
    stream: string,
    values: readonly JsonObject[],
    options: { o?: number; primaryKey?: string[] } = {},
  ) {
    declared.set(stream, options.primaryKey ?? ["id"]);
    author ??= await createAuthor();
    const runId = `author-run-${++author.runs}`;
    const { sync } = author;
    await sync.intake.begin(runId, {
      connector,
      artifactDigest: connector,
      wantFull: true,
      join: true,
      observedAt: options.o ?? 100,
      owner: { address: `0x${"22".repeat(20)}`, leaseId: null },
    });
    if (values.length > 0)
      await sync.intake.batch(runId, {
        batch: 0,
        records: values.map((data) => ({ stream, data })),
      });
    await sync.intake.end(
      runId,
      endRequest({
        lastBatch: values.length > 0 ? 0 : -1,
        streams: [stream],
        live: values.length > 0 ? [stream] : [],
        provenFullStreams: [stream],
      }),
    );
    const report = await sync.cycle();
    const failed = report.connections.find((c) => c.error !== null);
    if (failed) throw new Error(`fixture author cycle failed: ${failed.error}`);
    return { scope: streamScope(connector, ns, stream) };
  }
  return { registry, storage, reads, blobs, head, setControl, hashes, control };
}
