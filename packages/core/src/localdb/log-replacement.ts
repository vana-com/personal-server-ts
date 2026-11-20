import { sha256 } from "@noble/hashes/sha2";
import { REPLICA_SOURCE_MAX_RECORD_JSON_BYTES } from "../replication/limits.js";
import {
  canonicalJsonChunks,
  operationWireChunks,
  primaryKeyValues,
  type LogKey,
  type LogOmission,
  type LogOperation,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import {
  openLogWorkspace,
  type StagingWorkspaceUnit,
  type WorkspaceRows,
} from "./workspace-consumer.js";
import { runtimeAdmission, setWorkspaceAuthority } from "./workspace.js";

const encoder = new TextEncoder();
export function operationBytes(op: WireOperation): number {
  let bytes = 0;
  for (const chunk of operationWireChunks(op))
    bytes += encoder.encode(chunk).length;
  return bytes;
}
/** Charge the retained operation representation separately from its short wire names. */
export function residentOperationBytes(op: LogOperation): number {
  let bytes = 0;
  for (const chunk of canonicalJsonChunks(op))
    bytes += encoder.encode(chunk).length;
  return bytes;
}
/** Project only fixed-width hashes, through the actual operation encoder.
 * Canonical-record reads construct fresh objects, so remembered references
 * are not reused. No encryption or body-sized output buffer is needed. */
export function publishedOperationBytes(
  op: LogOperation,
  target: number,
): number {
  if (op.kind !== "upsert") return operationBytes(op);
  let bytes = 0;
  for (const chunk of canonicalJsonChunks(op.value))
    bytes += encoder.encode(chunk).length;
  if (bytes <= target) return operationBytes(op);
  const { kind: _kind, value: _value, ...rest } = op;
  const hash = `0x${"0".repeat(64)}` as const;
  const onePiece = operationBytes({
    ...rest,
    kind: "upsert-ref",
    body: { bytes, sha256: "0".repeat(64), pieces: [hash] },
  });
  // All piece hashes have the same JSON encoding width. Count repeated
  // array entries without allocating a piece-count-sized placeholder list.
  return (
    onePiece +
    (Math.ceil(bytes / target) - 1) *
      (encoder.encode(JSON.stringify(hash)).length + 1)
  );
}

function fragmentDigest(value: unknown): string {
  const digest = sha256.create();
  for (const chunk of canonicalJsonChunks(value))
    digest.update(encoder.encode(chunk));
  return Array.from(digest.digest(), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
async function stageOmissionPages(
  unit: StagingWorkspaceUnit,
  omitted: readonly LogOmission[],
  stream: string,
  cutoff: { o: number; r: string } | null,
  published: boolean,
) {
  let page: WorkspaceRows["omissions"][] = [],
    bytes = 0;
  for (const row of omitted) {
    const entry = {
      ...row,
      stream,
      cutoff: cutoff!,
      fragment: published ? 1 : 0,
      published,
    };
    const size =
      encoder.encode(JSON.stringify(entry)).length +
      encoder.encode(JSON.stringify([stream, row.pkHash])).length;
    if (page.length > 0 && (page.length === 64 || bytes + size > 65536)) {
      await unit.stageOmissions(page);
      page = [];
      bytes = 0;
    }
    page.push(entry);
    bytes += size;
  }
  if (page.length > 0) await unit.stageOmissions(page);
}

/** One frozen window under the connection's publication admission. All source-
 * sized facts live in indexed workspace relations, not generator closures. */
export async function openReplacementPlan(
  deps: LocalSyncDeps,
  input: {
    connection: string;
    generation: number;
    keyCheck: string;
    expectedHead: string;
    creatingControl: boolean;
    stream: string;
    from: number;
    to: number;
    primaryKey: readonly string[];
    cutoff: { o: number; r: string } | null;
    target: number;
  },
) {
  const [meta] = await deps.db.query<{
    owner: string;
    device_id: string;
    network: string;
    created_at: number;
  }>("SELECT owner,device_id,network,created_at FROM db_meta WHERE id=1");
  if (!meta) throw new Error("replacement_database_identity");
  const binding = {
    owner: meta.owner,
    // One derivation for every workspace kind: the connection has one
    // authority row, and a differing value would fence the other kind's workspace.
    databaseIncarnation: JSON.stringify([
      meta.network,
      meta.device_id,
      meta.created_at,
    ]),
    connection: input.connection,
    generation: input.generation,
    keyCheck: input.keyCheck,
    expectedHead: input.expectedHead,
    operation: deps.newOp(),
    codecVersion: 1,
    ...(input.creatingControl ? { controlState: "absent" as const } : {}),
  };
  await setWorkspaceAuthority(deps.db, binding);
  const ws = await openLogWorkspace(deps.db, binding);
  const lease = await ws.acquire(
    6 * REPLICA_SOURCE_MAX_RECORD_JSON_BYTES +
      input.target * 2 +
      2 * 1024 * 1024,
  );
  try {
    await ws.freezeChanges(input.stream, input.from, input.to);
    if (input.cutoff) await ws.freezeMembership(input.stream, input.cutoff);
  } catch (error) {
    await lease.release();
    throw error;
  }
  return {
    binding,
    dispose: ws.cleanupReplacement,
    failure: ws.failure,
    async hasChanges() {
      const cursor = ws.changeCursor();
      try {
        const unit = await cursor.next(lease);
        if (!unit) return false;
        await unit.release();
        return true;
      } finally {
        await cursor.close();
      }
    },
    async admitKey(bytes: number) {
      await ws.admit(lease, bytes * 6 + input.target * 2 + 2 * 1024 * 1024);
    },
    async prepare(
      watermark: number,
      omitted: readonly LogOmission[],
      complete: boolean,
    ) {
      const unit = await ws.replayableUnit(
        "selection",
        fragmentDigest([watermark, complete, omitted]),
      );
      if (unit.state === "staging") {
        await stageOmissionPages(
          unit,
          omitted,
          input.stream,
          input.cutoff,
          false,
        );
        await unit.stage("publication", {
          stream: input.stream,
          watermark,
          complete: false,
          completesAfterPublish: complete,
          published: false,
          from: omitted[0]?.pkHash ?? null,
          to: omitted.at(-1)?.pkHash ?? null,
        });
        await unit.commit();
      }
    },
    async *changes() {
      const cursor = ws.changeRecordPages(
        input.stream,
        Math.min(input.target, 65536),
      );
      try {
        for (
          let unit = await cursor.next(lease);
          unit;
          unit = await cursor.next(lease)
        ) {
          try {
            for (const row of unit.value.records()) yield row;
          } finally {
            await unit.release();
          }
        }
      } finally {
        await cursor.close();
      }
    },
    omissionCount: ws.membershipCount,
    async *omissions() {
      const cursor = ws.membershipRecordPages(
        input.stream,
        Math.min(input.target, 65536),
      );
      try {
        for (
          let unit = await cursor.next(lease);
          unit;
          unit = await cursor.next(lease)
        ) {
          try {
            for (const row of unit.value.records()) {
              if (!row.record) throw new Error("workspace_record_incomplete");
              const key = primaryKeyValues(
                JSON.parse(row.record.body),
                input.primaryKey,
              ) as LogKey;
              yield { pkHash: row.pk, key } satisfies LogOmission;
            }
          } finally {
            await unit.release();
          }
        }
      } finally {
        await cursor.close();
      }
    },
    async release(finished = true) {
      await lease.release();
      if (finished) await runtimeAdmission.finish(deps.db, binding.operation);
    },
    /** Conservative durable receipt. Canonical completion is still committed
     * with the accepted watermark by the existing publication transaction. */
    async published(omitted: readonly LogOmission[], complete: boolean) {
      const receiptLease = await ws.acquire(128 * 1024 * 1024);
      let finished = false;
      try {
        const unit = await ws.replayableUnit(
          "publication",
          fragmentDigest([input.to, complete, omitted]),
        );
        if (unit.state === "staging") {
          await stageOmissionPages(
            unit,
            omitted,
            input.stream,
            input.cutoff,
            true,
          );
          const cursor = ws.cursor("publication");
          try {
            const row = await cursor.next(receiptLease);
            if (!row) throw new Error("workspace_selection_incomplete");
            const value = row.value.row;
            await row.release();
            await unit.stage("publication", {
              ...value,
              published: true,
              complete: value.completesAfterPublish,
            });
          } finally {
            await cursor.close();
          }
          await unit.commit();
        }
        finished = true;
      } finally {
        await receiptLease.release();
        if (finished) await runtimeAdmission.finish(deps.db, binding.operation);
      }
    },
  };
}
