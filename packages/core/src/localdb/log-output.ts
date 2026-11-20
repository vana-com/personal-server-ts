// Where the ciphertext of a compaction lives between its encryption and its PUT.
//
// A snapshot is source-sized. Holding every part until upload made the output
// the largest retained object of a publish (design gap 3). Here the producer
// seals each part as one disk value in the compaction's workspace and stages a
// descriptor row; the plan and the candidate carry the workspace, never bytes.
// One consumer then reads one sealed value at a time, PUTs it, and receipts it.
//
// Phases (workspace.ts): collect -> folded -> sealed (every output staged) ->
// ready (every output has an upload receipt) -> sent (durable BEFORE the
// registry request leaves) -> finished | aborted -> clean. `settleSent` is the
// only way out of `sent`, and it decides from heads, never from a local claim.
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { LocalSyncDeps } from "./deps.js";
import type { ByteLease, WorkspaceBinding } from "./workspace-capability.js";
import type { openLogWorkspace } from "./workspace-consumer.js";
import {
  runtimeAdmission,
  cleanableOperation,
  cleanupWorkspaceOne,
  sentOperations,
  settleSent,
  type SentObservation,
  type SentSettlement,
} from "./workspace.js";

export type LogWorkspace = Awaited<ReturnType<typeof openLogWorkspace>>;

/** What a plan or candidate holds in place of ciphertext: a handle to the
 * workspace whose `outputs` rows are the objects, and how many there are. */
export interface OutputSet {
  readonly ws: LogWorkspace;
  readonly count: number;
}

const hex = (bytes: Uint8Array) => bytesToHex(sha256(bytes));
const outputUnit = (name: string) => `output:${name}`;
const uploadUnit = (name: string) => `upload:${name}`;
/** The runtime lease the upload loop holds: one object plus its read frame. */
const UPLOAD_LEASE_BYTES = 128 * 1024 * 1024;

function boundedValues(deps: LocalSyncDeps) {
  const values = deps.db.boundedValues;
  if (!values || values.version !== 1 || !deps.db.info.persistent)
    throw new Error("workspace_requires_bounded_values");
  return values;
}

/**
 * Seal one object's ciphertext as a disk value and stage its descriptor in one
 * unit receipt. The caller drops its buffer after this returns, so resident
 * output bytes are one part however many parts the snapshot has. A name that
 * is already staged keeps its first ciphertext: the unit digest is the name,
 * not the bytes, because two encryptions of one object differ.
 */
export interface OutputProducer {
  put(name: string, cipher: Uint8Array): Promise<void>;
  readonly count: number;
}
export function outputProducer(
  deps: LocalSyncDeps,
  ws: LogWorkspace,
  lease: ByteLease,
): OutputProducer {
  const values = boundedValues(deps);
  const binding = ws.binding;
  const chunk = Math.min(
    65536,
    Math.floor((values.frameCapacityBytes - 2048) / 6),
  );
  let count = 0;
  return {
    get count() {
      return count;
    },
    async put(name, cipher) {
      // A restarted producer meets units it already receipted, not at the
      // current end of the log: it checks for the receipt before it asks for a
      // staging unit at the next position.
      if (await receipted(deps, ws.binding, outputUnit(name), name)) return;
      const unit = await ws.unit(outputUnit(name), name, await ws.position());
      if (unit.state === "receipted") return;
      const writer = await values.begin(
        binding,
        cipher.length,
        hex(cipher),
        "binary",
      );
      for (let at = 0; at < cipher.length; at += chunk)
        await values.append(writer, at, cipher.subarray(at, at + chunk), lease);
      const token = await values.seal(writer, lease);
      await unit.stage("outputs", { objectKey: name, value: token });
      await unit.commit();
      count++;
    },
  };
}

/** Every output is staged: the producer is done. */
export async function sealOutputs(ws: LogWorkspace): Promise<void> {
  await ws.transition("folded", "sealed");
}

/**
 * The upload loop. Pages `outputs` by keyset cursor; for each object without an
 * upload receipt it reads the one sealed value into one buffer, PUTs it, and
 * commits the receipt before reading the next. Slow storage therefore holds one
 * object, and the producer (which finished first) cannot run ahead of it. An
 * object whose receipt was lost is put again from the same sealed bytes; the
 * bytes are never re-encrypted. Ends with `sealed -> ready`, whose guard checks
 * that every output has its receipt.
 */
export async function uploadOutputs(
  deps: LocalSyncDeps,
  outputs: OutputSet,
  put: (name: string, bytes: Uint8Array) => Promise<void>,
): Promise<void> {
  const { ws } = outputs;
  const values = boundedValues(deps);
  if ((await phaseOf(deps, ws.binding)) === "sealed") {
    const lease = await ws.acquire(UPLOAD_LEASE_BYTES);
    const cursor = ws.cursor("outputs");
    try {
      for (;;) {
        const next = await cursor.next(lease);
        if (!next) break;
        const row = next.value.row;
        await next.release();
        const token = row.value;
        // A committed receipt, never a staged row: `lookup` also reads the
        // staging of a unit whose commit a crash cut, and that unit is not done.
        if (
          await receipted(
            deps,
            ws.binding,
            uploadUnit(row.objectKey),
            token.sha256,
          )
        )
          continue;
        const bytes = new Uint8Array(token.bytes);
        for (let at = 0; at < bytes.length;) {
          const unit = await values.read(token, at, lease);
          try {
            bytes.set(unit.value, at);
            at += unit.value.length;
          } finally {
            await unit.release();
          }
        }
        await put(row.objectKey, bytes);
        const unit = await ws.unit(
          uploadUnit(row.objectKey),
          token.sha256,
          await ws.position(),
        );
        if (unit.state === "receipted") continue;
        await unit.stage("uploads", { objectKey: row.objectKey, value: token });
        await unit.commit();
      }
    } finally {
      await cursor.close();
      await lease.release();
      await runtimeAdmission.finish(deps.db, ws.binding.operation);
    }
    await ws.transition("sealed", "ready");
  }
}

async function receipted(
  deps: LocalSyncDeps,
  binding: WorkspaceBinding,
  unit: string,
  digest: string,
): Promise<boolean> {
  const row = (
    await deps.db.query<{ digest: string }>(
      "SELECT digest FROM workspace_receipts WHERE operation=? AND unit=?",
      [binding.operation, unit],
    )
  )[0];
  if (row && row.digest !== digest)
    throw new Error("workspace_receipt_conflict");
  return row !== undefined;
}

async function phaseOf(deps: LocalSyncDeps, binding: WorkspaceBinding) {
  return (
    await deps.db.query<{ phase: string }>(
      "SELECT phase FROM workspaces WHERE operation=?",
      [binding.operation],
    )
  )[0]?.phase;
}

/** `ready -> sent`, durable before the registry request leaves. */
export async function sendOutputs(
  outputs: OutputSet,
  position: number,
  oldHead: string | null,
  candidateHead: string,
): Promise<void> {
  await outputs.ws.markSent(position, oldHead, candidateHead);
}

/** Close a workspace that reached a terminal phase: page its rows away. */
async function cleanOutputs(deps: LocalSyncDeps, operation: string) {
  while (await cleanupWorkspaceOne(deps.db, operation)) {
    /* one indexed row or value per step */
  }
}

/** Settle a sent candidate from what a caller saw, then clean it if it ended. */
export async function settleOutputs(
  deps: LocalSyncDeps,
  outputs: OutputSet,
  observation: SentObservation,
): Promise<SentSettlement> {
  const settled = await outputs.ws.settleSent(observation);
  if (settled !== "sent")
    await cleanOutputs(deps, outputs.ws.binding.operation);
  return settled;
}

/** The registry refused the request itself (a definite reply, not a read). */
export async function refuseOutputs(
  deps: LocalSyncDeps,
  outputs: OutputSet,
): Promise<void> {
  if ((await phaseOf(deps, outputs.ws.binding)) === "sent")
    await settleOutputs(deps, outputs, { kind: "refused" });
  else await releaseOutputs(deps, outputs);
}

/**
 * Let go of a workspace that did not reach the registry: discard and clean it.
 * A sent workspace is left alone; only a head observation may end it.
 */
export async function releaseOutputs(
  deps: LocalSyncDeps,
  outputs: OutputSet,
): Promise<void> {
  const phase = await phaseOf(deps, outputs.ws.binding);
  if (phase === undefined || phase === "sent") return;
  if (phase !== "aborted" && phase !== "finished" && phase !== "clean")
    await outputs.ws.discard();
  await cleanOutputs(deps, outputs.ws.binding.operation);
}

/**
 * Settle the sent workspaces of a connection that no live candidate holds (a
 * process that stopped between its request and its reply), then page away some
 * of the finished and aborted ones. A candidate whose row the local log already
 * holds at its position was taken by the registry; any other is judged by one
 * read of the registry's head.
 */
export async function settleAbandonedOutputs(
  deps: LocalSyncDeps,
  connectionId: string,
  scope: string,
  logRefs: readonly { position: number; dataHash: string }[],
  live: ReadonlySet<string>,
  cleanupBudget = 256,
): Promise<void> {
  const sent = (await sentOperations(deps.db, connectionId)).filter(
    (s) => !live.has(s.operation),
  );
  let seen: SentObservation | undefined;
  for (const s of sent) {
    const own = logRefs.some(
      (r) => r.position === s.position && r.dataHash === s.candidateHead,
    );
    if (!own && !seen) {
      const read = await deps.registry.read(scope);
      seen = {
        kind: "head",
        version: read.found ? Number(read.version) : 0,
        head: read.found ? read.dataHash : null,
      };
    }
    const settled = await settleSent(
      deps.db,
      s.operation,
      own
        ? { kind: "head", version: s.position, head: s.candidateHead }
        : seen!,
    );
    if (settled !== "sent") await cleanOutputs(deps, s.operation);
  }
  for (let i = 0; i < cleanupBudget; i++) {
    const operation = await cleanableOperation(deps.db, connectionId);
    if (operation === null || live.has(operation)) return;
    await cleanupWorkspaceOne(deps.db, operation);
  }
}
