import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import {
  canonicalJson,
  followMeta,
  primaryKeyValues,
  stampAfter,
  PART_LIMIT_BYTES,
  type JsonObject,
  type LogEntry,
  type WireEntry,
  type WireOperation,
  type LogStreamMeta,
  type WireSegment,
  type WireSnapshotPart,
  type LogUpsertByRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import {
  openLogWorkspace,
  foldCellKey,
  type WorkspaceFoldCell,
} from "./workspace-consumer.js";
import {
  runtimeAdmission,
  checkLease,
  setWorkspaceAuthority,
} from "./workspace.js";
import { recordWorkspaceFailure } from "./workspace-failure.js";
import type { ValueToken } from "./workspace-capability.js";
import { fetchBody } from "./log-bodies.js";

const encoder = new TextEncoder(),
  decoder = new TextDecoder("utf-8", { fatal: true });
const digest = (bytes: Uint8Array) => bytesToHex(sha256(bytes));
/** One verified wire unit and one record. The host coefficients remain measurement work. */
const FOLD_LEASE_BYTES = 128 * 1024 * 1024;

export async function openDiskFold(
  deps: LocalSyncDeps,
  connection: string,
  keyCheck: string,
  head: string,
  expectedGeneration: number,
) {
  const values = deps.db.boundedValues;
  if (!values || values.version !== 1 || !deps.db.info.persistent)
    throw new Error("workspace_requires_bounded_values");
  if (values.supportsBorrowedSeal !== true)
    throw new Error("workspace_requires_borrowed_seal");
  const [identity] = await deps.db.query<{
    owner: string;
    device_id: string;
    network: string;
    created_at: number;
  }>("SELECT owner,device_id,network,created_at FROM db_meta WHERE id=1");
  const [control] = await deps.db.query<{
    generation: number;
    control_version: number;
  }>(
    "SELECT generation,control_version FROM connections WHERE connection_id=?",
    [connection],
  );
  if (!identity || !control) throw new Error("workspace_missing_connection");
  if (control.generation !== expectedGeneration)
    throw new Error("workspace_stale_generation");
  const binding = {
    owner: identity.owner,
    databaseIncarnation: JSON.stringify([
      identity.network,
      identity.device_id,
      identity.created_at,
    ]),
    connection,
    generation: control.generation,
    keyCheck,
    operation: deps.newOp(),
    expectedHead: head,
    codecVersion: 1,
  };
  // No decoded input exists before runtime-wide admission.
  await runtimeAdmission.enqueue(deps.db, binding.operation);
  // Wait for the one lease. No caller holds a lease here (compaction and
  // rebase open the fold first; the upload loop's lease ends before any other
  // fold starts), so the wait cannot be on itself.
  const lease = await runtimeAdmission.acquireWaiting(
    binding.operation,
    FOLD_LEASE_BYTES,
  );
  let ws: Awaited<ReturnType<typeof openLogWorkspace>>;
  try {
    await setWorkspaceAuthority(deps.db, binding);
    ws = await openLogWorkspace(deps.db, binding);
  } catch (error) {
    await lease.release();
    throw error;
  }
  const fail = (error: Error) =>
    recordWorkspaceFailure(deps.db, binding, "fold", "admission", error);
  async function admitRecord(bytes: number) {
    try {
      checkLease(
        lease,
        binding.operation,
        bytes * 4 + 2 * PART_LIMIT_BYTES + 2 * 1024 * 1024,
      );
    } catch {
      return fail(new Error("workspace_record_admission"));
    }
  }
  async function store(bytes: Uint8Array): Promise<ValueToken> {
    await admitRecord(bytes.length);
    const writer = await values!.begin(
      binding,
      bytes.length,
      digest(bytes),
      "utf8",
    );
    const chunk = Math.min(
      65536,
      Math.floor((values!.frameCapacityBytes - 2048) / 6),
    );
    for (let at = 0; at < bytes.length; at += chunk)
      await values!.append(writer, at, bytes.subarray(at, at + chunk), lease);
    return values!.seal(writer, lease);
  }
  async function read(token: ValueToken): Promise<unknown> {
    checkLease(
      lease,
      binding.operation,
      token.bytes * 4 + 2 * PART_LIMIT_BYTES + 2 * 1024 * 1024,
    );
    const bytes = new Uint8Array(token.bytes);
    for (let at = 0; at < bytes.length;) {
      const unit = await values!.read(token, at, lease);
      try {
        bytes.set(unit.value, at);
        at += unit.value.length;
      } finally {
        await unit.release();
      }
    }
    return JSON.parse(decoder.decode(bytes));
  }
  const lookup = (unit: string, stream: string, pkHash: string) =>
    ws.lookup(unit, "fold", foldCellKey(stream, pkHash), lease);
  async function ingest(
    unitId: string,
    hash: string,
    previous: number,
    input: WireSegment | WireSnapshotPart,
    scope: string,
  ) {
    const unit = await ws.unit(unitId, hash, previous);
    if (unit.state === "receipted") return;
    const staged = unit;
    // This directory belongs only to the current bounded wire unit.
    const primaryKeys = new Map(
      input.streams.map((meta) => [meta.stream, meta.primaryKey]),
    );
    for (const meta of input.streams) {
      // A unit that names a stream without a cursor leaves the one before it.
      const earlier = await ws.lookup(
        unitId,
        "streams",
        foldCellKey(meta.stream),
        lease,
      );
      const next = followMeta(
        earlier ? ((await read(earlier.metadata)) as LogStreamMeta) : undefined,
        meta,
      );
      await staged.stage("streams", {
        stream: meta.stream,
        metadata: await store(encoder.encode(canonicalJson(next))),
      });
    }
    async function deletion(
      stream: string,
      pkHash: string,
      key: WorkspaceFoldCell["key"],
      stamp: NonNullable<WorkspaceFoldCell["deletion"]>["stamp"],
      explicit: boolean,
    ) {
      const c = (await lookup(unitId, stream, pkHash)) ?? {
        stream,
        pkHash,
        key,
        upsert: null,
        deletion: null,
      };
      const d = c.deletion;
      if (
        !d ||
        stampAfter(stamp, d.stamp) ||
        (explicit && !d.explicit && !stampAfter(d.stamp, stamp))
      )
        await staged.stage("fold", {
          ...c,
          key,
          deletion: { stamp, explicit, key },
        });
    }
    const operations: readonly (WireOperation | WireEntry)[] =
      "operations" in input ? input.operations : input.entries;
    for (const op of operations) {
      if (op.kind === "complete") {
        for (const omitted of op.omitted)
          await deletion(
            op.stream,
            omitted.pkHash,
            omitted.key,
            op.cutoff,
            false,
          );
        continue;
      }
      if (op.kind !== "upsert" && op.kind !== "upsert-ref") {
        await deletion(
          op.stream,
          op.pkHash,
          op.key,
          op.stamp,
          op.kind === "delete",
        );
        continue;
      }
      // Resolve exactly one referenced body, even if it later loses the comparison.
      if (op.kind === "upsert-ref") await admitRecord(op.body.bytes);
      const value =
        op.kind === "upsert" ? op.value : await fetchBody(deps, scope, op.body);
      const primaryKey = primaryKeys.get(op.stream);
      if (!primaryKey) throw new Error("fold_missing_primary_key");
      const key = primaryKeyValues(
        value,
        primaryKey,
      ) as WorkspaceFoldCell["key"];
      const body = await store(encoder.encode(canonicalJson(value)));
      const c = (await lookup(unitId, op.stream, op.pkHash)) ?? {
        stream: op.stream,
        pkHash: op.pkHash,
        key,
        upsert: null,
        deletion: null,
      };
      const u = c.upsert;
      const ordinal = op.ordinal ?? 0;
      if (
        !u ||
        stampAfter(op.stamp, u.stamp) ||
        (!stampAfter(u.stamp, op.stamp) &&
          (ordinal > u.ordinal ||
            (ordinal === u.ordinal && body.sha256 > u.body.sha256)))
      ) {
        const source =
          op.kind === "upsert-ref"
            ? await store(encoder.encode(canonicalJson(op.body)))
            : undefined;
        await staged.stage("fold", {
          ...c,
          key,
          upsert: {
            stamp: op.stamp,
            ordinal,
            firstSeen: op.firstSeen,
            body,
            ...(source ? { source } : {}),
          },
        });
      }
    }
    await unit.commit();
  }
  async function* metadata() {
    let bytes = 0;
    const cursor = ws.cursor("streams");
    try {
      for (;;) {
        const unit = await cursor.next(lease);
        if (!unit) break;
        const token = unit.value.row.metadata;
        await unit.release();
        const meta = (await read(token)) as LogStreamMeta;
        bytes += JSON.stringify(meta).length * 6;
        if (bytes > PART_LIMIT_BYTES)
          await fail(new Error("workspace_metadata_admission"));
        yield meta;
      }
    } finally {
      await cursor.close();
    }
  }
  async function* entries(wire: boolean): AsyncGenerator<WireEntry> {
    const cursor = ws.cursor("fold");
    try {
      for (;;) {
        const unit = await cursor.next(lease);
        if (!unit) break;
        const c = unit.value.row;
        await unit.release();
        const u = c.upsert,
          d = c.deletion;
        const wins =
          u &&
          (!d ||
            stampAfter(u.stamp, d.stamp) ||
            (!d.explicit && !stampAfter(d.stamp, u.stamp)));
        if (d && (!wins || stampAfter(u!.stamp, d.stamp)))
          yield {
            kind: d.explicit ? "delete" : "omitted",
            stream: c.stream,
            pkHash: c.pkHash,
            key: d.key,
            stamp: d.stamp,
          };
        if (wins) {
          const base = {
            stream: c.stream,
            pkHash: c.pkHash,
            stamp: u!.stamp,
            ordinal: u!.ordinal,
            firstSeen: u!.firstSeen,
          };
          yield wire && u!.source
            ? {
                ...base,
                kind: "upsert-ref",
                body: (await read(u!.source)) as LogUpsertByRef["body"],
              }
            : {
                ...base,
                kind: "upsert",
                value: (await read(u!.body)) as JsonObject,
              };
        }
      }
    } finally {
      await cursor.close();
    }
  }
  return {
    binding,
    lease,
    ws,
    controlVersion: control.control_version,
    ingest,
    metadata,
    async primaryKey(stream: string) {
      const row = await ws.lookup(
        "seed-metadata",
        "streams",
        foldCellKey(stream),
        lease,
      );
      if (!row) throw new Error("seed_missing_primary_key");
      return ((await read(row.metadata)) as LogStreamMeta).primaryKey;
    },
    entries,
    async seedEntry(entry: LogEntry, primaryKey: readonly string[]) {
      await ws.stageSeed(entry, primaryKey);
    },
    /** Give up the lease and the job slot but keep the workspace and its rows:
     * its outputs go on to be uploaded. */
    async handOff() {
      await lease.release();
      await runtimeAdmission.finish(deps.db, binding.operation);
    },
    async close(cleanup = true) {
      await lease.release();
      await runtimeAdmission.finish(deps.db, binding.operation);
      await ws.discard();
      while (cleanup && (await ws.cleanupOne())) {
        /* bounded cleanup */
      }
    },
  };
}
