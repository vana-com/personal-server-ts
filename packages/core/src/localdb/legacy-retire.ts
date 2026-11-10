import type { LocalSyncDeps } from "./deps.js";
import { createImportLedger } from "./import-ledger.js";
import type {
  ImportReadback,
  ImportReceipt,
  LegacyCopy,
  LegacyRetireFileReport,
  LegacyRetireReport,
} from "./legacy-import-types.js";

/** F.2/F.4: host capability comes only from switched-owner legacy-access. */
export interface LegacyRetireAccess {
  copies(): AsyncIterable<LegacyCopy>;
  /** Fresh proof for every source named by copy, bound to this exact hash/revision. Caller holds queues: must not reacquire them. */
  readBack(copy: LegacyCopy): Promise<readonly ImportReadback[]>;
  /** Atomic compare-and-erase of local copies only; never gateway operations. */
  erase(copy: LegacyCopy): Promise<boolean>;
}

/** F.2: absent streamSync.retireLegacy means false on every host. */
export interface LegacyRetireOptions {
  readonly streamSync?: { readonly retireLegacy?: boolean };
  readonly dryRun?: boolean;
  readonly reportFile: (report: LegacyRetireFileReport) => void;
}

/**
 * F.2-F.5: under each connection queue, fresh read-back, unchanged source/file,
 * generation 1, no delete intent/control tombstone, nonempty complete source
 * coverage and stream.publish_watermark >= EACH receipt.highestSeq are ALL
 * required. Recheck before erase; serialize multi-stream copies in sorted
 * connection order. Stored verified status alone grants nothing. Unknowns,
 * exclusions and deleted connections hold files. Dry run never calls erase or
 * persists verified/retired state even with the flag on. Erase then mark retired;
 * a crash after erase may leave the receipt unretired. Generic ENOENT or
 * erase(false) is not proof of exact-copy absence. Without durable host intent,
 * leave this unknown; never erase a replacement to reconcile old state.
 * import_ledger has no exact-copy erase intent (id/path/contentHash/revision).
 * Its source receipt and free-text reason cannot stand in for such intent.
 * An unconfirmed erase is reported held/erase-not-confirmed, never retired.
 * Successful absence reconciliation requires a future durable intent contract;
 * this implementation deliberately grants no authority from ENOENT alone.
 */
export async function retireLegacyCopies(
  deps: LocalSyncDeps,
  access: LegacyRetireAccess,
  options: LegacyRetireOptions,
): Promise<LegacyRetireReport> {
  const mode =
    options.dryRun === true
      ? "dry-run"
      : options.streamSync?.retireLegacy === true
        ? "delete"
        : "readback-only";
  let files = 0;
  let ready = 0;
  let deleted = 0;
  const ledger = createImportLedger(deps.db);
  for await (const candidate of access.copies()) {
    // Do not let the adapter mutate the identity being proved between awaits.
    const copy: LegacyCopy = Object.freeze({
      ...candidate,
      sources: Object.freeze(
        candidate.sources.map((source) => Object.freeze({ ...source })),
      ),
    });
    files++;
    const report = (
      decision: LegacyRetireFileReport["decision"],
      reason: string | null,
    ) => options.reportFile({ file: copy.id, decision, reason });
    const keys = copy.sources.map(sourceKey);
    if (
      !copy.id ||
      !copy.path ||
      !copy.contentHash ||
      !copy.revision ||
      !copy.dataSet ||
      keys.length === 0 ||
      new Set(keys).size !== keys.length ||
      copy.sources.some((s) => !s.source || !s.connectionId || !s.stream)
    ) {
      report("held", "incomplete-source-coverage");
      continue;
    }

    const connections = [
      ...new Set(copy.sources.map((s) => s.connectionId)),
    ].sort();
    const locked = async (index: number): Promise<void> => {
      if (index < connections.length) {
        return deps.queue.run(connections[index]!, "end", () =>
          locked(index + 1),
        );
      }
      // Reject known deletion before asking an adapter to read the source.
      if (!(await fencesPass(deps, copy))) {
        report("held", "connection-or-stream-fenced");
        return;
      }
      let proofs: readonly ImportReadback[];
      try {
        proofs = await access.readBack(copy);
      } catch {
        report("held", "readback-unavailable");
        return;
      }
      if (proofs.length !== keys.length) {
        report("held", "incomplete-source-coverage");
        return;
      }
      const seen = new Set<string>();
      const receipts: ImportReceipt[] = [];
      for (const proof of proofs) {
        if (proof.receipt === null) {
          report("held", "missing_receipt");
          return;
        }
        const receipt = { ...proof.receipt };
        const key = sourceKey(receipt);
        if (!keys.includes(key) || seen.has(key)) {
          report("held", "incomplete-source-coverage");
          return;
        }
        seen.add(key);
        if (
          proof.pass !== true ||
          proof.reason !== null ||
          !validReceipt(receipt, copy) ||
          proof.actual.rows !== receipt.rows ||
          proof.actual.fingerprint !== receipt.fingerprint ||
          proof.projections.length === 0 ||
          proof.projections.some(
            (p) =>
              p.pass !== true ||
              !p.expectedHash ||
              p.actualHash !== p.expectedHash,
          ) ||
          !proof.projections.some((p) => p.dataSet === copy.dataSet)
        ) {
          report("held", "readback-not-proven");
          return;
        }
        if (!proof.copy || !sameCopy(copy, proof.copy)) {
          report("changed", "copy-changed");
          return;
        }
        // A fresh proof must still describe the durable receipt, not a cached
        // verified bit or an older import of the same source key.
        const current = await ledger.get(
          receipt.source,
          receipt.connectionId,
          receipt.stream,
        );
        if (!current || !sameReceipt(current, receipt)) {
          report("held", "receipt-changed-or-missing");
          return;
        }
        receipts.push({ ...receipt });
      }
      // All queues remain held. This one SQL view rechecks deletion/floor
      // fences AND every stream watermark after read-back and ledger reads.
      if (!(await fencesPass(deps, copy, receipts))) {
        report("held", "delete-or-publish-fence");
        return;
      }
      if (mode !== "delete") {
        ready++;
        report("ready", null);
        return;
      }
      // The storage adapter compares id/path/hash/revision under its own lock.
      // False is never treated as absence: a replacement must survive a retry.
      if (!(await access.erase(copy))) {
        report("held", "erase-not-confirmed");
        return;
      }
      // Erase first. Failure here leaves the receipt unretired, so recovery must
      // obtain another fresh exact-copy proof and pass the storage fence again.
      const at = deps.now();
      await deps.db.batch(
        receipts.flatMap((receipt) =>
          ledger.statements({ ...receipt, state: "retired", at }),
        ),
      );
      ready++;
      deleted++;
      report("retired", null);
    };
    await locked(0);
  }
  return { mode, files, ready, deleted };
}

function sourceKey(source: LegacyCopy["sources"][number]): string {
  return JSON.stringify([source.source, source.connectionId, source.stream]);
}

function sameCopy(a: LegacyCopy, b: LegacyCopy): boolean {
  if (
    a.id !== b.id ||
    a.path !== b.path ||
    a.contentHash !== b.contentHash ||
    a.revision !== b.revision ||
    a.dataSet !== b.dataSet ||
    a.sources.length !== b.sources.length
  )
    return false;
  const expected = a.sources.map(sourceKey).sort();
  return b.sources
    .map(sourceKey)
    .sort()
    .every((key, i) => key === expected[i]);
}

function validReceipt(receipt: ImportReceipt, copy: LegacyCopy): boolean {
  return (
    receipt.revision === copy.revision &&
    receipt.generation === 1 &&
    ["imported", "verified", "retired"].includes(receipt.state) &&
    Number.isSafeInteger(receipt.rows) &&
    receipt.rows > 0 &&
    !!receipt.fingerprint &&
    Number.isSafeInteger(receipt.highestSeq) &&
    receipt.highestSeq > 0
  );
}

function sameReceipt(a: ImportReceipt, b: ImportReceipt): boolean {
  return (
    sourceKey(a) === sourceKey(b) &&
    a.revision === b.revision &&
    a.generation === b.generation &&
    a.rows === b.rows &&
    a.fingerprint === b.fingerprint &&
    a.highestSeq === b.highestSeq &&
    a.state === b.state &&
    a.reason === b.reason &&
    a.at === b.at
  );
}

async function fencesPass(
  deps: LocalSyncDeps,
  copy: LegacyCopy,
  receipts: readonly ImportReceipt[] = [],
): Promise<boolean> {
  const streams = new Map(
    copy.sources.map((s) => [JSON.stringify([s.connectionId, s.stream]), s]),
  );
  const targets = [...streams.values()];
  const rows = await deps.db.query<{
    connection_id: string;
    stream: string;
    generation: number;
    control_state: string;
    deleted_at: number | null;
    last_delete_version: number;
    floor_version: string | null;
    floor_o: number | null;
    floor_r: string | null;
    publish_watermark: number;
    deleting: string | null;
  }>(
    `SELECT c.connection_id, s.stream, c.generation, c.control_state,
       c.deleted_at, s.last_delete_version, s.floor_version, s.floor_o,
       s.floor_r, s.publish_watermark, d.connector AS deleting
     FROM connections c
     JOIN stream_state s ON s.connection_id = c.connection_id
     LEFT JOIN delete_intents d ON d.connector = c.connector
     WHERE ${targets.map(() => "(c.connection_id = ? AND s.stream = ?)").join(" OR ")}`,
    targets.flatMap((s) => [s.connectionId, s.stream]),
  );
  if (rows.length !== targets.length) return false;
  for (const row of rows) {
    if (
      row.generation !== 1 ||
      (row.control_state !== "active" && row.control_state !== "absent") ||
      row.deleted_at !== null ||
      row.deleting !== null ||
      row.last_delete_version !== 0 ||
      row.floor_version !== null ||
      row.floor_o !== null ||
      row.floor_r !== null ||
      !Number.isSafeInteger(row.publish_watermark) ||
      row.publish_watermark < 0
    )
      return false;
  }
  return receipts.every((receipt) =>
    rows.some(
      (row) =>
        row.connection_id === receipt.connectionId &&
        row.stream === receipt.stream &&
        row.publish_watermark >= receipt.highestSeq,
    ),
  );
}
