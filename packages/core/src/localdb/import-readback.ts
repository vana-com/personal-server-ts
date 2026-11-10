import {
  canonicalJson,
  canonicalJsonChunks,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import {
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
  type PdppRecord,
} from "../legacy-projection/index.js";
import { legacyConnectorKey } from "../storage/canonical-legacy-projection.js";
import { importFingerprint } from "./import-fingerprint.js";
import { createImportLedger } from "./import-ledger.js";
import {
  stageImportSnapshot,
  clearImportSnapshot,
  canonicalImportRow,
  IMPORT_BATCH_BYTES,
} from "./import-snapshot.js";
import type { LocalSyncDeps } from "./deps.js";
import type {
  ImportSource,
  ImportReadback,
  LegacyCopy,
  ProjectionProof,
  CopyRecords,
  ImportFingerprint,
} from "./legacy-import-types.js";

export interface ImportProjectionReader {
  /** Every applicable frozen binding, including held/unsupported bindings. */
  compare(
    source: ImportSource,
    copy: LegacyCopy | null,
  ): Promise<readonly ProjectionProof[]>;
}

/** Caller owns every affected connection queue. No queue reacquisition or
 * durable proof writes. Source and actual SQL rows are independently staged;
 * actual bodies, keys and hashes are validated, not trusted as cached hashes. */
export async function readBackLegacyImport(
  deps: LocalSyncDeps,
  source: ImportSource,
  projections: ImportProjectionReader,
  copy: LegacyCopy | null,
): Promise<ImportReadback> {
  const receipt = await createImportLedger(deps.db).get(
    source.source,
    source.target.connectionId,
    source.target.stream,
  );
  let actual: ImportFingerprint = await importFingerprint(
    (async function* () {})(),
  );
  let proofs: readonly ProjectionProof[] = [];
  const result = (reason: string | null): ImportReadback => ({
    receipt,
    actual,
    projections: proofs,
    copy,
    pass: reason === null,
    reason,
  });
  if (!receipt) return result("missing_receipt");
  const [meta] = await deps.db.query<{ owner: string; network: string }>(
    "SELECT owner, network FROM db_meta WHERE id = 1",
  );
  if (
    meta?.owner !== source.owner.toLowerCase() ||
    meta.owner !== deps.ownerAddress.toLowerCase() ||
    meta.network !== source.network
  )
    return result("owner_mismatch");
  if (source.exclusions.length || receipt.state === "excluded")
    return result("source_excluded");
  if (receipt.revision !== source.revision || receipt.generation !== 1)
    return result("source_changed");
  if (copy && !copyIdentityMatches(copy, source)) return result("copy_changed");
  const expectedOp = deps.newOp();
  const actualOp = deps.newOp();
  try {
    const expected = await stageImportSnapshot(deps.db, source, expectedOp);
    actual = await stageImportSnapshot(
      deps.db,
      databaseSource(deps, source),
      actualOp,
    );
    if (
      !expected.rows ||
      !sameFingerprint(receipt, expected) ||
      !sameFingerprint(expected, actual)
    )
      return result("record_mismatch");
    proofs = await projections.compare(source, copy);
    const names = applicable(source).map(([name]) => name);
    if (
      !names.length ||
      proofs.length !== names.length ||
      new Set(proofs.map((p) => p.dataSet)).size !== names.length ||
      names.some(
        (name) =>
          !proofs.some(
            (p) =>
              p.dataSet === name &&
              p.pass &&
              p.expectedHash &&
              p.actualHash === p.expectedHash,
          ),
      )
    )
      return result("projection_unproven");
    if (
      copy &&
      (!names.includes(copy.dataSet) ||
        !copy.sources.some(
          (s) =>
            s.source === source.source &&
            s.connectionId === source.target.connectionId &&
            s.stream === source.target.stream,
        ))
    )
      return result("copy_uncovered");
    // Detect mutation during projection as well as between source passes.
    await clearImportSnapshot(deps.db, expectedOp);
    await clearImportSnapshot(deps.db, actualOp);
    const after = await stageImportSnapshot(deps.db, source, expectedOp);
    const actualAfter = await stageImportSnapshot(
      deps.db,
      databaseSource(deps, source),
      actualOp,
    );
    if (
      !sameFingerprint(after, expected) ||
      !sameFingerprint(actualAfter, actual)
    )
      return result("source_changed");
    return result(null);
  } catch (error) {
    const reasons = [
      "source_changed",
      "copy_unreadable",
      "copy_changed",
      "copy_uncovered",
      "projection_bound_exceeded",
      "stored_row_invalid",
      "invalid_record",
    ];
    return result(
      error instanceof Error && reasons.includes(error.message)
        ? error.message
        : "readback_unavailable",
    );
  } finally {
    await clearImportSnapshot(deps.db, expectedOp);
    await clearImportSnapshot(deps.db, actualOp);
  }
}
function sameFingerprint(a: ImportFingerprint, b: ImportFingerprint) {
  return a.rows === b.rows && a.fingerprint === b.fingerprint;
}
function applicable(source: ImportSource) {
  return [...LEGACY_SCOPE_BINDINGS].filter(
    ([, binding]) =>
      legacyConnectorKey(binding.pdppSource) === source.target.connector &&
      binding.pdppStreams.includes(source.target.stream),
  );
}
function databaseSource(
  deps: LocalSyncDeps,
  source: ImportSource,
): ImportSource {
  return {
    ...source,
    async *records() {
      let after = "";
      for (;;) {
        const [row] = await deps.db.query<{
          pk_hash: string;
          record_key: string;
          body: string;
          body_sha256: string;
        }>(
          "SELECT pk_hash, record_key, body, body_sha256 FROM records WHERE connection_id = ? AND stream = ? AND pk_hash > ? ORDER BY pk_hash LIMIT 1",
          [source.target.connectionId, source.target.stream, after],
        );
        if (!row) return;
        let record: Record<string, unknown>;
        try {
          record = JSON.parse(row.body);
          const computed = await canonicalImportRow(
            record,
            source.target.primaryKey,
          );
          if (canonicalJson(computed) !== canonicalJson(row)) throw new Error();
        } catch {
          throw new Error("stored_row_invalid");
        }
        yield record;
        after = row.pk_hash;
      }
    },
  };
}

/** Existing projectors accept arrays. Cap aggregate input/output at 4 MiB and
 * hold larger copies; this does not limit SQL import. Arrival-order/completion
 * and blob-backed content lack evidence at this port and remain held.
 * sourcesFor supplies immutable peers, never expected values from SQL. */
export function createImportProjectionReader(
  deps: LocalSyncDeps,
  projectionTime: string,
  sourcesFor: (source: ImportSource) => AsyncIterable<ImportSource>,
  copyRecords?: CopyRecords,
): ImportProjectionReader {
  return {
    async compare(source, copy) {
      if (copy && !copyRecords) throw new Error("copy_unreadable");
      if (copy && !copyIdentityMatches(copy, source))
        throw new Error("copy_changed");
      if (copy && !applicable(source).some(([name]) => name === copy.dataSet))
        throw new Error("copy_uncovered");
      const peers: ImportSource[] = [];
      for await (const peer of sourcesFor(source)) {
        if (peers.length >= 128) throw new Error("projection_bound_exceeded");
        peers.push(peer);
      }
      let copyHash: string | null = null;
      if (copy && copyRecords) {
        let count = 0;
        for await (const payload of copyRecords(copy)) {
          if (++count > 1) throw new Error("copy_unreadable");
          copyHash = payloadHash(payload);
        }
        if (count !== 1) throw new Error("copy_unreadable");
      }
      const proofs: ProjectionProof[] = [];
      for (const [name, binding] of applicable(source)) {
        const failed: ProjectionProof = {
          dataSet: name,
          expectedHash: "",
          actualHash: null,
          pass: false,
        };
        if (binding.rowOrder === "arrival") {
          proofs.push(failed);
          continue;
        }
        const selected: ImportSource[] = [];
        for (const stream of binding.pdppStreams) {
          const candidates = peers.filter(
            (p) =>
              p.target.stream === stream &&
              p.target.connector === source.target.connector &&
              p.target.connectionId === source.target.connectionId &&
              p.owner.toLowerCase() === source.owner.toLowerCase() &&
              p.network === source.network &&
              p.revision === source.revision &&
              p.exclusions.length === 0 &&
              canonicalJson(p.target.primaryKey) ===
                canonicalJson(binding.primaryKey[stream]),
          );
          if (candidates.length === 1) selected.push(candidates[0]!);
        }
        if (
          selected.length !== binding.pdppStreams.length ||
          !selected.some(
            (p) =>
              p.source === source.source &&
              p.target.stream === source.target.stream,
          )
        ) {
          proofs.push(failed);
          continue;
        }
        if (copy?.dataSet === name) {
          const keys = selected.map(sourceKey).sort();
          const copyKeys = copy.sources
            .map((s) => JSON.stringify([s.source, s.connectionId, s.stream]))
            .sort();
          if (canonicalJson(keys) !== canonicalJson(copyKeys)) {
            proofs.push(failed);
            continue;
          }
        }
        const expected: PdppRecord[] = [];
        const actual: PdppRecord[] = [];
        let bytes = 0;
        let unsupported = false;
        for (const peer of selected) {
          for await (const record of peer.records()) {
            bytes += utf8ToBytes(canonicalJson(record)).length;
            if (bytes > IMPORT_BATCH_BYTES)
              throw new Error("projection_bound_exceeded");
            if (Object.hasOwn(record, "blob_ref")) unsupported = true;
            expected.push({ stream: peer.target.stream, data: record });
          }
          for await (const record of databaseSource(deps, peer).records()) {
            bytes += utf8ToBytes(canonicalJson(record)).length;
            if (bytes > IMPORT_BATCH_BYTES)
              throw new Error("projection_bound_exceeded");
            actual.push({ stream: peer.target.stream, data: record });
          }
        }
        if (unsupported) {
          proofs.push(failed);
          continue;
        }
        const options = {
          fetchedStreams: [...binding.pdppStreams],
          now: projectionTime,
          orderByPrimaryKey: true,
        };
        const left = projectPdppRecordsToLegacyPayload(name, expected, options);
        const right = projectPdppRecordsToLegacyPayload(name, actual, options);
        if (
          !left.ok ||
          !right.ok ||
          left.diagnostics?.length ||
          right.diagnostics?.length ||
          left.projectionOmissions?.length ||
          right.projectionOmissions?.length
        ) {
          proofs.push(failed);
          continue;
        }
        const expectedHash = payloadHash(left.payload);
        const actualHash = payloadHash(right.payload);
        proofs.push({
          dataSet: name,
          expectedHash,
          actualHash,
          pass:
            expectedHash === actualHash &&
            (copy?.dataSet !== name || copyHash === expectedHash),
        });
      }
      return proofs;
    },
  };
}
function sourceKey(source: ImportSource) {
  return JSON.stringify([
    source.source,
    source.target.connectionId,
    source.target.stream,
  ]);
}
function payloadHash(payload: unknown) {
  const hash = sha256.create();
  let bytes = 0;
  for (const chunk of canonicalJsonChunks(payload)) {
    const encoded = utf8ToBytes(chunk);
    bytes += encoded.length;
    if (bytes > IMPORT_BATCH_BYTES)
      throw new Error("projection_bound_exceeded");
    hash.update(encoded);
  }
  return bytesToHex(hash.digest());
}

function copyIdentityMatches(copy: LegacyCopy, source: ImportSource) {
  return (
    !!copy.id &&
    !!copy.path &&
    /^[0-9a-f]{64}$/.test(copy.contentHash) &&
    copy.revision === source.revision
  );
}
