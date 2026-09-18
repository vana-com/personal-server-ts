/**
 * Import qualifying synced DataPipe envelopes into the PDPP record store.
 *
 * The production path already existed end to end: Unity's OwnerDataClient
 * writes an encrypted `DataFileEnvelope` and registers it with the Gateway,
 * and `sync/workers/download.ts` downloads, decrypts and indexes it. What was
 * missing was the last hop — that decrypted envelope reaching the PDPP record
 * store, so a grant-bound client can read it. This module is that hop, and
 * nothing else: it does not fetch, does not decrypt, and does not open a
 * second ingestion surface. There is no web HTTP ingest here by design; the
 * encrypted owner-data transport stays the only way data arrives.
 *
 * Why the metadata lives in `data.$pdpp`
 * -------------------------------------
 * The SDK's `DataFileEnvelopeSchema` accepts only `$schema`, `version`,
 * `scope`, `schemaId`, `collectedAt` and `data`, and STRIPS unknown top-level
 * keys. A `$pdpp` sibling of `scope` would therefore be silently deleted in
 * transit — not rejected, deleted — so the producer nests it inside `data`,
 * the one field whose interior the transport preserves verbatim. That is a
 * transport constraint, not a preference.
 *
 * The consequence this module owns: `$pdpp` is import metadata that arrived
 * inside the payload, so it must be removed before the record is stored.
 * Otherwise every PDPP read would serve back a `$pdpp` blob that is not part
 * of the source's declared schema, and a field projection computed from the
 * declaration would not cover it.
 *
 * What is verified before anything is written
 * -------------------------------------------
 * Every check below is a fail-closed rejection, because the alternative is
 * importing a record whose identity or authority we could not confirm:
 *
 *   1. `$pdpp.version === 1`. An unknown metadata version is refused rather
 *      than interpreted under this version's assumptions.
 *   2. The declaration digest is recomputed over the EXACT retained
 *      declaration document this deployment booted with, and must equal the
 *      digest the producer claims. This is the check that makes the rest
 *      meaningful: without it the producer would be asserting its own
 *      authority over the stream shape it is being validated against.
 *   3. `scope`, `stream.name` and `primaryKey` must agree with that same
 *      declaration, and `record.key` must agree with the payload's actual
 *      primary-key values.
 *
 * Only then is `$pdpp` stripped and the record handed to the store.
 *
 * Instance derivation is PS-owned
 * -------------------------------
 * The producer supplies no instance id and must not: an instance handle is a
 * statement about this deployment's connection inventory, which the producer
 * cannot observe. The importer derives it through the same function the
 * authorization and resource servers use, so an imported record is readable
 * under a grant issued for the same source. An id that cannot be derived is a
 * rejection, never an invention.
 */

import type {
  PdppRecordEnvelopeInput,
  PdppRecordStore,
  StreamSemantics,
} from "../storage/pdpp-records/index.js";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { Logger } from "../logger/index.js";

/** The reserved key carrying PDPP import metadata inside `data`. */
export const PDPP_METADATA_KEY = "$pdpp";

/** The only `$pdpp.version` this importer understands. */
export const SUPPORTED_PDPP_METADATA_VERSION = 1;

/**
 * The stream shape the importer validates against, projected from the
 * deployment's retained declaration. Deliberately not the full declaration
 * model: the importer only needs to answer "does this envelope match the
 * document we retained?".
 */
export interface ImportStreamShape {
  name: string;
  primaryKey: string[];
  semantics: StreamSemantics;
}

/**
 * One retained declaration, as this deployment booted with it.
 *
 * The digest must be taken over the exact retained bytes, not over a
 * re-serialization of a parsed snapshot. The distinction is the whole point
 * of the check: the authorization store persists a parsed `snapshot_json`,
 * and re-digesting that would produce a different value than the digest
 * recorded at retrieval (key order, whitespace, and fields the parser does
 * not carry). Digesting anything other than the retrieved bytes would be a
 * check that passes against itself while proving nothing about what the
 * producer actually read.
 */
export interface RetainedDeclaration {
  sourceId: string;
  version: string;
  /**
   * SHA-256 over the exact retained document, as bare lowercase hex.
   *
   * Passed in already computed rather than hashed here on purpose. This
   * module is bundled into the browser lite runtime, where `node:crypto` does
   * not exist; hashing here would break that build. The server computes it
   * once at boot from the document it read — which is also the only place the
   * original bytes exist — so doing it there costs nothing and keeps this
   * module runtime-agnostic.
   */
  documentDigest: string;
  streams: ImportStreamShape[];
}

export type PdppImportRejectionCode =
  | "no_metadata"
  | "malformed_metadata"
  | "unsupported_metadata_version"
  | "unknown_source"
  | "digest_mismatch"
  | "declaration_version_mismatch"
  | "scope_mismatch"
  | "unknown_stream"
  | "primary_key_mismatch"
  | "semantics_mismatch"
  | "record_key_mismatch"
  | "no_instance"
  | "store_rejected";

export interface PdppImportRejection {
  code: PdppImportRejectionCode;
  message: string;
}

export type PdppImportOutcome =
  /** Not a PDPP-bearing envelope. Legacy-only, and not an error. */
  | { status: "skipped" }
  /** Imported a new version. */
  | { status: "imported"; instance: string; stream: string; recordKey: string }
  /**
   * Verified and already present unchanged. Deliberately distinct from
   * "imported": re-writing it would allocate a new version and publish a
   * spurious `changes_since` entry for a record that did not change.
   */
  | { status: "unchanged"; instance: string; stream: string; recordKey: string }
  | { status: "rejected"; rejection: PdppImportRejection };

/** The envelope fields this importer reads. */
export interface ImportableEnvelope {
  scope: string;
  collectedAt: string;
  data: unknown;
}

export interface PdppImporterDeps {
  store: PdppRecordStore;
  /** The exact declarations this deployment retained at boot. */
  declarations: RetainedDeclaration[];
  /**
   * PS-owned instance derivation, wired to the same inventory the AS and RS
   * use so an imported record is readable under a grant for that source.
   */
  instanceFor: (sourceId: string) => string | undefined;
  logger: Logger;
}

export interface PdppImporter {
  /** Import one decrypted envelope. Never throws; failures are outcomes. */
  importEnvelope(envelope: ImportableEnvelope): PdppImportOutcome;
}

interface PdppMetadata {
  version: number;
  sourceId: string;
  declaration: {
    source: string;
    version: string;
    upstreamCommit: string | null;
    digest: string;
  };
  stream: {
    name: string;
    scope: string;
    semantics: string;
    primaryKey: string[];
  };
  record: { key: Record<string, unknown>; op: "upsert" | "delete" };
  run?: { id?: string; source?: string };
}

function reject(
  code: PdppImportRejectionCode,
  message: string,
): PdppImportOutcome {
  return { status: "rejected", rejection: { code, message } };
}

/**
 * Normalize a claimed digest to bare lowercase hex.
 *
 * The producer contract writes `sha256:<hex>`; this repo's
 * `computeDeclarationDigest` returns bare hex with no prefix. Accepting both
 * spellings of the same SHA-256 value keeps the two sides interoperable
 * without either silently coercing the other. Any OTHER algorithm prefix
 * returns null and fails the import: treating `md5:...` as if it were the
 * SHA-256 we computed would turn the digest check into decoration.
 */
export function normalizeDigest(claimed: string): string | null {
  const trimmed = claimed.trim().toLowerCase();
  const colon = trimmed.indexOf(":");
  if (colon === -1) return /^[0-9a-f]{64}$/.test(trimmed) ? trimmed : null;
  if (trimmed.slice(0, colon) !== "sha256") return null;
  const hex = trimmed.slice(colon + 1);
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Read `data.$pdpp` into a typed shape, or explain why it is not usable.
 *
 * Returns `null` for "no metadata present", which is the ordinary legacy
 * case and must stay distinguishable from a malformed `$pdpp` — a producer
 * that writes broken metadata should be visible, not silently treated as a
 * legacy write.
 */
function readMetadata(
  data: unknown,
): { ok: true; meta: PdppMetadata } | { ok: false; reason: string } | null {
  if (!isRecord(data)) return null;
  const raw = data[PDPP_METADATA_KEY];
  if (raw === undefined) return null;
  if (!isRecord(raw)) return { ok: false, reason: "$pdpp is not an object" };

  if (typeof raw.version !== "number") {
    return { ok: false, reason: "$pdpp.version is missing or not a number" };
  }
  if (typeof raw.sourceId !== "string" || raw.sourceId.length === 0) {
    return { ok: false, reason: "$pdpp.sourceId is missing" };
  }

  const declaration = raw.declaration;
  if (!isRecord(declaration)) {
    return { ok: false, reason: "$pdpp.declaration is missing" };
  }
  if (
    typeof declaration.digest !== "string" ||
    declaration.digest.length === 0
  ) {
    return { ok: false, reason: "$pdpp.declaration.digest is missing" };
  }
  if (typeof declaration.version !== "string") {
    return { ok: false, reason: "$pdpp.declaration.version is missing" };
  }

  const stream = raw.stream;
  if (!isRecord(stream))
    return { ok: false, reason: "$pdpp.stream is missing" };
  if (typeof stream.name !== "string" || stream.name.length === 0) {
    return { ok: false, reason: "$pdpp.stream.name is missing" };
  }
  if (typeof stream.scope !== "string" || stream.scope.length === 0) {
    return { ok: false, reason: "$pdpp.stream.scope is missing" };
  }
  if (
    !Array.isArray(stream.primaryKey) ||
    stream.primaryKey.length === 0 ||
    !stream.primaryKey.every((f) => typeof f === "string")
  ) {
    return { ok: false, reason: "$pdpp.stream.primaryKey is missing" };
  }

  const record = raw.record;
  if (!isRecord(record))
    return { ok: false, reason: "$pdpp.record is missing" };
  if (!isRecord(record.key)) {
    return { ok: false, reason: "$pdpp.record.key is missing" };
  }
  const op = record.op ?? "upsert";
  if (op !== "upsert" && op !== "delete") {
    return {
      ok: false,
      reason: `$pdpp.record.op '${String(op)}' is not valid`,
    };
  }

  return {
    ok: true,
    meta: {
      version: raw.version,
      sourceId: raw.sourceId,
      declaration: {
        source:
          typeof declaration.source === "string" ? declaration.source : "",
        version: declaration.version,
        upstreamCommit:
          typeof declaration.upstreamCommit === "string"
            ? declaration.upstreamCommit
            : null,
        digest: declaration.digest,
      },
      stream: {
        name: stream.name,
        scope: stream.scope,
        semantics: typeof stream.semantics === "string" ? stream.semantics : "",
        primaryKey: stream.primaryKey as string[],
      },
      record: { key: record.key, op },
      ...(isRecord(raw.run) && {
        run: {
          ...(typeof raw.run.id === "string" && { id: raw.run.id }),
          ...(typeof raw.run.source === "string" && { source: raw.run.source }),
        },
      }),
    },
  };
}

/** Remove `$pdpp` without mutating the caller's object. */
function stripMetadata(data: Record<string, unknown>): Record<string, unknown> {
  const { [PDPP_METADATA_KEY]: _dropped, ...rest } = data;
  return rest;
}

function sameArray(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Deep structural equality over JSON-shaped values.
 *
 * Used only to decide "did this record actually change?". Key order must not
 * count as a change: the producer re-serializes the payload on every run, so
 * an order-sensitive comparison would report every re-sync as a new version
 * and fill `changes_since` with records that are byte-identical to what a
 * client already read.
 */
function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((item, i) => jsonEqual(item, b[i]));
  }
  if (typeof a !== "object") return false;
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const aKeys = Object.keys(ao).sort();
  const bKeys = Object.keys(bo).sort();
  if (!sameArray(aKeys, bKeys)) return false;
  return aKeys.every((k) => jsonEqual(ao[k], bo[k]));
}

export function createPdppImporter(deps: PdppImporterDeps): PdppImporter {
  const { store, logger } = deps;

  const bySourceId = new Map<string, RetainedDeclaration>();
  for (const declaration of deps.declarations) {
    bySourceId.set(declaration.sourceId, declaration);
  }

  function importEnvelope(envelope: ImportableEnvelope): PdppImportOutcome {
    const read = readMetadata(envelope.data);
    if (read === null) return { status: "skipped" };
    if (!read.ok) return reject("malformed_metadata", read.reason);
    const meta = read.meta;

    if (meta.version !== SUPPORTED_PDPP_METADATA_VERSION) {
      return reject(
        "unsupported_metadata_version",
        `$pdpp.version ${meta.version} is not supported (expected ${SUPPORTED_PDPP_METADATA_VERSION})`,
      );
    }

    const retained = bySourceId.get(meta.sourceId);
    if (!retained) {
      return reject(
        "unknown_source",
        `no retained declaration for source '${meta.sourceId}'`,
      );
    }

    // The digest gate. Everything after this point is validated against a
    // document we have confirmed is the one the producer claims to have read.
    const claimed = normalizeDigest(meta.declaration.digest);
    if (claimed === null) {
      return reject(
        "digest_mismatch",
        `declaration digest '${meta.declaration.digest}' is not a recognized sha256 digest`,
      );
    }
    if (claimed !== retained.documentDigest.trim().toLowerCase()) {
      return reject(
        "digest_mismatch",
        `declaration digest does not match the retained declaration for '${meta.sourceId}'`,
      );
    }
    if (meta.declaration.version !== retained.version) {
      return reject(
        "declaration_version_mismatch",
        `declaration version '${meta.declaration.version}' does not match retained version '${retained.version}'`,
      );
    }

    // The scope the envelope was transported under must be the scope the
    // metadata claims. Without this, metadata for one scope could ride on a
    // blob decrypted under another scope's key.
    if (meta.stream.scope !== envelope.scope) {
      return reject(
        "scope_mismatch",
        `$pdpp.stream.scope '${meta.stream.scope}' does not match envelope scope '${envelope.scope}'`,
      );
    }

    const declaredStream = retained.streams.find(
      (s) => s.name === meta.stream.name,
    );
    if (!declaredStream) {
      return reject(
        "unknown_stream",
        `stream '${meta.stream.name}' is not declared by the retained declaration for '${meta.sourceId}'`,
      );
    }
    if (!sameArray(meta.stream.primaryKey, declaredStream.primaryKey)) {
      return reject(
        "primary_key_mismatch",
        `stream '${meta.stream.name}' declares primary key [${declaredStream.primaryKey.join(", ")}] but the envelope claims [${meta.stream.primaryKey.join(", ")}]`,
      );
    }
    if (
      meta.stream.semantics.length > 0 &&
      meta.stream.semantics !== declaredStream.semantics
    ) {
      return reject(
        "semantics_mismatch",
        `stream '${meta.stream.name}' is ${declaredStream.semantics} here but the envelope claims '${meta.stream.semantics}'`,
      );
    }

    const instance = deps.instanceFor(meta.sourceId);
    if (!instance) {
      return reject(
        "no_instance",
        `no instance handle could be derived for source '${meta.sourceId}'`,
      );
    }

    if (!isRecord(envelope.data)) {
      return reject("malformed_metadata", "envelope data is not an object");
    }
    const payload = stripMetadata(envelope.data);

    // `record.key` is the producer's claim about identity; the payload is the
    // record. They must agree, or the record would be stored under a key that
    // does not describe it — and a grant naming that key would authorize the
    // wrong row.
    let keyFromData: string;
    let keyFromClaim: string;
    try {
      keyFromData = computeRecordKeyFromData(
        payload,
        declaredStream.primaryKey,
      );
      keyFromClaim = computeRecordKeyFromData(
        meta.record.key,
        declaredStream.primaryKey,
      );
    } catch (err) {
      return reject("record_key_mismatch", (err as Error).message);
    }
    if (keyFromData !== keyFromClaim) {
      return reject(
        "record_key_mismatch",
        "$pdpp.record.key does not match the payload's primary key values",
      );
    }

    // Idempotency. `ingestBatch` allocates a NEW version on every accepted
    // mutable_state upsert, so an unconditional re-ingest would bump the
    // version and publish a `changes_since` entry every time the sync worker
    // re-downloads an unchanged record — which it does on any full reconcile
    // or retry. Comparing against the stored row first is what makes a repeat
    // sync a no-op rather than a fabricated change.
    // `getRecord` returns undefined for a deleted row as well as an absent
    // one, which is exactly the distinction both branches below need.
    const existing = store.getRecord(instance, meta.stream.name, keyFromData);
    const unchanged = {
      status: "unchanged" as const,
      instance,
      stream: meta.stream.name,
      recordKey: keyFromData,
    };

    if (meta.record.op === "delete") {
      // A delete for a record we do not currently hold changes nothing.
      // Ingesting it would write a tombstone announcing the removal of
      // something this store never served — a fabricated change.
      if (!existing) return unchanged;
    } else if (
      existing &&
      jsonEqual(existing.data, payload) &&
      existing.emittedAt === envelope.collectedAt
    ) {
      return unchanged;
    }

    // A single-field key must stay a bare string. `encodeRecordKey` treats an
    // array as a COMPOUND key and JSON-encodes it, so wrapping a lone value
    // in an array would produce `["235680975"]` where the data yields
    // `235680975` — a key/data mismatch the store rejects, on every record of
    // every single-key stream.
    const components = declaredStream.primaryKey.map((f) => String(payload[f]));
    const input: PdppRecordEnvelopeInput = {
      instance,
      stream: meta.stream.name,
      key: components.length === 1 ? components[0] : components,
      data: meta.record.op === "delete" ? null : payload,
      emitted_at: envelope.collectedAt,
      op: meta.record.op,
    };

    // One envelope per call, but through the batch API so the store's own
    // transaction wraps the write: a failure rolls back rather than leaving
    // a row without its history entry.
    const result = store.ingestBatch(
      [input],
      () => declaredStream.semantics,
      () => declaredStream.primaryKey,
    );
    if (result.rejected.length > 0) {
      return reject("store_rejected", result.rejected[0].reason);
    }
    if (result.accepted === 0) {
      // append_only duplicate: the store treats it as a no-op, and so do we.
      return {
        status: "unchanged",
        instance,
        stream: meta.stream.name,
        recordKey: keyFromData,
      };
    }

    logger.info(
      {
        instance,
        stream: meta.stream.name,
        sourceId: meta.sourceId,
        op: meta.record.op,
        ...(meta.run?.id && { runId: meta.run.id }),
      },
      "Imported synced DataPipe record into the PDPP record store",
    );

    return {
      status: "imported",
      instance,
      stream: meta.stream.name,
      recordKey: keyFromData,
    };
  }

  return { importEnvelope };
}
