import { type DataStoragePort } from "../ports/index.js";
import type {
  IndexEntry,
  NewIndexEntry,
  ScopeSummary,
} from "../storage/index/types.js";
import {
  createDataFileEnvelope,
  ScopeSchema,
  type DataFileEnvelope,
} from "@opendatalabs/vana-sdk/browser";
import { type WriteResult } from "../storage/hierarchy/index.js";
import { buildBinaryEnvelopeData, sha256Hex } from "./binary.js";
import { buildDataBlocksAsync } from "../storage/blocks/build.js";
import {
  hasReservedWriterKey,
  stampWriterAttribution,
  type WriterAttribution,
} from "../write/attribution.js";
import {
  hasReservedLineageKey,
  stampLineage,
  type StoredLineage,
} from "../lineage/lineage.js";

export type DataContractErrorCode =
  | "INVALID_SCOPE"
  | "INVALID_BODY"
  | "NOT_FOUND"
  /**
   * The scope IS indexed, but the file the index row names is not on disk.
   * Distinct from `NOT_FOUND` (nothing indexed at all) on purpose: the two
   * need different operator responses — one is "no data yet", the other is
   * an index/storage divergence that wants repairing.
   */
  | "DATA_FILE_MISSING"
  | "PRECONDITION_FAILED";

export type LegacyProducer = "pdpp-projector" | "pdpp-import-projection";
export interface LegacyProducerProvenance {
  projector_version: string;
  declaration_digest: string;
  inputs: Array<{ stream: string; changes_since_token: string }>;
  payload_sha256: string;
}
export type LegacyPrecondition =
  { kind: "none" } | { kind: "match"; version: number };

export interface DataContractErrorBody {
  error: DataContractErrorCode;
  message: string;
  current_version?: number | null;
  current_producer?: string | null;
}

export interface DataContractError {
  ok: false;
  status: 400 | 404 | 412;
  body: DataContractErrorBody;
}

/**
 * Discovery-time visibility of a local index entry. False hides the entry
 * (and, for scope listings, the scope whose latest entry it is) the same way
 * a read of it would answer 410: a copy a gateway tombstone covers must not
 * be discoverable either. When present, pagination and totals are computed
 * over the visible set.
 */
export type DataVisibilityFilter = (
  scope: string,
  entry: IndexEntry,
) => Promise<boolean> | boolean;

export interface ListDataScopesContractInput {
  storage: DataStoragePort;
  scopePrefix?: string;
  limit?: number;
  offset?: number;
  isVisible?: DataVisibilityFilter;
}

export interface ListDataScopesContractResult {
  ok: true;
  response: {
    scopes: ReturnType<DataStoragePort["listScopes"]>["scopes"];
    total: number;
    limit: number;
    offset: number;
  };
}

export interface ListDataVersionsContractInput {
  storage: DataStoragePort;
  scopeParam: string;
  limit?: number;
  offset?: number;
  isVisible?: DataVisibilityFilter;
}

export interface ListDataVersionsContractResult {
  ok: true;
  scope: string;
  response: {
    scope: string;
    versions: Array<{
      fileId: string | null;
      schemaId: string | null;
      collectedAt: string;
      version: number;
      producer: LegacyProducer | null;
      producer_provenance: LegacyProducerProvenance | null;
    }>;
    total: number;
    limit: number;
    offset: number;
  };
}

export interface ReadDataContractInput {
  storage: DataStoragePort;
  scopeParam: string;
  fileId?: string;
  at?: string;
}

export interface ReadDataContractResult {
  ok: true;
  scope: string;
  envelope: DataFileEnvelope;
}

/**
 * Thrown when an ingest has crossed the durable-write boundary but a later
 * step failed. Boot recovery or re-index can finish it, so callers must
 * treat the write as persisted:
 * never retry it under the same proof, never release a replay reservation.
 */
export class IngestPersistedError extends Error {
  constructor(
    public readonly relativePath: string,
    public readonly cause: unknown,
  ) {
    super(
      `Envelope persisted at ${relativePath} but write did not complete: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = "IngestPersistedError";
  }
}

async function indexWrittenEnvelope(
  storage: IngestDataContractInput["storage"],
  entry: Parameters<IngestDataContractInput["storage"]["insertEntry"]>[0],
): Promise<void> {
  try {
    await storage.insertEntry(entry);
  } catch (err) {
    throw new IngestPersistedError(entry.path, err);
  }
}

async function commitWrittenEnvelope(
  storage: DataStoragePort,
  envelope: DataFileEnvelope,
  entry: Omit<NewIndexEntry, "path" | "sizeBytes"> & { sizeBytes?: number },
  precondition?: LegacyPrecondition,
): Promise<{ ok: true; writeResult: WriteResult } | DataContractError> {
  if (storage.commitEnvelope) {
    const result = await storage.commitEnvelope(envelope, entry, precondition);
    if (!result.ok) {
      return {
        ok: false,
        status: 412,
        body: {
          error: "PRECONDITION_FAILED",
          message: "Scope version precondition failed",
          current_version: result.currentVersion,
          current_producer: result.currentProducer,
        },
      };
    }
    return result;
  }
  if (precondition) {
    throw new Error("Conditional legacy writes require atomic storage support");
  }
  const writeResult = await storage.writeEnvelope(envelope);
  await indexWrittenEnvelope(storage, {
    ...entry,
    path: writeResult.relativePath,
    sizeBytes: entry.sizeBytes ?? writeResult.sizeBytes,
  });
  return { ok: true, writeResult };
}

export interface IngestDataContractInput {
  storage: DataStoragePort;
  scopeParam: string;
  body: unknown;
  collectedAt: string;
  status: "stored" | "syncing";
  /**
   * Builder attribution for delegated (write-session) writes. When present,
   * it is stamped into the envelope `data` under the reserved `$writtenBy`
   * key so it travels through the unchanged encrypt/upload/register path.
   * Owner writes pass nothing and the envelope is byte-identical to today.
   */
  attribution?: WriterAttribution;
  /**
   * Validated lineage for a derivative write (see lineage/lineage.ts). When
   * present it is stamped into the envelope `data` under the reserved
   * `$lineage` key, next to `$writtenBy`; absent = root record, envelope
   * unchanged.
   */
  lineage?: StoredLineage;
  /** See `IndexEntry.afterTombstoneVersion`. */
  afterTombstoneVersion?: number | null;
  precondition?: LegacyPrecondition;
  producer?: LegacyProducer;
  producerProvenance?: LegacyProducerProvenance;
}

export interface IngestDataContractResult {
  ok: true;
  scope: string;
  collectedAt: string;
  response: {
    scope: string;
    collectedAt: string;
    status: "stored" | "syncing";
    /** Echoed for a derivative write: the accepted, normalized sources. */
    lineage?: { sources: `0x${string}`[] };
  };
  writeResult: WriteResult;
}

export interface IngestBinaryDataContractInput {
  storage: DataStoragePort;
  scopeParam: string;
  bytes: Uint8Array;
  mimeType: string;
  filename?: string;
  /** Free-form caller metadata (e.g. a description) stored alongside the file. */
  metadata?: unknown;
  collectedAt: string;
  status: "stored" | "syncing";
  /** Builder attribution for delegated writes (see IngestDataContractInput). */
  attribution?: WriterAttribution;
  /** Validated lineage for a derivative write (see IngestDataContractInput). */
  lineage?: StoredLineage;
  /** See `IndexEntry.afterTombstoneVersion`. */
  afterTombstoneVersion?: number | null;
  precondition?: LegacyPrecondition;
}

export interface DeleteDataScopeContractInput {
  storage: DataStoragePort;
  scopeParam: string;
}

export interface DeleteDataScopeContractResult {
  ok: true;
  deletedCount: number;
}

function invalidScope(message: string): DataContractError {
  return {
    ok: false,
    status: 400,
    body: {
      error: "INVALID_SCOPE",
      message,
    },
  };
}

export function parseDataScopeContract(
  scopeParam: string,
): { ok: true; scope: string } | DataContractError {
  const scopeResult = ScopeSchema.safeParse(scopeParam);
  if (!scopeResult.success) {
    return invalidScope(
      scopeResult.error.issues[0]?.message ?? "Invalid scope",
    );
  }
  return { ok: true, scope: scopeResult.data };
}

function normalizeLimit(value: number | undefined): number {
  return value ?? 20;
}

function normalizeOffset(value: number | undefined): number {
  return value ?? 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const VISIBILITY_PAGE_SIZE = 200;

export async function listDataScopesContract(
  input: ListDataScopesContractInput,
): Promise<ListDataScopesContractResult> {
  const limit = normalizeLimit(input.limit);
  const offset = normalizeOffset(input.offset);
  let page: ScopeSummary[];
  let total: number;
  if (input.isVisible) {
    // Filtered listing: walk every scope so the page and the total both
    // describe the visible set (the index cannot filter by tombstone).
    const visible: ScopeSummary[] = [];
    for (let scan = 0; ; scan += VISIBILITY_PAGE_SIZE) {
      const batch = input.storage.listScopes({
        scopePrefix: input.scopePrefix,
        limit: VISIBILITY_PAGE_SIZE,
        offset: scan,
      });
      for (const summary of batch.scopes) {
        const latest = input.storage.findEntry({
          scope: summary.scope,
          at: summary.latestCollectedAt,
        });
        if (!latest || (await input.isVisible(summary.scope, latest))) {
          visible.push(summary);
        }
      }
      if (batch.scopes.length < VISIBILITY_PAGE_SIZE) break;
    }
    total = visible.length;
    page = visible.slice(offset, offset + limit);
  } else {
    const result = input.storage.listScopes({
      scopePrefix: input.scopePrefix,
      limit,
      offset,
    });
    page = result.scopes;
    total = result.total;
  }
  const scopes = await Promise.all(
    page.map(async (summary) => {
      const entry = input.storage.findEntry({
        scope: summary.scope,
        at: summary.latestCollectedAt,
      });
      if (!entry) {
        return summary;
      }
      const hasBlocks =
        typeof input.storage.hasScopeBlocks === "function"
          ? await input.storage.hasScopeBlocks(
              summary.scope,
              summary.latestCollectedAt,
            )
          : false;
      return {
        ...summary,
        dataStatus: hasBlocks ? ("ready" as const) : ("indexing" as const),
        sizeBytes: entry.sizeBytes,
      };
    }),
  );
  return {
    ok: true,
    response: {
      scopes,
      total,
      limit,
      offset,
    },
  };
}

export async function listDataVersionsContract(
  input: ListDataVersionsContractInput,
): Promise<ListDataVersionsContractResult | DataContractError> {
  const scopeResult = parseDataScopeContract(input.scopeParam);
  if (!scopeResult.ok) return scopeResult;

  const limit = normalizeLimit(input.limit);
  const offset = normalizeOffset(input.offset);
  let page: IndexEntry[];
  let total: number;
  if (input.isVisible) {
    const visible: IndexEntry[] = [];
    for (let scan = 0; ; scan += VISIBILITY_PAGE_SIZE) {
      const batch = input.storage.listVersions(scopeResult.scope, {
        limit: VISIBILITY_PAGE_SIZE,
        offset: scan,
      });
      for (const entry of batch) {
        if (await input.isVisible(scopeResult.scope, entry)) {
          visible.push(entry);
        }
      }
      if (batch.length < VISIBILITY_PAGE_SIZE) break;
    }
    total = visible.length;
    page = visible.slice(offset, offset + limit);
  } else {
    page = input.storage.listVersions(scopeResult.scope, { limit, offset });
    total = input.storage.countVersions(scopeResult.scope);
  }
  return {
    ok: true,
    scope: scopeResult.scope,
    response: {
      scope: scopeResult.scope,
      versions: page.map((entry) => ({
        fileId: entry.fileId,
        schemaId: entry.schemaId,
        collectedAt: entry.collectedAt,
        version: entry.casRevision ?? entry.version,
        producer: entry.producer ?? null,
        producer_provenance: entry.producerProvenance
          ? (JSON.parse(entry.producerProvenance) as LegacyProducerProvenance)
          : null,
      })),
      total,
      limit,
      offset,
    },
  };
}

export async function readDataContract(
  input: ReadDataContractInput,
): Promise<ReadDataContractResult | DataContractError> {
  const scopeResult = parseDataScopeContract(input.scopeParam);
  if (!scopeResult.ok) return scopeResult;

  const entry = input.storage.findEntry({
    scope: scopeResult.scope,
    fileId: input.fileId,
    at: input.at,
  });

  if (!entry) {
    return {
      ok: false,
      status: 404,
      body: {
        error: "NOT_FOUND",
        message: `No data found for scope "${scopeResult.scope}"`,
      },
    };
  }

  // An index row whose backing file is gone is a 404, not a 500. The row
  // says the version exists — `/versions` lists it and a client may name it
  // explicitly — so the honest answer is "that version is not retrievable",
  // with a code distinct from `NOT_FOUND` (nothing indexed) so an operator
  // can tell a dangling row from an empty scope without reading a stack
  // trace. Before this it escaped as a bare INTERNAL_ERROR 500.
  let envelope;
  try {
    envelope = await input.storage.readEnvelope(
      scopeResult.scope,
      entry.collectedAt,
    );
  } catch (err) {
    if (!isMissingFileError(err)) throw err;
    return {
      ok: false,
      status: 404,
      body: {
        error: "DATA_FILE_MISSING",
        message: `Indexed data for scope "${scopeResult.scope}" is no longer on disk`,
      },
    };
  }

  return {
    ok: true,
    scope: scopeResult.scope,
    envelope,
  };
}

/**
 * A read that failed because the bytes are not there — as opposed to any
 * other storage fault, which stays a 500 because it is genuinely our bug.
 * Matched on the Node error code rather than the message so it survives
 * locale and wording changes; `ENOTDIR` is the same condition reached
 * through a removed scope directory.
 */
function isMissingFileError(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const code = (err as { code?: unknown }).code;
  return code === "ENOENT" || code === "ENOTDIR";
}

export async function ingestDataContract(
  input: IngestDataContractInput,
): Promise<IngestDataContractResult | DataContractError> {
  const scopeResult = parseDataScopeContract(input.scopeParam);
  if (!scopeResult.ok) return scopeResult;

  if (!isRecord(input.body)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message: "Request body must be a JSON object",
      },
    };
  }

  // The attribution key is server-stamped, never caller-supplied: a payload
  // that carries it could forge (or shadow) an attribution. That holds for
  // every JSON ingest, owner writes included, so consumers can trust that a
  // stored $writtenBy was always produced by the server.
  if (hasReservedWriterKey(input.body)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message: "Request body must not contain the reserved $writtenBy key",
      },
    };
  }
  // Same rule for the lineage mirror: `$lineage` is what the server
  // validated, so a caller must not be able to plant or shadow it.
  if (hasReservedLineageKey(input.body)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message: "Request body must not contain the reserved $lineage key",
      },
    };
  }

  const envelope = {
    ...createDataFileEnvelope(
      scopeResult.scope,
      input.collectedAt,
      stampServerKeys(input.body, input),
    ),
    ...(input.producer ? { producer: input.producer } : {}),
    ...(input.producerProvenance
      ? { producer_provenance: input.producerProvenance }
      : {}),
  };
  const committed = await commitWrittenEnvelope(
    input.storage,
    envelope,
    {
      fileId: null,
      schemaId: null,
      scope: scopeResult.scope,
      collectedAt: input.collectedAt,
      afterTombstoneVersion: input.afterTombstoneVersion ?? null,
      producer: input.producer ?? null,
      producerProvenance: input.producerProvenance
        ? JSON.stringify(input.producerProvenance)
        : null,
    },
    input.precondition,
  );
  if (!committed.ok) return committed;
  const { writeResult } = committed;
  try {
    await writeBlockSidecars(input.storage, envelope);
  } catch {
    // Best-effort bounded sidecars: raw envelope storage remains the source of truth.
  }

  return {
    ok: true,
    scope: scopeResult.scope,
    collectedAt: input.collectedAt,
    response: ingestResponse(scopeResult.scope, input),
    writeResult,
  };
}

/**
 * Stamp the server-owned reserved keys (`$writtenBy`, `$lineage`) into the
 * record about to be stored. Both are absent from owner root writes, so such
 * an envelope stays byte-identical to today's.
 */
function stampServerKeys(
  data: Record<string, unknown>,
  input: Pick<IngestDataContractInput, "attribution" | "lineage">,
): Record<string, unknown> {
  let stamped = data;
  if (input.lineage) stamped = stampLineage(stamped, input.lineage);
  if (input.attribution) {
    stamped = stampWriterAttribution(stamped, input.attribution);
  }
  return stamped;
}

function ingestResponse(
  scope: string,
  input: Pick<IngestDataContractInput, "collectedAt" | "status" | "lineage">,
): IngestDataContractResult["response"] {
  return {
    scope,
    collectedAt: input.collectedAt,
    status: input.status,
    ...(input.lineage ? { lineage: { sources: input.lineage.sources } } : {}),
  };
}

/**
 * Ingest unstructured/binary data (e.g. a PDF). The bytes are hashed and
 * base64-encoded into a binary DataFileEnvelope, then written and indexed
 * exactly like JSON ingest — so the downstream encrypt/upload/register path is
 * unchanged. Unlike JSON ingest, the body is raw bytes (not a JSON object) and
 * `schemaId` may be absent (the caller decides whether to auto-register one).
 */
export async function ingestBinaryDataContract(
  input: IngestBinaryDataContractInput,
): Promise<IngestDataContractResult | DataContractError> {
  const scopeResult = parseDataScopeContract(input.scopeParam);
  if (!scopeResult.ok) return scopeResult;

  if (input.bytes.length === 0) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message: "Request body must not be empty",
      },
    };
  }

  // The caller's metadata object is stored verbatim inside the record, so
  // the reserved server-stamped keys are refused there too (same rule as a
  // JSON body): a reader must never find a caller-planted $lineage or
  // $writtenBy anywhere in what the server wrote.
  if (
    isRecord(input.metadata) &&
    (hasReservedWriterKey(input.metadata) ||
      hasReservedLineageKey(input.metadata))
  ) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message:
          "X-Vana-Metadata must not contain the reserved $lineage or $writtenBy keys",
      },
    };
  }

  const contentHash = await sha256Hex(input.bytes);
  const data = buildBinaryEnvelopeData({
    bytes: input.bytes,
    mimeType: input.mimeType,
    filename: input.filename,
    contentHash,
    metadata: input.metadata,
  });

  const envelope = createDataFileEnvelope(
    scopeResult.scope,
    input.collectedAt,
    stampServerKeys(data, input),
  );
  const committed = await commitWrittenEnvelope(
    input.storage,
    envelope,
    {
      fileId: null,
      schemaId: null,
      scope: scopeResult.scope,
      collectedAt: input.collectedAt,
      sizeBytes: input.bytes.length,
      afterTombstoneVersion: input.afterTombstoneVersion ?? null,
    },
    input.precondition,
  );
  if (!committed.ok) return committed;
  const { writeResult } = committed;
  try {
    await writeBlockSidecars(input.storage, envelope);
  } catch {
    // Best-effort bounded sidecars: raw envelope storage remains the source of truth.
  }

  return {
    ok: true,
    scope: scopeResult.scope,
    collectedAt: input.collectedAt,
    response: ingestResponse(scopeResult.scope, input),
    writeResult,
  };
}

export async function deleteDataScopeContract(
  input: DeleteDataScopeContractInput,
): Promise<DeleteDataScopeContractResult | DataContractError> {
  const scopeResult = parseDataScopeContract(input.scopeParam);
  if (!scopeResult.ok) return scopeResult;

  return {
    ok: true,
    deletedCount: await input.storage.deleteScope(scopeResult.scope),
  };
}

async function writeBlockSidecars(
  storage: DataStoragePort,
  envelope: DataFileEnvelope,
): Promise<void> {
  if (!storage.writeBlockManifest) return;

  const built = await buildDataBlocksAsync({
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    schemaId: envelope.schemaId,
    content: envelope,
  });
  await storage.writeBlockManifest(
    envelope.scope,
    envelope.collectedAt,
    built.manifest,
    built.blocks,
  );
}
