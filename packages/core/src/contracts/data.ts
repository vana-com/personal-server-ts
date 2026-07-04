import { type DataStoragePort } from "../ports/index.js";
import {
  createDataFileEnvelope,
  ScopeSchema,
  type DataFileEnvelope,
} from "@opendatalabs/vana-sdk/browser";
import { type WriteResult } from "../storage/hierarchy/index.js";
import { buildBinaryEnvelopeData, sha256Hex } from "./binary.js";
import { buildDataBlocksAsync } from "../storage/blocks/build.js";

export type DataContractErrorCode =
  "INVALID_SCOPE" | "INVALID_BODY" | "NOT_FOUND";

export interface DataContractErrorBody {
  error: DataContractErrorCode;
  message: string;
}

export interface DataContractError {
  ok: false;
  status: 400 | 404;
  body: DataContractErrorBody;
}

export interface ListDataScopesContractInput {
  storage: DataStoragePort;
  scopePrefix?: string;
  limit?: number;
  offset?: number;
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

export interface IngestDataContractInput {
  storage: DataStoragePort;
  scopeParam: string;
  body: unknown;
  collectedAt: string;
  status: "stored" | "syncing";
}

export interface IngestDataContractResult {
  ok: true;
  scope: string;
  collectedAt: string;
  response: {
    scope: string;
    collectedAt: string;
    status: "stored" | "syncing";
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

export async function listDataScopesContract(
  input: ListDataScopesContractInput,
): Promise<ListDataScopesContractResult> {
  const limit = normalizeLimit(input.limit);
  const offset = normalizeOffset(input.offset);
  const result = input.storage.listScopes({
    scopePrefix: input.scopePrefix,
    limit,
    offset,
  });
  const scopes = await Promise.all(
    result.scopes.map(async (summary) => {
      const entry = input.storage.findEntry({
        scope: summary.scope,
        at: summary.latestCollectedAt,
      });
      if (!entry) {
        return summary;
      }
      const hasBlocks =
        typeof input.storage.canReadScopeBlocks === "function"
          ? await input.storage.canReadScopeBlocks(
              summary.scope,
              summary.latestCollectedAt,
            )
          : typeof input.storage.hasScopeBlocks === "function"
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
      total: result.total,
      limit,
      offset,
    },
  };
}

export function listDataVersionsContract(
  input: ListDataVersionsContractInput,
): ListDataVersionsContractResult | DataContractError {
  const scopeResult = parseDataScopeContract(input.scopeParam);
  if (!scopeResult.ok) return scopeResult;

  const limit = normalizeLimit(input.limit);
  const offset = normalizeOffset(input.offset);
  const entries = input.storage.listVersions(scopeResult.scope, {
    limit,
    offset,
  });
  return {
    ok: true,
    scope: scopeResult.scope,
    response: {
      scope: scopeResult.scope,
      versions: entries.map((entry) => ({
        fileId: entry.fileId,
        schemaId: entry.schemaId,
        collectedAt: entry.collectedAt,
      })),
      total: input.storage.countVersions(scopeResult.scope),
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

  return {
    ok: true,
    scope: scopeResult.scope,
    envelope: await input.storage.readEnvelope(
      scopeResult.scope,
      entry.collectedAt,
    ),
  };
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

  const envelope = createDataFileEnvelope(
    scopeResult.scope,
    input.collectedAt,
    input.body,
  );
  const writeResult = await input.storage.writeEnvelope(envelope);
  try {
    await writeBlockSidecars(input.storage, envelope);
  } catch {
    // Best-effort bounded sidecars: raw envelope storage remains the source of truth.
  }
  await input.storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: writeResult.relativePath,
    scope: scopeResult.scope,
    collectedAt: input.collectedAt,
    sizeBytes: writeResult.sizeBytes,
  });

  return {
    ok: true,
    scope: scopeResult.scope,
    collectedAt: input.collectedAt,
    response: {
      scope: scopeResult.scope,
      collectedAt: input.collectedAt,
      status: input.status,
    },
    writeResult,
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
    data,
  );
  const writeResult = await input.storage.writeEnvelope(envelope);
  try {
    await writeBlockSidecars(input.storage, envelope);
  } catch {
    // Best-effort bounded sidecars: raw envelope storage remains the source of truth.
  }
  await input.storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: writeResult.relativePath,
    scope: scopeResult.scope,
    collectedAt: input.collectedAt,
    sizeBytes: input.bytes.length,
  });

  return {
    ok: true,
    scope: scopeResult.scope,
    collectedAt: input.collectedAt,
    response: {
      scope: scopeResult.scope,
      collectedAt: input.collectedAt,
      status: input.status,
    },
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
