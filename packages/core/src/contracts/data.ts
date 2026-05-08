import { type DataStoragePort } from "../ports/index.js";
import {
  createDataFileEnvelope,
  type DataFileEnvelope,
} from "../schemas/data-file.js";
import { ScopeSchema } from "../scopes/index.js";
import { type WriteResult } from "../storage/hierarchy/index.js";

export type DataContractErrorCode =
  | "INVALID_SCOPE"
  | "INVALID_BODY"
  | "NOT_FOUND";

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
  schemaUrl?: string;
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

export function listDataScopesContract(
  input: ListDataScopesContractInput,
): ListDataScopesContractResult {
  const limit = normalizeLimit(input.limit);
  const offset = normalizeOffset(input.offset);
  const result = input.storage.listScopes({
    scopePrefix: input.scopePrefix,
    limit,
    offset,
  });
  return {
    ok: true,
    response: {
      scopes: result.scopes,
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
    input.schemaUrl,
  );
  const writeResult = await input.storage.writeEnvelope(envelope);
  input.storage.insertEntry({
    fileId: null,
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
