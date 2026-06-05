export type SyncFailureStage =
  | "download"
  | "openpgp_parse"
  | "decrypt"
  | "json_parse"
  | "envelope_validate"
  | "block_build"
  | "unknown";

export type SyncPayloadKind =
  | "openpgp"
  | "json"
  | "html"
  | "empty"
  | "binary"
  | "unknown";

export type SyncFailureDisposition = "deterministic" | "transient";

export interface SyncFileIssue {
  fileId: string;
  schemaId?: string;
  scope?: string;
  stage: SyncFailureStage;
  errorClass: string;
  message: string;
  payloadKind?: SyncPayloadKind;
  encryptedSizeBytes?: number;
  syncRunId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  disposition: SyncFailureDisposition;
  retryable: boolean;
}

export interface SyncDownloadFailureTelemetryEvent {
  event: "sync.download.failure";
  syncRunId: string;
  fileId: string;
  schemaId?: string;
  scope?: string;
  stage: SyncFailureStage;
  payloadKind?: SyncPayloadKind;
  encryptedSizeBytes?: number;
  errorClass: string;
  disposition: SyncFailureDisposition;
  retryable: boolean;
  appVersion?: string;
  personalServerVersion?: string;
  storageBackend?: string;
}

export interface ClassifySyncFailureInput {
  error: unknown;
  fileId: string;
  syncRunId: string;
  stage?: SyncFailureStage;
  schemaId?: string;
  scope?: string;
  payloadKind?: SyncPayloadKind;
  encryptedSizeBytes?: number;
  now?: Date;
  appVersion?: string;
  personalServerVersion?: string;
  storageBackend?: string;
}

export interface ClassifiedSyncFailure {
  issue: SyncFileIssue;
  telemetry: SyncDownloadFailureTelemetryEvent;
}

const DETERMINISTIC_STAGES = new Set<SyncFailureStage>([
  "openpgp_parse",
  "decrypt",
  "json_parse",
  "envelope_validate",
  "block_build",
]);

const TRANSIENT_STATUS_CODES = new Set([408, 425, 429, 500, 502, 503, 504]);

export function classifySyncFailure(
  input: ClassifySyncFailureInput,
): ClassifiedSyncFailure {
  const stage = input.stage ?? inferStage(input.error);
  const disposition = classifyDisposition(input.error, stage);
  const retryable = disposition === "transient";
  const timestamp = (input.now ?? new Date()).toISOString();
  const errorClass = getErrorClass(input.error);
  const message = getSafeIssueMessage(stage, disposition);

  const issue: SyncFileIssue = {
    fileId: input.fileId,
    schemaId: input.schemaId,
    scope: input.scope,
    stage,
    errorClass,
    message,
    payloadKind: input.payloadKind,
    encryptedSizeBytes: input.encryptedSizeBytes,
    syncRunId: input.syncRunId,
    firstSeenAt: timestamp,
    lastSeenAt: timestamp,
    disposition,
    retryable,
  };

  const telemetry: SyncDownloadFailureTelemetryEvent = {
    event: "sync.download.failure",
    syncRunId: input.syncRunId,
    fileId: input.fileId,
    schemaId: input.schemaId,
    scope: input.scope,
    stage,
    payloadKind: input.payloadKind,
    encryptedSizeBytes: input.encryptedSizeBytes,
    errorClass,
    disposition,
    retryable,
    appVersion: input.appVersion,
    personalServerVersion: input.personalServerVersion,
    storageBackend: input.storageBackend,
  };

  return { issue, telemetry };
}

export function inferPayloadKind(bytes: Uint8Array | string): SyncPayloadKind {
  const text =
    typeof bytes === "string"
      ? bytes
      : new TextDecoder().decode(bytes.slice(0, 256));
  const trimmed = text.trimStart();

  if (trimmed.length === 0) return "empty";
  if (trimmed.startsWith("-----BEGIN PGP MESSAGE-----")) return "openpgp";
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json";
  if (/^<!doctype html\b/i.test(trimmed) || /^<html[\s>]/i.test(trimmed)) {
    return "html";
  }
  if (containsBinaryByte(bytes)) return "binary";

  return "unknown";
}

function classifyDisposition(
  error: unknown,
  stage: SyncFailureStage,
): SyncFailureDisposition {
  if (stage === "download") {
    const status =
      getNumericProperty(error, "status") ??
      getNumericProperty(error, "statusCode");
    if (status !== undefined) {
      return TRANSIENT_STATUS_CODES.has(status) ? "transient" : "deterministic";
    }
    return "transient";
  }

  if (DETERMINISTIC_STAGES.has(stage)) {
    return "deterministic";
  }

  return "transient";
}

function inferStage(error: unknown): SyncFailureStage {
  if (error instanceof SyntaxError) return "json_parse";

  const name = getStringProperty(error, "name").toLowerCase();
  const message = getRawMessage(error).toLowerCase();

  if (name === "zoderror" || message.includes("zod"))
    return "envelope_validate";
  if (message.includes("decrypt") || message.includes("session key"))
    return "decrypt";
  if (message.includes("openpgp") || message.includes("pgp message")) {
    return "openpgp_parse";
  }

  return "unknown";
}

function getErrorClass(error: unknown): string {
  const name = getStringProperty(error, "name");
  if (name.length > 0) return name;
  if (error instanceof Error && error.constructor.name.length > 0) {
    return error.constructor.name;
  }
  return typeof error;
}

function getRawMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  const message = getStringProperty(error, "message");
  return message.length > 0 ? message : "Unknown sync failure";
}

function getStringProperty(value: unknown, key: string): string {
  if (typeof value !== "object" || value === null || !(key in value)) return "";
  const property = (value as Record<string, unknown>)[key];
  return typeof property === "string" ? property : "";
}

function getNumericProperty(value: unknown, key: string): number | undefined {
  if (typeof value !== "object" || value === null || !(key in value)) {
    return undefined;
  }
  const property = (value as Record<string, unknown>)[key];
  return typeof property === "number" ? property : undefined;
}

function containsBinaryByte(bytes: Uint8Array | string): boolean {
  if (typeof bytes === "string") return false;
  return bytes.some((byte) => byte === 0 || (byte < 0x09 && byte !== 0x07));
}

function getSafeIssueMessage(
  stage: SyncFailureStage,
  disposition: SyncFailureDisposition,
): string {
  switch (stage) {
    case "download":
      return disposition === "transient"
        ? "Download failed with a retryable storage or network error"
        : "Download failed with a non-retryable storage response";
    case "openpgp_parse":
      return "Encrypted payload could not be parsed as an OpenPGP message";
    case "decrypt":
      return "Encrypted payload could not be decrypted";
    case "json_parse":
      return "Decrypted payload could not be parsed as JSON";
    case "envelope_validate":
      return "Decrypted JSON did not match the expected envelope shape";
    case "block_build":
      return "Envelope was stored, but bounded block build failed";
    case "unknown":
      return "Sync file failed at an unknown stage";
  }
}
