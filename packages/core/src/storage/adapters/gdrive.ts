import {
  readBoundedResponse,
  type ByteBudget,
} from "../../additions/budget.js";
import { parseRetryAfterHeader } from "../../stream-sync/storage-retry.js";
import {
  StorageAuthRevokedError,
  StorageQuotaExceededError,
  StoredBlobConflictError,
  type BoundedStorageAdapter,
  type StorageCredentialProvider,
} from "./interface.js";
import { createRateLimitPolicyFeed } from "./rate-limit-policy.js";

const DEFAULT_GOOGLE_API_BASE_URL = "https://www.googleapis.com";
const MULTIPART_UPLOAD_LIMIT_BYTES = 5 * 1024 * 1024;
const GDRIVE_PROVIDER = "gdrive";
const ENCODED_PATH_SEPARATOR_PATTERN = /%(?:2f|5c)/i;

const QUOTA_ERROR_REASONS = new Set([
  "storageQuotaExceeded",
  "quotaExceeded",
  "teamDriveFileLimitExceeded",
]);

const RATE_LIMIT_REASONS = new Set([
  "rateLimitExceeded",
  "userRateLimitExceeded",
  "sharingRateLimitExceeded",
  "dailyLimitExceeded",
]);

const AUTH_REVOKED_REASONS = new Set([
  "authError",
  "insufficientPermissions",
  "appNotAuthorizedToFile",
  "domainPolicy",
]);

interface DriveFileRecord {
  id: string;
  name?: string;
  size?: string;
  sha256Checksum?: string;
  createdTime?: string;
}

interface DriveListResponse {
  files?: DriveFileRecord[];
  nextPageToken?: string;
}

export interface GoogleDriveStorageAdapterParams {
  /** Drive folder ID of the user's private "Vana" folder. */
  folderId: string;
  /** Host-owned short-lived access-token broker (never receives refresh token). */
  credentials: StorageCredentialProvider;
  /**
   * Optional protocol chain id used to namespace blob keys inside the Drive
   * folder so separate networks (e.g. Moksha 14800 vs Mainnet 1480) cannot
   * collide on identical `${scope}/${version}` keys.
   */
  chainId?: number;
  /** Optional Drive API base URL (defaults to https://www.googleapis.com). */
  apiBaseUrl?: string;
  /** Optional custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
}

/**
 * Runtime-neutral Google Drive `StorageAdapter` (pure Web Fetch + Web Crypto,
 * zero Node built-ins) so one implementation serves Desktop (PS Node), Web
 * (PS Lite), and Mobile.
 *
 * Contract guarantees:
 * - Private blobs only (`drive.file` scope; never calls `/permissions`).
 * - `urlForKey(key)` is synchronous and the exact inverse of `upload(key, data)`:
 *   `gdrive://<folderId>/[chains/<chainId>/]<encodeURIComponent-per-segment(key)>`.
 * - Write-once keys: identical bytes return idempotently; different bytes throw
 *   `StoredBlobConflictError(key)` with the stored bytes untouched. Concurrent
 *   multi-device races are resolved deterministically by earliest `createdTime`
 *   (tie-broken by `id`), deleting the losing duplicate.
 */
export function createGoogleDriveStorageAdapter(
  params: GoogleDriveStorageAdapterParams,
): BoundedStorageAdapter {
  const folderId = params.folderId.trim();
  if (!folderId || folderId.includes("/") || folderId.includes("\\")) {
    throw new Error("Google Drive folderId must be a non-empty identifier");
  }
  if (
    params.chainId !== undefined &&
    (!Number.isSafeInteger(params.chainId) || params.chainId < 0)
  ) {
    throw new Error("Google Drive chainId must be a non-negative integer");
  }
  const chainSegment =
    params.chainId !== undefined ? `chains/${params.chainId}/` : "";
  const apiBase = (params.apiBaseUrl ?? DEFAULT_GOOGLE_API_BASE_URL).replace(
    /\/+$/,
    "",
  );
  const feed = createRateLimitPolicyFeed(params.fetch);
  const urlPrefix = `gdrive://${folderId}/${chainSegment}`;

  // In-memory cache of logical key -> resolved Drive file metadata.
  const fileCache = new Map<string, { fileId: string; sha256?: string }>();
  // Per-key in-process write lock so concurrent uploads of one key serialize.
  const keyLocks = new Map<string, Promise<void>>();

  async function withKeyLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = keyLocks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => next);
    keyLocks.set(key, tail);
    await previous;
    try {
      return await fn();
    } finally {
      release();
      if (keyLocks.get(key) === tail) {
        keyLocks.delete(key);
      }
    }
  }

  function urlForKey(key: string): string {
    if (!key) {
      throw new Error("Storage key must be non-empty");
    }
    const subpath = key
      .split("/")
      .map((segment) => encodeURIComponent(segment))
      .join("/");
    return `${urlPrefix}${subpath}`;
  }

  function keyFromUrl(url: string): string {
    if (!url.startsWith(urlPrefix)) {
      throw new Error("Blob URL does not match configured Google Drive folder");
    }
    const rest = url.slice(urlPrefix.length);
    if (!rest) {
      throw new Error("Blob URL is missing storage key");
    }
    const segments = rest.split("/");
    for (const seg of segments) {
      if (!seg || ENCODED_PATH_SEPARATOR_PATTERN.test(seg)) {
        throw new Error("Blob URL contains an invalid key segment");
      }
    }
    return segments.map((seg) => decodeURIComponent(seg)).join("/");
  }

  function driveFileNameForKey(key: string): string {
    return encodeURIComponent(`${chainSegment}${key}`);
  }

  async function acquireToken(
    forceRefresh: boolean,
    signal?: AbortSignal,
  ): Promise<string> {
    signal?.throwIfAborted();
    try {
      const token = await params.credentials.getAccessToken({
        provider: GDRIVE_PROVIDER,
        forceRefresh,
        signal,
      });
      if (!token) {
        const message = "Google Drive access token is missing";
        params.credentials.onAuthRevoked?.(GDRIVE_PROVIDER, message);
        throw new StorageAuthRevokedError(GDRIVE_PROVIDER, message);
      }
      return token;
    } catch (err) {
      if (err instanceof StorageAuthRevokedError) {
        params.credentials.onAuthRevoked?.(GDRIVE_PROVIDER, err.message);
        throw err;
      }
      if (isAbortError(err)) throw err;
      if (isRevokedCredentialError(err)) {
        const message =
          err instanceof Error ? err.message : "Google Drive access revoked";
        params.credentials.onAuthRevoked?.(GDRIVE_PROVIDER, message);
        throw new StorageAuthRevokedError(GDRIVE_PROVIDER, message, {
          cause: err,
        });
      }
      throw err;
    }
  }

  async function authorizedFetch(
    url: string,
    init: RequestInit,
    signal?: AbortSignal,
  ): Promise<Response> {
    const runWithToken = async (token: string): Promise<Response> => {
      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${token}`);
      return feed.fetch(url, {
        ...init,
        headers,
        cache: "no-store",
        ...(signal ? { signal } : {}),
      });
    };

    const token = await acquireToken(false, signal);
    let response = await runWithToken(token);
    if (response.status === 401) {
      await response.body?.cancel();
      const refreshed = await acquireToken(true, signal);
      response = await runWithToken(refreshed);
      if (response.status === 401) {
        await response.body?.cancel();
        const message =
          "Google Drive rejected the refreshed access token (401)";
        params.credentials.onAuthRevoked?.(GDRIVE_PROVIDER, message);
        throw new StorageAuthRevokedError(GDRIVE_PROVIDER, message);
      }
    }
    return response;
  }

  async function classifyHttpError(
    response: Response,
    operation: "upload" | "download" | "probe" | "delete" | "list",
  ): Promise<Error> {
    const status = response.status;
    const retryAfterMs = parseRetryAfterHeader(
      response.headers.get("retry-after"),
      Date.now(),
    );
    const bodyText = await response.text().catch(() => "");
    const reason = extractDriveErrorReason(bodyText);

    if (
      status === 401 ||
      (status === 403 && reason && AUTH_REVOKED_REASONS.has(reason))
    ) {
      const message = `Google Drive ${operation} unauthorized (${status}${reason ? `: ${reason}` : ""})`;
      params.credentials.onAuthRevoked?.(GDRIVE_PROVIDER, message);
      return new StorageAuthRevokedError(GDRIVE_PROVIDER, message);
    }
    if (status === 403 && reason && QUOTA_ERROR_REASONS.has(reason)) {
      const message =
        "Your Google Drive is full. Free up space or choose another storage option.";
      params.credentials.onQuotaExceeded?.(GDRIVE_PROVIDER, message);
      return new StorageQuotaExceededError(GDRIVE_PROVIDER, message);
    }
    if (
      status === 429 ||
      status === 503 ||
      (status === 403 && reason && RATE_LIMIT_REASONS.has(reason))
    ) {
      const effectiveStatus = status === 403 ? 429 : status;
      return Object.assign(
        new Error(
          `gdrive ${operation} failed: ${effectiveStatus} ${reason ?? response.statusText}`,
        ),
        {
          status: effectiveStatus,
          ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
        },
      );
    }
    return Object.assign(
      new Error(
        `gdrive ${operation} failed: ${status} ${reason ?? response.statusText}`,
      ),
      { status },
    );
  }

  async function listMatchingFiles(
    key: string,
    signal?: AbortSignal,
  ): Promise<DriveFileRecord[]> {
    const fileName = driveFileNameForKey(key);
    const query = `name = '${escapeDriveQuery(fileName)}' and '${escapeDriveQuery(folderId)}' in parents and trashed = false`;
    const baseParams = {
      q: query,
      spaces: "drive",
      orderBy: "createdTime asc",
      pageSize: "20",
      fields: "nextPageToken,files(id,name,size,sha256Checksum,createdTime)",
    };
    const files: DriveFileRecord[] = [];
    const seenTokens = new Set<string>();
    let pageToken: string | undefined;
    do {
      const qs = new URLSearchParams(baseParams);
      if (pageToken !== undefined) qs.set("pageToken", pageToken);
      const res = await authorizedFetch(
        `${apiBase}/drive/v3/files?${qs.toString()}`,
        { method: "GET" },
        signal,
      );
      if (!res.ok) {
        throw await classifyHttpError(res, "list");
      }
      const payload = (await res.json()) as DriveListResponse;
      for (const f of payload.files ?? []) {
        if (typeof f.id === "string") files.push(f);
      }
      pageToken = payload.nextPageToken || undefined;
      if (pageToken !== undefined) {
        if (seenTokens.has(pageToken)) {
          throw new Error("gdrive list failed: repeated page token");
        }
        seenTokens.add(pageToken);
      }
    } while (pageToken !== undefined);
    // Deterministic tie-break when two concurrent uploads share identical createdTime.
    files.sort((a, b) => {
      const ta = a.createdTime ?? "";
      const tb = b.createdTime ?? "";
      if (ta !== tb) return ta < tb ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
    return files;
  }

  async function resolveFileId(
    key: string,
    signal?: AbortSignal,
  ): Promise<string | null> {
    const cached = fileCache.get(key);
    if (cached) return cached.fileId;
    const files = await listMatchingFiles(key, signal);
    const winner = files[0];
    if (!winner) return null;
    fileCache.set(key, { fileId: winner.id, sha256: winner.sha256Checksum });
    return winner.id;
  }

  async function downloadFileBytes(
    fileId: string,
    signal?: AbortSignal,
  ): Promise<Response> {
    return authorizedFetch(
      `${apiBase}/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`,
      { method: "GET" },
      signal,
    );
  }

  async function sha256OfExistingFile(
    file: DriveFileRecord,
    signal?: AbortSignal,
  ): Promise<string> {
    if (file.sha256Checksum && /^[0-9a-f]{64}$/i.test(file.sha256Checksum)) {
      return file.sha256Checksum.toLowerCase();
    }
    const res = await downloadFileBytes(file.id, signal);
    if (!res.ok) {
      throw await classifyHttpError(res, "download");
    }
    const bytes = new Uint8Array(await res.arrayBuffer());
    return sha256Hex(bytes);
  }

  async function deleteFileById(
    fileId: string,
    signal?: AbortSignal,
  ): Promise<boolean> {
    const res = await authorizedFetch(
      `${apiBase}/drive/v3/files/${encodeURIComponent(fileId)}`,
      { method: "DELETE" },
      signal,
    );
    if (res.status === 404) {
      await res.body?.cancel();
      return false;
    }
    if (!res.ok) {
      throw await classifyHttpError(res, "delete");
    }
    await res.body?.cancel();
    return true;
  }

  async function uploadMultipart(
    metadata: Record<string, unknown>,
    data: Uint8Array,
    signal?: AbortSignal,
  ): Promise<DriveFileRecord> {
    const boundary = `vana_gdrive_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const encoder = new TextEncoder();
    const preamble = encoder.encode(
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`,
    );
    const epilogue = encoder.encode(`\r\n--${boundary}--`);
    const body = new Uint8Array(
      preamble.byteLength + data.byteLength + epilogue.byteLength,
    );
    body.set(preamble, 0);
    body.set(data, preamble.byteLength);
    body.set(epilogue, preamble.byteLength + data.byteLength);

    const res = await authorizedFetch(
      `${apiBase}/upload/drive/v3/files?uploadType=multipart&fields=id,name,sha256Checksum,size,createdTime`,
      {
        method: "POST",
        headers: {
          "Content-Type": `multipart/related; boundary=${boundary}`,
        },
        body,
      },
      signal,
    );
    if (!res.ok) {
      throw await classifyHttpError(res, "upload");
    }
    return (await res.json()) as DriveFileRecord;
  }

  async function uploadResumable(
    metadata: Record<string, unknown>,
    data: Uint8Array,
    signal?: AbortSignal,
  ): Promise<DriveFileRecord> {
    const initRes = await authorizedFetch(
      `${apiBase}/upload/drive/v3/files?uploadType=resumable&fields=id,name,sha256Checksum,size,createdTime`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "X-Upload-Content-Type": "application/octet-stream",
          "X-Upload-Content-Length": String(data.byteLength),
        },
        body: JSON.stringify(metadata),
      },
      signal,
    );
    if (!initRes.ok) {
      throw await classifyHttpError(initRes, "upload");
    }
    const uploadUri = initRes.headers.get("location");
    await initRes.body?.cancel();
    if (!uploadUri) {
      throw new Error(
        "Google Drive resumable upload initiation did not return a Location header",
      );
    }

    const session = new URL(uploadUri, apiBase);
    if (
      session.origin !== new URL(apiBase).origin ||
      session.username ||
      session.password ||
      session.hash
    ) {
      throw new Error(
        "Google Drive resumable upload returned an invalid session URL",
      );
    }

    let offset = 0;
    // Keep retries within this invocation and only on confirmed progress.
    for (let attempt = 0; attempt < 8; attempt += 1) {
      signal?.throwIfAborted();
      const remaining = data.subarray(offset);
      const putRes = await authorizedFetch(
        session.href,
        {
          method: "PUT",
          redirect: "manual",
          headers: {
            "Content-Type": "application/octet-stream",
            "Content-Length": String(remaining.byteLength),
            "Content-Range": `bytes ${offset}-${data.byteLength - 1}/${data.byteLength}`,
          },
          body: copyToArrayBuffer(remaining),
        },
        signal,
      );
      if (putRes.ok) return (await putRes.json()) as DriveFileRecord;
      if (putRes.status !== 308)
        throw await classifyHttpError(putRes, "upload");

      const acknowledged = /^bytes=0-(\d+)$/.exec(
        putRes.headers.get("range") ?? "",
      );
      await putRes.body?.cancel();
      const next = acknowledged ? Number(acknowledged[1]) + 1 : 0;
      if (
        !Number.isSafeInteger(next) ||
        next <= offset ||
        next >= data.byteLength
      )
        throw new Error(
          "Google Drive resumable upload did not acknowledge a valid advancing range",
        );
      offset = next;
    }
    throw new Error(
      "Google Drive resumable upload exceeded its continuation limit",
    );
  }

  return {
    urlForKey,

    onRateLimitPolicy: feed.subscribe,

    async upload(
      key: string,
      data: Uint8Array,
      signal?: AbortSignal,
    ): Promise<string> {
      const canonicalUrl = urlForKey(key);
      return withKeyLock(key, async () => {
        signal?.throwIfAborted();
        const localSha256 = await sha256Hex(data);

        // 1. Pre-check existing file for write-once enforcement.
        const existing = await listMatchingFiles(key, signal);
        if (existing.length > 0) {
          const winner = existing[0]!;
          const remoteSha256 = await sha256OfExistingFile(winner, signal);
          fileCache.set(key, { fileId: winner.id, sha256: remoteSha256 });
          if (remoteSha256 === localSha256) {
            return canonicalUrl;
          }
          throw new StoredBlobConflictError(key);
        }

        // 2. Upload new private file directly inside the "Vana" folder.
        const keyHash = await sha256Hex(new TextEncoder().encode(key));
        const metadata = {
          name: driveFileNameForKey(key),
          parents: [folderId],
          mimeType: "application/octet-stream",
          appProperties: { vanaKeyHash: keyHash },
        };
        const created =
          data.byteLength > MULTIPART_UPLOAD_LIMIT_BYTES
            ? await uploadResumable(metadata, data, signal)
            : await uploadMultipart(metadata, data, signal);

        // 3. Post-upload race check: if another device created an earlier file
        // for the same key concurrently, delete our losing duplicate and decide
        // idempotency vs conflict against the earliest winner.
        const after = await listMatchingFiles(key, signal);
        const winner = after[0] ?? created;
        if (winner.id !== created.id) {
          await deleteFileById(created.id, signal).catch(() => undefined);
          const winnerSha256 = await sha256OfExistingFile(winner, signal);
          fileCache.set(key, { fileId: winner.id, sha256: winnerSha256 });
          if (winnerSha256 === localSha256) {
            return canonicalUrl;
          }
          throw new StoredBlobConflictError(key);
        }

        fileCache.set(key, {
          fileId: created.id,
          sha256: created.sha256Checksum?.toLowerCase() ?? localSha256,
        });
        return canonicalUrl;
      });
    },

    async download(url: string, signal?: AbortSignal): Promise<Uint8Array> {
      const key = keyFromUrl(url);
      let fileId = await resolveFileId(key, signal);
      if (!fileId) {
        throw Object.assign(
          new Error(`gdrive download failed: 404 Not Found`),
          {
            status: 404,
          },
        );
      }
      let res = await downloadFileBytes(fileId, signal);
      if (res.status === 404 && fileCache.has(key)) {
        await res.body?.cancel();
        fileCache.delete(key);
        fileId = await resolveFileId(key, signal);
        if (!fileId) {
          throw Object.assign(
            new Error(`gdrive download failed: 404 Not Found`),
            { status: 404 },
          );
        }
        res = await downloadFileBytes(fileId, signal);
      }
      if (!res.ok) {
        throw await classifyHttpError(res, "download");
      }
      return new Uint8Array(await res.arrayBuffer());
    },

    async downloadBounded(
      url: string,
      budget: ByteBudget,
    ): Promise<Uint8Array> {
      const key = keyFromUrl(url);
      let fileId = await resolveFileId(key, budget.signal);
      if (!fileId) {
        throw Object.assign(
          new Error(`gdrive download failed: 404 Not Found`),
          {
            status: 404,
          },
        );
      }
      budget.charge();
      let res = await downloadFileBytes(fileId, budget.signal);
      if (res.status === 404 && fileCache.has(key)) {
        await res.body?.cancel();
        fileCache.delete(key);
        fileId = await resolveFileId(key, budget.signal);
        if (!fileId) {
          throw Object.assign(
            new Error(`gdrive download failed: 404 Not Found`),
            { status: 404 },
          );
        }
        budget.charge();
        res = await downloadFileBytes(fileId, budget.signal);
      }
      if (!res.ok) {
        throw await classifyHttpError(res, "download");
      }
      return readBoundedResponse(res, budget);
    },

    async exists(url: string, signal?: AbortSignal): Promise<boolean> {
      const key = keyFromUrl(url);
      // Always probe live Drive metadata (never trust cache for exists()).
      const files = await listMatchingFiles(key, signal);
      const winner = files[0];
      if (!winner) {
        fileCache.delete(key);
        return false;
      }
      fileCache.set(key, { fileId: winner.id, sha256: winner.sha256Checksum });
      return true;
    },

    async delete(url: string): Promise<boolean> {
      const key = keyFromUrl(url);
      const files = await listMatchingFiles(key);
      fileCache.delete(key);
      if (files.length === 0) {
        return false;
      }
      let deletedAny = false;
      for (const file of files) {
        if (await deleteFileById(file.id)) {
          deletedAny = true;
        }
      }
      return deletedAny;
    },
  };
}

function escapeDriveQuery(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function extractDriveErrorReason(bodyText: string): string | undefined {
  if (!bodyText) return undefined;
  try {
    const parsed = JSON.parse(bodyText) as {
      error?: {
        errors?: Array<{ reason?: string }>;
        status?: string;
        message?: string;
      };
    };
    return parsed.error?.errors?.[0]?.reason ?? parsed.error?.status;
  } catch {
    return undefined;
  }
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

function isRevokedCredentialError(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const rec = err as Record<string, unknown>;
  if (rec.code === "STORAGE_AUTH_REVOKED" || rec.code === "revoked") {
    return true;
  }
  const msg = typeof rec.message === "string" ? rec.message : "";
  return /invalid_grant|revoked/i.test(msg);
}

function copyToArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    copyToArrayBuffer(data),
  );
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
