/**
 * An in-memory `StreamSyncRegistry`: the same port the gateway client
 * implements, held in process memory. A host that is built without a gateway
 * URL (tests, the stream-sync harnesses) passes it where the gateway client
 * would go. Every committed post is kept in `log`, in order. `beforePost` and
 * `afterPost` let a test hold a post before or after it commits (a batch calls
 * them once per row). The connection log is written only through `postBatch`,
 * which judges the conditions and each row as the gateway does.
 */
import {
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  RegistryBatchResult,
  RegistryBatchRow,
  RegistryPostResult,
  SignedRegistryBatch,
  SignedRegistryPost,
  StreamSyncBlobs,
  StreamSyncRegistry,
} from "./ports.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
  type StorageAccessPolicy,
} from "./storage-retry.js";

interface Version {
  readonly dataHash: string;
  readonly metadataHash: string;
  readonly at: string;
}

export class MemoryStreamSyncRegistry implements StreamSyncRegistry {
  /** Every committed registry post, in order. */
  readonly log: { scope: string; version: number; dataHash: string }[] = [];
  protected readonly versions = new Map<string, Version[]>();

  /** `at` of the n-th version of a scope is `baseMs + n` seconds. */
  constructor(private readonly baseMs = 0) {}

  /** Runs inside every registry row read. */
  beforeRead?: (scope: string) => Promise<void>;
  /** A test holds a registry POST here, before it commits. */
  beforePost?: (request: SignedRegistryPost) => Promise<void>;
  /** A test holds the caller here: the registry committed, the caller has not heard. */
  afterPost?: (request: SignedRegistryPost) => Promise<void>;

  async read(scope: string): Promise<ControlRead> {
    await this.beforeRead?.(scope);
    const rows = this.versions.get(scope);
    if (!rows?.length) return { found: false };
    const head = rows[rows.length - 1]!;
    return {
      found: true,
      version: rows.length,
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      deleted: false,
    };
  }

  async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
    await this.beforePost?.(request);
    const rows = this.versions.get(request.scope) ?? [];
    if (Number(request.expectedVersion) !== rows.length + 1) {
      return { kind: "conflict", latestVersion: String(rows.length) };
    }
    rows.push({
      dataHash: request.dataHash,
      metadataHash: request.metadataHash,
      at: new Date(this.baseMs + rows.length * 1000).toISOString(),
    });
    this.versions.set(request.scope, rows);
    this.log.push({
      scope: request.scope,
      version: rows.length,
      dataHash: request.dataHash,
    });
    await this.afterPost?.(request);
    return { kind: "committed" };
  }

  /**
   * The gateway's `POST /v1/data/batch`: every condition is judged first (one
   * that fails writes nothing), then each row lands or loses on its own. A row
   * whose version and hash are the head's is a resend and answers as a
   * conflict that names its own hash, which the caller reads as published.
   */
  async postBatch(request: SignedRegistryBatch): Promise<RegistryBatchResult> {
    for (const req of request.requires) {
      const rows = this.versions.get(req.scope);
      const head = rows?.[rows.length - 1];
      const reason = !rows
        ? ("absent" as const)
        : String(rows.length) !== req.expectedVersion
          ? ("version-mismatch" as const)
          : req.expectedDataHash !== undefined &&
              req.expectedDataHash.toLowerCase() !==
                head!.dataHash.toLowerCase()
            ? ("data-hash-mismatch" as const)
            : undefined;
      if (reason !== undefined)
        return {
          kind: "precondition_failed",
          failure: {
            scope: req.scope,
            reason,
            latestVersion: rows ? String(rows.length) : null,
            deleted: false,
          },
        };
    }
    const results: RegistryBatchRow[] = [];
    for (const row of request.rows) {
      const post = { ...row, ownerAddress: request.ownerAddress };
      await this.beforePost?.(post);
      const rows = this.versions.get(row.scope) ?? [];
      const head = rows[rows.length - 1];
      const latest = {
        latestVersion: String(rows.length),
        latestDataHash: head?.dataHash ?? null,
      };
      const fence = row.expectedHeadDataHash;
      if (
        Number(row.expectedVersion) !== rows.length + 1 ||
        (fence !== undefined &&
          head?.dataHash.toLowerCase() !== fence.toLowerCase())
      ) {
        results.push({ kind: "conflict", ...latest });
        continue;
      }
      rows.push({
        dataHash: row.dataHash,
        metadataHash: row.metadataHash,
        at: new Date(this.baseMs + rows.length * 1000).toISOString(),
      });
      this.versions.set(row.scope, rows);
      this.log.push({
        scope: row.scope,
        version: rows.length,
        dataHash: row.dataHash,
      });
      await this.afterPost?.(post);
      results.push({ kind: "committed" });
    }
    return { kind: "rows", rows: results };
  }

  async probeChange() {
    return this.log.length === 0 ? null : String(this.log.length);
  }

  async listControlRows() {
    const out: { scope: string; read: ControlRead }[] = [];
    for (const scope of this.versions.keys()) {
      if (parseScope(scope)?.kind === "control") {
        out.push({ scope, read: await this.read(scope) });
      }
    }
    return out;
  }

  async listStreamRows(connector: string) {
    const out: { scope: string; read: ControlRead }[] = [];
    for (const scope of this.versions.keys()) {
      const parsed = parseScope(scope);
      if (parsed?.kind === "stream" && parsed.connector === connector) {
        out.push({ scope, read: await this.read(scope) });
      }
    }
    return out;
  }

  async listConnectionRows(connector: string, ns: string) {
    const out: { scope: string; read: ControlRead }[] = [];
    for (const scope of this.versions.keys()) {
      const parsed = parseScope(scope);
      if (parsed?.connector === connector && parsed.ns === ns) {
        out.push({ scope, read: await this.read(scope) });
      }
    }
    return out;
  }
}

/** A fresh in-memory registry (see `MemoryStreamSyncRegistry`). */
export function createMemoryStreamSyncRegistry(): StreamSyncRegistry {
  return new MemoryStreamSyncRegistry();
}

/**
 * An in-memory `StreamSyncBlobs`: the blob store a test host passes where the
 * storage service would go. It has a real send governor, so a transfer over it
 * holds no more than the byte budget while its PUTs are pending.
 */
export function createMemoryStreamSyncBlobs(
  policy: Partial<StorageAccessPolicy> = {},
): StreamSyncBlobs {
  const blobs = new Map<string, Uint8Array>();
  return {
    governor: createStorageAccess({
      ...DEFAULT_STORAGE_ACCESS_POLICY,
      ...policy,
    }),
    async put(key, bytes) {
      blobs.set(key, bytes.slice());
    },
    async get(key) {
      return blobs.get(key) ?? null;
    },
    async exists(key) {
      return blobs.has(key);
    },
  };
}
