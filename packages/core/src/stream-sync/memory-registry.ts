/**
 * An in-memory `StreamSyncRegistry`: the same port the gateway client
 * implements, held in process memory. A host that is built without a gateway
 * URL (tests, the stream-sync harnesses) passes it where the gateway client
 * would go. Every committed post is kept in `log`, in order. `beforePost` and
 * `afterPost` let a test hold a post before or after it commits.
 */
import {
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  RegistryPostResult,
  SignedRegistryPost,
  StreamSyncBlobs,
  StreamSyncRegistry,
} from "./ports.js";

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
}

/** A fresh in-memory registry (see `MemoryStreamSyncRegistry`). */
export function createMemoryStreamSyncRegistry(): StreamSyncRegistry {
  return new MemoryStreamSyncRegistry();
}

/** An in-memory `StreamSyncBlobs`: the blob store a test host passes where the storage service would go. */
export function createMemoryStreamSyncBlobs(): StreamSyncBlobs {
  const blobs = new Map<string, Uint8Array>();
  return {
    async put(key, bytes) {
      blobs.set(key, bytes.slice());
    },
    async get(key) {
      return blobs.get(key) ?? null;
    },
  };
}
