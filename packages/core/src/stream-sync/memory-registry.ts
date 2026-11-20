/**
 * An in-memory `StreamSyncRegistry`: the same port the gateway client
 * implements, held in process memory. A host that is built without a gateway
 * URL (tests, the stream-sync harnesses) passes it where the gateway client
 * would go. Every committed post is kept in `log`, in order. `beforePost` and
 * `afterPost` let a test hold a post before or after it commits (a batch calls
 * them once per row).
 *
 * Stored batch versions model pending, unsubmitted gateway slots: the head
 * can be refreshed at the same version unless a head precondition refuses it.
 * It serves the gateway's batch contract: one all-or-nothing request,
 * conditions judged on the state the request commits. `serveBatch` changes
 * the policy it advertises; `stopServingBatch` makes it a gateway without
 * the route.
 */
import {
  controlHashes,
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { gatewayBatchRefusal } from "../localdb/batch-contract.js";
import { streamSyncHashes } from "./crypto.js";
import {
  RegistryBatchRouteMissingError,
  RegistryRefusedError,
  type RegistryBatchPolicy,
  type RegistryBatchResult,
  type RegistryBatchRow,
  type RegistryPostResult,
  type RegistryRequirement,
  type RegistryRequirementFailure,
  type SignedRegistryBatch,
  type SignedRegistryPost,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
} from "./ports.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
  type StorageAccessPolicy,
} from "./storage-retry.js";

interface Version {
  readonly dataHash: string;
  readonly metadataHash: string;
  /** The signature the row was written with: a replay must carry the same. */
  readonly signature: string;
  readonly at: string;
}

export class MemoryStreamSyncRegistry implements StreamSyncRegistry {
  /** Every committed registry post, in order. */
  readonly log: { scope: string; version: number; dataHash: string }[] = [];
  protected readonly versions = new Map<string, Version[]>();
  private readonly settled = new Map<string, number>();

  /** Model settlement of the current gateway head in a test. */
  settleHead(scope: string): void {
    const version = this.versions.get(scope)?.length;
    if (!version) throw new Error(`No head to settle: ${scope}`);
    this.settled.set(scope, version);
  }

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
      signature: request.signature,
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

  /** The batch contract this registry serves; `undefined`: no batch route. */
  private batch?: {
    readonly policy: RegistryBatchPolicy;
    readonly isTombstone?: (dataHash: string) => boolean;
  } = { policy: GATEWAY_BATCH_POLICY };
  /** Every batch request the route received, in order. */
  readonly batches: SignedRegistryBatch[] = [];

  /**
   * Serve `POST /v1/data/batch` with `policy`. `isTombstone` says which data
   * hash is a delete, for `notDeleted` conditions; by default, the control
   * tombstone every device writes.
   */
  serveBatch(
    policy: RegistryBatchPolicy,
    isTombstone?: (dataHash: string) => boolean,
  ): void {
    this.batch = { policy, ...(isTombstone && { isTombstone }) };
  }

  /** A gateway that serves no batch route: `postBatch` answers 404. */
  stopServingBatch(): void {
    this.batch = undefined;
  }

  batchPolicy(): RegistryBatchPolicy | undefined {
    return this.batch?.policy;
  }

  async readBatchPolicy(): Promise<RegistryBatchPolicy | undefined> {
    return this.batch?.policy;
  }

  async postBatch(request: SignedRegistryBatch): Promise<RegistryBatchResult> {
    const batch = this.batch;
    if (!batch) throw new RegistryBatchRouteMissingError("HTTP 404");
    const tombstone = (await CONTROL_TOMBSTONE).tombstoneData;
    const isTombstone =
      batch.isTombstone ??
      ((dataHash: string) => dataHash.toLowerCase() === tombstone);
    this.batches.push(request);
    // A test holds each row here as it holds a single post: before the
    // request's transaction begins.
    for (const row of request.rows)
      await this.beforePost?.({ ownerAddress: request.ownerAddress, ...row });
    const refusal = gatewayBatchRefusal(request, batch.policy);
    if (refusal !== null)
      throw new RegistryRefusedError(`batch POST refused: ${refusal}`, 400);
    const failed = async (
      need: RegistryRequirement,
    ): Promise<RegistryRequirementFailure | null> => {
      const row = await this.read(need.scope);
      const fail = (
        reason: NonNullable<RegistryRequirementFailure["reason"]>,
      ): RegistryRequirementFailure => ({
        scope: need.scope,
        reason,
        latestVersion: row.found ? String(row.version) : null,
        deleted: row.found && isTombstone(row.dataHash),
      });
      if (!row.found) return fail("absent");
      if (need.notDeleted && isTombstone(row.dataHash)) return fail("deleted");
      if (String(row.version) !== need.expectedVersion)
        return fail("version-mismatch");
      if (
        need.expectedDataHash !== undefined &&
        row.dataHash.toLowerCase() !== need.expectedDataHash.toLowerCase()
      )
        return fail("data-hash-mismatch");
      return null;
    };
    const written = new Set(request.rows.map((row) => row.scope));
    // Conditions on rows the request does not write: the state before it,
    // which is the state it commits.
    for (const need of request.requires) {
      if (written.has(need.scope)) continue;
      const failure = await failed(need);
      if (failure) return { kind: "precondition_failed", failure };
    }
    const before = new Map(
      [...written].map((scope) => [scope, this.versions.get(scope)?.slice()]),
    );
    const logged = this.log.length;
    const rollBack = () => {
      for (const [scope, kept] of before)
        if (kept === undefined) this.versions.delete(scope);
        else this.versions.set(scope, kept);
      this.log.length = logged;
    };
    const rows: (RegistryBatchRow & { written?: true })[] = [];
    for (const row of request.rows) {
      const stored = this.versions.get(row.scope) ?? [];
      const at = stored[Number(row.expectedVersion) - 1];
      if (
        at !== undefined &&
        at.dataHash.toLowerCase() === row.dataHash.toLowerCase() &&
        at.signature.toLowerCase() === row.signature.toLowerCase()
      ) {
        // A replay, as the gateway judges one (`replaysStoredRow`, without
        // `exclusive`, which a batch never sets): the same data hash and the
        // same signature. A different signature follows the refresh rules.
        rows.push({ kind: "committed" });
        continue;
      }
      const head = stored.at(-1);
      if (
        (Number(row.expectedVersion) !== stored.length + 1 &&
          (Number(row.expectedVersion) !== stored.length ||
            this.settled.get(row.scope) === Number(row.expectedVersion) ||
            (head !== undefined && isTombstone(head.dataHash)))) ||
        (row.expectedHeadAbsent === true && head !== undefined) ||
        (row.expectedHeadDataHash !== undefined &&
          head?.dataHash.toLowerCase() !==
            row.expectedHeadDataHash.toLowerCase())
      ) {
        rows.push({
          kind: "conflict",
          latestVersion: stored.length > 0 ? String(stored.length) : null,
          latestDataHash: head?.dataHash ?? null,
        });
        continue;
      }
      // Like a pending, unsubmitted gateway slot: a same-version refresh
      // replaces it unless a head precondition refuses it. Replays above
      // retain their original acknowledgement.
      stored[Number(row.expectedVersion) - 1] = {
        dataHash: row.dataHash,
        metadataHash: row.metadataHash,
        signature: row.signature,
        at: new Date(
          this.baseMs + (Number(row.expectedVersion) - 1) * 1000,
        ).toISOString(),
      };
      this.versions.set(row.scope, stored);
      this.log.push({
        scope: row.scope,
        version: stored.length,
        dataHash: row.dataHash,
      });
      rows.push({ kind: "committed", written: true });
    }
    if (rows.some((row) => row.kind === "conflict")) {
      rollBack();
      return {
        kind: "refused",
        rows: rows.map(({ written, ...row }) =>
          written ? { kind: "not_written" } : row,
        ),
      };
    }
    // Conditions on rows it writes: the state after its writes.
    for (const need of request.requires) {
      if (!written.has(need.scope)) continue;
      const failure = await failed(need);
      if (failure) {
        rollBack();
        return { kind: "precondition_failed", failure };
      }
    }
    // Committed. A test may hold the caller after the commit, per row.
    for (const [i, row] of request.rows.entries())
      if (rows[i]!.written)
        await this.afterPost?.({ ownerAddress: request.ownerAddress, ...row });
    return { kind: "committed" };
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

  async listOwnerRows() {
    const out: { scope: string; read: ControlRead }[] = [];
    for (const scope of this.versions.keys())
      out.push({ scope, read: await this.read(scope) });
    return out;
  }
}

/** A fresh in-memory registry (see `MemoryStreamSyncRegistry`). */
/**
 * The policy the gateway advertises (`Batch-Policy`), as `deriveBatchBounds()`
 * computes it from the backend's limits in data-gateway `lib/batch-bounds.ts`
 * (31 rows once the lock count includes the registry change trigger's
 * relations).
 */
const GATEWAY_BATCH_POLICY: RegistryBatchPolicy = {
  rows: 31,
  requires: 1952,
  bytes: 3_606_546,
};

/** The control tombstone's hashes: a constant label, the same for every key. */
const CONTROL_TOMBSTONE = controlHashes(
  streamSyncHashes.keccak256,
  "0".repeat(16),
);

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
