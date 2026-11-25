import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import type {
  DataPointFeedPort,
  DeleteBlobVersionsOutcome,
  DeleteDataPort,
  TombstoneOutcome,
  TombstoneFence,
} from "../ports/index.js";
import type { ServerSigner } from "../signing/signer.js";
import { computeDataPointId } from "./data-point-id.js";
import {
  isGatewayAlreadyDeletedCode,
  isGatewayAnswerCode,
  isGatewayHeadAbsentCode,
  type GatewayAnswerCode,
} from "./gateway-refusal.js";
import { parseGatewayNextVersion } from "./workers/upload.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "./tombstone.js";

/**
 * Scopes the gateway reserves (data-gateway lib/reserved-scopes.ts): it reads
 * them for the owner wallet only, so a server must use the signed inventory.
 */
export function isGatewayReservedScope(scope: string): boolean {
  return scope.startsWith("vana.system.");
}

/**
 * A tombstone the gateway answered with a code no retry changes
 * (`gateway-refusal.ts`): a terminal refusal, or the already-deleted answer.
 */
export class GatewayRefusalError extends Error {
  constructor(
    readonly status: number,
    readonly code: GatewayAnswerCode,
    detail: string,
  ) {
    super(`Gateway error: ${status} ${detail}`);
    this.name = "GatewayRefusalError";
  }
}

/**
 * A fenced delete cleans storage through the tombstone's version, so it may
 * count a deleted head as its own only at the version right after the fenced
 * head. A later tombstone sits over versions the fence never named; the caller
 * must write nothing for it.
 */
function assertFencedTombstone(
  fence: { head: TombstoneFence } | undefined,
  version: string | null,
): void {
  if (!fence) return;
  if (
    version === null ||
    BigInt(version) !== BigInt(fence.head.expectedVersion) + 1n
  )
    throw new Error(
      `Scope is deleted at v${version ?? "?"}, not directly after the fenced head (v${fence.head.expectedVersion})`,
    );
}

/** The terminal refusal a response body names, or null. */
function refusalOf(
  status: number,
  body: unknown,
  fallback: string,
): GatewayRefusalError | null {
  if (typeof body !== "object" || body === null) return null;
  const code = (body as Record<string, unknown>).code;
  if (!isGatewayAnswerCode(code)) return null;
  return new GatewayRefusalError(
    status,
    code,
    `${code}: ${detailFromBody(body, fallback)}`,
  );
}

export interface GatewayDeleteDataPortOptions {
  /** Gateway base URL, e.g. https://dp-rpc.vana.org */
  gatewayUrl: string;
  /** Deletion-aware registry lookup (current version + deleted state). */
  dataPointFeed: DataPointFeedPort;
  /**
   * Head of a reserved `vana.system.*` point. The gateway answers an unsigned
   * GET /v1/data/:id of one with 401 (owner wallet only), so these heads are
   * read through the signed version inventory, which admits registered
   * servers. Without it, reserved scopes use `dataPointFeed` like any other.
   */
  reservedHead?: (scope: string) => Promise<{
    expectedVersion: string;
    dataHash: string;
    metadataHash: string;
    deletedAt: string | null;
  } | null>;
  /** Data owner the tombstone is registered on behalf of. */
  serverOwner: `0x${string}`;
  /**
   * The same signer the upload worker uses for AddData: the personal server
   * account, which the registry trusts for this owner. Reused as-is so a
   * tombstone is signed exactly like a normal registration.
   */
  signer: Pick<ServerSigner, "signAddData">;
  storage: {
    /** vana-storage base URL, e.g. https://storage.vana.org */
    endpoint: string;
    /** Authentication origin may differ from the routing endpoint. */
    audience?: string;
    /** Protocol chain id; blob paths are chain-scoped. */
    chainId: number;
    /**
     * EIP-191 signer for the Web3Signed storage auth. The same account the
     * storage provider uploads with (the server account), so the DELETE is
     * authorised the way PUT is.
     */
    signMessage(message: string): Promise<`0x${string}`>;
  };
  /** Test seam; defaults to the global fetch. */
  fetch?: typeof fetch;
}

/**
 * Remote deletion against the DPv2 gateway + vana-storage.
 *
 * Gateway (durable fact):
 *   DELETE {gateway}/v1/data/{dataPointId}
 *   Authorization: Web3Signed {signature}
 *   { ownerAddress, scope, expectedVersion, signature }
 * where signature = EIP-712 AddData over
 *   { ownerAddress, scope, dataHash: TOMBSTONE_DATA_HASH,
 *     metadataHash: TOMBSTONE_METADATA_HASH, expectedVersion: current + 1 }
 *
 * Storage (one exact blob per version, never the scope prefix):
 *   DELETE {storage}/v1/chains/{chainId}/blobs/{owner}/{scope}/{version}
 *   authorization: Web3Signed (aud = storage endpoint, uri = that path)
 * The path is the one the SDK's vana-storage provider uploads to: lowercased
 * owner, every key segment URI-encoded; vana-storage resolves a three-segment
 * path as a single-object delete and answers 404 when the object is absent.
 */
export function createGatewayDeleteDataPort(
  options: GatewayDeleteDataPortOptions,
): DeleteDataPort {
  const gatewayBase = options.gatewayUrl.replace(/\/+$/, "");
  const storageBase = options.storage.endpoint.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  // The storage provider lowercases the owner in blob paths; match it or the
  // exact DELETE keys would not be the ones PUT wrote.
  const owner = options.serverOwner.toLowerCase() as `0x${string}`;

  // Current version and deleted state of the point behind `scope`.
  function currentHead(scope: string): Promise<{
    expectedVersion: string;
    dataHash: string;
    metadataHash: string;
    deletedAt: string | null;
  } | null> {
    if (options.reservedHead && isGatewayReservedScope(scope))
      return options.reservedHead(scope);
    return options.dataPointFeed.getDataPoint({
      ownerAddress: options.serverOwner,
      scope,
    });
  }

  async function sendTombstone(
    scope: string,
    dataPointId: string,
    version: bigint,
  ): Promise<Response> {
    const signature = await options.signer.signAddData({
      ownerAddress: options.serverOwner,
      scope,
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      expectedVersion: version,
    });
    return fetchImpl(`${gatewayBase}/v1/data/${dataPointId}`, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Web3Signed ${signature}`,
      },
      body: JSON.stringify({
        ownerAddress: options.serverOwner,
        scope,
        expectedVersion: String(version),
        signature,
      }),
    });
  }

  /**
   * The point is deleted already (a 410, or a 409 that says so). The winning
   * tombstone may sit above the version we attempted (another replica
   * advanced the scope first), and its version bounds the ciphertext to
   * delete, so take the gateway's word: the echoed row, else a re-read of the
   * deletion-aware feed, else unknown.
   */
  async function alreadyDeleted(
    scope: string,
    dataPointId: string,
    body: unknown,
  ): Promise<TombstoneOutcome> {
    const echoed = unwrap(body);
    let winning = normalizeVersionString(
      stringField(echoed, "expectedVersion"),
    );
    let deletedAt = stringField(echoed, "deletedAt");
    if (winning === null) {
      const reread = await currentHead(scope).catch(() => null);
      if (reread && reread.deletedAt !== null) {
        winning = normalizeVersionString(reread.expectedVersion);
        deletedAt = deletedAt ?? reread.deletedAt;
      }
    }
    return {
      status: "already-deleted",
      dataPointId,
      version: winning,
      deletedAt,
    };
  }

  /**
   * The one reading of the gateway's answer to a tombstone post, for the first
   * post and the re-signed one alike, so no answer is read by only one of them.
   * It throws on a terminal refusal or an error, returns an outcome for what is
   * the same fact as a 404 or 410 (a head already deleted, never registered),
   * and otherwise says the post was a version conflict or was accepted.
   */
  async function readTombstoneAnswer(
    scope: string,
    dataPointId: string,
    res: Response,
  ): Promise<
    | { kind: "outcome"; outcome: TombstoneOutcome }
    | { kind: "version-conflict"; body: unknown; statusText: string }
    | { kind: "accepted"; body: unknown }
  > {
    if (res.status === 409) {
      // A 409 is a version conflict, the owner's cutover refusal, or the
      // gateway's word on the head itself (already deleted, never registered);
      // the body says which. The head answers are read first: they are the
      // same facts as a 410 and a 404, and the refusal is terminal.
      const body = await res.json().catch(() => null);
      const code = (body as Record<string, unknown> | null)?.code;
      if (isGatewayAlreadyDeletedCode(code))
        return {
          kind: "outcome",
          outcome: await alreadyDeleted(scope, dataPointId, body),
        };
      if (isGatewayHeadAbsentCode(code))
        return {
          kind: "outcome",
          outcome: { status: "not-registered", dataPointId },
        };
      const refusal = refusalOf(409, body, res.statusText);
      if (refusal) throw refusal;
      return { kind: "version-conflict", body, statusText: res.statusText };
    }
    if (res.status === 404) {
      // The registry lost the row between our read and our write (or the
      // feed answered from a replica ahead of the writer): nothing to
      // tombstone.
      return {
        kind: "outcome",
        outcome: { status: "not-registered", dataPointId },
      };
    }
    if (res.status === 410) {
      // Raced with a concurrent deletion: the point is already gone.
      return {
        kind: "outcome",
        outcome: await alreadyDeleted(
          scope,
          dataPointId,
          await res.json().catch(() => null),
        ),
      };
    }
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      throw (
        refusalOf(res.status, body, res.statusText) ??
        new Error(
          `Gateway error: ${res.status} ${detailFromBody(body, res.statusText)}`,
        )
      );
    }
    return { kind: "accepted", body };
  }

  return {
    ...(options.reservedHead ? { head: options.reservedHead } : {}),
    async tombstone(
      scope: string,
      fence?: { head: TombstoneFence },
    ): Promise<TombstoneOutcome> {
      const dataPointId = computeDataPointId(options.serverOwner, scope);
      const current = await currentHead(scope);
      if (current === null) {
        return { status: "not-registered", dataPointId };
      }
      if (current.deletedAt !== null) {
        // A fenced delete may call a head deleted only when it is the pinned
        // head's own tombstone: the caller cleans storage through that version.
        assertFencedTombstone(fence, current.expectedVersion);
        return {
          status: "already-deleted",
          dataPointId,
          version: current.expectedVersion,
          deletedAt: current.deletedAt,
        };
      }

      if (
        fence &&
        (current.expectedVersion !== fence.head.expectedVersion ||
          current.dataHash.toLowerCase() !==
            fence.head.dataHash.toLowerCase() ||
          current.metadataHash.toLowerCase() !==
            fence.head.metadataHash.toLowerCase())
      ) {
        throw new Error(
          `Scope head (v${current.expectedVersion}) is not the one the fenced delete saw (v${fence.head.expectedVersion})`,
        );
      }
      let replaced: TombstoneFence | null = {
        expectedVersion: current.expectedVersion,
        dataHash: current.dataHash,
        metadataHash: current.metadataHash,
      };
      let version = BigInt(current.expectedVersion) + 1n;
      let answer = await readTombstoneAnswer(
        scope,
        dataPointId,
        await sendTombstone(scope, dataPointId, version),
      );
      if (answer.kind === "version-conflict") {
        if (fence) {
          throw new Error(
            `Scope head is not the one the fenced delete saw (v${fence.head.expectedVersion}): another writer moved it`,
          );
        }
        // Another replica advanced the scope between our read and our
        // write. The 409 body carries `currentExpectedVersion` (and the
        // legacy message phrasing names the next valid version); re-sign
        // once against it.
        const { body, statusText } = answer;
        const conflict = unwrap(body);
        // Gateway 409 body: `nextExpectedVersion` is the version to sign
        // next; `currentExpectedVersion` is the version the gateway holds,
        // so it needs +1. Prefer the explicit next, fall back to current+1,
        // then to the legacy message phrasing.
        const nextExplicit =
          integerField(conflict, "nextExpectedVersion") ??
          integerField(body, "nextExpectedVersion");
        const currentExpected =
          integerField(conflict, "currentExpectedVersion") ??
          integerField(body, "currentExpectedVersion");
        const legacyNext = parseGatewayNextVersion(
          detailFromBody(body, statusText),
        );
        const next =
          nextExplicit !== null
            ? nextExplicit
            : currentExpected !== null
              ? currentExpected + 1n
              : legacyNext !== null
                ? BigInt(legacyNext)
                : null;
        if (next === null) {
          throw new Error(
            `Gateway error: 409 ${detailFromBody(body, statusText)}`,
          );
        }
        version = next;
        // The head moved before the POST; which head this tombstone replaces
        // is not known, so no automatic re-submission may rely on it.
        replaced = null;
        // The re-signed post is read by the same decoder as the first.
        answer = await readTombstoneAnswer(
          scope,
          dataPointId,
          await sendTombstone(scope, dataPointId, version),
        );
      }
      if (answer.kind === "outcome") {
        if (answer.outcome.status === "already-deleted")
          assertFencedTombstone(fence, answer.outcome.version);
        return answer.outcome;
      }
      if (answer.kind === "version-conflict") {
        // A second conflict: the re-sign is once, not forever.
        throw new Error(
          `Gateway error: 409 ${detailFromBody(answer.body, answer.statusText)}`,
        );
      }
      const row = unwrap(answer.body);
      return {
        status: "tombstoned",
        dataPointId: stringField(row, "dataPointId") ?? dataPointId,
        version: stringField(row, "expectedVersion") ?? String(version),
        replaced,
        deletedAt: stringField(row, "deletedAt"),
      };
    },

    async deleteBlobVersions(
      scope: string,
      versions: string[],
    ): Promise<DeleteBlobVersionsOutcome> {
      const outcome: DeleteBlobVersionsOutcome = {
        deleted: [],
        missing: [],
        failed: [],
      };
      // Sequential on purpose: vana-storage rate-limits DELETE per owner
      // and the caller already bounds the batch size per pass.
      for (const version of versions) {
        const path = `/v1/chains/${options.storage.chainId}/blobs/${owner}/${encodeURIComponent(scope)}/${encodeURIComponent(version)}`;
        try {
          const authorization = await buildWeb3SignedHeader({
            signMessage: (message: string) =>
              options.storage.signMessage(message),
            aud: options.storage.audience ?? storageBase,
            method: "DELETE",
            uri: path,
          });
          const res = await fetchImpl(`${storageBase}${path}`, {
            method: "DELETE",
            headers: { authorization },
          });
          if (res.status === 404) {
            // Idempotent: an absent object is a completed delete.
            outcome.missing.push(version);
          } else if (res.ok) {
            outcome.deleted.push(version);
          } else {
            outcome.failed.push({
              version,
              error: `vana-storage delete failed: ${res.status} ${res.statusText}`,
            });
          }
        } catch (err) {
          outcome.failed.push({
            version,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return outcome;
    },
  };
}

function detailFromBody(body: unknown, fallback: string): string {
  if (typeof body === "object" && body !== null) {
    const record = body as Record<string, unknown>;
    if (typeof record.error === "string") return record.error;
    if (typeof record.message === "string") return record.message;
    if (typeof record.error === "object" && record.error !== null) {
      const nested = record.error as Record<string, unknown>;
      if (typeof nested.message === "string") return nested.message;
    }
  }
  return fallback;
}

// Versions are unbounded integers on the wire (decimal strings); parse them
// as bigint so a value past Number.MAX_SAFE_INTEGER cannot round.
// A registry version is a positive decimal integer; anything else (including
// the "0" a body-less 410 can synthesise) is "unknown".
function normalizeVersionString(value: string | null): string | null {
  if (value === null || !/^\d+$/.test(value)) return null;
  const parsed = BigInt(value);
  return parsed > 0n ? parsed.toString() : null;
}

function integerField(record: unknown, key: string): bigint | null {
  if (typeof record !== "object" || record === null) return null;
  const value = (record as Record<string, unknown>)[key];
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return null;
}

function unwrap(body: unknown): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null) return null;
  const record = body as Record<string, unknown>;
  if (typeof record.data === "object" && record.data !== null) {
    return record.data as Record<string, unknown>;
  }
  return record;
}

function stringField(
  record: Record<string, unknown> | null,
  key: string,
): string | null {
  const value = record?.[key];
  return typeof value === "string" ? value : null;
}
