/**
 * Gateway adapter for the stream-sync registry calls (§2.3).
 *
 * Reads are strict: a status other than 200 or 404 throws, so a synthesized
 * row never stands in for the authoritative read. Writes are exclusive
 * `POST /v1/data`: 2xx commits (a replay of the identical row also answers
 * 2xx), 409 is a conflict, 5xx and network failures are ambiguous, and any
 * other status is a refusal.
 *
 * `postBatch` writes several rows and their conditions with one
 * `POST /v1/data/batch`; `postConditional` sends `requires` on the single
 * write. The gateway's failure bodies differ between its two routes, so
 * `requirementFailure` reads both.
 */

import {
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeDataPointId } from "../sync/data-point-id.js";
import {
  AmbiguousRegistryReplyError,
  RegistryRefusedError,
  type ConditionalPostResult,
  type ConditionalRegistryPost,
  type RegistryBatchResult,
  type RegistryBatchRow,
  type RegistryPostResult,
  type RegistryRequirement,
  type RegistryRequirementFailure,
  type SignedRegistryBatch,
  type SignedRegistryPost,
  type StreamSyncRegistry,
} from "./ports.js";

export interface GatewayStreamSyncRegistryOptions {
  readonly gatewayUrl: string;
  readonly ownerAddress: string;
  readonly fetch?: typeof fetch;
  /** Page size for the control listing. */
  readonly listPageSize?: number;
}

interface RegistryRow {
  readonly scope?: unknown;
  readonly changedAt?: unknown;
  readonly expectedVersion?: unknown;
  readonly dataHash?: unknown;
  readonly metadataHash?: unknown;
  readonly deletedAt?: unknown;
}

function toControlRead(row: RegistryRow): ControlRead {
  const version = Number(row.expectedVersion);
  if (
    !Number.isSafeInteger(version) ||
    version < 1 ||
    typeof row.dataHash !== "string" ||
    typeof row.metadataHash !== "string"
  ) {
    throw new Error("registry row has no valid version or hashes");
  }
  return {
    found: true,
    version,
    dataHash: row.dataHash,
    metadataHash: row.metadataHash,
    deleted: typeof row.deletedAt === "string" && row.deletedAt !== "",
  };
}

function unwrap(body: unknown): RegistryRow {
  if (typeof body !== "object" || body === null) return {};
  const record = body as { data?: unknown };
  if (typeof record.data === "object" && record.data !== null) {
    return record.data as RegistryRow;
  }
  return record as RegistryRow;
}

/** Per-request read of a JSON body; `null` when it is not JSON. */
async function jsonOf(res: Response): Promise<unknown> {
  return res.json().catch(() => null);
}

const REQUIREMENT_REASONS = new Set([
  "absent",
  "deleted",
  "version-mismatch",
  "data-hash-mismatch",
]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

function versionOf(value: unknown): string | null {
  return typeof value === "string" || typeof value === "number"
    ? String(value)
    : null;
}

/**
 * The failed condition of a 409, or `null` when the 409 is not one. The final
 * body, for both routes: `{ error: "precondition_failed", requires: { reason,
 * scope, latestVersion, deleted } }`. The batch prototype's older body is
 * `{ success: false, requires: { ok: false, scope, version, deleted } }`
 * (no reason); both are read.
 */
function requirementFailure(body: unknown): RegistryRequirementFailure | null {
  const record = asRecord(body);
  const requires = asRecord(record?.requires);
  if (!record || !requires) return null;
  const failed =
    record.error === "precondition_failed" || requires.ok === false;
  if (!failed || typeof requires.scope !== "string") return null;
  const reason = requires.reason;
  return {
    scope: requires.scope,
    ...(typeof reason === "string" &&
      REQUIREMENT_REASONS.has(reason) && {
        reason: reason as RegistryRequirementFailure["reason"],
      }),
    latestVersion: versionOf(requires.latestVersion ?? requires.version),
    deleted: requires.deleted === true || reason === "deleted",
  };
}

function wireRequirement(requirement: RegistryRequirement) {
  return {
    scope: requirement.scope,
    expectedVersion: requirement.expectedVersion,
    notDeleted: requirement.notDeleted,
    ...(requirement.expectedDataHash !== undefined && {
      expectedDataHash: requirement.expectedDataHash,
    }),
  };
}

/** Reads the status of a reply that did not say whether the write landed. */
function ambiguousOrRefused(
  what: string,
  res: Response,
  text: string,
): AmbiguousRegistryReplyError | RegistryRefusedError {
  if (res.status >= 500 || res.status === 429) {
    return new AmbiguousRegistryReplyError(`${what} answered ${res.status}`);
  }
  return new RegistryRefusedError(
    `registry refused ${what}: ${res.status} ${text.slice(0, 200)}`,
    res.status,
  );
}

/** One row of a batch reply. Anything else than 2xx or 409 is not a result. */
function batchRowOf(raw: unknown, scope: string): RegistryBatchRow {
  const row = asRecord(raw);
  const status = typeof row?.status === "number" ? row.status : 0;
  if (status >= 200 && status < 300) return { kind: "committed" };
  if (status === 409) {
    const hash = row?.latestDataHash;
    return {
      kind: "conflict",
      latestVersion: versionOf(row?.latestVersion),
      latestDataHash: typeof hash === "string" ? hash : null,
    };
  }
  throw new AmbiguousRegistryReplyError(
    `registry batch gave ${scope} the status ${status}`,
  );
}

export function createGatewayStreamSyncRegistry(
  options: GatewayStreamSyncRegistryOptions,
): StreamSyncRegistry {
  const base = options.gatewayUrl.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const pageSize = options.listPageSize ?? 500;

  /** Page through every owner row and keep the scopes `keep` accepts. */
  async function listRows(keep: (scope: string) => boolean) {
    const out: { scope: string; read: ControlRead }[] = [];
    let cursor: string | null = null;
    do {
      const params = new URLSearchParams({
        user: options.ownerAddress,
        includeDeleted: "true",
        limit: String(pageSize),
      });
      if (cursor !== null) params.set("cursor", cursor);
      const res = await fetchImpl(`${base}/v1/data?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`registry listing failed: ${res.status}`);
      }
      const envelope = (await res.json()) as {
        data?: { dataPoints?: RegistryRow[] };
        pagination?: { hasMore?: boolean; nextCursor?: string | null };
      };
      for (const row of envelope.data?.dataPoints ?? []) {
        if (typeof row.scope !== "string" || !keep(row.scope)) continue;
        out.push({ scope: row.scope, read: toControlRead(row) });
      }
      // A delete depends on the whole listing: a missing or inconsistent page
      // marker must fail, not end the listing early.
      const page = envelope.pagination;
      if (page === undefined || page === null) {
        throw new Error("registry listing has no pagination marker");
      }
      if (page.hasMore === false) {
        cursor = null;
      } else if (
        typeof page.nextCursor === "string" &&
        page.nextCursor !== ""
      ) {
        cursor = page.nextCursor;
      } else {
        throw new Error(
          "registry listing says more rows follow but gives no cursor",
        );
      }
    } while (cursor !== null);
    return out;
  }

  /** `undefined` until the gateway answers the batch route once. */
  let batchRoute: "absent" | undefined;

  /** One `POST /v1/data`, with `requires` when the caller has conditions. */
  async function sendPost(
    request: SignedRegistryPost,
    requires: readonly RegistryRequirement[] | undefined,
  ): Promise<ConditionalPostResult> {
    let res: Response;
    try {
      res = await fetchImpl(`${base}/v1/data`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Web3Signed ${request.signature}`,
        },
        body: JSON.stringify({
          ownerAddress: request.ownerAddress,
          scope: request.scope,
          dataHash: request.dataHash,
          metadataHash: request.metadataHash,
          expectedVersion: request.expectedVersion,
          exclusive: true,
          ...(requires && { requires: requires.map(wireRequirement) }),
        }),
      });
    } catch (cause) {
      throw new AmbiguousRegistryReplyError(
        `registry POST of ${request.scope} got no reply: ${(cause as Error).message}`,
      );
    }
    if (res.status >= 200 && res.status < 300) return { kind: "committed" };
    if (res.status === 409) {
      const body = await jsonOf(res);
      const failure = requirementFailure(body);
      if (failure) return { kind: "precondition_failed", failure };
      const latest = asRecord(body)?.latestVersion;
      return { kind: "conflict", latestVersion: versionOf(latest) };
    }
    throw ambiguousOrRefused(
      `POST of ${request.scope}`,
      res,
      await res.text().catch(() => ""),
    );
  }

  /** The 2xx reply of a batch: one result per row, in request order. */
  function batchRowsOf(
    request: SignedRegistryBatch,
    body: unknown,
  ): RegistryBatchResult {
    const results = asRecord(body)?.results;
    if (!Array.isArray(results)) {
      throw new AmbiguousRegistryReplyError(
        "registry batch reply has no results",
      );
    }
    const byScope = new Map<string, unknown>();
    for (const result of results) {
      const scope = asRecord(result)?.scope;
      if (typeof scope === "string") byScope.set(scope, result);
    }
    const rows = request.rows.map((row) => {
      if (!byScope.has(row.scope)) {
        throw new AmbiguousRegistryReplyError(
          `registry batch reply has no result for ${row.scope}`,
        );
      }
      return batchRowOf(byScope.get(row.scope), row.scope);
    });
    return { kind: "rows", rows };
  }

  return {
    async read(scope) {
      const id = computeDataPointId(options.ownerAddress, scope);
      const res = await fetchImpl(`${base}/v1/data/${id}?includeDeleted=true`);
      if (res.status === 404) return { found: false };
      if (res.status !== 200) {
        throw new Error(`registry read of ${scope} failed: ${res.status}`);
      }
      return toControlRead(unwrap(await res.json()));
    },

    async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
      const result = await sendPost(request, undefined);
      // Without `requires` the gateway has no condition to fail.
      if (result.kind === "precondition_failed") {
        throw new RegistryRefusedError(
          `registry answered a precondition failure to ${request.scope}, which sent none`,
          409,
        );
      }
      return result;
    },

    postConditional(
      request: ConditionalRegistryPost,
    ): Promise<ConditionalPostResult> {
      return sendPost(request, request.requires);
    },

    async postBatch(request: SignedRegistryBatch) {
      // A 404 or 405 is the gateway's answer for the process's lifetime: ask
      // again only after a restart. Nothing is written by a request the
      // gateway has no route for.
      if (batchRoute === "absent") return { kind: "unsupported" as const };
      let res: Response;
      try {
        res = await fetchImpl(`${base}/v1/data/batch`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ownerAddress: request.ownerAddress,
            rows: request.rows.map((row) => ({
              scope: row.scope,
              dataHash: row.dataHash,
              metadataHash: row.metadataHash,
              expectedVersion: row.expectedVersion,
              signature: row.signature,
              ...(row.expectedHeadDataHash !== undefined && {
                expectedHeadDataHash: row.expectedHeadDataHash,
              }),
            })),
            requires: request.requires.map(wireRequirement),
          }),
        });
      } catch (cause) {
        throw new AmbiguousRegistryReplyError(
          `registry batch POST got no reply: ${(cause as Error).message}`,
        );
      }
      if (res.status === 404 || res.status === 405) {
        batchRoute = "absent";
        return { kind: "unsupported" as const };
      }
      const what = `batch POST of ${request.rows.length} rows`;
      if (res.status === 409) {
        // The batch route answers 409 only when a condition failed (a row that
        // lost answers inside a 2xx). A body without the detail is still that:
        // the caller reads the row.
        return {
          kind: "precondition_failed" as const,
          failure: requirementFailure(await jsonOf(res)),
        };
      }
      if (res.status < 200 || res.status >= 300) {
        throw ambiguousOrRefused(what, res, await res.text().catch(() => ""));
      }
      return batchRowsOf(request, await jsonOf(res));
    },

    listControlRows: () =>
      listRows((scope) => parseScope(scope)?.kind === "control"),

    listStreamRows: (connector) =>
      listRows((scope) => {
        const parsed = parseScope(scope);
        return parsed?.kind === "stream" && parsed.connector === connector;
      }),

    async probeChange() {
      const params = new URLSearchParams({
        user: options.ownerAddress,
        includeDeleted: "true",
        limit: "1",
      });
      const res = await fetchImpl(`${base}/v1/data?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`registry change probe failed: ${res.status}`);
      }
      const envelope = (await res.json()) as {
        data?: { dataPoints?: RegistryRow[] };
      };
      const rows = envelope.data?.dataPoints ?? [];
      if (rows.length === 0) return null;
      // Newest change first (`changedAt`, then id): the gateway stamps it on
      // every write, tombstone and revive of a row. The marker fingerprints
      // this one row. Another row stamped in the same millisecond leaves it
      // unchanged, so equal markers are not proof of "nothing changed": the
      // caller's unconditional timer cycle is the completeness guarantee.
      const newest = rows[0] as RegistryRow & { id?: unknown };
      if (typeof newest.changedAt !== "string" || newest.changedAt === "") {
        return undefined;
      }
      return `${newest.changedAt}|${String(newest.id)}|${String(newest.expectedVersion)}`;
    },

    listConnectionRows: (connector, ns) =>
      listRows((scope) => {
        const parsed = parseScope(scope);
        return (
          parsed !== null && parsed.connector === connector && parsed.ns === ns
        );
      }),
  };
}
