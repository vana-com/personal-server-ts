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
  RegistryUnavailableError,
  ChangeFeedAbsentError,
  RegistryRefusedError,
  RegistryBatchRouteMissingError,
  type ConditionalPostResult,
  type ConditionalRegistryPost,
  type RegistryBatchPolicy,
  type RegistryBatchResult,
  type RegistryChangeDelta,
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

/** One row of a refused batch's reply: 201 (a replay), 409 (it lost) or 424 (not written). */
function batchRowOf(raw: unknown, scope: string): RegistryBatchRow {
  const row = asRecord(raw);
  const status = typeof row?.status === "number" ? row.status : 0;
  if (status >= 200 && status < 300) return { kind: "committed" };
  if (status === 424) return { kind: "not_written" };
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
  /**
   * A read that cannot reach the registry (a network failure or timeout) or
   * that it answers with a 5xx says nothing about the data: it is
   * unavailability, which a caller may go on offline from. Writes keep their
   * own ambiguity handling.
   */
  async function fetchForRead(
    url: string,
    signal?: AbortSignal,
  ): Promise<Response> {
    let res: Response;
    try {
      res = await fetchImpl(url, { signal });
    } catch (cause) {
      throw new RegistryUnavailableError(
        `registry unreachable: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
    if (res.status >= 500)
      throw new RegistryUnavailableError(`registry answered ${res.status}`);
    return res;
  }
  /**
   * The body of a read answer. A body that fails in transit (a dropped
   * connection, a timeout after the headers) is unavailability like a failed
   * fetch; text that arrived whole but does not parse, or has the wrong shape,
   * is a bad answer and stays a plain error.
   */
  async function bodyForRead(res: Response): Promise<unknown> {
    let text: string;
    try {
      text = await res.text();
    } catch (cause) {
      throw new RegistryUnavailableError(
        `registry unreachable: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
    return JSON.parse(text);
  }
  const pageSize = options.listPageSize ?? 500;

  type OwnerRow = { scope: string; read: ControlRead };

  /** Page through every owner row. */
  async function fetchOwnerRows(signal?: AbortSignal): Promise<OwnerRow[]> {
    const out: OwnerRow[] = [];
    let cursor: string | null = null;
    do {
      const params = new URLSearchParams({
        user: options.ownerAddress,
        includeDeleted: "true",
        limit: String(pageSize),
      });
      if (cursor !== null) params.set("cursor", cursor);
      const res = await fetchForRead(
        `${base}/v1/data?${params.toString()}`,
        signal,
      );
      if (!res.ok) {
        throw new Error(`registry listing failed: ${res.status}`);
      }
      const envelope = (await bodyForRead(res)) as {
        data?: { dataPoints?: RegistryRow[] };
        pagination?: { hasMore?: boolean; nextCursor?: string | null };
      };
      for (const row of envelope.data?.dataPoints ?? []) {
        if (typeof row.scope !== "string") continue;
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

  // Callers that list at the same moment (a cycle applies every connection at
  // once, and each lists the owner's rows) share listings. A listing that is
  // already out began before a later caller's call, so that caller cannot take
  // it: it would not reflect what was written since. Such callers wait for the
  // next listing, and every caller that arrives while it is out takes that
  // same one. The listings of N concurrent callers are at most two requests,
  // each taken after the call of every caller that uses it.
  let listingOut: Promise<OwnerRow[]> | undefined;
  let listingNext: Promise<OwnerRow[]> | undefined;
  function startListing(): Promise<OwnerRow[]> {
    const listing = fetchOwnerRows();
    listingOut = listing;
    const done = () => {
      if (listingOut === listing) listingOut = undefined;
    };
    listing.then(done, done);
    return listing;
  }
  function ownerRows(): Promise<OwnerRow[]> {
    if (listingOut === undefined) return startListing();
    listingNext ??= listingOut
      .then(
        () => undefined,
        () => undefined,
      )
      .then(() => {
        listingNext = undefined;
        return startListing();
      });
    return listingNext;
  }

  /** Every owner row whose scope `keep` accepts. */
  async function listRows(
    keep: (scope: string) => boolean,
    signal?: AbortSignal,
  ) {
    return (await (signal ? fetchOwnerRows(signal) : ownerRows())).filter(
      (row) => keep(row.scope),
    );
  }

  let batchPolicy: RegistryBatchPolicy | undefined;
  /** The one policy read of this process; cleared when it got no answer. */
  let policyRead: Promise<RegistryBatchPolicy | undefined> | undefined;

  const absentFeed = (status?: number) =>
    new ChangeFeedAbsentError(
      status === undefined
        ? "registry has no change route"
        : `registry has no change route: ${status}`,
    );

  /** One `POST /v1/data`, with `requires` when the caller has conditions. */
  async function sendPost(
    request: SignedRegistryPost,
    requires: readonly RegistryRequirement[] | undefined,
    signal?: AbortSignal,
  ): Promise<ConditionalPostResult> {
    let res: Response;
    try {
      res = await fetchImpl(`${base}/v1/data`, {
        method: "POST",
        signal,
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

  /** A refused batch (409 `conflict`): one result per row, in request order. */
  function refusedRowsOf(
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
    if (!rows.some((row) => row.kind === "conflict")) {
      throw new AmbiguousRegistryReplyError(
        "registry refused a batch without naming the row that lost",
      );
    }
    return { kind: "refused", rows };
  }

  return {
    async read(scope, signal) {
      const id = computeDataPointId(options.ownerAddress, scope);
      const res = await fetchForRead(
        `${base}/v1/data/${id}?includeDeleted=true`,
        signal,
      );
      if (res.status === 404) return { found: false };
      if (res.status !== 200) {
        throw new Error(`registry read of ${scope} failed: ${res.status}`);
      }
      return toControlRead(unwrap(await bodyForRead(res)));
    },

    async post(
      request: SignedRegistryPost,
      signal?: AbortSignal,
    ): Promise<RegistryPostResult> {
      const result = await sendPost(request, undefined, signal);
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

    async postBatch(
      request: SignedRegistryBatch,
      signal?: AbortSignal,
    ): Promise<RegistryBatchResult> {
      let res: Response;
      try {
        res = await fetchImpl(`${base}/v1/data/batch`, {
          method: "POST",
          signal,
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
      // Nothing is written by a request the gateway has no route for.
      if (res.status === 404 || res.status === 405) {
        throw new RegistryBatchRouteMissingError(`HTTP ${res.status}`);
      }
      // Every answer of the route, errors included, carries the bounds.
      batchPolicy =
        parseBatchPolicy(res.headers.get("batch-policy")) ?? batchPolicy;
      const what = `batch POST of ${request.rows.length} rows`;
      if (res.status === 409) {
        // Nothing was written: a row lost (`conflict`), or a condition failed.
        // A body without the detail is a failed condition: the caller reads
        // the row.
        const body = await jsonOf(res);
        if (asRecord(body)?.error === "conflict") {
          return refusedRowsOf(request, body);
        }
        return {
          kind: "precondition_failed",
          failure: requirementFailure(body),
        };
      }
      if (res.status < 200 || res.status >= 300) {
        throw ambiguousOrRefused(what, res, await res.text().catch(() => ""));
      }
      // A commit says so, and gives every row the status 201 (written now, or
      // a replay of a stored version). A 2xx body that does not (a proxy's
      // page) may come from something other than the route. A route that
      // predates all-or-nothing answers 200 `success: true` with a 409 row
      // beside stored ones: that row lost, so the batch is not a commit.
      const body = asRecord(await jsonOf(res));
      const results = body?.results;
      const everyRowStored =
        Array.isArray(results) &&
        request.rows.every((row) =>
          results.some(
            (result) =>
              asRecord(result)?.scope === row.scope &&
              asRecord(result)?.status === 201,
          ),
        );
      if (body?.success !== true || !everyRowStored) {
        throw new AmbiguousRegistryReplyError(
          `${what} answered ${res.status} without a commit of every row`,
        );
      }
      return { kind: "committed" };
    },

    batchPolicy: () => batchPolicy,

    readBatchPolicy(signal) {
      if (batchPolicy !== undefined) return Promise.resolve(batchPolicy);
      // The route sets `Batch-Policy` before it answers a preflight, so an
      // OPTIONS request reads it without writing. Only two answers are kept
      // for the process's lifetime: the header, and a 404 or 405 (no batch
      // route). Any other answer says nothing lasting, so the next call asks
      // again: an error status is no answer, and a success without the header
      // is no policy for now.
      const read = () =>
        fetchImpl(`${base}/v1/data/batch`, { method: "OPTIONS", signal })
          .catch((cause: unknown) => {
            throw new AmbiguousRegistryReplyError(
              `registry batch policy read got no reply: ${(cause as Error).message}`,
            );
          })
          .then((res) => {
            const policy = parseBatchPolicy(res.headers.get("batch-policy"));
            if (policy !== undefined) {
              batchPolicy = policy;
              return policy;
            }
            if (res.status === 404 || res.status === 405) return undefined;
            if (!signal) policyRead = undefined;
            if (res.status < 200 || res.status >= 300)
              throw new AmbiguousRegistryReplyError(
                `registry batch policy read answered ${res.status}`,
              );
            return undefined;
          })
          .catch((error: unknown) => {
            if (!signal) policyRead = undefined;
            throw error;
          });
      if (signal) return read();
      policyRead ??= read();
      return policyRead;
    },

    listControlRows: (signal) =>
      listRows((scope) => parseScope(scope)?.kind === "control", signal),

    listStreamRows: (connector) =>
      listRows((scope) => {
        const parsed = parseScope(scope);
        return parsed?.kind === "stream" && parsed.connector === connector;
      }),

    async probeChange(signal) {
      const params = new URLSearchParams({
        user: options.ownerAddress,
        includeDeleted: "true",
        limit: "1",
      });
      const res = await fetchImpl(`${base}/v1/data?${params.toString()}`, {
        ...(signal && { signal }),
      });
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
      // caller's timer cycle, or the push's position, is the completeness guarantee.
      const newest = rows[0] as RegistryRow & { id?: unknown };
      if (typeof newest.changedAt !== "string" || newest.changedAt === "") {
        return undefined;
      }
      return `${newest.changedAt}|${String(newest.id)}|${String(newest.expectedVersion)}`;
    },

    async waitForChange(after, waitMs, signal, since) {
      const params = new URLSearchParams({ user: options.ownerAddress });
      if (after !== undefined) {
        params.set("after", after);
        params.set("wait", String(Math.max(0, Math.round(waitMs / 1000))));
      }
      if (since !== undefined) params.set("since", since);
      const res = await fetchImpl(
        `${base}/v1/data/changes?${params.toString()}`,
        { signal },
      );
      // "No such route" is learned from the response, never remembered here:
      // the caller decides when to ask again (the push waits one held period),
      // so a gateway upgrade is found without a restart. A gateway without the
      // route is told apart by what it answers: 404 or 405, or the 400 its
      // `/v1/data/:dataPointId` handler gives the id `changes` ("Invalid
      // dataPointId..."). Any other 400 is the change route refusing this
      // request (the route's own errors name `user`, `after`, `wait` or `since`): a
      // failure that may pass, not an absence.
      if (
        res.status === 404 ||
        res.status === 405 ||
        (res.status === 400 && (await isLegacyRouteRefusal(res)))
      ) {
        throw absentFeed(res.status);
      }
      if (!res.ok) {
        throw new Error(`registry change wait failed: ${res.status}`);
      }
      const body = (await res.json()) as {
        seq?: unknown;
        changed?: unknown;
        delta?: unknown;
      };
      if (
        typeof body.seq !== "string" ||
        !DECIMAL.test(body.seq) ||
        typeof body.changed !== "boolean"
      ) {
        throw new Error("registry change answer is not {seq, changed}");
      }
      // A changed answer to a request that sent `since` carries its delta
      // (rows or reset). One that does not, or carries another request's, or
      // one this client cannot read, fails the request: the push then pokes a
      // full pull on its next answer.
      if (!body.changed || since === undefined)
        return { seq: body.seq, changed: body.changed };
      const delta = parseDelta(body.delta, since, body.seq);
      if (delta === undefined)
        throw new Error(
          `registry change answer has no readable delta for since=${since}`,
        );
      return { seq: body.seq, changed: true, delta };
    },

    listOwnerRows: () => listRows(() => true),
  };
}

const DECIMAL = /^(0|[1-9]\d*)$/;

/**
 * The `delta` of a changed answer, or `undefined` when there is none or it is
 * not the delta of this request (another `since`) or not well formed (the
 * caller refuses the answer). Rows are
 * read as the listing's rows are: a row whose version or hashes are not valid
 * makes the whole delta unreadable, never a partial one.
 */
function parseDelta(
  value: unknown,
  since: string,
  seq: string,
): RegistryChangeDelta | undefined {
  const delta = asRecord(value);
  if (!delta || delta.since !== since) return undefined;
  if (delta.reset === true) return { since, seq, reset: true };
  if (
    delta.reset !== false ||
    !Array.isArray(delta.rows) ||
    !Array.isArray(delta.gone) ||
    typeof delta.serversChanged !== "boolean" ||
    !delta.gone.every((id) => typeof id === "string")
  )
    return undefined;
  const rows: { scope: string; read: ControlRead }[] = [];
  for (const raw of delta.rows) {
    const row = asRecord(raw);
    if (!row || typeof row.scope !== "string") return undefined;
    try {
      rows.push({ scope: row.scope, read: toControlRead(row) });
    } catch {
      return undefined;
    }
  }
  return {
    since,
    seq,
    reset: false,
    rows,
    gone: delta.gone as string[],
    serversChanged: delta.serversChanged,
  };
}

const LEGACY_REFUSAL = "Invalid dataPointId";

/**
 * True when a 400 is the gateway's `/v1/data/:dataPointId` handler refusing the
 * path segment `changes`, which is what a gateway without the change route
 * answers. That handler's refusals say "Invalid dataPointId"; the change
 * route's own 400s say "Invalid user", "Invalid after", "Invalid wait" or
 * "Invalid since".
 */
async function isLegacyRouteRefusal(res: Response): Promise<boolean> {
  try {
    const body = (await res.json()) as { error?: unknown };
    return (
      typeof body.error === "string" && body.error.startsWith(LEGACY_REFUSAL)
    );
  } catch {
    return false;
  }
}

/**
 * `Batch-Policy: rows=<R>;bytes=<B>;requires=<Q>[;lockedScopes=<L>]`.
 * `undefined` when the header is absent or any field is not a positive
 * integer: a client that cannot read the bounds keeps the ones it had. A field
 * this client does not know is ignored.
 */
export function parseBatchPolicy(
  header: string | null,
): RegistryBatchPolicy | undefined {
  if (header === null) return undefined;
  const fields = new Map<string, number>();
  for (const part of header.split(";")) {
    const [key, value] = part.trim().split("=");
    if (key === undefined || value === undefined || !/^[1-9]\d*$/.test(value))
      return undefined;
    fields.set(key, Number(value));
  }
  const rows = fields.get("rows");
  const requires = fields.get("requires");
  const bytes = fields.get("bytes");
  if (
    rows === undefined ||
    requires === undefined ||
    bytes === undefined ||
    !Number.isSafeInteger(rows) ||
    !Number.isSafeInteger(requires) ||
    !Number.isSafeInteger(bytes)
  )
    return undefined;
  // Optional, and ignored when it is not a positive integer: an older gateway
  // sends none, and a client without it packs to `rows` alone.
  const lockedScopes = fields.get("lockedScopes");
  return {
    rows,
    requires,
    bytes,
    ...(lockedScopes !== undefined &&
      Number.isSafeInteger(lockedScopes) && { lockedScopes }),
  };
}
