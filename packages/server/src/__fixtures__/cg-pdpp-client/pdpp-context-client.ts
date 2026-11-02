/**
 * Context Gateway → PDPP Core §8 Resource Server client.
 *
 * This is a typed transport for PDPP's Client role (spec §9 "Client
 * conformance"), built alongside the existing legacy PS read path in
 * `personal-server-data-read.ts` — it does not replace it. The legacy path
 * (`GET /v1/data/{scope}`, one JSON body, no cursor) stays live until PS
 * actually serves the §8 surface; this module targets `GET /v1/streams`,
 * `GET /v1/streams/{stream}`, and `GET /v1/streams/{stream}/records` per
 * spec-core.md §8, cited exhaustively in `pdpp-types.ts`.
 *
 * Authentication is pluggable via `PdppAuthorizationStrategy`, not
 * hardcoded, because two genuinely different mechanisms exist and must not
 * collapse into one:
 *
 *  - **Grantee identity** (which app is calling): one Privy-custodied
 *    Ethereum wallet per builder app (`grantee-wallets.ts`,
 *    `ensureGranteeWalletForApp`), unchanged by this PR. No shared CG
 *    wallet, no per-app Hydra OAuth client — neither exists in this
 *    codebase and this file does not add one.
 *  - **Request authorization** (what proves the request is allowed): per
 *    `local/conformance-fleet-0917/ps-auth-contract.md` (the AS/RS lane's
 *    published seam, `vana-com/personal-server-ts` branch
 *    `feat/pdpp-as-grants`, not yet pushed as of this revision), PS's PDPP
 *    AS issues real `access_token`s bound to a `Grant`, resolved via
 *    `PdppAuthorizationService.resolveToken`/`introspect`. That token,
 *    sent as `Authorization: Bearer <access_token>`, is what spec §8
 *    actually requires — not a Web3Signed header. Web3Signed remains valid
 *    only for the legacy `/v1/data/{scope}` endpoint, which this client
 *    does not call. `webSignedAuthorizationStrategy` below exists for
 *    conformance testing against a PS deployment that has not yet adopted
 *    real token issuance, not as this client's default.
 *
 * The two are complementary, not substitutable: obtaining an
 * `access_token` from the AS in the first place still requires the caller
 * to authenticate as a specific grantee app (out of scope for this file —
 * that's the AS's `/v1/pdpp/authorize` + `/v1/pdpp/token` flow per the
 * contract doc); this client only consumes the resulting bearer token.
 *
 * PROVISIONAL: neither the AS lane's branch (`pdpp-as-build-0917`,
 * `feat/pdpp-as-grants`) nor the RS lane's branch (`pdpp-ps-records-v2-0917`)
 * is pushed to `vana-com/personal-server-ts` as of this revision (verified
 * via `git ls-remote`) — the peer session claiming to run
 * `pdpp-as-build-0917` was not even found in this environment's live agent
 * list. This client is typed against `ps-auth-contract.md`'s TypeScript
 * seam and the spec text, not against a running server; there is nothing
 * to integration-test against yet. See the result report for the exact
 * live acceptance this leaves open.
 */

import {
  bearerTokenAuthorizationStrategy,
  type PdppAuthorizationStrategy,
  webSignedAuthorizationStrategy,
} from "./pdpp-authorization-strategy.js";
import {
  PDPP_REQUEST_ID_HEADER,
  PDPP_VERSION,
  PDPP_VERSION_HEADER,
  type PdppErrorBody,
  type PdppErrorCode,
  type PdppErrorType,
  type PdppGetRecordParams,
  type PdppListRecordsParams,
  type PdppListRecordsResponse,
  type PdppListStreamsResponse,
  type PdppRecord,
  type PdppStreamMetadata,
  type PdppTombstone,
} from "./pdpp-types.js";

export { bearerTokenAuthorizationStrategy, webSignedAuthorizationStrategy };
export type { PdppAuthorizationStrategy };

export interface PdppClientConfig {
  /** Base URL of the target Resource Server, e.g. the resolved PS URL. */
  baseUrl: string;
  /**
   * How to produce the `Authorization` header for each request. Required —
   * there is no default, so a caller cannot silently fall back to
   * Web3Signed by omission. Use `bearerTokenAuthorizationStrategy` (the
   * spec-conformant path, once the AS lane's token issuance is reachable)
   * or `webSignedAuthorizationStrategy` (explicit legacy-PS opt-in).
   */
  authorization: PdppAuthorizationStrategy;
  /** Overrides `PDPP_VERSION` for conformance testing against other versions. */
  pdppVersion?: string;
}

/**
 * Thrown for any non-2xx §8 response. Carries the parsed spec error body so
 * callers can branch on `code`, not on message text (`meta.warnings[]`
 * mirrors this rule for non-fatal cases — see spec §8 "Non-fatal warnings").
 */
export class PdppClientError extends Error {
  readonly httpStatus: number;
  readonly code: PdppErrorCode;
  readonly type: PdppErrorType;
  readonly requestId?: string;
  readonly param?: string;

  constructor(params: {
    httpStatus: number;
    code: PdppErrorCode;
    type: PdppErrorType;
    message: string;
    requestId?: string;
    param?: string;
  }) {
    super(params.message);
    this.name = "PdppClientError";
    this.httpStatus = params.httpStatus;
    this.code = params.code;
    this.type = params.type;
    this.requestId = params.requestId;
    this.param = params.param;
  }
}

/** Thrown when a response cannot be parsed as the spec §8 error envelope at all. */
export class PdppTransportError extends Error {
  readonly httpStatus: number;

  constructor(params: { httpStatus: number; message: string }) {
    super(params.message);
    this.name = "PdppTransportError";
    this.httpStatus = params.httpStatus;
  }
}

function isPdppErrorBody(value: unknown): value is PdppErrorBody {
  if (!value || typeof value !== "object") {
    return false;
  }
  const error = (value as { error?: unknown }).error;
  return (
    Boolean(error) &&
    typeof error === "object" &&
    typeof (error as { code?: unknown }).code === "string" &&
    typeof (error as { type?: unknown }).type === "string" &&
    typeof (error as { message?: unknown }).message === "string"
  );
}

async function throwForErrorResponse(response: Response): Promise<never> {
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    parsed = null;
  }
  if (isPdppErrorBody(parsed)) {
    const { error } = parsed;
    throw new PdppClientError({
      code: error.code,
      httpStatus: response.status,
      message: error.message,
      param: error.param,
      requestId:
        error.request_id ??
        response.headers.get(PDPP_REQUEST_ID_HEADER) ??
        undefined,
      type: error.type,
    });
  }
  throw new PdppTransportError({
    httpStatus: response.status,
    message: `PDPP resource server returned HTTP ${response.status} without a valid spec §8 error body`,
  });
}

/** Builds `filter[{field}]` / `filter[{field}][gte|gt|lte|lt]` query entries per spec §8. */
function appendFilterParams(
  search: URLSearchParams,
  filter: PdppListRecordsParams["filter"],
): void {
  if (!filter) {
    return;
  }
  for (const [field, value] of Object.entries(filter)) {
    if (typeof value === "string") {
      search.set(`filter[${field}]`, value);
      continue;
    }
    for (const op of ["gte", "gt", "lte", "lt"] as const) {
      const opValue = value[op];
      if (opValue !== undefined) {
        search.set(`filter[${field}][${op}]`, opValue);
      }
    }
  }
}

function buildListRecordsSearchParams(
  params: PdppListRecordsParams,
): URLSearchParams {
  const search = new URLSearchParams();
  if (params.limit !== undefined) {
    search.set("limit", String(params.limit));
  }
  if (params.cursor !== undefined) {
    search.set("cursor", params.cursor);
  }
  if (params.order !== undefined) {
    search.set("order", params.order);
  }
  appendFilterParams(search, params.filter);
  if (params.view !== undefined) {
    search.set("view", params.view);
  }
  if (params.fields !== undefined) {
    search.set("fields", params.fields.join(","));
  }
  for (const relation of params.expand ?? []) {
    search.append("expand[]", relation);
  }
  for (const [relation, limit] of Object.entries(params.expand_limit ?? {})) {
    search.set(`expand_limit[${relation}]`, String(limit));
  }
  if (params.changes_since !== undefined) {
    search.set("changes_since", params.changes_since);
  }
  return search;
}

/**
 * PDPP Core §8 client for the Resource Server's read surface. One instance
 * is scoped to one `PdppAuthorizationStrategy` closure, which in turn is
 * scoped to one grant/one grantee wallet — mirrors the immutability of the
 * DCR snapshot the legacy path relies on (never re-derive credentials from
 * a shared or ambient identity).
 */
export class PdppContextClient {
  private readonly config: PdppClientConfig;

  constructor(config: PdppClientConfig) {
    this.config = config;
  }

  async listStreams(): Promise<PdppListStreamsResponse> {
    return await this.get<PdppListStreamsResponse>("/v1/streams");
  }

  async getStreamMetadata(stream: string): Promise<PdppStreamMetadata> {
    return await this.get<PdppStreamMetadata>(
      `/v1/streams/${encodeURIComponent(stream)}`,
    );
  }

  async listRecords(
    stream: string,
    params: PdppListRecordsParams = {},
  ): Promise<PdppListRecordsResponse> {
    const search = buildListRecordsSearchParams(params);
    const qs = search.toString();
    const path = `/v1/streams/${encodeURIComponent(stream)}/records${qs ? `?${qs}` : ""}`;
    return await this.get<PdppListRecordsResponse>(path);
  }

  async getRecord(
    stream: string,
    id: string,
    params: PdppGetRecordParams = {},
  ): Promise<PdppRecord | PdppTombstone> {
    const search = new URLSearchParams();
    for (const relation of params.expand ?? []) {
      search.append("expand[]", relation);
    }
    const qs = search.toString();
    const path = `/v1/streams/${encodeURIComponent(stream)}/records/${encodeURIComponent(id)}${qs ? `?${qs}` : ""}`;
    return await this.get<PdppRecord | PdppTombstone>(path);
  }

  private async get<T>(pathname: string): Promise<T> {
    const origin = new URL(this.config.baseUrl).origin;
    const url = new URL(pathname, origin);

    // The `uri` passed to the authorization strategy is always the
    // pathname only, never the query string — required by the Web3Signed
    // strategy's verifier and harmless for the bearer-token strategy,
    // which ignores it.
    const authorization = await this.config.authorization({
      method: "GET",
      origin,
      uri: url.pathname,
    });

    const response = await fetch(url.toString(), {
      headers: {
        accept: "application/json",
        authorization,
        [PDPP_VERSION_HEADER]: this.config.pdppVersion ?? PDPP_VERSION,
      },
      method: "GET",
    });

    if (!response.ok) {
      await throwForErrorResponse(response);
    }

    return (await response.json()) as T;
  }
}
