/**
 * HTTP surface of the compute layer, mounted under `/v1/derivatives`:
 *
 *   POST   /questions                 register (builder write auth or owner)
 *   GET    /questions                 list (owner; builder with ?derivedScope=)
 *   GET    /questions/:id             status (owner or the registering builder)
 *   POST   /questions/:id/recompute   owner or the registering builder
 *   DELETE /questions/:id             owner or the registering builder
 *
 * Builder authentication is the Write API's: a write-session bearer token
 * plus the X-Vana-Write-Signature proof over the request, authorized for
 * `write:<derivedScope>` (api-auth authorizeWrite). No new credential.
 *
 * The proof signs the request URI INCLUDING its query string (see
 * canonicalSignedUri in write/attribution.ts), because on the list route the
 * query decides the authorization: `?derivedScope=X` is the scope the caller
 * is authorized against, and a proof that did not commit to it could be
 * captured on one scope and replayed on another.
 */

import {
  ContentTooLargeError,
  DerivativeComputeUnavailableError,
  DerivativeDerivedScopeRequiredError,
  DerivativeQuestionNotFoundError,
  DerivativeSourceNotGrantedError,
  ProtocolError,
} from "../errors/catalog.js";
import { parseJsonObjectBody } from "../contracts/http.js";
import { parseDataScopeContract } from "../contracts/data.js";
import { selectedGrantId } from "../api/index.js";
import type {
  PersonalServerApiAuthPort,
  PersonalServerApiDispatchOptions,
  PersonalServerWriteAuthResult,
  PersonalServerWriteSessionResult,
} from "../api/index.js";
import {
  createQuestionRegistration,
  parseQuestionInput,
  uncoveredSourceScopes,
} from "./registration.js";
import type { RecomputeScheduler } from "./scheduler.js";
import {
  questionRegistrationView,
  type QuestionRegisteredBy,
  type QuestionRegistration,
  type QuestionStore,
} from "./types.js";

/** Registration bodies are small; anything larger is refused up front. */
export const MAX_QUESTION_BODY_BYTES = 16 * 1024;

/** Poll hint served while a retry compute is in flight (no scheduled time). */
const RETRY_IN_FLIGHT_POLL_SECONDS = 5;

export interface PersonalServerDerivativesApiDeps {
  auth: Pick<
    PersonalServerApiAuthPort,
    | "authorizeOwner"
    | "authorizeWrite"
    | "authorizeWriteSession"
    | "authorizeBuilderRead"
  >;
  /** Absent = the compute layer is not wired; every route answers 503. */
  compute?: {
    store: QuestionStore;
    scheduler: Pick<
      RecomputeScheduler,
      "requestRecompute" | "markSourceChanged" | "markDemand"
    > & {
      /**
       * Next scheduled automatic retry of a failed question (ISO time), or
       * null. Optional so a minimal scheduler stays a valid dependency; the
       * status route then reports no retry.
       */
      nextRetryAt?(questionId: string): string | null;
      /** True while a retry compute is running (timer fired, not settled). */
      retryInFlight?(questionId: string): boolean;
    };
  } | null;
  now?: () => Date;
  createQuestionId?: () => string;
  logger?: {
    info?(payload: Record<string, unknown>, message: string): void;
  };
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

function errorResponse(
  status: number,
  errorCode: string,
  message: string,
): Response {
  return jsonResponse(
    { error: { code: status, errorCode, message } },
    { status },
  );
}

function stripBasePath(pathname: string, basePath: string | undefined): string {
  if (!basePath || basePath === "/") return pathname;
  if (pathname === basePath) return "/";
  if (pathname.startsWith(`${basePath}/`))
    return pathname.slice(basePath.length);
  return pathname;
}

/**
 * Authorize as the owner or, through the write-session path, as a builder
 * holding `write:<scope>`. Returns the builder result or undefined (owner).
 */
async function authorizeOwnerOrWriter(
  deps: PersonalServerDerivativesApiDeps,
  request: Request,
  scope: string,
): Promise<PersonalServerWriteAuthResult | undefined> {
  if (deps.auth.authorizeWrite) {
    return (await deps.auth.authorizeWrite({ request, scope })) ?? undefined;
  }
  await deps.auth.authorizeOwner(request);
  return undefined;
}

function sameBuilder(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * Is this a builder call at all? Identity only (no scope is authorized), for
 * the two answers that have no scope to authorize against: an unknown
 * question id and a list call with no `?derivedScope=`. Nothing is disclosed
 * either way, and the caller's proof is handed straight back — the request
 * ends in an error, so it must not burn the proof.
 */
async function recognizeWriteSession(
  deps: PersonalServerDerivativesApiDeps,
  request: Request,
): Promise<PersonalServerWriteSessionResult | undefined> {
  if (!deps.auth.authorizeWriteSession) return undefined;
  const session = (await deps.auth.authorizeWriteSession(request)) ?? undefined;
  await session?.releaseProof?.();
  return session;
}

/**
 * The registration a caller may act on, or a 404 for everyone who may not:
 * the owner sees every registration; a builder sees the ones it registered.
 * An id the store does not hold is 404 for any authenticated caller (a
 * builder holding a live write session, or the owner) and 401 for everyone
 * else, so a builder learns nothing from probing ids that it could not learn
 * from probing another builder's ids, which already answers 404.
 */
async function loadForCaller(
  deps: PersonalServerDerivativesApiDeps,
  request: Request,
  store: QuestionStore,
  questionId: string,
): Promise<{
  registration: QuestionRegistration;
  writer: PersonalServerWriteAuthResult | undefined;
}> {
  const registration = await store.get(questionId);
  if (!registration) {
    // No registration means no derived scope to authorize a builder against,
    // so fall back to identity: a live write session is enough to be told
    // 404. Without it the owner gate decides (and answers 401).
    if (!(await recognizeWriteSession(deps, request))) {
      await deps.auth.authorizeOwner(request);
    }
    throw new DerivativeQuestionNotFoundError({ questionId });
  }
  const writer = await authorizeOwnerOrWriter(
    deps,
    request,
    registration.derivedScope,
  );
  if (writer) {
    const by = registration.registeredBy;
    if (by.kind !== "builder" || !sameBuilder(by.builder, writer.builder)) {
      await writer.releaseProof?.();
      throw new DerivativeQuestionNotFoundError({ questionId });
    }
  }
  return { registration, writer };
}

/**
 * `GET /v1/derivatives/status?derivedScope=<scope>`: the lifecycle of the
 * question behind a derived scope, for the party that will READ the answer.
 *
 * Authorization is the data read's (`authorizeBuilderRead`, i.e. a live
 * grant covering the derived scope, or the owner) — deliberately NOT the
 * write-session path, because a consent-flow reader holds only a bare read
 * entry and can never open a write session. Nothing is served and nothing
 * is charged: this is authorization only, no x402 challenge and no
 * RECORD_DATA_ACCESS receipt, the same bar as the lineage read.
 *
 * The view is deliberately narrow: lifecycle only. The question text, the
 * source scopes, the question id, the registrar and the raw error string
 * stay owner-only — `errorCode` is a closed vocabulary precisely so a
 * stored error like "source scope X is deleted" cannot leak a scope name.
 * One class needs the same care as the raw string: `grant_invalid` arises
 * only from a builder-registered question, so a third-party reader gets
 * `internal` instead of learning who registered.
 * Auth runs before the store lookup, so an uncovered caller cannot probe
 * which scopes have questions behind them.
 *
 * Like every Web3Signed read (data, lineage), the signature covers the
 * path, not the query; per-scope authorization is enforced live against
 * the caller's grant on each request.
 */
async function handleStatusRoute(
  request: Request,
  url: URL,
  deps: PersonalServerDerivativesApiDeps,
  store: QuestionStore,
  scheduler: NonNullable<
    PersonalServerDerivativesApiDeps["compute"]
  >["scheduler"],
  now: () => Date,
): Promise<Response> {
  if (request.method !== "GET") {
    return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
  }
  const derivedScopeParam = url.searchParams.get("derivedScope");
  if (!derivedScopeParam) {
    throw new DerivativeDerivedScopeRequiredError();
  }
  // Same grammar gate as every scope-taking route, before anything is
  // authorized: an arbitrary string never reaches the grant policy.
  const scopeResult = parseDataScopeContract(derivedScopeParam);
  if (!scopeResult.ok) {
    return errorResponse(
      scopeResult.status,
      scopeResult.body.error,
      scopeResult.body.message,
    );
  }
  const derivedScope = scopeResult.scope;
  const auth =
    (await deps.auth.authorizeBuilderRead({
      request,
      scope: derivedScope,
      grantId: selectedGrantId(request, url),
    })) ?? undefined;
  const registrations = await store.list({ derivedScope });
  if (registrations.length === 0) {
    throw new DerivativeQuestionNotFoundError({ derivedScope });
  }
  // Demand. Asking for the lifecycle of an answer IS asking for the answer:
  // a reader that finds the scope stale would otherwise poll a status that
  // nothing is working towards. Strictly after the authorization above —
  // an unauthenticated or refused poll must never spend an inference call —
  // and through the scheduler, which collapses concurrent demand into one
  // compute. The view below is the state the demand starts from; the run
  // reports itself through the next poll.
  scheduler.markDemand(derivedScope);
  // Several registrations may share a derived scope, and data serving is
  // registration-agnostic: if ANY of them is ready, the scope has an answer
  // and the reader must not be told "failed" by a duplicate that never
  // wrote anything. Report the most optimistic true state — ready, then an
  // in-flight recompute, then never-computed, then failed — and within a
  // class let the most recently updated registration speak.
  const STATUS_PRECEDENCE: Record<QuestionRegistration["status"], number> = {
    ready: 0,
    stale: 1,
    pending: 2,
    failed: 3,
  };
  const registration = registrations.reduce((best, candidate) => {
    const byStatus =
      STATUS_PRECEDENCE[candidate.status] - STATUS_PRECEDENCE[best.status];
    if (byStatus !== 0) return byStatus < 0 ? candidate : best;
    return candidate.updatedAt >= best.updatedAt ? candidate : best;
  });
  const nextRetryAt = scheduler.nextRetryAt?.(registration.questionId) ?? null;
  // While the retry compute is RUNNING there is no scheduled time, but null
  // would be the terminal "will never retry" signature; serve a short poll
  // hint instead. 0 is never served — it invites a tight poll loop.
  const retryAfterSeconds =
    nextRetryAt !== null
      ? Math.max(
          1,
          Math.ceil((Date.parse(nextRetryAt) - now().getTime()) / 1000),
        )
      : scheduler.retryInFlight?.(registration.questionId)
        ? RETRY_IN_FLIGHT_POLL_SECONDS
        : null;
  // `grant_invalid` can only come from the live re-check of a REGISTERING
  // BUILDER's grant, which an owner-registered question never runs. Serving
  // it to a third-party reader would therefore disclose the registrar class
  // the rest of this view withholds. The owner and the registrar itself lose
  // nothing — they are the two parties who can act on it — and everyone else
  // reads the honest generic class: something is wrong server-side and no
  // retry is coming.
  const registrarView =
    auth === undefined ||
    auth.grantId === "owner" ||
    auth.grantId === "policy-bypass" ||
    (registration.registeredBy.kind === "builder" &&
      typeof auth.builder === "string" &&
      sameBuilder(registration.registeredBy.builder, auth.builder));
  const disclosedErrorCode =
    registration.errorCode === "grant_invalid" && !registrarView
      ? "internal"
      : registration.errorCode;
  return jsonResponse({
    derivedScope: registration.derivedScope,
    status: registration.status,
    lastComputedAt: registration.lastComputedAt,
    derivedVersion: registration.derivedVersion,
    derivedCollectedAt: registration.derivedCollectedAt,
    // Null unless failed, whatever an old store row holds: a stale question
    // is a recompute in progress, not a terminal failure.
    errorCode: registration.status === "failed" ? disclosedErrorCode : null,
    retryAfterSeconds,
  });
}

export async function handlePersonalServerDerivativesRequest(
  request: Request,
  deps: PersonalServerDerivativesApiDeps,
  options: PersonalServerApiDispatchOptions = {},
): Promise<Response> {
  try {
    const url = new URL(request.url);
    const pathname = stripBasePath(url.pathname, options.basePath);
    const parts = pathname.split("/").filter(Boolean);
    const isStatusRoute = parts[0] === "status" && parts.length === 1;
    if (!isStatusRoute && (parts[0] !== "questions" || parts.length > 3)) {
      return errorResponse(404, "NOT_FOUND", "Not found");
    }
    const compute = deps.compute;
    if (!compute) throw new DerivativeComputeUnavailableError();
    const { store, scheduler } = compute;
    const now = deps.now ?? (() => new Date());

    // /status — the reader-facing lifecycle view of a derived scope.
    if (isStatusRoute) {
      return await handleStatusRoute(request, url, deps, store, scheduler, now);
    }

    // /questions
    if (parts.length === 1) {
      if (request.method === "GET") {
        const derivedScope = url.searchParams.get("derivedScope") ?? undefined;
        if (derivedScope) {
          const writer = await authorizeOwnerOrWriter(
            deps,
            request,
            derivedScope,
          );
          const registrations = await store.list({
            derivedScope,
            ...(writer ? { builder: writer.builder } : {}),
          });
          return jsonResponse({
            questions: registrations.map(questionRegistrationView),
          });
        }
        // The unfiltered list is the owner's. A builder that reached it
        // simply forgot the parameter, so say that instead of 401: the
        // 401 would send a re-handshake-on-401 client through a handshake
        // and then report an authentication problem it does not have.
        if (await recognizeWriteSession(deps, request)) {
          throw new DerivativeDerivedScopeRequiredError();
        }
        await deps.auth.authorizeOwner(request);
        const registrations = await store.list();
        return jsonResponse({
          questions: registrations.map(questionRegistrationView),
        });
      }
      if (request.method === "POST") {
        // The derived scope decides which write grant must cover the call,
        // so the body is read (from a clone: the proof check reads it too)
        // before authorization. Nothing is stored until auth passed.
        const declared = Number(request.headers.get("content-length") ?? "0");
        if (declared > MAX_QUESTION_BODY_BYTES) {
          throw new ContentTooLargeError({ max: MAX_QUESTION_BODY_BYTES });
        }
        const bodyBytes = new Uint8Array(await request.clone().arrayBuffer());
        if (bodyBytes.byteLength > MAX_QUESTION_BODY_BYTES) {
          throw new ContentTooLargeError({ max: MAX_QUESTION_BODY_BYTES });
        }
        const parsed = await parseJsonObjectBody(
          request.clone(),
          "Request body must be valid JSON",
        );
        if (!parsed.ok) {
          return jsonResponse(parsed.result.body, {
            status: parsed.result.status,
          });
        }
        const rawScope = parsed.body.derivedScope;
        const scopeForAuth = typeof rawScope === "string" ? rawScope : "";
        const writer = await authorizeOwnerOrWriter(
          deps,
          request,
          scopeForAuth,
        );
        const registeredBy: QuestionRegisteredBy = writer
          ? {
              kind: "builder",
              builder: writer.builder,
              grantId: writer.grantId,
            }
          : { kind: "owner" };
        let registration: QuestionRegistration;
        try {
          if (writer) {
            // Consent: the answer exposes the sources to the builder, so
            // every source must be read-granted to it. Fail closed when
            // the auth port did not hand over the grant's scopes.
            const input = parseQuestionInput(parsed.body);
            const uncovered = uncoveredSourceScopes(
              input.sourceScopes,
              writer.grantScopes,
            );
            if (uncovered.length > 0) {
              throw new DerivativeSourceNotGrantedError({ scopes: uncovered });
            }
          }
          registration = await createQuestionRegistration({
            body: parsed.body,
            registeredBy,
            store,
            questionId: deps.createQuestionId?.() ?? crypto.randomUUID(),
            now,
          });
        } catch (err) {
          // Nothing stored: hand the builder's proof back for a retry.
          await writer?.releaseProof?.();
          throw err;
        }
        deps.logger?.info?.(
          {
            questionId: registration.questionId,
            derivedScope: registration.derivedScope,
            sourceScopes: registration.sourceScopes,
            registeredBy: registeredBy.kind,
            ...(writer
              ? { builder: writer.builder, grantId: writer.grantId }
              : {}),
          },
          "Derivative question registered",
        );
        scheduler.requestRecompute(registration.questionId, {
          immediate: true,
        });
        return jsonResponse(questionRegistrationView(registration), {
          status: 201,
        });
      }
      return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
    }

    const questionId = decodeURIComponent(parts[1] ?? "");

    // /questions/:id/recompute
    if (parts.length === 3) {
      if (parts[2] !== "recompute") {
        return errorResponse(404, "NOT_FOUND", "Not found");
      }
      if (request.method !== "POST") {
        return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
      }
      // Owner, or the registering builder (its retry after a transient
      // failure); same gate as GET / DELETE.
      const { registration } = await loadForCaller(
        deps,
        request,
        store,
        questionId,
      );
      scheduler.requestRecompute(questionId, { immediate: true });
      // The same registration view every other route returns, so a client
      // needs one schema. The status is the one the scheduled run starts
      // from: a question that never computed stays `pending`, anything else
      // is `stale` until the run lands.
      return jsonResponse(
        questionRegistrationView({
          ...registration,
          status: registration.status === "pending" ? "pending" : "stale",
        }),
        { status: 202 },
      );
    }

    // /questions/:id
    if (request.method === "GET") {
      const { registration } = await loadForCaller(
        deps,
        request,
        store,
        questionId,
      );
      return jsonResponse(questionRegistrationView(registration));
    }
    if (request.method === "DELETE") {
      const { registration } = await loadForCaller(
        deps,
        request,
        store,
        questionId,
      );
      await store.delete(questionId);
      deps.logger?.info?.(
        { questionId, derivedScope: registration.derivedScope },
        "Derivative question deleted",
      );
      return jsonResponse({ questionId, deleted: true });
    }
    return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
  } catch (err) {
    if (err instanceof ProtocolError) {
      return jsonResponse(err.toJSON(), { status: err.code });
    }
    return errorResponse(500, "INTERNAL_ERROR", "Internal server error");
  }
}
