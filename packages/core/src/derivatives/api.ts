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

export interface PersonalServerDerivativesApiDeps {
  auth: Pick<
    PersonalServerApiAuthPort,
    "authorizeOwner" | "authorizeWrite" | "authorizeWriteSession"
  >;
  /** Absent = the compute layer is not wired; every route answers 503. */
  compute?: {
    store: QuestionStore;
    scheduler: Pick<
      RecomputeScheduler,
      "requestRecompute" | "markSourceChanged"
    >;
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

export async function handlePersonalServerDerivativesRequest(
  request: Request,
  deps: PersonalServerDerivativesApiDeps,
  options: PersonalServerApiDispatchOptions = {},
): Promise<Response> {
  try {
    const url = new URL(request.url);
    const pathname = stripBasePath(url.pathname, options.basePath);
    const parts = pathname.split("/").filter(Boolean);
    if (parts[0] !== "questions" || parts.length > 3) {
      return errorResponse(404, "NOT_FOUND", "Not found");
    }
    const compute = deps.compute;
    if (!compute) throw new DerivativeComputeUnavailableError();
    const { store, scheduler } = compute;
    const now = deps.now ?? (() => new Date());

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
