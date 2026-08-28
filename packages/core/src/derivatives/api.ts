/**
 * HTTP surface of the compute layer, mounted under `/v1/derivatives`:
 *
 *   POST   /questions                 register (builder write auth or owner)
 *   GET    /questions                 list (owner; builder with ?derivedScope=)
 *   GET    /questions/:id             status (owner or the registering builder)
 *   POST   /questions/:id/recompute   owner only
 *   DELETE /questions/:id             owner or the registering builder
 *
 * Builder authentication is the Write API's: a write-session bearer token
 * plus the X-Vana-Write-Signature proof over the request, authorized for
 * `write:<derivedScope>` (api-auth authorizeWrite). No new credential.
 */

import {
  DerivativeComputeUnavailableError,
  DerivativeQuestionNotFoundError,
  ProtocolError,
} from "../errors/catalog.js";
import { parseJsonObjectBody } from "../contracts/http.js";
import type {
  PersonalServerApiAuthPort,
  PersonalServerApiDispatchOptions,
  PersonalServerWriteAuthResult,
} from "../api/index.js";
import { createQuestionRegistration } from "./registration.js";
import type { RecomputeScheduler } from "./scheduler.js";
import {
  questionRegistrationView,
  type QuestionRegisteredBy,
  type QuestionRegistration,
  type QuestionStore,
} from "./types.js";

export interface PersonalServerDerivativesApiDeps {
  auth: Pick<PersonalServerApiAuthPort, "authorizeOwner" | "authorizeWrite">;
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
 * The registration a caller may act on, or a 404 for everyone who may not:
 * the owner sees every registration; a builder sees the ones it registered.
 * An id the store does not hold is answered after owner auth, so a builder
 * learns nothing from probing ids.
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
    await deps.auth.authorizeOwner(request);
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
      await deps.auth.authorizeOwner(request);
      const registration = await store.get(questionId);
      if (!registration)
        throw new DerivativeQuestionNotFoundError({ questionId });
      scheduler.requestRecompute(questionId, { immediate: true });
      return jsonResponse(
        {
          questionId,
          status: registration.status === "pending" ? "pending" : "stale",
          derivedScope: registration.derivedScope,
        },
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
