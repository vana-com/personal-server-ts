/**
 * PS-Lite's HTTP surface for the query layer — the browser twin of
 * `packages/server/src/routes/query.ts`.
 *
 * `GET  {base}/scopes` — what the owner could ask about.
 * `POST {base}/ask`    — one question.
 *
 * Until this file existed the query layer was reachable on PS-Lite only by an
 * embedding host that imported `createLiteAskPersonalDataPort` or
 * `runLiteQuery` itself. Nothing in `packages/lite` constructed either, so a
 * browser Personal Server had no route to ask a question through and
 * `ask_personal_data` answered `query_unavailable`. The engine was built and
 * measured (design §19.18) but never mounted.
 *
 * ## Why the engine is INJECTED and not imported
 *
 * `quickjs-sandbox.ts` statically imports
 * `@jitl/quickjs-singlefile-browser-release-sync`, which base64-inlines a
 * ~1.1 MB WASM engine. This file therefore imports `./lite-query-service.js`
 * for TYPES ONLY and never as a value: the runner arrives through
 * {@link LiteQueryConfig.ask}.
 *
 * A dynamic `await import("./lite-query-service.js")` here was tried first and
 * MEASURED as a regression: esbuild's single-file output (`--outfile`, no
 * `--splitting`) inlines a dynamic import rather than emitting a chunk, so the
 * `ps-lite-debug` bundle went from 6,297,472 to 7,377,258 bytes — the engine in
 * every PS-Lite bundle, including the mobile `ps-lite-bundle.js` where WASM has
 * never run at all (design §19.18: Android WebView and iOS WKWebView are both
 * UNVERIFIED). Injection keeps `createPsLiteRuntime`'s module graph exactly
 * what it was, so a host that never wires the query layer never pays a byte
 * for it. `createLiteQueryAsk` in `./wire.js` is the one-line wiring for a host
 * that does want it — importing THAT module is what pulls the engine in, which
 * is the point.
 *
 * ## Auth, grant, and metering are the Node route's, not new ones
 *
 * The caller must prove it is the server owner (`authorizeOwner`, the same
 * check `/v1/grants` and `/v1/derivatives` use on this runtime). The grant IS
 * the owner's own scopes as `DataStoragePort.listScopes` reports them; a body
 * may NARROW that set and can never widen it. One `AccessLogWriter.write` row
 * per scope actually read, `action: "read"`, `grantId: "owner"` — the same row
 * an owner `GET /v1/data/:scope` writes, written after the bytes are in hand so
 * an unreadable scope is not logged as read.
 *
 * ## Streaming
 *
 * SSE by default with `?stream=false` for a single JSON `QueryAnswer` — the
 * Node route's contract, character for character, so a client written against
 * one runtime works against the other. The desktop query-chat page already
 * POSTs `/v1/query/ask` with no query parameter and parses SSE frames, and
 * that client must not have to know which runtime answered it.
 *
 * KNOWN LIMITATION, and the reason `stream=false` matters more here than on
 * Node: PS-Lite's relay bridge serialises every response through
 * `buildHttpResponse`, which decodes the whole body and emits an authoritative
 * `content-length` with `connection: close` (`relay.ts:712-745`). Nothing in
 * `packages/lite` streams today. So SSE works for a caller holding the
 * `Response` from `runtime.fetch` in the page, and a caller reaching this
 * server THROUGH THE RELAY will receive the stream buffered into one frame at
 * the end rather than incrementally. That is a relay-bridge property, not
 * something this route can fix, and it is why `stream=false` is offered.
 */

import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { QueryAnswer } from "@opendatalabs/personal-server-ts-core/query/agent";

// Types only, and it must STAY types only: `import type` is erased, so this
// does not pull the QuickJS engine into the module graph. See the header.
import type {
  LiteQueryEvent,
  LiteScopePayload,
  LiteScopeReader,
} from "./lite-query-service.js";

/** What the route hands the injected runner. */
export interface LiteQueryAskInput {
  reader: LiteScopeReader;
  question: string;
  scopes?: readonly string[];
  model?: string;
  budget?: { toolCalls?: number; outputBytes?: number };
  onEvent?: (event: LiteQueryEvent) => void | Promise<void>;
}

/**
 * The engine, injected.
 *
 * `createLiteQueryAsk` (`./wire.js`) builds one over `runLiteQuery`; a test
 * supplies a fake without loading QuickJS at all.
 */
export type LiteQueryAsk = (input: LiteQueryAskInput) => Promise<QueryAnswer>;

/** How many scopes the owner's grant may name. Matches the Node route. */
const MAX_OWNER_SCOPES = 500;

/**
 * Questions in flight at once, default.
 *
 * One, where the Node route defaults to four. This is not caution for its own
 * sake: `LITE_QUERY_LIMITS.memoryMb` is 512, so two concurrent runs ask one
 * browser tab for a gigabyte of WASM heap, and a tab has no way to shed load
 * when that fails — it dies, taking the owner's session with it.
 */
const DEFAULT_MAX_CONCURRENT = 1;

export interface LiteQueryConfig {
  /**
   * The runner. Built by `createLiteQueryAsk` (`./wire.js`), which is where
   * the inference provider and the T2 profiles are bound.
   */
  ask: LiteQueryAsk;
  /** Concurrent questions ceiling. Defaults to {@link DEFAULT_MAX_CONCURRENT}. */
  maxConcurrent?: number;
}

export interface LiteQueryRouteDeps {
  authorizeOwner: (request: Request) => Promise<void>;
  /** The same port the data routes read through. */
  dataStorage: DataStoragePort;
  /** The same writer `GET /v1/data/:scope` logs through. */
  accessLogWriter: AccessLogWriter;
  serverOwner?: string;
  /** Absent = the routes answer 503 and nothing else changes. */
  query?: LiteQueryConfig | null;
  now?: () => Date;
  createLogId?: () => string;
}

/** Mutable in-flight count, per route instance. */
export interface LiteQueryConcurrency {
  readonly limit: number;
  inFlight: number;
}

export function createLiteQueryConcurrency(
  limit: number,
): LiteQueryConcurrency {
  return { limit: Math.max(1, Math.floor(limit)), inFlight: 0 };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

/**
 * The owner's read path, one scope at a time.
 *
 * Identical in shape to the Node route's `createReader`, including the ordering
 * of the access-log write.
 */
function createReader(
  request: Request,
  deps: LiteQueryRouteDeps,
): LiteScopeReader {
  const ipAddress =
    request.headers.get("x-forwarded-for") ??
    request.headers.get("x-real-ip") ??
    "unknown";
  const userAgent = request.headers.get("user-agent") ?? "unknown";
  const newLogId = deps.createLogId ?? (() => crypto.randomUUID());
  const clock = deps.now ?? (() => new Date());
  const ownerScopes = () =>
    deps.dataStorage.listScopes({ limit: MAX_OWNER_SCOPES }).scopes;

  return {
    grantedScopes: () => ownerScopes().map((s) => s.scope),
    async readScope(scope: string): Promise<LiteScopePayload> {
      const entry = deps.dataStorage.findEntry({ scope });
      if (!entry) throw new Error("no local version of this scope");
      const envelope = await deps.dataStorage.readEnvelope(
        scope,
        entry.collectedAt,
      );
      await deps.accessLogWriter.write({
        logId: newLogId(),
        // `authorizeOwner` has already proven the caller is the owner, so the
        // owner address is the builder — the identical pair the data route
        // logs for an owner read.
        grantId: "owner",
        builder: deps.serverOwner ?? "unknown",
        action: "read",
        scope,
        timestamp: clock().toISOString(),
        ipAddress,
        userAgent,
      });
      return {
        data: envelope,
        collectedAt: entry.collectedAt,
        version: String(entry.version),
      };
    },
  };
}

interface AskBody {
  question: string;
  scopes?: readonly string[];
  model?: string;
  budget?: { toolCalls?: number; outputBytes?: number };
}

function parseAskBody(raw: unknown): AskBody {
  const body = (raw ?? {}) as {
    question?: unknown;
    scopes?: unknown;
    model?: unknown;
    budget?: unknown;
  };
  const question =
    typeof body.question === "string" ? body.question.trim() : "";
  if (question === "") {
    throw new ProtocolError(
      400,
      "INVALID_REQUEST",
      "`question` is required and must be a non-empty string.",
    );
  }
  const scopes = Array.isArray(body.scopes)
    ? body.scopes.filter((s): s is string => typeof s === "string")
    : undefined;
  const model = typeof body.model === "string" ? body.model : undefined;

  // Narrow only: a body may lower a budget and never raise it past what the
  // service's own default allows, because the service clamps to
  // LITE_QUERY_BUDGET when the field is absent.
  const rawBudget = body.budget as
    { toolCalls?: unknown; outputBytes?: unknown } | undefined;
  const budget =
    rawBudget && typeof rawBudget === "object"
      ? {
          ...(typeof rawBudget.toolCalls === "number" &&
          Number.isFinite(rawBudget.toolCalls)
            ? { toolCalls: Math.max(1, Math.floor(rawBudget.toolCalls)) }
            : {}),
          ...(typeof rawBudget.outputBytes === "number" &&
          Number.isFinite(rawBudget.outputBytes)
            ? { outputBytes: Math.max(1, Math.floor(rawBudget.outputBytes)) }
            : {}),
        }
      : undefined;

  return {
    question,
    ...(scopes ? { scopes } : {}),
    ...(model ? { model } : {}),
    ...(budget && Object.keys(budget).length > 0 ? { budget } : {}),
  };
}

/**
 * Handle a query request, or return `undefined` for a path this route does not
 * own so the caller can continue matching.
 */
export async function handleLiteQueryRequest(
  request: Request,
  deps: LiteQueryRouteDeps,
  options: { basePath?: string; concurrency?: LiteQueryConcurrency } = {},
): Promise<Response | undefined> {
  const basePath = options.basePath ?? "/v1/query";
  const url = new URL(request.url);
  const { pathname } = url;

  const isScopes = pathname === `${basePath}/scopes`;
  const isAsk = pathname === `${basePath}/ask`;
  if (!isScopes && !isAsk) return undefined;

  await deps.authorizeOwner(request);

  const config = deps.query ?? null;
  const concurrency =
    options.concurrency ??
    createLiteQueryConcurrency(config?.maxConcurrent ?? DEFAULT_MAX_CONCURRENT);

  if (isScopes) {
    if (request.method !== "GET") {
      throw new ProtocolError(405, "METHOD_NOT_ALLOWED", "Use GET.");
    }
    const scopes = deps.dataStorage
      .listScopes({ limit: MAX_OWNER_SCOPES })
      .scopes.map((s) => ({
        scope: s.scope,
        latestCollectedAt: s.latestCollectedAt,
        versionCount: s.versionCount,
        sizeBytes: s.sizeBytes ?? null,
        dataStatus: s.dataStatus ?? null,
      }));
    return json({ scopes, maxConcurrentQueries: concurrency.limit });
  }

  if (request.method !== "POST") {
    throw new ProtocolError(405, "METHOD_NOT_ALLOWED", "Use POST.");
  }

  if (!config) {
    throw new ProtocolError(
      503,
      "INFERENCE_UNAVAILABLE",
      "No inference provider is configured on this server.",
    );
  }

  const body = parseAskBody(await request.json().catch(() => ({})));

  // The busy check runs BEFORE the stream opens: a 503 with a JSON body is a
  // far better answer than a 200 whose first SSE frame is an error.
  if (concurrency.inFlight >= concurrency.limit) {
    throw new ProtocolError(
      503,
      "QUERY_BUSY",
      `This server is already answering ${concurrency.limit} question(s). Try again when one finishes.`,
    );
  }

  const reader = createReader(request, deps);
  const streaming = url.searchParams.get("stream") !== "false";

  if (!streaming) {
    concurrency.inFlight += 1;
    try {
      const answer = await config.ask({
        reader,
        question: body.question,
        ...(body.scopes ? { scopes: body.scopes } : {}),
        ...(body.model ? { model: body.model } : {}),
        ...(body.budget ? { budget: body.budget } : {}),
      });
      return json(answer);
    } finally {
      concurrency.inFlight -= 1;
    }
  }

  concurrency.inFlight += 1;
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(
          encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
        );
      };
      try {
        await config.ask({
          reader,
          question: body.question,
          ...(body.scopes ? { scopes: body.scopes } : {}),
          ...(body.model ? { model: body.model } : {}),
          ...(body.budget ? { budget: body.budget } : {}),
          onEvent: (event: LiteQueryEvent) => {
            const { type, ...rest } = event;
            send(type, type === "answer" ? event.answer : rest);
          },
        });
      } catch (err) {
        // An ordinary bad outcome is an `answer` with honest coverage;
        // reaching here means the transport or the engine failed.
        send("error", {
          code: "QUERY_FAILED",
          message: err instanceof Error ? err.message : String(err),
        });
      } finally {
        concurrency.inFlight -= 1;
        controller.close();
      }
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-store",
      connection: "keep-alive",
    },
  });
}
