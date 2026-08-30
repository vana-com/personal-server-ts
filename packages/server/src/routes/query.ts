/**
 * Query routes — the owner asks questions of their own Personal Server data
 * (implementation plan phase 8).
 *
 * `GET  /v1/query/scopes` — what the owner could ask about.
 * `POST /v1/query/ask`    — one question. SSE by default so the desktop chat
 *                           page can show reasoning as it happens; add
 *                           `?stream=false` for a single JSON `QueryAnswer`.
 *
 * ## Auth
 *
 * `createServerApiAuth(...).authorizeOwner`, constructed and called exactly
 * as `routes/grants.ts` and `routes/access-logs.ts` do. Nothing about this
 * route's auth is special, and nothing here weakens it: a caller that cannot
 * prove it is the server owner gets the same 401/403 it gets from
 * `/v1/grants`.
 *
 * ## The grant
 *
 * For an owner-authenticated request the grant IS the owner's own scopes, as
 * `DataStoragePort.listScopes` reports them — the owner is the subject of
 * every record on this server and `authorizeOwner` has already established
 * that the caller is them. A request body may NARROW that set and can never
 * widen it (`resolveGrant`); a scope named in the body that the owner does
 * not hold comes back in `coverage.scopesSkipped`, not as data.
 *
 * ## Metering and access logs
 *
 * Phase 8 requires the sweep to "settle and log per scope touched". The
 * existing path expresses that directly and this route reuses it unchanged:
 * one `AccessLogWriter.write` row per scope, `action: "read"`,
 * `grantId: "owner"` — the same row `GET /v1/data/:scope` writes for an owner
 * read, with a fresh `logId` each time. There is no settlement to perform:
 * owner reads have never been charged (`api/index.ts` exempts the `"owner"`
 * grant sentinel from the x402 cycle), and the read-fulfillment reporter
 * suppresses the `"owner"` grantId by design. So a question that scans eight
 * scopes writes eight access-log rows and settles nothing — which is what
 * eight owner `read_scope` calls would have done.
 */

import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { Logger } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";

import type { InferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";

import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import {
  QueryBusyError,
  createQueryConcurrency,
  resolveMaxConcurrent,
  runQuery,
  type QueryConcurrency,
  type QueryEvent,
  type QueryScopePayload,
  type QueryScopeReader,
} from "../query/query-service.js";

export interface QueryRouteDeps {
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /** The same port the data routes read through. */
  dataStorage: DataStoragePort;
  /** The same writer `GET /v1/data/:scope` logs through. */
  accessLogWriter: AccessLogWriter;
  /** The bootstrap's provider: E2EE, relay signing and receipts included. */
  inferenceProvider?: InferenceProvider;
  /** Concurrent questions ceiling. Defaults to `PS_QUERY_MAX_CONCURRENT` or 4. */
  maxConcurrent?: number;
  /** Shared across routes in tests; one is created per route otherwise. */
  concurrency?: QueryConcurrency;
  /** Injected for tests; defaults to `crypto.randomUUID`. */
  createLogId?: () => string;
  /** Injected for tests; defaults to `Date`. */
  now?: () => Date;
}

/** How many scopes the owner's grant may name. Matches the temp scaffolding. */
const MAX_OWNER_SCOPES = 500;

export function queryRoutes(deps: QueryRouteDeps): Hono {
  const app = new Hono();

  /**
   * Map `ProtocolError` here rather than relying on the app-level handler.
   *
   * `routes/grants.ts` and `routes/access-logs.ts` never need this because
   * they delegate to core handlers that *return* an error Response; this
   * route throws, the way `routes/mcp.ts` does. Owning the mapping keeps the
   * route's error contract true when it is mounted anywhere — including in a
   * test that exercises it on its own, where a 401 silently becoming a 500
   * would make the auth assertions meaningless.
   */
  app.onError((err, c) => {
    if (err instanceof ProtocolError) {
      deps.logger.warn({ err }, err.message);
      return c.json(err.toJSON(), err.code as 400 | 401 | 403 | 503);
    }
    deps.logger.error({ err }, "Unhandled query route error");
    return c.json(
      {
        error: {
          code: 500,
          errorCode: "INTERNAL_ERROR",
          message: "Internal server error",
        },
      },
      500,
    );
  });

  // Identical construction to routes/grants.ts and routes/access-logs.ts.
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  const concurrency =
    deps.concurrency ??
    createQueryConcurrency(resolveMaxConcurrent(deps.maxConcurrent));

  const ownerScopes = () =>
    deps.dataStorage.listScopes({ limit: MAX_OWNER_SCOPES }).scopes;

  /**
   * The owner's read path, one scope at a time.
   *
   * The access-log row is written on the way out, after the bytes are in
   * hand, so a scope that could not be read is not logged as read — the same
   * ordering `handlePersonalServerDataRequest` uses.
   */
  const createReader = (request: Request): QueryScopeReader => {
    const ipAddress =
      request.headers.get("x-forwarded-for") ??
      request.headers.get("x-real-ip") ??
      "unknown";
    const userAgent = request.headers.get("user-agent") ?? "unknown";
    const newLogId = deps.createLogId ?? (() => crypto.randomUUID());
    const clock = deps.now ?? (() => new Date());

    return {
      grantedScopes: () => ownerScopes().map((s) => s.scope),
      async readScope(scope: string): Promise<QueryScopePayload> {
        const entry = deps.dataStorage.findEntry({ scope });
        if (!entry) throw new Error("no local version of this scope");
        const envelope = await deps.dataStorage.readEnvelope(
          scope,
          entry.collectedAt,
        );
        await deps.accessLogWriter.write({
          logId: newLogId(),
          // `authorizeOwner` has already proven the caller is the owner, so
          // the owner address is the builder — the identical pair the data
          // route logs for an owner read.
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
  };

  /** GET /scopes — what the owner could ask about. */
  app.get("/scopes", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const scopes = ownerScopes().map((s) => ({
      scope: s.scope,
      latestCollectedAt: s.latestCollectedAt,
      versionCount: s.versionCount,
      sizeBytes: s.sizeBytes ?? null,
      dataStatus: s.dataStatus ?? null,
    }));
    return c.json({ scopes, maxConcurrentQueries: concurrency.limit });
  });

  /**
   * POST /ask — one question.
   *
   * Body: `{ question, scopes?, budget?, model? }`.
   *
   * SSE events, in order: `start` (the resolved grant and how each scope was
   * materialized), `turn` (one model reply and how the contract parsed it),
   * `script` (a script about to run), `run` (that script's host-authored
   * coverage and termination), `answer` (the final `QueryAnswer`), or `error`
   * for a transport failure. An ordinary bad outcome is an `answer` with
   * honest coverage, never an `error`.
   */
  app.post("/ask", async (c) => {
    await auth.authorizeOwner(c.req.raw);

    const provider = deps.inferenceProvider;
    if (!provider) {
      throw new ProtocolError(
        503,
        "INFERENCE_UNAVAILABLE",
        "No inference provider is configured on this server.",
      );
    }

    const body = (await c.req.json().catch(() => ({}))) as {
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
    const budget = normalizeBudget(body.budget);
    const reader = createReader(c.req.raw);

    // The busy check runs BEFORE the stream opens: a 503 with a JSON body is
    // a far better answer than a 200 whose first SSE frame is an error.
    if (concurrency.inFlight >= concurrency.limit) {
      throw new ProtocolError(
        503,
        "QUERY_BUSY",
        new QueryBusyError(concurrency.limit).message,
      );
    }

    if (c.req.query("stream") === "false") {
      try {
        const answer = await runQuery({
          reader,
          provider,
          question,
          concurrency,
          ...(scopes ? { scopes } : {}),
          ...(budget ? { budget } : {}),
          ...(model ? { model } : {}),
        });
        return c.json(answer);
      } catch (err) {
        if (err instanceof QueryBusyError) {
          throw new ProtocolError(503, "QUERY_BUSY", err.message);
        }
        throw err;
      }
    }

    return streamSSE(c, async (sse) => {
      const send = (event: string, data: unknown) =>
        sse.writeSSE({ event, data: JSON.stringify(data) });
      try {
        await runQuery({
          reader,
          provider,
          question,
          concurrency,
          ...(scopes ? { scopes } : {}),
          ...(budget ? { budget } : {}),
          ...(model ? { model } : {}),
          onEvent: async (event: QueryEvent) => {
            const { type, ...rest } = event;
            await send(type, type === "answer" ? event.answer : rest);
          },
        });
      } catch (err) {
        deps.logger.error({ err }, "query route failed");
        await send("error", {
          code: err instanceof QueryBusyError ? err.code : "QUERY_FAILED",
          message: err instanceof Error ? err.message : String(err),
        });
      }
    });
  });

  return app;
}

/**
 * Accept only the budget fields the loop actually honours, clamped.
 *
 * An unbounded `toolCalls` from a request body is a relay-spend hole: the
 * loop treats it as the hard ceiling on model turns and therefore on relay
 * calls.
 */
function normalizeBudget(
  input: unknown,
): { toolCalls?: number; wallClockMs?: number } | undefined {
  if (input === null || typeof input !== "object") return undefined;
  const raw = input as { toolCalls?: unknown; wallClockMs?: unknown };
  const budget: { toolCalls?: number; wallClockMs?: number } = {};
  if (typeof raw.toolCalls === "number" && Number.isFinite(raw.toolCalls)) {
    budget.toolCalls = Math.max(1, Math.min(30, Math.floor(raw.toolCalls)));
  }
  if (typeof raw.wallClockMs === "number" && Number.isFinite(raw.wallClockMs)) {
    budget.wallClockMs = Math.max(
      1_000,
      Math.min(600_000, Math.floor(raw.wallClockMs)),
    );
  }
  return Object.keys(budget).length > 0 ? budget : undefined;
}
