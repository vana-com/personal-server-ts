/**
 * `/v1/query` — the owner-authenticated entrypoint to the query layer.
 *
 * The properties under test are the ones a route can break that the service
 * below it cannot: that auth is the same gate `/v1/grants` uses, that the
 * grant is the owner's own scopes and only ever narrows, that a question
 * which touches N scopes writes N access-log rows, and that SSE delivers the
 * turns as they happen rather than as one lump at the end.
 */

import { describe, expect, it, vi } from "vitest";
import { pino } from "pino";

import {
  buildWeb3SignedHeader,
  createMemoryDataStorage,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createFakeInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import type {
  AccessLogEntry,
  AccessLogWriter,
} from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";

import { queryRoutes, type QueryRouteDeps } from "./query.js";
import { createQueryConcurrency } from "../query/query-service.js";

const logger = pino({ level: "silent" });
const SERVER_ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const stranger = createTestWallet(1);

/** A tiny corpus in the real on-disk shape: envelopes, not bare arrays. */
async function seedStorage(scopes: Record<string, unknown[]>) {
  const storage = createMemoryDataStorage();
  let n = 0;
  for (const [scope, items] of Object.entries(scopes)) {
    n += 1;
    const collectedAt = `2026-01-0${n}T00:00:00.000Z`;
    const write = await storage.writeEnvelope({
      version: 1,
      scope,
      collectedAt,
      data: { items },
    } as never);
    await storage.insertEntry({
      fileId: `file-${n}`,
      path: write.relativePath,
      scope,
      collectedAt,
      sizeBytes: write.sizeBytes,
    });
  }
  return storage;
}

function collectingLog(): AccessLogWriter & { rows: AccessLogEntry[] } {
  const rows: AccessLogEntry[] = [];
  return {
    rows,
    async write(entry) {
      rows.push(entry);
    },
  };
}

/**
 * A provider that writes one script sweeping the named scopes, then answers.
 *
 * The scope list is passed in rather than parsed out of the system prompt, so
 * a change to the prompt's wording cannot quietly turn a sweep into a no-op
 * and leave `recordsScanned: 0` looking like a passing coverage assertion.
 */
function sweepingProvider(scopes: string[]) {
  const body = scopes
    .map((s) => `total += (await vana.readAll(${JSON.stringify(s)})).length;`)
    .join("\n");
  return createFakeInferenceProvider({
    respond: (_input, n) =>
      n === 0
        ? {
            content:
              "```vana:run\nlet total = 0;\n" +
              body +
              '\nvana.result({ answer: "" + total, citations: [] });\n```',
          }
        : {
            content:
              "```vana:answer\n" +
              JSON.stringify({ answer: "swept", citations: [] }) +
              "\n```",
          },
  });
}

async function createApp(
  over: Partial<QueryRouteDeps> & {
    storage?: Awaited<ReturnType<typeof seedStorage>>;
  } = {},
) {
  const storage = over.storage ?? (await seedStorage({ "a.b": [{ x: 1 }] }));
  const accessLog = collectingLog();
  const deps: QueryRouteDeps = {
    logger,
    serverOrigin: SERVER_ORIGIN,
    serverOwner: owner.address,
    gateway: {} as GatewayClient,
    dataStorage: storage,
    accessLogWriter: accessLog,
    ...over,
  };
  return { app: queryRoutes(deps), accessLog, storage };
}

/**
 * A signed request for one question.
 *
 * The Web3Signed envelope binds the body hash, so the body has to be signed
 * with the request rather than attached afterwards — building both here keeps
 * them from drifting apart and silently turning an assertion into a 401.
 */
async function askRequest(
  body: Record<string, unknown>,
  query = "",
): Promise<[string, RequestInit]> {
  const text = JSON.stringify(body);
  const bytes = new TextEncoder().encode(text);
  const authorization = await buildWeb3SignedHeader({
    wallet: owner,
    aud: SERVER_ORIGIN,
    method: "POST",
    uri: "/ask",
    body: bytes,
  });
  return [
    `/ask${query}`,
    { method: "POST", headers: { authorization }, body: text },
  ];
}

async function ownerAuth(method: "GET" | "POST", uri: string) {
  return buildWeb3SignedHeader({
    wallet: owner,
    aud: SERVER_ORIGIN,
    method,
    uri,
  });
}

/* ------------------------------------------------------------------ *
 * Auth — the same gate /v1/grants uses
 * ------------------------------------------------------------------ */

describe("owner auth", () => {
  it("refuses a request with no credential", async () => {
    const { app } = await createApp();
    const res = await app.request("/scopes");
    expect(res.status).toBe(401);
  });

  it("refuses a bad signature", async () => {
    const { app } = await createApp();
    const header = await ownerAuth("GET", "/scopes");
    // Corrupt the signature while leaving the envelope well-formed.
    const tampered = header.slice(0, -8) + "deadbeef";
    const res = await app.request("/scopes", {
      headers: { authorization: tampered },
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(res.status).not.toBe(200);
  });

  it("refuses a valid signature from someone who is not the owner", async () => {
    const { app } = await createApp();
    const header = await buildWeb3SignedHeader({
      wallet: stranger,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/scopes",
    });
    const res = await app.request("/scopes", {
      headers: { authorization: header },
    });
    // The same 401 NOT_OWNER `/v1/grants` gives — this route inherits the
    // shared auth port's contract rather than defining its own.
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe("NOT_OWNER");
  });

  it("gates POST /ask behind the same check", async () => {
    const { app } = await createApp({
      inferenceProvider: createFakeInferenceProvider(),
    });
    const res = await app.request("/ask", {
      method: "POST",
      body: JSON.stringify({ question: "anything?" }),
    });
    expect(res.status).toBe(401);
  });

  it("admits the owner", async () => {
    const { app } = await createApp();
    const res = await app.request("/scopes", {
      headers: { authorization: await ownerAuth("GET", "/scopes") },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { scopes: { scope: string }[] };
    expect(body.scopes.map((s) => s.scope)).toEqual(["a.b"]);
  });
});

/* ------------------------------------------------------------------ *
 * Request validation
 * ------------------------------------------------------------------ */

describe("POST /ask validation", () => {
  it("answers 503 when no inference provider is configured", async () => {
    const { app } = await createApp();
    const res = await app.request(
      ...(await askRequest({ question: "anything?" }, "")),
    );
    expect(res.status).toBe(503);
  });

  it("rejects an empty question", async () => {
    const { app } = await createApp({
      inferenceProvider: createFakeInferenceProvider(),
    });
    const res = await app.request(
      ...(await askRequest({ question: "   " }, "")),
    );
    expect(res.status).toBe(400);
  });
});

/* ------------------------------------------------------------------ *
 * Metering: one access-log row per scope touched
 * ------------------------------------------------------------------ */

describe("access logging", () => {
  it("writes one row per scope the question touched", async () => {
    const storage = await seedStorage({
      "a.b": [{ x: 1 }],
      "c.d": [{ x: 2 }],
      "e.f": [{ x: 3 }],
    });
    const { app, accessLog } = await createApp({
      storage,
      inferenceProvider: sweepingProvider(["a.b", "c.d", "e.f"]),
    });

    const res = await app.request(
      ...(await askRequest(
        { question: "how many records in total?" },
        "?stream=false",
      )),
    );
    expect(res.status).toBe(200);

    // Phase 8: "settle and log per scope touched." Three scopes swept is
    // three rows, not one row for the question.
    expect(accessLog.rows).toHaveLength(3);
    expect(accessLog.rows.map((r) => r.scope).sort()).toEqual([
      "a.b",
      "c.d",
      "e.f",
    ]);
    // The identical pair GET /v1/data/:scope writes for an owner read —
    // owner reads are logged but never charged.
    expect(accessLog.rows.every((r) => r.grantId === "owner")).toBe(true);
    expect(accessLog.rows.every((r) => r.builder === owner.address)).toBe(true);
    expect(accessLog.rows.every((r) => r.action === "read")).toBe(true);
    // Fresh log ids, so N rows are N rows and not one row written N times.
    expect(new Set(accessLog.rows.map((r) => r.logId)).size).toBe(3);
  });

  it("does not log a scope it could not read", async () => {
    const storage = await seedStorage({ "a.b": [{ x: 1 }] });
    const broken = {
      ...storage,
      readEnvelope: async () => {
        throw new Error("decrypt failed");
      },
    };
    const { app, accessLog } = await createApp({
      storage: broken as never,
      inferenceProvider: createFakeInferenceProvider(),
    });
    const res = await app.request(
      ...(await askRequest({ question: "anything?" }, "?stream=false")),
    );
    expect(res.status).toBe(200);
    // The row is written after the bytes are in hand, so an unreadable scope
    // never appears in the log as though it had been served.
    expect(accessLog.rows).toHaveLength(0);
    const answer = (await res.json()) as {
      coverage: { complete: boolean; scopesSkipped: { scope: string }[] };
    };
    expect(answer.coverage.complete).toBe(false);
    expect(answer.coverage.scopesSkipped.map((s) => s.scope)).toEqual(["a.b"]);
  });
});

/* ------------------------------------------------------------------ *
 * The grant: narrow, never widen
 * ------------------------------------------------------------------ */

describe("the grant", () => {
  it("honours a narrowing body and never reads outside it", async () => {
    const storage = await seedStorage({
      "a.b": [{ x: 1 }],
      "c.d": [{ x: 2 }],
    });
    const { app, accessLog } = await createApp({
      storage,
      inferenceProvider: sweepingProvider(["a.b"]),
    });

    const res = await app.request(
      ...(await askRequest(
        { question: "how many?", scopes: ["a.b"] },
        "?stream=false",
      )),
    );
    const answer = (await res.json()) as {
      coverage: { scopesScanned: string[] };
    };
    // `c.d` is granted but was not asked for: never read, never logged.
    expect(accessLog.rows.map((r) => r.scope)).toEqual(["a.b"]);
    expect(answer.coverage.scopesScanned).toEqual(["a.b"]);
  });

  it("refuses to widen to a scope the owner does not hold", async () => {
    const storage = await seedStorage({ "a.b": [{ x: 1 }] });
    const { app, accessLog } = await createApp({
      storage,
      inferenceProvider: sweepingProvider(["a.b"]),
    });

    const res = await app.request(
      ...(await askRequest(
        {
          question: "how many?",
          scopes: ["a.b", "someone.elses"],
        },
        "?stream=false",
      )),
    );
    const answer = (await res.json()) as {
      coverage: { complete: boolean; scopesSkipped: { scope: string }[] };
    };
    expect(accessLog.rows.map((r) => r.scope)).toEqual(["a.b"]);
    // The refusal is a coverage fact, not a silent drop: the answer covers
    // less than was asked and says so.
    expect(answer.coverage.scopesSkipped).toContainEqual({
      scope: "someone.elses",
      reason: "not in the caller's granted scopes",
    });
    expect(answer.coverage.complete).toBe(false);
  });
});

/* ------------------------------------------------------------------ *
 * Coverage over envelope-shaped real data
 * ------------------------------------------------------------------ */

describe("coverage", () => {
  it("counts the records inside a real envelope, not the envelope", async () => {
    const storage = await seedStorage({
      "a.b": [{ x: 1 }, { x: 2 }, { x: 3 }],
      "c.d": [{ x: 4 }, { x: 5 }],
    });
    const { app } = await createApp({
      storage,
      inferenceProvider: sweepingProvider(["a.b", "c.d"]),
    });
    const res = await app.request(
      ...(await askRequest({ question: "how many records?" }, "?stream=false")),
    );
    const answer = (await res.json()) as {
      coverage: { recordsScanned: number; scopesScanned: string[] };
    };
    // Handed the envelope un-unwrapped, every one of these would read 1.
    expect(answer.coverage.recordsScanned).toBe(5);
    expect(answer.coverage.scopesScanned.sort()).toEqual(["a.b", "c.d"]);
  });
});

/* ------------------------------------------------------------------ *
 * Streaming
 * ------------------------------------------------------------------ */

describe("SSE", () => {
  it("emits the turns as they happen, ending with the answer", async () => {
    const storage = await seedStorage({ "a.b": [{ x: 1 }] });
    const { app } = await createApp({
      storage,
      inferenceProvider: sweepingProvider(["a.b"]),
    });

    const res = await app.request(
      ...(await askRequest({ question: "how many?" }, "")),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    const text = await res.text();
    const events = [...text.matchAll(/^event: (\w+)$/gm)].map((m) => m[1]);
    expect(events[0]).toBe("start");
    expect(events).toContain("turn");
    // The script is announced before it runs, so one the sandbox kills is
    // still on screen.
    expect(events.indexOf("script")).toBeLessThan(events.indexOf("run"));
    expect(events.at(-1)).toBe("answer");

    // The final frame carries a real QueryAnswer with honest coverage.
    const lastData = [...text.matchAll(/^data: (.*)$/gm)].at(-1)?.[1] ?? "{}";
    const answer = JSON.parse(lastData) as {
      coverage: { recordsScanned: number };
    };
    expect(answer.coverage.recordsScanned).toBe(1);
  });

  it("reports a provider failure as an SSE error, not a dead stream", async () => {
    const storage = await seedStorage({ "a.b": [{ x: 1 }] });
    const { app } = await createApp({
      storage,
      inferenceProvider: {
        defaultModel: "fake",
        chat: vi.fn().mockRejectedValue(new Error("relay is down")),
      },
    });
    const res = await app.request(
      ...(await askRequest({ question: "how many?" }, "")),
    );
    const text = await res.text();
    expect(text).toContain("event: error");
    expect(text).toContain("relay is down");
  });
});

/* ------------------------------------------------------------------ *
 * Concurrency (plan §3 risk 4)
 * ------------------------------------------------------------------ */

describe("concurrency", () => {
  it("refuses a question past the ceiling with 503 QUERY_BUSY", async () => {
    const gate = createQueryConcurrency(1);
    const storage = await seedStorage({ "a.b": [{ x: 1 }] });
    const { app } = await createApp({
      storage,
      concurrency: gate,
      inferenceProvider: sweepingProvider(["a.b"]),
    });

    // Occupy the only slot, as an in-flight question would.
    gate.acquire();

    const res = await app.request(
      ...(await askRequest({ question: "how many?" }, "?stream=false")),
    );
    // 503 with a JSON body beats a 200 whose first SSE frame is an error.
    expect(res.status).toBe(503);
    expect(JSON.stringify(await res.json())).toContain("QUERY_BUSY");
  });

  it("reports the ceiling on GET /scopes", async () => {
    const { app } = await createApp({
      concurrency: createQueryConcurrency(3),
    });
    const res = await app.request("/scopes", {
      headers: { authorization: await ownerAuth("GET", "/scopes") },
    });
    expect((await res.json()).maxConcurrentQueries).toBe(3);
  });
});
