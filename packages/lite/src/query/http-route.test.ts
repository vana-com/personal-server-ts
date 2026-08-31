/**
 * The PS-Lite query route.
 *
 * Two kinds of test live here, deliberately.
 *
 * Most inject a fake `ask` and assert the HTTP contract — auth, 503 when the
 * layer is off, the grant's direction, the access-log rows, the busy ceiling,
 * SSE framing. Those never load QuickJS.
 *
 * The last suite does the opposite: it wires the REAL `createLiteQueryAsk` and
 * therefore the real QuickJS-WASM engine, and drives a scripted model through
 * the route. That is the only assertion here that proves the route's execution
 * boundary is the VM rather than this process, so it is worth the ~1 s it costs.
 */

import { describe, expect, it } from "vitest";

import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { createFakeInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import type { QueryAnswer } from "@opendatalabs/personal-server-ts-core/query/agent";

import {
  createLiteQueryConcurrency,
  handleLiteQueryRequest,
  type LiteQueryAsk,
  type LiteQueryRouteDeps,
} from "./http-route.js";

const fence = "```";

interface ScopeFixture {
  scope: string;
  records: unknown[];
}

function fixtures(...scopes: ScopeFixture[]) {
  const logged: { scope: string; grantId: string; action: string }[] = [];
  const dataStorage = {
    listScopes: () => ({
      scopes: scopes.map((s) => ({
        scope: s.scope,
        latestCollectedAt: "2026-08-30T00:00:00.000Z",
        versionCount: 1,
        sizeBytes: 10,
        dataStatus: "ready",
      })),
    }),
    findEntry: ({ scope }: { scope: string }) =>
      scopes.some((s) => s.scope === scope)
        ? { collectedAt: "2026-08-30T00:00:00.000Z", version: 1 }
        : undefined,
    readEnvelope: async (scope: string) => {
      const found = scopes.find((s) => s.scope === scope);
      if (!found) throw new Error("unreachable");
      return { version: 1, scope, data: found.records };
    },
  };
  const accessLogWriter = {
    write: async (row: { scope: string; grantId: string; action: string }) => {
      logged.push({
        scope: row.scope,
        grantId: row.grantId,
        action: row.action,
      });
    },
  };
  return { dataStorage, accessLogWriter, logged };
}

const ANSWER: QueryAnswer = {
  answer: "42",
  evidence: "counted",
  coverage: {
    scopesScanned: ["notes.entries"],
    recordsScanned: 3,
    scopesSkipped: [],
    complete: true,
  },
} as unknown as QueryAnswer;

function deps(
  over: Partial<LiteQueryRouteDeps> = {},
  scopes: ScopeFixture[] = [{ scope: "notes.entries", records: [1, 2, 3] }],
) {
  const f = fixtures(...scopes);
  const d: LiteQueryRouteDeps = {
    authorizeOwner: async () => {},
    dataStorage: f.dataStorage as unknown as LiteQueryRouteDeps["dataStorage"],
    accessLogWriter:
      f.accessLogWriter as unknown as LiteQueryRouteDeps["accessLogWriter"],
    serverOwner: "0xowner",
    query: { ask: async () => ANSWER },
    ...over,
  };
  return { deps: d, logged: f.logged };
}

const ask = (url: string, init?: RequestInit) =>
  new Request(`https://ps-lite.local${url}`, init);

const post = (url: string, body: unknown) =>
  ask(url, { method: "POST", body: JSON.stringify(body) });

describe("handleLiteQueryRequest — routing", () => {
  it("returns undefined for a path it does not own, so the caller keeps matching", async () => {
    const { deps: d } = deps();
    expect(
      await handleLiteQueryRequest(ask("/v1/data/notes.entries"), d),
    ).toBeUndefined();
    expect(await handleLiteQueryRequest(ask("/health"), d)).toBeUndefined();
  });

  it("owns /scopes and /ask under the configured base path", async () => {
    const { deps: d } = deps();
    expect(
      await handleLiteQueryRequest(ask("/custom/scopes"), d, {
        basePath: "/custom",
      }),
    ).toBeDefined();
    // ...and no longer owns the default one.
    expect(
      await handleLiteQueryRequest(ask("/v1/query/scopes"), d, {
        basePath: "/custom",
      }),
    ).toBeUndefined();
  });
});

describe("handleLiteQueryRequest — auth", () => {
  it("authorizes the owner before doing anything else", async () => {
    const order: string[] = [];
    const { deps: d } = deps({
      authorizeOwner: async () => {
        order.push("auth");
        throw new ProtocolError(403, "FORBIDDEN", "not the owner");
      },
      query: {
        ask: async () => {
          order.push("ask");
          return ANSWER;
        },
      },
    });
    await expect(
      handleLiteQueryRequest(post("/v1/query/ask", { question: "hi" }), d),
    ).rejects.toThrow(/not the owner/);
    expect(order).toEqual(["auth"]);
  });

  it("refuses a non-owner on /scopes too", async () => {
    const { deps: d } = deps({
      authorizeOwner: async () => {
        throw new ProtocolError(401, "UNAUTHORIZED", "no token");
      },
    });
    await expect(
      handleLiteQueryRequest(ask("/v1/query/scopes"), d),
    ).rejects.toThrow(/no token/);
  });
});

describe("handleLiteQueryRequest — the layer being off", () => {
  it("raises INFERENCE_UNAVAILABLE rather than pretending to answer", async () => {
    const { deps: d } = deps({ query: null });
    await expect(
      handleLiteQueryRequest(post("/v1/query/ask", { question: "hi" }), d),
    ).rejects.toMatchObject({ code: 503, errorCode: "INFERENCE_UNAVAILABLE" });
  });

  it("still serves /scopes with the layer off, so a UI can render the picker", async () => {
    const { deps: d } = deps({ query: null });
    const res = await handleLiteQueryRequest(ask("/v1/query/scopes"), d);
    expect(res?.status).toBe(200);
    const body = (await res!.json()) as { scopes: { scope: string }[] };
    expect(body.scopes.map((s) => s.scope)).toEqual(["notes.entries"]);
  });
});

describe("handleLiteQueryRequest — /scopes", () => {
  it("reports the owner's scopes and the concurrency ceiling", async () => {
    const { deps: d } = deps({}, [
      { scope: "notes.entries", records: [] },
      { scope: "oura.sleep", records: [] },
    ]);
    const res = await handleLiteQueryRequest(ask("/v1/query/scopes"), d, {
      concurrency: createLiteQueryConcurrency(3),
    });
    const body = (await res!.json()) as {
      scopes: unknown[];
      maxConcurrentQueries: number;
    };
    expect(body.scopes).toHaveLength(2);
    expect(body.maxConcurrentQueries).toBe(3);
  });

  it("rejects a non-GET", async () => {
    const { deps: d } = deps();
    await expect(
      handleLiteQueryRequest(ask("/v1/query/scopes", { method: "POST" }), d),
    ).rejects.toMatchObject({ code: 405 });
  });

  it("reading the scope list writes no access-log row", async () => {
    const { deps: d, logged } = deps();
    await handleLiteQueryRequest(ask("/v1/query/scopes"), d);
    expect(logged).toEqual([]);
  });
});

describe("handleLiteQueryRequest — /ask body", () => {
  it("requires a non-empty question", async () => {
    const { deps: d } = deps();
    for (const body of [
      {},
      { question: "" },
      { question: "   " },
      { question: 7 },
    ]) {
      await expect(
        handleLiteQueryRequest(post("/v1/query/ask", body), d),
      ).rejects.toMatchObject({ code: 400, errorCode: "INVALID_REQUEST" });
    }
  });

  it("rejects a non-POST", async () => {
    const { deps: d } = deps();
    await expect(
      handleLiteQueryRequest(ask("/v1/query/ask"), d),
    ).rejects.toMatchObject({ code: 405 });
  });

  it("passes question, scopes, model and budget through to the runner", async () => {
    let seen: Parameters<LiteQueryAsk>[0] | undefined;
    const { deps: d } = deps({
      query: {
        ask: async (input) => {
          seen = input;
          return ANSWER;
        },
      },
    });
    await handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", {
        question: "  how many?  ",
        scopes: ["notes.entries", 7, "oura.sleep"],
        model: "m-1",
        budget: { toolCalls: 5, outputBytes: 100 },
      }),
      d,
    );
    expect(seen?.question).toBe("how many?");
    // Non-strings are dropped rather than coerced.
    expect(seen?.scopes).toEqual(["notes.entries", "oura.sleep"]);
    expect(seen?.model).toBe("m-1");
    expect(seen?.budget).toEqual({ toolCalls: 5, outputBytes: 100 });
  });

  it("ignores a malformed body rather than throwing a parse error", async () => {
    const { deps: d } = deps();
    await expect(
      handleLiteQueryRequest(
        ask("/v1/query/ask", { method: "POST", body: "not json" }),
        d,
      ),
    ).rejects.toMatchObject({ code: 400, errorCode: "INVALID_REQUEST" });
  });
});

describe("handleLiteQueryRequest — the grant's direction", () => {
  /**
   * The route never widens. It hands the runner a reader whose
   * `grantedScopes` is exactly what `listScopes` reports; a body's `scopes`
   * travel as a REQUEST, and `resolveGrant` inside the service is what
   * narrows. So a scope the owner does not hold cannot become readable by
   * naming it.
   */
  it("a reader only ever exposes the owner's own scopes", async () => {
    let granted: readonly string[] = [];
    const { deps: d } = deps(
      {
        query: {
          ask: async (input) => {
            granted = await input.reader.grantedScopes();
            return ANSWER;
          },
        },
      },
      [{ scope: "notes.entries", records: [1] }],
    );
    await handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", {
        question: "q",
        scopes: ["secrets.everything"],
      }),
      d,
    );
    expect(granted).toEqual(["notes.entries"]);
  });

  it("reading a scope the owner does not hold throws rather than returning data", async () => {
    let err: unknown;
    const { deps: d } = deps({
      query: {
        ask: async (input) => {
          err = await input.reader
            .readScope("secrets.everything")
            .catch((e: unknown) => e);
          return ANSWER;
        },
      },
    });
    await handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", { question: "q" }),
      d,
    );
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/no local version/);
  });
});

describe("handleLiteQueryRequest — metering", () => {
  it("writes one owner access-log row per scope actually read", async () => {
    const { deps: d, logged } = deps(
      {
        query: {
          ask: async (input) => {
            await input.reader.readScope("notes.entries");
            await input.reader.readScope("oura.sleep");
            return ANSWER;
          },
        },
      },
      [
        { scope: "notes.entries", records: [1] },
        { scope: "oura.sleep", records: [2] },
      ],
    );
    await handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", { question: "q" }),
      d,
    );
    expect(logged).toEqual([
      { scope: "notes.entries", grantId: "owner", action: "read" },
      { scope: "oura.sleep", grantId: "owner", action: "read" },
    ]);
  });

  it("a scope that could not be read is not logged as read", async () => {
    const { deps: d, logged } = deps({
      query: {
        ask: async (input) => {
          await input.reader.readScope("missing.scope").catch(() => {});
          return ANSWER;
        },
      },
    });
    await handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", { question: "q" }),
      d,
    );
    expect(logged).toEqual([]);
  });
});

describe("handleLiteQueryRequest — the busy ceiling", () => {
  it("refuses a second question past the ceiling, with a JSON 503", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const { deps: d } = deps({
      query: {
        ask: async () => {
          await gate;
          return ANSWER;
        },
      },
    });
    const concurrency = createLiteQueryConcurrency(1);
    const first = handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", { question: "q1" }),
      d,
      { concurrency },
    );
    // The first is in flight; the second must not open a stream.
    await expect(
      handleLiteQueryRequest(
        post("/v1/query/ask?stream=false", { question: "q2" }),
        d,
        { concurrency },
      ),
    ).rejects.toMatchObject({ code: 503, errorCode: "QUERY_BUSY" });
    release!();
    expect((await first)!.status).toBe(200);
    // And the slot is released, so a later question is served.
    expect(
      (await handleLiteQueryRequest(
        post("/v1/query/ask?stream=false", { question: "q3" }),
        d,
        { concurrency },
      ))!.status,
    ).toBe(200);
  });

  it("releases the slot even when the runner throws", async () => {
    const { deps: d } = deps({
      query: {
        ask: async () => {
          throw new Error("engine exploded");
        },
      },
    });
    const concurrency = createLiteQueryConcurrency(1);
    await expect(
      handleLiteQueryRequest(
        post("/v1/query/ask?stream=false", { question: "q" }),
        d,
        { concurrency },
      ),
    ).rejects.toThrow(/engine exploded/);
    expect(concurrency.inFlight).toBe(0);
  });
});

async function readSse(
  res: Response,
): Promise<{ event: string; data: unknown }[]> {
  const text = await res.text();
  return text
    .split("\n\n")
    .filter((b) => b.trim() !== "")
    .map((block) => {
      const event = /^event: (.+)$/m.exec(block)?.[1] ?? "";
      const data = /^data: (.+)$/m.exec(block)?.[1] ?? "null";
      return { event, data: JSON.parse(data) as unknown };
    });
}

describe("handleLiteQueryRequest — streaming", () => {
  it("streams SSE by default, matching the Node route's contract", async () => {
    const { deps: d } = deps({
      query: {
        ask: async (input) => {
          await input.onEvent?.({
            type: "start",
            question: "q",
            model: "m",
            grantedScopes: ["notes.entries"],
            scopes: [],
            skipped: [],
          } as never);
          await input.onEvent?.({ type: "answer", answer: ANSWER } as never);
          return ANSWER;
        },
      },
    });
    const res = await handleLiteQueryRequest(
      post("/v1/query/ask", { question: "q" }),
      d,
    );
    expect(res!.headers.get("content-type")).toBe("text/event-stream");
    const frames = await readSse(res!);
    expect(frames.map((f) => f.event)).toEqual(["start", "answer"]);
    // The `answer` frame carries the QueryAnswer itself, not a wrapper.
    expect((frames[1]!.data as QueryAnswer).answer).toBe("42");
  });

  it("returns a single JSON QueryAnswer for ?stream=false", async () => {
    const { deps: d } = deps();
    const res = await handleLiteQueryRequest(
      post("/v1/query/ask?stream=false", { question: "q" }),
      d,
    );
    expect(res!.headers.get("content-type")).toBe("application/json");
    expect(((await res!.json()) as QueryAnswer).answer).toBe("42");
  });

  it("a runner failure becomes an SSE error frame, not a broken stream", async () => {
    const { deps: d } = deps({
      query: {
        ask: async () => {
          throw new Error("engine exploded");
        },
      },
    });
    const res = await handleLiteQueryRequest(
      post("/v1/query/ask", { question: "q" }),
      d,
    );
    const frames = await readSse(res!);
    expect(frames).toEqual([
      {
        event: "error",
        data: { code: "QUERY_FAILED", message: "engine exploded" },
      },
    ]);
  });
});

/* ------------------------------------------------------------------ *
 * The real engine, through the real route.
 * ------------------------------------------------------------------ */

describe("handleLiteQueryRequest — end to end on real QuickJS", () => {
  /**
   * A scripted model: turn 1 writes a script, turn 2 answers. The script runs
   * inside the QuickJS VM, so what it can reach IS the containment claim.
   */
  function scriptedModel(script: string) {
    return createFakeInferenceProvider({
      respond: (_input, i) =>
        i === 0
          ? { content: `${fence}vana:run\n${script}\n${fence}` }
          : {
              content: `${fence}vana:answer\n${JSON.stringify({
                answer: "done",
                evidence: "counted every record in notes.entries",
                methodology: "read the scope and counted",
              })}\n${fence}`,
            },
    });
  }

  /** Drive the SSE path so the `run` frame — the host's own ledger — is visible. */
  async function askThroughRoute(script: string) {
    // Imported HERE, not at the top of the file: this is the import that pulls
    // the QuickJS engine in, and the other suites must not pay for it.
    const { createLiteQueryAsk } = await import("./wire.js");
    const { deps: d } = deps(
      {
        query: {
          ask: createLiteQueryAsk({ provider: scriptedModel(script) }),
        },
      },
      [{ scope: "notes.entries", records: [{ a: 1 }, { a: 2 }, { a: 3 }] }],
    );
    const res = await handleLiteQueryRequest(
      post("/v1/query/ask", { question: "how many notes?" }),
      d,
    );
    const frames = await readSse(res!);
    const run = frames.find((f) => f.event === "run")?.data as
      | {
          termination: string;
          coverage: { recordsScanned: number; scopesScanned: string[] };
          result: Record<string, unknown> | null;
          error: unknown;
        }
      | undefined;
    const answer = frames.find((f) => f.event === "answer")?.data as
      (QueryAnswer & { value?: unknown }) | undefined;
    return { frames, run, answer };
  }

  it("answers through the route, with coverage the host counted", async () => {
    const { frames, run, answer } = await askThroughRoute(
      `const rows = await vana.readAll("notes.entries");
       vana.result({ value: rows.length, unit: "records" });`,
    );
    expect(frames.map((f) => f.event)).toEqual([
      "start",
      "turn",
      "script",
      "run",
      "turn",
      "answer",
    ]);
    expect(run?.termination).toBe("completed");
    expect(run?.coverage.scopesScanned).toEqual(["notes.entries"]);
    expect(run?.coverage.recordsScanned).toBe(3);
    // The script's own result frame — proof the code really ran in the VM.
    expect(run?.result).toMatchObject({ value: 3, unit: "records" });
    expect(answer?.value).toBe(3);
  }, 30_000);

  it("the model's code runs with NO egress global: the VM has none to deny", async () => {
    /*
     * The containment assertion that matters for the web path. The unity web PS
     * boots Lite in the page's MAIN JS context, so if model-authored code ran
     * in that realm every name below would exist and the owner's bearer token
     * and IndexedDB keys would be reachable from it. It runs in QuickJS
     * instead, so they are absent — not denied by an enumeration, simply never
     * created.
     *
     * This asserts the SCRIPT's own observation, and `rows` in the same frame
     * proves the script executed rather than silently failing (which would make
     * an empty `present` vacuous).
     */
    const names = [
      "fetch",
      "XMLHttpRequest",
      "WebSocket",
      "importScripts",
      "indexedDB",
      "localStorage",
      "sessionStorage",
      "caches",
      "document",
      "window",
      "process",
      "require",
      "WebAssembly",
      "Worker",
      "navigator",
      "crypto",
    ];
    const { run } = await askThroughRoute(
      `const names = ${JSON.stringify(names)};
       const present = names.filter(function (n) {
         return typeof globalThis[n] !== "undefined";
       });
       const rows = await vana.readAll("notes.entries");
       vana.result({ value: present.length, unit: "egress globals",
                     present: present, rows: rows.length });`,
    );
    expect(run?.termination).toBe("completed");
    // The script ran and really read the grant...
    expect(run?.result).toMatchObject({ rows: 3 });
    // ...and from inside the VM, not one of these names exists.
    expect(run?.result?.present).toEqual([]);
    expect(run?.result?.value).toBe(0);
  }, 30_000);

  it("a script that throws is reported, not swallowed, and does not take the route down", async () => {
    const { run, answer } = await askThroughRoute(`throw new Error("boom");`);
    expect(run?.coverage.recordsScanned).toBe(0);
    expect(run?.error).toMatchObject({
      message: expect.stringMatching(/boom/),
    });
    // An ordinary bad outcome is still an answer with honest coverage.
    expect(answer?.coverage).toBeDefined();
  }, 30_000);
});
