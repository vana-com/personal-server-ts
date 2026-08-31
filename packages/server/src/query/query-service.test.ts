/**
 * The query layer's entrypoint contract (implementation plan phase 8 §3).
 *
 * These are the acceptance criteria, not incidental coverage:
 *
 * - `readPaths` is EXACTLY the grant (risk 1). Asserted against the spec the
 *   OS layer is actually handed, and against a real sandboxed script that
 *   tries to reach past it.
 * - Coverage stays honest (risk 3 / §19.16). A scope the request could not
 *   read must always show up in `scopesSkipped`.
 * - A source with no T2 profile is flagged reduced-confidence (risk 3).
 * - Concurrency is bounded (risk 4).
 * - Envelope-shaped real data yields real record counts, not `1`.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createFakeInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import type {
  Sandbox,
  SandboxSpec,
} from "@opendatalabs/personal-server-ts-core/query";

import {
  DEFAULT_MAX_CONCURRENT_QUERIES,
  QueryBusyError,
  applyGrantCoverage,
  createQueryConcurrency,
  materializeGrant,
  resolveGrant,
  resolveMaxConcurrent,
  runQuery,
  unwrapEnvelopeData,
  type QueryScopeReader,
} from "./query-service.js";

const scratchDirs: string[] = [];
function scratch(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratchDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (scratchDirs.length > 0) {
    const dir = scratchDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------------ *
 * resolveGrant — narrow, never widen
 * ------------------------------------------------------------------ */

describe("resolveGrant", () => {
  it("defaults to the caller's whole grant", () => {
    expect(resolveGrant(["a.b", "c.d"])).toEqual({
      scopes: ["a.b", "c.d"],
      rejected: [],
    });
  });

  it("honours a narrowing request", () => {
    expect(resolveGrant(["a.b", "c.d", "e.f"], ["c.d"])).toEqual({
      scopes: ["c.d"],
      rejected: [],
    });
  });

  it("refuses to widen, and reports what it refused", () => {
    const result = resolveGrant(["a.b"], ["a.b", "secret.scope"]);
    expect(result.scopes).toEqual(["a.b"]);
    // Silently dropping it would hide that the answer covers less than was
    // asked; it has to reach coverage instead.
    expect(result.rejected).toEqual(["secret.scope"]);
  });

  it("treats an empty narrowing list as narrowing to nothing", () => {
    expect(resolveGrant(["a.b"], []).scopes).toEqual([]);
  });

  it("de-duplicates a repeated request", () => {
    expect(resolveGrant(["a.b"], ["a.b", "a.b"]).scopes).toEqual(["a.b"]);
  });
});

/* ------------------------------------------------------------------ *
 * unwrapEnvelopeData — the real-data record count
 * ------------------------------------------------------------------ */

describe("unwrapEnvelopeData", () => {
  it("counts the records of a real DataFileEnvelope, not the envelope", () => {
    const envelope = {
      version: 3,
      scope: "oura.sleep",
      collectedAt: "2026-08-01T00:00:00Z",
      data: { items: [{ day: 1 }, { day: 2 }, { day: 3 }] },
    };
    const out = unwrapEnvelopeData(envelope);
    // The bug this exists to prevent: an un-unwrapped envelope is ONE record
    // and every coverage figure reads 1.
    expect(out.items).toHaveLength(3);
    expect(out.key).toBe("data.items");
  });

  it("unwraps an envelope whose data is already the record array", () => {
    const out = unwrapEnvelopeData({
      version: 1,
      scope: "x.y",
      collectedAt: "2026-01-01T00:00:00Z",
      data: [{ a: 1 }, { a: 2 }],
    });
    expect(out.items).toHaveLength(2);
    expect(out.key).toBe("data");
  });

  it("passes a bare array through — the eval corpus shape", () => {
    const out = unwrapEnvelopeData([{ a: 1 }]);
    expect(out).toEqual({ items: [{ a: 1 }], key: null });
  });

  it("takes the lone array-valued key without a note", () => {
    const out = unwrapEnvelopeData({ sessions: [1, 2], meta: "x" });
    expect(out.key).toBe("sessions");
    expect(out.note).toBeUndefined();
  });

  it("reports which key it took when several are plausible", () => {
    const out = unwrapEnvelopeData({ items: [1, 2], extras: [3] });
    expect(out.key).toBe("items");
    // Reported, never silent: a wrong guess moves every denominator.
    expect(out.note).toContain("items");
    expect(out.note).toContain("extras");
  });

  it("treats an object with no array as one record, and says so", () => {
    const out = unwrapEnvelopeData({ profile: { name: "x" } });
    expect(out.items).toHaveLength(1);
    expect(out.note).toContain("single record");
  });
});

/* ------------------------------------------------------------------ *
 * applyGrantCoverage — it can only ADD a limit, never remove one
 * ------------------------------------------------------------------ */

describe("applyGrantCoverage", () => {
  const swept = {
    scopesScanned: ["a.b"],
    recordsScanned: 10,
    scopesSkipped: [],
  };

  it("is a no-op when every granted scope was reached", () => {
    expect(applyGrantCoverage(swept, [])).toBe(swept);
  });

  it("records a granted scope the request could not reach as skipped", () => {
    const out = applyGrantCoverage(swept, [
      { scope: "c.d", reason: "unreadable" },
    ]);
    // §19.16 measured a confident total over a partial corpus at 0 of 35 rows.
    // A route that sweeps two of three scopes and never mentions the third is
    // the worst bug here, so the unreached scope must appear.
    expect(out.scopesSkipped).toEqual([{ scope: "c.d", reason: "unreadable" }]);
  });

  it("never removes a limit already in the coverage it was handed", () => {
    // The one-directionality that used to be expressed as "can never turn
    // `complete` true". It has no way to launder a partial run into a total
    // one: it cannot drop a skipped scope and it cannot touch a counter.
    const bounded = {
      ...swept,
      scopesSkipped: [{ scope: "e.f", reason: "no text layer" }],
      unreadable: 22,
    };
    const out = applyGrantCoverage(bounded, [{ scope: "c.d", reason: "x" }]);
    expect(out.scopesSkipped).toEqual([
      { scope: "e.f", reason: "no text layer" },
      { scope: "c.d", reason: "x" },
    ]);
    expect(out.unreadable).toBe(22);
    expect(out.recordsScanned).toBe(10);
    expect(out.scopesScanned).toEqual(["a.b"]);
  });

  it("does not duplicate a scope the host already skipped", () => {
    const out = applyGrantCoverage(
      {
        ...swept,
        scopesSkipped: [{ scope: "c.d", reason: "host said so" }],
      },
      [{ scope: "c.d", reason: "route said so" }],
    );
    expect(out.scopesSkipped).toEqual([
      { scope: "c.d", reason: "host said so" },
    ]);
  });
});

/* ------------------------------------------------------------------ *
 * materializeGrant — one metered read per scope touched
 * ------------------------------------------------------------------ */

describe("materializeGrant", () => {
  it("reads each granted scope exactly once — the metering count", async () => {
    const readScope = vi.fn(async (scope: string) => ({
      data: { items: [{ scope }, { scope }] },
    }));
    const reader: QueryScopeReader = {
      grantedScopes: () => ["a.b", "c.d", "e.f"],
      readScope,
    };
    const dir = scratch("ps-mat-");

    const out = await materializeGrant(reader, ["a.b", "c.d", "e.f"], dir);

    // A question that scans three scopes is three scope touches, and the
    // count of reads IS the count of access-log rows and settlements.
    expect(readScope).toHaveBeenCalledTimes(3);
    expect(readScope.mock.calls.map(([s]) => s)).toEqual(["a.b", "c.d", "e.f"]);
    expect(out.scopes.map((s) => s.scope)).toEqual(["a.b", "c.d", "e.f"]);
    expect(out.scopes.every((s) => s.itemCount === 2)).toBe(true);
  });

  it("writes the unwrapped records, so the runner counts records", async () => {
    const dir = scratch("ps-mat-");
    const out = await materializeGrant(
      {
        grantedScopes: () => ["oura.sleep"],
        readScope: async () => ({
          data: {
            version: 1,
            scope: "oura.sleep",
            collectedAt: "2026-01-01T00:00:00Z",
            data: { items: [{ day: 1 }, { day: 2 }] },
          },
        }),
      },
      ["oura.sleep"],
      dir,
    );
    const written = JSON.parse(
      readFileSync(join(dir, "oura.sleep.json"), "utf8"),
    );
    expect(written).toEqual([{ day: 1 }, { day: 2 }]);
    expect(out.scopes[0]?.itemCount).toBe(2);
  });

  it("skips an unreadable scope instead of materializing it", async () => {
    const dir = scratch("ps-mat-");
    const out = await materializeGrant(
      {
        grantedScopes: () => ["a.b", "bad.scope"],
        readScope: async (scope) => {
          if (scope === "bad.scope") throw new Error("no local version");
          return { data: [{ a: 1 }] };
        },
      },
      ["a.b", "bad.scope"],
      dir,
    );
    expect(out.scopes.map((s) => s.scope)).toEqual(["a.b"]);
    expect(out.skipped).toEqual([
      { scope: "bad.scope", reason: "no local version" },
    ]);
  });

  it("refuses a scope id that could escape the scratch root", async () => {
    const dir = scratch("ps-mat-");
    const readScope = vi.fn();
    const out = await materializeGrant(
      { grantedScopes: () => [], readScope },
      ["../../etc/passwd"],
      dir,
    );
    expect(out.scopes).toEqual([]);
    expect(out.skipped[0]?.reason).toBe("unsafe scope id");
    // Rejected before any read: an unsafe id never becomes a readPath.
    expect(readScope).not.toHaveBeenCalled();
  });
});

/* ------------------------------------------------------------------ *
 * Concurrency (plan §3 risk 4)
 * ------------------------------------------------------------------ */

describe("query concurrency", () => {
  it("admits up to the limit and refuses the next", () => {
    const gate = createQueryConcurrency(2);
    const a = gate.acquire();
    gate.acquire();
    expect(gate.inFlight).toBe(2);
    expect(() => gate.acquire()).toThrow(QueryBusyError);
    a();
    expect(gate.inFlight).toBe(1);
    expect(() => gate.acquire()).not.toThrow();
  });

  it("ignores a double release, so one caller cannot free another's slot", () => {
    const gate = createQueryConcurrency(1);
    const release = gate.acquire();
    release();
    release();
    expect(gate.inFlight).toBe(0);
  });

  it("never admits fewer than one", () => {
    expect(createQueryConcurrency(0).limit).toBe(1);
  });

  it("resolves the limit from option, then env, then default", () => {
    expect(resolveMaxConcurrent(7, {})).toBe(7);
    expect(
      resolveMaxConcurrent(undefined, { PS_QUERY_MAX_CONCURRENT: "3" }),
    ).toBe(3);
    expect(resolveMaxConcurrent(undefined, {})).toBe(
      DEFAULT_MAX_CONCURRENT_QUERIES,
    );
    expect(
      resolveMaxConcurrent(undefined, { PS_QUERY_MAX_CONCURRENT: "nonsense" }),
    ).toBe(DEFAULT_MAX_CONCURRENT_QUERIES);
  });
});

/* ------------------------------------------------------------------ *
 * runQuery — the assembled path
 * ------------------------------------------------------------------ */

/**
 * A `Sandbox` that records the spec it is handed and never runs anything.
 *
 * Lets the `readPaths`-is-the-grant assertion be exact and offline. The real
 * OS enforcement is covered by `hostile-scripts.test.ts`; what is under test
 * here is the derivation that decides what the OS is told to allow.
 */
const FULL_ENFORCEMENT = {
  filesystemRead: true,
  filesystemWrite: true,
  network: true,
  cpu: true,
  memory: true,
  processCount: true,
  wallClock: true,
  notes: [] as string[],
};

function recordingSandbox(): Sandbox & { specs: SandboxSpec[] } {
  const specs: SandboxSpec[] = [];
  return {
    specs,
    async capabilities() {
      return {
        available: true as const,
        enforcement: FULL_ENFORCEMENT,
      };
    },
    async run(_script: string, spec: SandboxSpec) {
      specs.push(spec);
      return {
        stdout: "",
        stderr: "",
        exitCode: 0,
        timedOut: false,
        truncated: false,
        durationMs: 1,
        termination: "completed" as const,
        enforcement: FULL_ENFORCEMENT,
        violations: [],
      };
    },
  };
}

function envelopeReader(
  scopes: Record<string, unknown[]>,
  onRead?: (scope: string) => void,
): QueryScopeReader {
  return {
    grantedScopes: () => Object.keys(scopes),
    async readScope(scope) {
      onRead?.(scope);
      const items = scopes[scope];
      if (!items) throw new Error("no local version of this scope");
      return {
        data: {
          version: 1,
          scope,
          collectedAt: "2026-01-01T00:00:00Z",
          data: { items },
        },
        collectedAt: "2026-01-01T00:00:00Z",
        version: "1",
      };
    },
  };
}

/** A provider that writes one script, then answers. */
function scriptedProvider(script: string) {
  return createFakeInferenceProvider({
    respond: (_input, n) =>
      n === 0
        ? { content: "```vana:run\n" + script + "\n```" }
        : {
            content:
              "```vana:answer\n" +
              JSON.stringify({ answer: "done", citations: [] }) +
              "\n```",
          },
  });
}

describe("runQuery", () => {
  it("hands the OS layer exactly the granted scopes as readPaths", async () => {
    const sandbox = recordingSandbox();
    await runQuery({
      reader: envelopeReader({ "a.b": [{ x: 1 }], "c.d": [{ x: 2 }] }),
      provider: scriptedProvider('const r = await vana.readAll("a.b");'),
      question: "how many?",
      createSandbox: () => sandbox,
    });

    expect(sandbox.specs).toHaveLength(1);
    const spec = sandbox.specs[0]!;
    // Exactly the grant: two granted scopes, two readable files, nothing else.
    expect(spec.readPaths).toHaveLength(2);
    expect(spec.readPaths.map((p) => p.split("/").pop()).sort()).toEqual([
      "a.b.json",
      "c.d.json",
    ]);
    // Zero egress is the containment for prompt injection, and it is typed
    // `true` so it cannot be switched off in a call.
    expect(spec.denyNetwork).toBe(true);
  });

  it("narrows readPaths to a narrowed grant, and never widens it", async () => {
    const reads: string[] = [];
    const sandbox = recordingSandbox();
    const answer = await runQuery({
      reader: envelopeReader({ "a.b": [{ x: 1 }], "c.d": [{ x: 2 }] }, (s) =>
        reads.push(s),
      ),
      provider: scriptedProvider('const r = await vana.readAll("a.b");'),
      question: "how many?",
      scopes: ["a.b", "not.granted"],
      createSandbox: () => sandbox,
    });

    // `c.d` was granted but not asked for: never read, never readable.
    // `not.granted` was asked for but not granted: never read either.
    expect(reads).toEqual(["a.b"]);
    expect(sandbox.specs[0]!.readPaths).toHaveLength(1);
    expect(sandbox.specs[0]!.readPaths[0]).toContain("a.b.json");
    // The scope the caller named but does not hold is a coverage fact.
    expect(answer.coverage.scopesSkipped).toContainEqual({
      scope: "not.granted",
      reason: "not in the caller's granted scopes",
    });
  });

  it("answers honestly rather than throwing when nothing is readable", async () => {
    const provider = createFakeInferenceProvider();
    const answer = await runQuery({
      reader: {
        grantedScopes: () => [],
        readScope: async () => ({ data: [] }),
      },
      provider,
      question: "anything?",
      createSandbox: () => recordingSandbox(),
    });
    expect(answer.coverage.recordsScanned).toBe(0);
    // No model turn was spent on a question with no corpus.
    expect(provider.calls).toHaveLength(0);
  });

  it("folds an unreadable granted scope into coverage as skipped", async () => {
    const sandbox = recordingSandbox();
    const answer = await runQuery({
      reader: {
        grantedScopes: () => ["a.b", "broken.scope"],
        readScope: async (scope) => {
          if (scope === "broken.scope") throw new Error("decrypt failed");
          return { data: [{ x: 1 }] };
        },
      },
      provider: scriptedProvider('const r = await vana.readAll("a.b");'),
      question: "how many?",
      createSandbox: () => sandbox,
    });
    expect(sandbox.specs[0]!.readPaths).toHaveLength(1);
    expect(answer.coverage.scopesSkipped).toContainEqual({
      scope: "broken.scope",
      reason: "decrypt failed",
    });
  });

  it("flags a source with no T2 profile as reduced-confidence", async () => {
    const answer = await runQuery({
      reader: envelopeReader({ "totally.unknown": [{ x: 1 }] }),
      provider: scriptedProvider('const r = await vana.readAll("x");'),
      question: "how many?",
      createSandbox: () => recordingSandbox(),
    });
    // Plan §3 risk 3: a source without a profile is answered as
    // reduced-confidence, never as if it were understood.
    expect(answer.coverage.unprofiledScopes).toContain("totally.unknown");
  });

  it("emits turns, scripts and runs in order, before the answer", async () => {
    const events: string[] = [];
    await runQuery({
      reader: envelopeReader({ "a.b": [{ x: 1 }] }),
      provider: scriptedProvider('const r = await vana.readAll("a.b");'),
      question: "how many?",
      createSandbox: () => recordingSandbox(),
      onEvent: (e) => {
        events.push(e.type);
      },
    });
    expect(events[0]).toBe("start");
    expect(events.at(-1)).toBe("answer");
    // The script is emitted BEFORE it runs, so one the sandbox kills is still
    // on screen.
    expect(events.indexOf("script")).toBeLessThan(events.indexOf("run"));
    expect(events).toContain("turn");
  });

  it("releases its concurrency slot when the run fails", async () => {
    const gate = createQueryConcurrency(1);
    const exploding = {
      defaultModel: "fake",
      async chat(): Promise<never> {
        throw new Error("relay is down");
      },
    };
    await expect(
      runQuery({
        reader: envelopeReader({ "a.b": [{ x: 1 }] }),
        provider: exploding,
        question: "how many?",
        concurrency: gate,
        createSandbox: () => recordingSandbox(),
      }),
    ).rejects.toThrow("relay is down");
    // A leaked slot would take the server to permanently-busy after N errors.
    expect(gate.inFlight).toBe(0);
  });

  it("refuses to start past the concurrency ceiling", async () => {
    const gate = createQueryConcurrency(1);
    gate.acquire();
    await expect(
      runQuery({
        reader: envelopeReader({ "a.b": [{ x: 1 }] }),
        provider: createFakeInferenceProvider(),
        question: "how many?",
        concurrency: gate,
        createSandbox: () => recordingSandbox(),
      }),
    ).rejects.toThrow(QueryBusyError);
  });
});

/* ------------------------------------------------------------------ *
 * The real sandbox: a script cannot reach a scope outside the grant
 * ------------------------------------------------------------------ */

// The OS sandbox is only meaningful where ASRT supports the platform; on an
// unsupported one `run()` refuses with `sandboxUnavailable`, which is itself
// fail-closed and covered in `hostile-scripts.test.ts`.
const osSandboxSupported =
  process.platform === "darwin" || process.platform === "linux";

describe.runIf(osSandboxSupported)("runQuery under the real OS sandbox", () => {
  /** Capture the one `run` event a single-script question produces. */
  async function runOneScript(
    script: string,
    scopes: Record<string, unknown[]>,
  ) {
    let event:
      | Extract<
          Parameters<NonNullable<Parameters<typeof runQuery>[0]["onEvent"]>>[0],
          { type: "run" }
        >
      | undefined;
    const answer = await runQuery({
      reader: envelopeReader(scopes),
      provider: scriptedProvider(script),
      question: "can you read the other scope?",
      onEvent: (e) => {
        if (e.type === "run") event = e;
      },
    });
    return { answer, event };
  }

  it("refuses a script that tries to reach the filesystem at all", async () => {
    // A file outside the grant, standing in for another scope's data. It is
    // not merely absent from the scratch root — it exists, on disk, and the
    // script is handed its exact path.
    const other = scratch("ps-query-secret-");
    const secret = join(other, "not-granted.json");
    writeFileSync(secret, JSON.stringify([{ secret: "TOPSECRET" }]));

    const { answer, event } = await runOneScript(
      `
      const fs = await import("node:fs/promises");
      const stolen = await fs.readFile(${JSON.stringify(secret)}, "utf8");
      vana.result({ answer: "BREACH:" + stolen, citations: [] });
      `,
      { "a.b": [{ x: 1 }, { x: 2 }] },
    );

    // Assert the DENIAL, not merely the absence of the secret: a script that
    // failed for an unrelated reason would otherwise be a false pass.
    expect(event?.error).toMatchObject({ code: "CONFINEMENT_VIOLATION" });
    expect(
      (event?.coverage as { stoppedBecause?: string }).stoppedBecause,
    ).toBe("policyDenied");
    // The bytes never come back, by any route. The capability layer refuses
    // before the OS layer is even asked — the file API does not exist inside
    // the confined interpreter.
    expect(JSON.stringify(answer)).not.toContain("TOPSECRET");
    expect(JSON.stringify(event)).not.toContain("TOPSECRET");
    // (`answer.script` echoes the script text, "BREACH:" literal included, so
    // the meaningful assertion is on the secret's contents, not the marker.)
  }, 90_000);

  it("denies a script the scope its caller did not grant", async () => {
    // Reads the granted scope first, so the denial that follows is provably
    // about the SECOND scope and not about the run having failed to start.
    const { answer, event } = await runOneScript(
      `
      const granted = await vana.readAll("a.b");
      const stolen = await vana.readAll("not.granted");
      vana.result({
        answer: "BREACH:" + granted.length + ":" + stolen.length,
        citations: [],
      });
      `,
      { "a.b": [{ x: 1 }, { x: 2 }] },
    );

    // The API layer refuses a scope outside the grant, by name, fail-closed.
    expect(event?.error).toMatchObject({ code: "SCOPE_NOT_GRANTED" });
    expect(event?.result ?? null).toBeNull();
    // The grant it DOES hold was read, so the denial is targeted rather than
    // the whole run having collapsed before it touched anything.
    expect(answer.coverage.scopesScanned).toEqual(["a.b"]);
    expect(answer.coverage.recordsScanned).toBe(2);
    // The ungranted scope never appears as read.
    expect(answer.coverage.scopesScanned).not.toContain("not.granted");
  }, 90_000);

  it("succeeds on the same shape when the scope IS granted", async () => {
    // The positive control for the test above: identical script, both scopes
    // granted. Without this, a denial assertion could be passing because the
    // script was broken rather than because the grant was enforced.
    const { answer, event } = await runOneScript(
      `
      const granted = await vana.readAll("a.b");
      const other = await vana.readAll("c.d");
      vana.result({
        answer: granted.length + ":" + other.length,
        citations: [],
      });
      `,
      { "a.b": [{ x: 1 }, { x: 2 }], "c.d": [{ y: 1 }] },
    );

    expect(event?.error ?? null).toBeNull();
    expect((event?.result as { answer: string }).answer).toBe("2:1");
    expect(answer.coverage.scopesScanned.sort()).toEqual(["a.b", "c.d"]);
    expect(answer.coverage.recordsScanned).toBe(3);
  }, 90_000);
});
