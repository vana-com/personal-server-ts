import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createSandboxToolHost } from "./sandbox-tool-host.js";
import type {
  Sandbox,
  SandboxResult,
} from "@opendatalabs/personal-server-ts-core/query";

/**
 * The double-count fix has to hold at BOTH levels.
 *
 * The single-run ledger stops a script re-reading a scope within one script.
 * This covers the other half: a question takes several turns, and a script
 * that reads `documents.files` in turn 1 and re-reads it in turn 3 covered
 * those records once. Summing bare totals across runs would reintroduce the
 * inflated denominator at the request level, where it is just as untrue.
 */
function frameFor(
  perScope: Record<
    string,
    { records: number; bytes: number; unreadable: number }
  >,
  over: { complete?: boolean; method?: "full" | "prefiltered" } = {},
) {
  const totals = Object.values(perScope).reduce(
    (a, t) => ({
      records: a.records + t.records,
      bytes: a.bytes + t.bytes,
      unreadable: a.unreadable + t.unreadable,
    }),
    { records: 0, bytes: 0, unreadable: 0 },
  );
  const doc = {
    v: 1 as const,
    coverage: {
      scopesScanned: Object.keys(perScope),
      recordsScanned: totals.records,
      bytesScanned: totals.bytes,
      unreadable: totals.unreadable,
      perScope,
      scopesSkipped: [],
      complete: over.complete ?? false,
      method: over.method ?? ("full" as const),
      enforcementNotes: [],
    },
    notes: [],
    toolCalls: 1,
    classifyUsd: 0,
  };
  const b64 = Buffer.from(JSON.stringify(doc), "utf8").toString("base64");
  return `__VANA_RESULT_V1_BEGIN__${b64}__VANA_RESULT_V1_END__`;
}

/** A sandbox that replays a scripted sequence of coverage frames. */
function scriptedSandbox(frames: string[]): Sandbox {
  let i = 0;
  return {
    async run(): Promise<SandboxResult> {
      const stdout = frames[Math.min(i++, frames.length - 1)];
      return {
        stdout,
        stderr: "",
        exitCode: 0,
        timedOut: false,
        truncated: false,
        durationMs: 1,
        termination: "completed",
        enforcement: {
          filesystemRead: true,
          filesystemWrite: true,
          network: true,
          cpu: true,
          memory: true,
          processCount: true,
          wallClock: true,
          notes: [],
        },
        violations: [],
      };
    },
    async capabilities() {
      return {
        available: true,
        enforcement: {
          filesystemRead: true,
          filesystemWrite: true,
          network: true,
          cpu: true,
          memory: true,
          processCount: true,
          wallClock: true,
          notes: [],
        },
      };
    },
  };
}

function hostOver(frames: string[]) {
  const dataRoot = mkdtempSync(join(tmpdir(), "cov-merge-"));
  const file = join(dataRoot, "documents.json");
  writeFileSync(file, "[]", "utf8");
  return createSandboxToolHost({
    sandbox: scriptedSandbox(frames),
    scopes: [{ scope: "documents.files", path: file }],
    dataRoot,
    scratchDir: mkdtempSync(join(tmpdir(), "cov-merge-scratch-")),
    budget: { toolCalls: 50, outputBytes: 1_000_000 },
    limits: {
      cpuMs: 5_000,
      memoryMb: 128,
      wallClockMs: 10_000,
      maxOutputBytes: 100_000,
    },
  });
}

const docs = (records: number, unreadable: number) => ({
  "documents.files": { records, bytes: 677_698, unreadable },
});

describe("coverage merged across runs in one request", () => {
  it("does not double-count a scope re-read in a later turn", async () => {
    const host = hostOver([frameFor(docs(340, 22)), frameFor(docs(340, 22))]);
    await host.execute("first turn");
    await host.execute("third turn, same scope");
    const coverage = host.coverage();
    expect(coverage.recordsScanned, "would be 680 if summed").toBe(340);
    expect(coverage.unreadable, "would be 44 if summed").toBe(22);
  });

  it("still adds scopes that were genuinely new in a later turn", async () => {
    // The merge must stay conservative in the other direction: reporting only
    // the last run's counters would let a two-scope answer claim one scope.
    const host = hostOver([
      frameFor(docs(340, 22)),
      frameFor({
        "email.messages": { records: 900, bytes: 1_000, unreadable: 0 },
      }),
    ]);
    await host.execute("read documents");
    await host.execute("read email");
    const coverage = host.coverage();
    expect(coverage.recordsScanned).toBe(1240);
    expect(coverage.scopesScanned.sort()).toEqual([
      "documents.files",
      "email.messages",
    ]);
  });

  it("takes the larger tally when a later turn read more of one scope", async () => {
    const host = hostOver([
      frameFor(docs(100, 5)), // bounded read
      frameFor(docs(340, 22)), // then a full pass
    ]);
    await host.execute("partial");
    await host.execute("full");
    expect(host.coverage().recordsScanned).toBe(340);
  });
});

/**
 * `complete` accumulates; it does not decay.
 *
 * The merge used to AND each run's flag, which meant the ordinary shape —
 * probe the scope list, then compute — was `complete: false` forever, because
 * the probe turn reads nothing and is honestly incomplete on its own. A later
 * turn cannot un-read what an earlier one read, so the request-level flag is a
 * disjunction over the turns.
 *
 * What keeps that from being a loosening: a single run's `complete` already
 * asserts that EVERY scope in the grant was streamed end to end with nothing
 * skipped, partial or stopped (`core/query/tools/coverage.ts`), and every run
 * in a request is ledgered against the same grant — so one `true` witnesses
 * the whole grant. The prefilter taint is the one conjunct a disjunction would
 * drop, so it is re-applied here against the merged method.
 */
describe("coverage.complete merged across runs in one request", () => {
  it("survives a probe turn that read nothing", async () => {
    const host = hostOver([
      frameFor({}), // `vana.scopes()` and nothing else
      frameFor(docs(340, 22), { complete: true }),
    ]);
    await host.execute("what scopes are there?");
    await host.execute("now read all of it");
    expect(host.coverage().complete).toBe(true);
  });

  it("is not undone by a later bounded read of an already-complete scope", async () => {
    const host = hostOver([
      frameFor(docs(340, 22), { complete: true }),
      frameFor(docs(50, 0)), // re-reads a window it has already covered
    ]);
    await host.execute("stream everything");
    await host.execute("look again at the first fifty");
    const coverage = host.coverage();
    expect(coverage.complete).toBe(true);
    expect(coverage.recordsScanned, "the full pass still subsumes").toBe(340);
  });

  it("stays false when no single turn covered the grant", async () => {
    // Two partial turns do not add up to a complete one: neither run can say
    // the grant was streamed, and the merge must not infer it from the pair.
    const host = hostOver([frameFor(docs(100, 5)), frameFor(docs(120, 3))]);
    await host.execute("first window");
    await host.execute("second window");
    expect(host.coverage().complete).toBe(false);
  });

  it("is dropped by a prefiltered turn anywhere in the request", async () => {
    // Prompt §5 gap 2: once any turn ranked rather than scanned, the answer
    // must say "the earliest found". A complete flag would contradict that in
    // metadata, so the taint outlives the turn that caused it.
    const host = hostOver([
      frameFor(docs(340, 22), { complete: true }),
      frameFor(docs(10, 0), { method: "prefiltered" }),
    ]);
    await host.execute("stream everything");
    await host.execute("then search");
    const coverage = host.coverage();
    expect(coverage.method).toBe("prefiltered");
    expect(coverage.complete).toBe(false);
  });

  it("is dropped when a frame never arrives, until a later turn earns it", async () => {
    const host = hostOver([
      "no frame at all",
      frameFor(docs(340, 22), { complete: true }),
    ]);
    await host.execute("truncated");
    expect(host.coverage().complete).toBe(false);
    await host.execute("stream everything");
    expect(host.coverage().complete).toBe(true);
  });
});
