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
  over: {
    method?: "full" | "prefiltered";
    /**
     * Which of these scopes this run read but did not exhaust.
     *
     * Defaults to none, i.e. every scope in the frame was streamed end to end.
     * A frame that names a scope here is the "sampled it" case.
     */
    partiallyScanned?: string[];
  } = {},
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
      scopesPartiallyScanned: over.partiallyScanned ?? [],
      recordsScanned: totals.records,
      bytesScanned: totals.bytes,
      unreadable: totals.unreadable,
      perScope,
      scopesSkipped: [],
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
 * `scopesPartiallyScanned` merged across runs — the AND/OR call.
 *
 * A scope is partially scanned FOR THE REQUEST only if no run exhausted it.
 * Once some turn streamed it end to end the request has seen every record, and
 * a bounded read in another turn adds no doubt about what was covered — which
 * is exactly the rule `CoverageLedger.completeScope` already applies inside one
 * run, so having the merge disagree would make a two-turn request report a
 * scope as sampled that a one-turn request with the same reads reported as
 * covered.
 *
 * Pinned in both directions because the removed `complete` flag got a decision
 * of precisely this shape backwards. The dangerous direction is the third
 * case: a scope no run exhausted must never come out of the merge looking
 * fully scanned.
 */
describe("scopesPartiallyScanned merged across runs in one request", () => {
  it("clears a scope that a later turn read in full", async () => {
    const host = hostOver([
      frameFor(docs(100, 5), { partiallyScanned: ["documents.files"] }),
      frameFor(docs(340, 22)),
    ]);
    await host.execute("bounded read");
    await host.execute("then a full pass");
    expect(host.coverage().scopesPartiallyScanned).toEqual([]);
    expect(host.coverage().scopesScanned).toEqual(["documents.files"]);
  });

  it("clears it in the other order too, so the merge is not last-writer-wins", async () => {
    const host = hostOver([
      frameFor(docs(340, 22)),
      frameFor(docs(100, 5), { partiallyScanned: ["documents.files"] }),
    ]);
    await host.execute("full pass");
    await host.execute("then a bounded re-read");
    expect(host.coverage().scopesPartiallyScanned).toEqual([]);
  });

  it("keeps a scope no turn ever exhausted", async () => {
    // The direction that matters: two samples are still a sample. Nothing here
    // reached `completeScope`, so the request may not present the scope as
    // covered — this is the anti-sampling property at the request level.
    const host = hostOver([
      frameFor(docs(100, 5), { partiallyScanned: ["documents.files"] }),
      frameFor(docs(120, 5), { partiallyScanned: ["documents.files"] }),
    ]);
    await host.execute("sample one window");
    await host.execute("sample another window");
    expect(host.coverage().scopesPartiallyScanned).toEqual(["documents.files"]);
    // Still listed as scanned — it WAS read. The two lists say different
    // things, and the second is what stops the first from being over-read.
    expect(host.coverage().scopesScanned).toEqual(["documents.files"]);
  });

  it("tracks each scope independently", async () => {
    const host = hostOver([
      frameFor(
        {
          "documents.files": { records: 100, bytes: 1, unreadable: 0 },
          "email.messages": { records: 900, bytes: 1, unreadable: 0 },
        },
        { partiallyScanned: ["documents.files"] },
      ),
      frameFor({
        "email.messages": { records: 900, bytes: 1, unreadable: 0 },
      }),
    ]);
    await host.execute("sample docs, stream email");
    await host.execute("stream email again");
    expect(host.coverage().scopesPartiallyScanned).toEqual(["documents.files"]);
  });
});

/**
 * The prefilter taint outlives the turn that caused it.
 *
 * Prompt §5 gap 2: once any turn ranked rather than scanned, the answer must
 * say "the earliest found" rather than "the earliest". A later exhaustive turn
 * must not clear that, so the taint is re-applied against the MERGED method
 * rather than taken from the last run to speak.
 */
describe("method merged across runs in one request", () => {
  it("stays prefiltered once any turn prefiltered", async () => {
    const host = hostOver([
      frameFor(docs(10, 0), { method: "prefiltered" }),
      frameFor(docs(340, 22)),
    ]);
    await host.execute("search");
    await host.execute("then stream everything");
    expect(host.coverage().method).toBe("prefiltered");
  });
});
