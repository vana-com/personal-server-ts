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
  over: { method?: "full" | "prefiltered" } = {},
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
