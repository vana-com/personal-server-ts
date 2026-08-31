import { describe, expect, it } from "vitest";

import { createLiteToolHost } from "./lite-tool-host.js";
import type {
  Sandbox,
  SandboxResult,
} from "@opendatalabs/personal-server-ts-core/query";

/**
 * The cross-run coverage merge, asserted on the Lite host.
 *
 * `lite-tool-host.ts` duplicates the Node host's merge deliberately: the Node
 * host reads its runner bundle with `readFileSync` and derives `readPaths`
 * through `node:path`, neither of which a browser has, and design §19.18 kept
 * the Node arm byte-for-byte the code its benchmark numbers were measured on.
 * A duplicated function is only safe while something fails when the two
 * diverge, so this suite asserts the same properties
 * `packages/server/src/query/coverage-merge.test.ts` asserts of
 * `createSandboxToolHost` — same cases, same expected numbers — against
 * `createLiteToolHost`. A change to one merge that is not made to the other
 * fails here rather than quietly changing what a counter means on one runtime.
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
  // Browser-side: no `Buffer`, so the frame is encoded the way the VM host is.
  const json = JSON.stringify(doc);
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  return `__VANA_RESULT_V1_BEGIN__${b64}__VANA_RESULT_V1_END__`;
}

const enforcement = {
  filesystemRead: true,
  filesystemWrite: true,
  network: true,
  cpu: true,
  memory: true,
  processCount: true,
  wallClock: true,
  notes: [] as string[],
};

/** A sandbox that replays a scripted sequence of coverage frames. */
function scriptedSandbox(frames: string[]): Sandbox {
  let i = 0;
  return {
    async run(): Promise<SandboxResult> {
      const stdout = frames[Math.min(i++, frames.length - 1)] as string;
      return {
        stdout,
        stderr: "",
        exitCode: 0,
        timedOut: false,
        truncated: false,
        durationMs: 1,
        termination: "completed",
        enforcement,
        violations: [],
      };
    },
    async capabilities() {
      return { available: true, enforcement };
    },
  };
}

function hostOver(frames: string[]) {
  return createLiteToolHost({
    sandbox: scriptedSandbox(frames),
    scopes: [{ scope: "documents.files", path: "/vana/grant/documents.files" }],
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

describe("Lite: coverage merged across runs in one request", () => {
  it("does not double-count a scope re-read in a later turn", async () => {
    const host = hostOver([frameFor(docs(340, 22)), frameFor(docs(340, 22))]);
    await host.execute("first turn");
    await host.execute("third turn, same scope");
    const coverage = host.coverage();
    expect(coverage.recordsScanned, "would be 680 if summed").toBe(340);
    expect(coverage.unreadable, "would be 44 if summed").toBe(22);
  });

  it("still adds scopes that were genuinely new in a later turn", async () => {
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
    expect(coverage.scopesScanned.slice().sort()).toEqual([
      "documents.files",
      "email.messages",
    ]);
  });

  it("takes the larger tally when a later turn read more of one scope", async () => {
    const host = hostOver([frameFor(docs(100, 5)), frameFor(docs(340, 22))]);
    await host.execute("partial");
    await host.execute("full");
    expect(host.coverage().recordsScanned).toBe(340);
  });
});

/**
 * The prefilter taint outlives the turn that caused it — a property of the
 * merge, so it belongs on whichever runtime is running it.
 *
 * Prompt §5 gap 2: once any turn ranked rather than scanned, the answer must
 * say "the earliest found" rather than "the earliest". A later exhaustive turn
 * must not clear that.
 */
describe("Lite: method merged across runs in one request", () => {
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
