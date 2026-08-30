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
 * fails here rather than quietly changing what `complete` means on one runtime.
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
 * `complete` accumulates; it does not decay — and the prefilter taint outlives
 * the turn that caused it. Both are properties of the merge, so both belong on
 * whichever runtime is running it.
 */
describe("Lite: coverage.complete merged across runs in one request", () => {
  it("survives a probe turn that read nothing", async () => {
    const host = hostOver([
      frameFor({}),
      frameFor(docs(340, 22), { complete: true }),
    ]);
    await host.execute("what scopes are there?");
    await host.execute("now read all of it");
    expect(host.coverage().complete).toBe(true);
  });

  it("is not undone by a later bounded read of an already-complete scope", async () => {
    const host = hostOver([
      frameFor(docs(340, 22), { complete: true }),
      frameFor(docs(50, 0)),
    ]);
    await host.execute("stream everything");
    await host.execute("look again at the first fifty");
    const coverage = host.coverage();
    expect(coverage.complete).toBe(true);
    expect(coverage.recordsScanned, "the full pass still subsumes").toBe(340);
  });

  it("stays false when no single turn covered the grant", async () => {
    const host = hostOver([frameFor(docs(100, 5)), frameFor(docs(120, 3))]);
    await host.execute("first window");
    await host.execute("second window");
    expect(host.coverage().complete).toBe(false);
  });

  it("is dropped by a prefiltered turn anywhere in the request", async () => {
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
