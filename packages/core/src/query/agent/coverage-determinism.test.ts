import { describe, expect, it } from "vitest";

import {
  createFakeInferenceProvider,
  type InferenceChatResult,
} from "../../derivatives/inference.js";
import { canonicalJsonBytes } from "../../json/jcs.js";
import { runQueryLoop } from "./loop.js";
import type { QueryCoverage } from "./types.js";
import type { QueryToolHost } from "./tool-host.js";

const fence = "```";

function reply(content: string): InferenceChatResult {
  return {
    content: `${fence}vana:answer\n${JSON.stringify({ answer: content })}\n${fence}`,
    usage: { promptTokens: 10, completionTokens: 5 },
    receiptId: "r-1",
  };
}

/**
 * A host that reports a fixed coverage object and never runs a script.
 *
 * The point of the fake is that the TEST owns the exact object identity and
 * therefore its own key insertion order — which is the thing under test. Real
 * hosts return a `CoverageCounters` (`tools/types.ts`), which carries two
 * fields `QueryCoverage` used to inherit silently on the spread, so the fakes
 * below carry them too: `perScope`, whose key order is the order scopes were
 * first touched, and `enforcementNotes`.
 */
function hostReporting(coverage: unknown): QueryToolHost {
  return {
    async listScopes() {
      return [{ scope: "oura.sleep", itemCount: 1030 }];
    },
    async execute() {
      throw new Error("no script should run on the wall-clock path");
    },
    coverage: () => coverage as QueryCoverage,
  } as QueryToolHost;
}

/**
 * Drive the loop to the wall-clock stop with a monotonic clock.
 *
 * `wallClockMs: 0` breaks before the first turn, so no script runs and the
 * coverage on the answer is exactly what the host reported, put through the
 * loop's projection. The wrap-up turn still fires; it cannot touch coverage.
 */
async function coverageFrom(host: QueryToolHost): Promise<QueryCoverage> {
  let t = 0;
  const provider = createFakeInferenceProvider({
    respond: () => reply("Nothing to report."),
  });
  const out = await runQueryLoop(
    {
      question: "how many?",
      grantedScopes: ["oura.sleep"],
      budget: { toolCalls: 4, wallClockMs: 0 },
    },
    { provider, tools: host, now: () => (t += 1000) },
  );
  return out.coverage;
}

/** Logically identical content, laid out in two different key orders. */
const CANONICAL_HOST = {
  scopesScanned: ["a.one", "b.two"],
  scopesPartiallyScanned: ["b.two"],
  recordsScanned: 340,
  bytesScanned: 0,
  unreadable: 0,
  perScope: {
    "a.one": { records: 140, bytes: 0, unreadable: 0 },
    "b.two": { records: 200, bytes: 0, unreadable: 0 },
  },
  scopesSkipped: [],
  method: "full",
  enforcementNotes: ["RSS watchdog samples every 50ms"],
};

/**
 * The same coverage, reached by a host that touched `b.two` first and that
 * assembles its own object in a different order.
 *
 * Nothing here is a different FINDING — every value is equal to
 * {@link CANONICAL_HOST}'s. Only the layout differs.
 */
const SHUFFLED_HOST = {
  enforcementNotes: ["RSS watchdog samples every 50ms"],
  method: "full",
  scopesSkipped: [],
  perScope: {
    "b.two": { records: 200, bytes: 0, unreadable: 0 },
    "a.one": { records: 140, bytes: 0, unreadable: 0 },
  },
  unreadable: 0,
  bytesScanned: 0,
  recordsScanned: 340,
  scopesPartiallyScanned: ["b.two"],
  scopesScanned: ["a.one", "b.two"],
};

describe("QueryCoverage serializes deterministically", () => {
  /**
   * The property, stated as bytes: identical content in, identical bytes out.
   *
   * This is the pin for the whole change. Before it, the loop spread the
   * host's object and then mutated it, so the key order of the coverage on an
   * answer was a function of how the run got there — which host shape it
   * started from, and which branch set which field — rather than of what the
   * run found.
   */
  it("is byte-identical across two host layouts of the same content", async () => {
    const a = await coverageFrom(hostReporting(CANONICAL_HOST));
    const b = await coverageFrom(hostReporting(SHUFFLED_HOST));

    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    // And the bytes are not merely equal to each other but to the declared
    // order, so the property is falsifiable by a reordering of the literal in
    // `loop.ts` and not only by a divergence between the two runs.
    expect(JSON.stringify(a)).toBe(
      JSON.stringify({
        scopesScanned: ["a.one", "b.two"],
        scopesPartiallyScanned: ["b.two"],
        recordsScanned: 340,
        bytesScanned: 0,
        scopesSkipped: [],
        unreadable: 0,
        method: "full",
        stoppedBecause: "wallClock",
        enforcementNotes: ["RSS watchdog samples every 50ms"],
      }),
    );
  });

  /**
   * `stoppedBecause` has exactly one position regardless of who set it.
   *
   * The two paths are the ones that used to disagree: the host's accumulator
   * already carried the reason, so the assignment landed on an existing key at
   * the host's mid position; or it did not, and the loop's assignment appended
   * the key last. Same reason, same run, two serializations.
   */
  it("puts a host-carried and a loop-set stoppedBecause in the same place", async () => {
    // Laid out where `snapshot()` in `tools/coverage.ts` actually emits it —
    // after `method`, before `enforcementNotes` — because the mid position is
    // the whole point. Appending it to a spread of `CANONICAL_HOST` would put
    // it last and accidentally agree with the loop-set path.
    const hostCarried = await coverageFrom(
      hostReporting({
        scopesScanned: CANONICAL_HOST.scopesScanned,
        scopesPartiallyScanned: CANONICAL_HOST.scopesPartiallyScanned,
        recordsScanned: CANONICAL_HOST.recordsScanned,
        bytesScanned: CANONICAL_HOST.bytesScanned,
        unreadable: CANONICAL_HOST.unreadable,
        perScope: CANONICAL_HOST.perScope,
        scopesSkipped: CANONICAL_HOST.scopesSkipped,
        method: CANONICAL_HOST.method,
        stoppedBecause: "wallClock",
        enforcementNotes: CANONICAL_HOST.enforcementNotes,
      }),
    );
    const loopSet = await coverageFrom(hostReporting(CANONICAL_HOST));

    expect(loopSet.stoppedBecause).toBe("wallClock");
    expect(JSON.stringify(hostCarried)).toBe(JSON.stringify(loopSet));
  });

  /**
   * `perScope` does not travel on the answer.
   *
   * It is the tool layer's substrate for the cross-run subsumption merge, read
   * off `CoverageCounters` in `sandbox-tool-host.ts` / `lite-tool-host.ts` and
   * nowhere else, and its key order is the order scopes were first touched.
   * That is the one field whose serialization could not be made a function of
   * its content, so it is not projected. The merge is untouched — this asserts
   * only that the projection drops it.
   */
  it("does not project perScope onto the answer", async () => {
    const coverage = await coverageFrom(hostReporting(CANONICAL_HOST));
    expect(Object.keys(coverage)).not.toContain("perScope");
    // The counters it attributes are still reported in full.
    expect(coverage.recordsScanned).toBe(340);
    expect(coverage.scopesScanned).toEqual(["a.one", "b.two"]);
  });

  /**
   * `scopesPartiallyScanned` travels, in its one declared position.
   *
   * Unlike `perScope` this one IS projected: its order is a function of its
   * content (the ledger sorts it) and it carries the anti-sampling property,
   * so a consumer needs it. It sits immediately after `scopesScanned`, whose
   * subset it is.
   */
  it("projects scopesPartiallyScanned next to scopesScanned", async () => {
    const coverage = await coverageFrom(hostReporting(CANONICAL_HOST));
    expect(coverage.scopesPartiallyScanned).toEqual(["b.two"]);
    const keys = Object.keys(coverage);
    expect(keys.indexOf("scopesPartiallyScanned")).toBe(
      keys.indexOf("scopesScanned") + 1,
    );
  });

  /**
   * A zero counter is reported, not dropped.
   *
   * The conditional spreads test `!== undefined` rather than truthiness for
   * exactly this: `bytesScanned: 0` over a run that read records with no bytes
   * attributed is a finding, and `unreadable: 0` is what makes an absence
   * answer honest. Testing for truthiness would silently delete both.
   */
  it("keeps a zero bytesScanned and a zero unreadable", async () => {
    const coverage = await coverageFrom(hostReporting(CANONICAL_HOST));
    expect(coverage.bytesScanned).toBe(0);
    expect(coverage.unreadable).toBe(0);
  });

  /**
   * No key is present with an `undefined` value.
   *
   * `JSON.stringify` hides that mistake by dropping such members, but the JCS
   * canonicalizer the on-chain `dataHash` commitment runs through throws on
   * one. This asserts the shape is safe to canonicalize, which is the point of
   * making it deterministic in the first place.
   */
  it("carries no undefined member, so it can be canonicalized", async () => {
    const coverage = await coverageFrom(hostReporting(CANONICAL_HOST));
    for (const [key, value] of Object.entries(coverage)) {
      expect(value, `coverage.${key}`).not.toBeUndefined();
    }
    expect(() => canonicalJsonBytes(coverage)).not.toThrow();
  });

  /**
   * What JCS does and does not buy, pinned so the next reader does not have to
   * re-derive it.
   *
   * JCS sorts object members recursively, so at the hash boundary key order is
   * already neutral — canonicalizing the two layouts above agreed even BEFORE
   * this change. What it does not neutralize is a JS consumer comparing,
   * diffing, logging or snapshotting the object itself, which sees insertion
   * order; nor array order, which is content.
   */
  it("canonicalizes equal, which is a weaker property than equal bytes", async () => {
    const a = await coverageFrom(hostReporting(CANONICAL_HOST));
    const b = await coverageFrom(hostReporting(SHUFFLED_HOST));
    expect(canonicalJsonBytes(a)).toEqual(canonicalJsonBytes(b));

    // The weaker property demonstrated: JCS would have agreed on these two
    // even though `JSON.stringify` does not, which is why the hash boundary
    // was never the thing at risk.
    const spreadOrder = { ...SHUFFLED_HOST, stoppedBecause: "wallClock" };
    const literalOrder = { stoppedBecause: "wallClock", ...SHUFFLED_HOST };
    expect(JSON.stringify(spreadOrder)).not.toBe(JSON.stringify(literalOrder));
    expect(canonicalJsonBytes(spreadOrder)).toEqual(
      canonicalJsonBytes(literalOrder),
    );
  });
});
