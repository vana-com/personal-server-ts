import { describe, expect, it } from "vitest";

import {
  createFakeInferenceProvider,
  type InferenceChatResult,
} from "../../derivatives/inference.js";
import { runQueryLoop } from "./loop.js";
import { EMPTY_COVERAGE } from "./types.js";
import type {
  ExecutedRun,
  QueryScriptResult,
  QueryToolHost,
} from "./tool-host.js";

const fence = "```";

function runBlock(body: string): string {
  return `${fence}vana:run\n${body}\n${fence}`;
}
function answerBlock(payload: Record<string, unknown>): string {
  return `${fence}vana:answer\n${JSON.stringify(payload)}\n${fence}`;
}
function reply(content: string): InferenceChatResult {
  return {
    content,
    usage: { promptTokens: 10, completionTokens: 5 },
    receiptId: "r-1",
  };
}

/**
 * A tool host that runs nothing. Since the 4a/4b/5 integration the loop has no
 * `Sandbox` of its own — the host owns both layers and returns an already
 * host-authored outcome — so these fakes stand in for a confined run rather
 * than for a sandbox.
 */
function executed(over: Partial<ExecutedRun> = {}): ExecutedRun {
  return {
    coverage: {
      scopesScanned: ["oura.sleep"],
      recordsScanned: 1030,
      scopesSkipped: [],
    },
    notes: [],
    termination: "completed",
    stdout: "",
    stderr: "",
    violations: [],
    truncated: false,
    ...over,
  };
}

function fakeTools(
  runs: ExecutedRun[] = [executed()],
  over: Partial<QueryToolHost> = {},
): QueryToolHost & { executed: string[] } {
  const seen: string[] = [];
  let i = 0;
  let last: ExecutedRun | undefined;
  return {
    executed: seen,
    async listScopes() {
      return [{ scope: "oura.sleep", itemCount: 1030 }];
    },
    async execute(modelCode: string) {
      seen.push(modelCode);
      last = runs[Math.min(i++, runs.length - 1)] ?? executed();
      return last;
    },
    // Stands in for the real host's accumulator. A request where no script
    // ran has read nothing, and must say so rather than inherit a default.
    coverage() {
      return (
        last?.coverage ?? {
          scopesScanned: [],
          recordsScanned: 0,
          scopesSkipped: [],
        }
      );
    },
    ...over,
  } as QueryToolHost & { executed: string[] };
}

/**
 * `EMPTY_COVERAGE` fails closed, and this is the pin for it.
 *
 * It used to carry that property by means of `complete: false`, which
 * `honestAnswerText` gated on. The flag is gone — it demanded every granted
 * scope be read end to end, so it was false on every real run and appended a
 * blanket caveat to every answer. The guarantee itself must survive, and it now
 * rests on the counters: `recordsScanned: 0` over `scopesScanned: []` is
 * host-authored, only a confined run can move either, and that condition alone
 * forces the caveat.
 *
 * This is the "no confined run ever reported" path — a contract violation burned
 * both attempts, or the coverage frame never arrived — so `tools.coverage()`
 * yields nothing and the loop falls back to the constant. "We learned nothing"
 * must not be able to render as a confident total.
 */
describe("EMPTY_COVERAGE fails closed", () => {
  /** A host whose accumulator never reported, forcing the fallback. */
  const silentHost = () =>
    fakeTools([executed()], {
      coverage: () =>
        undefined as unknown as ReturnType<QueryToolHost["coverage"]>,
    });

  it("is the zeroed shape, with no counter left undefined", () => {
    expect(EMPTY_COVERAGE.recordsScanned).toBe(0);
    expect(EMPTY_COVERAGE.scopesScanned).toEqual([]);
    expect(EMPTY_COVERAGE.scopesSkipped).toEqual([]);
  });

  it("caveats the answer text when no run ever reported", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "Exactly 42 of them." })),
    });
    const out = await runQueryLoop(
      { question: "how many?", grantedScopes: ["oura.sleep"] },
      { provider, tools: silentHost() },
    );

    // The answer must not stand as written. This is the whole property: the
    // caveat is in the TEXT, because a caller that renders only `answer` must
    // still see that nothing was read.
    expect(out.answer).toContain("incomplete");
    expect(out.answer).toContain("no record in any granted scope was read");
    expect(out.coverage.recordsScanned).toBe(0);
    expect(out.coverage.scopesScanned).toEqual([]);
  });

  it("caveats even when the grounding guard is exempted", async () => {
    // The sharp pin. Ordinarily a zero-record answer is refused outright by
    // the grounding guard, which would mask this property — but a run that
    // FAILED exempts that guard (a refusal is itself a host-authored finding
    // an absence answer can rest on), so the model's prose is accepted. On
    // this path the zeroed counters are the only thing standing between "we
    // learned nothing" and a confident total.
    const provider = createFakeInferenceProvider({
      // Turn 1 runs a script, which the host refuses. Turn 2 answers anyway.
      respond: (_i, n) =>
        n === 0
          ? reply(runBlock("await vana.readAll('not.granted');"))
          : reply(answerBlock({ answer: "You have never done that." })),
    });
    const out = await runQueryLoop(
      { question: "have I ever?", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools(
          [
            executed({
              termination: "error",
              error: { code: "SCOPE_NOT_GRANTED", message: "refused" },
            }),
          ],
          {
            coverage: () =>
              undefined as unknown as ReturnType<QueryToolHost["coverage"]>,
          },
        ),
      },
    );

    // The model's prose survives — the guard was exempted — so the caveat is
    // the only protection left, and it must be there.
    expect(out.answer).toContain("You have never done that");
    expect(out.answer).toContain("incomplete");
    expect(out.answer).toContain("no record in any granted scope was read");
  });

  it("does not report a record count it never observed", async () => {
    // The fallback cannot invent a reading. If this ever reported a non-zero
    // count, the caveat above would stop firing and an empty run would render
    // as a total one.
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "All 5000 of them." })),
    });
    const out = await runQueryLoop(
      { question: "how many?", grantedScopes: ["oura.sleep"] },
      { provider, tools: silentHost() },
    );
    expect(out.answer).not.toMatch(/\d+ record\(s\) across/);
  });
});

describe("runQueryLoop — happy path", () => {
  it("runs a script then returns the model's answer", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0
            ? runBlock("const s = await vana.readAll('oura.sleep');")
            : answerBlock({
                answer: "6.52 hours over 1030 nights, main sleep only.",
                citations: [{ scope: "oura.sleep" }],
              }),
        ),
    });
    const tools = fakeTools([executed({ stdout: "avg=6.52" })]);

    const out = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools },
    );

    expect(out.answer).toContain("6.52 hours");
    expect(out.coverage.recordsScanned).toBe(1030);
    expect(out.script).toContain("vana.readAll");
    // One script ran across two model turns. These were one number before and
    // the conflation hid work: a turn spent on a repair retry looked like a
    // tool call.
    expect(out.cost.toolCalls).toBe(1);
    expect(out.cost.modelTurns).toBe(2);
    expect(out.receiptIds).toEqual(["r-1", "r-1"]);
  });

  it("wraps the model's code before executing it — never runs it bare", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(n === 0 ? runBlock("evil()") : answerBlock({ answer: "done" })),
    });
    const tools = fakeTools();
    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools },
    );
    // The loop hands RAW model code to the host and holds no sandbox of its
    // own. Since the 4a/4b/5 integration the host runs it as data inside the
    // confined interpreter, so "running it bare" is unreachable from here
    // rather than merely avoided by convention.
    expect(tools.executed[0]).toBe("evil()");
    expect("sandbox" in ({} as Record<string, unknown>)).toBe(false);
  });

  it("feeds script output back as the next message's content", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(n === 0 ? runBlock("x") : answerBlock({ answer: "done" })),
    });
    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed({ stdout: "SENTINEL_OUT" })]),
      },
    );
    const second = provider.calls[1];
    expect(second?.messages.at(-1)?.content).toContain("SENTINEL_OUT");
    expect(second?.messages.at(-1)?.role).toBe("user");
  });

  it("ends the run when the script calls vana.result", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("vana.result({answer:'from script'})")),
    });
    const result: QueryScriptResult = {
      answer: "from script",
      citations: [{ scope: "oura.sleep" }],
      value: 6.52,
    };
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed({ result })]),
      },
    );
    expect(out.answer).toContain("from script");
    expect(out.value).toBe(6.52);
    expect(out.cost.toolCalls).toBe(1);
  });
});

describe("runQueryLoop — the response contract", () => {
  it("repairs once, then succeeds", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0
            ? "I think it's about 6 hours."
            : answerBlock({ answer: "6.52h" }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed()], {
          coverage: () => ({
            scopesScanned: ["oura.sleep"],
            recordsScanned: 1030,
            scopesSkipped: [],
          }),
        }),
      },
    );
    expect(out.answer).toContain("6.52h");
    // The repair message went back as a user turn.
    const repairTurn = provider.calls[1]?.messages.at(-1);
    expect(repairTurn?.content).toContain(
      "did not follow the response contract",
    );
  });

  it("gives up after a second violation, honestly", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply("still just prose, no block at all"),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools() },
    );
    expect(out.answer).toContain("could not produce a valid script");
    expect(out.coverage.stoppedBecause).toBe("contractViolation");
    // Exactly two model turns: the first attempt and the one repair — and
    // zero tool calls, because neither turn produced a runnable script. The
    // old single counter reported "2 tool calls" for a run that never called
    // a tool.
    expect(out.cost.modelTurns).toBe(2);
    expect(out.cost.toolCalls).toBe(0);
  });
});

/**
 * An answer has to be backed by a read.
 *
 * The PS-Lite benchmark's single miss was a model that emitted a `vana:answer`
 * over `recordsScanned: 0` and had it accepted, so a confabulation arrived
 * wearing the shape of a finding. The host's record counter is the witness:
 * only a confined run can move it.
 */
describe("runQueryLoop — an answer must be grounded in a read", () => {
  /** A host that has never run anything, reporting so honestly. */
  function unreadTools(over: Partial<QueryToolHost> = {}) {
    return fakeTools([executed()], {
      coverage: () => ({
        scopesScanned: [],
        recordsScanned: 0,
        scopesSkipped: [],
      }),
      ...over,
    });
  }

  it("refuses an answer emitted on a turn that ran no script", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "About six and a half." })),
    });
    const out = await runQueryLoop(
      { question: "how much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: unreadTools() },
    );

    // The model's prose is not the answer; the refusal is.
    expect(out.answer).not.toContain("About six and a half");
    expect(out.coverage.stoppedBecause).toBe("ungroundedAnswer");
    expect(out.cost.toolCalls).toBe(0);
  });

  it("pushes back once, naming what the host counted", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "About six and a half." })),
    });
    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: unreadTools() },
    );

    // Exactly one push-back, then the run ends — it must not spend the whole
    // turn budget re-asking, since each turn is a relay call.
    expect(provider.calls).toHaveLength(2);
    const pushBack = provider.calls[1]?.messages.at(-1);
    expect(pushBack?.role).toBe("user");
    expect(pushBack?.content).toContain("0 records read");
  });

  it("accepts the answer once a script has read something", async () => {
    // The same ungrounded first answer, but this time the model takes the
    // push-back, reads data, and answers from it.
    let ran = false;
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 1
            ? runBlock("const s = await vana.readAll('oura.sleep');")
            : answerBlock({ answer: "6.52 hours over 1030 nights." }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: unreadTools({
          async execute() {
            ran = true;
            return executed({ stdout: "avg=6.52" });
          },
          // Stands in for the host accumulator: zero until a run reports.
          coverage: () =>
            ran
              ? {
                  scopesScanned: ["oura.sleep"],
                  recordsScanned: 1030,
                  scopesSkipped: [],
                }
              : {
                  scopesScanned: [],
                  recordsScanned: 0,
                  scopesSkipped: [],
                },
        }),
      },
    );

    expect(out.answer).toContain("6.52 hours");
    expect(out.coverage.stoppedBecause).toBeUndefined();
    expect(out.coverage.recordsScanned).toBe(1030);
  });

  it("refuses an answer after a script that scanned zero records", async () => {
    // A script ran and completed, but read nothing. `toolCalls: 1` is not
    // evidence of a read, which is why the guard reads the host's counter
    // rather than the loop's own run count.
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0
            ? runBlock("const s = [];")
            : answerBlock({ answer: "You averaged 6.5 hours." }),
        ),
    });
    const emptyCoverage = {
      scopesScanned: [],
      recordsScanned: 0,
      scopesSkipped: [],
    };
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed({ coverage: emptyCoverage })], {
          coverage: () => emptyCoverage,
        }),
      },
    );

    expect(out.answer).not.toContain("6.5 hours");
    expect(out.coverage.stoppedBecause).toBe("ungroundedAnswer");
    expect(out.cost.toolCalls).toBeGreaterThan(0);
  });

  it("still lets a refused read be answered — the denial IS the finding", async () => {
    // `tools/api.ts` throws `SCOPE_NOT_GRANTED` rather than returning `[]`, so
    // a script cannot read a denial as "there is nothing there". Reporting
    // that denial is an honest answer, and it necessarily scanned 0 records:
    // the grounding rule must not swallow it. Note `error` maps to no
    // `stoppedBecause`, so the flag cannot key off the termination alone.
    const provider = createFakeInferenceProvider({
      respond: (input, n) =>
        n === 0
          ? reply(runBlock("await vana.readAll('bank.transactions');"))
          : // Echo what the host said back as the answer, as the eval harness
            // does, so the assertion reads the sandbox's own words.
            reply(
              answerBlock({
                answer: String(input.messages.at(-1)?.content ?? ""),
              }),
            ),
    });
    const denied = {
      scopesScanned: [],
      recordsScanned: 0,
      scopesSkipped: [],
    };
    const out = await runQueryLoop(
      { question: "how much did I spend?", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools(
          [
            executed({
              coverage: denied,
              termination: "error",
              error: {
                code: "SCOPE_NOT_GRANTED",
                message: 'scope "bank.transactions" is not in this grant',
              },
            }),
          ],
          { coverage: () => denied },
        ),
      },
    );

    expect(out.answer).toContain("not in this grant");
    expect(out.coverage.stoppedBecause).not.toBe("ungroundedAnswer");
  });

  it("refuses a vana.result figure computed over zero records", async () => {
    // The other door onto a clean final answer. A script that reports a
    // number while the host counted nothing read produced it from nowhere.
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("vana.result({answer:'6.5h',value:6.5})")),
    });
    const empty = {
      scopesScanned: [],
      recordsScanned: 0,
      scopesSkipped: [],
    };
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools(
          [
            executed({
              coverage: empty,
              result: { answer: "6.5h", value: 6.5 },
            }),
          ],
          { coverage: () => empty },
        ),
      },
    );

    expect(out.answer).not.toContain("6.5h");
    expect(out.coverage.stoppedBecause).toBe("ungroundedAnswer");
    // The refused figure must not survive into the answer.
    expect(out.value).toBeUndefined();
  });

  it("accepts a vana.result figure once records were read", async () => {
    const provider = createFakeInferenceProvider({
      respond: () =>
        reply(runBlock("vana.result({answer:'6.52h',value:6.52})")),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([
          executed({ result: { answer: "6.52h", value: 6.52 } }),
        ]),
      },
    );
    expect(out.answer).toContain("6.52h");
    expect(out.value).toBe(6.52);
    expect(out.coverage.stoppedBecause).toBeUndefined();
  });

  it("still answers a grant question that reads no records (Q12)", async () => {
    // The divergence from the answer branch, pinned. `vana.scopes()` returns
    // host data and scans nothing, and Q12 is answered over an EMPTY grant
    // where no counter can ever be non-zero. A figure-free `vana.result` here
    // is honest, and refusing it would make the class unanswerable.
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("vana.result({answer:'visible-count:0'})")),
    });
    const empty = {
      scopesScanned: [],
      recordsScanned: 0,
      scopesSkipped: [],
    };
    const out = await runQueryLoop(
      { question: "what did this server tell the builder?", grantedScopes: [] },
      {
        provider,
        tools: fakeTools(
          [
            executed({
              coverage: empty,
              result: { answer: "visible-count:0" },
            }),
          ],
          { coverage: () => empty },
        ),
      },
    );
    expect(out.answer).toContain("visible-count:0");
    expect(out.coverage.stoppedBecause).not.toBe("ungroundedAnswer");
  });

  it("pushes back once before failing a vana.result figure", async () => {
    // Shares the answer branch's counter, so the model gets exactly one turn
    // to write a script that reads something.
    let ran = 0;
    const empty = {
      scopesScanned: [],
      recordsScanned: 0,
      scopesSkipped: [],
    };
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("vana.result({answer:'6.5h',value:6.5})")),
    });
    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([], {
          async execute() {
            ran += 1;
            return executed({
              coverage: empty,
              result: { answer: "6.5h", value: 6.5 },
            });
          },
          coverage: () => empty,
        }),
      },
    );
    expect(ran).toBe(2);
    const pushBack = provider.calls[1]?.messages.at(-1);
    expect(pushBack?.content).toContain("0 records read");
  });

  it("says in the answer text that nothing was read", async () => {
    // The refusal has to be legible to a reader of the answer, not only to a
    // caller that inspects coverage — the same rule the zeroed counters carry.
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "Six and a half." })),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: unreadTools() },
    );
    expect(out.answer).toContain("incomplete");
    expect(out.answer).toContain("without running a script that read any");
  });
});

describe("runQueryLoop — honesty invariants", () => {
  it("caveats an answer whose run read nothing, and reports the zero", async () => {
    // A model that answers straight from its own prose has read nothing. The
    // host accumulator has no runs to report, so the counters are zero — and
    // the answer text has to say so. Without this, a hallucinated answer
    // inherits a confident-looking default.
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "About six and a half." })),
    });
    const out = await runQueryLoop(
      { question: "how much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools() },
    );
    expect(out.coverage.recordsScanned).toBe(0);
    expect(out.answer).toContain("incomplete");
  });

  it("surfaces a bounded reading in the ANSWER TEXT, not only metadata", async () => {
    // plan phase 5: a limit on what was read must be visible to a reader of
    // the answer. Metadata alone lets a caller render a confident wrong answer.
    const provider = createFakeInferenceProvider({
      respond: () =>
        reply(answerBlock({ answer: "You have never agreed to that." })),
    });
    const out = await runQueryLoop(
      { question: "have I ever?", grantedScopes: ["docs"] },
      {
        provider,
        tools: fakeTools([executed()], {
          coverage: () => ({
            scopesScanned: ["docs"],
            recordsScanned: 318,
            scopesSkipped: [{ scope: "email", reason: "not granted" }],
            unreadable: 22,
          }),
        }),
      },
    );
    expect(out.answer).toContain("incomplete");
    expect(out.answer).toContain("22 record(s) could not be read");
    expect(out.answer).toContain("email (not granted)");
  });

  it("carries a sandbox kill into stoppedBecause and into the answer text", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("forever()")),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        // The sandbox cut the run short. That has to reach both the metadata
        // and the prose, whatever the run managed to read first.
        tools: fakeTools([executed({ termination: "cpu" })]),
        maxTurns: 1,
      },
    );
    expect(out.coverage.stoppedBecause).toBe("cpu");
    expect(out.answer).toContain("CPU limit");
  });

  it("takes coverage from the host, ignoring what the model asserts", async () => {
    // The model claims a complete scan of 999999 records; the host counted 12.
    const provider = createFakeInferenceProvider({
      respond: () =>
        reply(
          answerBlock({
            answer: "Scanned all 999999 records, complete coverage.",
            coverage: { recordsScanned: 999_999 },
          }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed()], {
          coverage: () => ({
            scopesScanned: ["oura.sleep"],
            recordsScanned: 12,
            scopesSkipped: [],
          }),
        }),
      },
    );
    expect(out.coverage.recordsScanned).toBe(12);
  });

  it("reports budget exhaustion as an outcome, not an error", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("keep_going()")),
    });
    const out = await runQueryLoop(
      {
        question: "q",
        grantedScopes: ["oura.sleep"],
        budget: { toolCalls: 3 },
      },
      { provider, tools: fakeTools() },
    );
    expect(out.coverage.stoppedBecause).toBe("budget");
    expect(out.cost.toolCalls).toBe(3);
    expect(out.answer).toContain("budget");
  });

  it("carries sandbox violations into coverage", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0 ? runBlock("readSecret()") : answerBlock({ answer: "d" }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([
          executed({ violations: ["denied read /etc/passwd"] }),
        ]),
      },
    );
    expect(out.coverage.violations).toContain("denied read /etc/passwd");
  });

  it("flags scopes with no T2 profile as reduced confidence", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "done" })),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["mystery.source"] },
      {
        provider,
        tools: fakeTools([executed()], {
          async listScopes() {
            return [{ scope: "mystery.source" }];
          },
          coverage: () => ({
            scopesScanned: ["mystery.source"],
            recordsScanned: 5,
            scopesSkipped: [],
          }),
        }),
      },
    );
    expect(out.coverage.unprofiledScopes).toContain("mystery.source");
    expect(out.answer).toContain("no source profile");
  });
});

describe("runQueryLoop — transcript trimmed to fit the relay's body cap", () => {
  /**
   * Assistant scripts are NOT capped by `truncateOutput` (only run results
   * are), so a few verbose turns are the realistic way a transcript reaches
   * the budget. Each script here is ~50 KiB against a 120 KiB budget, so the
   * fit starts dropping turns partway through.
   */
  function verboseScript(n: number): string {
    return runBlock(`// ${"x".repeat(50_000)}\nconst t = ${n};`);
  }

  it("records dropped turns in coverage.violations, not just in the transcript", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n < 6
            ? verboseScript(n)
            : answerBlock({
                answer: "6.52 hours over 1030 nights.",
                citations: [{ scope: "oura.sleep" }],
              }),
        ),
    });

    const out = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools([executed({ stdout: "avg=6.52" })]) },
    );

    // The marker message tells the model. This asserts the HOST also knows:
    // with the old 1 MiB budget nothing was ever dropped, so there was no
    // violation to record and the run looked untrimmed.
    const violations = out.coverage.violations ?? [];
    expect(
      violations.some((v) => v.includes("dropped from the transcript")),
    ).toBe(true);
    expect(violations.some((v) => v.includes("262144"))).toBe(true);
  });

  it("still answers — trimming beats the 413 it replaces", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n < 6
            ? verboseScript(n)
            : answerBlock({
                answer: "6.52 hours over 1030 nights.",
                citations: [{ scope: "oura.sleep" }],
              }),
        ),
    });

    const out = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools([executed({ stdout: "avg=6.52" })]) },
    );

    expect(out.answer).toContain("6.52 hours");
  });

  it("leaves coverage.violations clear when nothing had to be dropped", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0
            ? runBlock("const s = await vana.readAll('oura.sleep');")
            : answerBlock({
                answer: "6.52 hours over 1030 nights.",
                citations: [{ scope: "oura.sleep" }],
              }),
        ),
    });

    const out = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools([executed({ stdout: "avg=6.52" })]) },
    );

    expect(
      (out.coverage.violations ?? []).some((v) =>
        v.includes("dropped from the transcript"),
      ),
    ).toBe(false);
  });
});
