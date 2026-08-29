/**
 * The query layer's agent loop: code as content.
 *
 * WHY NOT WIRE TOOL-CALLING (plan phase 5, decided — do not relitigate):
 * Phala E2EE v2 encrypts per field — each `messages[i].content` outbound and
 * exactly one `choices[i].message.content` inbound, AAD-bound. A tool-only
 * reply has no `content` to decrypt, so E2EE and wire tool-calling are
 * mutually exclusive per request. That costs us nothing: the model emits a
 * script in its message content, we run it, and we feed the result back as the
 * next message's content — exactly the fields E2EE covers. The script and its
 * results stay encrypted end to end, which is strictly better than tool traffic
 * travelling in clear JSON beside the ciphertext.
 *
 * WHY NOT pi-agent-core: see the phase 5 report. In short, we already own an
 * `InferenceProvider` that carries E2EE, Web3Signed relay auth and receipt
 * passthrough, and the plan forbids a second inference path. pi-ai is one.
 *
 * The loop is deliberately small. Everything expressive lives in the script the
 * model writes; everything trustworthy lives in the host's counters.
 */

import {
  InferenceRequestError,
  type InferenceMessage,
  type InferenceProvider,
} from "../../derivatives/inference.js";
import { buildSystemPrompt } from "./prompt.js";
import { parseTurn, repairMessage, type ParseFailure } from "./contract.js";
import type { QueryToolHost } from "./tool-host.js";
import {
  DEFAULT_OUTPUT_TAIL_BYTES,
  fitTranscript,
  renderRunResult,
} from "./transcript.js";
import {
  EMPTY_COVERAGE,
  type QueryAnswer,
  type QueryCitation,
  type QueryCoverage,
  type QueryRequest,
  type QueryStoppedBecause,
} from "./types.js";

export interface QueryLoopOptions {
  provider: InferenceProvider;
  /**
   * Owns BOTH sandbox layers. The loop deliberately has no `Sandbox` of its
   * own: model code must reach the confined interpreter, never Node.
   */
  tools: QueryToolHost;
  model?: string;
  /** Hard ceiling on model turns. Also the only bound on relay call volume. */
  maxTurns?: number;
  /**
   * Completion budget per turn.
   *
   * Deliberately above the provider default (2048). A *thinking* model spends
   * reasoning tokens out of this same budget, so a small ceiling can be
   * consumed entirely by reasoning and return a 200 with null content — which
   * killed 3 of 18 questions in the dogfood benchmark before this existed.
   */
  maxTokens?: number;
  /**
   * How many times to re-ask when a turn comes back with no content and the
   * provider gives no reason. Each retry raises the completion budget; see
   * {@link EMPTY_REPLY_RETRIES}.
   *
   * Does NOT govern a discarded tool call, which is a different failure with a
   * different answer — {@link MALFORMED_TOOL_CALL_RETRIES}.
   */
  emptyReplyRetries?: number;
  /** Per-turn cap on script output fed back to the model. */
  outputTailBytes?: number;
  profileBudgetChars?: number;
  /** Injected for tests; defaults to `Date.now`. */
  now?: () => number;
}

/**
 * Hard ceiling on model turns per question.
 *
 * Raised from 12 on benchmark evidence, not on feel. Across the 18-question
 * dogfood run the two questions that passed used 6 and 8 turns, while five
 * (28%) died at exactly 12 — several still making progress, having spent turns
 * on repair retries and scope exploration that never called a tool. 20 leaves
 * roughly 2.5x the observed successful working set.
 *
 * This is the only bound on relay call volume — the gateway has no rate
 * limiting — so it stays a hard ceiling, and the wrap-up turn below is
 * deliberately outside it by exactly one.
 */
export const DEFAULT_MAX_TURNS = 20;

/**
 * Per-turn completion budget.
 *
 * The provider default is 2048, which is not enough headroom for a reasoning
 * model: measured on `gemini-3.7-flash`, reasoning alone exhausted it and the
 * reply carried no content.
 */
export const DEFAULT_MAX_TOKENS = 8192;

/** Re-asks allowed when a turn returns no content and no reason. */
export const EMPTY_REPLY_RETRIES = 2;

/**
 * Re-asks allowed when the provider dropped a tool call it could not parse.
 *
 * The same count as {@link EMPTY_REPLY_RETRIES}, and at the SAME completion
 * budget every time. Only the escalation is removed, because only the
 * escalation is wrong — this is deliberately not a change to how many chances
 * a turn gets.
 *
 * On the N=3 dogfood sweep **all 20** contentless replies were a 200 with
 * `finish_reason: "function_call_filter: MALFORMED_FUNCTION_CALL"` and no
 * `content`. The model was never short of room: it tried to emit a tool call,
 * which this loop does not use (see the module comment) and which the
 * OpenAI-compat surface drops. Two measurements, one sweep each:
 *
 * | retry, at         | turns hit | recovered on the 1st re-ask |
 * | ----------------- | --------- | --------------------------- |
 * | doubled (8192→16k) | 14        | 9 (64%)                     |
 * | flat (8192→8192)   | 10        | 6 (60%)                     |
 *
 * **The budget is not the mechanism** — a flat re-ask recovers as often as a
 * doubled one, so the doubling only bought a larger prompt replay. What the
 * extra attempt buys is real, though: of the 5 turns that failed twice under
 * the old ladder, 4 recovered on the third attempt. A first cut of this fix
 * set the count to 1 and turned 1 stopped run into 4 — a cost with nothing
 * behind it, since the retry count was never the defect.
 */
export const MALFORMED_TOOL_CALL_RETRIES = EMPTY_REPLY_RETRIES;

/** Why a turn came back with nothing usable, when it did. */
type EmptyReplyCause = "emptyContent" | "malformedToolCall";

/**
 * Did this turn come back with nothing usable, and why?
 *
 * Read off `InferenceRequestError.code`, which `inference.ts` now sets from the
 * response body. This was a match on the error *message*, because a 200 with no
 * content carries no status or `errorType` a caller can branch on — and the
 * comment here asked for exactly this. The two causes need opposite responses
 * (see {@link MALFORMED_TOOL_CALL_RETRIES}), which a single string match could
 * not express.
 *
 * The message fallback stays for a provider adapter that is not
 * `InferenceRequestError` — the empty reply is still a real outcome there, and
 * losing it would turn a handled stop into a thrown crash. It classifies as
 * `emptyContent`, the conservative reading: budget escalation wastes tokens,
 * whereas not escalating a genuine truncation loses the run.
 */
function emptyReplyCause(err: unknown): EmptyReplyCause | undefined {
  if (err instanceof InferenceRequestError) {
    return err.code === "emptyContent" || err.code === "malformedToolCall"
      ? err.code
      : undefined;
  }
  return err instanceof Error &&
    err.message.includes("carried no assistant content")
    ? "emptyContent"
    : undefined;
}

/** Sandbox terminations that map onto a coverage `stoppedBecause`. */
const TERMINATION_TO_STOPPED: Record<string, QueryStoppedBecause | undefined> =
  {
    completed: undefined,
    error: undefined,
    wallClock: "wallClock",
    cpu: "cpu",
    memory: "memory",
    outputCap: "outputCap",
    policyDenied: "policyDenied",
    sandboxUnavailable: "sandboxUnavailable",
  };

function honestAnswerText(answer: string, coverage: QueryCoverage): string {
  // plan phase 5: `coverage.complete === false` must be surfaced in the answer
  // TEXT, not only in metadata. This is what makes an absence answer honest,
  // and it is the host's job because the model is not trusted to do it.
  if (coverage.complete) return answer;

  const reasons: string[] = [];
  if (coverage.stoppedBecause) {
    reasons.push(
      {
        budget: "the budget for this question ran out",
        wallClock: "the run hit its time limit",
        cpu: "the run hit its CPU limit",
        memory: "the run hit its memory limit",
        outputCap: "the script produced more output than the host allows",
        policyDenied: "the sandbox denied an operation the script needed",
        sandboxUnavailable: "no sandbox was available to run the script",
        contractViolation:
          "the model could not produce a valid script in the allowed attempts",
        malformedToolCall:
          "the model's replies kept arriving empty because the provider " +
          "discarded a tool call it could not parse",
        error: "the run ended with an error",
      }[coverage.stoppedBecause] ?? coverage.stoppedBecause,
    );
  }
  if (coverage.scopesSkipped.length > 0) {
    reasons.push(
      `these scopes were not read: ${coverage.scopesSkipped
        .map((s) => `${s.scope} (${s.reason})`)
        .join(", ")}`,
    );
  }
  if (typeof coverage.unreadable === "number" && coverage.unreadable > 0) {
    reasons.push(
      `${coverage.unreadable.toLocaleString("en-US")} record(s) could not be read`,
    );
  }
  if ((coverage.unprofiledScopes ?? []).length > 0) {
    reasons.push(
      `no source profile exists for ${coverage.unprofiledScopes!.join(", ")}, so their structure was inferred rather than known`,
    );
  }

  const detail =
    reasons.length > 0
      ? ` This answer is incomplete: ${reasons.join("; ")}.`
      : " This answer is incomplete.";

  const scanned =
    coverage.recordsScanned > 0
      ? ` ${coverage.recordsScanned.toLocaleString("en-US")} record(s) across ${coverage.scopesScanned.length} scope(s) were read.`
      : "";

  return `${answer}\n\n${detail.trim()}${scanned}`;
}

/**
 * One model turn, re-asked when the reply carries no content.
 *
 * Two ladders, because there are two causes and only one of them is a ceiling:
 *
 * - `emptyContent` — cause unstated, and a reasoning model that spent its whole
 *   allowance thinking is the likeliest one. The completion budget **doubles**
 *   on each attempt: another identical try would mostly reproduce the failure,
 *   so escalation is the point.
 * - `malformedToolCall` — the provider says it dropped an unparseable tool
 *   call. The budget is **left alone** and there is one retry only. Escalating
 *   here treats a provider-side parse failure as if it were a truncation; it
 *   burns a full prompt replay per doubling and, measured, never works.
 *
 * The two counters are independent, so a run that sees one of each still gets
 * the response each deserves. The last error is rethrown either way and the
 * caller re-reads its cause: the *reason* the run stopped has to reach
 * `coverage.stoppedBecause`, and a swallowed one is undiagnosable.
 */
async function chatWithEmptyReplyRetry(input: {
  provider: InferenceProvider;
  model: string;
  messages: InferenceMessage[];
  maxTokens: number;
  retries: number;
  malformedRetries: number;
  onRetry: (cause: EmptyReplyCause) => void;
}): Promise<Awaited<ReturnType<InferenceProvider["chat"]>>> {
  let lastError: unknown;
  let doublings = 0;
  let malformedRetries = 0;
  for (;;) {
    try {
      return await input.provider.chat({
        model: input.model,
        messages: input.messages,
        maxTokens: input.maxTokens * 2 ** doublings,
      });
    } catch (err) {
      const cause = emptyReplyCause(err);
      if (cause === undefined) throw err;
      lastError = err;
      if (cause === "emptyContent") {
        if (doublings >= input.retries) break;
        doublings += 1;
      } else {
        if (malformedRetries >= input.malformedRetries) break;
        // `doublings` deliberately untouched: the re-ask goes out at the same
        // budget it failed at, because the budget is not what failed.
        malformedRetries += 1;
      }
      input.onRetry(cause);
    }
  }
  throw lastError;
}

/**
 * Ask the model to conclude with whatever it already has.
 *
 * Strictly one attempt: it runs after the turn budget is spent, so it must not
 * become a way to keep going. A failure here is not an error — the caller
 * falls back to the plain budget-exhausted message.
 */
async function wrapUpTurn(input: {
  provider: InferenceProvider;
  model: string;
  messages: InferenceMessage[];
  maxTokens: number;
  reason: QueryStoppedBecause;
}): Promise<Awaited<ReturnType<InferenceProvider["chat"]>> | undefined> {
  const fitted = fitTranscript([
    ...input.messages,
    {
      role: "user",
      content:
        `You have run out of ${input.reason === "budget" ? "turns" : input.reason} for this question. ` +
        "Do not write any more scripts. Reply now with a ```vana:answer``` block " +
        "stating what you established, what you could not check, and why the " +
        "answer is partial. If you have a number you actually computed, include " +
        "it as `value`; if you never computed one, omit it rather than guessing.",
    },
  ]);
  try {
    return await input.provider.chat({
      model: input.model,
      messages: [...fitted.messages],
      maxTokens: input.maxTokens,
    });
  } catch {
    return undefined;
  }
}

/**
 * Run one question to an answer.
 *
 * Never throws for an ordinary bad outcome — a budget exhaustion, a sandbox
 * denial or a model that cannot follow the contract all end in a `QueryAnswer`
 * carrying honest coverage. Only a provider/transport failure propagates.
 */
export async function runQueryLoop(
  request: QueryRequest,
  options: QueryLoopOptions,
): Promise<QueryAnswer> {
  const {
    provider,
    tools,
    model = provider.defaultModel,
    maxTurns = DEFAULT_MAX_TURNS,
    maxTokens = DEFAULT_MAX_TOKENS,
    emptyReplyRetries = EMPTY_REPLY_RETRIES,
    outputTailBytes = DEFAULT_OUTPUT_TAIL_BYTES,
    now = Date.now,
  } = options;

  const startedAt = now();
  // `budget.toolCalls` bounds MODEL TURNS, not script executions. The two were
  // conflated: a question that spent two turns on repair retries had two fewer
  // left for real work, and `cost.toolCalls` reported turns that never called
  // a tool. Both are now counted separately and both are reported.
  const turnBudget = Math.max(1, request.budget?.toolCalls ?? maxTurns);
  const wallClockMs = request.budget?.wallClockMs;

  const scopes = await tools.listScopes();
  const system = buildSystemPrompt(
    options.profileBudgetChars === undefined
      ? { scopes }
      : { scopes, profileBudgetChars: options.profileBudgetChars },
  );

  const messages: InferenceMessage[] = [
    { role: "system", content: system.prompt },
    { role: "user", content: request.question },
  ];

  let turns = 0;
  let scriptRuns = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let lastScript: string | undefined;
  let repairsUsed = 0;
  let emptyReplies = 0;
  /**
   * How many of those empty replies were a discarded tool call.
   *
   * Counted apart from `emptyReplies` because the two have different fixes and
   * the sweep that produced this distinction could only be read because the
   * harness recorded reply SHAPES to a side file. This puts the same split in
   * the loop's own accounting, where a caller with no diagnostic file can see
   * it in the answer text.
   */
  let malformedToolCalls = 0;
  let stoppedBecause: QueryStoppedBecause | undefined;
  const receiptIds: string[] = [];
  const violations: string[] = [];

  let finalAnswer: string | undefined;
  let finalCitations: QueryCitation[] = [];
  let resultValue: number | undefined;
  let resultResolution: string | undefined;
  /**
   * Why the LAST script run ended, when it ended abnormally.
   *
   * Kept separate from `stoppedBecause` because they answer different
   * questions. `stoppedBecause` is "why did the run stop"; this is "did a
   * script along the way misbehave". Conflating them made a run that errored
   * on turn 3 and answered on turn 5 report `error` forever — it fired on
   * 24/54 benchmark runs *including passing ones*, so it read as "something
   * went wrong at some point" rather than a termination reason.
   */
  let lastRunTermination: QueryStoppedBecause | undefined;
  /** True once the model has actually committed to an answer. */
  let endedCleanly = false;

  while (turns < turnBudget) {
    if (wallClockMs !== undefined && now() - startedAt > wallClockMs) {
      stoppedBecause = "wallClock";
      break;
    }

    const fitted = fitTranscript(messages);
    turns += 1;

    // Snapshot: `messages` keeps growing, and a provider that retains what it
    // was handed must not observe turns that had not happened when it was
    // called. (`fitTranscript` returns the same array when nothing is dropped.)
    //
    // An empty reply is retried rather than thrown, and HOW it is retried
    // depends on why it was empty — see `chatWithEmptyReplyRetry`.
    let reply;
    try {
      reply = await chatWithEmptyReplyRetry({
        provider,
        model,
        messages: [...fitted.messages],
        maxTokens,
        retries: emptyReplyRetries,
        malformedRetries: MALFORMED_TOOL_CALL_RETRIES,
        onRetry: (cause) => {
          emptyReplies += 1;
          if (cause === "malformedToolCall") malformedToolCalls += 1;
        },
      });
    } catch (err) {
      const cause = emptyReplyCause(err);
      if (cause === undefined) throw err;
      // Out of retries. End with honest coverage instead of throwing out of
      // the answerer: a question that produced nothing is a result, not a
      // crash, and the caller still needs the coverage counters.
      emptyReplies += 1;
      if (cause === "malformedToolCall") {
        malformedToolCalls += 1;
        // A distinct `stoppedBecause` rather than the catch-all `error`,
        // because this one names a specific, actionable provider behaviour and
        // the last sweep could not be diagnosed from the dump precisely
        // because four situations shared one reason.
        stoppedBecause = "malformedToolCall";
        finalAnswer =
          `The provider returned ${emptyReplies} repl(ies) with no content, ` +
          `${malformedToolCalls} of them reporting that it discarded a tool call it ` +
          `could not parse. The completion budget was deliberately left at ` +
          `${maxTokens} tokens: this is not a truncation and a larger budget ` +
          `does not fix it. No answer was produced for this question.`;
      } else {
        stoppedBecause = "error";
        finalAnswer =
          `The model returned no content ${emptyReplies} time(s) in a row, ` +
          `even after raising the completion budget to ${maxTokens * 2 ** emptyReplyRetries} tokens. ` +
          `No answer was produced for this question.`;
      }
      break;
    }
    inputTokens += reply.usage?.promptTokens ?? 0;
    outputTokens += reply.usage?.completionTokens ?? 0;
    if (reply.receiptId) receiptIds.push(reply.receiptId);
    messages.push({ role: "assistant", content: reply.content });

    const parsed = parseTurn(reply.content);

    if (parsed.kind === "violation") {
      // Prompt doc §2: repair once. A second failure ends the run.
      if (repairsUsed >= 1) {
        stoppedBecause = "contractViolation";
        finalAnswer =
          "I could not produce a valid script. The model did not follow the response contract after a repair attempt, so no data was read and no answer was computed.";
        break;
      }
      repairsUsed += 1;
      messages.push({
        role: "user",
        content: repairMessage(parsed as ParseFailure),
      });
      continue;
    }

    if (parsed.kind === "answer") {
      finalAnswer = parsed.answer;
      finalCitations = parsed.citations;
      // An explicit value beats prose extraction, and beats a value left over
      // from an earlier run in the same request: this is the model's final say.
      if (parsed.value !== undefined) resultValue = parsed.value;
      if (parsed.resolution !== undefined) resultResolution = parsed.resolution;
      // The run ended because the model answered. An abnormal termination from
      // an earlier script is not the reason this run stopped; it stays in
      // `violations` so the diagnosis survives.
      stoppedBecause = undefined;
      endedCleanly = true;
      break;
    }

    // A run block. `execute` runs it as DATA inside the confined interpreter,
    // which itself runs inside the OS sandbox. The loop never holds a sandbox
    // and never sees a runnable script, so it cannot execute model code bare.
    lastScript = parsed.script;
    scriptRuns += 1;
    const result = await tools.execute(parsed.script);
    violations.push(...result.violations);

    const mapped = TERMINATION_TO_STOPPED[result.termination];
    if (mapped) {
      lastRunTermination = mapped;
      violations.push(`script run ${scriptRuns} ended: ${result.termination}`);
    }

    if (result.result?.value !== undefined) resultValue = result.result.value;
    if (result.result?.resolution !== undefined) {
      resultResolution = result.result.resolution;
    }
    if (result.result?.answer) {
      // `vana.result(...)` terminates the script and the run.
      finalAnswer = result.result.answer;
      finalCitations = result.result.citations ?? [];
      stoppedBecause = undefined;
      endedCleanly = true;
      break;
    }

    if (result.termination === "sandboxUnavailable") break;

    const rendered = renderRunResult({
      stdout: result.stdout,
      stderr: result.stderr,
      notes: result.notes,
      termination: result.termination,
      truncatedByHost: result.truncated,
      maxBytes: outputTailBytes,
      // A confinement denial is actionable feedback: the interpreter supports
      // a deliberate subset of JS, and the model can only correct a rejected
      // `class` or generator if it is told which construct was refused.
      ...(result.error ? { error: result.error } : {}),
    });
    messages.push({ role: "user", content: rendered.content });
  }

  if (finalAnswer === undefined) {
    stoppedBecause ??=
      lastRunTermination ?? tools.coverage()?.stoppedBecause ?? "budget";
    // One wrap-up turn, outside the budget by exactly one and never retried.
    //
    // Hitting the ceiling used to discard everything the run had learned and
    // return a bare "I ran out of budget", which is the least useful honest
    // answer available: the model has usually read most of what it needed and
    // simply not been asked to conclude. Asking it to state what it has
    // converts a dead run into a partial answer, and coverage still reports
    // `stoppedBecause`, so nothing here can make a partial run look complete.
    const wrapUp = await wrapUpTurn({
      provider,
      model,
      messages,
      maxTokens,
      reason: stoppedBecause,
    });
    if (wrapUp) {
      turns += 1;
      inputTokens += wrapUp.usage?.promptTokens ?? 0;
      outputTokens += wrapUp.usage?.completionTokens ?? 0;
      if (wrapUp.receiptId) receiptIds.push(wrapUp.receiptId);
      const parsed = parseTurn(wrapUp.content);
      if (parsed.kind === "answer") {
        finalAnswer = parsed.answer;
        finalCitations = parsed.citations;
        if (parsed.value !== undefined) resultValue = parsed.value;
        if (parsed.resolution !== undefined) {
          resultResolution = parsed.resolution;
        }
      }
    }
    finalAnswer ??=
      "I ran out of the budget for this question before reaching an answer.";
  }

  // Coverage is the tool layer's, not the model's, not this loop's.
  // Accumulated across every run in this request, not just the last one.
  const hostCoverage = tools.coverage() ?? EMPTY_COVERAGE;
  const coverage: QueryCoverage = {
    ...hostCoverage,
    complete: hostCoverage.complete && stoppedBecause === undefined,
  };
  if (stoppedBecause) {
    coverage.stoppedBecause = stoppedBecause;
  } else if (endedCleanly) {
    // The host merge carries the first abnormal termination it saw across the
    // whole request and never lets a later success supersede it, so a run that
    // recovered still reported `error`. Only the control-flow field is
    // cleared; every counter stays exactly as the host authored it.
    delete coverage.stoppedBecause;
  }
  if (system.unprofiledScopes.length > 0) {
    coverage.unprofiledScopes = system.unprofiledScopes;
  }
  if (system.summarizedScopes.length > 0) {
    coverage.profilesSummarized = system.summarizedScopes;
  }
  if (violations.length > 0) coverage.violations = violations;

  const answer: QueryAnswer = {
    answer: honestAnswerText(finalAnswer, coverage),
    citations: finalCitations,
    coverage,
    determinism: "generated",
    cost: {
      toolCalls: scriptRuns,
      modelTurns: turns,
      inputTokens,
      outputTokens,
    },
  };
  if (lastScript !== undefined) answer.script = lastScript;
  if (receiptIds.length > 0) answer.receiptIds = receiptIds;
  if (typeof resultValue === "number") answer.value = resultValue;
  if (resultResolution !== undefined) answer.resolution = resultResolution;
  return answer;
}
