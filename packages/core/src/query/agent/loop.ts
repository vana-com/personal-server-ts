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

import type {
  InferenceMessage,
  InferenceProvider,
} from "../../derivatives/inference.js";
import type { Sandbox } from "../ports.js";
import { buildSystemPrompt } from "./prompt.js";
import { parseTurn, repairMessage, type ParseFailure } from "./contract.js";
import type { QueryToolHost } from "./tool-host.js";
import {
  DEFAULT_OUTPUT_TAIL_BYTES,
  fitTranscript,
  renderRunResult,
} from "./transcript.js";
import type {
  QueryAnswer,
  QueryCitation,
  QueryCoverage,
  QueryRequest,
  QueryStoppedBecause,
} from "./types.js";

export interface QueryLoopOptions {
  provider: InferenceProvider;
  sandbox: Sandbox;
  tools: QueryToolHost;
  model?: string;
  /** Hard ceiling on model turns. Also the only bound on relay call volume. */
  maxTurns?: number;
  /** Per-turn cap on script output fed back to the model. */
  outputTailBytes?: number;
  profileBudgetChars?: number;
  /** Injected for tests; defaults to `Date.now`. */
  now?: () => number;
}

export const DEFAULT_MAX_TURNS = 12;

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
    sandbox,
    tools,
    model = provider.defaultModel,
    maxTurns = DEFAULT_MAX_TURNS,
    outputTailBytes = DEFAULT_OUTPUT_TAIL_BYTES,
    now = Date.now,
  } = options;

  const startedAt = now();
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
  let inputTokens = 0;
  let outputTokens = 0;
  let lastScript: string | undefined;
  let repairsUsed = 0;
  let stoppedBecause: QueryStoppedBecause | undefined;
  const receiptIds: string[] = [];
  const violations: string[] = [];

  let finalAnswer: string | undefined;
  let finalCitations: QueryCitation[] = [];
  let resultValue: number | undefined;

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
    const reply = await provider.chat({
      model,
      messages: [...fitted.messages],
    });
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
      break;
    }

    // A run block: prepare it (4b puts `vana` in scope), execute, feed back.
    const prepared = await tools.prepare(parsed.script);
    lastScript = parsed.script;
    const result = await sandbox.run(prepared.script, prepared.spec);
    violations.push(...result.violations);

    const mapped = TERMINATION_TO_STOPPED[result.termination];
    if (mapped) stoppedBecause = mapped;

    // `takeResult` drains, so call it exactly once per run and keep the value.
    const scriptResult = tools.takeResult();
    if (scriptResult?.value !== undefined) resultValue = scriptResult.value;
    if (scriptResult?.answer) {
      // `vana.result(...)` terminates the script and the run.
      finalAnswer = scriptResult.answer;
      finalCitations = scriptResult.citations ?? [];
      break;
    }

    if (result.termination === "sandboxUnavailable") break;

    const rendered = renderRunResult({
      stdout: result.stdout,
      stderr: result.stderr,
      notes: tools.takeNotes(),
      termination: result.termination,
      truncatedByHost: result.truncated,
      maxBytes: outputTailBytes,
    });
    messages.push({ role: "user", content: rendered.content });
  }

  if (finalAnswer === undefined) {
    stoppedBecause ??= "budget";
    finalAnswer =
      "I ran out of the budget for this question before reaching an answer.";
  }

  // Coverage is the tool layer's, not the model's, not this loop's.
  const hostCoverage = tools.coverage();
  const coverage: QueryCoverage = {
    ...hostCoverage,
    complete: hostCoverage.complete && stoppedBecause === undefined,
  };
  if (stoppedBecause) coverage.stoppedBecause = stoppedBecause;
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
    cost: { toolCalls: turns, inputTokens, outputTokens },
  };
  if (lastScript !== undefined) answer.script = lastScript;
  if (receiptIds.length > 0) answer.receiptIds = receiptIds;
  if (typeof resultValue === "number") answer.value = resultValue;
  return answer;
}
