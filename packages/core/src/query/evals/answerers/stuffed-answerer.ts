/**
 * The naive control arm: stuff the corpus into one prompt and ask once.
 *
 * Implementation plan §7 names this comparison as owed. PR #231's number —
 * 8% -> 80% retrieval accuracy — was measured against **newest-first
 * truncation**, and every figure this project has produced since is unanchored
 * because that control was never built. The eval has a reference answerer
 * (hand-written correct code) and a null answerer (returns nothing); "6 of 18
 * questions pass" cannot be read as good or bad until a plain LLM call has been
 * asked the same questions on the same corpus under the same grader.
 *
 * So this is deliberately the obvious thing, and deliberately NOT a strawman:
 *
 * - **A generous budget.** {@link DEFAULT_CORPUS_BUDGET_CHARS} is sized from a
 *   measurement of the target model, not from a guess — see the constant.
 * - **Newest-first truncation**, per §7. That is the documented heuristic this
 *   is meant to compare against, and it is applied globally across the granted
 *   scopes rather than per scope, because that is what the phrase means.
 * - **The same grant.** Only the scopes the case grants are read, exactly as
 *   `buildAgentAnswerer` does. Same question, same information.
 * - **The same T2 profiles**, rendered by the same `renderProfiles` the agent's
 *   system prompt uses. Stripping the profiles would confound two variables:
 *   the point is to isolate the code loop, not to also remove the prose the
 *   design calls its highest-leverage artifact (§18.2).
 * - **The same response contract** — `parseTurn` from `agent/contract.ts`, the
 *   same parser, the same one repair retry, the same empty-reply retry policy.
 *   A baseline that failed for not populating `value` would be measuring the
 *   contract, not the capability.
 *
 * **What it cannot do, and does not pretend to.** Coverage is host-authored
 * here exactly as it is in the agent arm (prompt doc §1) — this module counts
 * what it actually put in the prompt and reports that. When truncation drops
 * anything, `complete` is false and the dropped scopes are named. Nothing is
 * rounded up to satisfy the grader. An absence question asked over a truncated
 * slice SHOULD fail, and that failure is the measurement.
 *
 * The ledger the model is shown is deliberately about **transport, not
 * content**: how many records it was handed and how many were withheld, which
 * it has no other way to know. It is not told anything the agent's model would
 * have had to compute — no unreadable counts, no totals, no aggregates. Handing
 * it those would flatter the baseline on precisely the question (Q8) that the
 * host-authored-coverage invariant exists for.
 */

import { parseTurn, repairMessage } from "../../agent/contract.js";
import type {
  QueryAnswer,
  QueryCitation,
  QueryCoverage,
  QueryRequest,
} from "../../agent/types.js";
import type {
  InferenceMessage,
  InferenceProvider,
} from "../../../derivatives/inference.js";
import { renderProfiles } from "../../profiles/index.js";
import { isUnreadableRecord } from "../../tools/api.js";
import type { CorpusManifest } from "../fixtures/generate.js";
import type { FixtureSource } from "../fixtures/sink.js";
import type { EvalAnswerer } from "../types.js";

/**
 * Characters of corpus JSON allowed into one prompt.
 *
 * MEASURED against `gemini-3.7-flash` on this corpus, 2026-08-29, rather than
 * assumed:
 *
 *   chars=2,000       -> 677 prompt tokens      (2.95 chars/token)
 *   chars=500,000     -> 166,955 prompt tokens  (2.99)
 *   chars=2,000,000   -> 681,131 prompt tokens  (2.94), 40.7s
 *   chars=4,000,000   -> HTTP 400 INVALID_ARGUMENT,
 *                        "input token count exceeds the maximum ... 1048576"
 *
 * So the hard ceiling is 1,048,576 input tokens and this corpus's JSON runs at
 * ~2.95 chars/token. 2.6M chars is ~881k tokens, which leaves ~167k tokens of
 * headroom for the system prompt, the rendered profiles (up to ~54k chars on a
 * total grant, ~18k tokens), the question and the completion budget. That is
 * as much of the window as can be used without the 400 becoming a coin flip on
 * a long tail record.
 *
 * On the `dogfood` corpus this is genuinely generous: 10 of the 18 graded
 * questions have their ENTIRE grant fit inside it with room to spare.
 */
export const DEFAULT_CORPUS_BUDGET_CHARS = 2_600_000;

/** Mirrors `agent/loop.ts` — a thinking model spends reasoning from this. */
const DEFAULT_MAX_TOKENS = 8192;
/** Mirrors `agent/loop.ts`'s `EMPTY_REPLY_RETRIES`. */
const DEFAULT_EMPTY_REPLY_RETRIES = 2;

export interface StuffedAnswererOptions {
  /** The serialized corpus, read through the same source the reference uses. */
  source: FixtureSource;
  /** Scope -> files mapping. Scope ids come from here, never from filenames. */
  manifest: CorpusManifest;
  provider: InferenceProvider;
  model?: string;
  corpusBudgetChars?: number;
  maxTokens?: number;
  emptyReplyRetries?: number;
  profileBudgetChars?: number;
  name?: string;
}

/* ------------------------------------------------------------------ */
/* Newest-first ordering                                               */
/* ------------------------------------------------------------------ */

/**
 * Fields that carry a record's time, in priority order.
 *
 * Generic on purpose: a per-scope table of "the right field" would be this
 * module knowing the corpus, which is not what a newest-first truncation
 * heuristic gets to know. Every one of these appears in at least one shipped
 * source's real export shape.
 */
const TIME_KEYS = [
  "ts",
  "timestamp",
  "date",
  "day",
  "created",
  "create_time",
  "start",
  "start_datetime",
  "visit_time",
  "authored_at",
  "endTime",
  "bedtime_start",
  "update_time",
  "end",
] as const;

/**
 * Milliseconds for one record, or `undefined` when it carries no usable time.
 *
 * Handles the three encodings this corpus actually uses: ISO 8601 strings,
 * `YYYY-MM-DD` days, and epoch seconds as either a number (`create_time`) or a
 * numeric string (Slack's `ts`). A bare number is read as seconds unless it is
 * large enough to only make sense as milliseconds.
 */
export function recordTimeMs(record: unknown): number | undefined {
  if (typeof record !== "object" || record === null) return undefined;
  const row = record as Record<string, unknown>;
  for (const key of TIME_KEYS) {
    const raw = row[key];
    if (typeof raw === "number" && Number.isFinite(raw)) {
      return raw > 1e12 ? raw : raw * 1000;
    }
    if (typeof raw === "string" && raw.trim() !== "") {
      const trimmed = raw.trim();
      if (/^\d+(\.\d+)?$/.test(trimmed)) {
        const n = Number(trimmed);
        return n > 1e12 ? n : n * 1000;
      }
      const parsed = Date.parse(trimmed);
      if (!Number.isNaN(parsed)) return parsed;
    }
  }
  return undefined;
}

interface Candidate {
  scope: string;
  timeMs: number;
  text: string;
  unreadable: boolean;
}

/* ------------------------------------------------------------------ */
/* The prompt                                                          */
/* ------------------------------------------------------------------ */

/**
 * The system prompt.
 *
 * Written once, as the obvious translation of the shipped agent prompt
 * (`agent/prompt.ts`, `vana-query-prompt/3`) into a world with no script API:
 * the same response contract, the same ten rules minus the two that are purely
 * about the script API, the same `{{SCOPES}}` and `{{PROFILES}}` slots. It has
 * not been tuned against any result — see the module header.
 */
export const STUFFED_SYSTEM_PROMPT_TEMPLATE = `You answer questions about one person's own data, running inside their Personal
Server. Their data is included directly in the message below. You read it and
answer from it. You cannot run code and you cannot fetch anything else — what
you have been given is all you will get.

**How to respond.** End your reply with exactly one fenced block:

\`\`\`vana:answer
{"answer": "...", "citations": [{"scope": "..."}], "confidence": "high",
 "value": 1.23, "resolution": "which set you aggregated over"}
\`\`\`

Anything outside the block is ignored.

**\`value\` is required whenever the question has a single numeric answer** —
an average, a count, a sum, a percentage. Put the bare number there: \`6.52\`,
not \`"6.52 hours"\`, \`"6.5"\` or \`"6,520"\`. It is the same figure your prose
states, in machine-readable form, and it is what the number is read from.
Omit it only when the answer genuinely is not one number.

**Rules that matter more than being helpful:**

1. **Be exact.** Averages, counts, sums and joins must be worked out over the
   actual records below, one by one. Never eyeball a number from the shape of
   the data, and never round a figure you worked out into a vaguer one.
2. **Read the profile first.** Each scope below has a source profile
   describing its shape and its non-obvious rules. These rules are not
   suggestions — they encode how the data is actually structured, and ignoring
   them produces answers that are wrong in ways nobody can see. If a scope has
   no profile, say so in your answer and treat your result as lower confidence.
3. **State your definitions and denominators.** "6.5 hours over 28 of 31 nights,
   main sleep only, naps excluded" — not "about 6.5 hours".
4. **A question about whether something exists requires reading everything.**
   Never answer "no" or "never" from the records that happen to be nearest to
   hand. Read the whole of every scope you were given. If the data below is a
   truncated slice of a scope, you have not read everything and you must say
   what you did and did not see.
5. **Resolve the set before you aggregate it, and put that resolution in the
   \`resolution\` field.** Most questions name a set the data does not define —
   "last month", "my Japan trip", "days I run more than 10km", "people I talked
   to". Decide exactly which rows qualify, say so in \`resolution\` in one
   sentence (the window with real dates, the inclusion rule, what you excluded
   and why), then compute over that set. **A right number over the wrong set is
   a wrong answer**, and it is the most common way to be confidently wrong here.
   When a phrase has more than one defensible reading, compute the most
   literal one, and name the alternative and its number in your answer — do
   not silently choose one and drop the other.
6. **People appear under many names.** The same person may be an email address, a
   handle, and a display name. Reconcile them before counting.
7. **Distinguish what was measured from what was said.** If the data contains
   both a stated claim and behaviour that contradicts it, report both and the
   conflict.
8. **Cite.** Every claim traces to a scope, and where possible a record.
9. **Say what you do not know.** Missing days, unreadable files, scopes you
   lack access to, records that were withheld from you — surface them. An
   honest partial answer is correct; a confident complete-sounding one is a
   defect.

**Available scopes:** {{SCOPES}}

**Source profiles:** {{PROFILES}}`;

function renderScopeLine(scope: string, total: number): string {
  return `- \`${scope}\` (${total.toLocaleString("en-US")} items)`;
}

/* ------------------------------------------------------------------ */
/* The answerer                                                        */
/* ------------------------------------------------------------------ */

export function createStuffedAnswerer(
  options: StuffedAnswererOptions,
): EvalAnswerer {
  const budget = options.corpusBudgetChars ?? DEFAULT_CORPUS_BUDGET_CHARS;
  const maxTokens = options.maxTokens ?? DEFAULT_MAX_TOKENS;
  const emptyReplyRetries =
    options.emptyReplyRetries ?? DEFAULT_EMPTY_REPLY_RETRIES;
  const name = options.name ?? "stuffed";

  /** Parsed corpus, per scope. Read once; a request never mutates it. */
  const cache = new Map<string, unknown[]>();

  const loadScope = async (scope: string): Promise<unknown[]> => {
    const hit = cache.get(scope);
    if (hit) return hit;
    const entry = options.manifest.scopes.find((s) => s.scope === scope);
    const rows: unknown[] = [];
    for (const file of entry?.files ?? []) {
      const parsed: unknown = JSON.parse(await options.source.read(file));
      if (Array.isArray(parsed)) rows.push(...parsed);
      else rows.push(parsed);
    }
    cache.set(scope, rows);
    return rows;
  };

  const answer = async (request: QueryRequest): Promise<QueryAnswer> => {
    const granted = [...request.grantedScopes];

    /* ---- select, newest-first across the whole grant ---- */

    const totals = new Map<string, number>();
    const candidates: Candidate[] = [];
    for (const scope of granted) {
      const rows = await loadScope(scope);
      totals.set(scope, rows.length);
      for (const row of rows) {
        const timeMs = recordTimeMs(row);
        candidates.push({
          scope,
          // An undated record sorts oldest: newest-first cannot promote a row
          // whose age is unknown, and dropping it outright would be a silent
          // second truncation rule.
          timeMs: timeMs ?? Number.NEGATIVE_INFINITY,
          text: JSON.stringify(row),
          unreadable: isUnreadableRecord(row),
        });
      }
    }
    candidates.sort((a, b) => b.timeMs - a.timeMs);

    /**
     * Take the newest records that fit `budgetChars`.
     *
     * `continue` rather than `break`: a single huge record near the front must
     * not end the selection, since a smaller older one still fits. That is
     * still newest-first — it is newest-first *that fits*.
     */
    const select = (budgetChars: number) => {
      const includedByScope = new Map<string, Candidate[]>();
      let usedChars = 0;
      let included = 0;
      let unreadable = 0;
      for (const candidate of candidates) {
        // +1 for the newline each record is rendered on.
        if (usedChars + candidate.text.length + 1 > budgetChars) continue;
        usedChars += candidate.text.length + 1;
        included += 1;
        if (candidate.unreadable) unreadable += 1;
        const bucket = includedByScope.get(candidate.scope);
        if (bucket) bucket.push(candidate);
        else includedByScope.set(candidate.scope, [candidate]);
      }
      return {
        includedByScope,
        usedChars,
        included,
        unreadable,
        omitted: candidates.length - included,
      };
    };

    /* ---- the prompt ---- */

    const rendered = renderProfiles(
      granted,
      options.profileBudgetChars === undefined
        ? {}
        : { budgetChars: options.profileBudgetChars },
    );
    const scopeText =
      granted.length === 0
        ? "(none — you hold no granted scopes and cannot read any data)"
        : "\n" +
          granted.map((s) => renderScopeLine(s, totals.get(s) ?? 0)).join("\n");
    const profileText =
      rendered.text.trim() === ""
        ? "(none — no source profile exists for these scopes; treat your results as lower confidence and say so)"
        : "\n\n" + rendered.text;
    const system = STUFFED_SYSTEM_PROMPT_TEMPLATE.replace(
      "{{SCOPES}}",
      scopeText,
    ).replace("{{PROFILES}}", profileText);

    const renderUser = (selection: ReturnType<typeof select>): string => {
      const { includedByScope, included, omitted } = selection;
      const parts: string[] = [];
      parts.push(
        omitted === 0
          ? `Below is ALL of your data for the scopes you were granted: ${included.toLocaleString("en-US")} records across ${includedByScope.size} scope(s). Nothing was withheld.`
          : `Below is your data for the scopes you were granted. It did not all fit, so the ${included.toLocaleString("en-US")} MOST RECENT records were included and the ${omitted.toLocaleString("en-US")} older records were left out. You are seeing a truncated slice, not the whole of these scopes.`,
      );
      parts.push("");
      for (const scope of granted) {
        const bucket = includedByScope.get(scope) ?? [];
        const total = totals.get(scope) ?? 0;
        const dropped = total - bucket.length;
        parts.push(
          `## \`${scope}\` — ${bucket.length.toLocaleString("en-US")} of ${total.toLocaleString("en-US")} records included` +
            (dropped > 0
              ? `, ${dropped.toLocaleString("en-US")} older records omitted`
              : " (complete)"),
        );
        parts.push("");
        // Newest first inside the scope too, consistent with how they were
        // chosen. One JSON record per line, verbatim from the export.
        for (const candidate of bucket) parts.push(candidate.text);
        parts.push("");
      }
      parts.push("---", "", `Question: ${request.question}`);
      return parts.join("\n");
    };

    /* ---- one call, the same retry and repair policy as the loop ---- */

    const messages: InferenceMessage[] = [];

    let inputTokens = 0;
    let outputTokens = 0;
    let modelTurns = 0;
    const receiptIds: string[] = [];

    const ask = async (): Promise<string> => {
      let lastError: unknown;
      for (let attempt = 0; attempt <= emptyReplyRetries; attempt++) {
        try {
          const reply = await options.provider.chat({
            model: options.model ?? options.provider.defaultModel,
            messages,
            maxTokens: maxTokens * 2 ** attempt,
          });
          modelTurns += 1;
          inputTokens += reply.usage?.promptTokens ?? 0;
          outputTokens += reply.usage?.completionTokens ?? 0;
          if (reply.receiptId) receiptIds.push(reply.receiptId);
          return reply.content;
        } catch (err) {
          // Same discriminator `agent/loop.ts` uses, and the same reason: the
          // provider throws a 200 with no error type, so the message is the
          // only signal that separates "the model returned nothing" from a
          // real transport failure.
          if (!(
            err instanceof Error &&
            err.message.includes("carried no assistant content")
          )) {
            throw err;
          }
          lastError = err;
          modelTurns += 1;
        }
      }
      throw lastError;
    };

    /*
     * Fill the window, and back off if the provider says it is too full.
     *
     * A character budget cannot be converted to tokens without the model's
     * tokenizer, and the ratio is NOT constant across this corpus: measured on
     * `gemini-3.7-flash`, prose-heavy JSON (chatgpt, slack) runs at ~2.95
     * chars/token while numeric-dense JSON (`oura.sleep`) runs at ~1.83. A
     * single conservative constant would either overflow the window on the
     * numeric scopes or waste ~40% of it on the prose ones — and wasting it
     * would weaken exactly the arm this exists to steelman.
     *
     * So the budget is optimistic and the over-limit rejection is handled. The
     * rejection is cheap (measured: a 4M-char request is refused in 2.4s,
     * before any inference happens) and it is unambiguous in practice on this
     * endpoint — the only 400 a well-formed request draws here is the token
     * ceiling. Each retry keeps 60% of the previous budget.
     */
    const SHRINK = 0.6;
    const MAX_SHRINKS = 4;

    let selection = select(budget);
    let shrinks = 0;

    const coverage = (complete: boolean): QueryCoverage => ({
      scopesScanned: [...selection.includedByScope.keys()],
      recordsScanned: selection.included,
      bytesScanned: selection.usedChars,
      scopesSkipped: granted
        .filter((s) => !selection.includedByScope.has(s))
        .map((scope) => ({
          scope,
          reason: "no records fit the newest-first context budget",
        })),
      complete,
      unreadable: selection.unreadable,
      method: selection.omitted === 0 ? "full" : "prefiltered",
      ...(rendered.unprofiledScopes.length > 0
        ? { unprofiledScopes: rendered.unprofiledScopes }
        : {}),
      ...(rendered.summarized.length > 0
        ? { profilesSummarized: rendered.summarized }
        : {}),
    });

    const cost = () => ({
      // No script ever ran. This is the whole point of the arm.
      toolCalls: 0,
      modelTurns,
      inputTokens,
      outputTokens,
    });

    const failed = (text: string, reason: QueryCoverage["stoppedBecause"]) => ({
      answer: text,
      citations: [] as QueryCitation[],
      coverage: { ...coverage(false), stoppedBecause: reason },
      determinism: "generated" as const,
      cost: cost(),
      ...(receiptIds.length > 0 ? { receiptIds } : {}),
    });

    let text: string | undefined;
    let lastFailure: unknown;
    for (let attempt = 0; attempt <= MAX_SHRINKS; attempt++) {
      messages.length = 0;
      messages.push({ role: "system", content: system });
      messages.push({ role: "user", content: renderUser(selection) });
      try {
        text = await ask();
        break;
      } catch (err) {
        lastFailure = err;
        const overLimit =
          typeof (err as { status?: unknown }).status === "number" &&
          (err as { status: number }).status === 400;
        if (!overLimit || attempt === MAX_SHRINKS) break;
        shrinks += 1;
        selection = select(Math.floor(budget * SHRINK ** shrinks));
      }
    }
    if (text === undefined) {
      return failed(
        `The model produced no usable reply after ${shrinks} context reduction(s) (${(lastFailure as Error).message}). No answer was computed.`,
        "error",
      );
    }

    let parsed = parseTurn(text);
    if (parsed.kind === "violation") {
      // Prompt doc §2: repair once, exactly as the loop does. A second failure
      // ends the run.
      messages.push({ role: "assistant", content: text });
      messages.push({ role: "user", content: repairMessage(parsed) });
      try {
        text = await ask();
      } catch (err) {
        return failed(
          `The model produced no usable reply after a repair attempt (${(err as Error).message}).`,
          "error",
        );
      }
      parsed = parseTurn(text);
    }

    if (parsed.kind !== "answer") {
      return failed(
        "I could not produce a valid answer. The model did not follow the response contract after a repair attempt.",
        "contractViolation",
      );
    }

    return {
      answer: parsed.answer,
      citations: parsed.citations,
      // `complete` is derived from what was actually put in the prompt, never
      // from anything the model said. Truncation makes it false, and no answer
      // can talk its way out of that.
      coverage: coverage(selection.omitted === 0 && granted.length > 0),
      determinism: "generated",
      cost: cost(),
      ...(parsed.value !== undefined ? { value: parsed.value } : {}),
      ...(parsed.resolution !== undefined
        ? { resolution: parsed.resolution }
        : {}),
      ...(receiptIds.length > 0 ? { receiptIds } : {}),
    };
  };

  return { name, answer };
}
