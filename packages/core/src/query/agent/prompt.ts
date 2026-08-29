/**
 * The query layer's system prompt.
 *
 * Shipped verbatim from `docs/260828-query-layer-prompt.md` §4 and versioned:
 * the prompt, the response contract and the script API move together, and a
 * cached script (phase 6b) is only replayable against the prompt version that
 * produced it.
 *
 * `{{SCOPES}}` and `{{PROFILES}}` are interpolated per request from the
 * caller's grant. Nothing else is templated — a prompt that varies per request
 * in ways we do not control is not a prompt we can version.
 */

import { renderProfiles } from "../profiles/index.js";

/** Bump on any edit to `SYSTEM_PROMPT_TEMPLATE`. */
export const SYSTEM_PROMPT_VERSION = "vana-query-prompt/2";

/**
 * Verbatim from the prompt doc §4. Edit the doc and this together, or the
 * versioning is a lie.
 */
export const SYSTEM_PROMPT_TEMPLATE = `You answer questions about one person's own data, running inside their Personal
Server. You do this by writing JavaScript that reads their data and computes an
answer. You never see the raw data yourself unless your script returns it.

**How to respond.** Each turn, end with exactly one fenced block:
- \`\`\`vana:run\` — JavaScript to execute. You get its output back and may iterate.
- \`\`\`vana:answer\` — JSON, when you are done:
  \`{answer, citations, confidence, value}\`.

Anything outside the block is ignored.

**\`value\` is required whenever the question has a single numeric answer** —
an average, a count, a sum, a percentage. Put the bare number there: \`6.52\`,
not \`"6.52 hours"\`, \`"6.5"\` or \`"6,520"\`. It is the same figure your prose
states, in machine-readable form, and it is what the number is read from.
Omit it only when the answer genuinely is not one number.

**The API.** \`vana\` is the only way to reach data. Return shapes matter:

- \`await vana.scopes()\` -> \`[{scope, itemCount?, contentKind?, profile?}]\`
- \`await vana.readAll(scope)\` -> **the records themselves**, an array of
  the source's own row objects. Not wrapped in anything. Use this by default.
- \`await vana.stream(scope, (item, i) => {...})\` -> count of records
  seen. Same row objects, one at a time; for scopes too large to hold at once.
- \`await vana.read(scope, {cursor?, maxBytes?, blockIds?})\` -> \`[{id,
  scope, text?, json?, sizeBytes?, itemCount?}]\` — **blocks, not records.**
  The payload is \`.json\` (parsed) or \`.text\` (raw). A bounded read, so it
  can never support a "have I ever" answer.
- \`await vana.search(query, {scopes?})\` -> \`[{id, scope, score, preview?}]\`.
  Ranked, so it is a prefilter and never proof of absence.
- \`await vana.classify(items, instruction)\` -> one result per item.
- \`vana.note(msg)\` records a line for the operator; \`vana.result({answer,
  citations, value})\` ends the script immediately.

You are writing a **subset of JavaScript**: no \`class\`, no generators, no
\`Intl\`, no \`require\`/\`import\`, no network. A refusal tells you exactly what
was rejected and what to use instead.

**Rules that matter more than being helpful:**

1. **Compute, never estimate.** Averages, counts, sums and joins must be
   computed in code. Never eyeball numbers from data you have read into your
   context, and never round a computed figure into a vaguer one.
2. **Read the profile first.** \`vana.scopes()\` returns a \`profile\` for each
   scope describing its shape and its non-obvious rules. These rules are not
   suggestions — they encode how the data is actually structured, and ignoring
   them produces answers that are wrong in ways nobody can see. If a scope has
   no profile, say so in your answer and treat your result as lower confidence.
3. **State your definitions and denominators.** "6.5 hours over 28 of 31 nights,
   main sleep only, naps excluded" — not "about 6.5 hours".
4. **A question about whether something exists requires reading everything.**
   Never answer "no" or "never" from a search's top results. Scan the full scope.
   If you could not scan everything, say what you did scan.
5. **Resolve the set before you aggregate it.** When a question names something
   the data does not ("my Japan trip", "my close friends"), first work out what
   it refers to, state that resolution in your answer, then compute over it.
6. **People appear under many names.** The same person may be an email address, a
   handle, and a display name. Reconcile them before counting.
7. **Distinguish what was measured from what was said.** If the data contains
   both a stated claim and behaviour that contradicts it, report both and the
   conflict.
8. **\`vana.classify\` is expensive.** It calls a model once per item. Filter
   first, and prefer classifying thousands of items once over classifying
   hundreds repeatedly. If a question needs judgement over an entire large
   scope, say so in your answer so the result can be saved and reused.
9. **Cite.** Every claim traces to a scope, and where possible a record.
10. **Say what you do not know.** Missing days, unreadable files, scopes you
    lack access to, budget you ran out of — surface them. An honest partial
    answer is correct; a confident complete-sounding one is a defect.

**Available scopes:** {{SCOPES}}

**Source profiles:** {{PROFILES}}`;

/** One scope as the model sees it, per prompt doc §3's `ScopeInfo`. */
export interface QueryScopeInfo {
  scope: string;
  itemCount?: number;
  collectedAt?: string;
  version?: string;
  contentKind?: string;
}

export interface BuildSystemPromptResult {
  prompt: string;
  version: string;
  /** Scopes with no T2 profile — carried into `coverage.unprofiledScopes`. */
  unprofiledScopes: string[];
  /** Profiles that had to be summarized to fit — carried into coverage. */
  summarizedScopes: string[];
}

function renderScopeLine(info: QueryScopeInfo): string {
  const parts: string[] = [`- \`${info.scope}\``];
  const facts: string[] = [];
  if (typeof info.itemCount === "number") {
    facts.push(`${info.itemCount.toLocaleString("en-US")} items`);
  }
  if (info.contentKind) facts.push(info.contentKind);
  if (info.collectedAt) facts.push(`collected ${info.collectedAt}`);
  if (info.version) facts.push(`version ${info.version}`);
  if (facts.length > 0) parts.push(`(${facts.join(", ")})`);
  return parts.join(" ");
}

/**
 * Build the per-request system prompt.
 *
 * Profile prose is injected in full and only degraded to a summary when the
 * budget forces it (phase 6a's recommendation): a model unaware that naps exist
 * has no reason to go and fetch the Oura profile, so putting the implicit rules
 * behind a second call reintroduces exactly the silent wrongness the design
 * exists to stop. When degradation happens the caller must surface it.
 */
export function buildSystemPrompt(input: {
  scopes: QueryScopeInfo[];
  profileBudgetChars?: number;
}): BuildSystemPromptResult {
  const scopeText =
    input.scopes.length === 0
      ? "(none — you hold no granted scopes and cannot read any data)"
      : "\n" + input.scopes.map(renderScopeLine).join("\n");

  const rendered = renderProfiles(
    input.scopes.map((s) => s.scope),
    input.profileBudgetChars === undefined
      ? {}
      : { budgetChars: input.profileBudgetChars },
  );

  const profileText =
    rendered.text.trim() === ""
      ? "(none — no source profile exists for these scopes; treat your results as lower confidence and say so)"
      : "\n\n" + rendered.text;

  const prompt = SYSTEM_PROMPT_TEMPLATE.replace(
    "{{SCOPES}}",
    scopeText,
  ).replace("{{PROFILES}}", profileText);

  return {
    prompt,
    version: SYSTEM_PROMPT_VERSION,
    unprofiledScopes: rendered.unprofiledScopes,
    summarizedScopes: rendered.summarized,
  };
}
