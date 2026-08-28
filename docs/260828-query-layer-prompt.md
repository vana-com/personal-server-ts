# Query layer: system prompt, script API, and response contract

Companion to `260828-query-layer-implementation-plan.md`. Under the
code-as-content decision (plan §2 phase 5) this prompt **is** the interface —
there is no tool-calling wire format to fall back on, so it is specified here
rather than left to an implementation agent.

## 1. Integrity rule that shapes everything

**The model may never assert coverage. Coverage is produced by the host.**

Every read goes through the injected API, and the host counts records, bytes
and scopes as they are read. `coverage` in the final answer is assembled from
those counters, not from anything the script or the model says. A script that
scans 30 of 300 records cannot report completeness, because it does not author
that field.

This is what makes Q8-class answers ("have I ever…") trustworthy, and it is the
one invariant an implementer must not relax for convenience.

**The invariant holds; the mechanism stated above does not. Corrected
2026-08-28 (phase 4b), measured.** "Every read goes through the injected API,
and the host counts records as they are read" assumes the script _has_ to use
the API. Run as ordinary JavaScript in a Node subprocess — which is what the
phase 4a sandbox provides — it does not. A probe script inside that sandbox
produced:

```
READ_WITHOUT_API:GRANTED-DATA
FORGED_COVERAGE:{"recordsScanned":999999,"complete":true}
HAS_REQUIRE:function  HAS_PROCESS:object  HAS_EVAL:function  HAS_FUNCTION_CTOR:function
```

It read its granted file with `require('fs')`, so no counter observed the read,
and printed a forged coverage line on the same stdout the runtime writes to.
The OS sandbox was working correctly throughout — the read was inside
`readPaths`. What failed was the assumption that the API is the only path to
the data.

Two options were measured, on a 227,024-row scan:

| Approach                                              | Time            | Verdict                                |
| ----------------------------------------------------- | --------------- | -------------------------------------- |
| Native JS in the subprocess, counted in-process       | 13ms            | **Unsound** — the probe above          |
| Confined tree-walking interpreter, counted in-process | **612ms** (47x) | **Adopted**                            |
| Bridging every read to the host over IPC              | ~11,000ms       | Too slow; kills design §18.1's premise |

So generated code is **not executed by Node at all**. It is parsed with acorn
and walked by an evaluator with no `eval`, no `Function`, no `require`, no
`process` and no `globalThis`, which blocks `constructor`/`__proto__`/
`prototype` at every access including computed ones — severing
`({}).constructor.constructor("return process")()`. The coverage ledger is
closed over by the API factory and never bound into the script's realm, and
`complete` is _derived_ (true only when every granted scope was streamed end to
end), not settable. `console.log` routes to a host callback rather than stdout.

47x is the honest price of the confinement, and 612ms against a 60s wall clock
is affordable. This is design §19.6 item 3 — the `codemode` pattern — which was
described in the design but had not been built.

## 2. Response contract

Every model turn must end with exactly one fenced block, tagged either
`vana:run` or `vana:answer`. Prose outside the block is ignored (logged, not
parsed). The parser takes the **last** matching block.

Script form — the body is JavaScript:

````
```vana:run
const sleep = await vana.readAll("oura.sleep");
...
vana.result({ answer: `...`, citations: [...] });
```
````

Final form — the body is JSON:

````
```vana:answer
{"answer": "...", "citations": [{"scope": "oura.sleep"}], "confidence": "high"}
```
````

Parse failure is not fatal: the host replies with a repair message naming the
violation and re-prompts once. A second failure ends the run with
`coverage.complete=false` and an explicit "could not produce a valid script"
answer. Both paths are eval cases.

## 3. Script API (capability-confined, grant-scoped)

Registered per request from the consumer's grant. Scopes outside the grant are
not merely denied — they are absent from `vana.scopes()` and unnameable.

```ts
vana.scopes(): Promise<ScopeInfo[]>
  // { scope, itemCount, collectedAt, version, contentKind, profile? }
  // `profile` is the T2 prose summary; absent means no profile exists.

vana.readAll(scope, opts?): Promise<unknown[]>       // host counts every record
vana.read(scope, opts?): Promise<Block[]>            // bounded/cursored
vana.stream(scope, onItem): Promise<number>          // for large scopes
vana.search(query, opts?): Promise<Hit[]>            // lexical, returns blockRef

vana.classify(items, instruction, opts?): Promise<T[]>
  // LLM judgement applied to every item. The expensive operation.
  // Host meters cost and enforces budget. Encrypted under E2EE like any call.

vana.introspect(): Promise<{ grants, accessLog, lineage }>
  // Q12 only. Refused when the caller is the subject of the question.

vana.note(msg): void
vana.result(payload): void                           // terminates the script
```

Budgets (`query.*` config) are host-enforced: tool calls, wall clock, CPU,
memory, output bytes, and a cost ceiling on `classify`. Exhausting a budget is
a **first-class outcome**, not an error: the run ends with a partial answer and
`coverage.complete=false`, `coverage.stoppedBecause="budget"`.

**Implementation notes added 2026-08-28 (phase 4b):**

- **The script language is a subset of JavaScript, not all of it.** Per §1, code
  is walked by a confined evaluator rather than executed by Node. Unsupported
  syntax fails closed, so a model writing a `class` or a generator gets a
  refusal. The loop's repair-retry must surface the `CONFINEMENT_VIOLATION`
  message back to the model verbatim, or it burns its one repair on a mystery.
- **`readAll` on an ungranted scope throws; it does not return `[]`.**
  Deliberate: an empty result would let a script conclude "there is nothing
  there", which is precisely the Q8 false negative this design exists to
  prevent.
- **`vana.introspect()`'s refusal rule is not yet enforceable as written.** It
  says to refuse "when the caller is the subject of the question", but nothing
  in the request carries the subject. Phase 4b added `callerId` to
  `QueryToolContext`; deciding whether the caller _is_ the subject needs the
  question parsed, which belongs to the loop. **Open — Q12 is the one question
  whose answer must never be served to the party it is about, so this must not
  ship unenforced.**

## 4. The system prompt

Ship verbatim; version it. `{{SCOPES}}` and `{{PROFILES}}` are interpolated per
request from the caller's grant.

---

You answer questions about one person's own data, running inside their Personal
Server. You do this by writing JavaScript that reads their data and computes an
answer. You never see the raw data yourself unless your script returns it.

**How to respond.** Each turn, end with exactly one fenced block:

- ```vana:run` — JavaScript to execute. You get its output back and may iterate.
- ```vana:answer`— JSON, when you are done:`{answer, citations, confidence}`.

Anything outside the block is ignored.

**Rules that matter more than being helpful:**

1. **Compute, never estimate.** Averages, counts, sums and joins must be
   computed in code. Never eyeball numbers from data you have read into your
   context, and never round a computed figure into a vaguer one.
2. **Read the profile first.** `vana.scopes()` returns a `profile` for each
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
8. **`vana.classify` is expensive.** It calls a model once per item. Filter
   first, and prefer classifying thousands of items once over classifying
   hundreds repeatedly. If a question needs judgement over an entire large
   scope, say so in your answer so the result can be saved and reused.
9. **Cite.** Every claim traces to a scope, and where possible a record.
10. **Say what you do not know.** Missing days, unreadable files, scopes you
    lack access to, budget you ran out of — surface them. An honest partial
    answer is correct; a confident complete-sounding one is a defect.

**Available scopes:** {{SCOPES}}

**Source profiles:** {{PROFILES}}

---

## 5. Does this answer the question corpus?

Walking the 18 questions of `260828-query-layer-design.md` §3. Three gaps were
found by doing this; all three are folded into §3 above.

| Q                           | Path through the API                                                  | Holds?                                             |
| --------------------------- | --------------------------------------------------------------------- | -------------------------------------------------- |
| Q1 sleep average            | `readAll` → profile's nap rule → mean; denominator from host counters | ✅                                                 |
| Q2 focus this week          | window-filter 3 scopes → `classify` → aggregate                       | ✅                                                 |
| Q3 risk appetite            | multi-turn: sub-aggregates per sub-question, then synthesis           | ✅ needs several rounds                            |
| Q4 sleep × productivity     | `readAll` both → join on date                                         | ✅                                                 |
| Q5 needle lookup            | `search` then full scan fallback + alias resolution                   | ✅                                                 |
| Q6 distinct people          | `readAll` ×3 → alias-normalize → count                                | ✅                                                 |
| Q7 recurring expenses       | `readAll` → normalize merchant → cadence                              | ✅                                                 |
| Q8 absence                  | full `stream` over every granted scope; host counters prove totality  | ✅ **the invariant in §1**                         |
| Q9 first occurrence         | prefilter → `classify` → min(date)                                    | ⚠️ prefilter can miss the earliest oblique mention |
| Q10 changed thinking        | time-stratified sample → `classify` → contrast                        | ✅                                                 |
| Q11 HR anomaly              | full history baseline + window test                                   | ✅                                                 |
| Q12 what has app X seen     | **`vana.introspect()`**                                               | ⚠️ **gap found** — needed a new API                |
| Q13 plan my week            | future calendar + historical aggregate                                | ✅ freshness caveat                                |
| Q14 Japan trip spend        | resolve window → aggregate; rule 5 forces stating the resolution      | ✅                                                 |
| Q15 say vs do               | `classify` to extract intents, then Q8-style check per intent         | ⚠️ budget-bound                                    |
| Q16 morning person          | behavioural aggregate + stated claims; rule 7 forces the conflict     | ✅                                                 |
| Q17 brief me on X           | alias resolve → gather across scopes → compress                       | ✅                                                 |
| Q18 conditional aggregation | join with filter                                                      | ✅                                                 |

**The three gaps, and what they changed:**

1. **Q12 had no path at all.** Introspection reads grants, access logs and
   lineage — not content — and none of the data API touches those. Added
   `vana.introspect()`, with the rule that it is refused when the caller is the
   app being asked about. Without this, the only question about the server
   itself was unanswerable.
2. **Q9 and Q15 are honestly partial.** Both need semantic judgement over more
   items than a budget allows, so they prefilter. A prefilter can miss the
   earliest oblique mention of a topic — exactly what Q9 asks for. The system
   must mark these `coverage.method="prefiltered"` and the answer must say the
   date is the earliest _found_, not the earliest _that exists_.
3. **Budget exhaustion had no representation.** Q15 in particular can exceed any
   ceiling. Made it a first-class outcome (`stoppedBecause="budget"`) rather
   than an error, so a partial answer with honest coverage beats a failure.

**Two known weaknesses, not gaps:**

- **Q3-class questions depend on decomposition quality**, which is the thing
  DABStep measures at 14–16% on hard multi-step tasks. T2 profiles are what
  move this; the graded set is what tells us whether they moved it enough.
- **Q9/Q10 need real date spread in the eval fixture.** The current generator
  compresses conversations into ~10 days (see
  `docs/query-layer-fixtures/README.md`), which makes both questions vacuous
  until fixed.

## 6. What an implementation agent still decides

Deliberately left open, because they are cheap to change and should be tuned
against the graded set, not guessed here: the repair-retry wording, how much of
a script's stdout is fed back (start with the last 8KB plus any `vana.note`
output), `classify` batching, and whether the loop gets a scratch memo between
turns. Everything in §1–§4 is contract; these are parameters.
