# The query loop against the relay's daily caps: a measurement

**Date:** 2026-08-31
**Status:** measurement only. This document makes no recommendation and asks
for no exemption. It exists to put numbers in front of the FeeRegistry
conversation, not to pre-empt it.
**Scope:** `data-gateway`'s per-signer inference caps versus what one query-layer
question actually spends. Every figure below is either read from source at a
cited `file:line` or recomputed from a named recorded artifact. Anything not
measured is in §6 and is labelled as such.

---

## 1. Summary

|                                                            |                                                                   |
| ---------------------------------------------------------- | ----------------------------------------------------------------- |
| Median question, current scale operating point             | **61,894 tokens**, ≥7 relay calls                                 |
| Worst question observed                                    | **394,541 tokens**; separately, one run made **≥21 relay calls**  |
| Questions per signer per UTC day, token cap, at the median | **3.2**                                                           |
| Questions per signer per UTC day, call cap, at the median  | **≤2.9** (upper bound; see §4)                                    |
| **Which cap binds first**                                  | **the 20-call cap**, at the median and at the tail                |
| Questions per signer per day at the worst observed case    | **less than one** — a single question exceeds both caps by itself |

Three things the brief that commissioned this did not state, and which the
measurement found:

1. There is a **third cap** the brief did not mention: a **global** ceiling of
   500,000 tokens per UTC day for the _entire gateway_, across all signers
   (§2). At the measured median that is about **8 questions per day for
   everyone combined**.
2. A **256 KiB request-body cap** is enforced with a 413, and **our loop is
   built against an assumed 2 MiB** — an 8× mismatch, hard-coded, currently
   unreconciled (§5). This is a separate defect from the quota question and is
   arguably more urgent, because it fails a request outright rather than
   rationing it.
3. The premise "a median question is roughly 57,000 input tokens" is
   **correct but incomplete**. 57,130 is the median _input_ token count on the
   252 MB corpus and reproduces exactly (§3). The cap meters **input +
   output**, which makes the comparable median 61,894, and the _mean_ is
   85,641 because the distribution has a long right tail.

---

## 2. The caps, verified in `data-gateway`

Read from `/Users/kahtaf/Documents/workspace_vana/data-gateway` at
`main` = `22c8989` ("Promote dev to main: inference quota and daily budget
ceiling (#94)"), clean working tree. Nothing in that repo was modified.

### 2.1 The numeric limits

| Cap                                    | Value                       | Source                                                                  |
| -------------------------------------- | --------------------------- | ----------------------------------------------------------------------- |
| Calls, one signer, per UTC day         | **20**                      | `lib/inference-quota.ts:46` `DEFAULT_INFERENCE_SIGNER_REQUESTS_PER_DAY` |
| Tokens, one signer, per UTC day        | **200,000**                 | `lib/inference-quota.ts:48` `DEFAULT_INFERENCE_SIGNER_TOKENS_PER_DAY`   |
| **Tokens, whole gateway, per UTC day** | **500,000**                 | `lib/inference-quota.ts:50` `DEFAULT_INFERENCE_GLOBAL_TOKENS_PER_DAY`   |
| Largest `max_tokens` per request       | 4,096                       | `lib/inference-quota.ts:52` `DEFAULT_INFERENCE_MAX_OUTPUT_TOKENS`       |
| **Largest request body**               | **256 KiB (262,144 bytes)** | `lib/inference.ts:35` `DEFAULT_INFERENCE_MAX_BODY_BYTES`                |

All five are env-overridable (`lib/inference-quota.ts:73-96`,
`lib/inference.ts:109-125`). The repo carries **no committed override** — the
only occurrences of the env names are `.env.example:100,120,123,125` (all
commented out) and the documentation table at `docs/INFERENCE_RELAY.md:192-195`.
Whether production sets different values is **unverified**: I did not read any
deployment environment.

**The two caps the brief named are confirmed exactly. The global 500,000 cap
and the 256 KiB body cap are additional and were not in the brief.**

### 2.2 Window semantics: UTC calendar day, not rolling

Counters are keyed on a `YYYY-MM-DD` string derived from
`now.toISOString().slice(0, 10)` — `lib/inference-quota.ts:99-101`, and the
column is `usage_day varchar(10)` at `db/schema.ts:1693`. This is a **calendar-day
bucket that resets at UTC midnight**, not a rolling window. A signer that
exhausts its quota at 23:50 UTC is clear ten minutes later; one that exhausts it
at 00:10 UTC waits nearly 24 hours.

### 2.3 The token count is input **plus** output

`extractUsageTokens` reads the upstream `usage` envelope and charges
`total_tokens`, falling back to `prompt_tokens + completion_tokens`
(`lib/inference-quota.ts:210-215`). The constant's own doc comment says
"Tokens (prompt + completion)" (`lib/inference-quota.ts:47`). So the cap is
metered on **input + output**, which is why §3 reports totals and not input
alone.

Two accounting details that raise the effective charge:

- **Reserve-then-settle.** Before forwarding, a conservative estimate is
  reserved: `ceil(bodyBytes / 3) + (max_tokens ?? 1024)`
  (`lib/inference-quota.ts:170-178`, `INFERENCE_ESTIMATED_BYTES_PER_TOKEN = 3`
  at line 63). Since English is nearer 4 bytes/token, this over-reserves the
  prompt side by roughly a third. It is released and replaced by the measured
  count on settle (`lib/inference-quota.ts:387-425`), so for the **sequential**
  calls our loop makes it does not accumulate — but it does mean a call can be
  refused on an estimate larger than what it would actually have spent.
- **A streamed response is charged its reservation, not its usage**
  (`api/v1/inference/chat/completions.ts:270-279`): a streamed body is never
  parsed, so the over-estimate stands as the charge.
- **A failed upstream call still burns a call slot.** `settleInferenceQuota`
  adjusts `reserved_tokens` and `tokens` only; it never decrements `requests`
  (`lib/inference-quota.ts:400-422`). A 502/504 releases the tokens
  (`api/v1/inference/chat/completions.ts:237`) but the request counter keeps
  the increment from `lib/inference-quota.ts:334`. **Retries against a flaky
  upstream consume the 20-call budget.**

### 2.4 What the cap is keyed on

The **recovered EIP-191 request signer, lowercased**:
`signer.toLowerCase()` at `lib/inference-quota.ts:292`, stored as
`signer_address varchar(42)` (`db/schema.ts:1691`, described there as "the
relay's identity unit"), primary key `(signer_address, usage_day)`
(`lib/inference-quota.ts:332`). The signer is recovered by
`recoverMessageAddress` at `lib/web3-signed.ts:179` and is the same identity
that must hold a live server registration
(`api/v1/inference/chat/completions.ts:174`).

**One personal server = one signer = one 20-call, 200k-token budget.** There is
no per-user or per-question subdivision below it.

### 2.5 What the client observes when it trips

`api/v1/inference/chat/completions.ts:206-217`:

- **HTTP 429.**
- Header **`retry-after`**, in seconds, set to the time until the next UTC
  midnight (`lib/inference-quota.ts:108-119`).
- JSON body: `{ error, code, retryAfter, limit?, limitKind? }` where `code` is
  `INFERENCE_QUOTA_EXCEEDED` (per-signer) or `INFERENCE_BUDGET_EXCEEDED`
  (global). `limit` and `limitKind` (`"requests"` | `"tokens"`) are present
  **only for the per-signer refusal** — the global refusal is deliberately
  opaque and exposes no counters (`lib/inference-quota.ts:318-325`).
- The refusal **rolls back** its own reservation, so a refused call consumes
  nothing (`lib/inference-quota.ts:365-368`).

Confirmed against the gateway's own table at
`docs/INFERENCE_RELAY.md:107-108`.

**Note the retry hint is honest and unhelpful in equal measure:** it tells the
client to come back at UTC midnight. There is no backoff that recovers within a
session.

---

## 3. Our loop, verified

Worktree at `feat/query-layer`, tip **`286e065`**.

| Parameter                   | Value                 | Source                                          |
| --------------------------- | --------------------- | ----------------------------------------------- |
| `DEFAULT_MAX_TURNS`         | **20**                | `packages/core/src/query/agent/loop.ts:92`      |
| Per-turn completion budget  | 8,192                 | `packages/core/src/query/agent/loop.ts:101`     |
| Empty-reply retries         | 2                     | `packages/core/src/query/agent/loop.ts:104`     |
| Malformed-tool-call retries | 2                     | `packages/core/src/query/agent/loop.ts:132`     |
| Wrap-up turn                | 1, outside the budget | `packages/core/src/query/agent/loop.ts:569-604` |

### 3.1 It is **not** one relay call per turn

This is the single most important correction on our side.

- Each loop iteration calls `chatWithEmptyReplyRetry`
  (`loop.ts:446`), which is a **retry loop around `provider.chat`**
  (`loop.ts:254-290`). A turn issues 1 call normally, and up to
  **1 + 2 + 2 = 5** when it hits both the empty-content and the
  malformed-tool-call paths (`loop.ts:274-284`).
- After the budget is spent, **one more** call is made by `wrapUpTurn`
  (`loop.ts:299-327`, invoked at `loop.ts:580`).
- The `turns` counter is incremented **per iteration** (`loop.ts:436`), not per
  call. So `cost.modelTurns` **understates relay volume**, and by an amount
  nothing recorded.

**Theoretical worst case: 20 × 5 + 1 = 101 relay calls for one question —
5× the daily 20-call cap.** That is a ceiling from the constants, not an
observation.

The loop's own comment at `loop.ts:88-89` says the turn ceiling "is the only
bound on relay call volume — the gateway has no rate limiting". **That comment
is now false.** The gateway acquired rate limiting in `data-gateway` #94.

---

## 4. The measured distribution

### 4.1 Provenance

Per-question-run cost is recorded by `scripts/query-benchmark.ts:524-526`
(`inTok` ← `cost.inputTokens`, `outTok` ← `cost.outputTokens`, `toolCalls` ←
`cost.toolCalls`). Three surviving artifacts were used. Each was tied to its
design-doc section by matching its stored `totals` envelope **exactly**:

| Set   | Artifact                                                       | `totals`                            | Matches                                                                          |
| ----- | -------------------------------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------- |
| **A** | `…/c2f9a359-…/scratchpad/dogfood-n3-final.json`                | 7,170k in / 171.6k out, 54 rows     | design §19.8 line 1519-1520 ("7.17M input / 171.6k output tokens", N=3, 54 runs) |
| **B** | `…/e924c4dc-…/scratchpad/agent-after/dogfood-n3-final.json`    | 2,638k in / 169.5k out, 54 rows     | design §19.16, 20.2 MB agent column                                              |
| **C** | `…/e924c4dc-…/scratchpad/xl-agent/dogfood-xl-agent-final.json` | 4,421,440 in / 203,189 out, 54 rows | design §19.16, 252.2 MB agent column                                             |

(`…` = `/private/tmp/claude-501/-Users-kahtaf-Documents-workspace-vana-personal-server-ts`.)

Medians below use the repo's own convention — the upper-middle element for an
even sample, `scripts/query-benchmark.ts:578-583`. Under that convention set B
reproduces the design doc's **35,415** and set C reproduces its **57,130**
median input tokens exactly, which is the strongest available check that these
artifacts are the ones the document was written from.

**n = 54 question-runs per set** (18 questions × 3 repeats), all
`gemini-3.7-flash` at `temperature: 0`.

### 4.2 Tokens per question (input + output — what the cap meters)

|                   | A: 20 MB (§19.8)      | B: 20.2 MB (§19.16)   | **C: 252 MB (§19.16)** |
| ----------------- | --------------------- | --------------------- | ---------------------- |
| n                 | 54                    | 54                    | 54                     |
| median input      | 100,705               | 35,415                | 57,130                 |
| **median total**  | **103,419**           | **38,411**            | **61,894**             |
| mean total        | 135,952               | 51,994                | 85,641                 |
| **max total**     | **776,156** (Q6 run2) | **252,641** (Q7 run1) | **394,541** (Q7 run1)  |
| runs over 200,000 | 8 / 54 (15%)          | 1 / 54 (2%)           | 5 / 54 (9%)            |
| runs over 100,000 | 28 / 54 (52%)         | 5 / 54 (9%)           | 15 / 54 (28%)          |

Set C is the current scale operating point and is the one the rest of this
document uses. Set A is the older §19.8 run and is markedly more expensive per
question; it is included because it is the run the design document's headline
numbers come from, and because it shows the spread across configurations is
large.

**The distribution is heavily right-tailed.** In set C the mean is 1.38× the
median, and the worst run is 6.4× the median. A cap this size is not
experienced as "3 questions a day"; it is experienced as "3 questions a day,
unless one of them is Q7, in which case zero".

### 4.3 Relay calls per question — **NOT RECORDED**

This is the honest gap, and it is worth stating plainly rather than estimating
around.

**No artifact records a relay-call count, a model-turn count, or a receipt-id
list.** I surveyed every `*final.json` / `*.jsonl` benchmark artifact on disk
(19 files with cost data, from two sessions). The row schema is
`{id, run, klass, kind, outcome, modelGraded, ms, inTok, outTok, toolCalls,
records, bytes, scopes, complete, …}` — `toolCalls` is
`cost.toolCalls`, which is **scripts executed**
(`packages/core/src/query/agent/types.ts:91`, "Scripts actually executed. Not
the same as model turns"), not turns and not calls. `cost.modelTurns` exists in
the type but was never written to a row, and `receiptIds` was never written
either.

What can be stated **as a strict lower bound**, without extrapolating: a run
that executed _k_ scripts spent at least _k_ turns running them, plus at least
one further turn to produce or attempt an answer, and every turn is at least
one relay call. So **relay calls ≥ scripts + 1**.

|                            | A            | B            | **C**            |
| -------------------------- | ------------ | ------------ | ---------------- |
| median scripts             | 4            | 3            | **6**            |
| max scripts                | 15 (Q6 run2) | 10 (Q4 run1) | **20 (Q9 run1)** |
| **⇒ median relay calls ≥** | 5            | 4            | **7**            |
| **⇒ max relay calls ≥**    | 16           | 11           | **21**           |

**Set C, Q9 run 1 ran 20 scripts.** Twenty scripts means twenty turns, which is
the entire `DEFAULT_MAX_TURNS` budget, which means the run then took the
wrap-up turn — **≥21 relay calls, on one question**. That same run also spent
288,929 tokens. **It exceeds both per-signer caps by itself, and it is a run
that already happened.** The collision is not hypothetical; it is only
unobserved, because that run went to Gemini directly.

Because this is a lower bound, every call-based figure below is an
**upper bound on questions per day** — the true number is smaller.

---

## 5. The arithmetic

Using set C (252 MB, the current operating point). Caps: **20 calls** and
**200,000 tokens**, per signer, per UTC day.

### 5.1 At the median question (61,894 tokens, ≥7 relay calls)

| Cap    | Arithmetic       | Questions / signer / UTC day |
| ------ | ---------------- | ---------------------------- |
| Tokens | 200,000 ÷ 61,894 | **3.2**                      |
| Calls  | 20 ÷ 7           | **≤ 2.9**                    |

**The call cap binds first**, and it binds harder than shown, because 7 is a
lower bound on calls while 61,894 is an exact token count.

### 5.2 At the worst observed question

| Cap    | Worst observed    | Questions / signer / UTC day                                |
| ------ | ----------------- | ----------------------------------------------------------- |
| Tokens | 394,541 (Q7 run1) | **0.51** — one question is 1.97× the entire daily budget    |
| Calls  | ≥21 (Q9 run1)     | **≤0.95** — one question is over the entire daily allowance |

**At the tail a single question does not fit in a signer's whole day, under
either cap.**

### 5.3 The other two sets, for range

| Set                 | median total | questions/day (tokens) | median calls ≥ | questions/day (calls) ≤ |
| ------------------- | ------------ | ---------------------- | -------------- | ----------------------- |
| A (20 MB, §19.8)    | 103,419      | 1.9                    | 5              | 4.0                     |
| B (20.2 MB, §19.16) | 38,411       | 5.2                    | 4              | 5.0                     |
| C (252 MB, §19.16)  | 61,894       | 3.2                    | 7              | 2.9                     |

The call cap binds first in set C; in sets A and B the token cap binds first.
**Which cap binds is not stable across configurations** — it moves with how
much data the corpus makes the model read per turn. Any decision keyed to "the
token cap is the problem" would have been right on the 20 MB corpus and wrong
on the 252 MB one.

### 5.4 The global ceiling

500,000 tokens per UTC day for the **whole gateway**
(`lib/inference-quota.ts:50`). At set C's median of 61,894 tokens:

**≈ 8 median questions per day, across every signer combined.**

Two-and-a-half signers exhausting their personal allowance exhaust the gateway.
The gateway's own documentation sizes this deliberately — "about a week of
runway" on a 5 USD balance (`docs/INFERENCE_RELAY.md:231-234`) — so this is
working as designed and is a budget fact, not a bug. It belongs in the
FeeRegistry conversation because it bounds _any_ per-signer scheme from above.

### 5.5 The 256 KiB body cap versus our 2 MiB assumption

Separate from the daily quotas, and the sharpest single finding here.

`packages/core/src/query/agent/transcript.ts:26-27`:

```ts
/** The relay's body cap. Ours, not Phala's — ours is the binding one. */
export const RELAY_MAX_BODY_BYTES = 2 * 1024 * 1024;
```

From which `DEFAULT_TRANSCRIPT_BUDGET_BYTES = RELAY_MAX_BODY_BYTES * 0.5`
= **1 MiB of plaintext transcript** (`transcript.ts:38-41`), a safety factor
sized for E2EE ciphertext expansion (`transcript.ts:29-35`).

The gateway's actual cap is **256 KiB**
(`data-gateway/lib/inference.ts:35`), enforced as **413 `BODY_TOO_LARGE`**
(`data-gateway/api/v1/inference/chat/completions.ts:100-107`).

**Our transcript budget alone is 4× the gateway's entire body limit, before
E2EE expansion; the constant it is derived from is 8× too large.** The comment
asserting ours is "the binding one" is false against this gateway. A run whose
transcript approaches our budget does not get rationed — it gets a 413 and the
whole question fails. Whether any recorded run actually crossed 256 KiB is
**unmeasured**: per-call request-body size is not recorded anywhere (§6).

---

## 6. What is still UNMEASURED

Listed in the order I would rank them.

1. **The loop has never once run against Phala under these caps.** Every
   benchmark used Gemini direct: `scripts/run-n3-bench.sh:28` and
   `scripts/run-scale-bench.sh:22` both pin
   `INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai`.
   There is no recorded run through `data-gateway`'s relay, so **no 429 has
   ever been observed by this loop**, and how the loop behaves when it gets one
   mid-question is untested. Everything in §5 is arithmetic over Gemini-arm
   measurements, not an observation of the collision.
2. **Relay-call count per question was never recorded** (§4.3). Every call
   figure above is a lower bound derived from script counts. Now instrumented
   (§7), but no run has yet produced the number.
3. **Per-call request-body bytes are never recorded**, so the 256 KiB / 2 MiB
   mismatch in §5.5 is a verified _code_ discrepancy but an unverified
   _runtime_ one. The `bytes` field in the artifacts is bytes streamed into the
   sandbox, not request-body size.
4. **The production values of the caps are unverified.** §2.1 reports the
   compiled-in defaults and confirms no committed override; I did not read any
   deployment environment.
5. **E2EE overhead is not in any of these numbers.** All benchmarks ran with
   `INFERENCE_E2EE=false` (`run-n3-bench.sh:30`, `run-scale-bench.sh:24`).
   Ciphertext expansion pushes body bytes up against §5.5's cap and is exactly
   what `TRANSCRIPT_SAFETY_FACTOR` exists to absorb — untested against the real
   limit.
6. **Nothing here measures a real user's question mix.** The corpus is 18
   synthetic benchmark questions at N=3. A real day is not 18 draws from this
   distribution.
7. **Retry-storm behaviour is unmeasured.** §3.1's 101-call theoretical worst
   case has never been observed, and the recorded reply-shape files show
   malformed-tool-call replies do occur (20 in one sweep, design §19.8 region).
   How often a turn actually issues more than one call is unknown.

---

## 7. Instrumentation added

Because §4.3 found relay-call count is not recorded, minimal telemetry was
added. It changes no limit and no behaviour.

- `packages/core/src/query/agent/loop.ts` — the provider is wrapped in a
  counting decorator immediately after the options destructure, so **every**
  call site is counted and a future one cannot forget to. Adds `relayCalls` to
  the returned `cost`.
- `packages/core/src/query/agent/types.ts` — `QueryCost.relayCalls?: number`.
- `packages/core/src/query/evals/types.ts` — carries `modelTurns` and
  `relayCalls` through the eval result so a sweep can see them.
- `scripts/query-benchmark.ts` — writes `turns` and `relayCalls` onto each
  benchmark row.

After this, one ordinary sweep answers §4.3 exactly instead of by lower bound.

---

## 8. The trade-off, stated without a recommendation

The decision is not this document's to make. What the numbers constrain:

- **The caps and the loop were each sized sensibly and independently.**
  `DEFAULT_MAX_TURNS = 20` was raised from 12 on benchmark evidence
  (`loop.ts:82-89`) to stop budget kills. The 20-call cap was sized to make a
  5 USD balance last a week (`docs/INFERENCE_RELAY.md:231-234`). Neither is
  wrong on its own terms. They were simply never measured against each other,
  and the collision is exact: **the loop's per-question turn ceiling equals the
  gateway's per-signer daily call allowance.**
- **An exemption** moves the whole cost onto the gateway operator's key, whose
  global ceiling is 500,000 tokens/day — about 8 median questions for all
  signers combined (§5.4). An exemption large enough to matter is a change to
  that ceiling too.
- **Per-question metering** needs a per-question price, and §4.2 shows the
  spread it would have to price: median 61,894, mean 85,641, worst 394,541 —
  a 6.4× median-to-worst ratio, with 9% of runs over 200,000. Any flat
  per-question fee is badly wrong at one end of that distribution.
- **Either way, §5.5 is unaffected and still needs fixing.** A 413 is not a
  quota problem and no fee schedule resolves it.

---

## 9. Reproducing this

```
# our side
git -C <worktree> log --oneline -1        # 286e065
sed -n '92p'  packages/core/src/query/agent/loop.ts
sed -n '26,41p' packages/core/src/query/agent/transcript.ts

# the gateway
git -C ../data-gateway log --oneline -1   # 22c8989
sed -n '45,54p' ../data-gateway/lib/inference-quota.ts
sed -n '35p'    ../data-gateway/lib/inference.ts
```

The distributions in §4 were recomputed from the three artifacts named in §4.1
using the median convention at `scripts/query-benchmark.ts:578-583`. Those
artifacts live in session scratch directories and are not permanent; the
`totals` envelopes that tie each to its design-doc section are quoted in §4.1
so the identification survives them.
