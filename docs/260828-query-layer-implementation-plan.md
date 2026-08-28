# Query layer: implementation plan

Companion to `docs/260828-query-layer-design.md` (rationale, evidence,
measurements). This document is the build order. It assumes no prior context
beyond the repo.

## 0. What we are building, in one paragraph

We are replacing the Personal Server's current "newest 50 items, 200k chars,
one prompt" answering path with a **bounded code-writing agent that runs inside
a two-layer sandbox over the user's granted scopes**: the agent receives a
question, reads short per-source prose describing each scope's shape and its
implicit rules, writes a script against a capability-confined tool API, runs it
against the raw files with OS-enforced read scoping and zero network egress,
and returns an answer carrying citations and coverage metadata. Almost nothing
is precomputed — measured on a 222MB, ten-source corpus, every non-semantic
question (averages, joins, groupings, exhaustive scans of all 95MB of prose)
answers in 2–240ms directly off raw files, so the only artifacts we build ahead
of time are (a) **T2 source profiles**, the hand-written prose that stops an
agent silently mis-parsing naps or regenerated chat branches, and (b) **verified
scripts**, persisted as SKILL.md skills so a repeated question shape replays
deterministically instead of being regenerated; anything else is materialized
only when it is *expensive per query and reused across queries* (whole-corpus
LLM classification at $5–16/pass) or when it must exist as a durable record for
grant, lineage or payment reasons, in which case it is written as an ordinary
**derivative with `$lineage`** and invalidated by the scheduler that already
ships. Against the original question corpus this covers the exact-aggregation
class (SQL-shaped code, deterministic arithmetic, stated denominators), the
exhaustive/absence class (a total scan that *knows* it was total and returns the
count — the completeness guarantee no retrieval system could give), the
relational/join class (entity aliasing then joining), and the introspection
class (grants and access logs, never content); the representative-synthesis and
latent-inference classes are handled by the same loop calling the model as a
function over an exhaustively enumerated set, materializing that pass as a
derivative on second use.

## 1. Ground rules

- **Everything is a derivative.** Answers, scripts and any materialized
  intermediate are written through the existing write path with `$lineage`
  pointing at source data point ids. See `docs/derivative-data-api.md`.
- **Grants bind early and at the OS.** A consumer's grant determines which files
  the sandbox can read and which tools are registered. Never a post-filter.
- **The Personal Server authors the code** (design §16.5). The consumer supplies
  a question; the PS generates, runs, caches and attributes. This keeps grant
  enforcement, payment metering and access logging on our side of the boundary.
- **Determinism where possible.** Arithmetic happens in generated code, never in
  model prose. A cached script replays exactly.
- **Honest failure.** "I scanned X and found nothing" is a first-class result.
  Every tool returns coverage metadata.

## 2. Phases

Phases 1–3 are gates: they produce numbers that decide phases 5–7. Do not skip
them, and do not build the materialization layer before phase 7 says to.

---

### Phase 1 — Graded question set (gate)

Nothing downstream is decidable without this.

**Build:** `packages/core/src/query/evals/` with a fixture corpus and a runner.

- Port the generator from the design work:
  `scratchpad/gen.js` + `gen2.js` produce a 222MB, 13-file, ~10-source corpus
  (Oura with naps, 228k Spotify streams with podcast rows, 10.4k ChatGPT
  conversations with regenerated sibling branches, Slack, email, notes, bank,
  calendar, browser history). Re-implement as a seeded, deterministic TS
  fixture generator so runs are reproducible; commit the generator, not the
  corpus.
- Encode the 18 questions from design §3 as cases:

```ts
interface QueryEvalCase {
  id: string;                    // "Q1"
  question: string;
  class: "aggregation" | "exhaustive" | "synthesis" | "inference"
       | "relational" | "introspection";
  scopes: string[];              // scopes a consumer must hold to ask it
  expect:
    | { kind: "numeric"; value: number; tolerance: number; denominator?: number }
    | { kind: "set"; contains: string[]; excludes?: string[] }
    | { kind: "absence"; mustReportCoverage: true }
    | { kind: "judged"; rubric: string };
  mustCite: boolean;
  mustReportCoverage: boolean;
}
```

- Include the two measured trap cases explicitly, because they are the
  regression tests for T2:
  - **Q1 sleep average** — correct 6.48h (main sleep only) vs 5.81h (naps
    included): an 11.5% error.
  - **ChatGPT message count** — correct 119,758 via `current_node` walk vs
    137,736 by naive `mapping.values()` flatten: +15.0% phantom messages.

**Done when:** `npm run eval` prints per-case pass/fail, per-class rollups,
wall-clock and token cost, against a pluggable answerer interface.

---

### Phase 2 — Determinism measurement (gate)

The number nobody in the literature has, and it decides how much we materialize.

**Build:** an eval mode that runs each aggregation case **N=10** times through a
code-writing answerer and reports variance.

**Measure:** identical-answer rate, numeric spread, and whether the *generated
script* differs run to run even when the answer matches.

**Decides:**
- Low variance → cached scripts are an optimization; regeneration is acceptable.
- High variance → script caching (phase 6) becomes mandatory for every
  numeric class, and we materialize more aggressively in phase 7.

Record the result in the design doc; it is currently the largest open risk
(design §15.3).

---

### Phase 3 — Relay capability check (gate, small)

Determines the harness (design §19.4).

Check whether `inference.baseUrl` (default `https://inference.phala.com/v1`)
implements the **OpenAI Responses API** or only Chat Completions.

- **Responses API supported** → Codex CLI becomes viable, and with it the only
  bundled cross-platform OS sandbox (`codex-rs/sandboxing/`, Landlock+bwrap /
  Seatbelt / Windows restricted tokens, per-path scoping *and* network
  allowlisting). Re-open the harness decision.
- **Chat Completions only** (expected) → proceed with phase 4 as written.

Also confirm tool-calling support on the relay; PR #231 already proved the wire
format works against it.

---

### Phase 4 — Sandbox (two layers)

No harness we surveyed ships this; it is ours regardless. Both layers are
required — see design §19.7.

**4a. OS enforcement.** **Layering matters here:** `packages/core` is imported by
`packages/lite` and must stay browser-safe, so it may not import
`sandbox-runtime` or any Node built-in. Follow the existing ports pattern
(`packages/core/src/ports/index.ts`):

- `packages/core/src/query/ports.ts` — declare `CodeExecutionPort` (the
  `Sandbox` interface below), pure types only.
- `packages/server/src/query/node-sandbox.ts` — the Node implementation
  (`sandbox-runtime` wrapping a subprocess).
- `packages/lite/src/query-sandbox.ts` — the browser implementation (blob worker
  under CSP, §4.1).

Add a `./query` subpath to `packages/core/package.json` `exports`, matching the
existing convention.

```ts
interface SandboxSpec {
  readPaths: string[];      // absolute, exactly the granted scope files
  writePath: string;        // one scratch dir, discarded after the run
  denyNetwork: true;        // non-negotiable
  cpuMs: number;            // default 30_000
  memoryMb: number;         // default 512
  wallClockMs: number;      // default 60_000
  maxOutputBytes: number;   // default 1_000_000
}
interface SandboxResult {
  stdout: string; stderr: string; exitCode: number;
  timedOut: boolean; truncated: boolean; durationMs: number;
}
export interface Sandbox { run(script: string, spec: SandboxSpec): Promise<SandboxResult>; }
```

Default implementation: `@anthropic-ai/sandbox-runtime` (Apache-2.0; Seatbelt on
macOS, bubblewrap+seccomp on Linux, restricted user on Windows) wrapping a Node
subprocess. **Pin the version** — it is a Beta Research Preview under
`anthropic-experimental`. **Verify on day one whether it enforces CPU/memory
quotas or only access control**; if only access control, add `rlimit`s at spawn.

Fallback if that fails: Deno subprocess with `--allow-read=<paths>`
`--deny-net`, accepting the extra runtime dependency.

PS-Lite: `quickjs-emscripten` (MIT, WASM, real memory and interrupt limits) —
no native modules, reduced capability, and it must *say* it is reduced.

**Acceptance:** a test suite of hostile scripts — read outside `readPaths`,
open a socket, resolve DNS, fork-bomb, allocate 4GB, spin forever, write outside
the scratch dir, symlink escape. All must fail closed. This suite is the
security contract; treat a new bypass as a P0.

**4b. Capability confinement.** `packages/core/src/query/tools/`

The generated code calls a registered tool API and nothing else — the
`codemode` pattern (design §19.6). Tools are registered **per request from the
consumer's grant**, so out-of-scope data is not merely denied, it is unnameable.

```ts
interface QueryToolContext {
  grantedScopes: string[];
  resolveScopePath(scope: string): string;   // throws if not granted
  budget: { toolCalls: number; outputBytes: number };
}
```

Minimum tool set: `listScopes()`, `readScope(scope, opts)`,
`searchScopes(query, scopes)` (reuse `packages/core/src/mcp/search`, do not
duplicate it — PR #231's mistake), `recordCitation(...)`, `reportCoverage(...)`.

---

### Phase 5 — Agent loop

`packages/core/src/query/agent/`

**Default:** `@earendil-works/pi-agent-core` + `@earendil-works/pi-ai` (MIT,
in-process, ~2MB, arbitrary `baseUrl` + model as a first-class feature; already
the LLM layer under DeepSeek's harness). Point it at the existing
`inference.baseUrl`/`model` config — do not introduce a second inference path,
and keep the `aci_verified`/`zdr` provider flags and receipt passthrough
(`x-receipt-id`, `x-aci-identity`).

**Fallback:** our own loop, ~200–500 lines against `@ai-sdk/openai-compatible`,
if pi's abstractions fight the grant model.

**E2EE vs tool-calling — decided.** Since the design snapshot, `3a21eb3` landed
Phala E2EE v2 (`inference.e2ee`, **default true**; `INFERENCE_E2EE=false`
overrides). It encrypts **per field**: each `messages[i].content` on the way out
and exactly one `choices[i].message.content` on the way back, AAD-bound to
nonce/timestamp/keys/response id. Everything else travels as clear JSON, and a
tool-only reply has no `content` to decrypt. `main`'s `inference.ts` has **zero**
tool-calling support today; PR #231 built it on a pre-E2EE base and added a hard
guard refusing tools under E2EE, on protocol grounds. **They are mutually
exclusive per request, not merely unintegrated.**

This costs us nothing, because **our architecture does not need wire-level tool
calling.** We are a *code* loop, not a tool loop: the model emits a script in its
message content, we execute it in the sandbox, and we feed the result back as
the next message's content. Both directions are exactly the fields E2EE
encrypts, so the script and its results stay encrypted end to end — strictly
better than tool traffic, which would travel in clear JSON beside the
ciphertext. The evidence also favours it independently: CodeAct reports up to
20% higher success than JSON tool-calling on API-Bank.

Decision: **E2EE stays on by default and the loop is code-as-content.** Wire
tool-calling is an optional fast path only when an operator sets
`inference.e2ee=false`; if built, it must fail closed when E2EE is on, exactly
as PR #231 does. Requires a strict, versioned response contract (one fenced code
block, or a JSON object with `script` / `answer`) plus a repair retry on parse
failure — build this in phase 5 and make it an eval case.

**Lift from PR #231** (`gh pr view 231`; do not build on the branch). Note
`main`'s `inference.ts` has moved since that branch forked (`3d573ab`), so this
is a **rebase, not a cherry-pick**:
- Its tool-calling wire support only if we take the `e2ee=false` fast path
  above; otherwise skip it entirely.
- The `mode` field plumbing across `registration.ts` / `types.ts` / the question
  store, including the PRAGMA-guarded migration and PS-Lite rehydration. This is
  the part worth having either way.

**Relay auth — reuse, do not reimplement.** `ac53bdd` makes the server sign
relay requests: `aud` = origin, method, `pathname+search`, and `bodyHash` over
the **post-encryption** bytes, via `createRequestSigner`
(`packages/core/src/signing/request-signer.ts`) — the same signer already used
for lineage reads. `INFERENCE_API_KEY`, when set, wins and skips signing. A
signing failure is permanent (`relay_signing_failed`, no retry). New error codes
to handle: `relay_signing_failed`, `e2ee_attestation_*`.

**If the query layer ever registers or lists questions as a builder** (not
owner), note `d91124d`: the write-attribution proof's signed `uri` now covers
`pathname+search` with canonicalized param order, there is an optional `nonce`
claim, a new `authorizeWriteSession` auth-port method (404 vs 401 semantics),
and a new `DERIVATIVE_DERIVED_SCOPE_REQUIRED` (400). Breaking for any client
signing bare paths.

Discard `agentic.ts` itself: a fixed two-tool retrieval loop is the design we
argued against, and it cannot do arithmetic. Keep its eval number as prior art
(8% → 80% retrieval accuracy over newest-first truncation on a 36k-chunk
corpus).

**Loop contract:**

```ts
interface QueryRequest {
  question: string;
  grantedScopes: string[];
  budget?: { toolCalls?: number; wallClockMs?: number; usd?: number };
}
interface QueryAnswer {
  answer: string;
  citations: { scope: string; recordId?: string; blockRef?: string }[];
  coverage: {
    scopesScanned: string[];
    recordsScanned: number;
    scopesSkipped: { scope: string; reason: string }[];
    complete: boolean;          // false ⇒ the answer must say so
  };
  script?: string;              // the code that produced it
  determinism: "replayed" | "generated";
  cost: { toolCalls: number; inputTokens: number; outputTokens: number; usd?: number };
}
```

`coverage.complete === false` must be surfaced in `answer` text, not just in
metadata. This is what makes an absence answer honest.

---

### Phase 6 — T2 source profiles and script persistence

**6a. Source profiles.** `packages/core/src/query/profiles/<source>.md`

Short prose (target ~4KB, per the Cube evidence: +17–23pp on NL→SQL from a
small disambiguation doc), loaded into the agent's context for any granted
scope. One per source, hand-written by us, versioned, shipped with the code —
never authored by the user.

Each profile states: file layout and shapes; field meanings and units; the
**implicit rules** (this is the point); metric definitions; and known gaps.

Write three first, and make them pass the phase-1 trap cases:
- **Oura** — durations in seconds; a day can hold multiple sleep periods, so
  `sleep` rows are *not* 1:1 with `daily_sleep`; "sleep" means main-period
  `total_sleep_duration`, not time in bed, naps excluded unless asked.
- **ChatGPT** — the export is a full snapshot, never incremental; edits and
  regenerations are sibling children, not overwrites; the only correct
  reconstruction walks `current_node` back through `parent` and reverses.
- **Spotify** — podcast and track rows share one schema with no type flag
  (discriminate on which field cluster is non-null); `skipped` alone is
  unreliable, use `skipped OR reason_end IN ('backbtn','unknown','endplay','fwdbtn')`;
  ~2.6% of rows have overlapping timestamps and need dedup.

**6b. Verified scripts as skills.** Adopt **SKILL.md** (agentskills.io; already
implemented by pi, dsh, Goose, OpenCode, Crush, Gemini CLI, Letta). A script
that ran successfully and passed its eval case is persisted as a skill keyed by
question shape + source schema version, and **replayed** rather than
regenerated. Persist as a derivative so it carries lineage, is inspectable, and
is deletable by the user.

Replay invalidation: reuse `derivatives/scheduler.ts` — a source change marks
dependent skills stale exactly as it does questions today.

---

### Phase 7 — Wire into derivatives, and materialize only if graded

**7a.** Add `mode: "code"` alongside the existing compute path in
`packages/core/src/derivatives/compute.ts`. Keep the current path until phase 1
evals show the new one is better, then make it the default. Record shape is
unchanged except for `mode`, `script`, `coverage` and `citations`.

**7b.** Materialize **only** where the evals prove it. Apply the rule:

> Precompute only what is expensive per query **and** reused across queries — or
> what must exist as a durable record for grant, lineage or payment reasons.

Measured baselines: scans are 2–240ms and fail the test; a whole-corpus LLM
classification pass is $5–16 and passes it on the second question. Embeddings
are **not** in v1 — agentic keyword search reaches ~91–95% of RAG on text, and
FTS is already in the repo. Any proposal to add a vector index must first beat
lexical on the phase-1 set, per source.

---

### Phase 8 — MCP surface

Extend `packages/core/src/mcp/tools.ts` with one workflow-scoped tool, not a
pile of primitives:

- `ask_personal_data(question, scopes?, budget?)` → `QueryAnswer`.

Keep the existing primitives (`list_granted_scopes`, `read_scope`,
`list_scope_blocks`, `search_personal_context`, `get_scope_file`) for consumers
that want to drive their own loop. Respect the existing per-scope payment path:
a sweep across many scopes has metering and access-log consequences a single
`read_scope` did not — settle and log per scope touched.

## 3. Risks the implementer must not paper over

1. **Sandbox escape.** The hostile-script suite in 4a is the contract. Data
   under a grant is one bad `readPaths` computation away from exposure.
2. **Prompt injection.** The user's own data is untrusted input; a malicious
   email can try to steer generated code. Code execution shrinks the surface by
   keeping raw content out of the model's reasoning context, but does not
   eliminate it — results still flow back. Zero egress is the containment.
3. **Silent wrongness.** The 11.5% and 15.0% errors are what T2 exists to stop.
   Any new source without a profile must be flagged as reduced-confidence in
   `coverage`, not answered as if it were understood.
4. **Concurrency.** Ten consumers asking scan-shaped questions is ten full
   scans. Bound concurrent sandboxes and consider a short-lived result cache
   keyed by (question, scope versions).
5. **PS-Lite divergence.** No native modules and no local inference: decide
   deliberately what it degrades to, and make it say so.
6. **Scale.** At ~2GB the scan numbers move from milliseconds to seconds and
   phase 7's calculus changes. Re-run phase 1 at 10x before assuming it holds.

## 4. Runtime portability: PS full vs PS-Lite

PS-Lite is a **browser/WebView runtime** (`packages/lite`, "Browser/WebView
Personal Server Lite runtime boundary"): storage is OPFS with an IndexedDB
fallback (`RuntimeStoragePort.kind = "browser-indexeddb-opfs"`), the question
store persists through the runtime state store, and inference is a fetch-based
OpenAI-compatible provider. There is no filesystem, no subprocess, and no
native module.

The architecture ports. The sandbox mechanism and the performance profile do
not.

| | PS full (Node) | PS-Lite (browser/WebView) |
| --- | --- | --- |
| Derivatives, lineage, scheduler, question store | ✅ same code | ✅ already wired (`packages/lite/src/derivatives.ts`) |
| T2 source profiles | ✅ | ✅ same files |
| Capability-confined tool API | ✅ | ✅ same code |
| Coverage / citation contract | ✅ | ✅ |
| Lexical search | MiniSearch (pure JS) | ✅ same |
| Agent loop | `pi-agent-core` in-process | ⚠️ verify browser-safety |
| **OS-enforced sandbox** | Seatbelt / bubblewrap / restricted token | ❌ impossible — no subprocess |
| Code execution | Node subprocess under `sandbox-runtime` | Worker + CSP, or QuickJS-WASM |
| Scan performance | measured 2–240 ms | **1 to 2 orders of magnitude slower** |

### 4.1 Lite has no ambient authority to subtract

This is what makes Lite tractable rather than blocked. On Node the sandbox
exists to *remove* capabilities the process already has. In the browser there is
no filesystem to scope — data is reachable only through `DataStoragePort`, so
the injected tool API is the sole channel by construction. Capability
confinement (phase 4b) is the whole boundary in Lite, and it is the same code.

**Egress: blob-worker + CSP.** Verified behaviour, and the detail is
load-bearing:

- `connect-src 'none'` blocks `fetch`, `XMLHttpRequest`, `WebSocket`,
  `EventSource` and `sendBeacon` — but **not WebRTC**. Delete
  `RTCPeerConnection` explicitly.
- A same-origin `new Worker(url)` **does not inherit the document's CSP**; the
  header must be set on that script's own HTTP response. But a **`blob:` URL
  worker does inherit the creator's CSP** — which suits us exactly, since
  generated code is naturally a blob. Spawn it from a strictly-CSP'd controller
  and `connect-src 'none'` comes for free.
- Deleting `fetch`/`WebSocket` as defence in depth is worth doing but fragile:
  they are usually *inherited prototype* properties, so `delete self.fetch` is a
  **silent no-op**. Delete from the defining prototype, before untrusted code
  runs.

**QuickJS-WASM** (`quickjs-emscripten` v0.32.0, MIT, ~640KB sync variant) is the
fallback where CSP cannot be guaranteed. Verified to run in a Worker (its built
glue branches on `WorkerGlobalScope`), with real `setMemoryLimit`,
`setInterruptHandler` and `setMaxStackSize`. No host bindings exist unless we
inject them, so egress is blocked by construction.

Two CSP interactions to get right: loading the QuickJS `.wasm` is itself a
network fetch that `connect-src 'none'` would block — **fetch the bytes before
locking CSP down** — and instantiating it needs `script-src 'wasm-unsafe-eval'`,
which notably does **not** re-enable JS `eval`.

### 4.2 The conclusion that inverts on Lite

Design §17.3 concluded "don't precompute, scans are cheap." **That conclusion is
a function of scan speed, and Lite scans slower.** The rule is unchanged; its
threshold moves:

> Precompute only what is expensive per query and reused across queries.

On Lite more things clear that bar. Expect Lite to need T1-style materialized
rows for hot sources where full PS does not. **Run the phase-1 eval set under
the Lite runtime as a separate profile** and let it decide Lite's
materialization set independently. The Node numbers will not transfer.

How much slower is **unmeasured and unmeasurable from the literature**: no
benchmark exists anywhere for QuickJS on our workload shape (tens of MB of JSON
parsing plus string scanning), and `quickjs-emscripten` adds FFI marshaling
across the WASM boundary — large payloads are precisely its worst case. Do not
design around a guessed multiplier. **Run a throwaway benchmark on the real data
shape before committing to QuickJS**; prefer the blob-worker path, which runs on
V8 at native speed, wherever CSP can be guaranteed.

### 4.3 Lite-specific constraints to design for

- **Storage quota and eviction.** IndexedDB is evictable; OPFS needs
  `navigator.storage.persist()`. A materialized index that silently disappears
  is worse than none — check persistence and report it in `coverage`.
- **Memory.** Do not parse a 53MB scope in one go. Read through the existing
  `storage/blocks` manifest and cursor, which already bound reads.
- **No local inference fallback.** Lite must reach the relay; with
  `inference.baseUrl` at the direct-provider default the compute layer stays off
  and returns 503 `DERIVATIVE_COMPUTE_UNAVAILABLE`. The query layer inherits
  this. Good news: PS-Lite already wires the same request signer and E2EE as the
  Node server (`packages/lite/src/browser-runtime.ts`, `derivatives.ts`), so the
  phase-5 relay story is identical on both runtimes.
- **Reduced capability must be visible.** When Lite answers via a weaker path,
  `coverage` must say so. A silently degraded answer is the failure mode this
  design exists to avoid.

### 4.4 Harness portability — verified

Checked by extracting the published tarballs, not by reading READMEs:

- **`@earendil-works/pi-agent-core@0.84.3`** — `agentLoop()` itself has **zero
  Node built-in imports**: a pure control loop, browser-safe. Its
  `NodeExecutionEnv` (the only shipped filesystem/shell backend) uses
  `node:fs`/`child_process`/`os`/`path`, but sits behind a separate `./node`
  export subpath. **`ExecutionEnv` is a public exported interface**, so an
  OPFS-backed implementation is dependency injection, not a fork. The `bash`
  tool cannot port — there is no subprocess in a browser — which costs us
  nothing, since Lite's execution path is the blob worker.
- **`@earendil-works/pi-ai@0.84.3`** — the main `.` export (types, event stream,
  retry, fetch/WebSocket providers) has no Node imports reachable in normal use;
  Node-only paths (Bedrock's `@smithy/node-http-handler`, CLI, OAuth) are
  dynamically imported and code-splittable.
- Caveat: **there is no official browser build for either package.** This is
  inference from source, not a vendor guarantee. Treat a Lite smoke test as part
  of phase 5's definition of done.
- **`@ai-sdk/openai-compatible@3.0.40`** (Apache-2.0) — confirmed clean: zero
  Node imports in `dist`, fetch-only. (Its `undici` dependency is never actually
  imported; it only appears in an error-string match.) This remains the fallback
  loop's foundation and is the safer choice if pi's Lite smoke test fails.

Still to verify before building: whether the WebView host can guarantee
`connect-src 'none'` for the controller document (decides blob-worker vs
QuickJS), and what corpus size Lite realistically holds under OPFS — the 222MB
benchmark is a desktop figure, and no reliable large-file OPFS throughput
numbers were found.

## 5. Repo conventions an implementation agent must follow

- **`packages/core` must stay browser-safe.** It is consumed by `packages/lite`.
  Anything Node-specific goes behind a port (§ phase 4a) and lands in
  `packages/server`. This is the single easiest way to break the build in a way
  tests on Node will not catch.
- **Tests are colocated `*.test.ts`, run with vitest.** Every new module gets
  one. `npm run build` is `tsc --build`; both must pass.
- **Conventional commits** (commitlint, `@commitlint/config-conventional`).
  PR titles are validated by CI — a `[Don't merge]`-style prefix fails the check
  (this is why PR #231 shows a red title check).
- **Config** goes in `packages/core/src/schemas/server-config.ts` under a new
  `query` block with defaults, alongside the existing `inference` block. Suggested
  keys: `query.enabled`, `query.maxToolCalls`, `query.wallClockMs`,
  `query.cpuMs`, `query.memoryMb`, `query.maxOutputBytes`, `query.skillCache`.
  Add env overrides only for the Node server, matching `INFERENCE_*` precedent.
- **Error codes** go in `packages/core/src/errors/catalog.ts` next to the
  existing `DERIVATIVE_*` codes.
- **T2 profiles are shipped assets.** They are `.md` files that must reach
  `dist`; add a build copy step and a `files` entry the way `packages/lite` does
  for `browser-tls-rustls` (`npm run copy-tls`).
- **Reuse, don't duplicate.** `packages/core/src/mcp/search` already holds the
  MiniSearch index; extend it rather than building a second one (PR #231's
  mistake). Same for `createRequestSigner` and the `storage/blocks` cursor.
- The repo ships review skills under `.agents/skills/` (`code-review`,
  `autoreview`, `test-reviewer`, `atomic-commit-slicing`) — use them.

## 6. What is still open

None of these block starting; each is an experiment whose result feeds a
decision. Do not let an implementation agent silently pick an answer.

| Open item | Blocks | Resolved by |
| --- | --- | --- |
| Determinism of regenerated aggregation code | how much we materialize; whether skill caching is mandatory | Phase 2 |
| Does the relay speak the OpenAI Responses API? | whether Codex CLI's sandbox becomes available | Phase 3 (small) |
| QuickJS throughput on tens of MB of JSON | whether Lite can use the paranoid path at all | throwaway benchmark, §4.2 |
| Can the WebView host guarantee `connect-src 'none'`? | blob-worker vs QuickJS on Lite | §4.1 |
| Realistic Lite corpus size under OPFS | Lite's materialization set | Phase 1, Lite profile |
| Does `sandbox-runtime` enforce CPU/memory, or only access control? | whether we add `rlimit`s at spawn | Phase 4a, day one |
| Does `pi-agent-core` actually run in a browser? | harness choice for Lite, maybe both | Phase 5 smoke test |

**Already decided, do not relitigate:** the Personal Server authors the code
(design §16.5); E2EE stays on and the loop is code-as-content (phase 5);
embeddings are out of v1 (design §15.3); no ingest-time pipeline (design §17.3).

## 7. Prior art: PR #231

An abandoned experiment (`maciej/derivative-agentic-loop`, "[Don't merge]") — it
will not be merged. It is still the closest thing to a baseline we have, and two
things are worth taking:

1. **The `mode` field plumbing** across `registration.ts` / `types.ts` / the
   question store — PRAGMA-guarded migration and PS-Lite rehydration, already
   solved. This is the main lift.
2. **Its eval number as a baseline to beat**: 8% → 80% retrieval accuracy over
   newest-first truncation on a 36k-chunk ChatGPT corpus. Our phase-1 set should
   reproduce that comparison so we can show the code loop beats the tool loop,
   not just the old truncation heuristic.

Do **not** take `agentic.ts` (a fixed two-tool retrieval loop — the design we
argued against, and it cannot do arithmetic), and do not take its tool-calling
wire support while E2EE is on. Note its `inference.ts` forked at `3d573ab`,
before E2EE landed, so anything from it is a rebase, not a cherry-pick.

## 8. Order of work

1. Phase 1 (evals) — blocks everything. Build the Node profile first, the Lite
   profile immediately after (§4.2).
2. Phase 3 (relay check) — small, may re-open the harness choice.
3. Phase 4a (OS sandbox, Node) + hostile-script suite; §4.1 execution path for
   Lite in parallel.
4. Phase 5 (loop) + lift PR #231's `inference.ts` tool-calling. Verify pi's
   browser-safety here (§4.4).
5. Phase 4b (capability confinement — one implementation, both runtimes) +
   Phase 6a (three source profiles).
6. Phase 2 (determinism) — now runnable end to end, on both runtimes.
7. Phase 6b (skills) — mandatory if phase 2 shows high variance.
8. Phase 7 (derivative mode, then materialization only where graded — separately
   per runtime).
9. Phase 8 (MCP surface).
