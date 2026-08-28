# Query layer agent loop (phase 5)

Code as content. The model writes JavaScript in its message content, the host
runs it in the sandbox, and the host feeds the result back as the next
message's content.

## Why not wire tool-calling

Decided in plan phase 5, not to be relitigated. Phala E2EE v2 encrypts **per
field**: each `messages[i].content` outbound and exactly one
`choices[i].message.content` inbound, AAD-bound. A tool-only reply has no
`content` to decrypt, so **E2EE and wire tool-calling are mutually exclusive per
request**. Code-as-content costs nothing here — the script and its results ride
in exactly the fields E2EE covers, which is strictly better than tool traffic
travelling in clear JSON beside the ciphertext.

## Why not `pi-agent-core`

Measured, not assumed — see the phase 5 report. Summary:

- We already own an `InferenceProvider` (`derivatives/inference.ts`) carrying
  E2EE, Web3Signed relay auth, receipt passthrough and a retry seam. The plan
  forbids a second inference path; `pi-ai` is one.
- pi's value-add (tool registry, sessions, compaction, `ExecutionEnv` shell) is
  built around wire tool-calling, which E2EE rules out.
- Result: our own loop against the provider we already have — the plan's
  sanctioned fallback, and lighter than the plan expected, since it needs
  **zero new dependencies** (not even `@ai-sdk/openai-compatible`).

pi _is_ browser-viable, for the record: `pi-agent-core` bundles clean for
`platform: "browser"` (540KB, no `node:` refs) and `pi-ai`'s `node:fs/promises`
/ `node:os` uses are genuine dynamic imports in its OAuth file-credential path.
Plan §4.4's claim checks out. That question is settled; the harness choice was
made on the inference-path argument, not on browser safety.

## The two budgets, which are not the same budget

| Budget                   | Bounds                            | Default         |
| ------------------------ | --------------------------------- | --------------- |
| sandbox `maxOutputBytes` | how much a script may **produce** | 1 MB            |
| `transcript.ts`          | how much we may **send back**     | 1 MiB plaintext |

The relay caps a request body at 2 MiB (`INFERENCE_MAX_BODY_BYTES` on our
gateway; Phala's own cap is 32 MiB, so ours binds). The body carries the _whole
transcript_ every turn, so the cost is cumulative — with `maxToolCalls: 50` a
naive per-turn rule still walks into a 413. `fitTranscript` drops the oldest
turns and **says so in a marker message**; `truncateOutput` keeps head and tail
so neither a printed denominator nor a stack trace is lost.

## The invariant

Coverage is host-authored (prompt doc §1). `runQueryLoop` copies
`tools.coverage()` verbatim and only ever makes it _less_ complete — never
more. A model asserting `{"coverage": {"complete": true}}` in its answer JSON is
ignored; there is a test for exactly that.

`coverage.complete === false` is rendered into the **answer prose**, not just
the metadata, because a caller that renders only `answer` must not be able to
show a confident wrong result.

## Reconciling with phase 4b

`tool-host.ts` is a provisional five-method interface, written because
`query/tools/` did not exist yet. When 4b lands, either satisfy `QueryToolHost`
directly or add a thin adapter. The loop calls nothing else.
