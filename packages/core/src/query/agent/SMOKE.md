# Phase 5 live smoke test (operator-run)

The loop is fully tested against a mocked provider. What tests cannot prove is
that a **real** model, over the **real** relay, with **E2EE on**, reliably emits
the `vana:run` / `vana:answer` grammar. That needs one live run, and it is the
orchestrator's to make — no automated test in this repo calls the relay.

## What this checks

1. The relay accepts a request whose message content is a system prompt plus a
   question, under E2EE (`inference.e2ee` default true).
2. `z-ai/glm-5.2` follows the response contract on the first turn.
3. The repair path is not needed for a well-formed request (or, if it is, how
   often — which is a real number worth having before phase 2).

## Prerequisites

Signed relay access, i.e. either:

- `INFERENCE_API_KEY` set (direct provider, skips signing), or
- a live personal-server registration whose key the request signer can use.

`packages/core/src/derivatives/inference.ts` already handles both; nothing new
is needed.

## The script

There is deliberately no committed runner: the loop needs a `QueryToolHost`,
which phase 4b owns and which did not exist when this landed. Once 4b lands,
the smoke test is:

```ts
import { createOpenAiCompatibleInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import { runQueryLoop } from "@opendatalabs/personal-server-ts-core/query/agent";

const answer = await runQueryLoop(
  {
    question: "How much did I sleep on average last month?",
    grantedScopes: ["oura.sleep"],
  },
  {
    provider: createOpenAiCompatibleInferenceProvider({
      baseUrl: config.inference.baseUrl,
      requestSigner, // or apiKey for local dev
      encryption, // createPhalaE2eeEncryption, default on
    }),
    sandbox: createNodeSandbox(),
    tools: createQueryTools({ grantedScopes: ["oura.sleep"] }), // phase 4b
  },
);
console.log(answer.answer, answer.coverage, answer.cost);
```

## What to watch

- **Contract adherence.** If the model wraps its script in ` ```js ` instead of
  ` ```vana:run `, the parser reports `unknown-tag` and repairs once. A high
  repair rate is a prompt problem, not a parser problem — tune the prompt, and
  record the rate, because it is a cost multiplier on every question.
- **Body size.** Watch for HTTP 413. `fitTranscript` budgets plaintext at
  120 KiB against the relay's 256 KiB cap, halved for the E2EE hex expansion
  that makes the encoded body twice the plaintext we measure. If a 413 still
  appears, raise `REQUEST_OVERHEAD_RESERVE_BYTES` rather than raising the relay
  cap — and check `coverage.violations` for dropped turns, which is what a
  transcript hitting the budget looks like when it does NOT 413.
- **`x-receipt-id`.** Should be present on every turn and is collected into
  `answer.receiptIds`. Missing receipts mean the ACI path is not what we think.
