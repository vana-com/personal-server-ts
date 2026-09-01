/**
 * Live smoke test for the query-layer agent loop against ANY OpenAI-compatible
 * provider. Operator-run: no automated test in this repo calls a real model.
 *
 * It answers one question the unit tests cannot: does a *real* model reliably
 * emit the `vana:run` / `vana:answer` grammar from `docs/260828-query-layer-prompt.md`?
 * That is the provider-sensitive risk. The sandbox and the tool host are stubs
 * here on purpose — this exercises the model and the response contract, not
 * the confinement layers (which have their own suites).
 *
 * ---------------------------------------------------------------------------
 * RUNNING IT
 * ---------------------------------------------------------------------------
 *
 * Google Gemini (OpenAI compatibility layer):
 *
 *   INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai \
 *   INFERENCE_MODEL=gemini-3.7-flash \
 *   INFERENCE_API_KEY=<your Gemini key> \
 *   INFERENCE_E2EE=false \
 *   INFERENCE_REQUEST_FIELDS=none \
 *   npx tsx scripts/query-smoke.ts
 *
 * OpenAI:
 *
 *   INFERENCE_BASE_URL=https://api.openai.com/v1 \
 *   INFERENCE_MODEL=gpt-4o-mini \
 *   INFERENCE_API_KEY=sk-... \
 *   INFERENCE_E2EE=false INFERENCE_REQUEST_FIELDS=none \
 *   npx tsx scripts/query-smoke.ts
 *
 * The Vana relay with E2EE (production path) — needs a signer, so run it
 * through the server rather than this script.
 *
 * Why each var matters:
 *   INFERENCE_API_KEY        A bearer key means "this base URL is a provider,
 *                            not the relay", so request signing is skipped.
 *   INFERENCE_E2EE=false     Phala E2EE v2 is a *gateway* protocol. Any other
 *                            provider will reject or ignore the headers, and
 *                            the response has no encrypted field to read.
 *                            Prompts and answers then travel as plaintext over
 *                            TLS — fine for a smoke test with stub data, never
 *                            for real user data.
 *   INFERENCE_REQUEST_FIELDS=none
 *                            Drops the Vana/Phala `provider` routing hint that
 *                            is otherwise merged into every request body.
 *                            Gemini documents that unknown parameters are
 *                            "silently ignored", so this is hygiene rather
 *                            than strictly required — but on a provider that
 *                            validates its body it would be a hard failure.
 *
 * Cost: a handful of turns over a tiny stub scope. Cents, not dollars.
 * ---------------------------------------------------------------------------
 */

import { createOpenAiCompatibleInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import {
  runQueryLoop,
  type ExecutedRun,
  type QueryToolHost,
} from "@opendatalabs/personal-server-ts-core/query/agent";

import { parseRequestFields } from "../packages/server/src/bootstrap.js";

// --- the tiny stub scope ------------------------------------------------
// Six nights, one of them a nap, so a correct answer has to state a
// denominator and exclude the nap. Small enough to be legible in the output.
const SLEEP_ROWS = [
  { day: "2026-08-01", type: "long_sleep", total_sleep_duration: 25_200 },
  { day: "2026-08-02", type: "long_sleep", total_sleep_duration: 21_600 },
  { day: "2026-08-02", type: "late_nap", total_sleep_duration: 2_700 },
  { day: "2026-08-03", type: "long_sleep", total_sleep_duration: 28_800 },
  { day: "2026-08-04", type: "long_sleep", total_sleep_duration: 23_400 },
  { day: "2026-08-05", type: "long_sleep", total_sleep_duration: 26_100 },
];
const MAIN = SLEEP_ROWS.filter((r) => r.type === "long_sleep");
const EXPECTED_HOURS =
  MAIN.reduce((a, r) => a + r.total_sleep_duration, 0) / MAIN.length / 3600;

const QUESTION =
  "What was my average nightly sleep in hours over the days in oura.sleep? " +
  "State the denominator.";

/** Records every turn so a contract violation is diagnosable after the fact. */
const rawTurns: string[] = [];

/**
 * Stub tool host. It does NOT run the script — the confinement layers are the
 * integration path's job, not this script's. It echoes the stub rows so the
 * loop can carry on, which is all we need to see whether the model then emits
 * a well-formed `vana:answer`.
 *
 * Coverage is still host-authored: the model never sets it. Enforcement is
 * reported as none, because none of it is real here and the loop must never be
 * told otherwise.
 */
function stubToolHost(): QueryToolHost {
  return {
    async listScopes() {
      return [
        {
          scope: "oura.sleep",
          itemCount: SLEEP_ROWS.length,
          contentKind: "timeseries",
        },
      ];
    },
    async execute(modelCode: string): Promise<ExecutedRun> {
      rawTurns.push(`--- SCRIPT ---\n${modelCode}`);
      return {
        coverage: {
          scopesScanned: ["oura.sleep"],
          recordsScanned: SLEEP_ROWS.length,
          scopesSkipped: [],
          // `error`, always: nothing was executed and nothing was enforced, so
          // no reading this reports can be trusted.
          stoppedBecause: "error",
        },
        notes: ["STUB HOST - no script was executed and nothing was enforced"],
        termination: "completed",
        stdout: JSON.stringify({ rows: SLEEP_ROWS }, null, 2),
        stderr: "",
        violations: [],
        truncated: false,
      };
    },
    coverage() {
      return {
        scopesScanned: ["oura.sleep"],
        recordsScanned: SLEEP_ROWS.length,
        scopesSkipped: [],
        complete: false,
        stoppedBecause: "error",
      };
    },
  };
}

function redact(key: string): string {
  if (key.length <= 8) return "***";
  return `${key.slice(0, 4)}…${key.slice(-2)} (${key.length} chars)`;
}

async function main(): Promise<void> {
  const baseUrl = process.env.INFERENCE_BASE_URL;
  const model = process.env.INFERENCE_MODEL;
  const apiKey = process.env.INFERENCE_API_KEY;
  const e2ee = process.env.INFERENCE_E2EE !== "false";

  if (!apiKey) {
    console.error(
      "INFERENCE_API_KEY is not set.\n" +
        "This script talks to a provider directly and will not run without a key.\n" +
        "See the header of this file for a copy-pasteable Gemini recipe.",
    );
    process.exitCode = 1;
    return;
  }
  if (!baseUrl || !model) {
    console.error(
      "Set INFERENCE_BASE_URL and INFERENCE_MODEL. See the header.",
    );
    process.exitCode = 1;
    return;
  }
  if (e2ee) {
    console.error(
      "INFERENCE_E2EE is not false.\n" +
        "E2EE v2 is a Phala gateway protocol; against any other provider the\n" +
        "headers are meaningless and there is no encrypted field to read back.\n" +
        "Set INFERENCE_E2EE=false for a direct-provider smoke test.",
    );
    process.exitCode = 1;
    return;
  }

  const requestFields = parseRequestFields(
    process.env.INFERENCE_REQUEST_FIELDS,
    { provider: { aci_verified: true, zdr: true } },
  );

  console.log("=== query-layer smoke test ===");
  console.log(`  POST         ${baseUrl.replace(/\/+$/, "")}/chat/completions`);
  console.log(`  model        ${model}`);
  console.log(`  api key      ${redact(apiKey)}`);
  console.log(`  e2ee         off (plaintext over TLS)`);
  console.log(`  extra fields ${JSON.stringify(requestFields)}`);
  if (Object.keys(requestFields).length > 0) {
    console.log(
      "               ^ non-empty. On a non-Vana provider set\n" +
        "                 INFERENCE_REQUEST_FIELDS=none unless you know it is wanted.",
    );
  }
  console.log(`  question     ${QUESTION}`);
  console.log(
    `  stub data    ${SLEEP_ROWS.length} rows, ${MAIN.length} main-sleep;` +
      ` correct answer ≈ ${EXPECTED_HOURS.toFixed(2)}h over ${MAIN.length} nights\n`,
  );

  const provider = createOpenAiCompatibleInferenceProvider({
    baseUrl,
    model,
    apiKey,
    requestFields,
  });

  // Wrap chat() to capture raw model output; the loop does not expose it.
  const capturing = {
    defaultModel: provider.defaultModel,
    async chat(input: Parameters<typeof provider.chat>[0]) {
      const reply = await provider.chat(input);
      rawTurns.push(
        `--- MODEL TURN ${rawTurns.length + 1} ---\n${reply.content}`,
      );
      return reply;
    },
  };

  const startedAt = Date.now();
  let answer;
  try {
    answer = await runQueryLoop(
      {
        question: QUESTION,
        grantedScopes: ["oura.sleep"],
        budget: { toolCalls: 4 },
      },
      { provider: capturing, tools: stubToolHost() },
    );
  } catch (err) {
    console.error("\n=== TRANSPORT / PROVIDER FAILURE ===");
    console.error(err instanceof Error ? err.message : err);
    console.error(
      "\nIf this is a 400, the provider likely rejected a body field.\n" +
        "Try INFERENCE_REQUEST_FIELDS=none. If it persists, the culprit is\n" +
        "probably `max_tokens` — report it, do not patch inference.ts here.",
    );
    for (const t of rawTurns) console.error(`\n${t}`);
    process.exitCode = 1;
    return;
  }
  const elapsed = Date.now() - startedAt;

  for (const t of rawTurns) console.log(`\n${t}`);

  const repaired = rawTurns.some((t) => t.includes("MODEL TURN 2"))
    ? answer.cost.toolCalls > 1
    : false;

  console.log("\n=== VERDICT ===");
  console.log(`  turns            ${answer.cost.toolCalls}`);
  console.log(
    `  tokens           ${answer.cost.inputTokens} in / ${answer.cost.outputTokens} out`,
  );
  console.log(`  wall clock       ${elapsed}ms`);
  console.log(
    `  stoppedBecause   ${answer.coverage.stoppedBecause ?? "(none)"}`,
  );
  console.log(
    `  scopes scanned   ${answer.coverage.scopesScanned.join(", ") || "(none)"}`,
  );
  console.log(`  receipts         ${answer.receiptIds?.length ?? 0}`);
  console.log(`  multi-turn       ${repaired ? "yes" : "no"}`);

  const violated = answer.coverage.stoppedBecause === "contractViolation";
  console.log(
    `\n  CONTRACT: ${violated ? "FAILED — model never produced a valid block" : "OK"}`,
  );
  if (answer.cost.inputTokens === 0 && answer.cost.outputTokens === 0) {
    console.log(
      "  NOTE: provider reported no token usage. Cost metering will read zero\n" +
        "        for this provider — worth knowing before phase 2 measures cost.",
    );
  }
  console.log(`\n  answer: ${answer.answer}\n`);
  console.log(
    `  (reference: ${EXPECTED_HOURS.toFixed(2)}h over ${MAIN.length} nights,` +
      ` naps excluded — the stub sandbox did NOT run the script, so a correct\n` +
      `   number here means the model computed it from the returned rows.)`,
  );

  process.exitCode = violated ? 1 : 0;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
