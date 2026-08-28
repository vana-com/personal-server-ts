/**
 * Shared wiring for the query-layer eval and determinism runners.
 *
 * Extracted so `query-eval.ts` and `query-determinism.ts` drive the loop
 * through exactly one definition. Two copies would drift, and a determinism
 * measurement taken against different wiring than the eval grades is worse
 * than no measurement at all.
 */

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { CorpusManifest } from "@opendatalabs/personal-server-ts-core/query/evals";
import { createAgentAnswerer } from "../packages/core/src/query/agent/index.js";
import {
  createFakeInferenceProvider,
  createOpenAiCompatibleInferenceProvider,
  type InferenceProvider,
} from "../packages/core/src/derivatives/inference.js";
import { createNodeSandbox } from "../packages/server/src/query/node-sandbox.js";
import { createSandboxToolHost } from "../packages/server/src/query/sandbox-tool-host.js";

/**
 * Wire the agent loop over the generated corpus.
 *
 * Uses a scripted provider, not a live relay. The point is that
 * `npm run eval -- --answerer agent` is runnable in CI with no key and no
 * network while still exercising the whole nested path — contract parsing, the
 * confined interpreter, the OS sandbox, host-authored coverage. Only the
 * model's words are canned. Pointing this at a live relay is a separate,
 * deliberate act (see `packages/core/src/query/agent/SMOKE.md`).
 */
export async function buildAgentAnswerer(
  corpusDir: string,
  manifest: CorpusManifest,
  liveProvider?: InferenceProvider,
) {
  // Scope ids come from the MANIFEST, not from filenames. Deriving them from
  // filenames yields `oura_sleep`, which matches no profile — the profiles
  // declare `oura.*` / `spotify.*` / `chatgpt.*`. That silently disabled the
  // entire T2 layer, the highest-leverage artifact in the design (§18.2), and
  // only a live run surfaced it: the model reported every scope as
  // unprofiled and inferred the schema rules itself.
  const scopes = manifest.scopes.flatMap((s) =>
    s.files.map((f) => ({
      scope: s.scope,
      path: join(corpusDir, f),
      itemCount: s.records,
    })),
  );

  // Scripted per question. Q1 is scripted for real — it drives the whole
  // nested path and lands on the §18.2 nap trap, so a pass here means the
  // interpreter, the sandbox and host-authored coverage all did their jobs.
  // The rest answer honestly that no script was written, which the harness
  // correctly grades as a failure rather than letting it look like a pass.
  const provider =
    liveProvider ??
    createFakeInferenceProvider({
      respond: (input, n) => {
        const question =
          input.messages.find((m) => m.role === "user")?.content ?? "";
        const isSleepAverage =
          /sleep/i.test(question) && /average|how much/i.test(question);

        if (isSleepAverage && n === 0) {
          return {
            content:
              "```vana:run\n" +
              `const rows = await vana.readAll("oura.sleep");
// Oura profile, the load-bearing rules:
//  - a day can hold several sleep periods, so rows are not 1:1 with days;
//  - \`type\` has five values, and only main sleep counts here;
//  - bucket by the \`day\` field, never re-derive it from bedtime_start.
let lastDay = "";
for (const r of rows) { if (r.day > lastDay) lastDay = r.day; }
const cutoffMs = Date.parse(lastDay + "T00:00:00.000Z") - 30 * 86400000;
const cutoff = new Date(cutoffMs).toISOString().slice(0, 10);
const windowed = rows.filter(function (r) { return r.day >= cutoff; });
//  - total_sleep_duration is NULLABLE: a null night has no measurement, so it
//    leaves the denominator entirely. Coercing it to 0 silently drags the
//    average down (6.52h -> 6.44h on the full corpus).
const main = windowed.filter(function (r) {
  return r.type === "long_sleep" && r.total_sleep_duration !== null;
});
let total = 0;
for (const r of main) { total = total + r.total_sleep_duration; }
const hours = total / main.length / 3600;
vana.result({
  answer: "You slept " + hours.toFixed(2) + " hours per night on average over " +
    main.length + " of the last 31 nights, main sleep only, naps excluded.",
  value: hours,
  citations: [{ scope: "oura.sleep" }],
});` +
              "\n```",
          };
        }

        return {
          content:
            "```vana:answer\n" +
            JSON.stringify({
              answer: "no scripted answer for this case",
              citations: [],
            }) +
            "\n```",
        };
      },
    });

  const scratchDir = await mkdtemp(join(tmpdir(), "query-eval-scratch-"));
  const tools = createSandboxToolHost({
    sandbox: createNodeSandbox({ dataRoot: corpusDir }),
    scopes,
    dataRoot: corpusDir,
    scratchDir,
    budget: { toolCalls: 50, outputBytes: 1_000_000 },
    limits: {
      cpuMs: 30_000,
      memoryMb: 512,
      wallClockMs: 60_000,
      maxOutputBytes: 1_000_000,
    },
  });

  return createAgentAnswerer({
    provider,
    tools,
    name: liveProvider ? "agent-live" : "agent-loop",
  });
}

/**
 * A real provider, from the same env the server uses. Requires
 * INFERENCE_API_KEY; anything else is a deliberate operator choice.
 *
 * Note INFERENCE_REQUEST_FIELDS: the default body carries the Vana/Phala
 * routing hint `provider:{aci_verified,zdr}`, and a provider that validates
 * its body rejects it outright (Gemini answers 400 "Unknown name provider").
 * Set INFERENCE_REQUEST_FIELDS=none for any non-Vana endpoint.
 */
export function buildLiveProvider(): InferenceProvider {
  const apiKey = process.env.INFERENCE_API_KEY;
  if (!apiKey) {
    throw new Error(
      "a live provider needs INFERENCE_API_KEY (and usually INFERENCE_BASE_URL,\n" +
        "INFERENCE_MODEL, INFERENCE_E2EE=false, INFERENCE_REQUEST_FIELDS=none).",
    );
  }
  const raw = process.env.INFERENCE_REQUEST_FIELDS;
  const requestFields =
    raw === undefined
      ? undefined
      : raw === "none" || raw.trim() === ""
        ? {}
        : (JSON.parse(raw) as Record<string, unknown>);
  const baseUrl = process.env.INFERENCE_BASE_URL;
  const model = process.env.INFERENCE_MODEL;
  process.stderr.write(
    `live provider: ${baseUrl ?? "(default)"} model=${model ?? "(default)"} ` +
      `requestFields=${requestFields ? JSON.stringify(requestFields) : "(default)"}\n\n`,
  );
  return createOpenAiCompatibleInferenceProvider({
    baseUrl,
    model,
    apiKey,
    requestFields,
  });
}
