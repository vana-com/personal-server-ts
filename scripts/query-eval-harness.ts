/**
 * Shared wiring for the query-layer eval and determinism runners.
 *
 * Extracted so `query-eval.ts` and `query-determinism.ts` drive the loop
 * through exactly one definition. Two copies would drift, and a determinism
 * measurement taken against different wiring than the eval grades is worse
 * than no measurement at all.
 */

import { appendFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type {
  CorpusManifest,
  EvalAnswerer,
  EvalQueryRequest,
} from "@opendatalabs/personal-server-ts-core/query/evals";
import {
  createAgentAnswerer,
  type QueryToolHost,
} from "../packages/core/src/query/agent/index.js";
import {
  createFakeInferenceProvider,
  createOpenAiCompatibleInferenceProvider,
  type InferenceProvider,
} from "../packages/core/src/derivatives/inference.js";
import { createNodeSandbox } from "../packages/server/src/query/node-sandbox.js";
import { createSandboxToolHost } from "../packages/server/src/query/sandbox-tool-host.js";

/**
 * An `EvalAnswerer` that also reports the scripts the last request ran.
 *
 * `QueryAnswer.script` is the LAST script only — the loop keeps a single
 * `lastScript` and hands that back — so a row that reached 16 tool calls
 * retained one program out of sixteen and could not be audited. Q11 run 0 of
 * the N=3 sweep cites a sleep-heart-rate baseline that its retained script
 * never computes, and the dump cannot say whether an earlier turn computed it
 * (a retrieval success, answer selected badly) or nothing ever did (a
 * retrieval failure). That distinction is the reported diagnosis.
 *
 * Recorded HERE rather than in the loop because the harness owns the tool
 * host, and every script the loop runs passes through `execute` — so this
 * needs no change to `agent/loop.ts` or to the `QueryAnswer` contract. The
 * last recorded script is by construction the one `QueryAnswer.script`
 * carries.
 */
export interface RecordingEvalAnswerer extends EvalAnswerer {
  /** Every script the most recent `answer()` executed, in order. */
  scriptsForLastRequest(): string[];
}

/**
 * Per-row ceiling on retained script text, in characters.
 *
 * The 54-row N=3 sweep ran 202 scripts averaging ~1.6KB, and its widest row
 * ran 16 — so ~26KB is the observed worst case and this cap does not bite on
 * it. It exists for the 20-turn run that writes 4KB a turn, where retaining
 * everything would make one row a fifth of the file.
 */
export const SCRIPTS_CHAR_BUDGET = 40_000;

/**
 * Fit a run's scripts into the budget, from the front, always keeping the last.
 *
 * Whole scripts are dropped rather than truncated: half a program is not
 * auditable, which is the entire reason for keeping them. The first scripts
 * show the approach the model started with and the last is the one that
 * produced the answer, so the middle turns are the most skippable and that is
 * where the cap bites. The caller records how many went — the count on the row
 * is the difference between a capped dump and a silently lossy one.
 *
 * Lives here rather than beside the row it fills because `query-benchmark.ts`
 * runs on import and cannot be exercised from a test.
 */
export function retainScripts(all: readonly string[]): {
  kept: string[];
  elided: number;
} {
  if (all.length === 0) return { kept: [], elided: 0 };
  const total = all.reduce((n, s) => n + s.length, 0);
  if (total <= SCRIPTS_CHAR_BUDGET) return { kept: [...all], elided: 0 };
  const last = all[all.length - 1];
  const kept: string[] = [];
  let used = last.length;
  for (const s of all.slice(0, -1)) {
    if (used + s.length > SCRIPTS_CHAR_BUDGET) break;
    kept.push(s);
    used += s.length;
  }
  kept.push(last);
  return { kept, elided: all.length - kept.length };
}

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
): Promise<RecordingEvalAnswerer> {
  // Scope ids come from the MANIFEST, not from filenames. Deriving them from
  // filenames yields `oura_sleep`, which matches no profile — the profiles
  // declare `oura.*` / `spotify.*` / `chatgpt.*`. That silently disabled the
  // entire T2 layer, the highest-leverage artifact in the design (§18.2), and
  // only a live run surfaced it: the model reported every scope as
  // unprofiled and inferred the schema rules itself.
  const corpusScopes = manifest.scopes.flatMap((s) =>
    s.files.map((f) => ({
      scope: s.scope,
      path: join(corpusDir, f),
      itemCount: s.records,
    })),
  );

  /**
   * The scopes ONE request may read, from that request's own grant.
   *
   * Handing the host every manifest scope made `grantedScopes` all 18 on every
   * question however few the case declared, and quietly weakened four separate
   * things at once: the model was given the whole corpus to answer a
   * two-scope question; `coverage.complete`'s `everyGrantedScopeAccountedFor`
   * conjunct became unsatisfiable by construction, because no question needs
   * all 18; and `mustReportCoverage`, `gradeAbsence` and the scope-binding
   * assertions all graded against a grant nobody had asked for. A grant is a
   * per-request fact, so the list is built per request.
   */
  const scopesFor = (grantedScopes: readonly string[]) => {
    const granted = new Set(grantedScopes);
    return corpusScopes.filter((s) => granted.has(s.scope));
  };

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
  const name = liveProvider ? "agent-live" : "agent-loop";

  // Reset per request, alongside the host it observes. A recorder that
  // outlived the host would accumulate across questions in exactly the way
  // the fresh-host rule below exists to prevent.
  let executed: string[] = [];

  return {
    name,
    scriptsForLastRequest: () => [...executed],
    async answer(request: EvalQueryRequest) {
      // A fresh host per request, because the grant is per request — and
      // because the host also accumulates coverage across the turns of one
      // request. Reusing it across questions would carry one question's
      // counters into the next.
      const host = createSandboxToolHost({
        sandbox: createNodeSandbox({ dataRoot: corpusDir }),
        scopes: scopesFor(request.grantedScopes),
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
      const ran: string[] = [];
      executed = ran;
      // A pass-through that observes and changes nothing: the script is
      // recorded BEFORE `execute`, so a run the sandbox kills is still in the
      // record. Delegation is explicit rather than a spread of `host`, so a
      // new method on `QueryToolHost` is a compile error here instead of a
      // silently unobserved call.
      const tools: QueryToolHost = {
        listScopes: () => host.listScopes(),
        coverage: () => host.coverage(),
        execute: (modelCode: string) => {
          ran.push(modelCode);
          return host.execute(modelCode);
        },
      };
      return createAgentAnswerer({ provider, tools, name }).answer(request);
    },
  };
}

/* ------------------------------------------------------------------ */
/* Why a reply carried no content — recorded, not guessed               */
/* ------------------------------------------------------------------ */

/**
 * The SHAPE of one relay reply. Never its text.
 *
 * `inference.ts` collapses four different situations into one message,
 * "inference response carried no assistant content": no `choices`, a
 * `message.content` that is not a string, a body that is not an object at all
 * (Gemini reports errors as a JSON **array**, and `isRecord` excludes arrays,
 * so an array body reads as "no content" rather than as the error it is), and
 * a reply whose content decrypts to whitespace. `loop.ts` then matches that
 * message as a string and retries it three times with a doubled budget. When
 * the retries run out the benchmark records `stoppedBecause: "error"` and
 * nothing about *which* of the four it was — which is why the 2/54 recurrence
 * of the null-content crash in the N=3 sweep cannot be diagnosed from its
 * dump. This records the discriminator at the only place that still has the
 * bytes.
 *
 * Shape only, deliberately. `readErrorType` in `inference.ts` reads a
 * rejection's `type` and pointedly never its `message`; the same rule holds
 * here, so a diagnostic file can be pasted into a report without leaking the
 * question, the corpus or the model's words.
 */
interface ReplyShape {
  ms: number;
  status: number;
  bytes: number;
  /** Requested completion budget, so a doubled retry is identifiable. */
  maxTokens?: number;
  /** `array` is the shape a Gemini error arrives in. */
  top: "object" | "array" | "not-json";
  keys?: string[];
  choices?: number;
  finishReason?: string | null;
  /** `typeof choices[0].message.content`, or `absent`. */
  content?: string;
  contentChars?: number;
  promptTokens?: number;
  completionTokens?: number;
  /** From `{ error: { type, code, status } }`, in an object or an array body. */
  errorType?: string;
  errorCode?: string | number;
  errorStatus?: string;
  /** True when this reply is one `inference.ts` will reject as contentless. */
  contentless: boolean;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function describeReply(
  status: number,
  body: string,
  ms: number,
  maxTokens?: number,
): ReplyShape {
  const shape: ReplyShape = {
    ms,
    status,
    bytes: body.length,
    ...(maxTokens === undefined ? {} : { maxTokens }),
    top: "not-json",
    contentless: true,
  };
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return shape;
  }
  shape.top = Array.isArray(parsed)
    ? "array"
    : isPlainObject(parsed)
      ? "object"
      : "not-json";

  // An error can arrive as `{error:{...}}` or, from Gemini, as `[{error:{...}}]`.
  const errorHolder = Array.isArray(parsed) ? parsed[0] : parsed;
  if (isPlainObject(errorHolder) && isPlainObject(errorHolder.error)) {
    const e = errorHolder.error;
    if (typeof e.type === "string") shape.errorType = e.type;
    if (typeof e.code === "string" || typeof e.code === "number") {
      shape.errorCode = e.code;
    }
    if (typeof e.status === "string") shape.errorStatus = e.status;
  }

  if (!isPlainObject(parsed)) return shape;
  shape.keys = Object.keys(parsed);
  if (isPlainObject(parsed.usage)) {
    const u = parsed.usage;
    if (typeof u.prompt_tokens === "number")
      shape.promptTokens = u.prompt_tokens;
    if (typeof u.completion_tokens === "number") {
      shape.completionTokens = u.completion_tokens;
    }
  }
  if (!Array.isArray(parsed.choices)) return shape;
  shape.choices = parsed.choices.length;
  const first: unknown = parsed.choices[0];
  if (!isPlainObject(first)) return shape;
  shape.finishReason =
    typeof first.finish_reason === "string" ? first.finish_reason : null;
  if (!isPlainObject(first.message)) {
    shape.content = "no-message";
    return shape;
  }
  const content = first.message.content;
  shape.content = content === null ? "null" : typeof content;
  if (typeof content === "string") {
    shape.contentChars = content.length;
    // Mirrors `inference.ts`: a string that trims to nothing is rejected too.
    shape.contentless = content.trim() === "";
  } else if (Array.isArray(content)) {
    const chars = content.reduce(
      (n: number, part: unknown) =>
        n +
        (isPlainObject(part) && typeof part.text === "string"
          ? part.text.length
          : 0),
      0,
    );
    shape.contentChars = chars;
    shape.contentless = chars === 0;
  }
  return shape;
}

/**
 * A `fetch` that observes replies and changes none of them.
 *
 * The body is buffered and handed on as a fresh `Response`; `inference.ts`
 * reads only `ok`, `status`, `headers` and the body, so nothing it needs is
 * lost. Only interesting replies are reported — a rejection, or one that will
 * be rejected as contentless — so a healthy 50-minute sweep prints nothing and
 * a recurrence prints exactly the discriminator that is missing today.
 *
 * `QUERY_INFERENCE_DIAG=<path>` appends the same records as JSONL.
 */
function diagnosticFetch(diagPath: string | undefined): typeof fetch {
  return async (input, init) => {
    let maxTokens: number | undefined;
    try {
      const body: unknown = JSON.parse(String(init?.body ?? ""));
      if (isPlainObject(body) && typeof body.max_tokens === "number") {
        maxTokens = body.max_tokens;
      }
    } catch {
      // Not our JSON body; the budget is simply unknown for this record.
    }
    const started = Date.now();
    const response = await fetch(input, init);
    const text = await response.text();
    const shape = describeReply(
      response.status,
      text,
      Date.now() - started,
      maxTokens,
    );
    if (!response.ok || shape.contentless) {
      const line = JSON.stringify(shape);
      process.stderr.write(`\ninference reply shape: ${line}\n`);
      if (diagPath) {
        await appendFile(diagPath, line + "\n").catch(() => undefined);
      }
    }
    // 204/205/304 may not carry a body; nothing here produces one, but a
    // relay that did would make the reconstruction throw rather than pass
    // through, so the empty-body case is explicit.
    return new Response(text === "" ? null : text, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
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
  const diagPath = process.env.QUERY_INFERENCE_DIAG;
  process.stderr.write(
    `live provider: ${baseUrl ?? "(default)"} model=${model ?? "(default)"} ` +
      `requestFields=${requestFields ? JSON.stringify(requestFields) : "(default)"}` +
      `${diagPath ? ` diag=${diagPath}` : ""}\n\n`,
  );
  return createOpenAiCompatibleInferenceProvider({
    baseUrl,
    model,
    apiKey,
    requestFields,
    fetch: diagnosticFetch(diagPath),
  });
}
