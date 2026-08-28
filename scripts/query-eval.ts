/**
 * Query-layer eval runner (implementation plan phase 1).
 *
 * Generates the seeded fixture corpus and grades the question set against a
 * pluggable answerer. The eval harness itself lives in `packages/core` and is
 * browser-safe; this script supplies the Node filesystem sink it cannot.
 *
 *   npm run eval                        # small profile, reference answerer
 *   npm run eval -- --profile full      # the ~277MB corpus
 *   npm run eval -- --answerer null     # prove the harness fails honestly
 *   npm run eval -- --keep out/corpus   # keep the corpus for inspection
 */

import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  PROFILES,
  buildCases,
  createNullAnswerer,
  createReferenceAnswerer,
  formatReport,
  generateInto,
  runEval,
  type FixtureProfileName,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { createAgentAnswerer } from "../packages/core/src/query/agent/index.js";
import { createFakeInferenceProvider } from "../packages/core/src/derivatives/inference.js";
import { createNodeSandbox } from "../packages/server/src/query/node-sandbox.js";
import { createSandboxToolHost } from "../packages/server/src/query/sandbox-tool-host.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
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
async function buildAgentAnswerer(corpusDir: string) {
  const files = await readdir(corpusDir);
  const scopes = files
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({
      scope: f.replace(/\.json$/, ""),
      path: join(corpusDir, f),
    }));

  // Scripted per question. Q1 is scripted for real — it drives the whole
  // nested path and lands on the §18.2 nap trap, so a pass here means the
  // interpreter, the sandbox and host-authored coverage all did their jobs.
  // The rest answer honestly that no script was written, which the harness
  // correctly grades as a failure rather than letting it look like a pass.
  const provider = createFakeInferenceProvider({
    respond: (input, n) => {
      const question =
        input.messages.find((m) => m.role === "user")?.content ?? "";
      const isSleepAverage =
        /sleep/i.test(question) && /average|how much/i.test(question);

      if (isSleepAverage && n === 0) {
        return {
          content:
            "```vana:run\n" +
            `const rows = await vana.readAll("oura_sleep");
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
  citations: [{ scope: "oura_sleep" }],
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

  return createAgentAnswerer({ provider, tools, name: "agent-loop" });
}

async function main(): Promise<void> {
  const profile = (arg("profile", "small") ?? "small") as FixtureProfileName;
  if (!(profile in PROFILES)) {
    throw new Error(
      `unknown profile "${profile}" — expected one of ${Object.keys(PROFILES).join(", ")}`,
    );
  }
  const seed = Number(arg("seed", String(DEFAULT_SEED)));
  const keep = arg("keep");
  const dir = keep ?? (await mkdtemp(join(tmpdir(), "query-eval-")));

  const sink = new FsFixtureSink(dir);
  await sink.init();

  const startedAt = Date.now();
  process.stderr.write(
    `generating "${profile}" corpus (seed ${seed}) into ${dir}\n`,
  );
  const { manifest, source } = await generateInto(sink, { profile, seed });
  const fileCount = new Set(manifest.scopes.flatMap((s) => s.files)).size;
  process.stderr.write(
    `generated ${fileCount} files / ${manifest.scopes.length} scopes in ${Date.now() - startedAt}ms\n\n`,
  );

  const which = arg("answerer", "reference") ?? "reference";
  const answerer =
    which === "null"
      ? createNullAnswerer()
      : which === "agent"
        ? await buildAgentAnswerer(dir)
        : createReferenceAnswerer(source);

  const report = await runEval({
    cases: await buildCases(source),
    answerer,
    seed,
    profile,
  });

  process.stdout.write(formatReport(report) + "\n");

  if (!keep) await rm(dir, { recursive: true, force: true });
  process.exitCode = report.totals.fail > 0 ? 1 : 0;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
