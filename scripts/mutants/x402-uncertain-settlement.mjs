import { readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

const root = process.cwd();
const apiPath = path.join(root, "packages/core/src/api/index.ts");
const paymentPath = path.join(root, "packages/core/src/payment/x402.ts");
const command = [
  "vitest", "run", "--maxWorkers=4",
  "packages/core/src/payment/x402-uncertain-settlement.test.ts",
  "packages/core/src/payment/x402.test.ts",
];
const files = new Map();
let stopping = false;

async function restore() {
  for (const [file, contents] of files) await writeFile(file, contents);
  files.clear();
}

async function runSuite() {
  return new Promise((resolve) => {
    const child = spawn("nice", ["-n", "19", "npx", ...command, "--reporter=json"], {
      cwd: root,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => resolve({ error: error.message }));
    child.on("close", (code, signal) => {
      try {
        const start = stdout.indexOf("{");
        const report = start < 0 ? null : JSON.parse(stdout.slice(start));
        resolve({ code, signal, report, stderr, stdout });
      } catch (error) {
        resolve({ code, signal, error: `Could not parse Vitest JSON: ${error.message}`, stderr, stdout });
      }
    });
  });
}

function failedTests(run) {
  if (!run.report || !Array.isArray(run.report.testResults)) return null;
  const failures = [];
  for (const suite of run.report.testResults) {
    for (const test of suite.assertionResults ?? []) {
      if (test.status === "failed") failures.push(test.fullName ?? test.title ?? "");
    }
  }
  return failures;
}

async function save(file) {
  if (!files.has(file)) files.set(file, await readFile(file, "utf8"));
}

async function mutate(file, before, after) {
  await save(file);
  const current = await readFile(file, "utf8");
  if (!current.includes(before)) throw new Error(`Mutation anchor missing in ${path.relative(root, file)}`);
  await writeFile(file, current.replace(before, after));
}

const unknownReturn = 'return { kind: "gateway-error", status: 503, body: { error: "PAYMENT_OUTCOME_UNKNOWN", message: "Payment outcome is unknown. Retry with the same X-PAYMENT header." } };';
const mutations = [
  {
    name: "RECHALLENGE_ON_TRANSPORT", aimed: "UNCERTAIN_PAYMENT_RECHALLENGES",
    apply: () => mutate(apiPath, unknownReturn, 'return { kind: "challenge", body: await buildFreshChallenge() };'),
  },
  {
    name: "RECHALLENGE_ON_409", aimed: "CONFLICT_RECHALLENGES",
    apply: () => mutate(apiPath, `if (gatewayRes.status === 409 || gatewayRes.status >= 500) {\n    ${unknownReturn}\n  }`, `if (gatewayRes.status === 409 || gatewayRes.status >= 500) {\n    return { kind: "challenge", body: await buildFreshChallenge() };\n  }`),
  },
  {
    name: "ACCEPT_ALL_409", aimed: "CONFLICT_RECHALLENGES",
    apply: () => mutate(apiPath, `if (gatewayRes.status === 409 || gatewayRes.status >= 500) {\n    ${unknownReturn}\n  }`, `if (gatewayRes.status === 409 || gatewayRes.status >= 500) {\n    return { kind: "ok", payResponse: null };\n  }`),
  },
  {
    name: "REVALIDATE_SETTLED_AS_NEW", aimed: "REVALIDATE_SETTLED_AS_NEW",
    apply: () => mutate(paymentPath,
      '  // Stateless freshness check: extract the issue-time from the high 32 bits',
      '  if (msg.amount !== grant.fee.totalDue) return { ok: false, reason: "amount differs from current fee" };\n\n  // Stateless freshness check: extract the issue-time from the high 32 bits'),
  },
  {
    name: "SERVE_ON_UNKNOWN", aimed: "SERVE_ON_UNKNOWN",
    apply: () => mutate(apiPath, 'return jsonResponse(x402Result.body, { status: x402Result.status });', 'return jsonResponse({ ok: true }, { status: 200 });'),
  },
];

process.on("SIGINT", () => { stopping = true; void restore().finally(() => process.exit(130)); });
process.on("SIGTERM", () => { stopping = true; void restore().finally(() => process.exit(143)); });

const rows = [];
try {
  const baseline = await runSuite();
  const baselineFailures = failedTests(baseline);
  if (baseline.code !== 0 || baselineFailures === null || baselineFailures.length) {
    console.error("Baseline is red or Vitest JSON could not be read; refusing to run mutants.");
    console.error(baseline.stderr || baseline.error || "No assertion report available");
    process.exitCode = 1;
  } else {
    console.log("Baseline: PASS");
    for (const mutant of mutations) {
      if (stopping) break;
      let status = "error";
      let observed = "";
      try {
        await mutant.apply();
        const result = await runSuite();
        const failures = failedTests(result);
        if (failures === null || result.error || result.code === 0) {
          status = result.code === 0 ? "survived" : "error";
          observed = result.error ?? (failures === null ? "no assertion report" : "suite passed");
        } else {
          const aimedFailure = failures.find((name) => name.includes(mutant.aimed));
          if (aimedFailure) { status = "killed"; observed = aimedFailure; }
          else { status = "error"; observed = result.stderr || failures.join("; ") || "runner failed without assertion details"; }
        }
      } catch (error) {
        status = "error";
        observed = error instanceof Error ? error.message : String(error);
      } finally {
        await restore();
      }
      rows.push({ mutant: mutant.name, aimed: mutant.aimed, status, observed });
    }
  }
} finally {
  await restore();
}

console.log("| Mutant | Aimed test | Result | Evidence |");
console.log("|---|---|---|---|");
for (const row of rows) console.log(`| ${row.mutant} | ${row.aimed} | ${row.status.toUpperCase()} | ${row.observed.replaceAll("|", "\\|")} |`);
if (rows.length !== mutations.length || rows.some((row) => row.status !== "killed")) process.exitCode = 1;
