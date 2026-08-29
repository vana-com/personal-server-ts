// Sort benchmark failures into model weakness / harness artifact / fixture limit.
//
// The distinction is the whole point of the exercise: a scoreboard that counts
// "16 failures" without saying which are ours is not a measurement of the
// model. Classification is driven by observable signals in the run record, and
// anything it cannot place lands in `unclassified` rather than being guessed —
// a wrong bucket is worse than an empty one.
//
//   node scripts/classify-bench.mjs <path.json>
import { readFileSync } from "node:fs";

const d = JSON.parse(readFileSync(process.argv[2], "utf8"));
const rows = d.rows ?? [];

/** Questions the corpus cannot grade, per the case notes themselves. */
const FIXTURE_LIMITED = new Set(["Q12"]);

const HARNESS = [
  {
    // The grader falls back to first-number-in-prose when the model set no
    // `value`. On a budget-killed run that number is usually a scan count, so
    // the row reports a wildly wrong figure where the real fault was
    // exhaustion. The number is an artifact; the exhaustion is the finding.
    test: (r) =>
      r.stoppedBecause === "budget" &&
      r.reasons?.some((x) => /expected .* got \d{4,}/.test(x)),
    label: "budget kill, then extractNumber reported a scan count",
  },
  {
    test: (r) => r.reasons?.some((x) => /carried no assistant content/.test(x)),
    label: "null-content crash (loop threw out of the answerer)",
  },
  {
    test: (r) =>
      r.reasons?.some((x) => /coverage\.unreadable is unset/.test(x)),
    label: "coverage.unreadable never populated host-side",
  },
  {
    test: (r) => r.stoppedBecause === "budget",
    label: "budget exhaustion",
  },
];

const buckets = {
  model: [],
  harness: [],
  fixture: [],
  unclassified: [],
};

const ids = [...new Set(rows.map((r) => r.id))];
for (const id of ids) {
  const rs = rows.filter((r) => r.id === id);
  const fails = rs.filter((r) => r.outcome === "fail");
  if (fails.length === 0) continue;

  if (FIXTURE_LIMITED.has(id)) {
    buckets.fixture.push({
      id,
      n: fails.length,
      of: rs.length,
      why: "case notes: corpus models no grant ledger",
    });
    continue;
  }
  const hit = HARNESS.find((h) => fails.some((f) => h.test(f)));
  if (hit) {
    buckets.harness.push({
      id,
      n: fails.length,
      of: rs.length,
      why: hit.label,
    });
    continue;
  }
  // Everything left had what it needed and got it wrong: it produced an answer
  // and the answer did not satisfy the anchors.
  const reason = fails[0].reasons?.[0] ?? "wrong answer";
  if (fails.some((f) => f.value != null || (f.answerHead ?? "").length > 40)) {
    buckets.model.push({
      id,
      n: fails.length,
      of: rs.length,
      why: String(reason).slice(0, 120),
    });
  } else {
    buckets.unclassified.push({
      id,
      n: fails.length,
      of: rs.length,
      why: String(reason).slice(0, 120),
    });
  }
}

for (const [name, list] of Object.entries(buckets)) {
  console.log(`\n=== ${name.toUpperCase()} (${list.length}) ===`);
  for (const b of list)
    console.log(`  ${b.id}  ${b.n}/${b.of} failed  — ${b.why}`);
}
