# Query-layer eval harness (phase 1)

The graded question set from `docs/260828-query-layer-design.md` §3, plus the
seeded corpus it grades against. Everything downstream — the determinism
measurement, the sandbox, the agent loop, any decision about what to
materialize — is decided by numbers this produces.

## Layout

| Path                   | What it is                                                                                |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `fixtures/prng.ts`     | Seeded PRNG and per-stream seed derivation. `Math.random()` appears nowhere.              |
| `fixtures/time.ts`     | Realistic time axes: burstiness, weekday bias, diurnal curves.                            |
| `fixtures/text.ts`     | Filler prose and the identity graph (one person, many handles).                           |
| `fixtures/planted.ts`  | The facts the graded set turns on — Q5's needle, Q8's absence, Q11's anomaly, Q14's trip. |
| `fixtures/profiles.ts` | `small` (~8MB), `full` (~237MB), `lite`.                                                  |
| `fixtures/generate.ts` | The generator. Writes through `FixtureSink`; no Node built-ins.                           |
| `reference/compute.ts` | The independent reference path. Re-reads serialized bytes and recomputes.                 |
| `cases.ts`             | The 18 cases, with expected values from the reference path.                               |
| `runner.ts`            | Grading and reporting against a pluggable answerer.                                       |
| `answerers/`           | A reference answerer (upper bound) and a null answerer (floor).                           |

## Running

The `small` profile generates entirely in memory, so the default run needs no
filesystem and works in a browser, in vitest, and in CI:

```ts
const sink = new MemoryFixtureSink();
await generateCorpus(sink, { profile: "small" });
const report = await runEval({
  answerer: createReferenceAnswerer(sink),
  cases: await buildCases(sink),
  seed: DEFAULT_SEED,
  profile: "small",
});
console.log(formatReport(report));
```

Writing the `full` profile to disk needs a filesystem sink, which lives outside
`packages/core` — that package is imported by `packages/lite` and must stay
browser-safe.

## Why the corpus is generated, not committed

A committed 237MB corpus is unreviewable and unmaintainable. A seed plus a
generator is a few hundred lines, diffable, and reproduces byte for byte. The
tests assert reproducibility directly.

## Two properties worth knowing about

**Every source spans the full 1100-day window.** The generator this replaced
(`docs/query-layer-fixtures/gen*.js`) spaced each source by a fixed delta,
which compressed most of them into a fraction of the intended range —
conversations into ~11 days. Q9 and Q10 are diachronic questions and were
vacuous on that corpus. `spreadTimestamps` is the fix, and
`fixtures/generate.test.ts` guards it.

**The trap cases are structural, not incidental.** The nap error follows from
the nap rate and the duration ranges; the phantom-message rate follows from the
sibling-regeneration rate. Ratios hold across seeds and profiles; absolute
figures do not, so the tests assert ratios and the phase-1 run reports
absolutes.

## Measured traps (seed 20260828)

Sleep figures are identical on `small` and `full`: both keep the 1100-day
window and vary only density, so the sleep axis is profile-independent.

| Trap                                            | Correct        | Naive              | Error                   |
| ----------------------------------------------- | -------------- | ------------------ | ----------------------- |
| Sleep, naps included (31d)                      | 6.58h (n=28)   | 5.73h              | −12.8%                  |
| Sleep, naps included (full)                     | 6.52h (n=1030) | 5.93h              | −9.0%                   |
| Sleep, `type !== "late_nap"` (full)             | 6.52h          | 5.99h              | −8.1%                   |
| Sleep, null duration as zero (full)             | 6.52h          | 6.44h              | −1.2%                   |
| ChatGPT messages (full)                         | 120,003        | 138,047            | +15.0% phantom          |
| Sleep day re-derived from `bedtime_start`       | —              | 1043/1276 misdated | —                       |
| Resting HR baseline, `source` unfiltered        | 55.5 bpm       | 70.5 bpm           | +27%                    |
| Workout sessions, manual/autodetected undeduped | 301            | 334                | +11%                    |
| Run days if `distance` read as km not metres    | 193            | 301                | every workout qualifies |

The `full` profile is 21 files / ~277MB and generates in about 1.6s.

## Grading rules that are deliberate

- A `judged` case with no judge is **skipped**, never passed. A harness that
  scores unjudgeable cases as passes reports a number that looks like progress.
- A numeric case fails if the answer does not state its denominator. Design
  §4.3 makes the denominator part of correctness.
- An absence case fails if it claims complete coverage while unreadable records
  exist, or if the answer text does not mention them. Prompt doc §1: coverage
  is produced by the host, and an incomplete scan has to say so in prose, not
  only in metadata.
