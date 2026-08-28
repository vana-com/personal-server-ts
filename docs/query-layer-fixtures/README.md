# Query-layer fixtures and benchmark harness

Working scripts from the design measurements in
`../260828-query-layer-design.md` §18. Preserved here because the numbers in
that section came from them and should be reproducible.

- ~~`gen.js` + `gen2.js`~~ — **removed 2026-08-28.** Replaced by the seeded,
  deterministic TS generator at `packages/core/src/query/evals/fixtures/`.
  Run it with `npm run eval` (add `--profile full` for the ~277MB corpus,
  `--keep <dir>` to retain it). The old scripts used unseeded `Math.random()`,
  so nothing they produced was reproducible.
- `bench.js` — times the question corpus against it (Q1 sleep average, Q4
  join, Q5/Q8 exhaustive prose scan, Q6 identities, Q7 merchants, ChatGPT tree
  walk vs naive flatten).
- `bench2.js` — LLM map-reduce unit counts and cost, week-slice token counts,
  scan vs materialized comparison.

`bench.js` / `bench2.js` are throwaway measurement scripts, not production
code, and are kept only because design §18's numbers came from them.

**The date-compression artifact is fixed, and it was far worse than this file
originally claimed.** The note here blamed only `gen2.js` (conversations spaced
90 seconds apart, spanning ~11 days instead of ~3 years). In fact _nearly every
source_ was compressed: notes 278d, email 324d, Spotify 475d — and Spotify
started 200 days _before_ Oura, so the Q4 sleep×music join only partially
overlapped. Heart-rate samples were uniform 24/7 rather than clustered in
sleep. Only bank, calendar and Oura sleep were correct. The replacement
generator spreads every source across the full 1100-day window with realistic
burstiness and diurnal shape, and `generate.test.ts` guards each source at

> 90% of the window.
