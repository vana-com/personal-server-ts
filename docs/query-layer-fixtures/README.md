# Query-layer fixtures and benchmark harness

Working scripts from the design measurements in
`../260828-query-layer-design.md` §18. Preserved here because the numbers in
that section came from them and should be reproducible.

- `gen.js` + `gen2.js` — generate a ~222MB, 13-file, ~10-source synthetic
  personal corpus (Oura with naps, 228k Spotify streams incl. podcast rows,
  10.4k ChatGPT conversations with regenerated sibling branches, Slack, email,
  notes, bank, calendar, browser history). Run `node gen.js <dir>` then
  `node gen2.js <dir>`.
- `bench.js` — times the question corpus against it (Q1 sleep average, Q4
  join, Q5/Q8 exhaustive prose scan, Q6 identities, Q7 merchants, ChatGPT tree
  walk vs naive flatten).
- `bench2.js` — LLM map-reduce unit counts and cost, week-slice token counts,
  scan vs materialized comparison.

These are throwaway measurement scripts, not production code. Phase 1 of the
implementation plan replaces them with a **seeded, deterministic** TS fixture
generator under `packages/core/src/query/evals/`. Known artifact to fix when
porting: `gen2.js` spaces conversations 90 seconds apart, so 10.4k
conversations span ~10 days instead of ~3 years — realistic date spreading is
required for the diachronic questions (Q9, Q10) to mean anything.
