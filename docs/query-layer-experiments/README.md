# Reverted query-layer experiments

Three changes that were built, measured at N=3 against the live model, and
reverted because they did not beat the noise band. The design doc records what
each one measured — §19.13, §19.14, §19.15. These patches are the code, kept
because the measurements are worth more than the diffs and someone will
otherwise rebuild them from the doc.

All three apply to `becc984`..`d3c89d3`. Expect drift; they are a starting
point, not a merge.

| Patch                                     | §     | Result                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `19.13-value-provenance.patch`            | 19.13 | Contract rule carrying every figure from the final script's printed output. Complied almost perfectly — full-precision `value` 0/14 → 11/15 — and moved the score by nothing, at +82% input tokens. The premise was wrong: Q11 computes the wrong series, it does not misreport the right one.                                   |
| `19.14-classify-deferred-roundtrip.patch` | 19.14 | `vana.classify` has no implementation and never had one. This wires a deferred round trip, since judgement cannot happen inside a sandbox with no egress and, unlike search, cannot be precomputed. Once reachable it was still called in 0 of 54 runs.                                                                          |
| `19.15-search-deferred-roundtrip.patch`   | 19.15 | Same pattern for `vana.search`, resolved by the existing `search-bridge.ts` over MiniSearch. Called in 1 of 54 runs: the model reimplements search in JavaScript instead, which is the cheaper and more exact choice at 20.2MB. Includes a fix for duplicate MiniSearch ids on multi-file scopes, which made every search throw. |

The two round-trip patches share a mechanism and are the reason to keep any of
this: if the scale test ever shows a scan losing to a ranked prefilter, the
plumbing for both tools already exists here and was verified end to end —
honest denial preserved, grant enforced, coverage accounting kept separate from
`recordsScanned`.
