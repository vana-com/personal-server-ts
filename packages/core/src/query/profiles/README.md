# T2 source profiles

Short hand-written prose describing what a data source actually looks like and
which of its rules are implicit. Loaded into the query agent's context for every
granted scope, and surfaced per scope as `profile` on `vana.scopes()`.

These exist for one reason, measured in `docs/260828-query-layer-design.md`
§18.2: an agent handed raw Oura rows has no way to discover that a day can hold
several sleep periods, so it writes a defensible 1:1 join and reports 5.81h
where the truth is 6.48h — an 11.5% error with nothing in the output to show
that anything went wrong. The same holds for ChatGPT's regenerated branches
(+15.0% phantom messages). A profile is what stands between those two numbers.

Profiles are written by us, shipped with the code, and versioned. They are never
authored by the user, and they are not derived from the data at runtime.

## Files

| File                    | Role                                                               |
| ----------------------- | ------------------------------------------------------------------ |
| `<source>.md`           | The authored profile. **Source of truth — edit these.**            |
| `profiles.generated.ts` | The same text inlined as string constants. Generated; do not edit. |
| `index.ts`              | Parsing, scope matching, and `{{PROFILES}}` rendering.             |
| `frontmatter.ts`        | A ~100-line strict parser for the front matter subset below.       |
| `types.ts`              | `SourceProfile`, `RenderedProfiles`.                               |

`packages/core` is imported by `packages/lite` in a browser and may not touch
the filesystem, so the runtime path reads `profiles.generated.ts`, never the
`.md` files. `index.test.ts` re-reads the markdown with `node:fs` (test files are
excluded from the build) and fails if the two have drifted:

```
UPDATE_PROFILES=1 npx vitest run packages/core/src/query/profiles
```

Run that after editing any `.md`, and commit both files.

## Format

Front matter, then markdown. The front matter grammar is `key: scalar` and
`key:` followed by indented `- item` lines. Nothing else parses.

```markdown
---
id: oura # must equal the file name
title: Oura Ring
profileVersion: 1 # bump on any prose change
schemaVersion: oura-api-v2/1.37 # identifies the upstream schema
scopes:
  - oura.* # exact id, or one trailing `.*` wildcard
summary: One or two sentences naming the source's headline trap.
---

## Shape

...
```

`schemaVersion` is what phase 6b keys persisted scripts against: when the
upstream export changes shape, bump it and cached scripts invalidate.
`profileVersion` tracks the prose alone.

An exact scope id beats a wildcard, so a specific `oura.sleep` profile can be
added later without disturbing `oura.*`.

## Writing one

The reader is a competent code-writing model that has never seen this data and
will otherwise produce something defensible and wrong. Optimise for that.

Cover, in roughly this order:

1. **Shape** — files, record structure, volume, whether it is prose or rows.
2. **Units** — and the conversion the answer should state.
3. **The rule that matters** — the one thing that makes a naive parse wrong.
   Give it its own section, say what the wrong answer looks like, and quantify
   the error if it has been measured. This is the reason the file exists; if a
   profile has no such section, it is probably not worth shipping.
4. **Metric definitions** — what "a play", "a message", "sleep" mean here, and
   an instruction to state the definition in the answer.
5. **Known gaps** — required in every profile, and asserted by a test.

Two habits that matter:

- **Prefer "measure it and state it" over a constant.** A duplicate rate or a
  field vocabulary quoted from memory is a claim the profile cannot back.
  Telling the agent to enumerate the values actually present and report what it
  found is both more accurate and more honest.
- **Never launder an unverified fact into a rule.** Everything asserted here
  should be traceable to an official schema, real export, or maintained parser —
  cite it in a closing note. If it could not be verified, it belongs under
  "Known gaps" saying so. A profile that is confidently wrong is worse than no
  profile, because it reintroduces exactly the silent wrongness it exists to
  prevent.

Target ~4KB. The three shipped profiles run 6–7KB because their verified rule
sets are dense; treat that as the ceiling, not the goal.

## Rendering

`renderProfiles(scopes)` returns the `{{PROFILES}}` block plus what it had to
leave out. Full bodies are included while a character budget holds — a model
cannot know it needs a rule it has not read, so summaries are a degradation, not
a default. Profiles past the budget fall back to their `summary` and are listed
in `summarized`; granted scopes with no profile at all are listed in
`unprofiledScopes`. Both belong in the answer's `coverage`, per plan §3 risk 3:
a source without a profile is answered at reduced confidence, and says so.
