---
id: git
title: Git commits
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - git.*
summary: Commit rows with `authored_at` as a local timestamp carrying its own UTC offset. Reading the hour through `toISOString()` shifts every commit by the offset and can move it to the previous day, which inverts any question about what time of day someone works.
---

> **Describes the seeded fixture corpus, not a git export.** There are no
> branches, merges, parents or diffs here — one flat list of commits.

## Shape

One JSON array, `git_commits.json`. Each row:

| Field         | Type   | Notes                                          |
| ------------- | ------ | ---------------------------------------------- |
| `sha`         | string | Stable identifier. Cite it.                    |
| `authored_at` | string | ISO 8601 **with a UTC offset**, e.g. `-08:00`. |
| `repo`        | string | One of a small set of repository names.        |
| `message`     | string | One line.                                      |
| `additions`   | number | Lines added.                                   |
| `deletions`   | number | Lines removed.                                 |

## The rule that matters: read the hour locally, not in UTC

`authored_at` carries the offset the commit was made at. The **local wall-clock
hour is the meaningful one** — "when does this person work" is a question about
their day, not about UTC.

```js
// WRONG: shifts by the offset, and can land on the previous date
new Date(row.authored_at).getUTCHours();

// RIGHT: the hour as written, before the offset
Number(row.authored_at.slice(11, 13));
```

Under a `-08:00` offset a 06:00 commit becomes 14:00 UTC; under `+09:00` a
07:00 commit becomes 22:00 **the previous day**. So the mistake does not merely
blur the answer — it can produce the exact opposite one, turning an early riser
into a night owl, and it moves commits across date boundaries so any join to a
daily scope silently misattributes them.

## Commits are behaviour, and behaviour can contradict what was said

This scope is the _measured_ half of a stated-versus-measured question. If the
text scopes contain someone describing their habits and the commit distribution
disagrees, **report both and name the conflict** — do not pick whichever source
you happened to read. An answer that says "you describe yourself as a night owl,
but 62% of your commits land before 09:00" is the correct shape; one that
reports only the percentage has dropped half the question.

Note the distribution is **skewed, not degenerate**: there is a real early
cluster plus commits spread across the working day. Report a share or a median
hour rather than implying every commit is early.

## Weekends are sparse by construction

Most weekend days have no commits at all. A per-day average across a window
that includes weekends is therefore not a working-day average. Say which you
computed.

## Known gaps

- **No author field.** Every commit is the user's; there is no co-author or
  team attribution, so "who did I work with" is unanswerable here.
- **No branch, parent or merge structure.** Commits are a flat list, so no
  question about branching, reverts or history rewriting can be answered.
- **`additions`/`deletions` are unweighted line counts** with no file paths or
  languages behind them. They are a rough size signal, not a measure of effort.
