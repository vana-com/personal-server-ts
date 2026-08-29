---
id: notes
title: Notes
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - notes.*
summary: Note rows with a creation date only. `created` is when the note was started, not when its contents were written — dating an idea by it will place a long-lived note at its oldest point.
---

> **Describes the seeded fixture corpus, not a notes export.** A real export
> usually carries a modification time, folders and tags. None of that is here.

## Shape

One JSON array, `notes.json`. Each row:

| Field     | Type   | Notes                                |
| --------- | ------ | ------------------------------------ |
| `id`      | string | Stable identifier. Cite it.          |
| `created` | string | Full ISO 8601 timestamp with offset. |
| `title`   | string | Short line.                          |
| `body`    | string | Several paragraphs. The bulk.        |

Thousands of rows across the full history. Read whole for any existence or
first-occurrence question.

## The rule that matters: `created` is not when the content was written

`created` is the only timestamp. **There is no modification time.**

For a note edited over months or years, `created` marks when it was started —
so using it to date the _ideas inside_ the note attributes every one of them to
the note's oldest moment. For a "when did I first think about X" question this
biases the answer earlier, and there is nothing in the output to show it.

Report a date from this scope as **"first recorded in a note created on
<date>"**, not as "first thought of on <date>", and say that edit history is
unavailable. If a first-occurrence answer rests on a single note, say so — one
row is weak evidence for a date, and a corroborating timestamp from a
message-based scope is stronger.

## First-occurrence questions need time order, not relevance order

For "when did I first…", rank candidates by `created` ascending and examine the
**earliest** matches, not the best-matching ones. A relevance ranking surfaces
the most explicit statement of an idea, which is almost always a later one —
the early mentions are oblique and score badly, and they are exactly what the
question asks for.

If you narrowed the set before searching — by keyword, by date, by any
prefilter — the answer is the earliest match **found**, not the earliest that
exists. Say which, and mark the coverage as prefiltered.

## Known gaps

- **No modification time** (above), no version history, no deletion record.
- **No folders, tags, or notebooks**, so there is no organisational signal and
  no way to distinguish a journal entry from a shopping list.
- **No links between notes**, and no attachments.
- **Bodies are generated filler** — a bag of topic words rather than real
  sentences. Sentiment, theme extraction and "how did my thinking change"
  analysis over them return noise that reads like a finding. Exact-phrase search
  for a planted string is reliable; interpretation is not.
- `title` is a truncated fragment of the same filler and is not a summary of
  the body.

_Field names, the single `created` timestamp with no modification field, and the
filler body generation were read from the fixture generator._
