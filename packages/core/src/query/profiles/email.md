---
id: email
title: Email messages
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - email.*
summary: Flat rows with a single `from` and a single `to`, both display aliases rather than addresses. No threading exists in this data — conversation questions are unanswerable, not merely hard.
---

> **Describes the seeded fixture corpus, not a mail export.** A real mailbox has
> RFC-5322 headers, `In-Reply-To` threading, multi-recipient fields and MIME
> parts. None of that is here.

## Shape

One JSON array, `email.json`.

| Field     | Type   | Notes                                      |
| --------- | ------ | ------------------------------------------ |
| `id`      | string | Row identifier. Cite it.                   |
| `date`    | string | Full ISO 8601 with offset.                 |
| `from`    | string | **A single alias**, not an address list.   |
| `to`      | string | **A single alias**, not an array.          |
| `subject` | string | Short line.                                |
| `body`    | string | Several paragraphs; the bulk of the bytes. |

## The rule that matters: aliases, and one person has several

`from` and `to` hold **display aliases, not canonical addresses**, and one
person appears under several — a name, a handle, one or more addresses — which
may differ from the alias the same person uses in Slack or on a calendar invite.
Counting distinct `from` values counts handles, not correspondents. Resolve
across scopes and report the rule used.

**Two different people share the first name Sarah**, with different handles and
domains. Never resolve a bare first name silently: name who you chose and who
else it could have been.

Both fields are **single strings, not arrays**. `row.to.includes("sarah")` is a
substring test that matches both Sarahs and any address containing the word.
Compare against a resolved alias set with exact equality.

## There is no threading

No `thread_id`, no `In-Reply-To`, no `References`, and subjects do not repeat
with `Re:` prefixes. So "summarise my thread with X", "what was the last reply"
and "how long did that exchange run" **cannot be answered from this scope**.

Say that plainly rather than approximating a thread by grouping on subject or on
sender-and-day — both fabricate structure the data does not contain. Two
messages between the same people are correspondence, not a thread.

`date` is a full timestamp with an offset, unlike the date-only fields in some
other scopes; compare timestamps rather than string prefixes, and say which
timezone you bucketed by.

## Known gaps

- **No threading** (above): no reply latency, conversation length, or
  participants.
- **Single recipient.** No `Cc`, `Bcc`, group mail or mailing lists, so "who was
  on that email" and group-size questions are unanswerable.
- **No folders, labels, read state or attachments** — no spam/archive
  distinction, so every row counts equally as correspondence.
- **No direction marker.** Which alias is the user's own is not designated, so
  any sent-versus-received split is inference; say so.
- **Bodies are generated filler** — a bag of topic words. Tone, sentiment and
  topic analysis are meaningless; exact-phrase search is reliable.

_Field names, the single-string `from`/`to`, the full-ISO `date` and the absence
of any threading field were read from the fixture generator._
