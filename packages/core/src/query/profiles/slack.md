---
id: slack
title: Slack messages
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - slack.*
summary: Flat message rows. `ts` is a string of epoch SECONDS, not milliseconds. `user` is a display alias, not an account id — counting distinct `user` values overcounts people roughly threefold.
---

> **Describes the seeded fixture corpus, not a Slack export.** A real export is
> one file per channel per day plus `users.json`, with threads, edits and
> subtypes. None of that is here.

## Shape

One JSON array, `slack_messages.json`, ascending by time.

| Field     | Type   | Notes                                       |
| --------- | ------ | ------------------------------------------- |
| `ts`      | string | **Epoch seconds**, six decimals. See below. |
| `user`    | string | Display alias, not a stable id. See below.  |
| `channel` | string | `#name`; `#dm-<alias>` for direct messages. |
| `text`    | string | Message body.                               |

Thousands to tens of thousands of rows. Read whole for any existence question.

## The rule that matters: `user` is an alias, not an identity

**One person appears under several `user` values**, and their Slack alias
differs from their email address and their calendar name. Counting distinct
`user` strings counts handles, not people — here by roughly a factor of three.

Resolve identity **across scopes** before counting: the same human may be
`Sarah Johnson`, `sarahj`, `sarah@work.com` and `Sarah 🌸`.

**Two distinct people share the first name Sarah**, with different handles and
email domains. Matching on a first name merges them and silently mixes two
people. Match on the full alias set; when a question names someone by first name
only, say who you resolved it to and who else it could have been.

## `ts` is a string of seconds

`ts` is a **string** like `"1712345678.123456"`, in **epoch seconds**.

- `new Date(row.ts)` — invalid date or nonsense year.
- `new Date(Number(row.ts))` — off by 1000x; everything lands in January 1970.
- `new Date(Number(row.ts) * 1000)` — correct.

Either wrong form makes a time filter match nothing, and "no messages in that
window" then looks exactly like a correct negative. **If a time-bounded query
returns zero rows, check the conversion before reporting an absence.** Sort on
`Number(ts)`, not on the string.

Channels beginning `#dm-` are direct messages with the named alias. A question
about a private conversation means that channel _and_ mentions elsewhere.

## Known gaps

- **No threads** (`thread_ts`, replies), no edits, reactions, attachments or
  subtypes. Thread questions are unanswerable from this scope.
- **No `users.json`** — no id-to-person map, so identity resolution is inference
  from alias strings and should be reported as such.
- **Text is generated filler** — a bag of topic words, not real sentences. Topic
  clustering over it is meaningless; planted messages read as real prose.
- No channel metadata: membership, created date, private/public flag.

_Field names, the seconds `ts` format, the `#dm-` convention and the alias sets
were read from the fixture generator and `fixtures/text.ts`._
