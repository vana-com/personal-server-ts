---
id: calendar
title: Calendar events
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - calendar.*
summary: Events carry a `status` of accepted, declined or tentative. A declined event is a meeting that did not happen — counting it as attendance inflates both meeting counts and who you met.
---

> **Describes the seeded fixture corpus, not a calendar export.** A real
> calendar has recurrence rules, per-attendee responses, organisers and all-day
> events. None of that is here.

## Shape

One JSON array, `calendar.json`.

| Field       | Type     | Notes                                    |
| ----------- | -------- | ---------------------------------------- |
| `start`     | string   | Full ISO 8601 with offset.               |
| `end`       | string   | Full ISO 8601 with offset.               |
| `title`     | string   | Event title.                             |
| `attendees` | string[] | **Array** of display aliases.            |
| `status`    | string   | `accepted` \| `declined` \| `tentative`. |

## The rule that matters: `status` decides whether it happened

**A `declined` event is a meeting the user did not attend** — it is present
because it was invited, not because it occurred. Counting every row inflates
meeting counts and the set of people met, invisibly: a declined invitation looks
identical to an attended one apart from one field.

Filter before counting, and state the rule:

- `accepted` — attended. Include.
- `declined` — not attended. Exclude from attendance and from "who did I meet".
- `tentative` — unresolved. Decide deliberately and say which way; there is no
  correct default, and a total that silently absorbs them is not reproducible.

_"31 meetings — accepted only; 9 declined and 6 tentative excluded"_ is a
complete answer. "31 meetings" is not.

`attendees` uses the same alias vocabulary as Slack and email, where one person
has several forms and two people share the first name Sarah — resolve across
scopes, and report distinct people separately from distinct handles. There is
**no organiser field and no explicit "me"**, so who the user is among the
attendees is inference.

## Titles can resolve an implicitly-defined period

Some events name a period rather than a meeting — a trip, an out-of-office
block. **This is often the only place a period like "my Japan trip" is nameable
at all**, since no other scope states its dates. When a question refers to
something the data does not define as a field, look for a titled event bounding
it, then **state the resolved range before using it**. If a range resolved from
the calendar disagrees with one resolved from transactions, report the
disagreement rather than choosing silently.

## Known gaps

- **No recurrence** (`RRULE`); a weekly standup appears as independent rows.
- **No per-attendee response** — `status` is one value for the whole event.
- **No organiser, location, description or cancellation flag.**
- **Exactly two attendees per event**, so group-size questions cannot be
  exercised; **all events are one hour**, so duration analysis is degenerate —
  "time in meetings" is count times one hour, and should say so.
- **Titles are generated filler** apart from the deliberately named trip block.

_Field names, the three `status` values, the attendee array, the uniform
one-hour duration and the titled trip block were read from the fixture
generator._
