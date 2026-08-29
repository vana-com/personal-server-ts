---
id: browser
title: Browser history
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - browser.*
summary: Visit rows with url, title and time. There is no dwell time and no visit count, so "how much time did I spend on X" is unanswerable — a visit row is one arrival, not a duration.
---

> **Describes the seeded fixture corpus, not a browser export.** A real history
> database has visit counts, transition types and referrers. None of that is
> here.

## Shape

One JSON array, `browser_history.json`. Each row:

| Field        | Type   | Notes                                |
| ------------ | ------ | ------------------------------------ |
| `url`        | string | Full URL.                            |
| `title`      | string | Page title.                          |
| `visit_time` | string | Full ISO 8601 timestamp with offset. |

Tens of thousands of rows — the largest row count of any non-timeseries scope,
and the least informative per row.

## The rule that matters: a visit is an arrival, not a duration

Each row records **one navigation to a URL**. There is no dwell time, no session
grouping, no visit counter and no exit event.

So questions of the form "how much time did I spend on X" **cannot be answered
from this scope.** A model can count visits and can measure the gap between
consecutive rows, but the gap between two visits is not time spent on the first
page — the browser may have been closed, the tab idle, or the user asleep.

Answer with what the data supports — _"142 visits to that domain, most between
21:00 and 23:00"_ — and say explicitly that time-on-page is not recorded.
Silently presenting inter-visit gaps as attention is a fabricated metric, and it
looks entirely plausible in the output.

Counting visits is not counting distinct pages: a page reloaded ten times is ten
rows. State which you counted, and group by hostname rather than full URL for
"what sites" questions — path and query variation otherwise scatters one site
across many keys.

## Known gaps

- **No visit count, dwell time, transition type, or referrer**, so navigation
  paths and time budgets are unavailable.
- **No browser or device identifier**, no incognito flag, and no per-profile
  separation.
- **URLs are synthetic** (`site<N>.com`) and titles are generated filler.
  Domains carry no real-world meaning, so category, interest and topic analysis
  over this scope produce noise that reads like a finding. Do not perform it
  here; if a question needs it, say the data cannot support it.
- No favicon, page content, or search-query extraction.

_Field names, the absence of any duration or visit-count column, and the
synthetic URL and title generation were read from the fixture generator._
