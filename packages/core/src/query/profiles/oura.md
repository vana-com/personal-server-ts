---
id: oura
title: Oura Ring
profileVersion: 1
schemaVersion: oura-api-v2/1.37
scopes:
  - oura.*
summary: Oura API v2 documents. Durations are seconds. A day can hold several sleep periods — averaging them all understates sleep by ~11%.
---

## Shape

Oura API v2 `usercollection/*` documents, one JSON array per collection. Common
collections: `sleep`, `daily_sleep`, `daily_activity`, `daily_readiness`,
`heartrate`, `workout`, `daily_spo2`. Others exist (`daily_stress`,
`daily_resilience`, `session`, `tag`, `enhanced_tag`, `sleep_time`, `vO2_max`,
`rest_mode_period`, `ring_configuration`, `personal_info`) — enumerate what is
actually present rather than assuming this list.

Volume for a multi-year user: a few thousand daily rows per collection, plus
10^5+ `heartrate` samples. Small enough to read whole. There is no prose here —
never treat an Oura scope as text to search.

## Units

Seconds for every duration (`total_sleep_duration`, `time_in_bed`,
`awake_time`, `latency`, `deep_sleep_duration`, `rem_sleep_duration`,
`light_sleep_duration`, `*_activity_time`, `resting_time`, `non_wear_time`).
Meters for distance. Kilocalories for calories. Degrees Celsius for
`temperature_deviation`. Divide by 3600 for hours, and say so in the answer.

## The rule that matters: one day, several sleep periods

`sleep` holds **one row per sleep period, not per day**. A day with a nap has
two or more rows. `period` is the period index within the day.

`type` is the discriminator, and it has five values, not two:

| `type`       | Meaning                                                                             | Include in "sleep"?            |
| ------------ | ----------------------------------------------------------------------------------- | ------------------------------ |
| `long_sleep` | Sleep over 3h; contributes to daily scores automatically                            | **Yes — this is main sleep**   |
| `sleep`      | User-confirmed sleep/nap, 15 min to 3 h                                             | No, unless naps were asked for |
| `late_nap`   | Confirmed nap ending after the 18:00 sleep-day change; counts toward the _next_ day | No, unless naps were asked for |
| `rest`       | Falsely detected sleep, rejected by the user in the confirm prompt                  | **Never**                      |
| `deleted`    | Sleep deleted by the user                                                           | **Never**                      |

**Unless the question is about naps, filter to `type === "long_sleep"` before
you average anything.** Averaging every row mixes 40-minute naps into a nightly
mean and reports roughly 5.8 h where the true figure is 6.5 h — an ~11% error,
biased toward "you sleep less than you do", with nothing in the output to show
that anything went wrong. `rest` and `deleted` rows are worse: the user
explicitly rejected or removed them, so they must be dropped from every
calculation, including nap questions.

State the filter you applied and the denominator: "6.5 h over 28 of 31 nights,
main sleep periods only, naps excluded".

## `daily_sleep` cannot answer "how much did I sleep"

`daily_sleep` documents are `{id, day, timestamp, score, contributors}`. There
is **no duration field on them at all** — `score` is a 1–100 rating, not hours.
Sleep duration comes only from `sleep`. Do not join the two hoping to get one
row per night; `sleep` is the source for time, `daily_sleep` for score.

## Dates and the day boundary

- `day` (an ISO date) is authoritative: "day that the sleep belongs to". **Bucket
  by `day`. Never re-derive the date from `bedtime_start`.**
- Oura's sleep day changes at **18:00**, not midnight — this is why a nap ending
  after 18:00 is typed `late_nap` and counts toward the next day. A night's sleep
  starting 23:40 therefore belongs to the _following_ calendar date, which is
  what `day` already encodes.
- `bedtime_start` / `bedtime_end` are localized datetime **strings carrying a UTC
  offset**. Parsing one and taking `.toISOString().slice(0, 10)` converts to UTC
  and silently shifts the date for anyone not on UTC. Use the string's own date
  part, or use `day`.
- When joining Oura to another source (commits, nutrition, music), you are
  joining an 18:00-boundary day to a midnight-boundary day. Say which convention
  you used and that they differ.

## Other fields worth getting right

- `total_sleep_duration` is **nullable** and is _not_ `time_in_bed`. `time_in_bed`
  is always present and is always larger. Report which one you used. Rows with a
  null `total_sleep_duration` drop out of the numerator — subtract them from the
  denominator too, and report the count.
- `heartrate` rows are `{timestamp, timestamp_unix, bpm, source}` with `source`
  in `awake | workout | rest | sleep | live | session`. A resting-heart-rate
  baseline that does not filter on `source` is contaminated by workout samples
  and will read high. Pick the sources you mean and name them.
- `sleep.heart_rate` and `sleep.hrv` are sampled objects: `{interval, timestamp,
items}`, where `interval` is seconds between items and `items` **contains
  nulls**. Do not average `items` without dropping nulls, and do not assume a
  fixed length.
- `workout.distance` is in **meters** — "ran more than 10 km" is `distance >
10000`. `workout.source` is `manual | autodetected | confirmed |
workout_heart_rate`; the same session can appear more than once, so dedupe on
  overlapping `start_datetime` / `end_datetime` before counting or summing.
- `daily_spo2.spo2_percentage` is a **nested object** `{average}`, and it is
  nullable. `row.spo2_percentage.average` throws on days with no reading.
- `sleep.average_heart_rate` and `lowest_heart_rate` are computed from 30-second
  samples, while the Oura app displays 5-minute aggregates. Your number will not
  match the user's app screen. Say where it came from.
- `sleep_algorithm_version` is `v1` or `v2`. A multi-year window spans the change,
  so durations from before and after are not strictly comparable. Mention it for
  any baseline drawn over more than a year or so.

## Known gaps and unverified points

- **Heart-rate sampling cadence is not documented.** `PublicHeartRateRow` carries
  no interval field. Do not assume 5-minute samples, and do not compute "time
  spent above X bpm" by multiplying a sample count by an assumed interval —
  measure the actual gaps between timestamps and report them.
- **The exact day-boundary arithmetic is only partly specified.** The 18:00
  sleep-day change is documented for `late_nap`; the general rule for every edge
  case is not. Trust the `day` field; if a question forces you to bucket
  something yourself, state the rule you chose.
- **CSV exports from the Oura mobile app are not covered here.** Column names and
  units in those files are unverified. If the scope is CSV rather than API JSON,
  treat this profile as approximate and lower your confidence.
- Exports assembled by paging the API (`next_token`) can have gaps or duplicate
  documents at page boundaries. Check for duplicate `id` values and for missing
  days before reporting a complete window.

_Field names, types, units, the `type` and `source` enums, the 18:00 sleep-day
change, and the absence of durations on `daily_sleep` were read from the Oura
API v2 OpenAPI specification, version 1.37 (`cloud.ouraring.com`)._
