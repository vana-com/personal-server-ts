---
id: nutrition
title: Nutrition log
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - nutrition.*
summary: Self-logged food intake, `total_kcal` per logged day. Logging is partial and lapses on weekends, so the denominator is logged days, not calendar days. This is intake — it is not the `total_calories` an activity tracker reports, which is expenditure.
---

> **Describes the seeded fixture corpus, not a food-tracking export.** A real
> export carries per-item macros, brands and portion sizes. This has meals and
> calories.

## Shape

One JSON array, `nutrition_log.json`. **One row per logged day — days with no
log have no row at all**:

| Field        | Type    | Notes                                            |
| ------------ | ------- | ------------------------------------------------ |
| `day`        | string  | `YYYY-MM-DD`. The join key.                      |
| `entries`    | array   | `{meal, kcal, protein_g}` per meal, 2–4 of them. |
| `total_kcal` | number  | Sum of the day's entries. Use this.              |
| `complete`   | boolean | False when fewer than 3 meals were logged.       |

## The rule that matters: intake is not expenditure

A question about **how much someone eats** is answered from `total_kcal` here.
It is _not_ answered from `total_calories` on an activity or Oura-style daily
scope — that field is energy **burned**, and the two differ by hundreds of
kilocalories in the same person on the same day.

The failure is silent because both are "calories", both are plausible
four-digit numbers, and an activity scope is usually the denser, easier source
to reach for. A measured example from this corpus: the intake answer is
**≈2,055 kcal** while the expenditure proxy is **≈2,403** — a ~350 kcal gap
that reads as a believable answer to the wrong question.

If you use expenditure because intake is unavailable, say which one you used.

## The denominator is logged days, not days

Roughly **six days in ten are logged**, and the gaps are not random — **weekend
logging is materially worse than weekday logging**, by design. So:

- Filtering a date window and dividing by the number of days in the window
  understates intake, because unlogged days count as zero.
- Averaging only logged days is right, but it is a **weekday-biased** average.
  Say so when the window spans weekends.
- Always report `n` — how many days actually had a log — alongside the mean.
  A conditional question ("on days I ran more than 10km") makes this sharper:
  many qualifying days have no log at all, and those days are not zero-calorie
  days, they are unknown days.

```js
const logged = days.filter((d) => byDay.has(d));
const mean =
  logged.reduce((s, d) => s + byDay.get(d).total_kcal, 0) / logged.length;
// report: mean, logged.length, and days.length - logged.length as unknown
```

## `complete: false` days are partial, not light

A day flagged `complete: false` had fewer than three meals logged — the user
recorded breakfast and gave up. Its `total_kcal` is a **floor**, not a light
day. Including them drags a mean downward; excluding them is defensible;
silently treating them as ordinary days is not. State which you did.

## Known gaps

- **No timestamps within a day.** Meal ordering comes from the `meal` label
  only; there is no way to ask when someone ate.
- **No macro completeness.** `protein_g` is present, carbohydrate and fat are
  not, so macro-split questions are unanswerable.
- **No hydration, no supplements, no weight.**
