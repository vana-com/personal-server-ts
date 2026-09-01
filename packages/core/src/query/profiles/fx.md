---
id: fx
title: Exchange rates
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - fx.*
summary: Daily USD/JPY rates, one row per day. The field is `jpy_per_usd` — how many JPY one USD buys — so you divide a JPY amount by it. Multiplying instead is off by a factor of ~22,000 and looks like a plausible number.
---

> **Describes the seeded fixture corpus, not a market data feed.** A real rate
> source carries many currency pairs, bid/ask spreads and intraday ticks. This
> has one pair and one rate per day.

## Shape

One JSON array, `fx_rates.json`. One row per day of the corpus window:

| Field         | Type   | Notes                                     |
| ------------- | ------ | ----------------------------------------- |
| `date`        | string | `YYYY-MM-DD`. The join key.               |
| `base`        | string | Always `USD`.                             |
| `quote`       | string | Always `JPY`.                             |
| `jpy_per_usd` | number | How many JPY one USD buys. Four decimals. |

There is a row for **every** day in the window, so a transaction date always
has a rate and you never need to interpolate or carry a rate forward.

## The rule that matters: divide, do not multiply

`jpy_per_usd` is quoted **JPY per one USD**. To convert a JPY amount to USD:

```js
const usd = Math.abs(jpyAmount) / rate.jpy_per_usd;
```

Multiplying instead produces a number roughly **22,000 times too large** on a
rate near 150. That error does not look absurd on a single row — a ¥3,000 lunch
becomes $448,500, which is obviously wrong, but a whole-trip total of
"$82,000,000" reads as a formatting problem rather than an inverted rate, and a
model that spots it often "fixes" it by dividing by 1,000 rather than by
re-deriving the conversion.

The field is named `jpy_per_usd` rather than `rate` precisely so the direction
is stated in the data. Read the name before using the number.

## Join on the transaction's own date

Rates in this corpus **drift day to day** on the `dogfood` profile, by up to a
few percent over a season. Converting a multi-week trip at one flat rate is
therefore wrong even when the direction is right.

```js
const byDate = new Map(fx.map((r) => [r.date, r.jpy_per_usd]));
const usd = Math.abs(txn.amount) / byDate.get(txn.date);
```

Design's requirement for spend questions is FX applied **at transaction date**,
not at today's rate and not at an average. State the basis you used in the
answer — "converted at each transaction's own date" — because a reader cannot
otherwise tell which of the three you did.

## Known gaps

- **One currency pair only.** A transaction in any currency other than USD or
  JPY has no rate here. Say so rather than guessing one.
- **No intraday rates.** Everything is a daily close; a same-day pair of
  transactions converts at one rate.
- **No fees or card spreads.** A real card charge differs from the mid-market
  rate by a percent or two. Do not present a converted figure as the exact
  amount billed.
