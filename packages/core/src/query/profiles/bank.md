---
id: bank
title: Bank transactions
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - bank.*
summary: Transaction rows carrying an explicit per-row currency. Summing amounts without converting currency produced a total 71x too large — identically, on every run. Amounts are signed; merchant strings are dirty.
---

> **Describes the seeded fixture corpus, not a bank export.** The rules below
> were read from the generator, not from any institution's format. A real export
> has more fields, more currencies and real merchant data.

## Shape

One JSON array, `bank_transactions.json`, sorted ascending by `date`. Each row:

| Field      | Type   | Notes                                              |
| ---------- | ------ | -------------------------------------------------- |
| `date`     | string | `YYYY-MM-DD`. Date only — no time, no timezone.    |
| `merchant` | string | Raw descriptor as the processor emitted it. Dirty. |
| `amount`   | number | **Signed.** See below.                             |
| `currency` | string | ISO-4217. **Varies row to row.**                   |
| `account`  | string | Account identifier.                                |

Low thousands of rows over ~3 years. Read whole; never sample, and never treat
it as text to search.

## The rule that matters: `currency` varies per row

**Every row carries its own `currency`, and a total computed across rows of
different currencies is meaningless unless each amount is converted first.**

This is not hypothetical. Asked "how much did I spend on my Japan trip", a model
that summed `amount` across the trip window returned **550824** against a true
**7727.24** — a **71x overstatement, returned identically on four of four
runs**. Perfectly reproducible, and perfectly wrong: the trip mixes JPY rows
(hundreds to tens of thousands per row) with USD rows (single to triple
digits), so summing the raw numbers adds yen to dollars as though they were the
same unit. Nothing in the output looked unusual.

Before any sum, average or comparison: **group by `currency` first** and
enumerate what is actually present rather than assuming USD; **convert at the
transaction's own `date`**, not at today's rate; and **state the currency, the
rate and the rate's source**. If the set is already one currency, say so.

### There is no exchange rate in this data

**The corpus contains no rate field, no rate table, and no FX reference of any
kind, and the sandbox has no network access.** So a correct conversion is not
derivable from the granted data alone.

Do not let that become a silent guess. Prefer stating the total **per currency,
unconverted** — `¥546,754 plus $4,070.42` is completely correct and hides
nothing. If a single figure is required, convert with an explicitly stated rate
and mark the dependency: _"≈$7,727, converting ¥546,754 at 149.5 JPY/USD — this
rate is my assumption, it is not in your data, and the figure moves about $12
per 0.5 of rate."_ A single number presented without naming the rate is the
failure this section exists to prevent, whether or not it happens to be close.

## Signs: amounts are negative

Spending is a **negative** `amount`, so a raw sum is negative; take absolute
values and say which. Reporting "you spent -7727.24" makes a correct answer look
wrong.

Every row in this fixture is negative — no refunds, credits, deposits or
transfers — so it cannot tell you how a real export signs them. Against real
data, check for positive amounts and decide explicitly whether they belong in a
spend total: a refund offsetting a purchase usually does, a paycheck does not.

## Merchant strings are dirty — normalise before grouping

Descriptors carry processor prefixes, store numbers and terminal ids:

```
SQ *BLUE BOTTLE 9821     AMZN Mktp US*2H9     WHOLEFDS #104
UBER *TRIP               SHELL OIL 4471       TRADER JOES #221
SPOTIFY P0A2             NETFLIX.COM          RENT ACH
```

Grouping on the raw string scatters one merchant across many keys and
under-reports every per-merchant total. Strip a leading processor token
(`SQ *`, `AMZN Mktp`), strip trailing digit runs and `#`-prefixed store numbers,
case-fold, then group — and **report the normalisation applied**. Over-merging
distinct merchants is worse than leaving them split, because it is invisible.

Recurring subscriptions appear on a **fixed monthly cadence**, and some **change
amount partway through the history**. Detect recurrence from cadence plus
normalised merchant, not from the name looking subscription-like. When an amount
changes, report both values and the change date rather than averaging across it
— an average hides exactly the "which ones crept up" signal being asked for.

## Date-range questions: the set is the hard part

Resolving _which rows belong to X_ is the work; the arithmetic is trivial after.

**A charge can fall outside the window it belongs to.** A pre-paid flight or
hotel is charged when booked, often months before travel, so
`date BETWEEN start AND end` silently omits it and the answer is quietly low.
Look for related charges outside the window and say explicitly which you
included and why. `date` has no time component, so a window is inclusive of both
endpoints and no finer than a day. State the window you used.

## Known gaps

- **No FX rate exists in the data** (above). Any single-currency total rests on
  a rate the model supplied, and must say so.
- **Only negative amounts.** No refunds, credits, deposits or transfers, so
  sign handling for those is untested here.
- **One account.** No cross-account transfer double-counting, which is a real
  hazard against a real export: money moved between two of the user's own
  accounts appears as spend in one and income in the other, and must not be
  counted as spending.
- **No categories, no MCC codes, no balances.** Category questions cannot be
  answered from this scope; say so rather than inferring a category from the
  merchant name.
- **No pending vs posted distinction**, no transaction ids, and no duplicate
  detection is possible beyond exact row equality.
- `date` is date-only, so time-of-day spending questions are unanswerable here.

_Field names, the per-row `currency`, the negative sign convention, merchant
descriptor formats, the fixed monthly subscription cadence with mid-history
amount changes, and the absence of any rate field were read from the fixture
generator (`packages/core/src/query/evals/fixtures/generate.ts`). The 550824 vs
7727.24 result is from the phase 2 determinism run, recorded in design §15.3._
