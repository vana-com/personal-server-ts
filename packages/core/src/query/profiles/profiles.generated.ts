// Generated from the sibling *.md profile documents. Do not edit by hand.
// Regenerate with: UPDATE_PROFILES=1 npx vitest run packages/core/src/query/profiles
export const PROFILE_DOCUMENTS: Record<string, string> = {
  bank: `---
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

One JSON array, \`bank_transactions.json\`, sorted ascending by \`date\`. Each row:

| Field      | Type   | Notes                                              |
| ---------- | ------ | -------------------------------------------------- |
| \`date\`     | string | \`YYYY-MM-DD\`. Date only — no time, no timezone.    |
| \`merchant\` | string | Raw descriptor as the processor emitted it. Dirty. |
| \`amount\`   | number | **Signed.** See below.                             |
| \`currency\` | string | ISO-4217. **Varies row to row.**                   |
| \`account\`  | string | Account identifier.                                |

Low thousands of rows over ~3 years. Read whole; never sample, and never treat
it as text to search.

## The rule that matters: \`currency\` varies per row

**Every row carries its own \`currency\`, and a total computed across rows of
different currencies is meaningless unless each amount is converted first.**

This is not hypothetical. Asked "how much did I spend on my Japan trip", a model
that summed \`amount\` across the trip window returned **550824** against a true
**7727.24** — a **71x overstatement, returned identically on four of four
runs**. Perfectly reproducible, and perfectly wrong: the trip mixes JPY rows
(hundreds to tens of thousands per row) with USD rows (single to triple
digits), so summing the raw numbers adds yen to dollars as though they were the
same unit. Nothing in the output looked unusual.

Before any sum, average or comparison: **group by \`currency\` first** and
enumerate what is actually present rather than assuming USD; **convert at the
transaction's own \`date\`**, not at today's rate; and **state the currency, the
rate and the rate's source**. If the set is already one currency, say so.

### There is no exchange rate in this data

**The corpus contains no rate field, no rate table, and no FX reference of any
kind, and the sandbox has no network access.** So a correct conversion is not
derivable from the granted data alone.

Do not let that become a silent guess. Prefer stating the total **per currency,
unconverted** — \`¥546,754 plus $4,070.42\` is completely correct and hides
nothing. If a single figure is required, convert with an explicitly stated rate
and mark the dependency: _"≈$7,727, converting ¥546,754 at 149.5 JPY/USD — this
rate is my assumption, it is not in your data, and the figure moves about $12
per 0.5 of rate."_ A single number presented without naming the rate is the
failure this section exists to prevent, whether or not it happens to be close.

## Signs: amounts are negative

Spending is a **negative** \`amount\`, so a raw sum is negative; take absolute
values and say which. Reporting "you spent -7727.24" makes a correct answer look
wrong.

Every row in this fixture is negative — no refunds, credits, deposits or
transfers — so it cannot tell you how a real export signs them. Against real
data, check for positive amounts and decide explicitly whether they belong in a
spend total: a refund offsetting a purchase usually does, a paycheck does not.

## Merchant strings are dirty — normalise before grouping

Descriptors carry processor prefixes, store numbers and terminal ids:

\`\`\`
SQ *BLUE BOTTLE 9821     AMZN Mktp US*2H9     WHOLEFDS #104
UBER *TRIP               SHELL OIL 4471       TRADER JOES #221
SPOTIFY P0A2             NETFLIX.COM          RENT ACH
\`\`\`

Grouping on the raw string scatters one merchant across many keys and
under-reports every per-merchant total. Strip a leading processor token
(\`SQ *\`, \`AMZN Mktp\`), strip trailing digit runs and \`#\`-prefixed store numbers,
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
\`date BETWEEN start AND end\` silently omits it and the answer is quietly low.
Look for related charges outside the window and say explicitly which you
included and why. \`date\` has no time component, so a window is inclusive of both
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
- \`date\` is date-only, so time-of-day spending questions are unanswerable here.

_Field names, the per-row \`currency\`, the negative sign convention, merchant
descriptor formats, the fixed monthly subscription cadence with mid-history
amount changes, and the absence of any rate field were read from the fixture
generator (\`packages/core/src/query/evals/fixtures/generate.ts\`). The 550824 vs
7727.24 result is from the phase 2 determinism run, recorded in design §15.3._
`,
  browser: `---
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

One JSON array, \`browser_history.json\`. Each row:

| Field        | Type   | Notes                                |
| ------------ | ------ | ------------------------------------ |
| \`url\`        | string | Full URL.                            |
| \`title\`      | string | Page title.                          |
| \`visit_time\` | string | Full ISO 8601 timestamp with offset. |

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
- **URLs are synthetic** (\`site<N>.com\`) and titles are generated filler.
  Domains carry no real-world meaning, so category, interest and topic analysis
  over this scope produce noise that reads like a finding. Do not perform it
  here; if a question needs it, say the data cannot support it.
- No favicon, page content, or search-query extraction.

_Field names, the absence of any duration or visit-count column, and the
synthetic URL and title generation were read from the fixture generator._
`,
  calendar: `---
id: calendar
title: Calendar events
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - calendar.*
summary: Events carry a \`status\` of accepted, declined or tentative. A declined event is a meeting that did not happen — counting it as attendance inflates both meeting counts and who you met.
---

> **Describes the seeded fixture corpus, not a calendar export.** A real
> calendar has recurrence rules, per-attendee responses, organisers and all-day
> events. None of that is here.

## Shape

One JSON array, \`calendar.json\`.

| Field       | Type     | Notes                                    |
| ----------- | -------- | ---------------------------------------- |
| \`start\`     | string   | Full ISO 8601 with offset.               |
| \`end\`       | string   | Full ISO 8601 with offset.               |
| \`title\`     | string   | Event title.                             |
| \`attendees\` | string[] | **Array** of display aliases.            |
| \`status\`    | string   | \`accepted\` \\| \`declined\` \\| \`tentative\`. |

## The rule that matters: \`status\` decides whether it happened

**A \`declined\` event is a meeting the user did not attend** — it is present
because it was invited, not because it occurred. Counting every row inflates
meeting counts and the set of people met, invisibly: a declined invitation looks
identical to an attended one apart from one field.

Filter before counting, and state the rule:

- \`accepted\` — attended. Include.
- \`declined\` — not attended. Exclude from attendance and from "who did I meet".
- \`tentative\` — unresolved. Decide deliberately and say which way; there is no
  correct default, and a total that silently absorbs them is not reproducible.

_"31 meetings — accepted only; 9 declined and 6 tentative excluded"_ is a
complete answer. "31 meetings" is not.

\`attendees\` uses the same alias vocabulary as Slack and email, where one person
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

- **No recurrence** (\`RRULE\`); a weekly standup appears as independent rows.
- **No per-attendee response** — \`status\` is one value for the whole event.
- **No organiser, location, description or cancellation flag.**
- **Exactly two attendees per event**, so group-size questions cannot be
  exercised; **all events are one hour**, so duration analysis is degenerate —
  "time in meetings" is count times one hour, and should say so.
- **Titles are generated filler** apart from the deliberately named trip block.

_Field names, the three \`status\` values, the attendee array, the uniform
one-hour duration and the titled trip block were read from the fixture
generator._
`,
  chatgpt: `---
id: chatgpt
title: ChatGPT export
profileVersion: 1
schemaVersion: chatgpt-export/2026-08
scopes:
  - chatgpt.*
summary: ChatGPT conversation export. Each conversation is a tree, not a list — flattening it invents ~15% of messages that were never sent.
---

## Shape

\`conversations.json\` is an array of conversations. Each conversation is roughly:

\`\`\`
{ conversation_id, title, create_time, update_time,
  current_node: "<node id>",
  mapping: { "<node id>": { id, message, parent, children: [...] }, ... } }
\`\`\`

A node's \`message\` is \`null\` for the synthetic root and for some structural
nodes. A message is roughly \`{id, author: {role}, create_time, content:
{content_type, parts, ...}, metadata, recipient, status, weight}\`.

Timestamps are **unix seconds as floats** (not milliseconds, not ISO strings).
\`create_time\` on a message is **nullable**.

This is the one source in a typical corpus that is mostly prose, and the one
worth reading as text. Volume for a heavy 2–3 year user: 100–200 MB, 10^4
conversations, 10^5 messages.

## The rule that matters: a conversation is a tree

\`mapping\` is a **tree, not a transcript**. Every edit of a prompt and every
regenerated answer is added as an **additional child of the same parent** — a
sibling — and nothing is overwritten. The abandoned branches stay in the file
forever.

\`Object.values(mapping)\` therefore returns every message the user ever saw _and
every draft they discarded_. Flattening it and sorting by \`create_time\` yields
roughly **15% more messages than were actually exchanged**, inflating every
count, every "how often did I", and every date range built on it. The phantom
messages look completely ordinary; there is no field that marks them.

**The correct reconstruction is the only one: start at \`current_node\`, follow
\`parent\` to the root, collect, and reverse.**

\`\`\`js
function activeBranch(conversation) {
  const out = [];
  const seen = new Set();
  let id = conversation.current_node;
  while (id && !seen.has(id)) {
    seen.add(id);
    const node = conversation.mapping[id];
    if (!node) break;
    if (node.message) out.push(node.message);
    id = node.parent;
  }
  return out.reverse();
}
\`\`\`

The \`seen\` guard is not decoration — malformed exports do contain cycles, and a
naive walk hangs. Also handle a \`current_node\` that is missing from \`mapping\`.

If a question genuinely is about drafts and regenerations, walk the whole
\`mapping\` deliberately and **say that you did** — the count means something
different from the count of messages exchanged.

## Exports are snapshots, never increments

Every export is a **full dump of the account at that moment**. Two exports are
not two halves of a history; the newer one contains the older one, plus edits.
If a scope holds more than one export, deduplicate by \`conversation_id\` and keep
the copy with the newest \`update_time\` before counting anything. Concatenating
them doubles the corpus.

Deletion is invisible: a conversation the user deleted is simply absent from
later exports. You cannot tell "deleted" from "never existed", so do not claim a
conversation was removed.

## Counting messages honestly

Even on the correct branch, not every message is one the user exchanged:

- \`author.role\` is \`user | assistant | system | tool | function\`. \`system\`
  includes injected custom instructions; \`tool\` and \`function\` are model
  plumbing.
- \`metadata.is_visually_hidden_from_conversation\` marks messages the UI never
  showed.
- Content types like \`code\` (code-interpreter input), \`thoughts\` (reasoning),
  and browsing status updates are internal even when the role is \`assistant\`.
- \`weight: 0\` marks a message dropped from the model's context.

"How many messages" has at least three defensible answers. Pick one — usually
\`role === "user"\` on the active branch, excluding hidden messages — and **state
the rule you used** alongside the number.

## Reading message text

\`content.parts\` is nullable, and its items are **not always strings**. A part
can be an object such as \`{content_type: "image_asset_pointer",
asset_pointer: "file-service://..."}\`. \`parts.join("")\` throws or produces
\`[object Object]\` and quietly corrupts character counts and search.

Text can also live outside \`parts\` depending on \`content_type\`: \`content.text\`
(quotes from browsing), \`content.result\` (tool output), \`content.thoughts\` (a
list of \`{summary, content}\` reasoning objects), \`content.content\` (canvas and
reasoning recaps). Extract defensively: filter \`parts\` to strings, then fall
back to the other fields, and skip what you cannot read rather than coercing it.

Attachments appear under \`metadata.attachments\`; their contents are **not** in
\`conversations.json\`. If a question depends on an attached file, say it was not
readable.

## Dates

- Use \`message.create_time\` where present; fall back to the conversation's
  \`create_time\`, and say you did.
- \`create_time\` can be \`null\` on individual messages. Do not let a null become
  epoch 1970 — that would make it the "earliest" record and answer a
  first-occurrence question with a date that does not exist.
- The conversation's \`create_time\` is when the thread started, which can be years
  before a message added to it. For "when did I first say X", use the message's
  own timestamp and order by time, not by relevance.

## Known gaps and unverified points

- **The full list of files in a current export is not verified here.**
  \`conversations.json\` is the substantive one; other files (chat HTML, user
  metadata, feedback) may or may not be present and their shapes are unconfirmed.
  Enumerate what the scope actually contains.
- **The export schema drifts.** Fields have been added and removed over time —
  some 2026-era exports omit \`status\` and \`weight\` on messages. Treat every field
  outside \`mapping\` / \`current_node\` / \`parent\` / \`children\` / \`author.role\` /
  \`content\` as optional and guard accordingly.
- \`title\` can be \`null\`.
- Whether a given conversation's \`current_node\` points at the branch the user
  last _viewed_ versus last _created_ is not documented. It is the best available
  signal for "what the conversation actually says", and it is what this profile
  tells you to use, but it is not a guarantee.

_The tree-walk reconstruction, the message and content field shapes, the role
enum, hidden-message handling and the cycle guard were checked against
\`mohamed-chs/convoviz\`, a maintained open-source parser of this export format.
The export's file inventory was not verifiable from OpenAI's documentation._
`,
  documents: `---
id: documents
title: Documents
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - documents.*
summary: PDF records where \`text_extracted\` is nullable. A document that failed extraction is one you have not read, not an empty one — treating it as empty turns "I found nothing" into a false negative.
---

> **Describes the seeded fixture corpus, not a document store.**

## Shape

One JSON array, \`documents.json\`. A few hundred rows — always read all of them,
since this scope exists to answer existence questions and those require totality.

| Field              | Type           | Notes                                    |
| ------------------ | -------------- | ---------------------------------------- |
| \`id\`               | string         | Stable identifier. Cite it.              |
| \`title\`            | string         | Document title.                          |
| \`content_type\`     | string         | MIME type.                               |
| \`created\`          | string         | \`YYYY-MM-DD\`, date only.                 |
| \`text_extracted\`   | string \\| null | **Nullable.** Body, or null.             |
| \`extraction_error\` | string \\| null | Non-null exactly when extraction failed. |

## The rule that matters: null \`text_extracted\` is unread, not empty

Some documents have \`text_extracted: null\` and a non-null \`extraction_error\`.
These are **real documents whose contents were never extracted** — scanned
images with no text layer. They are not empty. They are documents you **have not
read**.

This decides whether an absence answer is honest. A search that skips them and
reports "there is nothing like that in your documents" makes a completeness
claim it cannot support — the answer could be in a file that never got a text
layer. That is the worst failure mode in this system: a confident "no" the user
cannot distinguish from a correct one.

For any "have I ever" or "is there any" question:

1. **Partition** into readable (\`text_extracted\` non-null) and unreadable.
2. **Search the readable set exhaustively** — every row, not a top-k.
3. **Report both counts**, scoped, never absolute: _"No match across the 318
   documents whose text could be read. 22 could not be read (\`extraction_error\`:
   'scanned image, no text layer'), so I cannot rule out a match in those."_

Never write "no such document exists" while unread documents remain.
\`row.text_extracted.includes(...)\` throws on null rows — a truthiness guard that
quietly skips them produces exactly the dishonest negative above. Guard
deliberately and count what you skipped.

## Match substance, not keywords

The corpus contains documents sharing vocabulary with a conflict question
without being one — an unexecuted draft, a declined offer, an expired agreement.
A keyword scan flags all of them. Before reporting a match, check whether it is
**in force**: executed rather than draft, accepted rather than declined, current
rather than expired. _"Three documents mention exclusivity; one is an unsigned
draft, one was declined, one expired, so none is a live conflict"_ is far more
useful than either a bare "no" or three false positives.

## Known gaps

- **All rows are \`application/pdf\`**; no images, spreadsheets or office formats.
- **No file size, page count, author, or modification date**; no folder or
  source path, so provenance and sharing are unknown.
- **One error reason string** for every failed row, so the corpus cannot
  distinguish an encrypted PDF from a scan from a corrupt file. Against real
  data, read the actual error.
- **Readable bodies are generated filler** apart from planted documents;
  semantic similarity is meaningless, exact-phrase search is not.
- \`created\` is date-only. No versioning: an amended document appears as
  unrelated rows, if at all.

_Field names, the nullable \`text_extracted\` paired with a non-null
\`extraction_error\`, and the non-binding near-miss documents were read from the
fixture generator._
`,
  email: `---
id: email
title: Email messages
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - email.*
summary: Flat rows with a single \`from\` and a single \`to\`, both display aliases rather than addresses. No threading exists in this data — conversation questions are unanswerable, not merely hard.
---

> **Describes the seeded fixture corpus, not a mail export.** A real mailbox has
> RFC-5322 headers, \`In-Reply-To\` threading, multi-recipient fields and MIME
> parts. None of that is here.

## Shape

One JSON array, \`email.json\`.

| Field     | Type   | Notes                                      |
| --------- | ------ | ------------------------------------------ |
| \`id\`      | string | Row identifier. Cite it.                   |
| \`date\`    | string | Full ISO 8601 with offset.                 |
| \`from\`    | string | **A single alias**, not an address list.   |
| \`to\`      | string | **A single alias**, not an array.          |
| \`subject\` | string | Short line.                                |
| \`body\`    | string | Several paragraphs; the bulk of the bytes. |

## The rule that matters: aliases, and one person has several

\`from\` and \`to\` hold **display aliases, not canonical addresses**, and one
person appears under several — a name, a handle, one or more addresses — which
may differ from the alias the same person uses in Slack or on a calendar invite.
Counting distinct \`from\` values counts handles, not correspondents. Resolve
across scopes and report the rule used.

**Two different people share the first name Sarah**, with different handles and
domains. Never resolve a bare first name silently: name who you chose and who
else it could have been.

Both fields are **single strings, not arrays**. \`row.to.includes("sarah")\` is a
substring test that matches both Sarahs and any address containing the word.
Compare against a resolved alias set with exact equality.

## There is no threading

No \`thread_id\`, no \`In-Reply-To\`, no \`References\`, and subjects do not repeat
with \`Re:\` prefixes. So "summarise my thread with X", "what was the last reply"
and "how long did that exchange run" **cannot be answered from this scope**.

Say that plainly rather than approximating a thread by grouping on subject or on
sender-and-day — both fabricate structure the data does not contain. Two
messages between the same people are correspondence, not a thread.

\`date\` is a full timestamp with an offset, unlike the date-only fields in some
other scopes; compare timestamps rather than string prefixes, and say which
timezone you bucketed by.

## Known gaps

- **No threading** (above): no reply latency, conversation length, or
  participants.
- **Single recipient.** No \`Cc\`, \`Bcc\`, group mail or mailing lists, so "who was
  on that email" and group-size questions are unanswerable.
- **No folders, labels, read state or attachments** — no spam/archive
  distinction, so every row counts equally as correspondence.
- **No direction marker.** Which alias is the user's own is not designated, so
  any sent-versus-received split is inference; say so.
- **Bodies are generated filler** — a bag of topic words. Tone, sentiment and
  topic analysis are meaningless; exact-phrase search is reliable.

_Field names, the single-string \`from\`/\`to\`, the full-ISO \`date\` and the absence
of any threading field were read from the fixture generator._
`,
  fx: `---
id: fx
title: Exchange rates
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - fx.*
summary: Daily USD/JPY rates, one row per day. The field is \`jpy_per_usd\` — how many JPY one USD buys — so you divide a JPY amount by it. Multiplying instead is off by a factor of ~22,000 and looks like a plausible number.
---

> **Describes the seeded fixture corpus, not a market data feed.** A real rate
> source carries many currency pairs, bid/ask spreads and intraday ticks. This
> has one pair and one rate per day.

## Shape

One JSON array, \`fx_rates.json\`. One row per day of the corpus window:

| Field         | Type   | Notes                                     |
| ------------- | ------ | ----------------------------------------- |
| \`date\`        | string | \`YYYY-MM-DD\`. The join key.               |
| \`base\`        | string | Always \`USD\`.                             |
| \`quote\`       | string | Always \`JPY\`.                             |
| \`jpy_per_usd\` | number | How many JPY one USD buys. Four decimals. |

There is a row for **every** day in the window, so a transaction date always
has a rate and you never need to interpolate or carry a rate forward.

## The rule that matters: divide, do not multiply

\`jpy_per_usd\` is quoted **JPY per one USD**. To convert a JPY amount to USD:

\`\`\`js
const usd = Math.abs(jpyAmount) / rate.jpy_per_usd;
\`\`\`

Multiplying instead produces a number roughly **22,000 times too large** on a
rate near 150. That error does not look absurd on a single row — a ¥3,000 lunch
becomes $448,500, which is obviously wrong, but a whole-trip total of
"$82,000,000" reads as a formatting problem rather than an inverted rate, and a
model that spots it often "fixes" it by dividing by 1,000 rather than by
re-deriving the conversion.

The field is named \`jpy_per_usd\` rather than \`rate\` precisely so the direction
is stated in the data. Read the name before using the number.

## Join on the transaction's own date

Rates in this corpus **drift day to day** on the \`dogfood\` profile, by up to a
few percent over a season. Converting a multi-week trip at one flat rate is
therefore wrong even when the direction is right.

\`\`\`js
const byDate = new Map(fx.map((r) => [r.date, r.jpy_per_usd]));
const usd = Math.abs(txn.amount) / byDate.get(txn.date);
\`\`\`

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
`,
  git: `---
id: git
title: Git commits
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - git.*
summary: Commit rows with \`authored_at\` as a local timestamp carrying its own UTC offset. Reading the hour through \`toISOString()\` shifts every commit by the offset and can move it to the previous day, which inverts any question about what time of day someone works.
---

> **Describes the seeded fixture corpus, not a git export.** There are no
> branches, merges, parents or diffs here — one flat list of commits.

## Shape

One JSON array, \`git_commits.json\`. Each row:

| Field         | Type   | Notes                                          |
| ------------- | ------ | ---------------------------------------------- |
| \`sha\`         | string | Stable identifier. Cite it.                    |
| \`authored_at\` | string | ISO 8601 **with a UTC offset**, e.g. \`-08:00\`. |
| \`repo\`        | string | One of a small set of repository names.        |
| \`message\`     | string | One line.                                      |
| \`additions\`   | number | Lines added.                                   |
| \`deletions\`   | number | Lines removed.                                 |

## The rule that matters: read the hour locally, not in UTC

\`authored_at\` carries the offset the commit was made at. The **local wall-clock
hour is the meaningful one** — "when does this person work" is a question about
their day, not about UTC.

\`\`\`js
// WRONG: shifts by the offset, and can land on the previous date
new Date(row.authored_at).getUTCHours();

// RIGHT: the hour as written, before the offset
Number(row.authored_at.slice(11, 13));
\`\`\`

Under a \`-08:00\` offset a 06:00 commit becomes 14:00 UTC; under \`+09:00\` a
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
- **\`additions\`/\`deletions\` are unweighted line counts** with no file paths or
  languages behind them. They are a rough size signal, not a measure of effort.
`,
  notes: `---
id: notes
title: Notes
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - notes.*
summary: Note rows with a creation date only. \`created\` is when the note was started, not when its contents were written — dating an idea by it will place a long-lived note at its oldest point.
---

> **Describes the seeded fixture corpus, not a notes export.** A real export
> usually carries a modification time, folders and tags. None of that is here.

## Shape

One JSON array, \`notes.json\`. Each row:

| Field     | Type   | Notes                                |
| --------- | ------ | ------------------------------------ |
| \`id\`      | string | Stable identifier. Cite it.          |
| \`created\` | string | Full ISO 8601 timestamp with offset. |
| \`title\`   | string | Short line.                          |
| \`body\`    | string | Several paragraphs. The bulk.        |

Thousands of rows across the full history. Read whole for any existence or
first-occurrence question.

## The rule that matters: \`created\` is not when the content was written

\`created\` is the only timestamp. **There is no modification time.**

For a note edited over months or years, \`created\` marks when it was started —
so using it to date the _ideas inside_ the note attributes every one of them to
the note's oldest moment. For a "when did I first think about X" question this
biases the answer earlier, and there is nothing in the output to show it.

Report a date from this scope as **"first recorded in a note created on
<date>"**, not as "first thought of on <date>", and say that edit history is
unavailable. If a first-occurrence answer rests on a single note, say so — one
row is weak evidence for a date, and a corroborating timestamp from a
message-based scope is stronger.

## First-occurrence questions need time order, not relevance order

For "when did I first…", rank candidates by \`created\` ascending and examine the
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
- \`title\` is a truncated fragment of the same filler and is not a summary of
  the body.

_Field names, the single \`created\` timestamp with no modification field, and the
filler body generation were read from the fixture generator._
`,
  nutrition: `---
id: nutrition
title: Nutrition log
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - nutrition.*
summary: Self-logged food intake, \`total_kcal\` per logged day. Logging is partial and lapses on weekends, so the denominator is logged days, not calendar days. This is intake — it is not the \`total_calories\` an activity tracker reports, which is expenditure.
---

> **Describes the seeded fixture corpus, not a food-tracking export.** A real
> export carries per-item macros, brands and portion sizes. This has meals and
> calories.

## Shape

One JSON array, \`nutrition_log.json\`. **One row per logged day — days with no
log have no row at all**:

| Field        | Type    | Notes                                            |
| ------------ | ------- | ------------------------------------------------ |
| \`day\`        | string  | \`YYYY-MM-DD\`. The join key.                      |
| \`entries\`    | array   | \`{meal, kcal, protein_g}\` per meal, 2–4 of them. |
| \`total_kcal\` | number  | Sum of the day's entries. Use this.              |
| \`complete\`   | boolean | False when fewer than 3 meals were logged.       |

## The rule that matters: intake is not expenditure

A question about **how much someone eats** is answered from \`total_kcal\` here.
It is _not_ answered from \`total_calories\` on an activity or Oura-style daily
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
- Always report \`n\` — how many days actually had a log — alongside the mean.
  A conditional question ("on days I ran more than 10km") makes this sharper:
  many qualifying days have no log at all, and those days are not zero-calorie
  days, they are unknown days.

\`\`\`js
const logged = days.filter((d) => byDay.has(d));
const mean =
  logged.reduce((s, d) => s + byDay.get(d).total_kcal, 0) / logged.length;
// report: mean, logged.length, and days.length - logged.length as unknown
\`\`\`

## \`complete: false\` days are partial, not light

A day flagged \`complete: false\` had fewer than three meals logged — the user
recorded breakfast and gave up. Its \`total_kcal\` is a **floor**, not a light
day. Including them drags a mean downward; excluding them is defensible;
silently treating them as ordinary days is not. State which you did.

## Known gaps

- **No timestamps within a day.** Meal ordering comes from the \`meal\` label
  only; there is no way to ask when someone ate.
- **No macro completeness.** \`protein_g\` is present, carbohydrate and fat are
  not, so macro-split questions are unanswerable.
- **No hydration, no supplements, no weight.**
`,
  oura: `---
id: oura
title: Oura Ring
profileVersion: 1
schemaVersion: oura-api-v2/1.37
scopes:
  - oura.*
summary: Oura API v2 documents. Durations are seconds. A day can hold several sleep periods — averaging them all understates sleep by ~11%.
---

## Shape

Oura API v2 \`usercollection/*\` documents, one JSON array per collection. Common
collections: \`sleep\`, \`daily_sleep\`, \`daily_activity\`, \`daily_readiness\`,
\`heartrate\`, \`workout\`, \`daily_spo2\`. Others exist (\`daily_stress\`,
\`daily_resilience\`, \`session\`, \`tag\`, \`enhanced_tag\`, \`sleep_time\`, \`vO2_max\`,
\`rest_mode_period\`, \`ring_configuration\`, \`personal_info\`) — enumerate what is
actually present rather than assuming this list.

Volume for a multi-year user: a few thousand daily rows per collection, plus
10^5+ \`heartrate\` samples. Small enough to read whole. There is no prose here —
never treat an Oura scope as text to search.

## Units

Seconds for every duration (\`total_sleep_duration\`, \`time_in_bed\`,
\`awake_time\`, \`latency\`, \`deep_sleep_duration\`, \`rem_sleep_duration\`,
\`light_sleep_duration\`, \`*_activity_time\`, \`resting_time\`, \`non_wear_time\`).
Meters for distance. Kilocalories for calories. Degrees Celsius for
\`temperature_deviation\`. Divide by 3600 for hours, and say so in the answer.

## The rule that matters: one day, several sleep periods

\`sleep\` holds **one row per sleep period, not per day**. A day with a nap has
two or more rows. \`period\` is the period index within the day.

\`type\` is the discriminator, and it has five values, not two:

| \`type\`       | Meaning                                                                             | Include in "sleep"?            |
| ------------ | ----------------------------------------------------------------------------------- | ------------------------------ |
| \`long_sleep\` | Sleep over 3h; contributes to daily scores automatically                            | **Yes — this is main sleep**   |
| \`sleep\`      | User-confirmed sleep/nap, 15 min to 3 h                                             | No, unless naps were asked for |
| \`late_nap\`   | Confirmed nap ending after the 18:00 sleep-day change; counts toward the _next_ day | No, unless naps were asked for |
| \`rest\`       | Falsely detected sleep, rejected by the user in the confirm prompt                  | **Never**                      |
| \`deleted\`    | Sleep deleted by the user                                                           | **Never**                      |

**Unless the question is about naps, filter to \`type === "long_sleep"\` before
you average anything.** Averaging every row mixes 40-minute naps into a nightly
mean and reports roughly 5.8 h where the true figure is 6.5 h — an ~11% error,
biased toward "you sleep less than you do", with nothing in the output to show
that anything went wrong. \`rest\` and \`deleted\` rows are worse: the user
explicitly rejected or removed them, so they must be dropped from every
calculation, including nap questions.

State the filter you applied and the denominator: "6.5 h over 28 of 31 nights,
main sleep periods only, naps excluded".

## \`daily_sleep\` cannot answer "how much did I sleep"

\`daily_sleep\` documents are \`{id, day, timestamp, score, contributors}\`. There
is **no duration field on them at all** — \`score\` is a 1–100 rating, not hours.
Sleep duration comes only from \`sleep\`. Do not join the two hoping to get one
row per night; \`sleep\` is the source for time, \`daily_sleep\` for score.

## Dates and the day boundary

- \`day\` (an ISO date) is authoritative: "day that the sleep belongs to". **Bucket
  by \`day\`. Never re-derive the date from \`bedtime_start\`.**
- Oura's sleep day changes at **18:00**, not midnight — this is why a nap ending
  after 18:00 is typed \`late_nap\` and counts toward the next day. A night's sleep
  starting 23:40 therefore belongs to the _following_ calendar date, which is
  what \`day\` already encodes.
- \`bedtime_start\` / \`bedtime_end\` are localized datetime **strings carrying a UTC
  offset**. Parsing one and taking \`.toISOString().slice(0, 10)\` converts to UTC
  and silently shifts the date for anyone not on UTC. Use the string's own date
  part, or use \`day\`.
- When joining Oura to another source (commits, nutrition, music), you are
  joining an 18:00-boundary day to a midnight-boundary day. Say which convention
  you used and that they differ.

## Other fields worth getting right

- \`total_sleep_duration\` is **nullable** and is _not_ \`time_in_bed\`. \`time_in_bed\`
  is always present and is always larger. Report which one you used. Rows with a
  null \`total_sleep_duration\` drop out of the numerator — subtract them from the
  denominator too, and report the count.
- \`heartrate\` rows are \`{timestamp, timestamp_unix, bpm, source}\` with \`source\`
  in \`awake | workout | rest | sleep | live | session\`. A resting-heart-rate
  baseline that does not filter on \`source\` is contaminated by workout samples
  and will read high. Pick the sources you mean and name them.
- \`sleep.heart_rate\` and \`sleep.hrv\` are sampled objects: \`{interval, timestamp,
items}\`, where \`interval\` is seconds between items and \`items\` **contains
  nulls**. Do not average \`items\` without dropping nulls, and do not assume a
  fixed length.
- \`workout.distance\` is in **meters** — "ran more than 10 km" is \`distance >
10000\`. \`workout.source\` is \`manual | autodetected | confirmed |
workout_heart_rate\`; the same session can appear more than once, so dedupe on
  overlapping \`start_datetime\` / \`end_datetime\` before counting or summing.
- \`daily_spo2.spo2_percentage\` is a **nested object** \`{average}\`, and it is
  nullable. \`row.spo2_percentage.average\` throws on days with no reading.
- \`sleep.average_heart_rate\` and \`lowest_heart_rate\` are computed from 30-second
  samples, while the Oura app displays 5-minute aggregates. Your number will not
  match the user's app screen. Say where it came from.
- \`sleep_algorithm_version\` is \`v1\` or \`v2\`. A multi-year window spans the change,
  so durations from before and after are not strictly comparable. Mention it for
  any baseline drawn over more than a year or so.

## Known gaps and unverified points

- **Heart-rate sampling cadence is not documented.** \`PublicHeartRateRow\` carries
  no interval field. Do not assume 5-minute samples, and do not compute "time
  spent above X bpm" by multiplying a sample count by an assumed interval —
  measure the actual gaps between timestamps and report them.
- **The exact day-boundary arithmetic is only partly specified.** The 18:00
  sleep-day change is documented for \`late_nap\`; the general rule for every edge
  case is not. Trust the \`day\` field; if a question forces you to bucket
  something yourself, state the rule you chose.
- **CSV exports from the Oura mobile app are not covered here.** Column names and
  units in those files are unverified. If the scope is CSV rather than API JSON,
  treat this profile as approximate and lower your confidence.
- Exports assembled by paging the API (\`next_token\`) can have gaps or duplicate
  documents at page boundaries. Check for duplicate \`id\` values and for missing
  days before reporting a complete window.

_Field names, types, units, the \`type\` and \`source\` enums, the 18:00 sleep-day
change, and the absence of durations on \`daily_sleep\` were read from the Oura
API v2 OpenAPI specification, version 1.37 (\`cloud.ouraring.com\`)._
`,
  slack: `---
id: slack
title: Slack messages
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - slack.*
summary: Flat message rows. \`ts\` is a string of epoch SECONDS, not milliseconds. \`user\` is a display alias, not an account id — counting distinct \`user\` values overcounts people roughly threefold.
---

> **Describes the seeded fixture corpus, not a Slack export.** A real export is
> one file per channel per day plus \`users.json\`, with threads, edits and
> subtypes. None of that is here.

## Shape

One JSON array, \`slack_messages.json\`, ascending by time.

| Field     | Type   | Notes                                       |
| --------- | ------ | ------------------------------------------- |
| \`ts\`      | string | **Epoch seconds**, six decimals. See below. |
| \`user\`    | string | Display alias, not a stable id. See below.  |
| \`channel\` | string | \`#name\`; \`#dm-<alias>\` for direct messages. |
| \`text\`    | string | Message body.                               |

Thousands to tens of thousands of rows. Read whole for any existence question.

## The rule that matters: \`user\` is an alias, not an identity

**One person appears under several \`user\` values**, and their Slack alias
differs from their email address and their calendar name. Counting distinct
\`user\` strings counts handles, not people — here by roughly a factor of three.

Resolve identity **across scopes** before counting: the same human may be
\`Sarah Johnson\`, \`sarahj\`, \`sarah@work.com\` and \`Sarah 🌸\`.

**Two distinct people share the first name Sarah**, with different handles and
email domains. Matching on a first name merges them and silently mixes two
people. Match on the full alias set; when a question names someone by first name
only, say who you resolved it to and who else it could have been.

## \`ts\` is a string of seconds

\`ts\` is a **string** like \`"1712345678.123456"\`, in **epoch seconds**.

- \`new Date(row.ts)\` — invalid date or nonsense year.
- \`new Date(Number(row.ts))\` — off by 1000x; everything lands in January 1970.
- \`new Date(Number(row.ts) * 1000)\` — correct.

Either wrong form makes a time filter match nothing, and "no messages in that
window" then looks exactly like a correct negative. **If a time-bounded query
returns zero rows, check the conversion before reporting an absence.** Sort on
\`Number(ts)\`, not on the string.

Channels beginning \`#dm-\` are direct messages with the named alias. A question
about a private conversation means that channel _and_ mentions elsewhere.

## Known gaps

- **No threads** (\`thread_ts\`, replies), no edits, reactions, attachments or
  subtypes. Thread questions are unanswerable from this scope.
- **No \`users.json\`** — no id-to-person map, so identity resolution is inference
  from alias strings and should be reported as such.
- **Text is generated filler** — a bag of topic words, not real sentences. Topic
  clustering over it is meaningless; planted messages read as real prose.
- No channel metadata: membership, created date, private/public flag.

_Field names, the seconds \`ts\` format, the \`#dm-\` convention and the alias sets
were read from the fixture generator and \`fixtures/text.ts\`._
`,
  spotify: `---
id: spotify
title: Spotify listening history
profileVersion: 1
schemaVersion: spotify-privacy-export/2026-08
scopes:
  - spotify.*
summary: Spotify streaming history. Two different export packages share the name — one covers a lifetime, the other only the past year. Tracks and podcasts share one schema with no type flag.
---

## Shape: check which package you have first

Spotify ships **two different exports**, and they are easy to confuse because
both are called streaming history. Getting this wrong silently answers a
ten-year question with one year of data.

|                | Account data              | Extended streaming history                                                       |
| -------------- | ------------------------- | -------------------------------------------------------------------------------- |
| Coverage       | **the past year only**    | **the lifetime of the account**                                                  |
| Files          | \`StreamingHistory*.json\`  | \`Streaming_History_Audio_<years>_<n>.json\`, and video/podcast counterparts       |
| Timestamp      | \`endTime\`                 | \`ts\`                                                                             |
| Play duration  | \`msPlayed\`                | \`ms_played\`                                                                      |
| Track / artist | \`trackName\`, \`artistName\` | \`master_metadata_track_name\`, \`master_metadata_album_artist_name\`                |
| Context fields | none                      | \`reason_start\`, \`reason_end\`, \`shuffle\`, \`skipped\`, \`offline\`, platform, country |

**Look at the field names before anything else.** If you see \`msPlayed\`, you have
at most the last twelve months, and any question about "over the years" must say
so. The rest of this profile describes the extended package.

A ten-year heavy user's extended export is roughly 200k–250k rows across ~150 MB
in ~12 MB chunks. That is small enough to read in full — always aggregate over
every row rather than sampling. There is no prose here; do not search it as text.

## Extended history fields

\`ts\` (stream **end** time, UTC), \`ms_played\`, \`platform\`, \`conn_country\`,
\`master_metadata_track_name\`, \`master_metadata_album_artist_name\`,
\`master_metadata_album_album_name\`, \`spotify_track_uri\`, \`episode_name\`,
\`episode_show_name\`, \`spotify_episode_uri\`, \`reason_start\`, \`reason_end\`,
\`shuffle\`, \`skipped\`, \`offline\`, \`offline_timestamp\`, \`incognito_mode\`, plus
\`username\`, \`ip_addr\` and \`user_agent\`.

Two consequences:

- **\`ts\` is when the stream ended, not when it started.** For "what was I
  listening to at 11pm" or for joining to sleep or work sessions, subtract
  \`ms_played\` to get the start. A long track ending at 00:05 was mostly played
  the previous day.
- **\`ip_addr\`, \`user_agent\` and \`username\` are personal identifiers** that
  nothing about a listening question needs. Do not carry them into an answer.

Durations are milliseconds. Divide by 60000 for minutes, and say which.

## The rule that matters: one schema, several media types

Music tracks, podcast episodes and video share a **single row schema with no
type field**. Discriminate on **which cluster of fields is non-null**:

- a music row has \`master_metadata_track_name\` / \`master_metadata_album_artist_name\`
  populated and the \`episode_*\` fields null;
- a podcast row has \`episode_name\` / \`episode_show_name\` populated and the
  \`master_metadata_*\` fields null.

Counting rows without splitting them mixes hours of podcasts into "top artists"
and into listening totals. Filter explicitly, and state which media types the
answer covers.

## Skips

\`skipped\` alone is unreliable — it is frequently null or false on plays that
plainly ended early. Real parsers combine it with \`reason_end\`, treating
next-button, back-button and early-stop reasons as skips.

Do not hardcode a reason vocabulary from memory. **Enumerate the distinct
\`reason_end\` values present in this export first**, then define a skip in terms
of what you actually found, and **state the definition in your answer** — for
example "skips counted as \`skipped === true\` or \`reason_end\` in (\`fwdbtn\`,
\`backbtn\`, \`endplay\`), 41,203 of 227,024 plays". A skip threshold on \`ms_played\`
(under 30 seconds, say) is another defensible definition; if you use one, say so.

## Duplicates

A small share of rows overlap in time — the same play recorded twice, or plays
from two devices in the same instant. It is a low single-digit percentage, not
zero, and it inflates play counts and listening totals.

**Measure it rather than assuming a figure**: group by \`(ts, spotify_track_uri)\`
or look for rows whose \`[ts - ms_played, ts]\` intervals overlap, report the
duplicate rate you found, and say whether you deduplicated. For "how many times
did I play X", deduplicate. For "how many hours did I listen", deduplicating
matters more, because overlapping intervals double-count real time.

## Metric definitions

- **A "play"** — one row. **A "listen"** usually means a row with \`ms_played\`
  above a threshold; state it.
- **"Top artist"** — by play count and by total \`ms_played\` give different
  answers, especially where podcasts or long tracks are involved. Say which you
  used, and prefer time when the question is about how much something mattered.
- **\`offline\` plays** are recorded with \`offline_timestamp\`; their \`ts\` can be
  the sync time rather than the listen time. Note it if offline rows are a
  meaningful share of the window.

## Known gaps and unverified points

- **The \`reason_start\` / \`reason_end\` value vocabulary is not officially
  documented.** Derive it from the data, as above. Any list quoted from memory —
  including the one in this repository's design notes — is unverified.
- **The duplicate rate is corpus-specific.** The ~2.6% figure in the design notes
  came from one synthetic corpus and must not be reported as this user's number.
- **The export ships a \`Read Me First - Extended Streaming History\` file**
  describing each technical field. If it is present in the scope, read it: it is
  authoritative and more current than this profile.
- Podcast and video files are separate from the audio files. If only
  \`Streaming_History_Audio_*\` is present, podcast and video listening may be
  missing entirely rather than zero — say which files you saw.
- Field-level semantics of \`platform\`, \`conn_country\` and \`incognito_mode\` are
  not verified here beyond their names.

_The two-package split, the extended package's lifetime coverage and field
inventory, and the account-data package's one-year window were read from
Spotify's "Understanding your data" support documentation. Field-value
vocabularies were not verifiable from that source._
`,
};
