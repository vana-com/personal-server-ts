// Generated from the sibling *.md profile documents. Do not edit by hand.
// Regenerate with: UPDATE_PROFILES=1 npx vitest run packages/core/src/query/profiles
export const PROFILE_DOCUMENTS: Record<string, string> = {
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
