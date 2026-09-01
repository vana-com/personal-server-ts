---
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
| Files          | `StreamingHistory*.json`  | `Streaming_History_Audio_<years>_<n>.json`, and video/podcast counterparts       |
| Timestamp      | `endTime`                 | `ts`                                                                             |
| Play duration  | `msPlayed`                | `ms_played`                                                                      |
| Track / artist | `trackName`, `artistName` | `master_metadata_track_name`, `master_metadata_album_artist_name`                |
| Context fields | none                      | `reason_start`, `reason_end`, `shuffle`, `skipped`, `offline`, platform, country |

**Look at the field names before anything else.** If you see `msPlayed`, you have
at most the last twelve months, and any question about "over the years" must say
so. The rest of this profile describes the extended package.

A ten-year heavy user's extended export is roughly 200k–250k rows across ~150 MB
in ~12 MB chunks. That is small enough to read in full — always aggregate over
every row rather than sampling. There is no prose here; do not search it as text.

## Extended history fields

`ts` (stream **end** time, UTC), `ms_played`, `platform`, `conn_country`,
`master_metadata_track_name`, `master_metadata_album_artist_name`,
`master_metadata_album_album_name`, `spotify_track_uri`, `episode_name`,
`episode_show_name`, `spotify_episode_uri`, `reason_start`, `reason_end`,
`shuffle`, `skipped`, `offline`, `offline_timestamp`, `incognito_mode`, plus
`username`, `ip_addr` and `user_agent`.

Two consequences:

- **`ts` is when the stream ended, not when it started.** For "what was I
  listening to at 11pm" or for joining to sleep or work sessions, subtract
  `ms_played` to get the start. A long track ending at 00:05 was mostly played
  the previous day.
- **`ip_addr`, `user_agent` and `username` are personal identifiers** that
  nothing about a listening question needs. Do not carry them into an answer.

Durations are milliseconds. Divide by 60000 for minutes, and say which.

## The rule that matters: one schema, several media types

Music tracks, podcast episodes and video share a **single row schema with no
type field**. Discriminate on **which cluster of fields is non-null**:

- a music row has `master_metadata_track_name` / `master_metadata_album_artist_name`
  populated and the `episode_*` fields null;
- a podcast row has `episode_name` / `episode_show_name` populated and the
  `master_metadata_*` fields null.

Counting rows without splitting them mixes hours of podcasts into "top artists"
and into listening totals. Filter explicitly, and state which media types the
answer covers.

## Skips

`skipped` alone is unreliable — it is frequently null or false on plays that
plainly ended early. Real parsers combine it with `reason_end`, treating
next-button, back-button and early-stop reasons as skips.

Do not hardcode a reason vocabulary from memory. **Enumerate the distinct
`reason_end` values present in this export first**, then define a skip in terms
of what you actually found, and **state the definition in your answer** — for
example "skips counted as `skipped === true` or `reason_end` in (`fwdbtn`,
`backbtn`, `endplay`), 41,203 of 227,024 plays". A skip threshold on `ms_played`
(under 30 seconds, say) is another defensible definition; if you use one, say so.

## Duplicates

A small share of rows overlap in time — the same play recorded twice, or plays
from two devices in the same instant. It is a low single-digit percentage, not
zero, and it inflates play counts and listening totals.

**Measure it rather than assuming a figure**: group by `(ts, spotify_track_uri)`
or look for rows whose `[ts - ms_played, ts]` intervals overlap, report the
duplicate rate you found, and say whether you deduplicated. For "how many times
did I play X", deduplicate. For "how many hours did I listen", deduplicating
matters more, because overlapping intervals double-count real time.

## Metric definitions

- **A "play"** — one row. **A "listen"** usually means a row with `ms_played`
  above a threshold; state it.
- **"Top artist"** — by play count and by total `ms_played` give different
  answers, especially where podcasts or long tracks are involved. Say which you
  used, and prefer time when the question is about how much something mattered.
- **`offline` plays** are recorded with `offline_timestamp`; their `ts` can be
  the sync time rather than the listen time. Note it if offline rows are a
  meaningful share of the window.

## Known gaps and unverified points

- **The `reason_start` / `reason_end` value vocabulary is not officially
  documented.** Derive it from the data, as above. Any list quoted from memory —
  including the one in this repository's design notes — is unverified.
- **The duplicate rate is corpus-specific.** The ~2.6% figure in the design notes
  came from one synthetic corpus and must not be reported as this user's number.
- **The export ships a `Read Me First - Extended Streaming History` file**
  describing each technical field. If it is present in the scope, read it: it is
  authoritative and more current than this profile.
- Podcast and video files are separate from the audio files. If only
  `Streaming_History_Audio_*` is present, podcast and video listening may be
  missing entirely rather than zero — say which files you saw.
- Field-level semantics of `platform`, `conn_country` and `incognito_mode` are
  not verified here beyond their names.

_The two-package split, the extended package's lifetime coverage and field
inventory, and the account-data package's one-year window were read from
Spotify's "Understanding your data" support documentation. Field-value
vocabularies were not verifiable from that source._
