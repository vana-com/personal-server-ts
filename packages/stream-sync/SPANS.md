# Spanning records (head format 2)

Status: design note for the change that removes the 8 MiB record exclusion.

## Problem

A record is one canonical line. A line over 8 MiB (`INLINE_LINE_LIMIT_BYTES`)
was counted as `record_too_large` and left out of the head. The cursor still
moved past it, so the record was lost on every surface.

## Decision

A line over the inline limit **spans consecutive fragment parts**. Nothing else
about parts, heads or merge changes.

- **Fragment.** The canonical line bytes are cut into pieces of exactly
  4 MiB (`SPAN_FRAGMENT_BYTES`); the last piece may be shorter. Each piece is
  a part blob (`g<gen>-p-<sha256>`), encrypted and verified like any part. It
  holds raw line bytes, not NDJSON. A line spans at most 64 fragments
  (256 MiB). Past that the writer fails the stream loudly; it never skips the
  record.
- **Head entry.** A fragment entry is
  `{"bytes","hash","prefix","span":{"i","k","n"}}`: fragment `i` of `n` of the
  line whose key hash is `k`. It has no `count`. `recordCount` counts the line
  once. The head stays the only authority on which parts form the version.
- **Order.** Entries stay sorted by `prefix`. In format 2 several entries may
  share a prefix: the inline parts and span runs of one bucket, in `pkHash`
  order. A span run is `n` consecutive entries, `i = 0..n-1`, same `k` and
  prefix. Every fragment but the last is 4 MiB. A line that fits inline must
  not span, so every writer produces one head for one version.
- **Overlay by primary key.** Unchanged. A spanning line is a line: it has an
  `(o, r)` stamp and a `pkHash`, and the greatest stamp wins. The stamp is in
  the first bytes of fragment 0, so a merge reads fragment 0 only to decide
  whether a base span still wins. A winning base span is carried into the new
  head as the same entries (no fragment is read, decrypted or uploaded again).
  A newer run line for the same key replaces it. A stream delete tombstones
  the stream row, as before.
- **Planner.** Base fragments take no part in size planning (they are never
  re-encoded). Bytes of a spanning line in a run still count in the spool
  shard totals, so the buckets that hold it split to their cap. Parts stay
  correct; there may be a few more small parts next to a huge record.

## Format version

`format` is 1 for a head with no span and 2 for a head with at least one. A
format-1 head is byte-identical to today's, so existing data and the v1
vectors for it do not change. Readers accept 1 and 2 (the current and the
previous version). A reader that knows only format 1 gets
`unsupported_format` for a format-2 head and refuses the stream; it cannot
misread it. The decoder rejects a format-1 head with a fragment and a
format-2 head without one.

Order of release: readers (Personal Server, Lite, Web) ship first. A writer
produces format 2 only for a stream that holds a record over 8 MiB; before
this change that record was dropped. Until all readers of an account are
updated, that one stream shows `unsupported_format` to an old reader.

## Verification

Import checks each fragment's size and SHA-256 and the run structure. The
join is verified when a read assembles the line: UTF-8, canonical line form,
and `pkHash(line.v) = k`. Peak memory of one spanning record is a function of
its size; see the PR for measurements.

## Not in this change

The Desktop client still skips a line over its 8 MiB batch limit, and the run
intake route still caps a batch body at 8 MiB. Both need a chunked record
transport before an oversized record can reach the Personal Server from
Desktop. The seed upload route now accepts lines up to 256 MiB.
