# Open design questions (stream sync revision 4.1, P0)

The package implements section 2 of the design. Where the design is ambiguous
or silent, the package takes the reading below, marks it in code and in
`vectors/v1.json` (field `question`), and waits for an answer. No reading
below can publish under a generation the start snapshot does not admit.

## Questions

**Q1. Start unknown, current foreign.** Two rows of the §2.4 table match
`(S = unknown, C = foreign)`: "unknown | any → discard, recollect" and
"any | foreign → keep pending, `key_mismatch`". The foreign row must override
the "other" cells, or it can never apply. The package lets it override the
unknown row too: the result is `keep_pending key_mismatch`. Neither choice
publishes. Which one is meant?

**Q2. Start foreign.** No row starts from `S = foreign` (the listing at run
start saw another key's control row). If `C` is still foreign, the foreign row
gives `key_mismatch`. Otherwise the package discards the run without clearing
checkpoints. Is that right, or should it clear checkpoints, or keep pending?

**Q3. Planner estimate for a coarse base part.** §2.6 says "estimate each
bucket as base part bytes + run shard bytes". When a base part covers a larger
key range than the bucket (the base part prefix is a prefix of the bucket
prefix), the package counts the base part bytes in proportion to the share of
the range: `bytes / 2^(bucket depth − part depth)`. Counting it in full would
split a 4 MiB base part down to the 16-bit cap. This affects part sizes only;
merge results do not depend on split points. Confirm, or name another rule.

**Q4. Oversized bucket below the cap.** §2.6 names `bucket_too_large` only for
a capped bucket whose winners exceed 16 MiB. A bucket above the cap can exceed
16 MiB only when its estimate was wrong (Q3, or skewed base parts). The package
reports `bucket_too_large` for any bucket over 16 MiB, so no part over the
decoder limit is written. Should the host instead split such a bucket by the
next bit and reduce again?

**Q5. Same connector version, different primary key.** §2.5 covers a writer
with a higher or lower `profile.version`. For an equal version with a different
`primaryKey`, the package returns `connector_update_required` (does not
publish). Is that right?

**Q6. Selecting among live connections.** §2.10 selects "most recently
registered heads". The package takes an opaque registration order per
connection from the host (for example the latest registry time of its live
heads) and breaks ties by the lowest `ns`. Confirm the measure and the tie
rule.

**Q7. Character sets of `c` and `s`.** The design states only that `c` has no
`~`, the parse rule, and the 256-byte limit. The package applies only those: `c`
is any non-empty string without `~` (it may contain `.`), and `s` is any
non-empty string. The SDK scope schema rejects `~` in scope segments, so the gateway
and read-path work must check SDK validation too. Should the package narrow `c` and `s`
to the existing scope segment classes?

**Q8. Foreign row right after a create or reconnect.** §2.4 says "after
create/reconnect, C must re-read as active(T), else discard", and the table
says "any | foreign → keep pending, `key_mismatch`". The package applies the
first rule: discard. Is that right?

**Q9. No-op of an incomplete head and the checkpoint.** §2.4 blocks the
checkpoint only when a stream "was published `complete:false`". A no-op
publishes nothing, so the package lets a no-op whose unchanged head is
`complete:false` save the checkpoint. Then only the device that published the
incomplete head holds `needsFull` for it. If that device never runs again, the
head can stay incomplete, against L3. Should a no-op onto an incomplete base
also set `needsFull` (and so block the checkpoint)?

## Format details the design leaves open (assumed)

- A1. Every part line ends with `\n`, including the last line. An empty bucket
  has no part.
- A2. `r` compares by UTF-16 code unit (the same as bytes for ASCII run ids).
- A3. Registry hashes (`dataHash`, control hashes) are `0x` + lowercase hex.
  Blob names use bare hex: `h-<64 hex>`, `g<gen>-p-<64 hex>`. The head
  `generation` is a decimal string without leading zeros.
- A4. `accountId` is a non-empty string.
- A5. The head decoder requires canonical bytes and the exact field set. Any
  `format` other than the number 1 (including a missing field) is
  `unsupported_format`.
- A6. An empty base (absent, tombstoned, other generation, or replaced by the
  compatible-writer rule) counts as `complete:false` in the `complete`
  formula.
- A7. Control classification compares the data hash only: own `ACTIVE_DATA` →
  `active`, any other live hash → `foreign`. A row with both tombstone hashes
  is `deleted` even before `deleted_at` is visible.
- A8. The planner starts at prefix `""` and leaves out buckets with an
  estimate of 0.
