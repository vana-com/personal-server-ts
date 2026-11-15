# Provenance that stream-sync log format 2 must carry

Design only. No code, no PR. Source pin: `vana-com/personal-server-ts` at
`49354640ef7a6346a52bc9be65d91c5d1ee10243` (branch `feat/stream-sync`). All
`file:line` references are at that pin unless the text says otherwise. PR #715
(typed deletion keys `rk`) is assumed merged next and is not re-opened here.

At this pin `LOG_FORMAT = 1` (`packages/stream-sync/src/log.ts:87`). "Format 2"
below is the format that PR #715 and this design introduce. The owner's
statement that no released client has written format 2 is taken as given; I
did not verify it.

## 1. The decision in one page

Add two structures now (five descriptor fields and one entry field). Everything else is either derivable, already held
elsewhere, or cannot be filled today, so waiting loses nothing.

1. **A run descriptor table.** Each segment and each snapshot part carries
   `runs: [{a, c, n, r, w}]`, one row per distinct run id `r` that its entries
   cite. An entry already carries `r`, so each entry gets its provenance with
   zero extra bytes. The five fields:
   - `w`: writer id, the id of the device that made the observation.
   - `c`: causal context, the log position that device had applied when the
     run began.
   - `n`: a counter, per writer, that grows by one for each run that writer
     begins.
   - `a`: the artifact (connector) version string the run used.
   - `r`: the run id, the key.
2. **A commit position `q` on every snapshot-part entry.** A segment entry
   gets `q` for free, because the segment holds its own position
   (`Segment.position`, `log.ts:212` onward). Fold throws that away today. `q`
   is the key into the registry's durable per-version commit time (section 5).

Do **not** add: a per-op id, an HLC logical counter, a frontier vector, a
raw start time, a run end time, or a commit-time field. Section 2 gives the
reason for each.

Add later, **needs owner** (manifest field): source version and upstream
account. Add when the feature first occurs: owner hide, delete and restore.

Retention decision: **Option B.** The stream log stays a compacted baseline
that keeps the winner of each key, now with full run provenance. Record-level
sync adds a separate observation journal that starts at a launch position and
uses the format-2 snapshot at that position as its baseline. No stored data is
rewritten under B. Section 4 gives the cost comparison.

Ordering semantics do not change. No TLA+ update is required for the provenance
fields. Section 6 names the module and invariants that a later rule change
must update.

## 2. Field table

"Test" columns: (a) cannot be rebuilt later from stored data; (b) generic, no
connector knowledge in hosts or the PS; (c) small cost. Bytes are per entry
unless the row says per run. Byte counts for the descriptor were measured with
a node one-liner on the real JSON shape; the rest is computed from the wire
field lists. None of it was measured on a device.

| Field | Decision | Deciding test | Where it is set (at 49354640) | Bytes |
|---|---|---|---|---|
| Writer id `w` | **Add now**, in run descriptor | (a) fails to rebuild: a run id is a UUID, and no field of `ns`, signer or registry position names the device. (b) passes: the id is opaque. (c) passes. | Source: `db_meta.device_id`, minted at `open.ts:41`. Copy it into a new `runs.w` column in the same batch that inserts the run row (`run-intake.ts:393`). Encode in a new descriptor field list beside `UPSERT_FIELDS` (`log.ts:630`); add `runs` to the segment and part field lists (`log.ts:636-645`). | 0 per entry. About 40-50 per run (inside the 115-125 B descriptor). |
| Causal context `c` | **Add now**, in run descriptor | (a) fails to rebuild: the position the device had applied at run begin is local state that moves on. (b) passes. (c) passes. | Read `log_state.position` (`schema.ts:327`) inside the begin batch, in the same statement list as the `runs` insert (`run-intake.ts:393`). Store it in `runs.c`. Never recompute at publish. | 0 per entry. 11 per run. |
| Writer run counter `n` | **Add now**, in run descriptor | (a) fails to rebuild: it is the only clock-free order of one writer's own runs, and equal `c` ties them. (b) passes. (c) passes. | Allocate from a never-decreasing counter row in `db_meta` inside the begin batch. Do not use `MAX(n)` over `runs`: run rows are pruned. | 0 per entry. 7 per run. |
| Artifact version `a` | **Add now**, in run descriptor | (a) fails to rebuild: it names the connector build that observed the row. (b) passes: the host already stores it as an opaque string. (c) passes. | Already held: `runs.artifact_version` (`schema.ts:70` onward, set at `run-intake.ts:393`). Only the wire field is new. | 0 per entry. 12 per run. |
| Run id `r` | Already present | n/a | `LogStamp.r` (`log.ts:123`). It becomes the descriptor key. | 43 per run, already paid today. |
| Commit position `q` (snapshot-part entries only) | **Add now** | (a) fails to rebuild: `foldLog` (`log.ts:344`) drops the segment position of each winner, and the registry commit time can only be read by position. (b) passes. (c) passes. | Fold fills it from `Segment.position` for entries it takes from segments. It keeps the old `q` for entries it takes from a prior part. A first snapshot written straight from `records` commits in one registry commit, so `q` is that commit's position. In a segment the field is absent: the segment position is the value. | 11 per snapshot entry (`"q":123456,`). 0 in segments. |
| Per-op id | **Never** | (a) passes the "derivable" bar: one body per key per run (`run_rows` primary key is `(run_id, stream, pk_hash)`), so `(r, stream, pkHash, kind)` already names an observation. A random id adds bytes and no information. | None. | 0 |
| HLC logical counter | **Never** | (a) not needed: with `c` as a Lamport clock (section 3), `n` and `w`, every tie has a deterministic break. An independent review of HLC designs found a receive-clamp HLC is unsound. (c) cost with no gain. | None. | 0 |
| Frontier vector (per-writer) | **Never** | (a) not needed if the context collapses to one number (section 3). | None. | 0 |
| Raw start time `t` | **Never** | `o` is `min(req.observedAt ?? now, now + 300000)` (`run-intake.ts:359`), a caller claim. `clampRunStart` (`admit.ts:316`) then raises `o` above the tombstone watermark so a run cannot resurrect a row that a newer run deleted. A rule that used the unclamped claim would reopen that bug. So the raw value is a hazard, not evidence. | None. | 0 |
| Run end time `e` | **Never** | (a) cannot be set: a batch publishes while its run still collects (`publishWhileCollecting`), so the run end is unknown when the first segment is built. The registry commit time bounds each entry from above instead. | None. | 0 |
| Commit time field in the log | **Never** | A segment is hashed before the registry accepts it, so the log cannot hold the acceptance time. The registry keeps it (section 5). | None. | 0 |
| Source version | **Add later. Needs owner: manifest field.** | (a) nothing can fill it today, so waiting loses nothing. (b) fails today: only a connector can name its comparable version. Smallest addition below. | n/a | n/a |
| Upstream account | **Add later. Needs owner: manifest field.** | Same as source version. | n/a | n/a |
| Certified complete-scan flag | **Never** (already covered) | The op kinds already record it: an explicit delete versus an `omit` entry (`log.ts:630-632` field lists). `complete` on the stream meta and the declared full inventory (`run_streams.full_read`, `replace`) certify the scan. A separate flag would repeat them. | None. | 0 |
| Owner hide, delete, restore | **Add when the feature first occurs** | The feature has never run, so no past operation is lost. | n/a | n/a |
| Unsettled flag (the five-minute window) | **Never** | Derivable from stored inputs plus a fixed rule version. Storing the boolean would freeze one rule. | None. | 0 |
| Losing candidates | **Not in this log.** See section 4. | Retention decision. | n/a | n/a |

Size of the whole set. A descriptor is 115-125 B (measured: 115 B with a
32-hex writer, 125 B with a 0x-address writer, 119 B with a UUID writer).
Typical segments hold entries of a few runs, so the table is a few hundred
bytes. The inline alternative (the same five fields on each entry) costs about
98 B per entry, so the table is cheaper whenever the average run contributes
more than about 1.2 entries to a part. Worst case, when every entry in a part
comes from a different run, the table costs 115-125 B per entry against 98 B
inline. That is about 10% of a 1.2 KB entry. I judge that case unrealistic
for a part that holds many keys from one import, but I did not measure real
distinct-run counts.

Today's entry sizes for context: an upsert is about 187 B with an empty value;
a delete is about 162 B before the `rk` field from PR #715. I took the `rk`
size from the PR description and did not measure it.

### Handling a run with no descriptor

A row can cite a run whose descriptor this device does not hold. Two causes:
the reserved seed stamp `(0, "seed")` (`records.ts:26`), which belongs to no
real run; and a row admitted before the descriptor table existed whose run row
was pruned. The rule: the encoder writes no descriptor for that run, and a
decoder reads "no descriptor" as **unknown**. It does not invent defaults. This
matches the independent ordering review, which requires an explicit unknown. It also keeps
publish from stalling on a legacy row.

### Remote runs

The device must keep the descriptor of every run it applies from other writers.
Two paths republish an old stamp: `promoteSeen` (`merge.ts:186`) and any later
batch that re-reads `records`. `operationsFor` (`log-publish.ts:738`) reads the
current `records` row, which can carry another writer's stamp. The published
segment must then carry that other writer's descriptor, not the publisher's.
So `log-apply` must store applied descriptors in a new local table keyed by
`r`. Without this, a republished remote observation would lose its writer.

## 3. Causal context: does one number suffice?

Hypothesis from the brief: the connection log is one linear CAS chain, so a
run's causal context collapses to one number, the position the device had
applied when the run began, and the per-writer frontier is unnecessary.

**Result: sound, with two conditions and one stated limit.**

The chain is linear. Positions are dense: a segment lists `refs` for positions
`base+1 .. position-1` ascending with no gap (`log.ts:212` onward). The
registry accepts one writer per position by compare-and-swap. So the set of
positions a device has applied is always a prefix `1..p` of the chain (after a
snapshot, `base+1..p` plus the snapshot). One number `p` names the whole set,
which is the full causal frontier over the log. A vector would repeat what the
prefix already says.

Condition 1: persist `c` at run begin, per run. Do not derive it at publish.
Evidence from the CAS retry path: `snapshotRound` (`log-publish.ts:273`) reads
`log_state.position` again on every round, and on a conflict
(`log-publish.ts:998-1001`) it applies the competing segment and plans again.
A `c` read at publish time would therefore include the competitor that just
won. That would claim the run had seen an observation made while it was
collecting. This is the "seal-time frontier" error, the independent ordering review finding B.
Reading `c` in the begin batch avoids it. After a retry the same run id is
republished in a new segment, and the descriptor is read from the stored row,
so it does not change.

Condition 2: one segment may combine several runs, and `promoteSeen` may
republish an older stamp. So the context cannot be one number per segment. It
is one number per run, keyed by `r`. That is why the descriptor is a table and
not a segment header field.

Why `c` is also a clock. If observation X is known before observation Y, then
X's commit position `q_x` is at most `c_y`. A run's `c` is strictly below the
commit position of anything that run publishes, so `c_x < q_x <= c_y`. So
`c_x < c_y`. Sorting by `(c, w, n)` therefore respects every causal edge the
log records. That is all an Automerge-style rule needs. Hence no HLC counter.

The limit: `c` is the context at run **begin**. A device may apply a remote
segment while a run is still collecting. Then the run may have read upstream
data after seeing that segment, yet `c` does not say so. The recorded context
**under-reports** what the run knew; it never over-reports, because everything
at or below `c` was applied before the run's first observation. For a rule
that treats "concurrent" as "re-observe before asking the owner", an
under-report is the safe direction: it yields more re-observation, never a
wrong claim of causality. For an Automerge-style rule, the order stays
deterministic and consistent with every recorded edge, but it is not a
freshness rule (the independent ordering review). I did not model the mid-run apply case in
TLA+.

## 4. Retention: journal from launch, or keep losing candidates now?

Question: must the stream log keep losing candidates now, so that record-level
sync can pick any rule later? Or can record-level sync be a separate
observation journal that starts at a launch position, with the stream log as
its baseline?

**Decision: Option B, a separate journal from launch.**

What the log loses today. `foldLog` keeps one upsert and one deletion per key
(`log.ts:344`; `upsert()` replaces only when the new stamp is greater). The
equal-body local re-observation in `mergeIncoming` moves only the local SEEN
stamp and publishes nothing (`merge.ts:151`). `operationsFor` publishes one
current row per key (`log-publish.ts:738`). Compaction replaces refs with a
snapshot (`log-publish.ts` compaction path; `planCompaction` in
`log-compact.ts`). So a losing candidate never reaches a segment, and a
winner folds to one entry.

Option A: make the log keep a causal antichain per key, that is, every
candidate not dominated by a known-later one. This changes `foldLog`, the
wire format, the compaction rule and the TLA+ model (`OrderOK`, P1-P5). Every
snapshot part grows by the number of live concurrent candidates. I have no
measure of how many keys have more than one, so I cannot bound the first-load
cost. The first-load floor row 3b is about 25 s for 439 MB at 17 MB/s
(the first-load floor); each added percent of bytes costs about 0.25 s
there. Option A also keeps the shipped design open until record-level sync
decides its rule.

Option B: the shipped log stays what it is (a compacted baseline), now with
full provenance on each winner. At launch, record-level sync reads the
format-2 snapshot at launch position `P_L` as its baseline and starts an
append-only journal from `P_L`. The journal keeps every observation, with the
same descriptor fields. Cost on the first-load floor: the table and `q`
(section 2), about 1% in the common case. Cost of the later migration: none
for stored entries. Format-2 entries already carry what the journal's baseline
needs.

What B loses, said plainly. A candidate that loses under the shipped
`(o, r)` rule between the ship date and `P_L` is not kept. If a later rule
would have picked it, the log holds the wrong winner for that key. The next run
that observes the key upstream restores the right value, and the
re-observe-before-asking-the-owner policy in the prior ordering research covers the
residual. Option A would keep those candidates, at the cost above. I judge the
loss acceptable because the owner has ruled that most data is recoverable from
upstream (a product decision). This is a judgment, not a measurement.

Which option avoids rewriting stored data? Both avoid rewriting entries that
exist at launch. B also avoids changing the shipped fold, the wire format
beyond section 2, and the TLA+ model. A changes all three now.

Prior art. These claims come second-hand through the prior ordering research and
the independent ordering review. I did not re-read the primary sources.
- CouchDB keeps a revision tree and stores every conflicting leaf until a
  client resolves it; `revs_limit` stems old interior revisions. Its model is
  Option A, and it pays for it in document size.
- Automerge keeps the full change history, with the actor id, a sequence
  number and dependencies on every change. Our `w`, `n` and `c` are the same
  three facts in a compact form. Its per-op counter is not reproducible here,
  but any causality-consistent Lamport order is.
- LiveStore keeps an event log as the source of truth and rebuilds state by
  folding it; snapshots are caches. That matches B: the journal is the event
  log, the stream log is the snapshot.
- Kafka log compaction keeps the latest record per key, and keeps deletion
  tombstones for `delete.retention.ms`. A compacted topic is a baseline, not a
  history. That also matches B for the stream log.

## 5. Commit time: does the registry keep it?

Yes. `vana-com/data-gateway` (read with `gh`, read only) stores a durable
`added_at` per data point version, set on the first insert and not changed
afterwards (`db/migrations/0028_split_data_point_versions.sql`, with later
migrations `0048`-`0050`). The log row of a connection is a data point, and its
version is the log position, so every position has a server-assigned commit
time.

How a replica reads it. The owner or a registered server reads it through the
signed versions inventory (`api/v1/data/[dataPointId]/versions.ts`,
`docs/version-inventory.md`). The hot read path does not give it: the head GET
returns the first-registration `addedAt` only, and the PS drops that field in
`toControlRead` (`packages/core/src/stream-sync/registry.ts:56`). So the log
needs **no time field**, but a later host must read the inventory by
`q`. That is why the design keeps `q` on snapshot entries (a position the log
loses at fold; a time the registry does not).

What I could not verify:
- whether Web and PS-lite are authorized to call the versions inventory;
- whether `added_at` can be stale for a version whose first insert failed and
  was retried (failed-slot `addedAt`);
- the read cost of the inventory. A host that needs many positions will batch
  them; I have not measured it.

## 6. Does anything change ordering semantics? TLA+

**The provenance fields do not.** The winner of a key stays the greatest
`(o, r)` stamp, with deletes beating ties with upserts and an omission ranking
below an observation at the same stamp. `foldLog` still keeps one upsert and
one deletion per key. The descriptor table and `q` ride beside that decision
and take no part in it. So no TLA+ update is required before review for this
change. The required check is a code property test: folding the same input
with and without descriptors gives the same winners.

**A later rule change does.** If a record-level rule replaces `(o, r)` with
`(c, w, n)` order, a source-version rule or the v3 window, then the model must
change first:
- module: `docs/formal/log-protocol/LogProtocol.tla`;
- invariants to update: `OrderOK` (line 85, equal-stamp corpus folds the same
  forwards and backwards) and `P1` to `P5` (the config `Good.cfg` lists them);
- one invariant to add: projection convergence, that for every permutation of
  delivery the projected winners are equal;
- `StampEqualsLamport` (line 269) is an expected-FALSE witness that the two
  conflict orders differ. It must stay FALSE or be replaced, not silently
  flipped.

The README of that module says TLC has not been run and its pin is `1ca1a110`,
not `49354640`. So the model's "verified" status is a prediction, not evidence.

## 7. Items for the owner

1. **Source version.** Needs owner: manifest field. Smallest addition: a
   per-stream key, for example `source_version: { field: "<record field>",
   kind: "integer" | "timestamp" }`. The host reads the named field and writes
   it to a new entry field. A deletion carries the version only if the
   connector reports it at delete time. Waiting costs nothing for upserts,
   because the value is in the body; for deletes nothing can supply it today.
2. **Upstream account.** Needs owner: manifest field. Smallest addition: a
   per-connector key naming the stream and field that hold the stable account
   id, for example `account: { stream, field }`. The host binds it to the
   connection. If the account changes, the host must bump `generation`, which
   `Segment` already carries. Nothing can fill it today.
3. **Format bump for any later field.** The codec is strict (`exactKeys`,
   `log.ts:647`), so each later field needs a `LOG_FORMAT` bump and a lockstep
   client upgrade. It does not need a rewrite of stored data, because absence
   means unknown. I advise against loosening the codec to ignore unknown keys:
   that would let an old client fold an entry it does not understand.
4. **Retention judgment (section 4).** Option B accepts the loss of
   candidates that lose between ship and `P_L`. This is the owner's call; the
   evidence is the product decision that most data is recoverable from upstream, not a measurement.

## 8. Expect it to work because:

**Why this set is enough for both rules.** Every ordering rule discussed in
the independent ordering review needs only three kinds of evidence about an observation: who
made it, what that writer knew when it began, and an upper bound on when it
happened. `w`, `n` and `c` give the first two. `q` plus the registry's
`added_at` give the third. An Automerge-style rule sorts by `(c, w, n)` with
`o` and `r` as tie-breaks. It is consistent with every recorded causal edge
because `c_x < q_x <= c_y` whenever X is known before Y. A v3-style rule needs
the same three kinds plus two inputs no field here can supply today: source
version and upstream account. Those two have nothing to store until a manifest
field exists, and absence reads as unknown, so waiting loses no data. A rule
that needs per-record observation time inside a run cannot be served by any
log field, because the hosts never record it; the run start `o` and the commit
time bound it from both sides.

**How it works end to end.**
1. Run begin: one batch inserts the `runs` row with `w`, `c`, `n` and `a`
   (`run-intake.ts:393`), reading `log_state.position` (`schema.ts:327`).
2. Publish: the segment builder collects the distinct `r` of its entries,
   looks each up (local runs table or applied remote descriptors), and writes
   the descriptor table. A CAS conflict re-plans and re-reads the same stored
   rows, so the descriptors are unchanged (`log-publish.ts:998-1001`).
3. Apply: a device stores the descriptors it reads, so it can republish a
   remote observation under its original writer.
4. Fold: the new snapshot keeps one descriptor per surviving `r` and one `q`
   per surviving entry.
5. Launch of record-level sync: read the snapshot at `P_L` as the baseline and
   start the journal.

**The riskiest assumption.** That one begin-time position is a sound and
sufficient context, so no vector or HLC is needed. Evidence: the chain is
dense and linear, so a position names a full prefix (`log.ts:212` onward); the
retry path re-reads the position every round, which proves why `c` must be
stored at begin and shows it can be (section 3); and the Lamport inequality
above holds for every recorded edge. What it does not cover: mid-run apply
under-reports context (safe direction), and I have not run the model or any
test for it. A second, smaller risk: `device_id` may not be unique if a
database is cloned or restored. A duplicated `w` with a repeated `n` would
make two different runs look like one writer's sequence. Detection is
possible, because the same `(w, n)` would appear with two different `r`
values, but I did not verify how `open.ts:41` behaves on a copy.

## 9. What I could not verify

- `device_id` uniqueness across Desktop, Web and PS-lite, and whether a clone
  or restore re-mints it.
- Progressive first load while a run begins (the interaction of the
  descriptor table with the progressive-load path in floor row 3b).
- Web and PS-lite authorization for the registry versions inventory, and
  failed-slot `addedAt` staleness.
- Prior-art claims (CouchDB, Automerge, LiveStore, Kafka): second-hand, not
  re-read at the primary source.
- Format-2 `rk` bytes: taken from the PR description.
- Any measured first-load or publish impact. The byte figures are computed
  from the JSON shapes; the 1% estimate for `q` and the worst-case 10% for the
  descriptor table are arithmetic, not device measurements.
- Whether `foldLog` can fill `q` without a signature change. `foldLog` receives
  `Segment` objects, each with its `position`, so I expect it can; I did not
  write the change.
- TLC results for any module under `docs/formal/log-protocol/`.
