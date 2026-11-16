# Provenance that stream-sync log format 2 must carry

Design only. No code. Revision 3, after two independent reviews.

Source pin: `vana-com/personal-server-ts` at
`85b3a8578fc66ba81834f5a5f4ac14e3fc6ef95d` (`feat/stream-sync`, after #715).
Every `file:line` is at that SHA. At this SHA `LOG_FORMAT = 2`
(`packages/stream-sync/src/log.ts:109`). If no released client has written
format 2, the fields below extend format 2 in place. If one has, they need
format 3. I did not verify which.

Goal, unchanged: store enough evidence before format 2's first real write that
a later ordering rule (counter-style, or bounded observation time) is a
projection over stored data, with no migration. Where a review found the
evidence too thin, this revision fixes the evidence. Where a fix costs more
than it buys, it says so and states exactly what is lost.

What this document claims, and no more: section 16 lists what the design
proves by argument, what it requires tests to show, and what stays unverified.

## 1. What changed, and why

### Revision 3 (this revision)

| Review finding | Decision | Why | Cost |
|---|---|---|---|
| P2: the fallback between known and unknown provenance is not transitive (provenance A<B, stamp B<C<A, C unknown, gives a cycle) | **Fix: one total order `P` for the whole population.** Two classes. Observations with no context sit in one block below all observations that have one. Inside each class a fixed tuple orders them. Section 9. "Nothing else is lost" is withdrawn. | A pairwise rule that mixes two orders can cycle. A lexicographic order on `(class, tuple)` cannot. | No bytes. The cost is semantic: across the two classes the stamp is not consulted. Section 9 says what that loses. |
| P2: fork evidence disappears when compaction drops the losing branch | **Fix: a monotonic fork set `f` in every segment and snapshot part,** scoped to the log generation, merged by union, independent of winners. The identity of an observation now includes its body hash, so a same-`(w, s)` or same-run conflict is a conflict, not a duplicate. Section 8. | A fork seen only as two live rows is forgotten when fold keeps one. | 7 B per container when empty, 36 B per forked writer. |
| P2: progressive apply shows rows while `log_state.position` has not moved, so an event can read a row `X` with `c < q_X` | **Weaken, narrowly, and mark it.** An event admitted while a first-load pass is open carries `u = 1`: its `c` is a lower bound and its dependency record may be incomplete. Section 4.4. | Fixing the evidence exactly needs a per-key position read inside every admission and run-end statement. The window exists only during a first load on a device that already collects. That costs more than it buys. | 7 B per context row. Loses: an exact causal edge from a flagged event to the partial rows it read. |
| P2: a promoted seen sighting takes the winner's context, not its own | **Fix: store the seen observation's context id with `seen_o/seen_r` and move it on promotion, in the same statement.** Origin `q` of a promoted observation is `NULL` until its own first publication. Section 10. | The promoted stamp is the sighting's. The context must be its context. | One nullable local column. No wire bytes. |
| Equal-stamp tie rule, to agree with any other fix of the divergence | **Exact rule written down.** Section 9.1. | One comparator on admission, merge and fold. | No bytes. |
| Window is conditionally sound; `c = 0`; missing inventory; `A(c) > A(q)` | **Defined.** Section 5. | | none |
| `q` minimum holds for one identity in one generation; acknowledgements; resets | **Pinned.** Section 6. | | none |
| Retained winner provenance is not historical winner selection; artifact `a` is diagnostic; retention prose | **Stated.** Sections 3 and 11. | | none |

### Revision 2 (kept)

Begin-time `c` was replaced by `c` captured at each observation event. The
host clock `t` is clamped into a window taken from the registry's commit
times. `q` means origin commit. The writer id is a random incarnation id, not
`device_id`. TLC evidence was corrected. These stay as section 4 to 7 state
them.

Things decided **not** to do, because the fix costs more than it buys: a
per-writer frontier vector or an HLC counter (the position `c` names a full
applied prefix); quarantining a connection on a conflicting identity (the
log's winners do not depend on provenance, so a conflict needs a flag, not a
stop); using the unclamped caller claim as evidence (it would reopen the
tombstone-resurrection bug that `clampRunStart` prevents); an exact per-key
applied position during a progressive load (section 4.4).

## 2. The set

Add now, as three structures and one rule:

1. **Observation contexts.** Each segment and each snapshot part carries
   `ctx: [{a, c, r, s, t, u, w}, ...]`, sorted by `(w, s, r)`. One row names
   one *observation event*: a batch that a run admitted into `records`, or the
   run-end step that applies deletes, omissions and staged rows. Fields:
   - `w`: writer incarnation id (32 lowercase hex, random). Section 7.
   - `s`: the writer's admission sequence. It grows by one per event, durably.
   - `c`: the log position this writer had applied when the event happened.
   - `t`: the host's wall clock (ms) when the event happened.
   - `u`: `1` if the event happened while a progressive first load was open,
     else `0`. Section 4.4.
   - `a`: the artifact (connector) version string of the run. Diagnostic only.
   - `r`: the run id.
2. **A reference on each entry.** Upsert, delete and completion entries gain
   `d`, an index into the container's `ctx`. An entry with no `d` has unknown
   provenance (seed rows, rows imported before contexts existed).
3. **`q` on entries:** the commit position at which the observation first
   reached this log. A snapshot entry always carries it (`0` = unknown). A
   segment entry carries it only when it is a copy of an older observation;
   otherwise it is the segment's own `position`.
4. **A fork set `f` on every segment and snapshot part:** a sorted list of
   writer ids known to have forked in this log generation. Section 8.

Not added: a random op id, an HLC counter, a frontier vector, a raw start
time, a run end time, a commit-time field. Source version and upstream
account wait for a manifest field (section 14).

## 3. Field table

Bytes are per row or per entry as the row says. The context row and the empty
fork set were measured with a node one-liner on the real JSON shape (143 B per
context row with a 32-hex writer, a 7-digit `s`, a 13-digit `t`, a UUID run
id and a short artifact version). Everything else is computed from the wire
field lists. None of it was measured on a device.

| Field | Decision | Deciding test | Where it is set (at 85b3a857) | Bytes |
|---|---|---|---|---|
| `w` writer incarnation | **Add now** | (a) not rebuildable: nothing in a stamp, namespace or position names the device. (b) opaque. (c) small. | New local table, minted at first admission and on rotation (section 7). Field lists at `log.ts:689` (segment), `log.ts:711` (part). | 38 per row |
| `s` admission sequence | **Add now** | (a) not rebuildable: the only clock-free order of one writer's own events, and part of an observation's identity (section 8). | Allocated in the same `db.batch` as the admission, from a counter row. Admission batch: `run-intake.ts:596` (`admitUpserts`, `admit.ts:100`). Run end: `run-end.ts:290`. | 12 per row |
| `c` applied position | **Add now** | (a) not rebuildable: local state that moves on. (b) generic. (c) small. | `SELECT position FROM log_state` (`schema.ts:327`) inside the admission batch. `log-apply.ts:147` writes the position in the same batch as the rows it stands for, except during a progressive first load (section 4.4). | 11 per row |
| `t` host admission time | **Add now** | (a) not rebuildable. Evidence only inside a registry window (section 5). | `deps.now()` inside the admission batch, as `run-intake.ts:359` already reads it for `o`. | 18 per row |
| `u` open-load flag | **Add now** | (a) not rebuildable: whether a load was open at the event is local state that is gone later. | A durable local marker, set and cleared by apply (section 4.4). | 7 per row |
| `a` artifact version | **Add now. Diagnostic only.** | (a) not rebuildable: it names the build that observed the row. It is not an ordering input and not part of identity. | Already held: `runs.artifact_version` (`schema.ts:70`, `run-intake.ts:393`). Only the wire field is new. | 12 per row |
| `r` run id | Already present | n/a | `LogStamp.r` (`log.ts:145`). Also in the row so a row is self-describing. | 43 per row |
| `d` entry reference | **Add now** | (a) not rebuildable. An entry's event cannot be inferred from its run, because one run has many events. | New field on `UPSERT_FIELDS` (`log.ts:705`), `DELETE_FIELDS` (`:706`), `COMPLETE_FIELDS` (`:707`). | 6-9 per entry |
| `q` origin commit | **Add now** | (a) not rebuildable: `foldLog` (`log.ts:416`) drops the segment position of each winner. | Section 6. | 11 per snapshot entry; 0 in a segment unless a copy |
| `f` fork set | **Add now** | (a) not rebuildable: a fork seen only as two live rows is forgotten when fold keeps one. | New field on the segment and part field lists. | 7 per container; 36 per forked writer |
| Per-op id | **Never** | Derivable: `(w, s, stream, pk, kind, bodyHash)` (section 8). | None | 0 |
| HLC logical counter | **Never** | `c` is already a Lamport clock (section 4); `P` breaks every tie (section 9). | None | 0 |
| Frontier vector | **Never** | `c` names a full applied prefix. | None | 0 |
| Raw (unclamped) start time | **Never** | `clampRunStart` (`admit.ts:316`) raises `o` so a run cannot bring back a row that a newer run deleted. A rule that used the raw claim would reopen that bug. | None | 0 |
| Run end time | **Never** | Unknown when the first segment is built (`publishWhileCollecting`). The registry commit time bounds each entry from above. | None | 0 |
| Commit time in the log | **Never** | The segment is hashed before the registry accepts it. Section 12. | None | 0 |
| Source version | **Add later. Needs owner: manifest field.** | Nothing can fill it today. | n/a | n/a |
| Upstream account | **Add later. Needs owner: manifest field.** | Same. | n/a | n/a |
| Owner hide, delete, restore | **Add when the feature first occurs** | I found no owner operation in the log codec (`log.ts:314`, `LogEntry`). I did not check whether another store holds such operations. | n/a | n/a |

**Local columns, no wire bytes.** `records` and `log_tombstones` gain `obs`
(the context id of the winning observation), `seen_obs` (the context id of the
seen sighting, section 10) and `origin_q` with `origin_g` (section 6).

**Cost per run.** A run has one context row per event that left a surviving
entry: one per admitted batch and one for the run end. A small run has one or
two rows (143-286 B). A run that sends 100 batches has about 100 rows, about
14.3 KB. Each entry then costs 6-9 B for `d`, and a snapshot entry costs 11 B
more for `q`: 17-20 B per snapshot entry, about 1.5% of a 1.2 KB entry. Each
container adds 7 B for an empty `f`. On the first-load floor (about 25 s for
439 MB at 17 MB/s) that is about 0.4 s. The percentage falls if entries are
larger. This is arithmetic, not a device measurement. Revision 3 adds 7 B per
context row and 7 B per container to revision 2.

## 4. Causal context

### 4.1 What revision 1 got wrong

Revision 1 stored `c` once per run, at run begin. A device can apply a remote
segment while a run is still collecting. `log-apply.ts:147` shows apply
batches run independently of intake batches. A later batch of the same run can
then depend on that segment, and the begin-time `c` does not say so.

Review counterexample. Writer A's observation X commits at position 1, with
`c = 0`. Writer B's run begins at `c = 0`, B applies position 1, then B's
batch admits Y, which depends on X. With a begin-time `c`, Y has `c = 0`. If
`w_B < w_A`, the order `(c, w, s)` puts Y before X. That is the wrong order
for a counter-style rule.

### 4.2 The fix

Capture `c` at the **observation event**. Both writes of `records` happen in
one `db.batch`: an upsert batch (`admitUpserts`, `admit.ts:100`, called from
`run-intake.ts:596`) and a run end (`run-end.ts:290` for deletes, with the
omissions and staged rows). Each event reads `log_state.position`, `deps.now()`
and the next `s` in that same batch. SQLite serializes the batch against apply
batches, so every segment applied before the batch is at or below `c`, and
none applied after it is.

Same scenario. A's event: `(w_A, s=1, c=0)`. X commits at `q_X = 1`. B's first
batch: `(w_B, s=1, c=0)`. B applies position 1 (`log_state.position = 1`). B's
second batch admits Y: `(w_B, s=2, c=1)`. Now `q_X = 1 <= c_Y = 1`, so X
precedes Y by the recorded edge, and `(c, w, s)` gives X `(0, w_A, 1)` and Y
`(1, w_B, 2)`. Y sorts after X for any `w_A`, `w_B`.

### 4.3 Why it holds, and for which events

- **Edges.** For observations X and Y with `q_X <= c_Y`, the device that made Y
  had applied X before it admitted Y. The row of Y records that edge.
- **Lamport.** The event of X happened before X was published, so
  `c_X < q_X`. With `q_X <= c_Y` this gives `c_X < c_Y`.
- **Same writer.** `c` never decreases along `s` for one writer incarnation,
  because the applied position never decreases. So `(c, w, s)` respects `s`.
  Rotation (section 7) starts a new `w`. After a copy or a rollback the new
  incarnation's first `c` is the position its database had applied, which can
  be below what the old incarnation published. The two are then different
  writers, ordered by `c` edges only.
- **Normal apply.** Every apply batch that advances `log_state.position`
  writes it with the rows it stands for (`log-apply.ts:147`; the tail
  segments of a progressive pass do the same through `state` at
  `log-apply.ts:1027`). So for an event that is not flagged `u`, `c` is never
  above the applied data. An over-report would claim an edge the device did
  not have. An under-report is the safe direction for a rule that treats
  unknown order as concurrent.

**Claim, for events with `u = 0`:** every observation that was visible on the
device when the event happened, and that reached the log before it, has
`q <= c` of the event. A linear extension such as `(c, w, s)` respects every
recorded edge. This is the property an Automerge-style rule needs. Automerge's
own per-op counter is not reproduced, and a causality-consistent order is not
a freshness rule.

**Not claimed.** The position says nothing about local observations that were
never published (they are ordered by `s` for one writer), nor about a record a
run read from upstream before it applied a segment. The event captures when
the device *admitted* the observation, which is the creation point of the log
operation. For events with `u = 1`, see 4.4.

### 4.4 Progressive first load (review finding 3)

**The gap, read from the code.** A first load applies the snapshot's parts
and then the tail segments as one pass (`log-apply.ts`, loop around `:985` to
`:1055`). For a part before the last, `state` is `undefined`, so
`log_state.position` does not move. The last part writes
`snapshot.position`, and each tail segment writes its own position. After each
batch the loop calls `announceApplied` (`log-apply.ts:1055`), so the rows of
the applied prefix are visible, and a stream whose last batch has applied
reads as finished. A local run can admit an observation Y on a key whose row X
came from an earlier part. X has `q_X` up to the snapshot position, and the
event reads `c` equal to the old position. So `c_Y < q_X` although Y read X,
and `(c, w, s)` may put Y before X.

**Three choices.**

| Choice | What it does | Cost | What it loses |
|---|---|---|---|
| Exact: per-key position | `c = max(position, origin_q of every row or tombstone the event replaces, deletes or omits)` | An extra read of `origin_q` inside each admission and each run-end statement. The run end's delete and omission predicates would have to be written twice. A mismatch between the two copies silently under- or over-reports. | Nothing, for rows the event touches. |
| Fence: hold events | Refuse or delay admission while a pass is open | A first load takes about 25 s on the floor figure. A connector run would stall that long, and intake would need a gate it does not have. | Nothing, but the user feels it. |
| **Mark (chosen)** | A durable local marker is set in the pass's first batch and cleared in the same `db.batch` that writes `log_state.position` for the last part. Events admitted while it is set carry `u = 1`. | One marker, one bit per context row (7 B), one test. | For `u = 1` events, an exact causal edge from the event to the partial rows it read. |

**Why the mark.** The window exists only on a device that is loading a
connection for the first time and also admits a local observation of that
connection in the same minute. The exact choice costs a second copy of every
run-end predicate for that case. A mark keeps the rest of the evidence: `c` is
still a valid lower bound, so every recorded edge of a flagged event is real,
and the time window of section 5 still holds (a smaller `c` gives a looser
lower bound). I do not claim this recovers the lost edge: it does not, and
**the evidence is not recoverable later.**

**What a future rule loses.** A counter-style rule cannot order a flagged
event after a partial row it read, unless that row's `q` is at most the
event's `c`. A rule that needs complete dependencies must treat a `u = 1`
event as having an incomplete record, and may place it by `c`, `w`, `s` only
as a best effort. In the projection order `P` (section 9) a flagged event
stays in the class with contexts: moving it below would break the edges it
does record.

**Marker.** The build can reuse `stream_partial` (`schema.ts:372`) if its rows
cover exactly the window between the first part batch and the batch that
writes the position. I did not verify that. If they do not, add a
connection-level marker row. A crash mid-pass leaves the marker set, and the
next admission is flagged, which is correct: partial rows are still visible.

**Tests, all new.** An early-completed stream X, then a local Y on the same
key before the pass ends: Y's context has `u = 1` and `c` equal to the old
position; the marker is cleared in the same batch as `log_state.position`; a
crash between two parts leaves it set; after the pass the next event has
`u = 0`; publish, fold and a fresh replica keep `u` on the row.

## 5. Observation time

`o` is a caller claim. `run-intake.ts:359` sets `o = min(observedAt ?? now,
now + 300000)`, then `clampRunStart` (`admit.ts:316`) may raise it above the
tombstone watermark. So `o` can be later than the observation, even later than
the commit, and an old claim can be arbitrarily early. It is a stamp, not a
clock. This design does not change the stamp or the clamp.

Evidence added: `t`, the host's wall clock at the event. It is untrusted by
itself. It is made useful by a window from the registry's commit times.

**The window.** `A(p)` is the registry's server commit time of log position
`p` (section 12).
- **Lower bound `L`.** The event happened after position `c` was applied, so
  after the registry committed `c`: `L = A(c)` if `c > 0` and `A(c)` is
  known. Otherwise `L = -infinity`. **`c = 0` means no position was applied,
  so there is no lower bound.**
- **Upper bound `U`.** The observation was in the log by its origin commit:
  `U = A(q)` if `q > 0` and `A(q)` is known. Otherwise `U = +infinity`. A
  local row never published has `q = NULL` and `U = +infinity`.
- **Estimate.** `clamp(t, L, U)`.

**When the window is trusted.** Only when all three hold:
1. both bounds are finite;
2. `L <= U`. If `A(c) > A(q)` the registry's commit times were not monotone in
   position (a retried first insert, or a clock step). The window is
   **invalid**: the rule must not swap or clamp, and treats the timing as
   unknown;
3. the registry's `added_at` is a monotone function of position and is the
   time the position became visible to readers. This is an assumption about
   the registry that I did not verify (section 12).

With bounds that are finite and valid, the estimate is wrong by at most the
window's width, whatever the device clock says. With one bound, `t` only
picks a side, and there is **no error bound**. With none, or with an inverted
window, or when the signed inventory is unreadable or has expired the
version (section 12), timing is **unknown**. Clamped host time alone is not
evidence: it is a position inside a window and nothing more. A writer that
lies about `c` or `t` can move its own estimate inside the window it chose;
the design does not defend against a hostile writer (section 7).

**Old and unknown timing.** Rows with no `d` (seed rows, rows imported before
contexts existed), snapshot entries with `q = 0`, events with an invalid or
unbounded window: a bounded-observation-time rule cannot place them against a
concurrent candidate. It uses the order `P` of section 9 for them. It loses:
detection of near-simultaneous conflicts with those rows, and the five-minute
"unsettled" signal for them.

## 6. Origin commit `q`

Decision: `q` is the **stable origin commit**: the log position at which an
observation first reached this log. Not the position of the container that
holds a copy.

Why origin and not materialization. A materialization position changes every
time an observation is copied: by `operationsFor` (`log-publish.ts:854`),
which reads the current `records` row and so can republish another writer's
stamp (`changedKeys`, `log-publish.ts:825`, selects keys by local changes,
and the row may have been replaced by a remote apply since); by a repeat
publish after a lost acknowledgement; and by a snapshot (`log-publish.ts`
compaction, `log-compact.ts`). A later copy time would pass as the original
time in a time-window rule. A materialization bound is still an upper bound,
and it stays available: it is the container's `position`.

How `q` is set and kept.
- **First publication.** The writer sets no `q` in the segment entry. The
  reader reads it as the segment's `position`. A conflict on the registry's
  compare-and-swap re-plans the segment at a new position
  (`log-publish.ts:1173`), so the position is the one that committed.
- **Local storage.** `records` and the delete tombstones (`log_tombstones`)
  gain a nullable `origin_q` and an `origin_g` (the generation it is valid
  in). `NULL`: never published. Apply sets both from the entry (`q`, or the
  segment position). The publisher sets them when its own segment commits.
- **Acknowledgement keeps the identity.** At plan time the publisher records,
  for each entry it sends, the row's `(obs, body_sha256)`. On acknowledgement
  it sets `origin_q = COALESCE(origin_q, position)` **only if the row still
  has that `(obs, body_sha256)`**. If the row changed since planning (a newer
  local write, or a remote apply replaced it), the acknowledgement does not
  touch it, because the committed entry is not the row's current identity. A
  lost acknowledgement that republishes the same identity finds `origin_q`
  already set, or sets it again from the same `COALESCE`, and sends the stored
  `origin_q` as an explicit `q` (a copy).
- **Republish of a copy.** The entry carries the stored `origin_q` as an
  explicit `q`, so the copy does not take the new position.
- **Fold.** `foldLog` (`log.ts:416`) already receives each `Segment` with its
  `position`. For each surviving entry it writes `q` = the entry's explicit
  `q`, or the position of the segment it came from, or the old part's `q`.
- **Bootstrap.** The first snapshot is written from `records` at position `P`.
  A row with a context (`d`) was admitted under this design, so its first
  appearance in the log is `P`: `q = P`. A row without a context has no
  recorded origin: **`q = 0`**, which means unknown.
- **Which entries are "equal".** The same observation can appear many times
  (segment, part, copy). Its identity is
  `(w, s, stream, pk, kind, bodyHash)` (section 8): **the body hash is part of
  it.** The merged `q` is the **minimum over occurrences of one identity with
  `q > 0`**; `0` loses to any known value. The minimum is commutative,
  associative and idempotent, so fold order and repeat folds give the same
  bytes. Two entries that share `(w, s, stream, pk, kind)` but differ in body
  are **two identities**, kept apart; they never merge their `q`. They are a
  fork (section 8).
- **Generations.** Positions are comparable only inside one generation. A part
  and its segments share a generation, so the minimum never mixes
  generations. When apply meets a generation different from a row's
  `origin_g`, it sets that row's `origin_q` to `NULL` (the row is replaced by
  the new generation's own snapshot anyway). A bump also empties `f` and drops
  the old contexts.

Cost: 11 B on each snapshot entry; nothing on a first-publication segment
entry; two nullable columns.

## 7. Writer incarnation

### 7.1 What the code does today

`db_meta.device_id` (`schema.ts:22`) is written once, with `INSERT OR IGNORE`
(`open.ts:41`), from `LocalDbIdentity.deviceId`. Hosts pass the **server
account address**: the Node server at `server/src/bootstrap.ts:920` and
PS-Lite at `lite/src/sync.ts:618` (with an optional override,
`localDbDeviceId`). So:

- two databases of one server account have one `device_id`;
- a deleted and re-created database gets the same `device_id` again;
- a clone or a restore keeps it.

It cannot serve as a writer id. Revision 1 named it as the source; that was
wrong.

A separate writer identity exists for the replication profile
(`core/src/replication/writer-identity.ts`; the append-only
`pdpp_replica_writer_identity` table in `writer-identity-store.ts:27`). It
derives ids from the owner, the server, a gateway registration id and a random
nonce, and its README states the rule: "Clone/restore must rotate writer
identity before making new writes" (`core/src/replication/README.md:60`). A
host asks for rotation with `rotateWriterIdentity`
(`lite/src/replication-host.ts:113`, consumed at `:210`). That path runs only
when replication runs in the boot. The log protocol does not depend on
replication, so it cannot rely on that path alone.

### 7.2 What each host does today

I read the desktop shell, browser host and phone shell in the application
repository at the pinned commit through a read-only survey. These are
statements about behavior, not about this repository's code, and I did not
re-read them line by line.

| Host | Where the database lives | Copy or restore guard | Paths that re-create or delete it |
|---|---|---|---|
| Desktop | One directory per network, an SQLite file with WAL | Yes. The shell keeps a random binding in the OS keyring with a machine id hash, plus a copy next to the database. A mismatch sets a rotation request for the runtime at boot. The request is consumed when replication launches. Replication is off by default. Stated gaps: a restore on the same machine with the same keyring is not seen; with no keyring every start rotates; a second profile on the same folder is not seen. | An owner change moves the database aside and the next boot creates a new one. "Delete local data" removes the directory. No copy or restore code. |
| Browser | An SQLite file in the browser's origin storage, guarded by a lock against two tabs. In an embedded frame, or when that storage is missing, the database is in memory and is new on every load. | **None.** No binding, no rotation request. | Only the separate key-value state is deleted on some configuration errors. No storage export or import. A profile copy or an operating-system restore carries the data with it. |
| Phone | An SQLite file in the application's per-owner directory | Yes. A keystore binding plus a file in the store directory. A mismatch sends a rotation request at start, and an unconfirmed rotation refuses to boot. Backup is disabled on both platforms, but device-to-device transfer can still carry the data. | No code path found that calls the owner delete. Sign-out keeps the data. |

Unverified: how the runtime uses `device_id` relative to these bindings, and
the browser database's exact storage name.

### 7.3 The design

- **`w` is a random 128-bit incarnation id**, 32 lowercase hex characters,
  minted by a cryptographic random source. The incarnation is encoded in `w`;
  there is no second field. A new database mints one at its first admission.
- **Storage.** One new local table, append-only like the replication identity
  table: `log_writer(w, born_at, next_s)`. The current writer is the newest
  row. `next_s` is the only mutable column. The allocation of `s` reads and
  increments `next_s` in the **same `db.batch` as the admission**, so a crash
  cannot lose or reuse a value inside one database file.
- **Rotation happens at a run boundary, never inside a run.** Rotation adds a
  row with a new `w` and `next_s = 1`. It takes effect before the **first
  admission of the next run**. So one run has one `w` in one database. This is
  what lets the equal-stamp rule of section 9.1 compare `s` safely: equal
  stamps are the same run. Ordering across a rotation is kept by the `c` edges
  (section 4); `s` order is not, because the two incarnations are different
  writers. Triggers:
  1. **Host request.** `openLocalDb` gains an input equal to the existing boot
     request (`rotateWriterIdentity`). The log writer rotates before the first
     run of the boot, whether or not replication runs. Desktop and phone
     already compute this request; browser hosts do not.
  2. **First use.** A database with no `log_writer` row mints one.
  3. **Rollback or clone seen in the log.** At apply, if a descriptor carries
     the device's *current* `w` and either its `s >= next_s` or its `s` is
     held locally with a different `r`, then the log holds history from this
     writer that this database does not have. The database was rolled back or
     cloned. It rotates before its next run, and the writer is added to the
     fork set `f` (section 8). This covers the browser, which has no host
     guard. It does not cover a clone that publishes nothing before the second
     copy publishes: until the second copy's first publication reaches the
     other, the two share a `w` and may reuse `s`.
- **Trust.** Every writer of a connection's log is the owner's own device.
  Descriptors of other writers are copies the publisher read from the log. The
  design does not defend against a hostile writer; it records enough to detect
  an honest fork.

## 8. Identity of an observation, conflicts, and the fork set

### 8.1 What intake accepts (review point 2, kept)

**Intake can accept two different bodies for one `(run, stream, pk)`.** Read
from the code, not run:

- `run-intake.ts:561` stages a row with `INSERT OR REPLACE INTO run_rows`. A
  later batch with the same key replaces the earlier staged body. The table's
  primary key is `(run_id, stream, pk_hash)` (`schema.ts:86`); it holds one
  row at a time, not the history. `run-intake.ts:487` answers a replayed batch
  (same or older batch number) as a replay, but a new batch for the same key
  is accepted.
- A run that admits while collecting does the same on `records`:
  `replaceOwnRunRows` (`admit.ts:168`) says "within a run the later batch
  wins". It replaces the body at the **same stamp** `(o, r)`.
- `records_au` logs that change as a local change with origin `local`, so
  `changedKeys` (`log-publish.ts:825`) selects the key again, and
  `operationsFor` publishes the new body at the same stamp.
- A reader applies it through `mergeIncoming` (`merge.ts:107`), which replaces
  a different body only when its stamp is **strictly** newer, and `foldLog`
  keeps the first equal-stamp upsert (`log.ts:434`). So the later body is
  ignored by readers, and the writer keeps it.

So one `(r, stream, pkHash, kind)` can name two bodies, and the writer and
every reader can end on different bodies. The formal model assumes this cannot
happen: `Admissible` (`docs/formal/log-protocol/LogProtocol.tla:121`) refuses
a batch with an equal key and stamp and a different body. The implementation
does not enforce it on this path. I did not reproduce the divergence; it needs
a test (section 15). `run_id` is also only text of length 1-128
(`schema.ts:70`), so a UUID is a host convention. The rule that closes it is
section 9.1.

### 8.2 The identity, corrected

Revision 2 said an observation is "unique by construction" as
`(w, s, stream, pkHash, kind)`. **That is withdrawn.** It holds for one
database file. A clone can keep `w`, reuse `s`, and write a different body, and
a clone can keep a run id.

**An observation is `(w, s, stream, pkHash, kind, bodyHash)`**, with `bodyHash`
null for a delete or an omission. The body hash is already in the row
(`body_sha256`). Consequences:
- two entries with equal `(w, s, stream, pkHash, kind)` and different bodies
  are two observations. They are never merged, and their `q` never mixes;
- a context row is identified by `(w, s)` and compared on `(r, c, t, u, a)`.

### 8.3 What counts as a fork

A writer `w` is **forked** when a log, in one generation, holds any of:
1. two context rows with the same `(w, s)` and a different `(r, c, t, u, a)`;
2. two observations with the same `(w, s, stream, pkHash, kind)` and different
   body hashes;
3. one run id `r` carried by contexts of two different writer ids, or the same
   `(r, stream, pkHash, kind)` with different body hashes under different `w`.
   A run has one `w` (section 7.3), so this is a clone that kept running a run.
   Both writers are marked, because the log cannot say which side is the copy.

### 8.4 The retained fork set `f`

- **Where.** Every segment and every snapshot part carries `f`: a sorted list
  of writer ids, no duplicates, scoped to the log generation. Every part of one
  snapshot carries the same `f`, so a fresh install reads it from the first
  part (as it already reads `streams`).
- **How it grows.** `f(output) = union of f(inputs) union forks detected among
  the inputs`. Detection runs at apply (stored locally in a `log_forks`
  table), at publish (the segment carries the local set), and in the pure fold
  over *all* candidates before it keeps one per key. Union is commutative,
  associative and idempotent, so repeat folds and split folds give the same
  `f`.
- **It does not depend on winners.** The losing branch's context row may be
  dropped by fold, because contexts are kept per surviving entry. The writer's
  id stays in `f`.
- **A generation bump empties it**, with the observations it described.
- **What a forked writer's rows mean.** `s` order among a forked writer's rows
  is unknown. The projection order `P` (section 9) uses `(c, w)` and then
  `(r, kind, bodyHash)` for those rows and ignores `s`. Every edge `c` records
  remains valid.

### 8.5 What the fork set cannot do

A fork is detectable only when both sides were present together in some input:
a context row held beside the conflicting one, in apply, in a publish plan or
in one fold. If the first side was folded away before the second side arrived,
no bounded structure can tell the second from a legitimate old event: a
per-writer high-water `s` cannot separate a clone's new event from a republished
copy of an old one. So **a fork whose first side was compacted alone is not
detected.** What still holds for it:
- the order `P` respects every recorded edge in each branch (`c` does not
  decrease along `s` in a branch, so `(c, w, s)` orders each branch's own
  events correctly);
- identities are kept apart by the body hash, so no `q` merges wrongly;
- the winner is still the same on every replica, because `W` reads no fork
  state (section 9.1).

What is lost: the flag. A rule that wants to distrust `s` for that writer
cannot know to.

### 8.6 Tests, all new

Conflict, losing branch, compaction, fresh install, later same-`w`
operations:
1. Replicas A and B hold clones with the same `w`. Each publishes a different
   `(w, s) -> r`. One replica applies both: it flags `w`, locally and in its
   next segment's `f`.
2. The conflicting row loses its key. Fold keeps the winner, drops the loser's
   context row, and keeps `w` in `f`.
3. A snapshot is written. A **fresh install** applies the snapshot and its tail
   and reports `w` in `f`, with no loser anywhere in its data.
4. The clone continues to write under `w`. A later row of `w` arrives after
   the snapshot: `P` treats it as forked, and `f` is unchanged by a second
   fold.
5. Same body under same `(w, s)` and same `r`, different body under same
   `r` and different `w`, and different `a`: each is classified as in 8.3.
6. A generation bump empties `f`.
7. The undetectable case (8.5): the first side alone compacted, the second
   arrives: no flag, `P` order unchanged for each branch, identities distinct.

## 9. Comparators

There are two comparators and they must not be confused. **`W`** picks the
winner of a key. It exists today and has a defect (8.1). **`P`** is the one
order the later ordering rule projects over. `P` changes no winner.

### 9.1 The winner comparator `W`, with an exact tie rule

Compare two observations of one key in one generation. The greater wins.
`W` is the lexicographic order on this tuple:

`(o, r, rank, w', s', bodyHash)`

1. **`(o, r)`**: the stamp. Greater wins. Unchanged.
2. **`rank`**: the existing rank. An explicit delete beats an upsert, and an
   omission ranks below an observation (`OMISSION_RANK`, `log-apply.ts`
   tombstone rank). Unchanged.
3. **`w'`, then `s'`**: the observation's writer and its event sequence.
   `w'` is the context's `w`, or the empty string if there is no context, so
   **an observation with no context ranks below any observation with one**.
   `s'` is the context's `s`, or 0 if there is none. Greater wins.
   Equal stamp means the same run, and the same run has one `w` in one
   database (section 7.3), so for ordinary traffic `w'` is equal and `s'` is
   the order of the run's events (its batches and its run end): the later
   batch wins. `s` is incarnation-local. Across two writers the greater `w'`
   wins, and that has **no meaning in time**: it only makes the order total
   and the same on every replica.
4. **`bodyHash`**: the greater lowercase-hex hash wins; null (a delete or
   omission) is the same as any other null. Equal hashes mean equal bytes. The
   code compares body bytes after the hash today; that stays as the last guard.

`W` reads no part of the fork set `f`: a winner must not change when a fork is
learned later.

How each case lands:

| Case | Decided at |
|---|---|
| Legacy row, no context, against a row with a context | Step 3: the legacy row loses |
| Two legacy rows | Step 4 |
| Same run, one writer, two batches | Step 3: the later `s` wins. This equals today's "later batch wins" on the writer (`replaceOwnRunRows`, `admit.ts:168`), so the writer and the readers agree |
| Different writer incarnations, same run id (a clone) | Step 3: the greater `w` wins (deterministic, not temporal) |
| Same `(w, s)`, different bodies (a fork) | Step 4 |
| Equal hash and body | Same observation: no conflict |
| Delete against upsert at equal stamp | Step 2: the delete wins, whatever `s` is. `s` never overrides kind |
| Omission against observation | Step 2, unchanged |

**`W` is a strict total order.** It is a lexicographic order on a tuple of
totally ordered components, so it is transitive. (A version that compared `s`
only inside one writer and used the hash across writers is **not** transitive:
three observations from writers `w1`, `w2`, `w1` with `s` 5, 1, 3 and hashes
rising can form a cycle. That is the same flaw as the review's mixed-provenance
cycle, and it is why `w'` comes before `s'` here.) Because `W` is total, a fold
that keeps the greatest observation under `W` is commutative, associative and
idempotent. That removes the order dependence of the first-equal-wins rule at
`log.ts:434`.

**One comparator in three places.** The same rule must run on:
- local admission (`replaceOwnRunRows`, `admit.ts:168`, whose "later batch
  wins" is step 3);
- remote merge (`mergeIncoming`, `merge.ts:107`: today it replaces only on a
  strictly newer stamp; it must also replace when `W` is greater at an equal
  stamp);
- fold (`foldLog`, `log.ts:416`, replacing the first-equal-stamp upsert at
  `log.ts:434`) and `stampAfter` (`log.ts:151`).

SQL cannot call the TypeScript function, so the SQL form is a second
implementation. A property test compares them (section 9.2 and slice 6).
Records and tombstones need `w` and `s` at comparison time, so `records` joins
its context row on the equal-stamp path only.

**Agreement with any other fix of the equal-stamp divergence.** A change that
uses a per-run batch ordinal `b` (later batch wins) gives the same answer as
steps 3 and 4 on every pair of one writer's rows, because `s` is allocated in
the same transaction as the batch that carries `b` and both grow with intake
order. They can differ only for clone pairs and for legacy rows. For those the
other change must adopt steps 3 and 4 as written, with the hash last. The two
must not both be live with different orders, and the comparator must be one
function (SQL and TypeScript pair) used by admission, merge and fold. This
section does not wait on that change.

**Format.** `W` changes no stored byte: every entry already holds the stamp,
`d` (so `w` and `s`) and the body.

### 9.2 The projection order `P`

The problem in the review: a pairwise rule "use provenance if both have it,
else the stamp" is not transitive. With provenance order A < B, stamp order
B < C < A, and C unknown, the pairs give A < B, B < C and C < A, a cycle.

**`P` is one order for the whole population of a key in one generation.** Each
observation maps to one tuple, and tuples compare lexicographically.

- **Class N: no context.** The observation has no `d`, or a `d` whose context
  was never stored. Tuple: `(0, o, r, rank, bodyHash)`.
- **Class C: has a context.** Tuple: `(1, c, w, s', r, rank, bodyHash)`, where
  `s' = s` if `w` is not in `f` and `s' = 0` if `w` is in `f`.
  Events flagged `u = 1` are class C.

So **every observation of class N sorts below every observation of class C**,
whatever the stamps are, and the order inside each class is fixed and total.

**It is a strict total order.** Each tuple is a function of stored fields and
of `f` only. Each component has a total order. A lexicographic order on tuples
of totally ordered components is a total order. The last components make equal
tuples mean the same observation. It is therefore transitive, with no cycle.
Run on the review's counterexample: A and B are class C, so A < B. C is class
N, so C < A < B. The stamp order B < C < A is **not consulted** across classes.

**What it respects.** Inside class C: every edge `c` records (4.3), including
for flagged events (their recorded edges are real, 4.4). Inside class N: the
stamp, which is today's order.

**What it loses. "Nothing else is lost" is withdrawn.** Across the two
classes the stamp is ignored. So:
- a class N observation never beats a class C one under `P`, even where its
  stamp is greater. Class N rows are old by construction (seed rows, rows from
  before contexts existed), and under a lockstep upgrade no run after the
  upgrade creates one. An **import** or seed written after the upgrade is
  also class N, and may be younger than a class C row it ranks below. I did
  not check whether imports get contexts; the build should decide, and
  giving them contexts removes the loss;
- the order of events of a forked writer by `s` is lost (8.4);
- a flagged event can sort before a partial row it read (4.4);
- `P` is a function of `f`. Two replicas that hold the same containers agree.
  Replicas with different `f` can disagree until they converge, and `f`
  only grows.

**Mixed folds.** Fold and snapshot do not store `P`. They store the fields
`P` reads. So a population that is partly class N and partly class C folds,
splits and re-folds without changing any field.

**Tests, all new.**
- *Six-permutation.* Three observations of one key: A and B in class C with
  A < B by `(c, w, s)`, and C in class N with stamps ordering B < C < A.
  For each of the six delivery orders, and for each of: segments only, snapshot
  plus segment, fold then more segments, fold twice: the same `P` order
  C, A, B, the same `W` winner, and byte-equal folded output.
- *Property: strict total order.* Random populations over class N, class C,
  flagged, forked, equal `c`, equal `(c, w, s)`, equal stamp: for every pair,
  exactly one of `<`, `=`, `>`; for every triple, transitivity; sorting any
  shuffle gives one result.
- *Property: `W` parity.* The SQL form and the TypeScript form of `W` agree on
  random pairs and triples that include legacy rows, clone pairs (different `w`,
  same run), equal `s`, equal hash, delete/upsert and omission ties, including
  the three-writer cycle shape of 9.1.
- *Snapshot split.* A snapshot written at every possible split of a segment
  list, then applied on a fresh replica, gives the same `P` order and the same
  winners as the segments alone.

## 10. Seen sightings and promotion (review finding 4)

**What the code does.** An equal-body re-observation with a newer stamp moves
only `seen_o/seen_r` (`merge.ts:151`) and publishes nothing. The row keeps its
published stamp and, now, its published context. Three statements later turn
that sighting into the row's stamp, as a local change, so publish sends it:
- `mergeIncoming` with `promoteSeen` (`merge.ts:186` to `:205`), when a remote
  body that differs and is newer than the stamp arrives and the sighting is
  newer still;
- `applyDelete` (`merge.ts:253`), when a head omits the row and the sighting
  is later than the omission;
- `survivors` (`log-apply.ts:346`, the update at `:363`), for a delete or
  omission that the sighting outranks.

Without a change, each of these sets `stamp_o/stamp_r` to the sighting's and
leaves `obs` as the old winner's. Publish would then send the sighting's stamp
with the *old* observation's context. That is a wrong attribution.

**The design.**
- `seen_obs` is a nullable local column beside `seen_o/seen_r`. It holds the
  context id of the event that produced the sighting. That event already wrote
  a context row (every admitted event does), so there is nothing new to
  capture.
- **Invariant.** `seen_obs IS NULL` exactly when `seen_o IS NULL`, and
  `seen_obs` names the event of the stamp `(seen_o, seen_r)`. Every statement
  that sets, keeps or clears the seen stamp changes `seen_obs` in the same
  expression:

| Site | What it does to the seen stamp | What must happen to `seen_obs` |
|---|---|---|
| `merge.ts:151` | sets it from the incoming row | `seen_obs` = the incoming row's context id |
| `merge.ts:164-165` | keeps it if it outranks the incoming stamp, else clears it | the same `CASE`; and `obs`, `origin_q` come from the incoming row |
| `merge.ts:186-205` (promote) | copies it into the stamp | in the same `UPDATE`: `obs = seen_obs`, `origin_q = NULL`, `origin_g = NULL` |
| `merge.ts:253` (`applyDelete`) | copies it into the stamp | the same three assignments |
| `log-apply.ts:363` (`survivors`) | copies it into the stamp | the same three assignments |
| `merge.ts:349` | clears it for a retired run | `seen_obs = NULL` |
| `admit.ts:179` (`replaceOwnRunRows`) | clears it and replaces the body at the same stamp | `seen_obs = NULL`; `obs` = the new event's context id; `origin_q = NULL` |

- **Origin `q` of a promoted observation is `NULL` until its own first
  publication.** It was never published, even though its body equals a
  published one. Its identity (8.2) differs from the old winner's, because
  `(w, s)` differ. So the old `q` must not carry over, and no minimum is taken
  with it. Publish sends it as a first publication: no explicit `q`, and the
  reader reads the segment position.
- **Enforcement.** The wrong action is a statement that changes the seen stamp
  and not `seen_obs`. The build adds a trigger or a post-condition check on
  `records` that rejects `(seen_o IS NULL) <> (seen_obs IS NULL)`, so a new
  statement that forgets cannot ship silently. I did not check which SQLite
  forms `ALTER TABLE ADD COLUMN` allows for such a constraint, so the build
  chooses between a trigger and a test over every writer of `seen_o`.
- **Legacy.** A row whose `seen_o` was set before the upgrade has
  `seen_obs = NULL`. Promoting it gives `obs = NULL`: unknown provenance,
  class N. That is the honest result.
- **Local context rows** are kept while any of `obs`, `seen_obs`, an
  unpublished `record_changes` row or a tombstone refers to them, and may be
  dropped after the last reference goes. A sighting that is never promoted
  keeps one 143 B local row and publishes nothing.

**Test, all new (the review's).** Replica R holds key k with body `b`,
published (origin `q = 5`, context X). R applies a remote segment at position 6
(`c = 6`). A run on R re-observes `k` with the same body: event Y with
`(w_R, s, c = 6)`, so `seen = (o_Y, r_Y)` and `seen_obs = Y`; nothing is
published. Then, in three variants, a remote operation arrives: (a) a different
newer body (`promoteSeen`), (b) a head that omits k (`applyDelete`), (c) a
delete older than the sighting (`survivors`). Each time:
1. the row's `obs` is now Y and `origin_q` is `NULL`;
2. publish sends the entry with Y's context and no explicit `q`;
3. fold keeps the entry with `d` for Y and `q` equal to the new position;
4. a **fresh replica** applies the snapshot and shows the same `(w, s, c, t,
   u, a, r)` for k as R's Y, not X's;
5. a remote conflict at the same stamp and a remote delete after the promotion
   do not change attribution except through `W`;
6. the invariant holds after every statement (a property test over all
   writers of `seen_o`).

## 11. Retention

Decision unchanged: **Option B.** The stream log stays a compacted baseline
that keeps each key's winner, now with full provenance. A later record-level
sync adds a separate observation journal. This is a product tradeoff, not
preservation of every observation. The log loses:

- observations that lose at admission and never reach a segment: a body that
  `mergeIncoming` rejects (`merge.ts:107`), and an equal-body re-observation,
  which moves only the local seen stamp and publishes nothing, **unless a
  later remote operation promotes it (section 10)**. A promoted sighting is
  published, with its own context, once, and then it is the winner like any
  other. So whether a sighting survives depends on what arrives after it;
- intermediate changes to one key between two publishes, because
  `operationsFor` reads one current row per key (`log-publish.ts:854`);
- losing candidates that did reach a segment and were later folded away:
  `foldLog` keeps one upsert and one deletion per key (`log.ts:434`);
  compaction replaces the refs with a snapshot;
- older deletion, omission and upsert evidence under the same fold, and any
  per-run certificate of a complete scan: stream metadata holds the latest
  stream state, and `full_read` and `replace` are local run fields. An
  omission keeps today's semantics, not every future certification need.

**What the retained provenance supports.** A projection over the observations
that the log still holds: their writer, their order evidence, their window. It
does **not** support choosing a different winner by replaying discarded
candidates. A rule that would pick another historical winner needs the
journal, from its checkpoint on.

**What the journal needs, so it can start without a rewrite.**
- **Capture point.** The journal must record at the observation event, before
  a loser or an equal-body re-observation is dropped. The event is the same
  one that now writes a context row. A journal cannot be built by reading the
  log from a position, because the log never held those observations. The
  context row gives the journal a stable key for each event: `(w, s)`.
- **Atomic checkpoint.** Turning the journal on is one transaction that
  records the first `s` it covers. A journal entry before that `s` does not
  exist; this is stated, not repaired.
- **Baseline.** The state of a connection at the checkpoint is the result of
  applying the log through its position: the snapshot plus the retained
  segments above its `base`. It is not "a snapshot at exactly position `P_L`".
  A publish may leave a snapshot at another position (`log-publish.ts`
  compaction path).
- **Unknown history is not rebuilt.** Candidates that lose between the first
  format-2 write and the checkpoint are gone. A later upstream run can restore
  a current value only if upstream still serves it. It cannot restore a
  transient or deleted upstream state.
- **Deletion evidence and resets** need their own journal entries when the
  feature that makes them first appears, scoped by generation. I did not
  check whether any other store already holds them.

Prior art, second-hand and not re-read at the primary source: CouchDB keeps
every conflicting revision leaf until a client resolves it (Option A in cost).
Automerge keeps the full change history with actor, sequence and
dependencies; `w`, `s` and `c` are those three facts in compact form. LiveStore
treats an event log as the source of truth and snapshots as caches, which
matches the journal plus baseline. Kafka compaction keeps the latest record
per key and keeps deletion tombstones for `delete.retention.ms`, which
matches the stream log as a baseline.

## 12. Commit time at the registry

The registry keeps a durable server commit time for every position. In
`vana-com/data-gateway`, `data_point_versions.added_at` is set at the first
insert of a version and not changed afterwards (migration
`0028_split_data_point_versions.sql`, with `0048`-`0050`). The log row is a
data point, and its version is the log position. The signed versions
inventory (`api/v1/data/[dataPointId]/versions.ts`) lists it. The head read
returns only the first-registration `addedAt`, and the server drops it in
`toControlRead` (`packages/core/src/stream-sync/registry.ts:56`). So the log
needs no time field, and a later host must read the inventory by position.
That is why the log keeps `q` and `c`: they are the keys into `A(q)` and
`A(c)`.

Not verified: whether Web and PS-Lite hosts may call the inventory; whether
`added_at` is stale for a version whose first insert failed and was retried;
whether an old version can drop out of the inventory (expiry), which makes `A`
unknown for it; the read cost of many positions; whether `added_at` is
monotone in position; and its permanence across registry migrations. Section 5
gives the result when `A` is missing, unreadable or inverted: timing is
unknown and `P` is used.

## 13. Ordering semantics, TLA+, and formal evidence

**The provenance fields change no winner.** The winner of a key is `W`
(section 9.1): the greatest stamp, then rank, then the writer id and `s`, then the
body hash. The context table, `d`, `q` and `f` take no part in `W` except
through `w` and `s` in step 3. The existing invariants P1 to P5 and `OrderOK` do
**not** cover these fields: they model winners only. So the build must add
provenance checks as tests (section 15), not rely on the model.

**Formal evidence, corrected.** The model README's header still says "TLC has
not been run". Its own result sections record TLC runs on 2026-11-15. The
`Good` configuration is **bounded**: it stopped at 45 minutes (exit 124) with
no invariant error in at least 31.8 million distinct states, and
`EventuallyConverged` was not finished. `LostPush` finished the breadth-first
search with no invariant error, and its liveness check did not finish. The
mutant configurations (`DropGap`, `OutOfOrder`, `DroppedDeleteEffect`,
`ForgetTombstone`, `OmissionWithoutCutoff`, `OmissionInclusive`, `DropKind`,
`ReplayFromBase`, `LamportDifference`) failed as predicted. So the model is
checked inside its bound. There is **no complete proof of liveness and no
PASS** for `Good`. It models the protocol, not a refinement of the code.

**What changes in the model, and what does not.**
- **`W` (slice 6) changes semantics, so the model changes first.** Extend the
  stamp comparison in `LogProtocol.tla` with the writer's `s` and the body hash
  (`OrderOK`, line 85); replace `Admissible` (line 121) with "an equal key and
  stamp and `s` has the same body, or the tie rule decides"; re-run `Good` and
  every mutant, and add a mutant that keeps first-equal-wins to show the model
  catches the divergence.
- **`P` is not in the model.** It reads fields the model does not carry. Its
  properties (strict total order, edges respected, fold stability) are checked
  by the property tests of section 9.2, not by TLC. I did not extend the model
  to carry contexts. That would be a larger change, and I do not claim it.
- **A later counter-style or time-window rule** replaces `P`'s tuple, not `W`.
  It updates `OrderOK` and P5 only if it changes winners; it then needs a
  projection-convergence invariant (for every delivery order, equal projected
  winners). Keep `StampEqualsLamport` (line 269) an expected-FALSE witness, or
  replace it deliberately.

## 14. Items for the owner

1. **Source version.** Needs owner: manifest field. Smallest addition: a
   per-stream key, for example `source_version: { field, kind: "integer" |
   "timestamp" }`. The host reads the named field into a new entry field.
   Waiting costs nothing for upserts, because the value is in the body, and
   nothing can supply it for a delete today.
2. **Upstream account.** Needs owner: manifest field. Smallest addition: a
   per-connector key, for example `account: { stream, field }`. The host binds
   it to the connection and bumps the generation if it changes.
3. **Retention (section 11).** Option B accepts the loss of candidates that
   lose before the journal checkpoint. This is a product decision.
4. **Winner tie rule `W` (section 9.1).** Needs a decision and a model change
   before format 2 ships. It is not a provenance field.
5. **Browser rotation.** The browser host has no copy or restore guard. The
   in-log rollback check (section 7) is the only protection there.
6. **Imports.** Whether a row written by an import gets a context (section
   9.2). Giving it one removes the class N loss for imports.
7. **Any later field** needs a `LOG_FORMAT` bump and a lockstep client
   upgrade, because the codec is strict (`exactKeys`, `log.ts:723`). It needs
   no rewrite of stored data, because absence means unknown. I advise against
   a codec that ignores unknown keys.

## 15. Build slices

Each slice names its files and its tests. Tests marked **new** do not exist.

1. **Incarnation, sequence and forks.** Files: `core/src/localdb/schema.ts`
   (migration: `log_writer`, `log_forks`), `core/src/localdb/open.ts` (mint,
   rotation input, rotation at run boundary), `server/src/bootstrap.ts` and
   `lite/src/sync.ts` (pass the rotation request), the Desktop and phone hosts
   (they already compute the request). Tests, **new**: rotation on request and
   only at a run boundary; first mint; `s` never repeats across a crash inside
   one batch; a cloned file's rotation after the log shows its own `w`; the
   fork tests of 8.6.
2. **Context capture and the open-load marker.** Files: `run-intake.ts`
   (admission batch), `admit.ts`, `run-end.ts`, `log-apply.ts` (set the marker
   in a pass's first part batch; clear it in the batch that writes
   `log_state.position`), `merge.ts` (row carries its context id), `schema.ts`
   (`obs_ctx` with `u`, plus `obs`, `seen_obs`, `origin_q`, `origin_g` on
   `records` and `log_tombstones`; context id on `record_changes`). Tests,
   **new**: the counterexample of 4.1; `c` never exceeds the applied position
   for `u = 0` events; the progressive tests of 4.4 (early-completed stream X
   then local Y; marker cleared atomically; crash leaves it set); a CAS retry
   leaves a published event's context unchanged; one run, many events;
   unreferenced local contexts are dropped.
3. **Wire format.** Files: `stream-sync/src/log.ts` (field lists at `:689`,
   `:705-711`; encode and decode; `foldLog`: `ctx` with `u`, `d`, `q`, `f`;
   identity with the body hash), `log.test.ts`. Tests, **new**: the
   idempotence suite below, and the fork-set union.
4. **Apply, republish and promotion.** Files: `log-apply.ts` (`:346`,
   `:363`), `log-publish.ts` (`operationsFor`, `changedKeys`), `merge.ts`
   (`:151`, `:164-165`, `:186-205`, `:253`, `:349`), `admit.ts` (`:179`).
   Apply stores the descriptor and `origin_q` of every applied entry. Publish
   writes the stored descriptor of a copy, not the publisher's. Promotion moves
   `obs ← seen_obs` and clears `origin_q`. Tests, **new**: a remote
   observation republished keeps its `w`, `s`, `c`, `t`, `u` and `q`; the
   promotion test of section 10 in all three variants; the `seen_obs`
   invariant property test.
5. **Origin `q`.** Files: `log.ts` (fold minimum rule), `log-publish.ts` (set
   `origin_q` at commit only for the planned identity; bootstrap), `log-apply.ts`
   (generation reset). Tests, **new**: the idempotence suite; a lost
   acknowledgement keeps the minimum; an acknowledgement for a row changed
   since planning is ignored; a generation bump clears `origin_q`.
6. **Winner comparator `W` (separate change, before format 2 ships).** Files:
   `log.ts` (`stampAfter`, fold), `merge.ts`, `admit.ts`, `LogProtocol.tla`
   (first). Tests, **new**: a run publishes while collecting and replaces the
   body of a published key, and the writer and a fresh reader end on the same
   body; the `W` parity property test (SQL against TypeScript); all rows of the
   table in 9.1.
7. **Projection order `P` (a test-only reference implementation).** Files: a
   pure function and its tests under `stream-sync`. No production path reads
   it yet. Tests, **new**: the four tests of 9.2.
8. **Window helper (tests only, no host call).** A pure function from
   `(t, c, q, A)` to `{estimate, trusted}`. Tests, **new**: `c = 0`; missing
   inventory; an expired version; `A(c) > A(q)`; one-sided window; a valid
   window with a device clock far off.

**Idempotence and preservation suite (all new, slices 3 and 5).**
- `fold(fold(x))` equals `fold(x)` byte for byte, including `ctx` order, `d`,
  `q` and `f`.
- Splitting the same input at every point (snapshot plus segments, segments
  alone, fold then more segments) gives equal entries, `ctx`, `q` and `f`.
- Republishing a copy does not change its `q`. Publishing the same entry
  twice (a lost acknowledgement) converges to the minimum `q`.
- Applying a segment twice, or a snapshot then its own segments, leaves
  `origin_q` unchanged.
- A bootstrap row without a context has no `d` and `q = 0`, and a later copy
  with `q > 0` of the same identity wins by the minimum rule.
- Two entries with one `(w, s, stream, pk, kind)` and different bodies stay
  two identities and keep their own `q`.
- Identical `ctx` rows collapse; conflicting rows coexist and the fork is
  reported in `f`.
- After any sequence of publish, apply and compact, the winner's `(w, s, c, t,
  u, a, r)` equals the admission's.
- Winners with and without provenance are equal.
- TLA+: no change for slices 1-5, 7 and 8. Slice 6 changes `LogProtocol.tla`
  first.

## 16. Expect it to work because:

**What this design proves, by argument.** These are arguments from the code
and the definitions, not machine-checked results.
1. `P` is a strict total order on any mixed population (9.2): a lexicographic
   order on a total tuple. The counterexample of the review lands as
   C < A < B.
2. For every event with `u = 0`, the stored `c` is at or above `q` of every
   observation visible to the device at the event (4.3). `P` respects every
   edge recorded this way, including the edges a flagged event does record.
3. An identity includes the body hash, so no `q` is ever merged across bodies
   (8.2). The `q` minimum is idempotent, commutative and associative over true
   duplicates in one generation (6).
4. `W` is a total order, so a fold that keeps its maximum does not depend on
   delivery order (9.1). That closes the equal-stamp divergence of 8.1: every
   pair is decided by the tuple, with no pair left to arrival order.
5. A promoted sighting is published with its own context and no inherited `q`
   (10), if every writer of `seen_o` also writes `seen_obs`, which a trigger or
   test enforces.
6. A fork detected while both sides were together stays in `f` through
   compaction and reaches a fresh install (8.4).

**What it does not prove.**
- It does **not** record the exact causal edges of events admitted during a
  progressive first load (`u = 1`, 4.4). The record is a lower bound.
- It does **not** detect a fork whose first side was compacted away alone
  (8.5).
- It does **not** order class N against class C by the stamp (9.2), and it
  does not recover real time for rows with no window (5).
- It does **not** support choosing a different historical winner from discarded
  candidates (11).
- It proves nothing about timing unless the registry's commit times are
  monotone and readable (5, 12).
- `P` and the context fields are not in the TLC model. TLC is bounded and has
  no completed liveness result (13).
- The code was not run. The equal-stamp divergence is read from the code, not
  reproduced.

**How it works end to end.**
1. An admission batch or run end writes the rows, takes `s` from the counter,
   reads `c`, `now` and the open-load marker, and stores one context row. All
   in one `db.batch`.
2. Publish selects the changed keys, reads each row's stored context, and
   writes the `ctx` table with `d` indexes and the local fork set as `f`. A
   CAS conflict re-plans; the stored contexts do not change. The
   acknowledgement sets `origin_q` only for the identity it planned.
3. Apply stores each entry's descriptor and `origin_q`, adds any detected
   fork to `log_forks`, and sets or clears the open-load marker with the
   position.
4. A promotion moves `obs ← seen_obs` and clears `origin_q`.
5. Fold writes one `ctx` row per surviving descriptor, in canonical order, each
   surviving entry's minimum `q`, and the union `f`.
6. The journal starts at an atomic checkpoint and records events by `(w, s)`.

**The riskiest assumption.** That the one remaining gap, the open-load window,
is as rare as I believe and that a lower bound is enough there. Evidence for
rarity: it needs a first load of a connection and a local observation of the
same connection at the same time, and the design marks every such event.
Evidence that the loss is bounded: `c` is a valid lower bound, so no recorded
edge is wrong. What I did not measure: how often a device collects while it
loads. If it is often, the exact per-key choice of 4.4 is the upgrade, and it
cannot be applied to events already written. A second risk: the writer
incarnation protects against copies and rollbacks the host or the log can see.
A clone that has not published yet is not seen, and two copies can reuse `s`
until one publishes. The effect is bounded: identities stay apart, `P` stays
total, and the fork is flagged once both sides meet. A third: the latent
equal-stamp divergence is read from the code, not reproduced.

## 17. What I could not verify

- Whether a released client has written format 2.
- Whether `stream_partial` (`schema.ts:372`) covers exactly the open-load
  window, so the marker can reuse it.
- Whether a row written by an import gets a context, and the SQLite forms
  allowed for the `seen_obs` constraint.
- The host rows in section 7 come from a read-only survey of another
  repository, not re-read here. Browser database naming and the runtime's use
  of `device_id` next to the bindings are unverified.
- The equal-stamp divergence of 8.1: read from `run-intake.ts`, `admit.ts`,
  `merge.ts` and `log.ts`, not run.
- Registry questions in section 12 (host access, staleness, expiry,
  monotonicity, permanence, cost).
- Prior-art claims in section 11: second-hand.
- Byte figures: the 143 B context row and the 7 B empty `f` were measured on
  their JSON shape; all other figures, and the 0.4 s first-load estimate, are
  arithmetic, not device measurements.
- That `foldLog` can fill `q`, `ctx` and `f` without a signature change. It
  receives each `Segment` with its `position`, so I expect it can.
- TLC results beyond what the model's README records.
