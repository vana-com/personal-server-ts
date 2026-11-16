# Provenance that stream-sync log format 2 must carry

Design only. No code. Revision 2, after an independent review of revision 1.

Source pin: `vana-com/personal-server-ts` at
`85b3a8578fc66ba81834f5a5f4ac14e3fc6ef95d` (`feat/stream-sync`, after #715).
Every `file:line` is at that SHA. At this SHA `LOG_FORMAT = 2`
(`packages/stream-sync/src/log.ts:109`). If no released client has written
format 2, the fields below extend format 2 in place. If one has, they need
format 3. I did not verify which.

Goal, unchanged: store enough evidence before format 2's first real write that
a later ordering rule (counter-style, or bounded observation time) is a
projection over stored data, with no migration. Where the review found the
evidence too thin, this revision fixes the evidence. Section 1 says, for each
finding, what changed and what it costs.

## 1. What changed from revision 1, and why

| Review finding | Decision | Why | Cost |
|---|---|---|---|
| P2: begin-time `c` misses a dependency when the device applies a remote segment mid-run | **Fix the evidence.** Capture the applied position at each observation event (an admitted batch, or a run end), not at run begin. | A weaker promise ("concurrent unless known at begin") would let a counter-style rule order a later observation before the one it depended on. The fix is one `SELECT` in a batch that already runs. | One 136 B context row per event, plus 6-9 B per entry. Section 4. |
| P2: `o` is a caller claim and is not a lower bound | **Fix the evidence, in part; mark old timing unknown.** Add the host's own clock at each event (`t`). A rule clamps `t` into a window that comes from the registry's server-side commit times. `o` and the stamp do not change. | `t` alone is not trusted. The window needs no trust in any device clock. Where the window is not known (bootstrap rows), timing is unknown and the rule falls back to today's stamp order. | 18 B per context row. Section 5. |
| P2: `q` has no stable origin rule | **Fix: `q` means origin commit.** It survives republish, snapshot and fold by a minimum rule. `0` marks an unknown origin. | The commit time is the only server-side upper bound on an observation. A copy's later `q` would pass as the original time in a time-window rule. | 11 B per snapshot entry; 0 in a segment unless the entry is a copy. Section 6. |
| P2: writer incarnation is a precondition | **Fix: a new writer incarnation id, minted per database, rotated on copy, restore, rollback or reinstall.** `device_id` is not usable. | `device_id` is the server account address. It is the same for two databases of one account, and it survives a deleted and re-created database. Section 7. | 38 B per context row (inside the 136 B). |
| P3: formal evidence | **Corrected.** TLC ran on 2026-11-15. It is bounded, with no complete liveness proof. Section 11. | | none |
| Review point 2: run, stream and key identity | **Intake can accept two different bodies for one `(run, stream, pk)`.** The identity is `(w, s, stream, pk, kind)`, where `s` is a per-event sequence. This is by construction, so no random op id is needed. Section 8. | | none |

Things I decided **not** to do, because the fix costs more than it buys: a
per-writer frontier vector or an HLC counter (the position `c` already names a
full applied prefix); quarantining a connection on a conflicting identity (the
log's winners do not depend on provenance, so a conflict only needs a flag);
and using the unclamped caller claim as evidence (it would reopen the
tombstone-resurrection bug that `clampRunStart` prevents).

## 2. The set

Add now, as two structures and one rule:

1. **Observation contexts.** Each segment and each snapshot part carries
   `ctx: [{a, c, r, s, t, w}, ...]`, sorted by `(w, s, r)`. One row names one
   *observation event*: a batch that a run admitted into `records`, or the
   run-end step that applies deletes, omissions and staged rows. Fields:
   - `w`: writer incarnation id (32 lowercase hex, random). Section 7.
   - `s`: the writer's admission sequence. It grows by one per event, durably.
   - `c`: the log position this writer had applied when the event happened.
   - `t`: the host's wall clock (ms) when the event happened.
   - `a`: the artifact (connector) version string of the run.
   - `r`: the run id.
2. **A reference on each entry.** Upsert, delete and completion entries gain
   `d`, an index into the container's `ctx` array. An entry with no `d` has
   unknown provenance (seed rows, rows imported before the context existed).
3. **`q` on entries:** the commit position at which the observation first
   reached this log. A snapshot entry always carries it (`0` = unknown). A
   segment entry carries it only when it is a copy of an older observation;
   otherwise it is the segment's own `position`.

Not added: a random op id, an HLC counter, a frontier vector, a raw start
time, a run end time, a commit-time field. Source version and upstream
account wait for a manifest field (section 12).

## 3. Field table

Bytes are per row or per entry as the row says. The context row was measured
with a node one-liner on the real JSON shape (136 B with a 32-hex writer, a
7-digit `s`, a 13-digit `t`, a UUID run id). Everything else is computed from
the wire field lists. None of it was measured on a device.

| Field | Decision | Deciding test | Where it is set (at 85b3a857) | Bytes |
|---|---|---|---|---|
| `w` writer incarnation | **Add now** | (a) not rebuildable: nothing in a stamp, namespace or position names the device. (b) opaque. (c) small. | New local table, minted at first admission and on rotation (section 7). Encoded in the new `ctx` row; field lists at `log.ts:689` (segment), `log.ts:711` (part). | 38 per row |
| `s` admission sequence | **Add now** | (a) not rebuildable: the only clock-free order of one writer's own events, and the key that makes an observation's identity unique (section 8). | Allocated in the same `db.batch` as the admission, from a counter row. Admission batch: `run-intake.ts:596` (`admitUpserts`, `admit.ts:100`). Run end: `run-end.ts:290`. | 12 per row |
| `c` applied position | **Add now** | (a) not rebuildable: local state that moves on. (b) generic. (c) small. | `SELECT position FROM log_state` (`schema.ts:327`) inside the admission batch. `log-apply.ts:147` writes the position in the same batch as the rows it stands for, so `c` never runs ahead of applied data. | 11 per row |
| `t` host admission time | **Add now** | (a) not rebuildable. It is evidence only inside a registry window (section 5). | `deps.now()` inside the admission batch, as `run-intake.ts:359` already reads it for `o`. | 18 per row |
| `a` artifact version | **Add now** | (a) not rebuildable: it names the build that observed the row. | Already held: `runs.artifact_version` (`schema.ts:70`, `run-intake.ts:393`). Only the wire field is new. | 12 per row |
| `r` run id | Already present | n/a | `LogStamp.r` (`log.ts:145`). It also appears in the row so a row is self-describing. | 43 per row |
| `d` entry reference | **Add now** | (a) not rebuildable. An entry's event cannot be inferred from its run, because one run has many events. | New field on `UPSERT_FIELDS` (`log.ts:705`), `DELETE_FIELDS` (`:706`), `COMPLETE_FIELDS` (`:707`). | 6-9 per entry |
| `q` origin commit | **Add now** | (a) not rebuildable: `foldLog` (`log.ts:416`) drops the segment position of each winner. | Section 6. | 11 per snapshot entry; 0 in a segment unless a copy |
| Per-op id | **Never** | Derivable: `(w, s, stream, pk, kind)` is unique by construction (section 8). | None | 0 |
| HLC logical counter | **Never** | `c` is already a Lamport clock (section 4); `(c, w, s)` breaks every tie. | None | 0 |
| Frontier vector | **Never** | `c` names a full applied prefix. | None | 0 |
| Raw (unclamped) start time | **Never** | `clampRunStart` (`admit.ts:316`) raises `o` so a run cannot bring back a row that a newer run deleted. A rule that used the raw claim would reopen that bug. | None | 0 |
| Run end time | **Never** | Unknown when the first segment is built (`publishWhileCollecting`). The registry commit time bounds each entry from above. | None | 0 |
| Commit time in the log | **Never** | The segment is hashed before the registry accepts it. Section 10. | None | 0 |
| Source version | **Add later. Needs owner: manifest field.** | Nothing can fill it today. | n/a | n/a |
| Upstream account | **Add later. Needs owner: manifest field.** | Same. | n/a | n/a |
| Owner hide, delete, restore | **Add when the feature first occurs** | I found no owner operation in the log codec (`log.ts:314`, `LogEntry`). I did not check whether another store holds such operations. | n/a | n/a |

**Cost per run.** A run has one context row per event that left a surviving
entry: one per admitted batch and one for the run end. A small run has one or
two rows (136-272 B). A run that sends 100 batches has about 100 rows, about
13.7 KB. Each entry then costs 6-9 B for `d`, and a snapshot entry costs 11 B
more for `q`: 17-20 B per snapshot entry, about 1.5% of a 1.2 KB entry. On the
first-load floor (about 25 s for 439 MB at 17 MB/s) that is about 0.4 s. The
percentage falls if entries are larger. This is arithmetic, not a device
measurement. Revision 1 cost 115 B per run and 11 B per snapshot entry; the
increase buys the fix for finding 1.

## 4. Causal context (finding 1)

### What revision 1 got wrong

Revision 1 stored `c` once per run, at run begin. A device can apply a remote
segment while a run is still collecting. `log-apply.ts:147` shows apply
batches run independently of intake batches. A later batch of the same run
can then depend on that segment, and the begin-time `c` does not say so.

Review counterexample. Writer A's observation X commits at position 1, with
`c = 0`. Writer B's run begins at `c = 0`, B applies position 1, then B's
batch admits Y, which depends on X. With a begin-time `c`, Y has `c = 0`. If
`w_B < w_A`, the order `(c, w, s)` puts Y before X. That is the wrong order
for a counter-style rule.

### The fix and the counterexample under it

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
`(1, w_B, 2)`. Y sorts after X for any `w_A`, `w_B`. The counterexample is
ordered correctly.

### Why it holds in general

- **Edges.** For observations X and Y with `q_X <= c_Y`, the device that made Y
  had applied X before it admitted Y. The row of Y records that edge.
- **Lamport.** The event of X happened before X was published, so
  `c_X < q_X`. Together with `q_X <= c_Y`, this gives `c_X < c_Y`.
- **Same writer.** `c` never decreases along `s` for one writer incarnation,
  because the applied position never decreases. So `(c, w, s)` respects `s`.
  Rotation (section 7) starts a new `w`. After a copy or a rollback the new
  incarnation's first `c` is the position its database had applied, which can
  be below what the old incarnation published. The two are then different
  writers, ordered by `c` edges only.
- **No over-report.** The position is written in the same batch as the rows
  it stands for (`log-apply.ts:147`), so for a normal apply `c` never runs
  ahead of applied data. A first load that applies parts progressively
  (`log-progressive.ts`) is the case I did not verify: the build must prove
  that it does not advance `log_state.position` before its rows are applied
  (section 13, slice 2). An under-report is the safe direction for a rule
  that treats unknown order as concurrent; an over-report is not.

### What is and is not claimed

Claimed: for every pair of observations, the stored evidence records every
order the device itself knew at its observation events. A linear extension
such as `(c, w, s)` respects all of them. This is the property an
Automerge-style rule needs. Automerge's own per-op counter is not reproduced,
and a causality-consistent order is not a freshness rule.

Not claimed: the position says nothing about local observations that were
never published (they are ordered by `s` for one writer), nor about a record a
run read from upstream before it applied a segment. The event captures when
the device *admitted* the observation, which is the creation point of the log
operation.

Cost: the `SELECT` is one indexed read. The row is 136 B per event.

## 5. Observation time (finding 2)

`o` is a caller claim. `run-intake.ts:359` sets `o = min(observedAt ?? now,
now + 300000)`, then `clampRunStart` (`admit.ts:316`) may raise it above the
tombstone watermark. So `o` can be later than the observation, even later
than the commit, and an old claim can be arbitrarily early. It is a stamp,
not a clock. This design does not change the stamp or the clamp.

Evidence added: `t`, the host's wall clock at the event. It is untrusted by
itself. It is made useful by a window that needs no device clock:

- **Lower bound.** The event happened after position `c` was applied, so it
  happened after the registry committed position `c`. The server commit time
  of `c` (`A(c)`) is a lower bound. `A(0)` is unknown.
- **Upper bound.** The observation was in the log by its origin commit `q`.
  The server commit time of `q` (`A(q)`) is an upper bound. Section 10 says
  how to read `A`.
- **Estimate.** `t`, clamped into `[A(c), A(q)]`. The estimate cannot be wrong
  by more than the window's width, whatever the device clock says. A quiet log
  gives a wide window and a busy log a narrow one.

Skew assumption: none for safety. The window uses only the registry's clock.
For accuracy, a fast or slow device clock moves `t` inside the window and no
further. If the registry's `added_at` is unreadable or stale (section 10), the
window is unknown and the rule must use the fallback below.

**Old timing is unknown, and a time-window rule loses exactly this.** Rows
that have no `d` (seed rows, rows imported before contexts existed) and
snapshot entries with `q = 0` have no window. A bounded-observation-time rule
cannot place them against a concurrent candidate. It falls back to the stamp
order (today's rule) for any comparison that involves such a row. It loses:
detection of near-simultaneous conflicts with those rows, and the five-minute
"unsettled" signal for them. Nothing else is lost. A counter-style rule is not
affected, because it uses `c`, `w` and `s`, which are absent for the same
rows; for them it also falls back to the stamp.

## 6. Origin commit `q` (finding 3)

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
- **Local storage.** `records` and the delete tombstones (`log_tombstones`,
  `schema.ts:327` onward) gain a nullable `origin_q`. `NULL`: never published.
  Apply sets it from the entry (`q`, or the segment position). The publisher
  sets it when its own segment commits.
- **Republish of a copy.** The entry carries the stored `origin_q` as an
  explicit `q`, so the copy does not take the new position.
- **Fold.** `foldLog` (`log.ts:416`) already receives each `Segment` with its
  `position`. For each surviving entry it writes `q` = the entry's explicit
  `q`, or the position of the segment it came from, or the old part's `q`.
- **Bootstrap.** The first snapshot is written from `records` at position `P`.
  A row with a context (`d`) was admitted under this design, so its first
  appearance in the log is `P`: `q = P`. A row without a context has no
  recorded origin: **`q = 0`**, which means unknown. The container's position
  stays the only bound for it.
- **Equal identities.** The same observation can appear many times (segment,
  part, copy). Its identity is `(w, s, stream, pk, kind)` (section 8). The
  merged `q` is the **minimum over occurrences with `q > 0`**; `0` loses to
  any known value. The minimum is commutative, associative and idempotent, so
  fold order and repeat folds give the same bytes. Two occurrences of one
  identity with different bodies are not a valid input (section 8): keep the
  first by position and flag it.
- **Generations.** Positions are comparable inside one generation. A part and
  its segments share a generation, so the minimum never mixes generations.

Cost: 11 B on each snapshot entry; nothing on a first-publication segment
entry; one nullable column.

## 7. Writer incarnation (finding 4)

### What the code does today

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

### What each host does today

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

### The design

- **`w` is a random 128-bit incarnation id**, 32 lowercase hex characters,
  minted by a cryptographic random source. The incarnation is encoded in `w`;
  there is no second field. A new database mints one at its first admission.
- **Storage.** One new local table, append-only like the replication identity
  table: `log_writer(w, born_at, next_s)`. The current writer is the newest
  row. `next_s` is the only mutable column. The allocation of `s` reads and
  increments `next_s` in the **same `db.batch` as the admission**, so a
  crash cannot lose or reuse a value inside one database file.
- **Rotation, without rewriting history.** Rotation adds a row with a new `w`
  and `next_s = 1`. Old descriptors keep the old `w`. Ordering across the
  rotation is kept by the `c` edges (section 4); `s` order is not, because the
  two incarnations are different writers. Triggers:
  1. **Host request.** `openLocalDb` gains an input equal to the existing
     boot request (`rotateWriterIdentity`). The log writer rotates before the
     first admission of the boot, whether or not replication runs. Desktop and
     phone already compute this request; browser hosts do not.
  2. **First use.** A database with no `log_writer` row mints one.
  3. **Rollback or clone seen in the log.** At apply, if a descriptor carries
     the device's *current* `w` and either its `s >= next_s` or its `s` is
     held locally with a different `r`, then the log holds history from this
     writer that this database does not have. The database was rolled back or
     cloned. It rotates before its next admission. This covers the browser,
     which has no host guard. It does not cover a clone that publishes
     nothing before the second copy publishes: until the second copy's first
     publication reaches the other, the two share a `w` and may reuse `s`.
- **A conflicting `(w, s) -> r`.** `(w, s)` must name one event, and an event
  has one `r`. When apply meets a row with the same `(w, s)` and a different
  `r` (or different `c`, `t` or `a`), it **keeps both rows and flags `w` as
  forked**, locally and by deriving it again from the log at any time. Both
  rows can coexist because every entry holds its own `d` and the rows differ
  by content. A projection rule must treat `s` order within a forked `w` as
  unknown, and use `c` alone for those rows. Nothing is rejected and no apply
  stalls. The replication layer quarantines a connection for the same kind of
  conflict (its README, line 60). I do not copy that here: a log winner does
  not depend on provenance, so a provenance conflict cannot make two devices
  disagree about winners. It only weakens ordering evidence.
- **Trust.** Every writer of a connection's log is the owner's own device.
  Descriptors of other writers are copies the publisher read from the log. The
  design does not defend against a hostile writer; it records enough to detect
  an honest fork.

## 8. Identity of an observation, and what intake accepts (review point 2)

**Intake can accept two different bodies for one `(run, stream, pk)`.** Read
from the code, not run:

- `run-intake.ts:561` stages a row with `INSERT OR REPLACE INTO run_rows`. A
  later batch with the same key replaces the earlier staged body. The table's
  primary key is `(run_id, stream, pk_hash)` (`schema.ts:86`); it holds one
  row at a time, not the history. `run-intake.ts:487` answers a replayed batch (same or older batch
  number) as a replay, but a new batch for the same key is accepted.
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

So with a run that publishes while it collects, one `(r, stream, pkHash,
kind)` can name two bodies, and the writer and every reader can end on
different bodies. The formal model assumes this cannot happen:
`Admissible` (`docs/formal/log-protocol/LogProtocol.tla:121`) refuses a batch
with an equal key and stamp and a different body. The implementation does not
enforce it on this path. I did not reproduce the divergence; it needs a test
(section 13). `run_id` is also only text of length 1-128 (`schema.ts:70`), so
a UUID is a host convention.

**The identity rule.** An observation is `(w, s, stream, pkHash, kind)`. It is
unique by construction: `s` is allocated once per event, and an event writes
one body per key (`incoming` is keyed by `(op, stream, pk_hash)`, so a later
row of the same batch replaces the earlier one before it reaches `records`).
So no random op id is needed (it would add bytes and no information), and the
rule needs no intake check.

**The winner tie rule is a separate, existing defect.** Provenance does not
change which observation wins. The case above needs a deterministic tie rule at
equal stamp. With `s` in every entry, the smallest sound rule is: at equal
`(o, r)`, the greater `s` wins, and equal `s` with different bodies is a
forked identity and falls back to the greater body hash. That changes ordering
semantics, so it needs the model change in section 11 first. It is not part
of format 2: it changes no stored byte, because every entry already holds
what the rule reads. I recommend it as a separate change before format 2
ships, because the divergence exists today whenever a run publishes while it
collects.

## 9. Retention

Decision unchanged: **Option B.** The stream log stays a compacted baseline
that keeps each key's winner, now with full provenance. A later record-level
sync adds a separate observation journal. This is a product tradeoff, not
preservation of every observation. The review corrected the list of what the
log loses. It is:

- observations that lose at admission and never reach a segment: a body that
  `mergeIncoming` rejects (`merge.ts:107`), and an equal-body re-observation,
  which moves only the local seen stamp and publishes nothing;
- intermediate changes to one key between two publishes, because
  `operationsFor` reads one current row per key (`log-publish.ts:854`);
- losing candidates that did reach a segment and were later folded away:
  `foldLog` keeps one upsert and one deletion per key (`log.ts:434`);
  compaction replaces the refs with a snapshot;
- older deletion, omission and upsert evidence under the same fold, and any
  per-run certificate of a complete scan: stream metadata holds the latest
  stream state, and `full_read` and `replace` are local run fields. An
  omission keeps today's semantics, not every future certification need.

Revision 1 said "a losing candidate never reaches a segment". That was
overbroad and is withdrawn.

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
  A publish may leave a snapshot at another position
  (`log-publish.ts` compaction path).
- **Unknown history is not rebuilt.** Candidates that lose between the first
  format-2 write and the checkpoint are gone. A later upstream run can
  restore a current value only if upstream still serves it. It cannot restore
  a transient or deleted upstream state.
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

## 10. Commit time at the registry

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
the read cost of many positions; and the permanence of `added_at` across
registry migrations. Section 5 gives the fallback when `A` is unreadable.

## 11. Ordering semantics, TLA+, and formal evidence

**The provenance fields change no winner.** The winner of a key stays the
greatest `(o, r)` stamp. Deletes beat ties with upserts, and an omission ranks
below an observation at the same stamp. `foldLog` keeps one upsert and one
deletion per key. The context table, `d` and `q` take no part in that
decision. The existing invariants P1 to P5 and `OrderOK` do **not** cover
these fields: they model winners only. So the build must add provenance checks
as tests (section 13), not rely on the model.

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

**A later rule change updates the model first.** Module:
`docs/formal/log-protocol/LogProtocol.tla`. If a counter-style or time-window
rule replaces `(o, r)`:
- update `OrderOK` (line 85) and P5 (snapshot and full-replay consistency),
  and the convergence obligations;
- add a projection-convergence invariant: for every delivery order, the
  projected winners are equal;
- keep `StampEqualsLamport` (line 269) an expected-FALSE witness, or replace it
  deliberately.

**The tie rule of section 8** changes semantics. Before it is built: extend the
stamp comparison in `LogProtocol.tla` with `s`, replace `Admissible` (line 121)
with "an equal key, stamp and `s` has the same body", and re-run `Good` and the
mutants. Without that edit the model keeps assuming a property the code does not
enforce on this path.

## 12. Items for the owner

1. **Source version.** Needs owner: manifest field. Smallest addition: a
   per-stream key, for example `source_version: { field, kind: "integer" |
   "timestamp" }`. The host reads the named field into a new entry field.
   Waiting costs nothing for upserts, because the value is in the body, and
   nothing can supply it for a delete today.
2. **Upstream account.** Needs owner: manifest field. Smallest addition: a
   per-connector key, for example `account: { stream, field }`. The host binds
   it to the connection and bumps the generation if it changes.
3. **Retention (section 9).** Option B accepts the loss of candidates that
   lose before the journal checkpoint. This is a product decision.
4. **Equal-stamp tie rule (section 8).** Needs a decision and a model change
   before format 2 ships. It is not a provenance field.
5. **Browser rotation.** The browser host has no copy or restore guard. The
   in-log rollback check (section 7) is the only protection there.
6. **Any later field** needs a `LOG_FORMAT` bump and a lockstep client
   upgrade, because the codec is strict (`exactKeys`, `log.ts:723`). It needs
   no rewrite of stored data, because absence means unknown. I advise against
   a codec that ignores unknown keys.

## 13. Build slices

Each slice names its files and its tests. Tests marked **new** do not exist.

1. **Incarnation and sequence.** Files: `core/src/localdb/schema.ts`
   (migration: `log_writer`), `core/src/localdb/open.ts` (mint, rotation
   input), `server/src/bootstrap.ts` and `lite/src/sync.ts` (pass the rotation
   request), the Desktop and phone hosts (they already compute the request).
   Tests, **new**: rotation on request; first mint; `s` never repeats across a
   crash inside one batch; a cloned file's rotation after the log shows its
   own `w`; a forked `(w, s) -> r` keeps both rows and sets the flag.
2. **Context capture.** Files: `run-intake.ts` (admission batch),
   `admit.ts`, `run-end.ts`, `merge.ts` (row carries its context id),
   `schema.ts` (`obs_ctx`, plus a context id on `records` and
   `record_changes`). Tests, **new**: the review counterexample (B applies a
   segment mid-run, then admits Y; `c_Y >= q_X`); `c` never exceeds the
   applied position, including during the progressive first load; a CAS retry
   leaves a published event's context unchanged; one run, many events.
3. **Wire format.** Files: `stream-sync/src/log.ts` (field lists at `:689`,
   `:705-711`; encode and decode; `foldLog`), `log.test.ts`. Tests, **new**:
   the idempotence suite below.
4. **Apply and republish.** Files: `log-apply.ts`, `log-publish.ts`
   (`operationsFor`, `changedKeys`), `merge.ts`. Apply stores the descriptor
   and `origin_q` of every applied entry. Publish writes the stored descriptor
   of a copy, not the publisher's. Tests, **new**: a remote observation
   republished keeps its `w`, `s`, `c`, `t` and `q`.
5. **Origin `q`.** Files: `log.ts` (fold minimum rule), `log-publish.ts`
   (set `origin_q` at commit), bootstrap in `log-publish.ts`. Tests, **new**:
   see the suite.
6. **Tie rule (separate change).** Files: `log.ts` (`stampAfter`, upsert),
   `merge.ts`, `LogProtocol.tla`. Test, **new**: a run publishes while
   collecting and replaces the body of a published key; the writer and a fresh
   reader end on the same body.

**Idempotence and preservation suite (all new, slice 3 and 5).**
- `fold(fold(x))` equals `fold(x)` byte for byte, including `ctx` order, `d`
  and `q`.
- Splitting the same input at every point (snapshot plus segments, segments
  alone, fold then more segments) gives equal entries, `ctx` and `q`.
- Republishing a copy does not change its `q`. Publishing the same entry
  twice (a lost acknowledgement) converges to the minimum `q`.
- Applying a segment twice, or a snapshot then its own segments, leaves
  `origin_q` unchanged.
- A bootstrap row without a context has no `d` and `q = 0`, and a later copy
  with `q > 0` of the same identity wins by the minimum rule.
- Identical `ctx` rows collapse; conflicting rows coexist and the fork is
  reported.
- After any sequence of publish, apply and compact, the winner's `(w, s, c, t,
  a, r)` equals the admission's.
- Winners with and without provenance are equal.
- TLA+: no change for slices 1-5. Slice 6 changes `LogProtocol.tla` first.

## 14. Expect it to work because:

**Why this set is enough for both rules.** A counter-style rule needs, for
each observation, who made it, what order that writer knew, and every
observation the writer had applied when it made it. `w`, `s` and `c` at the
event give exactly those, and section 4 shows `(c, w, s)` respects every
recorded edge, including the review's counterexample. A bounded-observation-time
rule needs a window for each observation. `t` clamped into `[A(c), A(q)]`
gives one whose width, not a device clock, bounds its error, and rows with no
window are marked unknown so the rule can fall back to the stamp. Neither rule
needs a stored byte that this design does not carry: source version and
upstream account have nothing to store until a manifest field exists, and
absence reads as unknown.

**How it works end to end.**
1. An admission batch or run end writes the rows, takes `s` from the counter,
   reads `c` and `now`, and stores one context row. All in one `db.batch`.
2. Publish selects the changed keys, reads each row's stored context, and
   writes the `ctx` table with `d` indexes. A CAS conflict re-plans; the
   stored contexts do not change.
3. Apply stores each entry's descriptor and `origin_q`, so a later republish
   keeps the original writer and origin.
4. Fold writes one `ctx` row per surviving descriptor, in canonical order, and
   each surviving entry's minimum `q`.
5. The journal starts at an atomic checkpoint and records events by `(w, s)`.

**The riskiest assumption.** That capturing context at the admission event
records every dependency a rule can need. Evidence: the applied position is
written with the rows it stands for (`log-apply.ts:147`); SQLite serializes the
admission batch against apply batches; and the Lamport inequality holds for
every recorded edge. What is not covered: an observation a run read from
upstream before it applied a segment is ordered as after that segment. That is
the creation point of the log operation, and it matches Automerge's meaning of
a dependency, but a freshness rule will see the read time only through `t` and
the window. A second risk: the writer incarnation protects against copies and
rollbacks the host or the log can see. A clone that has not published yet is
not seen, and two copies can reuse `s` until one publishes. The effect is
bounded: both rows are kept, the fork is flagged, and a rule falls back to
`c`. A third: the latent equal-stamp divergence of section 8 is read from the
code, not reproduced, and its fix is a separate change.

## 15. What I could not verify

- Whether a released client has written format 2.
- Whether the progressive first load (`log-progressive.ts`) advances the
  applied position before its rows are applied. The `c` guarantee depends on it.
- The host rows in section 7 come from a read-only survey of another
  repository, not re-read here. Browser database naming and the runtime's use
  of `device_id` next to the bindings are unverified.
- The equal-stamp divergence of section 8: read from `run-intake.ts`,
  `admit.ts`, `merge.ts` and `log.ts`, not run.
- Registry questions in section 10 (host access, staleness, permanence, cost).
- Prior-art claims in section 9: second-hand.
- Byte figures: the 136 B context row was measured on its JSON shape; all other
  figures, and the 0.4 s first-load estimate, are arithmetic, not device
  measurements.
- That `foldLog` can fill `q` and `ctx` without a signature change. It receives
  each `Segment` with its `position`, so I expect it can.
- TLC results beyond what the model's README records.
