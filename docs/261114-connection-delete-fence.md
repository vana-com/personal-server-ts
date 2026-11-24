# Connection delete: control tombstone first (a fence)

Status: implemented in `packages/core/src/localdb/delete.ts`.

## Problem

`land()` cleaned stream after stream (about 7 registry calls each) and wrote the
control tombstone last. Two faults followed.

1. **Latency.** Delete time was the sum of all stream chains (8.2 s measured,
   0.5 s floor).
2. **Data loss.** A delete that finishes late (a Web tab closed mid-delete) could
   land its control tombstone after another device had reconnected and published.
   The late tombstone then ended the new lifetime too.

## Design

1. **Fence.** Post the control tombstone first, at `pin.version + 1`. It is the
   single linearization point. After it, every surface reads the connection as
   deleted.
2. **Persist the phase.** `delete_intents` keeps `fences: [{ns, version}]`. A
   restart does not mistake its own tombstone for a reconnect, and a saved fence
   is not posted again.
3. **Confirm, never re-issue.** After a refused (409), a lost reply or any other
   failed post, read the control row. The fence holds if control is deleted at
   version >= pin+1, or active at a generation > pin (a reconnect won). The read
   decides even when the post failed for a transport reason, so a registry that
   now refuses posts but still answers reads does not hold the delete pending.
   Only when the read cannot prove the fence does the delete stay pending; the
   next attempt resends the same `pin + 1`. The tombstone never lands twice: a
   resend is refused by the registry's CAS, or confirmed by the read. It can be
   sent more than once (crash or lost reply before the fence phase is saved), and
   it is never a new, incremented tombstone.
4. **Cleanup in parallel.** Each stream chain touches only its own registry row.
   Chains run together. `streamsLanded` stays cleanup-only.
5. **Cleanup is bounded by the lifetime it ended.** A stream is tombstoned only if
   its head generation is <= the ended lifetime (`holdsEndedLifetimeOnly`). A row
   written by a later lifetime is left alone. There is no "superseded" exit.
6. **No second tombstone.** After the fence the control row is never written
   again by this delete, even when a reconnect superseded it.
7. **Request answer.** `requestConnectionDelete` waits for the fence, then
   answers `{deleteId, fenced}`. `fenced:false` means the registry did not
   confirm the fence in time: the delete is saved and retried, but other devices
   cannot see it yet.
8. **Bounded wait.** The request waits for the fence no longer than the resume
   loop's first wait (`deleteRetryMs.first`, 5 s by default, in `sync.ts`). That is
   the time after which the loop would look at a delete that has not landed, so
   the answer and the retry agree. No existing deadline fits better: the registry
   client has no per-call deadline, the storage `retryBudgetMs` (180 s) is a
   storage budget and far above a click, and Desktop and Web call the route with
   no deadline of their own. The landing is not cancelled at the budget: a slow
   registry that answers later still lands the fence. `plan()` (registry reads
   before the intent is saved) is outside this bound, as it was before.

## Prior art

- Kubernetes namespace deletion: a Terminating state is set first; controllers
  then delete the children. Divan:
  `distributed-systems/a-container-delete-is-fenced-by-a-lifetime-identity-or-terminating-state-...`.
- Kleppmann, fencing tokens: the store checks a monotone token. Here the
  gateway checks the control row as an atomic condition on every publish batch.

## Reader paths (a deleted control row hides live stream rows)

| Reader                       | Behaviour                                                                                                                                |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| apply (`apply.ts`)           | deleted control: purge local rows, `control_state='deleted'`, checkpoint cleared                                                         |
| bootstrap (`bootstrap.ts`)   | a joining device records the deleted state and loads no stream                                                                           |
| history/query (`history.ts`) | `control_state='deleted'` answers 410; reads join on `control_state='active'`                                                            |
| publish (`publish.ts`)       | a deleted control row purges; a publish from an old holder is refused by the gateway condition                                           |
| publish, new lifetime        | a stream row of an earlier lifetime that is still live makes the publisher defer (`stream_delete_not_proven_earlier`) until cleanup runs |

Covered by `delete-reconnect-publish.test.ts`: "after the fence and before
cleanup, every reader hides the streams..." (apply, bootstrap, publish) and
"after the fence, direct history and query reads answer deleted and empty..."
(`createLocalHistory.versions` and `.lineage` answer `deleted`; `listRecords`
and `getRecord` are empty). A device reads the fence on its next apply: a device
that has not synchronized yet still serves its cached rows until then.

## Model coverage (the delete-order TLA+ model, variants A, A3s and bare reorder)

Modelled: fence-first order, head-generation classification, confirm at
version >= pin+1, cleanup bounded by lifetime, parallel cleanup chains, reconnect,
crash, stale in-flight CAS.
Not modelled, handled in code and tests: absent control rows (cleanup only,
no tombstone), legacy intents without `fences` (they enter the fence phase too: control first; one already `streamsLanded` skips cleanup and finishes with the tombstone),
local purge (`purgeLocal` generation guards kept), registry lag (a read below
pin+1 stays pending).

The model's cleanup was one sequential loop, so it was extended first: variant
`OptionAPar` runs each stream as its own chain with any number of CAS in flight
(a superset of the code, which waits for each reply). TLC exhausted the state
space at 2 surfaces (50k distinct states) and 3 surfaces (14.2M): no safety
invariant fails, and at 2 surfaces every intent ends with no old data left. Only
`NoLossAfterReq` fails, the known limit. A mutant that also tombstones a later
lifetime fails `NoNewGenLoss`, so the check can fail. Results and bounds:
`results-d3.txt` next to the model. The tests also assert parallelism (a barrier
test and a latency-ratio test).

## Known limits

- `NoLossAfterReq` fails in the model for every variant. A delete not yet visible
  on the registry cannot protect later publishes, so the caller sees `fenced:false`.
  Data published at the same generation before the fence is deleted by design.
- If the deleting device never returns, rows of the ended lifetime stay and a
  reconnected device defers. The old order had the same hole. Follow-up: an
  orphan sweeper that any surface can run, or letting the publisher overwrite
  data heads it can prove ended.
- A registry call that never returns holds the landing (and the per-connector queue
  lane) for good, and `plan()` is not bounded: the request still waits there. The
  registry adapter has no timeout.
- Unity Surfaces UI should show "pending" when `fenced:false`. Out of scope here.

## After the fence: the legacy copy and the status

On a switched account the fence is not the whole delete. The gateway still lists
the connector's legacy data points, and storage still holds their blobs. Once a
control tombstone of the connector is final, the deleter's settled pass retires
every legacy scope bound to the connector (`localdb/legacy-delete.ts`):

- It is driven by state (a final control tombstone, a bound legacy scope with a
  live gateway head), not by `delete_intents`. That row means "a delete is
  landing" and blocks reconnects; a legacy retire can take hours behind
  storage's rate limit. The start sweep resumes it after a restart.
- It does nothing before the switch (the legacy copy is the live store then).
  After it, no legacy scope accepts a write, so a connection added again writes
  only to its own log scope, which the stage never names. Each tombstone is
  fenced to the head the stage read.
- The tombstone leaves through the seal's `remove`. A gateway refusal that a
  retry cannot change (`owner_stream_sync_required`, `server_revoked`,
  `server_unregistered`) shows that scope as `blocked`, is asked once, and
  never holds back a scope that is only waiting: retry is decided per scope,
  and per stage (legacy, storage), apart from what is shown.
- A legacy scope is `done` only on evidence any device can re-check, never on
  this device's queue being empty. With the head deleted and the tombstone
  final, the stage reads the scope's gateway history (the version inventory,
  which keeps every slot after a tombstone) and confirms each slot with
  storage's idempotent delete: deleted or missing. A crash between the
  tombstone and the queue write, or another device's unfinished drain, leaves
  work that the next device to look re-derives this way. A restart confirms
  again; that costs delete requests, not state.
- Storage reads `done` only when this delete's own evidence shows that every
  log object of the deleted lifetime is gone: this device enumerated the log
  whole before it erased (`enumerated_logs`, one mark per registry head, so one
  lifetime's enumeration never vouches for the next) and storage acknowledged
  each object. Every other path reads `blocked`, never `done`:
  - `body_pieces_retained`: this device erased the log and left body pieces
    (`retained_log_pieces`), the record that makes later passes answer for them.
  - `erased_elsewhere`: objects were already gone when this device looked and
    it has no mark for this head (another device erased, or was cut off after
    the parts and segments but before the head), or the log is gone and the
    registry shows one existed. This device cannot re-check the pieces.
  - `re_added`: a reconnect replaced the deleted lifetime before or during the
    pass. The old objects stay, and the new lifetime hides what is safe to
    erase.
  - `tombstone_rolled_back`, `log_unreadable` as before.
    A log the registry never held an object of counts as enumerated whole. A
    namespace this device knows a tombstone for but no pass has judged is
    `pending`.
- A delete is identified by its control tombstones: the registry version each
  namespace's tombstone landed at, learned when this device lands the fence or
  purges the connection the tombstone ended. Both stages judge that tombstone's
  own finality (`tombstoneState`), not the control head as it is now, so a
  reconnect (a live head over a final tombstone) still retires the legacy copy
  and a rollback (the live head back, the tombstone failed) reads
  `blocked(tombstone_rolled_back)`. The cached verdict is kept under the same
  identity: a higher tombstone is a newer delete and drops it, and a pass that
  began under the older one cannot write a verdict. A refused request changes
  nothing.
- The identity survives a restart. Each learned tombstone is a row of
  `delete_tombstones(connector, ns, version, done_at)`, written in the
  transaction that taught it (the fence landing with the intent, the purge with
  the connection's removal; a higher version replaces a lower and resets
  `done_at`). A start loads the table before the first pass, and the start sweep
  owes every connector that has a row with `done_at IS NULL`, so a connection
  added again after its delete does not hide the delete's work. When all three
  parts are `done` at the versions held, the rows are kept and `done_at` is set:
  the final verdict is durable, so a reconnect and a restart still read `done`
  and owe nothing. They do not use `connections.control_version`, which a
  reconnect moves. Migration 41 adds `done_at`.
- A verdict, and a ledger row, speak only for the confirmed tombstone they were
  judged at. The ledger takes only confirmed tombstones: a fence that landed, a
  tombstone a purge adopted from the registry, or one a registry listing shows.
  A purge that runs ahead of its fence (the local purge after the intent is
  saved), or of a connection no registry row names (version 0), still trips the
  stale runs but writes no row; a foreign head that supersedes a fence leaves
  none behind. Before any path reads a verdict it compares it with the newest
  tombstone a fresh listing shows, in one function (`adoptEnded`): a tombstone
  above the one held for the same namespace is recorded, clears the connector's
  `done_at`, drops the cached verdicts and refusals and owes both stages. The
  status read, a delete request (its plan), the erasure pass and the start
  sweep all make that comparison first; a listing that fails leaves the known
  tombstones standing. A read that finds a newer delete arms the retry loop.
- A part that reads `pending` always has work queued, found from the same rows
  that gave the status. The erasure report names every deleted namespace it left
  alone (`skipped`: a live local connection holds it). A skipped tombstone reads
  `storage: blocked(re_added)` and owes no pass (a reconnect replaced the
  lifetime); one the report neither erased nor skipped reads `pending` and the
  pass retries. Retry flags come from the parts, not from a separate flag.
  Only `done` is durable: `blocked` is judged again at each start, and a
  gateway refusal is asked once per process for one delete identity.
- A refusal is terminal for the same delete. Re-applying the same deleted
  control row calls `noteSettled` with the same tombstone version; that owes
  only stages with no final verdict, and keeps the refusal. A higher tombstone
  version is a new delete: it clears the verdicts and the refusal and owes both
  stages.
- The terminal gateway codes are one list, `GATEWAY_REFUSAL_CODES` in
  `sync/gateway-refusal.ts`. The gateway parser, the retirement scheduler, the
  rollback resubmitter and `DeleteBlockReason` all derive from it. The answer
  that data-gateway #212 will give for a tombstone aimed at a head already
  deleted maps to `done` in one marked place, `GATEWAY_ALREADY_DELETED_CODES`
  (empty until the gateway fixes the code name).
- The rollback resubmitter stops at a terminal gateway refusal of the
  re-submitted delete (`gateway-refused`) after one attempt; only other
  failures use the attempt budget.
- `deleter.deleteStatus(connector)` answers `{ fence, legacy, storage }`, each
  `done`, `pending` or `blocked(reason)` (`localdb/delete-status.ts`). The owner
  connector routes carry it as `deleteStatus` (202 body and `GET`). An app says
  "deleted" only when all three are `done`.
