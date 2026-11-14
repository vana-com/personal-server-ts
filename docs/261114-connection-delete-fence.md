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
