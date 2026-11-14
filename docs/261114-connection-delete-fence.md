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
   restart does not post a second tombstone and does not mistake its own
   tombstone for a reconnect.
3. **Confirm, never re-issue.** After a refused (409) or lost reply, read the
   control row. The fence holds if control is deleted at version >= pin+1, or
   active at a generation > pin (a reconnect won). Otherwise the delete stays
   pending and the next attempt re-posts the same version.
4. **Cleanup in parallel.** Each stream chain touches only its own registry row.
   Chains run together. `streamsLanded` stays cleanup-only.
5. **Cleanup is bounded by the lifetime it ended.** A stream is tombstoned only if
   its head generation is <= the ended lifetime (`holdsEndedLifetimeOnly`). A row
   written by a later lifetime is left alone. There is no "superseded" exit.
6. **No second tombstone.** After the fence the control row is never written
   again by this delete, even when a reconnect superseded it.
7. **Request answer.** `requestConnectionDelete` waits for the fence, then
   answers `{deleteId, fenced}`. `fenced:false` means the registry was
   unreachable: the delete is saved and retried, but other devices cannot see it.

## Prior art

- Kubernetes namespace deletion: a Terminating state is set first; controllers
  then delete the children. Divan:
  `distributed-systems/a-container-delete-is-fenced-by-a-lifetime-identity-or-terminating-state-...`.
- Kleppmann, fencing tokens: the store checks a monotone token. Here the
  gateway checks the control row as an atomic condition on every publish batch.

## Reader paths (a deleted control row hides live stream rows)

| Reader | Behaviour |
| --- | --- |
| apply (`apply.ts`) | deleted control: purge local rows, `control_state='deleted'`, checkpoint cleared |
| bootstrap (`bootstrap.ts`) | a joining device records the deleted state and loads no stream |
| history/query (`history.ts`) | `control_state='deleted'` answers 410; reads join on `control_state='active'` |
| publish (`publish.ts`) | a deleted control row purges; a publish from an old holder is refused by the gateway condition |
| publish, new lifetime | a stream row of an earlier lifetime that is still live makes the publisher defer (`stream_delete_not_proven_earlier`) until cleanup runs |

Each row is covered by `delete-reconnect-publish.test.ts` ("after the fence and
before cleanup, every reader hides the streams...").

## Model coverage (the delete-order TLA+ model, variants A, A3s and bare reorder)

Modelled: fence-first order, head-generation classification, confirm at
version >= pin+1, cleanup bounded by lifetime, reconnect, crash, stale in-flight CAS.
Not modelled, handled in code and tests: absent control rows (cleanup only,
no tombstone), legacy intents without `fences` (old order, unchanged),
local purge (`purgeLocal` generation guards kept), registry lag (a read below
pin+1 stays pending).

Parallel cleanup was not added to the model. Argument: each CAS touches only its
own row; the shared effects (`VEG`, clear) are monotone; a crash leaves only stale
in-flight CAS messages, which the model already has (`W_StaleInflightCas`). This is
an argument, not a TLC result. The tests assert parallelism (a barrier test and a
latency-ratio test).

## Known limits

- `NoLossAfterReq` fails in the model for every variant. A delete not yet visible
  on the registry cannot protect later publishes, so the caller sees `fenced:false`.
  Data published at the same generation before the fence is deleted by design.
- If the deleting device never returns, rows of the ended lifetime stay and a
  reconnected device defers. The old order had the same hole. Follow-up: an
  orphan sweeper that any surface can run, or letting the publisher overwrite
  data heads it can prove ended.
- The registry adapter has no timeout, so a hung registry hangs the request, as in `plan()`.
- Unity Surfaces UI should show "pending" when `fenced:false`. Out of scope here.
