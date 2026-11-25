# Legacy retire: retiring a connector's legacy copy on its own

`LegacyRetire.tla` models `DELETE /v1/owner/connectors/:id/legacy`. The route
persists one retirement intent (`legacy_retirements`), pins the gateway head of
each bound legacy scope, and retires those heads and no others. It never
touches the connection's control, stream heads or records. While the intent is
open, `importLegacySource` refuses the connector's legacy import.

Code owners:

- `packages/core/src/localdb/legacy-retire-intent.ts`: request, status, resume, pass
- `packages/core/src/localdb/legacy-delete.ts`: `retireLegacyScope`, `pinHolds`, `confirmErased`
- `packages/core/src/localdb/legacy-import.ts`: `importFence` (preflight), `guardImport` (in the merge transaction)

## What is modelled

| Actor    | Steps                                                                                                                                                                                                                                      |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| request  | `RRead` reads every bound head (the pin). `RInsert` is `INSERT OR IGNORE`: the first row stands, a repeat resumes it.                                                                                                                      |
| worker   | per scope: `WRead` (compare to the pin), `WSend` (the adapter: reads the head itself, tombstones or cleans), `WSendLocal` (its local erase), `WReread`, `WLocal` (the fenced local cleanup of a landed tombstone), `WErase`, then `WDone`. |
| importer | `IPre` is the preflight `importFence`. `IMerge` is the merge batch: its guard and the merge are one transaction.                                                                                                                           |
| crash    | `Crash` loses every in-flight step. Durable rows (intent, gateway, blobs, local erase, current connection) stay.                                                                                                                           |
| host     | `Revoke` and `Restore`: the host's write authority (a registration hold) closes and comes back.                                                                                                                                            |
| gateway  | `Publish` and `ForeignTomb`: another writer moves the head or tombstones it. In the real system the head normally stays still.                                                                                                             |
| sync     | `CWrite`: the current connection keeps writing.                                                                                                                                                                                            |

A live head at version `v` is tombstoned at `v + 1`. Erasing a tombstone at
version `t` frees every blob slot `<= t` (`confirmErased`), so a tombstone that
does not directly follow the pinned head frees slots the pin never named.

## Invariants

| Invariant                       | Meaning                                                                                                                                       |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `NoLegacyMergeWhileOpen`        | No importer batch merges while the intent is open.                                                                                            |
| `CurrentConnectionUntouched`    | An action of request, worker or restart never changes the current connection (action property).                                               |
| `DoneOnlyAfterConfirm`          | `done` implies every bound head is tombstoned, its blobs are erased and its local copy is gone through the pinned tombstone.                  |
| `OneIntent`                     | A restart or a repeat never makes a second intent.                                                                                            |
| `NoTombstoneOverMovedHead`      | A tombstone of ours is never written over a head that moved since the pin.                                                                    |
| `NoStaleMergeAfterDone`         | No batch merges a bound scope once the intent is `done`: a retired scope stays refused.                                                       |
| `NoEraseOfUnpinnedVersion`      | No erase (blobs or local) and no storage cleanup, queued or done, for a tombstone that does not directly follow the pin (found by the model). |
| `NoDestructiveWithoutAuthority` | No tombstone post, queue write, local erase, storage delete or done verdict runs while the host has no write authority.                       |

## Results

Run with `TLA2TOOLS=<tla2tools.jar> [JAVA=...] [WORKERS=4] ./run.sh <Config> [outdir]`.
It takes the shared heavy-run lock, runs `nice -n 19 ionice -c3`, and uses 4
workers. Constants: two scopes, `MaxVer = 2`, `MaxReq = 2`, `MaxB = 1`,
`MaxCrash = 2`, `MaxW = 1`, `MaxRev = 1`. `Good` takes about 2 minutes; a mutant takes seconds to a minute. Round 7 lowered `MaxB` and `MaxW` from 2 to 1: the new variables made the old bounds too large, and no invariant needs a second import batch or a second current write. Logs are in `traces/`. A trace length is the number of states TLC prints; with several workers it can differ by one between runs.

| Config                                                                                               | Result                                                                                                                                        |
| ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `Good`                                                                                               | No error. 62,676,431 states generated, 13,846,227 distinct, depth 27. All invariants above.                                                   |
| `MutNoBatchFence-NoLegacyMergeWhileOpen`                                                             | `NoLegacyMergeWhileOpen` violated, 6-state trace (the batch has no guard of its own).                                                         |
| `MutNoPin-NoTombstoneOverMovedHead`                                                                  | `NoTombstoneOverMovedHead` violated, 6-state trace (the worker does not compare to the pin).                                                  |
| `MutDoneBeforeErase-DoneOnlyAfterConfirm`                                                            | `DoneOnlyAfterConfirm` violated, 9-state trace (done once tombstoned, before the erase).                                                      |
| `MutNewIntentOnRestart-OneIntent`                                                                    | `OneIntent` violated, 5-state trace (a restart makes a new intent for an open one).                                                           |
| `MutTouchesCurrent-CurrentConnectionUntouched`                                                       | `CurrentConnectionUntouched` violated, 7-state trace (the erase also writes the connection).                                                  |
| `MutOldPinHolds-NoEraseOfUnpinnedVersion`                                                            | `NoEraseOfUnpinnedVersion` violated, 7-state trace: the code before the fix (see below).                                                      |
| `Probe-NotDone`, `Probe-NotBlocked`, `Probe-NotBlockedByForeignTomb`, `Probe-NotFreeMergedAfterDone` | Each fails by design: `done`, a blocked scope, a block by a foreign tombstone, and an import of an unbound stream after `done` are reachable. |
| `MutDoneLiftsFence-NoStaleMergeAfterDone`                                                            | `NoStaleMergeAfterDone` violated, 15-state trace: the code before the fix (see below).                                                        |
| `MutAbsentCleans-NoEraseOfUnpinnedVersion`                                                           | `NoEraseOfUnpinnedVersion` violated, 6-state trace: the adapter before round 5 (see below).                                                   |
| `MutAdapterCleansFirst-NoEraseOfUnpinnedVersion`                                                     | `NoEraseOfUnpinnedVersion` violated, 7-state trace: the delete adapter before round 4 (see below).                                            |
| `MutGateOnce-NoDestructiveWithoutAuthority`                                                          | `NoDestructiveWithoutAuthority` violated, 6-state trace: the code before round 7 (see below).                                                 |
| `MutEchoCleans-NoEraseOfUnpinnedVersion`                                                             | `NoEraseOfUnpinnedVersion` violated, 6-state trace: the code before round 7 (see below).                                                      |
| `MutResumeSkipsLocal-DoneOnlyAfterConfirm`                                                           | `DoneOnlyAfterConfirm` violated, 10-state trace: the code before round 7 (see below).                                                         |

## Finding: a later tombstone passed `pinHolds` (fixed)

`pinHolds` once accepted any tombstone for a live pin (`MutOldPinHolds`). A 7-state trace (TLC may add an unrelated step on the other scope):

1. `RRead`: the request reads the heads at version 1.
2. `Publish`: another writer publishes version 2.
3. `ForeignTomb`: another writer tombstones it at version 3.
4. `RInsert`: the intent pins version 1.
5. `WRead`: the worker reads a deleted head. The old `pinHolds` accepts it.
6. `WErase`: the erase frees every slot up to 3, including version 2, which the pin never named.

The repair is in `pinHolds`: for a live pin, a tombstone is accepted only when
its version is `pin.fence.expectedVersion + 1`. Any other tombstone answers
`legacy_head_changed`, and no storage delete runs. `Good` is the fixed rule.

## Finding: the delete adapter cleaned before the pin recheck (fixed)

The worker compared the head to the pin, then called the delete adapter
(`createGatewayDeleteDataPort.tombstone`, then `deleteScope`). The adapter reads
the head again itself. It took any deleted head as "already deleted", and
`deleteScope` then queued or ran storage cleanup through that version before the
worker's second compare. The first model treated read, tombstone and compare as
one step. `WSend` is now the adapter's own head read plus its cleanup, so another
writer can move the head between the worker's read and the adapter's
(`MutAdapterCleansFirst`, the code before the fix). A 7-state trace:

1. `RRead`, `RInsert`: the intent pins live version 1.
2. `WRead`: the worker reads the head live at 1. The pin holds.
3. `Publish`: another writer publishes version 2.
4. `ForeignTomb`: another writer tombstones at version 3.
5. `WSend`: the adapter reads a deleted head at 3, calls it "already deleted" and
   cleans through 3. Version 2's blob is queued or gone. The recheck then blocks
   too late.

The repair is in `createGatewayDeleteDataPort.tombstone`: with a fence, an
already-deleted answer (the first head read or the gateway's reply) counts only
at `fence.head.expectedVersion + 1`. Any other version throws before any storage
write or queue row. The worker then reads the head again, and a head that is not
the pin's gives `legacy_head_changed`. `Good` is the fixed rule.

## Finding: an absent head under a live pin led to cleanup (fixed)

The same gap, for another adapter answer. The worker reads the pinned head live.
The adapter's lookup or tombstone POST then answers "head absent" (404, a 409
`owner_stream_head_absent`, or no feed row), and the adapter returned
`not-registered`. The shared delete worker treats that as "nothing at the gateway"
and queues locally indexed blob keys and erases local entries before the
retirement worker rechecks the pin. `WSendAbsent` is the adapter's absent answer;
`MutAbsentCleans` (the code before the fix) marks cleanup the pin never named.

The repair is in `createGatewayDeleteDataPort.tombstone`: with a pinned fence (a
retirement held to a pin; `retire(scope, fence, { pinned })`), an absent answer throws before any queue row or local erase. The worker then reads the head
again: a head that is not the pin's gives `legacy_head_changed`, and the same head
keeps the scope waiting. A connector delete's fence is not pinned and keeps
"not registered": its local copy goes with it. `Good` is the fixed rule. The model lets the adapter see
"absent" at any time while the head is live, a superset of what the gateway does.

## Where the model differs from the code

- **Check and merge.** The code's preflight `importFence` and the merge batch are
  separate awaits (the model's `IPre`, `IMerge`). `guardImport` runs inside the
  merge `db.batch`, so the guard and the merge are one transaction. The model
  treats them as one atomic step. A test pauses an import between them.
- **Intent insert.** The pin read and the `INSERT OR IGNORE` are separate steps
  (`RRead`, `RInsert`). The model keeps them separate. The insert itself is one
  statement.
- **Import scope.** The model's importer names a bound scope or "free". The code
  derives the scopes from the import's connector and stream through the legacy
  binding table, which can name several scopes for one stream.
- **Worker order.** The code retires scopes one after another in one pass. The
  model lets each scope step in any order, a superset of the code's runs.
- **Adapter.** `WSend` joins the adapter's head read, tombstone and cleanup
  write in one step. The real adapter does them in order. The version check of
  the repair comes before every write, so no step between them is observable.
- **Startup.** The model's worker may step whenever the intent is open. In the
  code a restart resumes it when a registered, switched runtime opens (Lite) and
  at each sync cycle; a read-only registration waits for the cycle.
- **Memory.** A done intent releases its in-memory history, verdict and loop. The
  model has no memory of that kind.
- **Shutdown.** `close()` waits for passes in flight before the database closes
  (a test holds a storage call open). It is not a model step.
- **Erase.** `confirmErased` makes several storage requests, checks finality and
  the history, and can report pending. The model's `WErase` is one step. A crash
  between `WSend` and `WErase` is covered: the next read sees the tombstone, and
  since round 7 the next pass also runs `WLocal` before `WErase`.
- **Retries and backoff.** The model has no timers. A worker step is always
  enabled while the intent is open. A status poll (GET) is not a model step: it
  starts a worker only when none exists, and the model assumes that worker runs.
- **Blocked is sticky.** In the code a pass reads the head again, but a head
  never moves back, so the verdict is the same. The model keeps `blk` once set.
- **Pins of deleted heads.** A request that reads an already tombstoned head
  pins that version (`pinHolds` compares versions). The model pins live heads only.
- **Gateway refusals and "needs another device"** are not modelled. They block a
  scope without a head change.
- **Another writer's tombstone** after our own is not modelled. The head is final
  once deleted, and the model's gateway cannot move a tombstoned head.

## Round 7: authority, echoed versions and local cleanup (fixed)

Three findings, one rule: destructive work runs only under live write
authority, bounded by the pinned version, and `done` means the remote and the
local copy are both gone.

- **Authority read once** (`MutGateOnce`). The host's `writeReady` was read when
  the pass called the delete, and the adapter then read the head again. A
  registration hold that began in between still got its tombstone, queue write
  and local erase. Trace: `RRead`, `RInsert`, `WRead`, `Revoke`, `WSend`. The
  repair: `writeReady` rides the fence into the adapter (read right before the
  post) and into `deleteScope` (read before the queue write and before the local
  erase). `Good` disables each step while the authority is closed; `WAbandon`
  ends the pass.
- **Echoed version** (`MutEchoCleans`). A 2xx tombstone answer that echoed a
  later `expectedVersion` bounded the cleanup. Trace: `WSendEcho` queues and
  erases up to a version no pin names. The repair: a fenced 2xx is checked against
  the version signed (`assertFencedTombstone`); a different echo throws, nothing is
  cleaned, and the worker reads the head again.
- **Local copy after a restart** (`MutResumeSkipsLocal`). A pass that found the
  tombstone landed checked remote storage only. Trace: `WSend` tombstones, `Crash`
  before `WSendLocal`, `WRead` sees the tombstone, `WErase`, `WDone` with the local
  copy still present. A failed local erase had the same gap. The repair: a pinned
  pass runs the fenced delete again over the pinned tombstone (`cleanLocal`,
  `WLocal`) before it confirms the blobs, and a local erase that did not finish
  leaves the pass pending. The local index tells which entries a tombstone covers
  (`isEntryCoveredByTombstone`: a registered entry by its version, a local-only
  entry by its re-add marker), so the erase is bounded by the pinned tombstone.

The model already had a crash point between the tombstone and the erase (`Crash`
from any step); round 7 made the local erase a step of its own, so that crash now
leaves a local copy behind. `Good` passes with it.

## Finding: `done` lifted the fence (fixed)

An import that passed its preflight before the intent existed reads a batch.
The retirement then finishes (tombstone, erase, `done`) before that batch's merge
transaction. `done` lifted the fence, so the guard admitted the merge and the
deleted records came back (`MutDoneLiftsFence`, 12-state trace: `IPre` on a bound
scope, a full request and retire to `done`, then `IMerge`).

The repair: a `legacy_retirements` row keeps fencing the scopes it lists after
`done`. `importFence` and `guardImport` refuse (`legacy_retired`) an import whose
stream a listed scope feeds (the request records each bound scope's streams in the
row, from the legacy binding table, through `LegacyDeletePorts.streamsOf`). It is per bound scope: an open intent still fences the
whole connector, a done one fences only its scopes, and a stream no listed scope
feeds still imports (`Probe-NotFreeMergedAfterDone`). A repeated request after
`done` returns the same done intent and sends nothing.

This is bounded model evidence. It is not a refinement proof of the SQL. Tests
in `packages/core/src/localdb/legacy-retire-intent.test.ts` run the invariants
against the real code.
