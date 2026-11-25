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

| Actor    | Steps                                                                                                                          |
| -------- | ------------------------------------------------------------------------------------------------------------------------------ |
| request  | `RRead` reads every bound head (the pin). `RInsert` is `INSERT OR IGNORE`: the first row stands, a repeat resumes it.          |
| worker   | per scope: `WRead` (compare to the pin), `WSend` (tombstone fenced to the head it read), `WReread`, `WErase`, then `WDone`.    |
| importer | `IPre` is the preflight `importFence`. `IMerge` is the merge batch: its guard and the merge are one transaction.               |
| crash    | `Crash` loses every in-flight step. Durable rows (intent, gateway, blobs, current connection) stay.                            |
| gateway  | `Publish` and `ForeignTomb`: another writer moves the head or tombstones it. In the real system the head normally stays still. |
| sync     | `CWrite`: the current connection keeps writing.                                                                                |

A live head at version `v` is tombstoned at `v + 1`. Erasing a tombstone at
version `t` frees every blob slot `<= t` (`confirmErased`), so a tombstone that
does not directly follow the pinned head frees slots the pin never named.

## Invariants

| Invariant                    | Meaning                                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- |
| `NoLegacyMergeWhileOpen`     | No importer batch merges while the intent is open.                                                   |
| `CurrentConnectionUntouched` | An action of request, worker or restart never changes the current connection (action property).      |
| `DoneOnlyAfterConfirm`       | `done` implies every bound head is tombstoned and its blobs are erased.                              |
| `OneIntent`                  | A restart or a repeat never makes a second intent.                                                   |
| `NoTombstoneOverMovedHead`   | A tombstone of ours is never written over a head that moved since the pin.                           |
| `NoEraseOfUnpinnedVersion`   | A scope is erased only for the tombstone that directly follows the pinned head (found by the model). |

## Results

Run with `TLA2TOOLS=<tla2tools.jar> [JAVA=...] [WORKERS=4] ./run.sh <Config> [outdir]`.
It takes the shared heavy-run lock, runs `nice -n 19 ionice -c3`, and uses 4
workers. Constants: two scopes, `MaxVer = 2`, `MaxReq = 2`, `MaxB = 2`,
`MaxCrash = 2`, `MaxW = 2`. A run takes seconds. Logs are in `traces/`. A trace length is the number of states TLC prints.

| Config                                                               | Result                                                                                          |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `Good`                                                               | No error. 3,405,762 states generated, 886,482 distinct, depth 24. All invariants above.         |
| `MutNoBatchFence-NoLegacyMergeWhileOpen`                             | `NoLegacyMergeWhileOpen` violated, 5-state trace (the batch has no guard of its own).           |
| `MutNoPin-NoTombstoneOverMovedHead`                                  | `NoTombstoneOverMovedHead` violated, 6-state trace (the worker does not compare to the pin).    |
| `MutDoneBeforeErase-DoneOnlyAfterConfirm`                            | `DoneOnlyAfterConfirm` violated, 9-state trace (done once tombstoned, before the erase).        |
| `MutNewIntentOnRestart-OneIntent`                                    | `OneIntent` violated, 4-state trace (a restart makes a new intent for an open one).             |
| `MutTouchesCurrent-CurrentConnectionUntouched`                       | `CurrentConnectionUntouched` violated, 7-state trace (the erase also writes the connection).    |
| `MutOldPinHolds-NoEraseOfUnpinnedVersion`                            | `NoEraseOfUnpinnedVersion` violated, 8-state trace: the code before the fix (see below).        |
| `Probe-NotDone`, `Probe-NotBlocked`, `Probe-NotBlockedByForeignTomb` | Each fails by design: `done`, a blocked scope and a block by a foreign tombstone are reachable. |
| `Observe-NoStaleMergeAfterDone`                                      | Violated, 12-state trace: an observation, not a requirement (see below).                        |

## Finding: a later tombstone passed `pinHolds` (fixed)

`pinHolds` once accepted any tombstone for a live pin (`MutOldPinHolds`). An 8-state trace (TLC may add an unrelated step on the other scope):

1. `RRead`: the request reads the heads at version 1.
2. `Publish`: another writer publishes version 2.
3. `ForeignTomb`: another writer tombstones it at version 3.
4. `RInsert`: the intent pins version 1.
5. `WRead`: the worker reads a deleted head. The old `pinHolds` accepts it.
6. `WErase`: the erase frees every slot up to 3, including version 2, which the pin never named.

The repair is in `pinHolds`: for a live pin, a tombstone is accepted only when
its version is `pin.fence.expectedVersion + 1`. Any other tombstone answers
`legacy_head_changed`, and no storage delete runs. `Good` is the fixed rule.

## Where the model differs from the code

- **Check and merge.** The code's preflight `importFence` and the merge batch are
  separate awaits (the model's `IPre`, `IMerge`). `guardImport` runs inside the
  merge `db.batch`, so the guard and the merge are one transaction. The model
  treats them as one atomic step. A test pauses an import between them.
- **Intent insert.** The pin read and the `INSERT OR IGNORE` are separate steps
  (`RRead`, `RInsert`). The model keeps them separate. The insert itself is one
  statement.
- **Worker order.** The code retires scopes one after another in one pass. The
  model lets each scope step in any order, a superset of the code's runs.
- **Erase.** `confirmErased` makes several storage requests, checks finality and
  the history, and can report pending. The model's `WErase` is one step. A crash
  between `WSend` and `WErase` is covered: the next read sees the tombstone.
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

## Observation: an import staged before the intent

`Observe-NoStaleMergeAfterDone` shows an import that passed its preflight before
the intent existed, and merges after the intent is `done`. `done` lifts the
fence, so the guard passes. In the code this import reads the legacy source in
the batch loop (`source.records()`), and a retired scope's blobs are erased, so
the read would fail rather than merge. That is a property of the reader, not of
the guard. It is not one of the requirements above and the model does not fail
`Good` on it.

This is bounded model evidence. It is not a refinement proof of the SQL. Tests
in `packages/core/src/localdb/legacy-retire-intent.test.ts` run the invariants
against the real code.
