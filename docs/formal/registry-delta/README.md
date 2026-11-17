# Registry change delta: TLC model

`RegistryDelta.tla` models the gateway's change feed with deltas. Writers commit registry rows for one owner. A reader holds a cursor and asks for every row that changed after it. The model checks that a reader that applies those answers never skips a committed change, and that a reset is always followed by a full listing. Delta receipt, persistence, and cursor settlement are separate actions. The reader admits no second answer while persistence or settlement is unfinished.

The gateway side it models (data-gateway, migration `0070_registry_change_rows.sql`):

- **Numbering.** One counter row per owner. A writer takes the next number by an `UPDATE` of that row, so it holds the row lock from the number to the end of its transaction. Numbers are in commit order and have no gaps. A Postgres `SEQUENCE` does not give this: `nextval()` takes no lock, so a later number can commit first.
- **Records.** Each changed row keeps one change record: the number of its latest change. A hard-deleted row keeps its record and is reported gone.
- **One snapshot.** A delta reads the counter and the records above the cursor in one snapshot, and joins each record to the row as it is now.
- **Floor.** Records are complete only above a floor (changes made before the records existed have none). A cursor below the floor, or above the counter, is answered "reset", and the reader lists everything.

The reader side is the Personal Server's `SyncManager` and `applyRegistryDelta` (`packages/core/src/localdb/delta-apply.ts`). A delta is applied only from the position the last clean pass started under; a reset runs the full cycle. The owner has one connection: a control row `ctl` and a log row `log`. Per row, the reader:

- applies a control tombstone (a delete): it saves the row and purges the connection, as the cycle does, and skips the connection's log row, because the cycle's apply returns at a deleted control before it reads the log;
- applies a log row of a connection it holds active;
- hands the delta to the cycle for a control row active again (a reconnect, which needs a first load), a gone row, and a log row of a connection it does not hold.

The code also skips an active control row of the lifetime it holds (only bookkeeping moved) and hands a deleted log row to the cycle. The model has no such writes.

## Host obligations

`SyncManager` serializes passes, including delta applies and fallback cycles. A delta arriving during a pass requests a full follow-up rather than joining the unfinished apply. The applied cursor (`since`) is cleared while a pass runs and advances only after its promise completes. Database batches commit the log position with the records they represent. A reset always takes the full cycle, whose owner listing is awaited before settlement.

Ordinary answers at or below the applied position are discarded. An older observed position cannot replace a newer one. A lower reset triggers a listing without settling its older position; a subsequent answer establishes the new baseline. An unreadable log can suppress repeated polling, but that diagnostic position is never offered as an applied cursor. The cursor is deliberately not persisted across restart: a new manager must run a full cycle before requesting deltas.

Across connections, the applier awaits every operation even when one fails. Successful siblings stay persisted; a failure runs the fallback cycle only after all siblings finish. Real SQLite tests cover two connections with one failed and one blocked operation. The model still has only one connection and does not enumerate partial multi-connection failures or delayed network answers; those are host-test obligations.

`node docs/formal/registry-delta/mutations.mjs` runs four executable mutations, restoring each source before exit: advertise an unreadable reset as applied, settle a reset before the fallback promise completes, let an older answer regress the observed position, and return on the first failed connection. Each mutation must fail its named assertion. The overlap test also holds an older apply open while a newer answer arrives.

## Request counts after the log-only cycle change

The existing request trace wraps the real local database cycle and delta apply with a fake gateway and blob store. One connection, two streams, one page of owner rows:

| Scenario                         | Full cycle | Delta apply | Requests saved |
| -------------------------------- | ---------: | ----------: | -------------: |
| Invoked idle cycle / empty delta |          2 |           0 |              2 |
| One remote log commit            |          3 |           1 |              2 |
| Remote connection delete         |          3 |           0 |              3 |

The idle cycle takes one owner listing and one control read. A remote commit adds one segment GET. The delta uses the supplied log row and fetches only that segment. Counts exclude the held change request, common to both paths, and the host's server-registration prerequisite. Including the held request makes a remote commit 4 versus 2 requests.

Steady idle with healthy push is already zero cycle requests on both paths: the manager skips the timer cycle. A timer fallback still takes two requests on both paths; it has no delta. The empty-delta row measures an invocation's cost, not an additional steady-idle saving. No new wall-clock latency claim is made.

## Properties

- `NoSkip` (invariant): for every row, the reader holds at least the version that was committed at or below its cursor.
- `ResetThenListing` (action property): while a reset is owed, the cursor does not move except by the listing.
- `CatchUp` (liveness): once writers stop, the reader ends holding exactly the registry.

## Results

The current run separates persisted apply from cursor settlement. Raw outputs below are from this model.

Two writers, one reader, two rows, at most 4 transactions. The floor may rise once. Each mutation switches off one design choice. The checker is `tla2tools.jar` from the TLA+ tools release v1.7.4, which reports itself as "TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)". 4 workers, `nice 19`. Raw output is in `out/`.

| config                | what it changes                                           | result            | states                         |
| --------------------- | --------------------------------------------------------- | ----------------- | ------------------------------ |
| D1-design             | nothing: the design (`ControlRows = "apply"`)             | pass (all three)  | 12457990 gen, 4653810 distinct |
| D0-control-handoff    | every control row hands to the cycle (the earlier design) | pass (all three)  | 12613320 gen, 4702958 distinct |
| M1-sequence           | number from a lock-free sequence (`nextval()`)            | `NoSkip` VIOLATED | 55901 gen, 19545 distinct      |
| M2-two-reads          | records and counter read in two statements                | `NoSkip` VIOLATED | 2208 gen, 936 distinct         |
| M3-reset-no-listing   | a reset moves the cursor without a listing                | `NoSkip` VIOLATED | 1758 gen, 815 distinct         |
| M4-no-floor           | no reset for a cursor below the floor                     | `NoSkip` VIOLATED | 13914 gen, 4794 distinct       |
| M5-no-gone-records    | a hard delete removes its change record                   | `NoSkip` VIOLATED | 12023 gen, 4159 distinct       |
| M6-reconnect-by-delta | a control row active again is applied from the delta      | `NoSkip` VIOLATED | 4005537 gen, 1352897 distinct  |
| M7-tombstone-ignored  | a control tombstone in the delta is skipped               | `NoSkip` VIOLATED | 6894 gen, 2580 distinct        |

Every design choice is needed: switching off any one of them lets the reader skip a committed change. M6's trace: a delete and a log append arrive in one delta (the delete is applied, the log skipped); a reconnect then arrives alone and is applied from the delta, and the reader never fetches the log of the new lifetime. A reconnect therefore runs the cycle.

## Run

One configuration (one TLC job, 4 workers, `nice 19`):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/registry-delta/run.sh D1-design
