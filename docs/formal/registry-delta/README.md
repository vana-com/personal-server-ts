# Registry change delta: TLC model

`RegistryDelta.tla` models the gateway's change feed with deltas. Writers commit registry rows for one owner. A reader holds a cursor and asks for every row that changed after it. The model checks that a reader that applies those answers never skips a committed change, and that a reset is always followed by a full listing.

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

## Properties

- `NoSkip` (invariant): for every row, the reader holds at least the version that was committed at or below its cursor.
- `ResetThenListing` (action property): while a reset is owed, the cursor does not move except by the listing.
- `CatchUp` (liveness): once writers stop, the reader ends holding exactly the registry.

## Results

Two writers, one reader, two rows, at most 4 transactions. The floor may rise once. Each mutation switches off one design choice. The checker is `tla2tools.jar` from the TLA+ tools release v1.7.4, which reports itself as "TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)". 4 workers, `nice 19`. Raw output is in `out/`.

| config                | what it changes                                           | result            | states                        |
| --------------------- | --------------------------------------------------------- | ----------------- | ----------------------------- |
| D1-design             | nothing: the design (`ControlRows = "apply"`)             | pass (all three)  | 4991100 gen, 1906592 distinct |
| D0-control-handoff    | every control row hands to the cycle (the earlier design) | pass (all three)  | 5307452 gen, 2022284 distinct |
| M1-sequence           | number from a lock-free sequence (`nextval()`)            | `NoSkip` VIOLATED | 13641 gen, 4915 distinct      |
| M2-two-reads          | records and counter read in two statements                | `NoSkip` VIOLATED | 1429 gen, 629 distinct        |
| M3-reset-no-listing   | a reset moves the cursor without a listing                | `NoSkip` VIOLATED | 1275 gen, 526 distinct        |
| M4-no-floor           | no reset for a cursor below the floor                     | `NoSkip` VIOLATED | 1355 gen, 579 distinct        |
| M5-no-gone-records    | a hard delete removes its change record                   | `NoSkip` VIOLATED | 1619 gen, 707 distinct        |
| M6-reconnect-by-delta | a control row active again is applied from the delta      | `NoSkip` VIOLATED | 298338 gen, 87981 distinct    |
| M7-tombstone-ignored  | a control tombstone in the delta is skipped               | `NoSkip` VIOLATED | 170 gen, 122 distinct         |

Every design choice is needed: switching off any one of them lets the reader skip a committed change. M6's trace: a delete and a log append arrive in one delta (the delete is applied, the log skipped); a reconnect then arrives alone and is applied from the delta, and the reader never fetches the log of the new lifetime. A reconnect therefore runs the cycle.

## Run

One configuration (one TLC job, 4 workers, `nice 19`):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/registry-delta/run.sh D1-design
