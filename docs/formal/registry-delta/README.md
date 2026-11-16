# Registry change delta: TLC model

`RegistryDelta.tla` models the gateway's change feed with deltas. Writers commit registry rows for one owner. A reader holds a cursor and asks for every row that changed after it. The model checks that a reader that applies those answers never skips a committed change, and that a reset is always followed by a full listing.

The gateway side it models (data-gateway, migration `0070_registry_change_rows.sql`):

- **Numbering.** One counter row per owner. A writer takes the next number by an `UPDATE` of that row, so it holds the row lock from the number to the end of its transaction. Numbers are in commit order and have no gaps. A Postgres `SEQUENCE` does not give this: `nextval()` takes no lock, so a later number can commit first.
- **Records.** Each changed row keeps one change record: the number of its latest change. A hard-deleted row keeps its record and is reported gone.
- **One snapshot.** A delta reads the counter and the records above the cursor in one snapshot, and joins each record to the row as it is now.
- **Floor.** Records are complete only above a floor (changes made before the records existed have none). A cursor below the floor, or above the counter, is answered "reset", and the reader lists everything.

The reader side is the Personal Server's `SyncManager`: a delta is applied only from the position the last clean pass started under; a reset runs the full cycle.

## Properties

- `NoSkip` (invariant): for every row, the reader holds at least the version that was committed at or below its cursor.
- `ResetThenListing` (action property): while a reset is owed, the cursor does not move except by the listing.
- `CatchUp` (liveness): once writers stop, the reader ends holding exactly the registry.

## Results

Two writers, one reader, two rows, at most 4 transactions. The floor may rise once. Each mutation switches off one design choice. TLC 1.7.4, 4 workers, `nice 19`. Raw output is in `out/`.

| config              | what it changes                                | result            | states                      |
| ------------------- | ---------------------------------------------- | ----------------- | --------------------------- |
| D1-design           | nothing: the design                            | pass (all three)  | 610997 gen, 213036 distinct |
| M1-sequence         | number from a lock-free sequence (`nextval()`) | `NoSkip` VIOLATED | 8608 gen, 3040 distinct     |
| M2-two-reads        | records and counter read in two statements     | `NoSkip` VIOLATED | 1224 gen, 552 distinct      |
| M3-reset-no-listing | a reset moves the cursor without a listing     | `NoSkip` VIOLATED | 953 gen, 405 distinct       |
| M4-no-floor         | no reset for a cursor below the floor          | `NoSkip` VIOLATED | 981 gen, 405 distinct       |
| M5-no-gone-records  | a hard delete removes its change record        | `NoSkip` VIOLATED | 910 gen, 394 distinct       |

Every design choice is needed: switching off any one of them lets the reader skip a committed change.

## Run

One configuration (one TLC job, 4 workers, `nice 19`):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/registry-delta/run.sh D1-design
