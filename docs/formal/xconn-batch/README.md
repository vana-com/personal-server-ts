# One commit across connections: TLC model

`XConnBatch.tla` models one sync cycle that commits the dirty streams of several connections to the registry in as few batch requests as the gateway's bound allows, and checks that sharing a request between connections costs no safety.

A stream owns two registry rows, `head` and `pos`, and every writer moves both in one request, so they stay at one version. A connection owns a control row; a deleted control row is a deleted connection. One batch request is one gateway transaction over a set of rows that can name rows of several connections. Two rules judge it, as the gateway does:

- `requires`: every connection in the request must have its control row, or nothing is written (`reqMode = "txn"`).
- Per-row compare-and-set: a row is written only if its version is the one the cycle planned over. A refused row is skipped and its siblings still commit.

The cycle sends the streams it planned in requests of at most `B` rows (`B` is the gateway's advertised bound). A request holds whole streams. Other writers move a stream in their own request or delete a connection. A reader takes a snapshot of every row in one statement, so every state of the model is a possible snapshot.

Three switches are mutants when they are not the shipped setting: `AtomicApply` (a request's writes appear in one step), `MidStream` (the cycle splits at the row bound, so the two rows of a stream can travel in different requests) and `reqMode` (`txn`, `perConn` or `none`).

Run one configuration (one TLC job, 4 workers, `nice 19`, the metadir deleted when it ends):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/xconn-batch/run.sh S1-shipped-b4

TLC 1.7.4, two connections, three streams, versions up to 2. Raw output is in `out/`.

## Invariants

| name                   | says                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------- |
| `CommitAtomic`         | a snapshot that sees one write of a request sees every write of it, across connections |
| `StreamLockstep`       | no snapshot shows a stream's `head` and `pos` at different versions                    |
| `NoMidStreamSplit`     | every request the cycle sends holds both rows of each stream it names                  |
| `RequiresAllOrNothing` | a request whose conditions failed wrote nothing                                        |
| `NoWriteAfterDelete`   | a deleted connection's rows never move again                                           |

## Results

| config                       | what it checks                                              | invariant checked      | result   | states                     |
| ---------------------------- | ----------------------------------------------------------- | ---------------------- | -------- | -------------------------- |
| S1-shipped-b4                | shipped: atomic, whole streams, `txn`, bound 4              | all five               | pass     | 107129 gen, 44636 distinct |
| S2-shipped-b2                | same, bound 2 (every stream in its own request)             | all five               | pass     | 50303 gen, 21428 distinct  |
| S3-shipped-b6                | same, bound 6 (the whole cycle in one request)              | all five               | pass     | 117465 gen, 48676 distinct |
| M1-nonatomic-apply           | mutant: a request's rows appear one per step                | `CommitAtomic`         | VIOLATED | 65 gen, 50 distinct        |
| M2-split-midstream           | mutant: split at the row bound inside a stream              | `NoMidStreamSplit`     | VIOLATED | 60 gen, 46 distinct        |
| M2b-split-midstream-lockstep | same mutant, seen by a reader                               | `StreamLockstep`       | VIOLATED | 78 gen, 57 distinct        |
| M3-perconn-conditions        | mutant: conditions judged per connection, passing rows stay | `RequiresAllOrNothing` | VIOLATED | 263 gen, 207 distinct      |
| M4-no-conditions             | mutant: no conditions                                       | `NoWriteAfterDelete`   | VIOLATED | 321 gen, 252 distinct      |
| R1-reach-crossconn           | reach: no request writes rows of two connections            | `NoCrossConnWrite`     | VIOLATED | 81 gen, 66 distinct        |
| R2-reach-split               | reach: no cycle needs more than one request                 | `NoSplitCycle`         | VIOLATED | 143 gen, 108 distinct      |

A mutant is caught when its invariant is violated, so each invariant can fail. R1 and R2 are reach checks, expected to be violated: they show that the shipped runs do put rows of two connections in one request and do split a cycle, so the passes above are not vacuous.

## What the model does not cover

The gateway transaction and its locks are the gateway's own tests' subject (`tests/data-point-batch-postgres.test.ts` in the gateway). This model takes "one request is one transaction with per-row compare-and-set and an all-or-nothing `requires`" as the contract and checks what a client can build on it. It has no time, no lost replies and no resend: those are covered by the batch-commit tests of the client.
