# Late seed: filling a stream that already has real writes

`LateSeed.tla` models the first device that sees the stream-sync switch. It
converts every legacy record that has `$pdpp` identity into its stream, even if
the stream already holds real writes, a published head, or deletes. Before this
model, `importLegacySource` refused such a stream (the "seed window"). The
question: can a device decide from local state which keys it may fill, with no
protocol change?

## What is modelled

- Keys, devices, a shared log, and per device: stored rows (`records`), the
  tombstones it learned by applying the log (`log_tombstones`), and the changes
  waiting to publish (`record_changes`, pruned once a publish is acknowledged).
- A seed record has stamp `(0, seed)`. Every real stamp is at least 1. Rank at
  one stamp: omission < upsert < explicit delete.
- Actions: `Seed`, `LiveUp`, `LiveRemove` (delete or omission), `Publish`,
  `Drop` and `Apply` (a device applies the log), `Wipe` and `LearnWipe` (a
  connection delete, which has a watermark), `SeedSkip`.
- The seed fills only a key that the device does not hold, has no tombstone
  for, has no pending removal of, and that no delete watermark covers.
- A receipt makes a retry a no-op.

## Invariants

| Invariant               | Meaning                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `NoResurrection`        | A record a delete or omission covers is not live after any seed. |
| `SeedNeverClobbersLive` | A seed never changes a key that a real write holds.              |
| `LiveWins`              | A seed stamp never beats a real stamp.                           |
| `WipeStays`             | A deleted connection's keys do not come back.                    |
| `Convergence`           | Devices that applied the whole log hold the same rows.           |
| `RetryAddsNothing`      | A repeated seed adds no row and no change.                       |
| `Fills`                 | A key that nothing covers is filled.                             |

## Finding

A device that publishes its own delete or omission keeps no durable trace of
it. `log_tombstones` is filled by applying a segment, and a device does not
apply its own. After the publish is acknowledged, compaction prunes the pending
change. A seed that checks only rows, tombstones and pending changes then
brings the record back. The counterexample (`MutOwnTombOff`, depth 5):

1. `Seed` k2.
2. `LiveRemove` k2 (explicit delete, stamp 1).
3. `Publish`: the pending change is acknowledged and pruned. No tombstone.
4. `Seed` k2 again: the record is live under the seed stamp.

The repair is local: the commit that publishes a delete or omission also writes
the device's own `log_tombstones` row (`tombstoneStatements` in `log-batch.ts`,
called by `candidateAcknowledgements` in `log-publish.ts`). It writes nothing to
the wire.

## Results

Run with `TLA2TOOLS=<tla2tools.jar> ./run.sh <Config>` (one job, 4 workers,
`nice -n 19 ionice -c3`). Constants: two keys, two devices, `MaxO = 2`,
`MaxEv = 3`, `MaxLog = 5`. Logs are in `traces/`.

| Config                                   | Result                                                                                                                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Good`                                   | No error. 23,516,317 states generated, 8,227,927 distinct, depth 19.                                                                        |
| `MutOwnTombOff-NoResurrection`           | `NoResurrection` violated, depth 5.                                                                                                         |
| `MutOwnTombOff-RetryAddsNothing`         | `RetryAddsNothing` violated, depth 5.                                                                                                       |
| `MutSeedIgnoresTomb-NoResurrection`      | `NoResurrection` violated, depth 5.                                                                                                         |
| `MutSeedIgnoresPend-NoResurrection`      | `NoResurrection` violated, depth 4.                                                                                                         |
| `MutSeedOverwrite-SeedNeverClobbersLive` | `SeedNeverClobbersLive` violated, depth 3.                                                                                                  |
| `MutSeedStampLive-LiveWins`              | `LiveWins` violated, depth 7.                                                                                                               |
| `MutSeedNotPublished-Convergence`        | `Convergence` violated, depth 2.                                                                                                            |
| `MutSeedIgnoresWipe-WipeStays`           | `WipeStays` violated, depth 3.                                                                                                              |
| `MutWindowClosed-Fills`                  | `Fills` violated, depth 8: the old window leaves keys unfilled.                                                                             |
| `MutNoReceipt-all`                       | Same state count as `Good`, no error: the model's retry safety comes from the fill rule, so the receipt is a cost bound, not a safety rule. |

This is bounded model evidence. It is not a refinement proof of the SQL.
Tests in `packages/server/src/localdb/late-seed.test.ts` run each invariant
against the real code, and two mutations of that code (no own tombstones; no
`fillOnly`) turn four and eight of them red.

## Known limits

- A full refresh drops seed rows that upstream does not list (stamp 0 is below
  every real stamp). A record that exists only in an archive can be dropped this
  way. This is existing behaviour and the model keeps it.
- Older instances of the same upstream identity (O2) are not seed sources yet.
  The legacy store keeps no upstream account identity, only a label.
