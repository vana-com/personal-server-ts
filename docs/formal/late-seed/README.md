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

## Upgrade

The repair above covers a delete published after it ships. A device on the build
before it may already have published a delete, compacted its pending change and
kept no tombstone. The seed cannot tell that key from one the stream never held,
and the owner's deleted record comes back (`MutUpgradedNoRecover`, depth 6):

1. `LiveUp` k, `LiveRemove` k (explicit delete), `Publish` on the old build:
   no own tombstone, and the pending change is pruned.
2. `Upgrade`: the device runs the new build.
3. `Seed` k: the record is live under the seed stamp.

The log still holds every deletion (a snapshot keeps every tombstone), so the
repair is local too. Before an import fills a connection, `recoverLogTombstones`
(`log-tombstone-recovery.ts`) writes the tombstone of every deletion and
omission in the log the device holds. The model has `bld[d]` ("old", "new",
"rec"), `Upgrade` and `Recover`, enabled only in the two upgrade modes; a seed
pass (its fills, skips and receipt) begins only at "rec". In the mutant it
begins at "new".

## Results

Run with `TLA2TOOLS=<tla2tools.jar> [WORKERS=2] ./run.sh <Config>` (one job, 4
workers unless `WORKERS` says otherwise, `nice -n 19 ionice -c3`). Constants: two keys, two devices, `MaxO = 2`,
`MaxEv = 3`, `MaxLog = 5`. Logs are in `traces/`.

| Config                                   | Result                                                                                                                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Good`                                   | No error. 30,351,465 states generated, 8,227,927 distinct, depth 19.                                                                        |
| `MutOwnTombOff-NoResurrection`           | `NoResurrection` violated, depth 5.                                                                                                         |
| `MutOwnTombOff-RetryAddsNothing`         | `RetryAddsNothing` violated, depth 5.                                                                                                       |
| `MutSeedIgnoresTomb-NoResurrection`      | `NoResurrection` violated, depth 5.                                                                                                         |
| `MutSeedIgnoresPend-NoResurrection`      | `NoResurrection` violated, depth 4.                                                                                                         |
| `MutSeedOverwrite-SeedNeverClobbersLive` | `SeedNeverClobbersLive` violated, depth 4.                                                                                                  |
| `MutSeedStampLive-LiveWins`              | `LiveWins` violated, depth 6.                                                                                                               |
| `MutSeedNotPublished-Convergence`        | `Convergence` violated, depth 2.                                                                                                            |
| `MutSeedIgnoresWipe-WipeStays`           | `WipeStays` violated, depth 4.                                                                                                              |
| `MutWindowClosed-Fills`                  | `Fills` violated, depth 8: the old window leaves keys unfilled.                                                                             |
| `Upgraded`                               | No error, all invariants of `Good`. 31,740,157 states generated, 8,638,953 distinct, depth 21 (`MaxLog = 4`).                               |
| `MutUpgradedNoRecover-NoResurrection`    | `NoResurrection` violated, depth 6: the seed runs on the new build before it recovers.                                                      |
| `MutNoReceipt-all`                       | Same state count as `Good`, no error: the model's retry safety comes from the fill rule, so the receipt is a cost bound, not a safety rule. |

This is bounded model evidence. It is not a refinement proof of the SQL.
Tests in `packages/server/src/localdb/late-seed.test.ts` run each invariant
against the real code, and two mutations of that code (no own tombstones; no
`fillOnly`) turn four and eight of them red. Three upgrade tests drop the
tombstones a device holds, as the earlier build left them (a published delete, a
published omission, a delete folded into a snapshot), and turn red without
`recoverLogTombstones`.

## Known limits

- A full refresh drops seed rows that upstream does not list (stamp 0 is below
  every real stamp). A record that exists only in an archive can be dropped this
  way. This is existing behaviour and the model keeps it.
- Older instances of the same upstream source are seed sources: the server
  runner folds a source's live instances newest first into one ranked import per
  `(source, stream)`, so on one device the newest instance's body wins whatever
  the order of arrival (`SeedRank.tla`, below). Archive and deleted instances
  are never merged.
- Across devices the body is not ranked. Devices exchange seed bodies at equal
  stamp `(0, seed)` and the greater `body_sha256` wins (accepted ruling Q11). If
  two devices hold different instance sets, the devices still agree, but the body
  they agree on may come from an older instance (`SeedRank-ranked-split-GlobalRank`).

## Which body wins when instances overlap (`SeedRank.tla`)

`LateSeed.tla` has no bodies, so it cannot say which of two seed bodies a key
ends with. `SeedRank.tla` adds one key, two instances (one newer than the other)
and two devices. The hash order is the reverse of the rank order, so "follows the
rank" and "follows the hash" give different answers. Two import modes: `arrival`
(one import per instance, any order) and `ranked` (one folded import per device).
Two layouts: `same` (each device holds both instances) and `split` (`d1` holds
both, `d2` only the older one). Run with `MODULE=SeedRank ./run.sh <Config>`.

| Config                             | Result                                                                                                                                                             |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SeedRank-ranked-same`             | No error. `TypeOK`, `LocalRank`, `Convergence`, `GlobalRank` hold. 45 states generated, 24 distinct, depth 7.                                                      |
| `SeedRank-ranked-split`            | No error. `TypeOK`, `LocalRank`, `Convergence` hold. 78 states generated, 42 distinct, depth 9.                                                                    |
| `SeedRank-ranked-split-GlobalRank` | `GlobalRank` violated, depth 9 (74 states generated). The devices agree, on the older instance's body: the cross-device tie-break is the hash (Q11), not the rank. |
| `SeedRank-arrival-same-LocalRank`  | `LocalRank` violated, depth 3 (12 states generated): the instance that arrives first stays, so the body follows arrival order.                                     |
| `SeedRank-arrival-Convergence`     | No error. 136 states generated, 68 distinct, depth 10: arrival order costs rank, not agreement.                                                                    |

T2 answer: newest-first submission does not give "newest body wins" by itself,
because an import never replaces a held row. It does when the instances are
folded into one ranked import per device, as the runner now does. A negative
control in `canonical-instance-merge.test.ts` shows two separate imports let the
arrival order decide. These are bounded results for one key; they are not a
proof of the SQL.
