# Formal model of whole-file stream sync

Status: **stopped on a counterexample to the design.** The model is not
complete. Do not read the configs below as proof. The model checks the
section-4 property list of design revision 4. The first small-profile run
found a run of the design that breaks S7 (checkpoint safety). It also
breaks S3 (reconnect is clean), read literally. The design is not patched
here. The trace is in [traces/split-run.txt](traces/split-run.txt).

## The counterexample

One connection `n1`, two devices, two streams. Device `d2` makes its first
connect (`userConnect`, `boundGen = 0`). Its run has streams `s1` and `s2`.

| Step | What happens                                                                                                                                                                    | Control      |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| 4–7  | `d2` reads control (absent), creates it, publishes `s1` at generation 1.                                                                                                        | `active(1)`  |
| 8    | `d1` deletes the connection.                                                                                                                                                    | `deleted(2)` |
| 9–12 | `d2` reads control again for `s2` (the publish sequence decides per stream). It sees `deleted(2)` with `userConnect`, so it reconnects. Then it publishes `s2` at generation 3. | `active(3)`  |
| 13   | Every stream of the run is committed, so `d2` saves the checkpoint.                                                                                                             | `active(3)`  |

Result: one run has committed at two generations, `(s1, g1)` and
`(s2, g3)`.

- **S7.** No single `(ns, generation)` tag covers both streams. Tag the
  checkpoint with generation 3: `s1` is not committed under it. Tag it with
  generation 1: `s2` is not committed under it. The design tags checkpoints
  with `(ns, generation)`, but it does not say which generation applies when
  a run's streams commit at different generations.
- **What the user sees.** Generation 3 has `s2` but no `s1`: `s1`'s only
  head is at generation 1, so it is not live. If the checkpoint stands, the
  next run is incremental and does not collect again the `s1` records that
  this run collected. Generation 3 stays without those records until a full
  run. The §2.7 rule (an incremental run that publishes `complete:false`
  drops the checkpoint) makes the run after that full. So the loss lasts
  one or two runs. It is not permanent.
- **S3, read literally.** Generation 3 holds lines of run 2, and run 2 also
  committed at generation 1. This conflicts with §2.4 "B's connect wins".
  That rule wants a racing connect to republish, so it is a question of
  intent, not a clean violation. S7 is the clean violation.

The trace does not need a lost reply, a crash or a second account. Any
`userConnect` run with two or more streams can straddle a delete made on
another device.

Reproduce (Java 11+, `tla2tools.jar`; checked with TLC 2026.11.03):

```sh
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 4 -deadlock \
  -config cfg/CE-split-run.cfg StreamSync.tla
```

TLC reports `Invariant S7_CheckpointSafe is violated` at depth 13 or 14,
after 300,000 to 350,000 distinct states (the count depends on the worker
count). `traces/story.py` turns a
`-dumpTrace json` file into the table in `traces/split-run.txt`.

## What the model is

`StreamSync.tla` models one connector with these parts:

- connections (namespaces) with a control row chain;
- one registry row chain per stream, with exclusive writes;
- storage objects by name;
- per device: knownGen, stopped, a checkpoint and an outbox entry;
- per device: an imported view.

Every guard in section 4 is a constant. A control sets one guard to FALSE.
`configs.mjs` is the one source of the TLC configs in `cfg/`.

Modelling choices the reader should check:

- One part per line, plus one empty part when `EmptyParts` is TRUE and a
  head lacks a key. Lines carry `(o, r)`, so parts of different generations
  never have equal bytes. The empty part is the only exception. Without
  empty parts, the "no generation in part names" control cannot fail.
- A run's ns is known at run start. Its `boundGen` is knownGen at that time.
  A `boundGen = 0` entry that publishes at generation g is bound to g from
  then on (the "join" row of the decide table).
- A first sighting by the sync loop (knownGen 0 → g) is not a generation
  change. It does not clear the device's entries.
- A no-op publish (the base head already holds the run) counts as committed
  at the base's `(ns, generation)`.
- S2 is checked for a device once its sync loop, or its own delete, has seen
  the tombstone. Other devices show old rows until their next sync. This is
  accepted limitation 8.
- `X1_CompleteHonest` is extra: it is not in the design's list. A head marked
  `complete` has a line for every key.

## Not done (stopped)

These parts were not done because the model found the counterexample:

- the full profile;
- the six controls;
- L1;
- scenario witness traces;
- replay against package code;
- statecharts;
- `check.mjs`.

The package that implements this design does not exist yet. The package in
`src/` implements the earlier snapshot design.
