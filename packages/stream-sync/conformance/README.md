# Conformance: the TLA+ model against the package

This directory checks mechanically that the package decides as the model in
`../formal/StreamSync.tla` does. It has two parts:

- **Trace replay.** TLC writes traces of the model. `replay.ts` replays every
  step against the package functions and reports each place where the
  package decides differently. `../src/conformance.test.ts` runs the replay
  in CI.
- **Property tests.** `../src/conformance.properties.test.ts` uses fast-check
  for the parts that the model abstracts: merge, reduce, the bucket planner,
  the codecs and the names.

## Files

| File                          | What it is                                                                                                                                                                                                                                                                         |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `StreamSyncConformance.tla`   | Extends the model. It adds no variables and no actions. It adds the trace `ALIAS` (model operators evaluated in each state), the end-of-run marker for simulation, and the witness states of the fixed traces.                                                                     |
| `StreamSyncConformanceR3.tla` | Witnesses that read model fields older revisions do not have (`seen`, `fin`): `q9-noop` and `incomplete-plan-lost-to-409`.                                                                                                                                                         |
| `generate.mjs`                | Runs TLC and writes the corpus.                                                                                                                                                                                                                                                    |
| `corpus/corpus.ndjson.gz`     | The corpus, gzipped NDJSON. Line 1 is metadata: model commit, SHA-256 of `StreamSync.tla` and of the wrapper, design constants, profiles and TLC runs. Every other line is one trace. A trace stores its first state in full and each later state as the changed top-level fields. |
| `replay.ts`                   | The replay and the value mapping.                                                                                                                                                                                                                                                  |
| `report.ts`                   | `tsx conformance/report.ts [corpus]` prints the decision-point counts and every divergence.                                                                                                                                                                                        |
| `known-divergences.json`      | The divergences the test expects, each with the side that is wrong and why.                                                                                                                                                                                                        |

## Regenerate the corpus

Run from `packages/stream-sync`, with TLC 2026.11.03 (`tla2tools.jar`) on
Java 17:

```sh
TLA2TOOLS=/path/to/tla2tools.jar node conformance/generate.mjs \
  --formal formal --model-ref "$(git rev-parse --short=12 HEAD)" \
  --scratch /path/to/empty/dir --seeds 60 --fixed-timeout 120
```

The output is `conformance/corpus/corpus.ndjson.gz`. The run is
deterministic for a model and seed list, and gzip writes no timestamp. TLC runs one job at a
time under `nice -n 19`. A fixed trace uses breadth-first search on 4
workers, and the generator leaves out a fixed trace whose search does not
finish within `--fixed-timeout` seconds; the metadata names it. Each
simulated trace is one `-simulate` run with one worker and a fixed seed.
Duplicate traces are removed.

The corpus metadata records the model commit. When the model changes,
regenerate the corpus, run the test, and update `known-divergences.json`.

### Traces

- **Fixed traces** are the shortest traces to a named state: `late-head`
  (a stream's base decision while a newer generation's row is the latest),
  `split-run` (the revision 4 counterexample shape), `CE-late-head` (the
  S1 counterexample under the design; S1 holds, so it is normally
  absent), `stale-generation` (a base decision while the latest row has a
  generation above the stream's target), `q9-noop` (a no-op onto a
  complete:false head of the run's generation), `incomplete-plan-lost-to-409`
  (a checkpoint skipped although every committed head is complete), and the
  model's own scenario witnesses (`W-*`). The metadata names each witness
  that holds or timed out.
- **Simulated traces** cover the model's bound profiles: `late`, `split`,
  `lean`, `key`, `idless`, `small`, `twice` and `slice-q9`, with seeds
  1..60 and a raised run count, so that more runs reach publish and
  checkpoint.

## Mapping

The model's connector is `c`. A model account `A` maps to `ns` = the UTF-8
hex of its name, left-padded with `0` to 16 characters; the identity-less
namespace `""` maps to `""`. A model owner key maps to `keyCheck` = the
first 16 hex characters of SHA-256 of its name.

| Model                                                                         | Package                                                                                                                                             | Arguments                                                                                                                                                     |
| ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Control state `[k, g]`                                                        | `ControlState`                                                                                                                                      | `absent`, `active(generation g)`, `deleted(version g)`, `foreign(version g)`                                                                                  |
| Start state (`EffStart`)                                                      | `StartState`                                                                                                                                        | as above, and `unknown`                                                                                                                                       |
| Line `<<pk, rid, acct, "run">>`                                               | `Line`                                                                                                                                              | `{o: rid, r: "run-" + rid as 6 digits, v: {id: pk, acct}}`                                                                                                    |
| Line `<<pk, 0, "desk", "seed">>`                                              | `Line`                                                                                                                                              | `{o: SEED_OBSERVED_AT, r: SEED_RUN_ID, v: {id: pk, acct: "desk"}}`                                                                                            |
| Line `<<pk, 0, acct, "raw">>`                                                 | `Line`                                                                                                                                              | `{o: 0, r: "raw", v: {id: pk, acct}}`                                                                                                                         |
| Stream row head `[g, lines, complete, key, at]`                               | `Head` built by `BucketReducer` + `encodePart` + `encodeHead`, checked by `decodeHead`                                                              | `generation g`, `complete`, `keyCheck(key)`, `observedAt at`, primary key `["id"]`                                                                            |
| `TombHead` (an old app's DELETE)                                              | stream row `tombstoned`                                                                                                                             |                                                                                                                                                               |
| `LiveP(v, n, s)` (`xreg.liveP`)                                               | `isHeadLive(control, streamRow, headGeneration)`                                                                                                    | every state, every namespace and stream                                                                                                                       |
| `Read(v, L, name)[1]`, `ViewNS` (`xread.k`, `xread.vns`)                      | `eligible({connections, target: logical [name], legacyFile})`                                                                                       | every state; each name; legacy file absent, older and newer than the heads                                                                                    |
| `Readiness(v, L, name)` (`xread.ready`)                                       | `isReady(...)`                                                                                                                                      | as above                                                                                                                                                      |
| `connections[ns].latestHeadRegistration`                                      | `Stamp(v, n)`                                                                                                                                       | the model orders by run id (`at`)                                                                                                                             |
| `StartRun`, `StartRunFor`, `Rerun`: `e.full`                                  | `!checkpoint \|\| runMustBeFull(needsFull, c)`, then `createOutboxEntry`                                                                            | `needsFull` of the device before the step                                                                                                                     |
| `Decide(d, s)`: the step taken (`EffTable` value cross-checked)               | `decide({start, current, userConnect, full, phase})` and `targetFor(start)`                                                                         | `phase` is tracked per stream: `first`; `after_write` after a create or reconnect reply that inserted or replayed the row; `reread` after a `reread` decision |
| A planned stream whose table value is −1 (keep pending, no step enabled)      | `decide(...)` must give `keep_pending`, or `reread` and then `keep_pending`                                                                         | every state                                                                                                                                                   |
| `PlanStale(d, s)` / `PlanPublish(d, s)`: the base (`Plan` in older revisions) | `chooseBase(streamRow, head, T)`                                                                                                                    | the latest row (the base version under `AckImmutable`)                                                                                                        |
| `PlanPublish`: lines and `complete` of the planned head, or a no-op           | `BucketReducer` over base, seed, raw and run lines; `encodePart`; `headComplete({full, baseComplete, seedMerged})`; `isNoop(base, parts, complete)` | both raw options when the model allows raw; the model's `seeded` and `rawOK` are restated                                                                     |
| Publish `complete:false`: `needsFull` and checkpoint                          | `afterCommit(needsFull, {complete: false, runFull})`                                                                                                |                                                                                                                                                               |
| No-op onto a `complete:false` base (Q9): `needsFull` and checkpoint           | `afterCommit(needsFull, {complete: false, runFull})`                                                                                                | only when the model has `NoOpNeedsFull`                                                                                                                       |
| `Post(d, s)`: `needsFull` after a commit                                      | `afterCommit(needsFull, {complete, runFull})`                                                                                                       |                                                                                                                                                               |
| `Finish(d)`: checkpoint saved or not                                          | `checkpointDecision({target, streams, control, seedReceiptsPending})`                                                                               | per-stream results tracked through the trace; `control` = `CtlNow`; `seedReceiptsPending` = not `rcptOk` (restated)                                           |
| `Leave(d)`                                                                    | (host) drop the device's outbox entry, `needsFull` and checkpoint                                                                                   | the replay resets its per-device memory                                                                                                                       |

The replay reads model operators from the trace (`TraceAlias`) and so does
not re-implement them. The few expressions that live inside an action's
`LET` are restated in `replay.ts`, each marked "restated from
StreamSync.tla".

## What neither method checks

Model abstractions with no package counterpart:

- **Account switch with a reused checkpoint.** The model publishes
  `complete:false` when a run reuses a checkpoint of another account
  (`e.sw`). The package has no input for it; the replay counts these steps
  (`modelOnly`).
- **A stream planned only for the seed that gets no seed.** The host records
  it as `skipped` (§2.9). No package function decides it; the replay counts it.
- **Eligibility order.** The model orders connections by run id; the
  package takes the registry order the host passes.
- **Stream deletion.** The model never tombstones a stream row except by an
  old app's DELETE (limitation L11).
- **Host sequencing.** The order of steps, the outbox, retries, 409 handling,
  lost replies (`LateApply`), and what the host does with each decision.
  The replay checks each decision; it does not run a host.
- **Registry, storage and reader PS.** CAS, settlement, cleanup, imports and
  reader lag are model actions with no package function.
- **The compatible-writer rule** (`writerCompatibility`). The model has no
  writer versions or profiles, so the corpus does not reach it.
- **`runMustBeFull` is never decisive.** In the model a device that has
  `needsFull` never also has a checkpoint, so `!checkpoint` already makes
  the run full. The replay checks the call at every run start, but a
  mutant of `runMustBeFull` passes. The property tests do not cover it
  either.
- **When the host sets `needsFull` after `complete:false`.** The model sets
  it (and the run's `incomp` flag) when the request is persisted, and keeps
  the flag when a 409 sends the stream back to plan. The package decides
  from the committed results. So when a `complete:false` request loses to
  another device's complete head and the re-plan commits `complete:true`,
  the model skips the checkpoint and the package saves it. The package's
  save is safe; the model costs one extra full run. An older model
  revision's corpus showed this once; the witness
  `incomplete-plan-lost-to-409` does not finish within the timeout on the
  current model, so the corpus does not have it.
- **An empty spool with no seed.** The model treats it as a no-op onto the
  base. No package function takes that input; the host must not call
  `merge` for it. The replay counts these steps.
- **One record key per line and one bucket.** Model records are one field;
  every trace fits one bucket. The planner, multi-part heads and
  `bucket_too_large` are covered only by the property tests.

The property tests cover merge order, the reducer, the planner, the codecs
and names over random inputs. They do not check any rule that needs the
registry or the outbox.
