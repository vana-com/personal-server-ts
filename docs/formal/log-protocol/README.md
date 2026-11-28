# Connection-log models and recorded evidence

## Current evidence summary and open obligations

**Documentation/source snapshot:**
`2f3228e6f461d5a1c2e1672d1570c1980bafdd2e` is the tree reviewed for this
summary. It is **not** a claimed source SHA for every TLC run below. The only
explicit original source pin, `1ca1a110d9304adc4dab709c78cf770584a895fa`,
belongs to the initial design exploration in [History](#history-initial-design-exploration).
Later sections record model revisions and run dates, but do not provide one
verified implementation/model pin covering the whole set.

**Status:** TLC has been run. Results are model-specific: completed checks,
intentional failing mutants and interrupted runs are distinguished below.
This is bounded model evidence, not a proof of the integrated product or a
refinement proof from the models to its implementation.

| Evidence                                        | Bounds and last recorded result                                                                                                                                                                            | Source in this document                                                                                                                                      |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Latest dated run: `PartialView.tla`, 2026-11-17 | Three segments; operations over two keys; position stamps. `PartialView.cfg` records no error, 20,480 generated / 16,384 distinct states. Both lying-removal and no-hold mutants violate `Exact`.          | [Progressive first load](#progressive-first-load-shows-only-rows-the-finished-log-keeps-partialviewtla-host-run-2026-11-17)                                  |
| Incremental SQL rank, 2026-11-16                | One key at one stamp; ordinal/body ordering. `SqlRank.cfg` completes: 1,029,883 distinct states, depth 6. Two mutants fail `RowIsFold`.                                                                    | [Incremental apply](#incremental-apply-sqlranktla-host-run-2026-11-16)                                                                                       |
| Equal-stamp abstract order, rerun 2026-11-16    | Five-batch corpus; `EqualStamp.cfg` completes at 3,447,086 distinct states. Lifetime variant stopped at 40 minutes; liveness not checked.                                                                  | [Equal-stamp order](#equal-stamp-order-host-run-2026-11-15)                                                                                                  |
| Head cursor/replay, 2026-11-16                  | One stream, three devices, two heads/two rounds. Durable-obligation checks and rollback variant pass their listed properties; memory-only variants fail. Pending local writes and compaction are excluded. | [HeadCursor](#headcursor-a-per-stream-head-that-predates-the-log), [stored replay obligation](#the-stored-replay-obligation)                                 |
| General and keyed log models, 2026-11-15/16     | Corpus/config-specific bounds; `MaxSteps=6` bounds commits/reset, not network steps. Good, LostPush temporal checking and keyed runs include unfinished checks, not established PASS results.              | [State and abstraction](#state-and-abstraction), [TLC results](#tlc-results-host-run), [key-ordered first load](#key-ordered-first-load-host-run-2026-11-16) |

Fresh workspace transaction checks are recorded in [Durable bounded workspace](#durable-bounded-workspace-2026-11-19). A proposed upper cap on record stamps is checked in [Finality cap](#finality-cap-proposed-checked-before-it-is-built-2026-11-20); it is a design check, not a model of shipped code. An alternative that fixes fast clocks at the source (offset plus refusal) is checked in [Source clock](#source-clock-an-alternative-to-the-cap-checked-before-it-is-built-2026-11-21). The historical run summary above remains specific to its original checks.

**Open obligations before relying on this evidence:**

- Record matching implementation/model/config pins and rerun relevant checks
  for a release. The dated receipts below are not fresh runs on this snapshot.
- Complete or explicitly bound the unfinished safety/liveness obligations;
  no invariant error before a timeout is not a completed PASS. See the Good,
  LostPush, keyed and EqualStampLifetime rows.
- Preserve each model's assumptions. General convergence assumes eventual
  successful reads and writer quiescence; keyed recovery explicitly conditions
  liveness on crashes ending. See [properties](#properties-and-expected-host-results)
  and [rebaseline](#rebaseline-of-an-unfinishable-key-ordered-load-host-run-2026-11-16).
- Establish implementation-level evidence for omitted concerns, including real
  gateway CAS/authentication, crypto, crash/storage behavior and local pending
  writes where excluded. [Host invocation and exclusions](#host-invocation-and-exclusions)
  and the individual model sections state what is not proved.
- `PartialView` assumes truthful removal facts. Its section explicitly describes
  the runtime limitation when a writer supplies a false fact; do not interpret
  the model's `Exact` result as unconditional runtime safety.

The runtime uses a connection log, segment application, batch publication and
control-row deletion fences; see the [package overview](../../../packages/stream-sync/README.md#current-protocol-and-ownership).
Descriptions below are retained at the revision they discuss. In particular,
[per-stream heads beside the log](#per-stream-heads-beside-the-log-applyts)
records an older fallback/flag design, not the current publication contract.
That historical summary did not execute new TLC or product tests. Fresh workspace
checks are recorded below.

## Durable bounded workspace (2026-11-19)

Implementation source pin: `584e2be2fdd7ee19ec5bea2784e5d9482b523c14`.
This is a **proposed local transaction contract**, checked before workspace
finalize/recovery implementation. It does not claim that this source implements
these new steps. The model SHA-256 hashes and complete TLC command lines below
pin the checked models without relying on external handoff files.
No formal-source-sync registry or checker exists in this source tree.

`Workspace.tla` adds local phases without replacing the remote protocol in
`LogProtocol` or the continuity/replay obligations in `HeadCursor`.
It instantiates `SqlRank`'s comparator and new pure fold-cell operators. The
existing SQL rank state machine is unchanged. Each cell keeps the greatest
upsert and greatest deletion independently. An independent set-maximum oracle
checks every incremental prefix; fixed vectors check same-body ordinal changes,
body-hash ties, an omission at the upsert stamp, explicit deletion, resurrection,
the retained preceding tombstone, and the winner's own `first_o`. Zero encodes
NULL; positive integers encode first-seen values. This deliberately does not use
`LogProtocol`'s historical minimum-first field as the current `first_o` oracle.
The fold mapping is `packages/stream-sync/src/log.ts:551-650`.

Seven one-operation input units, two keys, one output object, one publication
candidate, two concurrent CAS request slots and one workspace are modeled. Two
chunks stand for a body. Only a validated unit commits its receipt, fold data and visible complete bodies.
The snapshot cursor/completion commits with the last unit. A crash can follow
**every** transition, including successful commits before reply delivery. Restart
aborts speculative unreceipted bytes and starts that unit again; durable receipts
and their fold survive. Replay skips only an exact unit/digest/generation/key-check
identity. Missing or corrupt input is abstracted as unavailable; no ingest or
cursor advancement occurs until repair. Digest verification itself is assumed. Retry digest, generation
and key-check vary independently. The generation/key-check mutants ignore only their named
field; the oracle always requires all identity fields to match.

Seed preparation precedes a single seed-promotion/cursor-rollback transaction.
`SeedAtomic` checks both directions: promotion requires reset, reset requires
promotion, and the old cursor is zero exactly when reset is true. `seedFirst`
promotes first and delays cursor rollback until after restart; it must fail.
The seed obligation contains folded entries (including both deletion and later
resurrection) plus one unpublished local observation. This abstracts a frozen
connection/revision at finalize, not concurrent mutable local-row handling.
The remaining phases separate partial output from sealed output, upload success
from durable upload receipt, CAS send from remote outcome, and authoritative
outcome read from local watermark finish. An uncertain response can represent
old authority, the exact candidate, or a competitor. `Send` adds an independent
pending request; reading old authority, restart and local cleanup cannot erase it.
`Land` may process either pending request in any local phase. At processing time,
it checks the expected remote head, deletion state, generation and key-check.
A lifetime change updates remote authority and the local known fence together in
this bounded model; it does not cancel the network request. A rejected request
is removed from the pending set after processing. Two slots also permit a retry before the original
request lands. Only the exact accepted candidate advances the watermark. Deletion, generation change and key-check
change each fence subsequent ingest, rebase, CAS admission and finish;
abandonment permits cleanup. Cleanup of an active workspace cannot remove its inputs or outputs.
Remote objects are never garbage-collected here.

`PartialWorkspace.tla` extends `PartialView` directly: its exhaustive three-part,
two-key corpus and truthful future-removal holdback stay owned there. It adds
speculative chunk reads, durable body/position/marker commit, restart and final
snapshot cursor. Partial markers are true exactly for a nonempty unfinished
prefix; completion and snapshot cursor require the final part. It is a separate
small product of facts and durability, **not** a composed refinement proof of
all workspace and progressive actions.

Fresh TLC 2.19 (tools 1.7.4), Java 17, one worker, 1 GiB heap, low CPU/I/O
priority. All searches in the table completed. The earlier run of unchanged
`SqlRank.cfg` passed: 1,340,914 generated / 1,029,883 distinct states, depth 7.
Counts for failures are at the first invariant violation, not full graph sizes. No parser/runtime failures count as mutant kills.

| Config                      | Result                              | Generated | Distinct | Depth |
| --------------------------- | ----------------------------------- | --------: | -------: | ----: |
| WorkspaceGood               | PASS safety and temporal properties | 8,320,331 |  143,960 |    49 |
| WorkspaceLateLandWitness    | REACHED `NoLateReadLand`            |   822,198 |   20,192 |    38 |
| WorkspaceFencedLandWitness  | REACHED `NoFencedLand`              |   825,851 |   20,481 |    38 |
| WorkspaceIgnoreGeneration   | FAIL `ReplayGeneration`             |       114 |       58 |     6 |
| WorkspaceIgnoreKeyCheck     | FAIL `ReplayKeyCheck`               |       116 |       60 |     6 |
| WorkspaceSeedFirst          | FAIL `SeedAtomic`                   |   404,195 |   12,755 |    31 |
| WorkspaceEarlyCursor        | FAIL `NoGap`                        |         8 |        7 |     2 |
| WorkspaceOmittedUpload      | FAIL `UploadBeforeCAS`              |   632,039 |   17,163 |    35 |
| WorkspaceDroppedTombstone   | FAIL `ReceiptedFold`                |    34,285 |    2,555 |    17 |
| WorkspaceEarlyCleanup       | FAIL `LiveInputs`                   |       124 |       68 |     6 |
| WorkspaceSplitSeed          | FAIL `SeedAtomic`                   |   404,195 |   12,755 |    31 |
| WorkspaceReceiptWithoutFold | FAIL `ReceiptedFold`                |        63 |       35 |     5 |
| PartialWorkspaceGood        | PASS safety and temporal properties |    81,920 |   40,960 |    10 |
| WorkspaceEarlyCompletion    | FAIL `TruthfulMarkers`              |    20,481 |   12,289 |     4 |

Liveness is conditional on crashes stopping, input eventually becoming available,
fair local work and repair, and strong fairness of CAS landing when repeatedly
attempted. A competing authority or lifetime fence settles by abandonment rather
than publication. Fairness does not turn permanently corrupt input into success.
The model does not bound actual RSS, caches, bytes, disk or query complexity.
`OneLease` checks only the abstract unit ownership shape.

The two witness configurations deliberately check the negation of desired
reachability: an invariant violation (exit 12) means the requested interleaving
was reached, not a safety failure. `NoLateReadLand` witnesses successful acceptance
after an old-authority read returned the local phase to ready. `NoFencedLand`
witnesses a pending request processed after a lifetime fence (and rejected by its
remote preconditions). These witnesses are separate from all safety properties.

Red-first checks against the phase-coupled landing rule could not reach either
witness: each exhausted 130,049 generated / 9,140 distinct states, depth 44,
without a violation. Offering independent identities with the old replay check
violated `ReplayGeneration` (114 / 58, depth 6) and `ReplayKeyCheck` (116 / 60,
depth 6). The old one-way seed assertion missed the seed-first mutant entirely:
3,722,825 / 68,264, depth 49, no violation. The strengthened checks discriminate
all three added mutants. No design contradiction appeared in the good model.

Model SHA-256 hashes (the exact bytes checked for this table):

```text
ed1bebf8189eefe19e899c6acb0f6ca3f846a68f3e0e78de3f33e74e3fa21e08  Workspace.tla
234516578a2fcaf52a50bc1e09cfed82d828d3c958c94df014f00f8b491a8bf2  SqlRank.tla
e0ec444cfb46f2051116212d448a69d11af7b8983a2ec98205e050a7467eda40  PartialWorkspace.tla
a9a5a2793eb636cbbf19fa864c4db353dbca1df359e1133629665d0181967053  PartialView.tla
```

Reproduce the full table from the repository root. Supply a trusted tools jar
and a fresh disk-backed output directory. Each job runs serially with one worker;
expected invariant failures exit 12, while good configurations exit zero.

```sh
cd docs/formal/log-protocol
: "${TLA2TOOLS:?set the tools jar path}"
: "${TLC_OUTPUT:?set a fresh disk-backed output directory}"
mkdir -p "$TLC_OUTPUT"
for cfg in \
  WorkspaceGood WorkspaceLateLandWitness WorkspaceFencedLandWitness \
  WorkspaceIgnoreGeneration WorkspaceIgnoreKeyCheck WorkspaceSeedFirst \
  WorkspaceEarlyCursor WorkspaceOmittedUpload WorkspaceDroppedTombstone \
  WorkspaceEarlyCleanup WorkspaceSplitSeed WorkspaceReceiptWithoutFold \
  PartialWorkspaceGood WorkspaceEarlyCompletion
do
  model=Workspace
  expected=12
  case "$cfg" in
    PartialWorkspaceGood|WorkspaceEarlyCompletion) model=PartialWorkspace ;;
  esac
  case "$cfg" in
    WorkspaceGood|PartialWorkspaceGood) expected=0 ;;
  esac
  if nice -n 19 ionice -c3 java -XX:+UseParallelGC -Xmx1g -cp "$TLA2TOOLS" \
    tlc2.TLC -workers 1 -metadir "$TLC_OUTPUT/$cfg" \
    -config "$cfg.cfg" "$model" > "$TLC_OUTPUT/$cfg.log" 2>&1
  then status=0
  else status=$?
  fi
  cat "$TLC_OUTPUT/$cfg.log"
  if [ "$status" -ne "$expected" ]; then exit 1; fi
done
```

Remaining obligations: implementation-to-atomic-step mapping and replay tests on
real durable SQLite/files; matching source/model/config pins after implementation;
multiple output objects/publication prefixes; concurrent pending local writes
and revision validation; schema migrations; stream metadata; host append offset
and digest checks; cryptographic verification; bounded-memory ownership and
adapter measurements. Existing uncompleted log-model obligations above remain
open. No design claim was contradicted by the completed bounded checks.

## Finality cap (proposed, checked before it is built; 2026-11-20)

`FinalityCap.tla` checks a proposed **upper cap on record stamps** before anyone builds it. It is a new,
small module. It does not change `LogProtocol.tla`, `SqlRank.tla` or any existing config.

**Proposal.** The registry stamps each segment with `finality[seg]`: the time of ONE registry clock when the
segment became final. A device that applies a segment orders it by `eff = min(stamp_o, finality)`. The value
is the same on every device. The lower clamp (`clampRunStart` in
`packages/core/src/localdb/admit.ts`, built) then reads `eff`, not raw stamps.

**Model SHA-256** (`FinalityCap.tla`): `f31aef9690848c65e4121f992b695b98599658f840b448d1824b00cdc54c3a23`.
Base tree: `origin/main` at `91022e59`. TLC 2.19 (tools 1.7.4), Java 17, `-workers 2`, `nice -n 19 ionice -c3`.
Command, from this directory, for every config `X`:

```
nice -n 19 ionice -c3 java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 2 -config X.cfg FinalityCap
```

### What the model contains

- Two devices. Device 1 has a clock that reads registry time plus `SkewA` (fast); device 2 reads
  registry time plus `SkewB`. Clocks do not step back. Registry time `t` is bounded by `MaxT`.
- A registry log (a sequence). A device holds a prefix of it. A writer appends only when its device holds the
  whole log (the registry compare-and-swap). Each append gets `finality = t`; one append per tick
  (the mutant `tieFinality` removes that).
- Runs with distinct ids, at most `MaxSegs` segments each, published while collecting. A delete is a run's
  last segment, as in the code (intake admits upserts only; the delete is a run-end entry).
- The lower clamp as built: the maximum over the held `(stamp, run id)` pairs; the clock if
  `(clock, run id)` is above it; else the held `o` if the run id sorts after the held run id; else one above.
- The order: `(eff, run id, kind, ordinal, position)`, kind delete above upsert, position standing for the
  body hash. The seed is one upsert per key at `(0, run id 0)`.
- Two keys; bodies unique per segment.

**Not modelled** (so nothing below says anything about them): the compaction watermark and stream floors
(each is a maximum over stamps the device already held, so the model's held-stamp maximum stands for them
**only if every stored copy of a stamp is `eff`**; see open risks); the SEEN stamp; omissions; two writers
with one run id (clones); clock steps backwards; crashes; a rollout in which some devices have the cap and
some do not; more than two devices or keys; runs that overlap on one device.

### Invariants

| Name                                             | Meaning                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Converged` (a)                                  | Two devices that hold the same log prefix hold the same winner for every key.                                                                                                                                                                                                                                  |
| `BeginAfterWins` (b)                             | A run that began after its device applied position `j` ranks above `j` at every device that holds both. So its write ends as the winner or a successor wins. This is the fast-clock bug of #846.                                                                                                               |
| `SameRunOrder`, `DeleteWinsTie`, `SeedLoses` (c) | Later segments of one run outrank earlier ones of the same key. A delete outranks an upsert of its own run. Every run's segment outranks the seed. `DeleteWinsTie` and `SeedLoses` follow from the rank layout; they are guard rails, not discoveries. `DeleteWinsTie` is exercised by the `midDelete` mutant. |
| `DragRaw`, `DragSlow` (d)                        | A run's raw start is at most `max(its own clock at begin, registry time at begin + 1)`. `DragSlow` is the same bound for a run on the slowest-clock device: the fast device's skew does not enter it.                                                                                                          |
| `DragEff` (d2)                                   | No stamp a device orders by is above the registry time now.                                                                                                                                                                                                                                                    |
| `CausalNoFlip`                                   | For a pair whose later run began after the earlier was applied, the cap never puts the later below the earlier when the raw order has it above.                                                                                                                                                                |
| `ConcurrentNoFlip`                               | For two runs where neither began after applying the other, raw order and eff order agree. Expected to fail.                                                                                                                                                                                                    |
| `RawCausalMonotone`                              | For a causal pair the RAW order also has the later above. Expected to fail with the cap.                                                                                                                                                                                                                       |

### Results

All counts are TLC "states generated / distinct". Bounds for every row except 3, 4 and 4b: `MaxT = 4`,
`SkewA = 2`, `SkewB = 0`, device 1 has up to 2 runs, device 2 has 1 run, `MaxSegs = 2`
(3 runs, up to 6 segments, 2 keys). Rows 3, 4 and 4b widen one bound each. A failing run stops at the first violation: its state counts and depth depend on
the order in which two workers reach it and are not a measure of the space. Depth is the breadth-first level reached when it stopped
(about the trace length plus one).

| #   | Config                       | Mode                                            | Invariants                                                | Result                                                                                                             | States                  | Depth             |
| --- | ---------------------------- | ----------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------- | ----------------- |
| 1   | `CapGood.cfg`                | proposal                                        | a, b, c, `CausalNoFlip`, `DragRaw`, `DragSlow`, `DragEff` | **PASS**                                                                                                           | 4,026,052 / 2,627,188   | 17                |
| 2   | `CapGoodSkew31.cfg`          | proposal, `SkewA = 3`, `SkewB = 1`              | as row 1                                                  | **PASS**                                                                                                           | 4,026,052 / 2,627,188   | 17                |
| 3   | `CapGoodT5.cfg`              | proposal, `MaxT = 5`, 2 + 1 runs, `MaxSegs = 2` | as row 1                                                  | **PASS** (36 min 41 s)                                                                                             | 27,098,627 / 17,673,761 | 19                |
| 4   | `CapGoodFour.cfg`            | proposal, `MaxT = 4`, 2 + 2 runs, `MaxSegs = 1` | as row 1                                                  | **PASS** (39 min 37 s)                                                                                             | 19,703,116 / 16,189,724 | 16                |
| 4b  | `CapGoodLong.cfg`            | proposal, `MaxT = 6`, 2 + 2 runs, `MaxSegs = 1` | as row 1                                                  | **NOT COMPLETE**: stopped at the 40-minute limit, no violation seen, 15.4 million states still queued. Not a PASS. | 33,452,489 / 26,285,660 | 14 (when stopped) |
| 5   | `CapBuilt.cfg`               | `noCap`: the lower clamp as built, no cap       | a, b, c, `CausalNoFlip`, `RawCausalMonotone`              | **PASS** (control: the built clamp keeps (a) to (c))                                                               | 4,026,052 / 2,627,188   | 17                |
| 6   | `CapRawClampSafe.cfg`        | `rawClamp`: cap orders, clamp reads raw stamps  | as row 5                                                  | **PASS**                                                                                                           | 4,026,052 / 2,627,188   | 17                |
| 7   | `CapRawClampDragEff.cfg`     | `rawClamp`                                      | `DragEff`                                                 | **PASS**                                                                                                           | 4,026,052 / 2,627,188   | 17                |
| 8   | `CapNoCapDragSlow.cfg`       | `noCap`                                         | `DragSlow`                                                | **FAIL** (mutant 1)                                                                                                | 1,039 / 847             | 6                 |
| 9   | `CapNoCapDragEff.cfg`        | `noCap`                                         | `DragEff`                                                 | **FAIL** (mutant 1)                                                                                                | 30 / 30                 | 4                 |
| 10  | `CapRawClampDragSlow.cfg`    | `rawClamp`                                      | `DragSlow`                                                | **FAIL** (mutant 2)                                                                                                | 990 / 806               | 6                 |
| 11  | `CapLocalFinality.cfg`       | `localFinality`                                 | `Converged`                                               | **FAIL** (mutant 3)                                                                                                | 34,642 / 28,328         | 9                 |
| 12  | `CapOwnRaw.cfg`              | `ownRaw`                                        | `Converged`                                               | **FAIL** (extra)                                                                                                   | 30,319 / 23,112         | 9                 |
| 13  | `CapTieFinality.cfg`         | `tieFinality`                                   | `BeginAfterWins`                                          | **FAIL** (extra)                                                                                                   | 2,846 / 1,889           | 6                 |
| 14  | `CapNoClamp.cfg`             | `noClamp`: cap, no lower clamp                  | `BeginAfterWins`                                          | **FAIL** (extra)                                                                                                   | 18,789 / 14,524         | 8                 |
| 15  | `CapMidDelete.cfg`           | `midDelete`                                     | `DeleteWinsTie`                                           | **FAIL** (extra)                                                                                                   | 1,040 / 844             | 6                 |
| 16  | `CapFlipConcurrent.cfg`      | proposal                                        | `ConcurrentNoFlip`                                        | **FAIL** (a finding, not a mutant)                                                                                 | 9,813 / 7,718           | 8                 |
| 17  | `CapFlipConcurrentBuilt.cfg` | `rawClamp`                                      | `ConcurrentNoFlip`                                        | **FAIL** (a finding)                                                                                               | 10,165 / 8,033          | 8                 |
| 18  | `CapRawNotMonotone.cfg`      | proposal                                        | `RawCausalMonotone`                                       | **FAIL** (a finding)                                                                                               | 6,039 / 4,824           | 7                 |

The full runs in rows 1, 2, 5, 6 and 7 generate the same count. The enabled actions do not read the stored
stamp values; only the invariants do. So the reachable-state graph has the same shape in every mode. That
equal count does not mean the modes are equal: rows 8 to 10 show the modes differ in the invariants.

**Counterexamples, in plain words** (registry time `t`; `o` is a run's raw start; `F` is finality):

- _Mutant 1, no cap (rows 8, 9)._ Fast device 1 begins a run at `t = 1`, its clock reads 3, so `o = 3`, and
  publishes at `t = 1`. Slow device 2 applies it, then begins a run at `t = 1` and its clock reads 1, but the
  clamp raises `o` to 3: two above the registry time. The fast clock reached a device that is not fast.
  (`DragEff`: the held stamp 3 is above registry time 1.)
- _Mutant 2, clamp reads raw stamps (row 10)._ The same trace. The cap makes the segment's `eff` 1, but the
  clamp reads its raw stamp 3, so device 2's run still starts at `o = 3`. Its **ordering** stamp is still
  bounded (row 7 passes: `eff` never exceeds the registry time), but its raw stamp is dragged.
- _Mutant 3, local finality (row 11)._ Two concurrent runs. Device 1 (fast) applies its own segment with
  finality from its own clock (3); device 2 applies the same segment with its own clock (1). After both
  segments are applied the two devices pick different winners for the key.
- _`ownRaw` (row 12)._ The same shape: the author keeps its own raw stamp 3 while the other device caps it
  to 1. The two devices pick different winners. So the author must restamp its own rows to `eff` when the
  registry acknowledges the segment.
- _`tieFinality` (row 13)._ Device 1 publishes a delete at `t = 2` with `F = 2`. Its next run begins at
  `t = 2`, holds `eff = 2`, and publishes at the same tick with `F = 2`: `eff` ties, the new run id is
  smaller, and the new write loses to the delete it followed. The registry must give a strictly larger
  finality to each later segment.
- _`noClamp` (row 14)._ Device 1 publishes at `t = 1` (`eff = 1`). Device 2 applies it, begins at `t = 1`
  with clock 1 and a smaller run id, and publishes at `t = 2`: `eff = 1` again, tie, it loses. The cap alone
  does not replace the lower clamp.
- _`midDelete` (row 15)._ A run publishes a delete at `t = 1` (`eff = 1`) and an upsert of the same key at
  `t = 2` (`eff = 2`). By raw stamp the delete wins the tie; by `eff` the later upsert wins. The cap needs
  "a delete is a run's last segment". The code has that rule today; it must stay.
- _Concurrent flip (rows 16, 17)._ Device 1 and device 2 begin runs at `t = 2` without seeing each other:
  `o = 4` (fast) and `o = 2`. The fast run is final at `t = 2` (`eff = 2`), the slow one at `t = 3`
  (`eff = 2`). By raw stamp the fast run wins; under the cap they tie and the larger run id (the slow run)
  wins. Row 17 shows the same on a history written by the built clamp.
- _Raw order not causal under the cap (row 18)._ Device 1 deletes key 1 in run 2 (`o = 3`, `F = 1`).
  Run 1 begins after applying that delete and writes the key (`o = 3`, `F = 2`). The clamp reads `eff = 1`,
  so run 1 keeps its clock, 3, which ties the delete's raw stamp; run id 1 is below 2, so by **raw** stamp the
  delete is above the later write. By `eff` the later write wins, as it should.

### Answers in plain words

**What bound does the model prove for (d)?** For every run, in the checked bounds:
`o <= max(own clock reading at begin, registry time at begin + 1)`. Another device's skew does not enter
it. The `+ 1` is the lower clamp's tie rule (a run whose id sorts before the held run id starts one above).
Also, no stamp a device orders by is above the registry time at that moment (`DragEff`). Checked at skews
2/0 and 3/1 with registry time up to 4, and at skew 2/0 with registry time up to 5 (rows 1 to 3) and with 4 runs
(row 4).
Without the cap (row 8) the slow device's run starts at 3 when the registry time is 1.

**Does capping ever reorder two writes that were already ordered on every device?**

- _Causal pairs, no._ If the later run began after its device applied the earlier write, the cap never puts
  it below, in the proposal (row 1) and on a history written by the built clamp and read under the cap
  (row 6). That holds because each later finality is strictly larger and the clamp keeps `o` above
  the held `eff`.
- _Concurrent pairs, yes._ Neither run saw the other, and the fast run's raw stamp is above its finality.
  The order every device computed by raw stamp can flip (rows 16, 17). The trace shows a flip decided
  by the run-id tie-break; TLC stops at the shortest trace and does not show whether a larger gap also flips.
  Every device that applies the cap flips together, so devices still agree with each other. A value a user
  saw win can change.
- _One more direction (row 18)._ Under the cap, the raw stamps of causal pairs are not always in causal order
  any more. The cap makes `eff` right and raw wrong. Anything that still orders by raw stamps (a device
  without the cap, a rollback of the cap, a reader of the stored stamp) can mis-order such a pair.
  The cap cannot be switched off again after it has been on.

**What happens to a run that is still collecting when its segment's finality is earlier than its raw stamp?**
Each segment is capped by its own finality. Finality is strictly larger for each later segment, so a run's
`eff` values never go down in publish order: ordinals and "a delete is last" keep working
(`SameRunOrder`, `DeleteWinsTie`, rows 1 to 4; row 4 has one segment per run, so it adds nothing for this point). The run's early segments rank by their publish time, not its
start stamp. A concurrent write can therefore win over an early segment and still lose to a later one of the
same run. Its own rows, before the registry acknowledges them, still carry the raw stamp: the author must
replace them with `eff` at the acknowledgement, or devices diverge (row 12).

**Does the lower clamp have to read `eff`, not raw stamps?** For (a), (b), (c) and `DragEff`: no. A clamp
that reads raw stamps keeps all of them (rows 6, 7). For (d) as stated, the raw start of a run on a
slower device: yes. With a raw-reading clamp the slow device's raw starts still inherit the fast device's
skew (row 10); the cap hides it from the order but not from the stored stamp. A clamp that does not
exist (row 14) is not enough: the cap alone loses ties.

### What this does not establish

- The bounds above: 3 runs and 6 segments at `MaxT = 4`, and rows 3 and 4. Registry time 6 with 4 runs (row 4b) did not finish. An intermediate run
  (`MaxT = 5`, 4 runs) ended without a result at about 21 million states, probably on host memory; it is not
  recorded as evidence and its config is not kept. Clones,
  more than two devices, more than two keys, runs overlapping on one device and longer times are not checked.
- That the code does what the model assumes. The model assumes (1) one registry clock with a strictly larger
  value for each later segment; (2) every device computes `eff` from the registry's value, including the author
  for its own rows; (3) every place that stores a stamp the clamp reads (rows, tombstones, the compaction
  watermark, stream floors, the SEEN stamp) stores `eff`, not the raw stamp. Rows 11, 12 and 13 show what
  breaks without (1) and (2). Nothing here checks (3); a watermark or floor written from a raw stamp is a
  place where a fast clock can still lift every later stamp.
- A mixed rollout. Devices with and without the cap disagree on the order (row 18, row 11 by analogy),
  so the cap needs the same lockstep as the other order changes. Not modelled.
- Equal-stamp order between clones of one run (they now differ by finality, not by ordinal and body when the
  finality is below the stamp). Not modelled.
- Existing models are not re-run; this change touches none of them.

## Source clock (an alternative to the cap; checked before it is built; 2026-11-21)

`SourceClock.tla` checks design D, an alternative to the cap above. It is a new module that reuses the shape of
`FinalityCap.tla`. It changes no existing module or config. The cap fixes fast clocks where records are
_ordered_. D fixes them where records are _stamped_.

**Design D.**

1. A device keeps `off = registry time - device clock`, measured at its last contact with the registry
   (an append, a refused append, or reading a log position). A run takes its start stamp from the device clock
   plus that offset. Then the built lower clamp (`clampRunStart`) raises it above the newest held stamp.
   The device clock can still jump ahead after the last contact, so the corrected stamp can be ahead.
2. The registry **refuses** an append whose run stamp is greater than the registry time at acceptance. There is
   no fixed margin. A refused append changes nothing in the log.
3. On refusal the device measures the offset again. The run takes a new stamp (offset, then the clamp over
   everything the device holds now), and its causal snapshot becomes the whole log the device holds now. Only
   a run's first append can be refused: a later append comes at a later registry time than the accepted stamp.
4. A stored stamp is never rewritten. Every device orders by the raw stored stamp, as it does today.
   There is no `eff` and no finality.

**Model SHA-256** (`SourceClock.tla`): `8fd782067d414e8b135545777e4c66eedd95bfa1a6897a0124f91e8f0cbebd6e`.
Base tree: `origin/feat/finality-cap-model` at `1aa0fe92`. TLC 2.19 (tools 1.7.4), Java 17, `-workers 2`,
`nice -n 19 ionice -c3`, run on a host at load 20 to 50. Command, from this directory, for every config `X`:

```
nice -n 19 ionice -c3 timeout 2400 java -XX:+UseParallelGC -Xmx4g -cp tla2tools.jar tlc2.TLC -workers 2 -config X.cfg SourceClock
```

### What the model contains

- Two devices, two keys, one log, one run open per device, as in the cap model. Device clock = registry time +
  fixed skew (`SkewA`, `SkewB`) + `jmp`. A clock may jump ahead in steps of one, at most `MaxJump` (= 1) in
  total per device, at any time. A device starts with offset 0 (never measured) or the exact offset.
- Contact measures the offset exactly and at once: a successful append, a refused append, and applying a log
  position. A run's stamp is taken once, at its begin or at a retry. A later clock jump does not change it.
- `Publish` is the registry accepting the first or a later append (the device holds the whole log, the stamp is
  not above the registry time). `Refuse` is the registry refusing the first append, plus the retry.
- `OnePerTick = TRUE` allows at most one append per registry tick. **This is not part of D.** It is the bound
  the cap model uses (one registry clock value per segment). It is a size bound: without it the space is too
  large for TLC at the cap's bounds (see "Results"). `OnePerTick = FALSE` allows several appends at one
  registry time.
- `Flip = "off"` starts with D on and switches it off once. `Flip = "on"` starts with D off and switches it
  on once. While D is off, a device stamps with its raw clock (no offset) and the registry does not refuse.

**Not modelled:** a clock that steps backwards or runs slow; the delay between the registry's reading and the
device's use of it; more than two devices or keys; clones; crashes; the compaction watermark and stream floors
(the held-stamp maximum stands for them, as in the cap model, **only if every stored stamp is the stored raw
stamp**, which D guarantees by never rewriting it); the SEEN stamp; omissions; the author's own pending rows
before the registry accepts them; a mixed rollout of devices with and without D.

### Invariants

Names that also appear in the cap model keep their meaning. `Rk` is the rank each device uses; in D it is the
rank of the raw stored stamp. `RawRk` is the rank of the stamp the author took.

| Name                                   | Meaning                                                                                                                                                         |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Converged`, `BeginAfterWins`          | As in the cap model. `snap` is reset at a retry, so a retried run must also rank above everything the device held at the retry.                                  |
| `SameRunOrder`, `DeleteWinsTie`, `SeedLoses` | As in the cap model.                                                                                                                                      |
| `DragAccepted`                         | No stamp accepted while D is on is above the registry time at its acceptance.                                                                                    |
| `DragEff`                              | No stamp a device orders by is above the registry time now. Same name and meaning as in the cap model.                                                           |
| `RetryBound`                           | A retried run's new stamp is at most one above the registry time of the retry, whatever the skew.                                                                |
| `RetryAccepts`                         | One tick after a retry, the run's first append is not refused (if its device holds the whole log). The enabledness half of "eventually accepted".               |
| `CausalNoFlip`, `RawCausalMonotone`    | As in the cap model: for a causal pair, the order the devices use never puts the later write below, and the raw stamps have it above.                           |
| `ConcurrentNoFlip` (new for D)         | For two writes where neither run began after applying the other, the order by the author's stamp equals the order every device uses.                            |
| `ReaderAgrees` (new)                   | For every pair of one key, a reader that orders by the raw stored stamp agrees with the protocol's order. This is switch-off safety.                             |
| `WinnerOnlyRises` (new, a step property) | A winner a device has applied only ever changes to a higher-ranked segment.                                                                                    |

### Results

Counts are TLC "states generated / distinct". A failing run stops at the first violation; its counts and depth
depend on worker order and are not a measure of the space. All configs have skew 2/0 unless the row says
otherwise, and `MaxJump = 1`. "Full" means the cap model's shape: `MaxT = 4`, device 1 up to 2 runs, device 2
1 run, `MaxSegs = 2`.

| #   | Config                    | Mode / shape                                                          | Invariants                                                | Result                                                                                                         | States                    | Depth |
| --- | ------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------- | ----- |
| 1   | `SourceClockGoodOneSeg`   | D, `OnePerTick`, 2 + 1 runs, `MaxSegs = 1`, `MaxT = 4`                 | all of the table above + `WinnerOnlyRises`                | **PASS** (15 min)                                                                                              | 8,296,248 / 4,185,796     | 15    |
| 2   | `SourceClockGood`         | D, `OnePerTick`, **full**                                             | as row 1                                                  | **NOT COMPLETE**: stopped at the 40-minute limit, no violation seen, 4.06 million states still queued. Not a PASS. | 22,039,437 / 10,910,024 (when stopped) | 14 (when stopped) |
| 3   | `SourceClockGoodSkew31`   | as row 1, skew 3/1                                                    | as row 1                                                  | **PASS** (14 min)                                                                                                       | 9,733,264 / 4,669,316                 | 15 |
| 4   | `SourceClockOffSafe`      | D switched off once; `OnePerTick`, 2 + 1 runs, `MaxSegs = 1`, `MaxT = 3` | `TypeOK`, a, b, c, both no-flips, `ReaderAgrees`, `RawCausalMonotone`, `DragAccepted` | **PASS** (17 min)                                          | 10,734,495 / 5,684,070    | 15    |
| 5   | `SourceClockOnSafe`       | D switched on once from a log written without it; same shape as row 4 | as row 4                                                  | **PASS** (12 min). The order-level checks hold across the switch-on; row 6 shows the progress cost.                                                                                                       | 7,245,013 / 3,435,330                 | 15 |
| 6   | `SourceClockOnRetry`      | D switched on once; full shape, no `OnePerTick`                       | `RetryAccepts`                                            | **FAIL** (a finding, not a mutant)                                                                             | 183,621 / 88,754          | 7     |
| 7   | `SourceClockOffDragEff`   | D switched off once                                                   | `DragEff`                                                 | **FAIL** (expected: after switch-off a device may stamp ahead again)                                           | 744 / 459                 | 4     |
| 8   | `SourceClockNoRefuse`     | `noRefuse`                                                            | `DragAccepted`                                            | **FAIL** (mutant)                                                                                              | 134 / 104                 | 3     |
| 9   | `SourceClockNoRefuseEff`  | `noRefuse`                                                            | `DragEff`                                                 | **FAIL** (mutant)                                                                                              | 95 / 81                   | 3     |
| 10  | `SourceClockNoRemeasure`  | `noRemeasure`                                                         | `RetryAccepts`                                            | **FAIL** (mutant)                                                                                              | 1,426 / 827               | 5     |
| 11  | `SourceClockNoOffset`     | `noOffset`                                                            | `RetryAccepts`                                            | **FAIL** (mutant)                                                                                              | 765 / 459                 | 4     |
| 12  | `SourceClockDevTime`      | `devTime`                                                             | `DragAccepted`                                            | **FAIL** (mutant)                                                                                              | 115 / 92                  | 3     |
| 13  | `SourceClockSlack`        | `slack`                                                               | `DragAccepted`                                            | **FAIL** (extra)                                                                                               | 419 / 277                 | 4     |
| 14  | `SourceClockNoClamp`      | `noClamp`                                                             | `BeginAfterWins`                                          | **FAIL** (extra)                                                                                               | 6,507 / 3,365             | 5     |
| 15  | `SourceClockRetakeNoClamp`| `retakeNoClamp`                                                       | `BeginAfterWins`                                          | **FAIL** (extra)                                                                                               | 30,651 / 15,178           | 6     |
| 16  | `SourceClockCapOrderFlip` | `capOrder`: the cap in this module                                    | `ConcurrentNoFlip`                                        | **FAIL** (control: the cap's finding, reproduced here)                                                         | 50,710 / 31,650           | 7     |
| 17  | `SourceClockCapOrderReader` | `capOrder`                                                          | `ReaderAgrees`                                            | **FAIL** (control)                                                                                             | 18,198 / 11,343           | 6     |

Not run: `MaxT = 5` (row 2 does not complete at `MaxT = 4`). Also run and stopped, so **not evidence**: the
same shapes without `OnePerTick`. 2 + 1 runs, `MaxSegs = 1`: stopped at 5.6 million distinct states, depth 13,
no violation. 1 + 1 runs, `MaxSegs = 2`: stopped at 4.4 million distinct states, depth 13, no violation. The
space without `OnePerTick` is larger because several appends can share one registry time.

**Property by design** (cap: rows of the cap results table above; D: rows of this table). "n/a" means the
property has no meaning in that design.

| Property                                              | Cap                                                    | D                                                                                    |
| ----------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| Convergence (a)                                       | PASS (row 1)                                           | PASS (rows 1, 4, 5)                                                                  |
| Begin-after-wins (b)                                  | PASS (row 1)                                           | PASS (rows 1, 4, 5); fails without the clamp or without it on retry (rows 14, 15)    |
| Equal-stamp order (c)                                 | PASS (row 1)                                           | PASS (rows 1, 4, 5)                                                                  |
| Causal no-flip                                        | PASS (row 1)                                           | PASS (rows 1, 4, 5)                                                                  |
| Drag: a stored stamp is at most the registry time at its acceptance | n/a: the stored stamp is not bounded; only `eff` is | PASS (`DragAccepted`, rows 1, 4, 5); fails without refusal (row 8), with a fixed margin (row 13), or comparing with device time (row 12) |
| Drag: a stamp a device orders by is at most the registry time now | PASS (`DragEff`, row 1)                | PASS (`DragEff`, rows 1, 3); fails without refusal (row 9)                           |
| Slow device not dragged by the fast one (`DragSlow`)  | PASS (row 1)                                           | Implied by `DragAccepted`: every accepted stamp is at most the registry time        |
| **Concurrent no-flip**                                | **FAIL** (row 16)                                      | PASS (rows 1, 4, 5); the cap in this module fails it too (row 16 of this table)        |
| **Switch-off safety** (raw order agrees)              | **FAIL** (`RawCausalMonotone`, row 18)                 | PASS (`ReaderAgrees` and `RawCausalMonotone`, row 4)                                 |
| Winner only changes to a higher rank                  | Not run (the cap's order is also fixed per segment)    | PASS (`WinnerOnlyRises`, rows 1, 4, 5)                                               |
| Progress under refusal                                | n/a: the cap never refuses an append                   | PASS (`RetryBound`, `RetryAccepts`, rows 1, 3); fails without re-measure or offset (rows 10, 11) |
| Switch D **on** over a log written without it         | Not checked                                            | Order checks PASS (row 5). Progress **FAIL** (row 6): writers wait until the registry time passes the highest held stamp                                                                              |

How to read the D column. `Converged`, `ReaderAgrees` and `ConcurrentNoFlip` are close to true by construction:
D orders by one stored number that nothing rewrites. They pass, and the `capOrder` control fails them, so the
checks can fail. The checks with content are `BeginAfterWins` (the clamp and the retry), the two drag bounds,
and the retry invariants. Each mutant in rows 8 to 15 fails the property it targets.

**Counterexamples, in plain words** (`t` is registry time; `o` is a run's stamp):

- _`noRefuse` (rows 8, 9) and `devTime` (row 12)._ Device 1 (skew 2) has never measured its offset. It begins a
  run at `t = 1`: `o = 3`. The registry accepts it at `t = 1`. A stamp 2 above the registry time is stored. With
  `devTime` the registry compares 3 with the device's own clock (3), so it accepts. The drag bound is the
  refusal against the **registry's** time.
- _`slack` (row 13)._ Device 1 starts with the exact offset, then its clock jumps ahead by 1. It begins at
  `t = 1` with `o = 2`. A margin of 1 accepts it. The stored stamp is 1 above the registry time. Any fixed
  margin lets that much drag in. The bound needs `stamp <= registry time`.
- _`noRemeasure` (row 10)._ The same first run is refused at `t = 1`. The retry uses the old offset 0, so
  `o = 3` again. One tick later (`t = 2`) it is still above the registry time. Each retry at time `t` takes
  `t + 2`, so the run is never accepted while the skew lasts.
- _`noOffset` (row 11)._ The device measures the offset but never applies it. Same result: a run with a fast
  clock is refused at every `t`. Refusal without the offset is a lock-out, not a fix.
- _`noClamp` (row 14)._ Run 2 publishes at `t = 1` with `o = 1`. Run 1 begins after applying it, with `o = 1`,
  and the smaller run id loses the tie. The offset does not replace the lower clamp.
- _`retakeNoClamp` (row 15)._ Run 2 publishes at `t = 1` with `o = 1`. Run 1 begins after applying it; the tie
  rule of the clamp gives `o = 2`, one above the registry time, so the registry refuses. The retry takes the
  clock reading, `o = 1`, with no clamp. It is accepted and ranks below run 2, which it followed. The retry
  must clamp again.
- _Switch D on over old history (rows 5, 6)._ D is off. A fast device publishes a run with `o = 3` at `t = 1`.
  D is switched on. The next run on that device clamps above the held stamp 3, is refused (`3 > 1`), and the
  retry again clamps to 3. At `t = 2` it is still refused. The run waits until the registry time reaches 3.
  That is the lower clamp and the refusal pulling against each other. `RetryAccepts` fails (row 6).
- _`capOrder` control (rows 16, 17)._ The cap's concurrent flip: device 1 (`o = 3`, finality 1) and device 2
  (`o = 1`, finality 2) have equal `eff`. The larger run id wins; by stamp the other run wins. Under D, rank is
  the stored stamp and nothing changes it, so there is no pair to flip.

### Answers in plain words

**Does D fail anything the cap passes?** Not an invariant that the cap model also states: in the checked
bounds D passes everything the cap passes, and the two the cap fails (concurrent no-flip, switch-off). D
costs something the cap does not:

- **Availability.** The registry can refuse an append. The refused run retries, and it is accepted one registry
  tick later at the latest (`RetryBound`, `RetryAccepts`). A refusal needs no skew: the lower clamp's tie rule
  can produce a stamp one above the registry time (row 15 shows it with exact clocks). The cap never refuses.
- **Switch-on over history that already has stamps above the registry time** (rows 5 and 6). Row 6 fails: a
  run waits until the registry time catches up with the highest held stamp. The cap on a log with raw stamps
  was not checked. D must be switched on from a log in which no stamp is above the registry time, or those
  writers wait.
- **A refusal path for old clients.** Not modelled (mixed rollout): an old device does not retry with a new
  offset.

**Progress, and the fairness it needs.** A run whose device holds the whole log gets its first append accepted
one registry tick after its last retry (`RetryBound`: the retried stamp is at most `registry time + 1`;
`RetryAccepts`: one tick later the registry would accept it). The retried stamp does not depend on the skew,
because the device just measured it: stamp = clock + (registry time - clock) = registry time, then at most
+1 from the clamp's tie rule. So the claim needs no bound on skew. It needs: (1) registry time advances;
(2) the device attempts the append when it holds the whole log. This is the compare-and-swap condition and is
independent of clocks: if other writers keep appending between the device's read and its append, the append
can fail for that reason forever, with or without D; (3) the offset measured at a refusal is exact, or low (a
device that takes the registry's reading against its clock at the moment of _receipt_ errs low, so its stamp
is not ahead; this is reasoning, not checked). I could not check liveness in TLC: with a clock bounded by `MaxT`, TLC's fairness check passed
for the mutants too (every stuck behaviour ends at the time bound and is dropped as unfair). So progress is
stated and checked as the two bounded invariants above, which the two mutants break.

**Does the offset replace the clamp?** No (rows 14, 15). Does refusal replace the offset? No (row 11): refusal
alone locks out a device that is ahead. Does the offset replace refusal? No (rows 8, 12, 13): a clock that
jumps ahead after the last contact still produces a stamp above the registry time. Each of the three rules does
one job.

**Can D be switched off?** Yes, from a state in which D wrote the log (rows 1, 4). The stored stamps are the
raw ones, and the built clamp keeps causal order over them (`RawCausalMonotone`, `ReaderAgrees`). After
switch-off a fast device can drag again (row 7). That is the old behaviour, not new damage.

### What D does not cover

- **A clock that jumps while the device is offline.** The jump itself is modelled (a jump of 1, after the last
  contact, before the run begins). The registry's refusal catches the stamp when the device comes back. Not
  modelled: what the device shows locally in the meantime. If the author's own read model applies a run's rows
  with the unaccepted stamp, a refusal and a new stamp re-rank them. The author may see a write win and then
  lose. The model assumes no one, including the author, applies the rows of a refused append. Also not checked:
  jumps larger than 1, and two runs queued on one device while offline.
- **A clock that steps back or runs slow.** The stamp is then below the registry time. That is safe for
  ordering (the clamp still holds the causal order) but the device's concurrent writes lose to others more often.
- **A mixed rollout.** Devices with and without D, and a registry that refuses only some of them. An old
  fast device is refused with no retry, or accepted and drags. Needs the same lockstep as the cap.
- **More than two devices or keys.** Nothing in D couples devices except the clamp over held stamps, but this
  was not checked.
- **Clones** (two writers with one run id) and **runs that overlap on one device**.
- **Delay in measuring the offset.** The model measures at one instant. In practice the error is half a round
  trip at most; the refusal is exact, so the error costs a retry, not safety. Take the registry's reading
  against the device clock at receipt, so the error is low.
- **The bounds.** Row 2 (the cap model's full shape) did not complete. The passes use fewer runs or one segment
  per run, and 3 runs at most. `MaxT = 5` and `MaxJump >= 2` were not run. The code is not checked against the
  model: the model assumes (1) the registry's time is one clock, never behind an accepted stamp; (2) every
  stored stamp the clamp reads (rows, tombstones, watermark, floors, SEEN) is the stored raw stamp; (3) the
  offset is applied at begin and at every retry.

## History: initial design exploration

The following opening and source mapping describe the initial authored model,
before the recorded host runs and later protocol changes. “Not run” and
“future protocol” here are historical status, not the current evidence summary.

Source pin: `1ca1a110d9304adc4dab709c78cf770584a895fa`.
Status: authored and statically reviewed; **TLC has not been run**. Expected
outcomes below are predictions, not verification evidence. No production code
changes. This models the requested future protocol, not a claim that this pin
already implements immutable operation segments.

### Source mapping and explicit boundaries

- `packages/core/src/localdb/merge.ts`: `mergeIncoming` compares effective
  SEEN observation pairs, preserves later local sightings, and can promote a
  sighting when a remote different body loses. `replaceDelete` removes only
  pairs strictly below the cutoff. `deleteRunRecords` gives explicit deletes
  their run stamp and records tombstones even for missing keys. The model treats
  promoted effective observations as already emitted operations. It does not
  confuse immutable content stamps with local SEEN stamps.
- Two bodies of one key at one stamp are admitted: a collection run that
  publishes while it collects can emit a key again in a later intake batch.
  The model no longer assumes they agree (the old `Admissible` assumption is
  removed). The order that settles them is in "Equal-stamp order" below.
- `localdb/replace.ts#decideReplace` requires declared full inventory,
  mutable state, successful covered/proven full streams; `replaceMayApply`
  requires the recorded basis. Model omission operations assume those admission
  checks succeeded. They name a specific absent key, not a whole-stream wipe.
- `localdb/apply.ts#control` refuses stale active generations after a known
  deletion; generation changes purge/reset stream state. The head-generation
  guards and final control recheck reject old-lifetime content.
  `publish.ts#commitBatchTurn` uses connection control and per-stream CAS
  conditions in one batch request, but supports unbatched fallback and
  per-row conflict outcomes. The proposed single immutable segment and global
  connection position are **new design**, not inferred current CAS semantics.
- `replication/envelope.ts` declares upsert/delete, connection register/reset/
  delete and stream-complete/invalidate. Its completion carries proof,
  dependencies and digest, **not the proposed omission list**.
  `completion.ts` checks unique digest-bound dependencies and selects
  completion by revisions. `visibility-engine.ts#completionAvailability`
  additionally requires matching live count/digest and eligible evidence.
  Those facts are assumed established before emitting a proposed omission.
- `replication/stream.ts` validates per-writer sequence/previous and fragment
  bindings; that is not the model's connection-wide log position.
  `revision.ts#compareRevisions` orders counter, original writer/operation,
  then own writer/operation; `nextLamportCounter` increments the observed
  maximum. The P6 witness has distinct counters, so omitted tie fields and
  rebaseline-origin fields cannot change that witness.
- P5 promises only a **known-lifetime fence**, consistent with apply/publish
  generation guards and profile visibility withdrawal on superseded generation.
  It does not promise instantaneous disappearance on an offline device, prevent
  legitimate recollection in a new lifetime, or model profile connection-delete
  (which is absorbing rather than reset). Local purge implementation and
  lifetime-boundary internals are outside this source selection.

### State and abstraction

Devices 1 and 2 are writers and replicas; device 3 only reads. Two keys stand
for two distinct streams. A batch is an ordered sequence applied atomically;
the first two batches each touch both streams. A fixed five-batch corpus keeps
the state space small while allowing every delivery/compaction/reset interleaving.
There is no local uncommitted overlay; writers' committed views synchronize by
the same reader actions. This is not exhaustive arbitrary-operation checking.

Encoded stamp `s=2*o+r`, with `r in {0,1}`, preserves lexicographic pair order.
An ordinary operation has rank `2*s`; omission cutoff has rank `2*s-1`.
Thus a live observation at or above cutoff survives and older ones lose.
Rank/body zero is absence; nonzero rank with body zero retains a tombstone.
Real explicit-delete/upsert equal-stamp conflicts are refused at admission.

`log` is immutable committed history and the reference oracle.
`retained` is the fetchable segment index set. Readers may fetch only indices
in it, except that `Install` obtains the compacted snapshot. The oracle retains
history only for assertions and snapshot construction, not reader fallback.
Compaction bound is derived as head minus one retained tail segment.
Snapshots replace a committed-prefix view; there is no uncommitted local overlay
to merge. The latest winner, including a tombstone, is preserved per key.

`MaxSteps=6` bounds commits plus reset, **not network transitions**. This is
intentional: cutting off all actions at depth six would invalidate liveness
claims about delivery after writers stop. The graph is finite without bounding
duplicate hints. One reset is possible; position resets to zero only when
adopting a newer epoch, so monotonicity means the pair (epoch, position).

### Actions

- Commit: writer of the next catalog batch appends one immutable segment and
  atomically advances the connection position; emits a hint.
- Stop: writers stop permanently; weak fairness guarantees eventual quiescence.
- Deliver / Drop: choose any hint. Deliver can repeat indefinitely and reorder
  old/new hints; max-known position never retreats. Stale epochs cannot roll
  back a device. Drop removes a hint without applying any content.
- FullCheck: authoritative head/lifetime read independent of hints; adopts a
  new lifetime by clearing old data/position.
- Apply: fetch one retained next segment and atomically apply its whole batch.
  No position n+1 before n in good mode.
- Compact: snapshot at the derived bound, remove only covered fetchable segments.
- Install: a reader behind the bound installs snapshot then applies the tail.
- Reset: new authoritative lifetime, empty log/snapshot; offline views are not
  magically rewritten. All old hints remain eligible for transport, not authority.
- SkipGap: mutant-only advancement of a checkpoint from a later hint.
- ApplyRun (`Mode` grouped, groupedSkip): the segments `position+1..q` apply in
  ONE transaction that writes position q with the last of them. It models the
  host's group commit of a first load, and equals q-position separate `Apply`
  steps with no committed state between them (each segment folds over the rows
  of the ones before it). The `groupedSkip` mutant leaves out the middle
  segments and must fail P5.
- KeyedLoad / KeyedBucket / KeyedPublish / StageLost (`Mode` keyed, keyedSkip,
  keyedEarly, keyedLeak, keyedBypass): a device with position 0 and no rows, over a log that
  has never compacted, folds the log key by key into a staging area
  (`KeyedLoad(d,k,q)`: key k's operations from segments 1..q), in any key order,
  any number of times. `KeyedBucket(d,k)` makes one key's staged fold durable
  in the live rows (`dur`) with no position: a bucket's commit. Durable rows
  carry the target they were written for (`durAt`, in the epoch `durEp`; it is
  the `log_keyed_pending` row in the code). `PendingAdmits(d,q)` is the rule:
  a load may fold, make durable or publish a target q only if no durable rows
  exist, or they are of this epoch and q is not shorter than their target.
  `KeyedPublish(d,q)` writes the rows (durable rows merged with the staging
  area) and the position q in ONE transaction, only when every key is folded to
  q, and clears the durable rows and the target. `StageLost` drops the staging
  area (a crash, or the next start) and leaves the durable rows. Reset,
  Rollback and FullCheck clear the staging area; a rollback of the epoch makes
  the durable rows foreign, so `PendingAdmits` refuses them. The `keyedSkip`
  mutant leaves a key's fold without the segment before its last (a stage that
  lost rows) and must fail P1. The `keyedEarly` mutant publishes while a key is
  not yet folded and must fail P5. The `keyedLeak` mutant is the earlier rule,
  with no `PendingAdmits`: a retry that can fold only a shorter prefix publishes
  over durable rows of a longer one, and must fail P5.
  Durable rows are also a state of the device, so every other way the device
  moves its position is gated on `NoPending(d)` (no durable rows): Install,
  Apply, SkipGap, ApplyRun and a lifetime change (FullCheck). A device that
  holds durable rows may only finish them by `KeyedPublish` (`LiveRows(d)` is
  what the rows of such a device are: the durable rows merged over its data).
  `KeyedPage(d,k,j)` makes a key's fold durable in slices of its operations,
  `j` at a time, in any order and any number of times (a key whose history is
  over the budget). The `keyedBypass` mutant drops the `NoPending` gate, so the
  position may move past durable rows by another action, and must fail P5.
- Rebaseline (`Mode` keyedRebase, keyedStuck): a device that holds durable rows
  (`durAt[d] # 0`) of a log that is now of another lifetime (`durEp[d] # epoch`) or
  compacted (`cut > 0`) can never finish them: `PendingAdmits` and `KeyedGate` refuse
  every load and `NoPending` refuses every other move. `Unfinishable(d)` names that
  case and `Rebaseline(d)` ends it in one step: durable rows, pending target and
  stage go together, the position stays 0, and the device starts again from the log
  as it is. A log that is only shorter and agrees (`Len(log) < durAt[d]`) is not
  `Unfinishable`: it stays refused, rows kept. The `keyedStuck` mutant has no
  `Rebaseline` and must violate `LiveWhenCrashesEnd`. Both modes use one device and
  `AllowReset`. What the device wrote itself and has not published is not in this
  model: the code keeps it, and its tests state that (`log-keyed-first-load.test.ts`,
  "keeps the writes the device has not published").

### Properties and expected host results

| Configuration             | Expected result                     | Target                                                                                                        |
| ------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Good.cfg                  | PASS within this finite abstraction | TypeOK, P1–P5; eventual convergence                                                                           |
| LostPush.cfg              | PASS, even with no Deliver action   | P2 full-check recovery and eventual convergence                                                               |
| DropGap.cfg               | FAIL P2                             | skipped missing predecessors                                                                                  |
| OutOfOrder.cfg            | FAIL P2                             | later segment applied first                                                                                   |
| DroppedDeleteEffect.cfg   | FAIL P1 after snapshot+tail         | snapshot built without delete operations                                                                      |
| ForgetTombstone.cfg       | FAIL P1 via replay                  | correct delete, then snapshot forgets its tombstone; a later replayed upsert resurrects the key               |
| OmissionWithoutCutoff.cfg | FAIL P3                             | newer observed row erased by old omission                                                                     |
| OmissionInclusive.cfg     | FAIL P3                             | omission at equal stamp erases an observation AT the cutoff (`<=` boundary)                                   |
| LamportDifference.cfg     | FAIL StampEqualsLamport             | P6 orders choose different winners                                                                            |
| Grouped.cfg               | PASS within this finite abstraction | group commit (`ApplyRun`): TypeOK, P1–P5, OrderOK                                                             |
| GroupedSkip.cfg           | FAIL P5                             | a group commit that leaves out the segments between its first and last                                        |
| Keyed.cfg                 | BOUNDED, no violation               | key-ordered first load (`KeyedLoad`, `KeyedBucket`, `KeyedPublish`, `StageLost`): TypeOK, P1–P5, OrderOK      |
| KeyedSkip.cfg             | FAIL P1                             | a key's fold that leaves out a segment                                                                        |
| KeyedEarly.cfg            | FAIL P5                             | the position written while a key is not yet folded                                                            |
| KeyedLeak.cfg             | FAIL P5                             | no `PendingAdmits`: a shorter retry publishes durable rows of a longer, stopped load                          |
| KeyedShort.cfg            | BOUNDED, no violation               | Keyed with `Len(log) <= 3`: TypeOK, P1–P5, OrderOK                                                            |
| KeyedBypass.cfg           | FAIL P5                             | no `NoPending` gate: another action moves the position past durable rows of an unfinished load                |
| KeyedLife.cfg             | BOUNDED, no violation               | Keyed with `AllowReset` and `Len(log) <= 3`: a lifetime change while durable rows exist                       |
| KeyedRebase.cfg           | PASS (complete)                     | `Rebaseline`: LiveWhenCrashesEnd (the connection eventually serves once crashes end), TypeOK, P1–P5, OrderOK  |
| KeyedStuck.cfg            | FAIL LiveWhenCrashesEnd             | no `Rebaseline`: durable rows of a reset or compacted log leave the device stopped with position 0            |
| Recommit.cfg              | PASS (complete)                     | `Recommit` after the registry loses one or two rows: EventuallyConverged, TypeOK, P1–P5, P7, OrderOK          |
| RecommitOther.cfg         | PASS (complete)                     | as Recommit, and another segment may replace a lost row: TypeOK, P1–P5, P7, OrderOK (no liveness claim)       |
| RecommitForeign.cfg       | FAIL P5                             | `Recommit` without the check that the registry's rows are the ones the device applied                         |
| NoRecommit.cfg            | FAIL EventuallyConverged            | no `Recommit`: a device ahead of a rolled-back registry never converges                                       |
| Rebase.cfg                | PASS (complete)                     | `Rebase` when another segment replaced a row the device applied: NoLoss, Faithful, TypeOK, P1–P5, P7, OrderOK |
| RebaseLive.cfg            | PASS (complete)                     | `Rebase` with one device (`rebaseLive`): EventuallyConverged                                                  |
| RebaseRows.cfg            | FAIL NoLoss                         | a rebase that queues only the keys the device holds a record of, not its deletes and omissions                |
| RebaseExplicit.cfg        | FAIL Faithful                       | a rebase that queues an omission as an explicit delete                                                        |

Corpus (batch 6): an equal-cutoff omission (key 1, stamp 5) meets the live
stamp-5 row, and an older omission (key 2, stamp 1) sits below the live delete.
Good requires the correct boundary: omission rejects `<`, so an observation AT
the cutoff wins. Traces of each failing mutant are in `traces/`.

P1 compares every caught-up replica with greatest-stamp reference state, not
just replicas with each other. P2 records actual step-order and lexicographic
position checks. P3 records an omission's before/after safety obligation.
P4 compares every compacted snapshot with its exact reference prefix.
P5 compares each current-lifetime device prefix with that lifetime's oracle;
this is stronger than merely checking an epoch tag on stale content.
`EventuallyConverged` uses weak fairness for Stop and each device's FullCheck
and Recover. Storage reads succeed eventually; Byzantine storage, perpetual
outage and infinitely continuing writers are not silently proved live.

### Predicted counterexample recipes (not TLC output)

- Gap: Commit twice; FullCheck(3); SkipGap(3) advances 0 to 2 without records.
- Out-of-order: Commit twice; FullCheck(3); Apply(3,2) violates prefixOK.
- Tombstone: Commit three times; Compact to 2; reader at 0 FullCheck, Install,
  Apply tail 3. Dropped explicit delete lets key 2's older body 21 reappear.
- Cutoff: Commit through batch 4; reader applies 1,2,3,4 in order. Before
  completion, key 1 has stamp 5/body 13; cutoff 4 must not remove it. Mutant does.
- P6: Commit batch 1 then 2. Key 1 observation stamp 3/body 11 beats stamp 2/
  body 12; Lamport counter 2 instead beats counter 1. Greatest-stamp replicas
  still converge when all segments arrive. This is an order mismatch, not a
  demonstrated production bug or equivalence of the two protocols.

Each mutant changes a transition/reducer, not the invariant. The tombstone
mutant folds the compacted prefix with explicit delete operations removed,
retaining earlier live values; its config tests a reader-visible error rather
than failing immediately on the snapshot oracle.

### Host invocation and exclusions

From this directory, use the host's installed TLC, for example:
`java -cp /path/to/tla2tools.jar tlc2.TLC -workers 1 -config Good.cfg LogProtocol`.
Repeat for all seven configs; save actual traces/states/timing. Expected FAIL
configs are successful mutation detection only if the named invariant fails.
Parse failures, deadlocks, timeouts and unrelated failures do not count.
No tool download, TLC, syntax check or repository script was run by the worker.

Excluded: arbitrary stamp conflicts, profile equivocation/quarantine, hash/
signature verification, auth/declarations, crash durability, storage failures,
writer CAS retries, per-writer fragment reassembly, bulk schema/attachment
semantics, local SEEN promotion internals, operation-id tie cases, and physical
snapshot garbage collection. No refinement mapping to the current implementation
is claimed. Host validation remains necessary before relying on this model.

## TLC results (host run)

Run on 2026-11-15 with TLC 2.19 (`tla2tools.jar` 1.7.4, Java 17), `-workers 4`,
under `nice -n 19 ionice -c3`, one job at a time, foreground. Each config had its
own metadir, deleted after its run.

Spec change for this run: one lexical edit, line 108 of `LogProtocol.tla`,
`log'=<<>>` → `log' = <<>>`. In TLA+ ASCII, `=<` is the `≤` token, so `'=<<>>`
did not lex. A grep for `=<<` found no other hit. No other spec or config
change.

| Configuration             | Expected                | Actual                                                                                                                | Distinct states               | Depth | Wall time                             |
| ------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ----- | ------------------------------------- |
| Good.cfg                  | PASS                    | BOUNDED: stopped at 20.3M distinct, no invariant error in explored states; EventuallyConverged not checked            | at least 20,309,206 (partial) | n/a   | 47 min 51 s, stopped                  |
| LostPush.cfg              | PASS                    | BFS COMPLETE, no invariant error (23,019,334 distinct, 0 left on queue); temporal check cut at bound                  | 23,019,334                    | n/a   | 46 min 7 s, stopped in temporal check |
| DropGap.cfg               | FAIL P2                 | FAIL P2 as expected (`Invariant P2 is violated`)                                                                      | 130 at failure                | 6     | <1 s                                  |
| OutOfOrder.cfg            | FAIL P2                 | FAIL P2 as expected (`Invariant P2 is violated`)                                                                      | 131 at failure                | 6     | <1 s                                  |
| DroppedDeleteEffect.cfg   | FAIL P1                 | FAIL P1 as expected (`Invariant P1 is violated`)                                                                      | 2,509 at failure              | 8     | <1 s                                  |
| ForgetTombstone.cfg       | FAIL P1                 | FAIL P1 as expected; trace: Install, then replayed batch 5 resurrects key 2                                           | 16,135 at failure             | 10    | 2 s                                   |
| OmissionWithoutCutoff.cfg | FAIL P3                 | FAIL P3 as expected (`Invariant P3 is violated`)                                                                      | 7,842 at failure              | 9     | <1 s                                  |
| OmissionInclusive.cfg     | FAIL P3                 | FAIL P3 as expected; trace: stamp-5 omission erases the stamp-5 row                                                   | 45,443 at failure             | 11    | <1 s                                  |
| LamportDifference.cfg     | FAIL StampEqualsLamport | FAIL StampEqualsLamport as expected                                                                                   | 4 at failure                  | 3     | <1 s                                  |
| Grouped.cfg               | PASS                    | BFS COMPLETE, no invariant error (372,262,911 generated, 0 left on queue); no temporal property                       | 20,306,222                    | 24    | 22 min 29 s (2 workers)               |
| GroupedSkip.cfg           | FAIL P5                 | FAIL P5 as expected; trace: three commits, FullCheck, then a group that omits the segments between its first and last | 184 at failure                | 6     | <1 s                                  |

Good and LostPush hit the bound before TLC finished (20M distinct states or 45
min), so their PASS is not established. Good stopped with no invariant violation
in its explored states; LostPush finished the state space with no invariant
violation, and its liveness check did not finish. Earlier, under the 5-batch
corpus, both completed (6,160,198 distinct states, depth 31); the batch-6
corpus grew the space by roughly 3.7x (23.0M vs 6.16M).

For FAIL rows, the distinct-state count is what TLC had reached when it stopped
on the violation. It is not a full state-space size. Counterexample traces for
every failing mutant are in `traces/`. The `DroppedDeleteEffect` trace is the
old `DropTombstone` mutant, renamed.

These are the first TLC results for this model. They are a check of the finite
abstraction only, within the scope limits above. They do not show a refinement
to the implementation.

## Key-ordered first load (host run, 2026-11-16)

TLC 1.7.4 (`tla2tools.jar`, 2.19 engine), `-workers 4 -Xmx10g`, `nice -n 19`, one job at
a time, metadirs deleted after each run. Expected results were stated before the
run: `Keyed.cfg`, `KeyedShort.cfg` and `KeyedLife.cfg` hold; `KeyedSkip.cfg`
fails P1; `KeyedEarly.cfg`, `KeyedLeak.cfg` and `KeyedBypass.cfg` fail P5.

The first model of the keyed load had one crash outcome: the staging area is
lost. A bucket's commit also makes rows durable, with no stream version and no
position, so the model has `dur`, `durAt`, `durEp`, the `KeyedBucket` and
`KeyedPage` actions, the `PendingAdmits` rule and the `NoPending` gate on every
other way to move the position. Results below are for that model.

| Configuration   | Expected | Actual                                                                                                                                       | Distinct states     | Depth | Wall time       |
| --------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----- | --------------- |
| KeyedLeak.cfg   | FAIL P5  | FAIL P5 as expected: 3 commits, FullCheck, a bucket made durable for q=3, the staging area lost, a retry that folds only q=2 publishes       | see `traces/`       | 11    | 24 s            |
| KeyedBypass.cfg | FAIL P5  | FAIL P5 as expected: 2 commits, FullCheck, a bucket made durable, then another action moves the position past the durable rows               | 4,119 at failure    | 8     | 1 s             |
| KeyedSkip.cfg   | FAIL P1  | FAIL P1 as expected: a key's fold omits a segment, then the keyed publish installs rows that differ from the reference                       | 6,578 at failure    | 8     | 1 s             |
| KeyedEarly.cfg  | FAIL P5  | FAIL P5 as expected: the position is written while a key is not folded, so a device claims a prefix it does not hold                         | 598 at failure      | 7     | <1 s            |
| KeyedShort.cfg  | PASS     | BOUNDED: stopped at the 9 min limit; no invariant error in the explored states (132,349,328 generated, 5,418,158 left on queue)              | at least 11,740,986 | 17    | 9 min, stopped  |
| KeyedLife.cfg   | PASS     | BOUNDED: stopped at the 9 min limit; no invariant error in the explored states (152,565,182 generated, 7,529,445 left on queue)              | at least 14,425,007 | 16    | 9 min, stopped  |
| Keyed.cfg       | PASS     | BOUNDED, earlier model (before `KeyedPage` and the `NoPending` gate): stopped at the 10 min limit; no invariant error in the explored states | at least 25,583,041 | 14    | 10 min, stopped |

No passing run finished, so their PASS is not established: they are bounded
evidence, the same status as `Good.cfg`. `KeyedShort.cfg` restricts the log to
three segments (`ShortLog`), which holds the `KeyedLeak` scenario (a target of 3
and a retry of 2). `KeyedLife.cfg` adds `AllowReset`, so a lifetime change meets
durable rows. The `Keyed.cfg` row is from before the model had `KeyedPage` and
the `NoPending` gate and was not rerun to the same limit, so it is not evidence
for the current model. The failing runs stop at the first violation, so their
state counts are what TLC had reached, not a space size. Traces:
`traces/KeyedLeak.txt`, `traces/KeyedBypass.txt`, `traces/KeyedSkip.txt`,
`traces/KeyedEarly.txt`.

## Rebaseline of an unfinishable key-ordered load (host run, 2026-11-16)

Question. A key-ordered load that stopped leaves durable rows and a marker. If the
log then compacts or is rewritten, no key-ordered load can finish them, and (before
this change) the connection was refused for good. Does a rebaseline step restore the
liveness property "the connection eventually serves"?

Property. `EventuallyConverged` (`<>[](stopped /\ CaughtUp /\ P1)`) fails in any model in
which a crash drops the stage again before every step (`StageLost` forever: the first
run of `KeyedRebase.cfg` found that loop, a device that crashes in every attempt). So
the property checked is `LiveWhenCrashesEnd == <>[][no StageLost] => EventuallyConverged`:
the claim holds for runs in which crashes end.

TLC 1.7.4, `-workers 4 -Xmx4g`, `nice -n 19`, one job at a time (the long `Keyed.cfg`
run was paused with SIGSTOP while these ran and resumed after).

| Configuration   | Expected                | Actual                                                                                                                                                                                                         | Distinct states     | Depth | Wall time      |
| --------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----- | -------------- |
| KeyedStuck.cfg  | FAIL LiveWhenCrashesEnd | FAIL as expected: three commits, FullCheck, a key staged, a bucket made durable, then `Reset` (a new lifetime) and `Stop`; the device stutters with durable rows and no step enabled (`traces/KeyedStuck.txt`) | 24,485 at failure   | 9     | 3 s            |
| KeyedRebase.cfg | PASS                    | PASS, complete: "Model checking completed. No error has been found." 8,860,053 states generated, 0 left on queue                                                                                               | 1,093,310           | 24    | 6 min 24 s     |
| KeyedShort.cfg  | PASS (bounded)          | BOUNDED on the new model: stopped at the 9 min limit; no error in the explored states (about 166M states generated, 6.2M left on queue)                                                                        | at least 13,809,461 | 16    | 9 min, stopped |
| KeyedLife.cfg   | PASS (bounded)          | BOUNDED on the new model: stopped at the 9 min limit; no error in the explored states (about 186M states generated, 8.6M left on queue)                                                                        | at least 16,957,565 | 16    | 9 min, stopped |

`KeyedRebase.cfg` and `KeyedStuck.cfg` differ in one thing: `Mode`. Both use one
device, `AllowReset = TRUE`, `AllowRollback = FALSE`, `MaxSteps = 6` and the `NoPushSpec`
(no per-stream hints). `Rollback` is off because the code does not rebaseline a
registry that is behind the marker: it stays refused (`KeyedLeak` covers that
safety property). The complete run is complete for this finite abstraction only: one
device, two keys, at most six commits, resets and compactions, and it does not model
the rows a device wrote locally and has not published.

## A registry that lost log rows a device applied (host run, 2026-11-16)

Question. A registry restored from a backup is behind the devices: the log rows of
its newest positions are gone, and the segments they named are still in storage
(content-addressed, never deleted). Before this change the device that applied them
failed with `LogDivergedError` on every cycle. `log-recommit.ts` makes that device
commit the lost segments again, in order, each against the registry's head. Does
that restore convergence without breaking the fail-closed rule for a registry on
another history?

Model. `Rollback` in the four `RecommitModes` drops one or two rows and keeps at
least one; in `recommitOther` and `recommitForeign` another corpus batch may take the
first lost position (a writer that continued from the rolled-back registry). Epoch 2
here marks only that the registry's history moved under the devices. `applied[d]` is
the device's `log_state.refs` (a snapshot install keeps the registry's refs up to its
position). `FullCheck` keeps a device's rows when the log holds, at each position the
device applied, the segment it applied (`Explains`); otherwise the device takes no
step here (in the rebase modes it rebases: see the next section). `Recommit(d)` appends `applied[d][Len(log)+1]` when `applied[d]`
agrees with every row the log holds, and adopts the registry's history at its own
position. Mutants: `recommitForeign` drops the agreement check (the code's check of
the segment the registry names at its position); `noRecommit` has no `Recommit`.

TLC 1.7.4 (2.19 engine, Java 17), `-workers 4 -Xmx4g`, `nice -n 19`, one job at a
time. All four configurations: `Spec`, two devices, `MaxSteps = 6`,
`AllowReset = FALSE`, `AllowRollback = TRUE`.

| Configuration       | Expected                 | Actual                                                                                                                                                                        | Distinct states    | Depth | Wall time  |
| ------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ----- | ---------- |
| RecommitForeign.cfg | FAIL P5                  | FAIL P5 as expected: device 1 at position 3, `Rollback` replaces position 2 with another batch, `Recommit` puts its batch 3 over it and adopts (`traces/RecommitForeign.txt`) | 103,807 at failure | 10    | 2 s        |
| NoRecommit.cfg      | FAIL EventuallyConverged | FAIL as expected: both devices at 3, `Rollback`, `Stop`; both stutter on epoch 1 with no step enabled (`traces/NoRecommit.txt`)                                               | 665,456 at failure | 15    | 65 s       |
| RecommitOther.cfg   | PASS                     | PASS, complete: "Model checking completed. No error has been found." 108,505,589 states generated, 0 left on queue                                                            | 9,038,614          | 29    | 5 min      |
| Recommit.cfg        | PASS                     | PASS, complete, EventuallyConverged included: 30,932,669 states generated, 0 left on queue                                                                                    | 2,345,350          | 29    | 7 min 22 s |

Regression check of the extended model: DropGap, OutOfOrder (FAIL P2), ReplayFromBase,
GroupedSkip, ForgetTombstone, KeyedBypass (FAIL P5) and KeyedStuck (FAIL
LiveWhenCrashesEnd) fail as before, and KeyedRebase passes complete with the same
1,093,310 distinct states as before `applied` was added.

Limits. Two devices, two keys, at most six commits. Devices do not write in this model,
so a device that recommits is never also publishing new rows; the code's recommit runs
in the apply step, before the device's own publish. A registry that lost every row
(`Len(log) = 0`) is not modelled, and the code does not recommit it (`recommitApplied`
needs the row at the registry's position). A device whose refs do not cover each
position from the registry's to its own is refused in the code; in the model `applied`
always covers them.

## A registry on another history: the rebase (host run, 2026-11-16)

Question. A registry restored from a backup and then written by another device names
another segment at a position a device applied, or a registry rolled back below a
device's snapshot names none of its segments. `Recommit` cannot help: the log no longer
continues the device's history. Before this change the device failed with
`LogDivergedError` on every cycle. `log-rebase.ts` puts back what only the device's
history held as the device's own changes: it folds the segments it applied above the
fork (the last position both logs name the same segment), queues every key they touched
at what the device holds of it (a record, or the delete or omission that removed it,
also kept in `log_tombstones`), moves its position back to the fork, reads the
registry's log over its rows and publishes the queue. Does that converge every device
without losing the device's history or writing anything no writer wrote?

Model. `Rebase(d)` in the three `RebaseModes` is enabled for a device the log does not
explain (`~Explains(d)`) and that cannot recommit (`~CanRecommit(d)`). It is one atomic
step: it appends one batch `Seed(d)`, the winner in `applied[d]` of every key the
segments above `Fork(d)` touched, and the device adopts `FoldLog` of the new log. The
corpus (`RebaseBatches`) has a delete and an omission at stamp 3 that another writer's
batch at stamp 3 and an older upsert at stamp 2 can follow. The ghost variable
`rebasedOps` collects every operation a device applied before it rebased. Invariants:
`NoLoss` (each such operation is at or below its key's winner in the log's fold) and
`Faithful` (the log holds only corpus operations). Mutants: `rebaseRows` seeds only
the keys the device holds a record of; `rebaseExplicit` seeds an omission as an
explicit delete.

TLC 1.7.4 (2.19 engine, Java 17), `-workers 4 -Xmx4g`, `nice -n 19`, one job at a time.
All configurations: `Spec`, two devices, `MaxSteps = 6`, `AllowReset = FALSE`,
`AllowRollback = TRUE`, `KeepTail = 1`.

| Configuration      | Expected      | Actual                                                                                                                                                                                                                                               | Distinct states   | Depth | Wall time    |
| ------------------ | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ----- | ------------ |
| RebaseRows.cfg     | FAIL NoLoss   | FAIL NoLoss as expected: device 1 applies a delete of key 1 at stamp 3, `Rollback` replaces that position with another batch, `Rebase` queues no deletion, and key 1 is back at stamp 1 (`traces/RebaseRows.txt`)                                    | 25,171 at failure | 9     | 1 s          |
| RebaseExplicit.cfg | FAIL Faithful | FAIL Faithful as expected: `Rebase` queues the omission of key 2 as an explicit delete, an operation no writer made (`traces/RebaseExplicit.txt`)                                                                                                    | 53,348 at failure | 10    | 1 s          |
| Rebase.cfg         | PASS          | PASS, complete: "Model checking completed. No error has been found." 171,269,269 states generated, 0 left on queue                                                                                                                                   | 14,084,246        | 29    | 14 min 49 s  |
| RebaseLive.cfg     | PASS          | NOT COMPLETE: stopped at the 1 h limit with 233,437 distinct states and 50,911 on the queue; the 12 partial temporal checks (the last over 174,637 states) found no violation. TLC ran at under 1,000 states a minute under the host's IO contention |                   |       | 1 h, stopped |

The first `Rebase.cfg` run failed TypeOK at depth 16: two devices each rebased once and
the log reached seven positions, past `MaxSteps`. A seed is a commit the writers'
budget does not count, and each device rebases at most once (one rollback epoch), so
TypeOK now bounds positions by `LogBound`, `MaxSteps` plus one per device in the rebase
modes. `RebaseLive.cfg` checks EventuallyConverged with one device (`rebaseLive`), as the
other liveness runs do: a device's recovery does not depend on another device's. A two-device
liveness run would cover the 14 million states above with its behaviour graph on
disk; the host did not finish one.

Limits. The rebase is one step here; the code takes three (seed and reset in one
commit, then the apply, then the publish), and a crash between them leaves queued
changes that the next publish sends, which the model does not interleave. Devices do
not write new rows in this model. A fork of 0 rereads the device's whole snapshot, so
its cost grows with the data set. A key the rebase brings back after the registry's
history deleted it is not preceded by that delete in the queue; the merge by stamp
decides it, as for any write.

## #705 r3 extension (host run, 2026-11-15)

Scope: the model now represents the r3 rules of the log-segments PR (head
`664c5d10`, `packages/stream-sync/src/log.ts` and `packages/core/src/localdb/log-apply.ts`):

- Tombstone kinds rank omission < upsert < explicit delete at equal stamp.
  Mutant `dropKind` gives delete the upsert rank.
- Each row carries `first` (firstSeen): the smallest batch position at which an
  observation with the winning rank was applied. Equal-rank observations merge
  by minimum.
- Install merges the snapshot into the reader's existing rows (`MergeRow`),
  not a replacement. Lagging, fresh and uninterrupted readers are checked by
  P5 at every position, on body, stamp, rank and `first`.
- A registry rollback (`Rollback`, at most one, needs epoch 1 and leaves
  epoch 2) moves the head back one batch, or drops it, or replaces it with
  another corpus batch, and rebases the snapshot to Empty. Under Good, devices
  on the old lifetime fail closed through `FullCheck`. Mutant `replayFromBase`
  keeps the rows and position of such a device.
- Corpus batch 7: an upsert and an explicit delete at stamp 4 in one batch.
  `OrderOK` checks each batch folds the same forwards and backwards. Batch 7
  is reached only by Rollback's replacement path, since commits are capped by
  MaxSteps.
- P5 now fails on a device whose position is past the head, instead of
  comparing a prefix that does not exist.

Not represented: hintApplied (job 1 item c, not done), the transport and
generation fences of the real gateway, and firstSeen as a wall-clock value.

Expected results were written down before any run, in
a local `EXPECTED.md` (not committed), and are restated here.

| Configuration           | Invariant                                  | Expected                                                                     | Actual                                                                                                                    | Distinct states                                      | Depth | Wall time                       |
| ----------------------- | ------------------------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ----- | ------------------------------- |
| Good.cfg (r3 model)     | TypeOK P1–P5, OrderOK; EventuallyConverged | no violation; bounded, not PASS                                              | BOUNDED: stopped at 45 min (exit 124); no invariant error in explored states; liveness not finished                       | at least 31,812,556 distinct (343,151,617 generated) | n/a   | 45 min                          |
| DropKind.cfg            | OrderOK                                    | violated, depth 1                                                            | FAIL as expected (`The invariant of OrderOK is equal to FALSE`, reported before any step; the check is state-independent) | 1                                                    | 0     | 241 s, mostly queued for a slot |
| ReplayFromBase.cfg      | P5                                         | violated after Rollback + FullCheck, depth ~6–9                              | FAIL as expected at depth 8: device 1 at position 2 over a one-batch log is labelled current                              | 135,191 at failure                                   | 8     | 1 s                             |
| ForgetTombstone.cfg     | P1, P5                                     | P5 violated: a fresh device installs a snapshot missing the delete, depth ~6 | FAIL P5 at depth 7 (3 commits, Compact, FullCheck, Install); P1 not reached first                                         | 867 at failure                                       | 7     | <1 s                            |
| DroppedDeleteEffect.cfg | P1                                         | not predicted                                                                | FAIL P1 at depth 8                                                                                                        | 2,700 at failure                                     | 8     | <1 s                            |
| OmissionInclusive.cfg   | P3                                         | not predicted                                                                | FAIL P3 at depth 11                                                                                                       | 55,581 at failure                                    | 11    | <1 s                            |

Expected-versus-actual: every prediction matched. The DropKind failure is
reported as a constant-level invariant error, not as a counterexample trace.
Its trace file holds only that line. Good was not run to completion, so
`EventuallyConverged` is not established.

Traces for the failing r3 runs are in `traces/r3-*.txt`. The earlier traces
(`traces/DroppedDeleteEffect.txt`, `ForgetTombstone.txt`, `OmissionInclusive.txt`)
are from the pre-r3 model. The earlier table above is also from the pre-r3 model:
the delete rank changed, rows carry `first`, and Install merges, so its state
counts and depths do not apply to this file.

## Equal-stamp order (host run, 2026-11-15)

Defect: with publish-while-collecting on, one run can emit two different
bodies for one key at the same stamp `(o, r)`. The writer kept the later body
(`INSERT OR REPLACE` in run intake, `replaceOwnRunRows` in admission). A
reader kept the first (the strict newer-stamp rule in `merge.ts`, the first
equal-stamp upsert in the `log.ts` fold). The old `Admissible` assumption said
equal key and stamp imply equal body, so the model never explored the case.

Model change: operations carry `ord`, the intake batch ordinal (`OpN`; `Op` is
`OpN` with ord 0). Mode `equalStamp` adds a corpus where one run emits a key
again at one stamp, with a delete, an omission and a clone (same run id, other
writer) at neighbouring stamps. `Rank` is the one total order:

    (stamp, kind rank, ordinal, body hash)    omission < upsert < delete

Equal rank implies equal body. A writer incarnation field, when the log
provenance design adds one, goes between kind rank and ordinal; it is equal
for all non-clone data, so no outcome changes. `P7` compares every reader with
an oracle that does not depend on apply order (greatest rank, then its body).
Mode `equalStampToday` is the mutant that ignores ordinal and body hash.

| Configuration          | Expected                                     | Actual                                                                                                                                          | Distinct states               | Depth | Wall time |
| ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ----- | --------- |
| EqualStampToday.cfg    | FAIL P7                                      | FAIL P7 (`traces/EqualStampToday.txt`): a reader applies batch 2 (bodies 12, 22) after batch 1 (11, 21) at one stamp and keeps the first bodies | 704 at failure                | 6     | <1 s      |
| EqualStamp.cfg         | PASS (P1–P5, P7, EventuallyConverged)        | PASS, state space complete, no error found                                                                                                      | 3,447,086                     | 31    | 17 min    |
| EqualStampLifetime.cfg | no violation (same, with Reset and Rollback) | BOUNDED: stopped at 40 min (exit 124), no invariant error in explored states; 9.5M states left on queue; liveness not checked                   | at least 81,930,672 (partial) | n/a   | 40 min    |

Each run used `-workers 4`, `nice -n 19`, one job at a time, and its own
metadir, deleted after the run. An earlier 6-batch corpus did not finish in 30
minutes with no violation; the corpus was cut to five batches, which is the
one the table covers. Reset and Rollback are checked only in the Lifetime
config, because together with the equal-stamp corpus they grew the space
without bound.

The other configs still fail where expected (DropGap P2, OmissionInclusive P3,
DropKind OrderOK). Rerun 11-16 with radices derived from the corpus: EqualStampToday fails P7 (704 distinct states at failure), DropKind fails OrderOK, EqualStamp completes with the same 3,447,086 states and no error. Good.cfg and LostPush.cfg were not rerun: the base corpus
has ord 0 throughout and `Rank` reduces to the old order there, so their
results are unchanged by construction, not by a new run.

These results cover the abstract max operator only. The incremental SQL step is
checked separately, in "Incremental apply" below.

Clone and legacy rules the model fixes: two writers with one run id and one
ordinal go to the greater body hash, never to first seen; a legacy entry with
no ordinal counts as 0; an explicit delete beats every ordinal; an omission
loses to every upsert at its stamp.

## Incremental apply (`SqlRank.tla`, host run, 2026-11-16)

`LogProtocol.tla` folds a log with the max of one order. The local database
does not fold. It applies one observation at a time to a stored row in SQL:
`mergeIncoming` for a pulled operation and `replaceOwnRunRows` for the run's
own batch. The `LogProtocol.tla` result therefore covers the abstract max
operator only. The first version of the fix had two SQL shortcuts the model did
not explore:

- An identical body took the stored row only at a strictly greater stamp, so a
  higher ordinal of a body the database held was dropped. Trace: A at ordinal
  0, A at 2, then B at 1. The fold keeps A at 2 and rejects B; the incremental
  database kept A at 0 and then took B.
- `replaceOwnRunRows` replaced a different body at the run's stamp whatever the
  row held. A run that had pulled a clone's higher-ranked body lost it to its
  own lower batch.

`SqlRank.tla` models the incremental step on one key at one stamp (order:
ordinal, then body hash, as a tuple compare with no numeric packing). A
database either pulls an operation from the log or admits its own next batch
(strictly increasing ordinal). Its own batch is in the log only when it changed
the row. `RowIsFold`: the stored row equals the fold of the log, in any order.

| Configuration           | Expected | Actual                                                                                                                  | Distinct states | Depth |
| ----------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------- | --------------- | ----- |
| SqlRank.cfg             | PASS     | PASS, state space complete, no error found                                                                              | 1,029,883       | 6     |
| SqlRankSameBodyKeep.cfg | FAIL     | FAIL `RowIsFold` in 3 states (`traces/SqlRankSameBodyKeep.txt`): a pulled identical body at a higher ordinal is dropped | 33 at failure   | 3     |
| SqlRankOwnReplace.cfg   | FAIL     | FAIL `RowIsFold` in 3 states (`traces/SqlRankOwnReplace.txt`): the run's lower batch replaces a pulled higher one       | 80 at failure   | 3     |

Rules the passing model fixes, and the code that carries them:

- One order, `rankAfter` in `merge.ts` (stamp, ordinal, body hash). Pulled
  operations, an identical body at a higher ordinal included, advance the stored
  row. `replaceOwnRunRows` replaces only when the incoming batch ranks above
  the row by the same function. The stream-sync fold uses `upsertAfter`, the
  same order in TypeScript. `equal-stamp-order.test.ts` runs the SQL and the
  fold on the same operations: every sequence of up to three observations and
  200 random sequences of eight, drawn from a 32-bit generator. The test also
  counts the shapes in that corpus (every kind of step, an identical body at a
  higher ordinal, mixed alternation), so a degenerate generator fails it.
- A database's own batch with a body the row already holds is a sighting, not a
  change. It moves no ordinal and publishes nothing. So the ordinal a row holds
  is always one that is in the log or waiting to be published. Two writers that
  share a run id and both emit one body at different ordinals both publish, and
  the log then orders them. The alternative (the own sighting advances the
  ordinal and publishes the same body again) costs a log entry for each
  re-emitted unchanged row and fixes nothing the fold can see.
- Pulled operations apply to the row under origin `remote`. That already logged
  nothing for publish, so advancing the ordinal on an identical body needs no
  publish step.

Not modelled: the SEEN stamp, `promoteSeen` and a stored stamp older than the
run's. They act between different stamps. The older-stamp case of
`replaceOwnRunRows` is covered by the same `rankAfter`: a row with an older
stamp ranks below the run's batch whatever its ordinal. The `LogProtocol.tla`
rank packing takes its radices from the corpus (one more than the largest
ordinal and body it uses; kinds have three ranks), so it is exact for any
corpus. `SqlRank.tla` compares the tuple and packs nothing.

## Per-stream heads beside the log (`apply.ts`)

A head's parts carry no ordinal, and the server does not serialize `stamp_n` in
a head (`stamp_n` is read only by `log-publish.ts` and written by intake,
admission, the merge and the log's apply). `apply.ts` stages a part's row with
`stamp_n = 0`, so in the merge it is a legacy log entry: one `Pull` of
`SqlRank.tla` with ordinal 0. A log-on device applies the registry's heads
before the log (`applyConnection`), then the log, so a first load meets both. The
order is one total order, so a part and a log entry arriving in either order
give one row. `equal-stamp-order.test.ts` has a `part` step (same SQL options as
`applyOneOnce`) in its exhaustive and random sequences, and
`log-protocol.test.ts` loads a head and a log naming one key at one stamp
through a first load, a progressive first load and a compacted snapshot. Those
tests assert first-load devices only. The writer and a reader that already
followed the log are cycled and asserted in the head-beside-the-log tests (below).

A log-on device that already follows the log reads a registry head it has not
consumed, as a first load does, whatever the head's registry version is beside
its own local version (`applyOneOnce`, `stream_state.consumed_*`; see HeadCursor
below). It then reads the log over the head. `log-protocol.test.ts` asserts all
four devices (writer, early reader, fresh, progressive) end on the head's row,
at an equal stamp and at a later one, and stay there over repeated cycles.

What publishes a head beside a log is not only the flag. A log-off device does.
So does a log-on device whose registry has no batch route, or that cached "no
batch route" earlier: `publishLog` returns `null` and the caller publishes per
stream (`log-publish.ts:184-185`, `232-234`). A fleet whose flags are all on is
not by that fact free of this case, for example during a gateway rollout.
No test here drives that fallback. A device that flips from log on to log off on
one database also fails its per-stream publish with a `UNIQUE` error on
`stream_versions` (the log's apply allocates versions there); that refusal
predates the ordinal. Whether it leaves the records, the remote head and the
retry consistent is not verified here.

With the log off and admission on (`publishWhileCollecting`) a device stores
`stamp_n` in its own rows and orders its own bodies by it. No log segment is
written and a head holds no ordinal. A device that turns the log on after it
published a head, then a first load, both hold the final body (the test asserts
bodies only).

## HeadCursor: a per-stream head that predates the log

`HeadCursor.tla` is a separate small model (one stream, three devices). It adds
what this model leaves out: a registry per-stream head committed by another
device before any log row exists (the gateway refuses it afterwards), the log
writer's rounds, and the two numbers a device keeps: `lver` (the local
`head_version`, which log rounds and applied segments advance) and `cons` (the
last registry head consumed). A row is `[rank, live]`; a head apply merges the
head's rows and then drops rows the head lacks whose rank is at or below its
cutoff. Pending unpublished local changes, compaction and snapshots are not
modelled. The corpus (two heads, two rounds) is a model limit, not a claim.

| Configuration                | Skip rule              | After admitting a head                    | TLC result (EventuallyConverged)                                                                                        |
| ---------------------------- | ---------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| HeadCursor-today.cfg         | `lver > head version`  | log not replayed                          | FAIL                                                                                                                    |
| HeadCursor-todayRebase.cfg   | `lver > head version`  | log replayed from 0                       | FAIL: the writer keeps `cons=1`, `lver=3`, never reads head 2                                                           |
| HeadCursor-fixedNoRebase.cfg | `head version <= cons` | log not replayed                          | FAIL: the head's cutoff drops the writer's own row `a`; position stays, replay never restores it                        |
| HeadCursor-fixed.cfg         | `head version <= cons` | log replayed from 0                       | PASS: 4568 states generated, 658 distinct, depth complete                                                               |
| HeadCursor-fixedSplit.cfg    | `head version <= cons` | head step and log step are two operations | FAIL InvReplayed: a device holds the head and lacks the replay (a single-stream apply that returns after the head step) |

`InvReplayed` (a device holding the current head holds the head's rows with the log's rows over them) is checked in `fixed` and `fixedSplit`. The code keeps them in one job: a job that admits a head also reads the log before it returns, and the batch stores the obligation for the case where it cannot (next section).

### The stored replay obligation

`fixed` makes head and replay one transition. The code cannot: the head batch
commits, and the log pass is a later call that can fail, crash, or find a
registry that moved. Modes `durable` and `memory` split them (`AdmitHead`,
`Replay`) and add a registry rollback (`Rollback`, then a log of another history,
`ForeignRound`) and a crash that loses memory (`MemCrash`).

- `durable` (the code): the head batch also writes the obligation and the cursor
  it replaces (`evPos`, `evId`; `log_replay`), for a device with a cursor and for
  one without. `Replay` runs whenever the obligation exists or the log is ahead,
  refuses a registry that does not fit the cursor and the evidence, and clears
  both only after a validated replay. The registry log is also read just before
  the batch.
- `memory` (what the earlier head had): the obligation lived in the job and only
  for a device that had a cursor row, and the cursor row, with its position, went
  with the head.

| Configuration                  | Result                                                                                                          |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| HeadCursor-durable.cfg         | PASS: InvReplayedOrOwed, InvKept, EventuallyConverged (44343 states generated, 10318 distinct)                  |
| HeadCursor-durableRollback.cfg | PASS: InvReplayedOrOwed, InvKept with a rollback and a foreign log anywhere (357343 generated, 101618 distinct) |
| HeadCursor-memory.cfg          | FAIL InvKept: the cursor is below the position it applied and the evidence is gone                              |
| HeadCursor-memoryReplay.cfg    | FAIL InvReplayedOrOwed: a crash, or a device that held no cursor, holds the head and owes no replay             |
| HeadCursor-memoryRollback.cfg  | FAIL InvKept: a rollback during the window passes unnoticed                                                     |

`InvKept`: a cursor below the highest position the device applied keeps that
position and its segment as evidence, with the obligation owed.
`InvReplayedOrOwed`: a device that holds the current head owes the replay or
holds the head's rows with the log's rows over them. Not modelled: pending local
changes, compaction, and other log bookkeeping that the head batch must leave
alone (a keyed first load's pending rows are the log pass's, not the head's; the
head batch deletes none of them).

Run on 2026-11-16, TLC 2.19 (`tla2tools.jar` 1.7.4, Java 17), `-workers 4`.
Traces: `traces/head-cursor-*.txt`. The two mutants show that both halves of the
fix are needed: the cursor (skip by consumption) and the replay (a head applied
over log rows can drop them).

## Progressive first load shows only rows the finished log keeps (`PartialView.tla`, host run, 2026-11-17)

A progressive first load applies the segments of a log tail in position order
and shows the rows of the applied prefix. Row 3b of the stream-sync plan starts
that load from the first downloaded segment, so the reader cannot know, at that
point, what the later segments hold. The head's refs carry one fact per segment,
`removes`: whether the segment holds a delete or an omission. The reader reads
the segments that say they remove first, before it applies a batch, and hides
the keys they remove until its last batch commits. The segments that remove
nothing arrive in any order while the batches apply.

The model chooses a corpus of `N = 3` segments, each any set of
`{k1, k2} x {up, del}` operations, and which segments the head says remove.
`Exact`: every row the view shows is in the finished fold, at every step.
`Complete`: after the last segment the view is the fold. The stamp is the
position, later wins, and a delete outranks an upsert inside one segment (the
log's rank).

| Config                  | Constants                     | Expected                                                         | TLC result                                         |
| ----------------------- | ----------------------------- | ---------------------------------------------------------------- | -------------------------------------------------- |
| `PartialView.cfg`       | `Lie = FALSE`, `Hold = TRUE`  | no error                                                         | no error; 20,480 states generated, 16,384 distinct |
| `PartialViewLie.cfg`    | `Lie = TRUE`, `Hold = TRUE`   | `Exact` violated: a segment removes but its ref says it does not | `Exact` violated                                   |
| `PartialViewNoHold.cfg` | `Lie = FALSE`, `Hold = FALSE` | `Exact` violated: the view ignores later removals                | `Exact` violated                                   |

Outcome: as expected. The model holds the head's facts true. The code meets a
false fact (`removes: false` on a segment that removes) at the moment it stages
that segment, and then refuses the segment: the load stops and marks its streams
unfinished instead of finishing. Rows a load showed before it reached that
segment stay shown until a retry ends (the writer is the owner's own device, so
a false fact is a writer bug, not an attack). A ref with no `removes` field
(a log written before the fact existed) counts as removing, so such a log is
read in full before its first apply, as before.

Run: `java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 2 -config
PartialView.cfg PartialView` (and the other two configs), with `nice -n 19`.
