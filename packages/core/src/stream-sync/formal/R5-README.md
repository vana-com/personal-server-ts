# r5 stream sync: TLA+ models

Two modules. `CoveredReplace.tla` (from #560) is unchanged. Its stamp, start-basis and fence rules
are reused in `StreamSyncR5.tla`, which adds what #560 does not model: a local database per replica
(records, change log, publish watermark, `head_parts`), apply, publish with a registry CAS,
un-write, delete (intent, heads, tombstone, purge), import seeds, and the retry cursor.
`AccountGate.tla` is separate because it needs temporal fairness and none of the database state.

Run: `java -cp tla2tools.jar tlc2.TLC -workers 4 -cleanup -config cfg/<name>.cfg <Module>.tla`
(`StreamSyncR5.tla` for every cfg except `ag*`, which use `AccountGate.tla`).
Raw TLC output for every cfg is in `results/`. Every run is exhaustive; none is simulation.

## StreamSyncR5

One connection, one stream, two keys, two replicas (a device and an in-memory embed frame are both
replicas). Three runs (two in the delete configs). TLC chooses each run's owner, covered flag,
content and connector version (`OWN`, `COV`, `CV`, `CONT`, `RET` in the cfg).
Stamps: 0 absent, 1 seed, run r has stamp r+1; the newest stamp wins.

Quiescence `Q`: every run is terminal, no replica has publish or apply in flight, nothing is pending
publish, and every replica matches the registry. Properties are checked at `Q`, so a witness cfg proves
`Q` is reachable with rows present.

| Property | Meaning |
|---|---|
| `NoLostWrite` | at `Q`, every row an accepted run (or seed) owes is readable on every replica |
| `ReplaceFenced` | a replace never drops a row written by a post newer than the run's basis (ghost counter) |
| `NoResurrection` | at `Q`, every row traces to a run or seed from after the last delete |
| `DeleteDurable` | at `Q`, a started delete is a tombstone in the registry (or was superseded by a reconnect) |

Mutant switches (cfg constants): `WmAt="commit"`, `ApplyGuard=FALSE`, `LoserApplies=FALSE`,
`Fence=FALSE`, `UnwDropsParts=FALSE`, `RetryMode="dropRows"|"noCursor"`, `DelFence=FALSE`,
`SeedGenOnly=FALSE`, `DelIntentFirst=FALSE`, `ImpChecksLocal=FALSE`, `TombAbsent=FALSE`.

## Results

| cfg | what | result | distinct states |
|---|---|---|---|
| `pub` | publish/apply/CAS: baseline | pass | 538,002 |
| `pub-witnessQ` | witness: quiescence with rows | violated: WitnessQ | 127,780 |
| `pub-witnessCas` | witness: CAS lost | violated: WitnessCasLost | 92,874 |
| `pub-M-wm-at-commit` | mutant: watermark taken at commit | violated: NoLostWrite | 136,740 |
| `pub-M-apply-no-guard` | mutant: apply drops unpublished-rows guard | violated: NoLostWrite | 322,793 |
| `pub-M-loser-overwrites` | mutant: CAS loser overwrites without applying | violated: NoLostWrite | 370,119 |
| `rep` | replace behind fence: baseline | pass | 10,784,840 |
| `rep-witness` | witness: a replace passes the fence | violated: WitnessReplace | 117,403 |
| `rep-M-no-fence` | mutant: no fence (ghost counter) | violated: ReplaceFenced | 1,556,468 |
| `rep-M-no-fence-oracle` | mutant: no fence (oracle) | violated: NoLostWrite | 5,231,563 |
| `unw` | un-write as r5 states it (overlapping runs allowed, no end refusal) | violated: NoLostWrite | 4,261,356 |
| `unw-witness` | witness: un-write happens | violated: WitnessUnwrite | 490,105 |
| `unw-M-keeps-parts` | mutant: un-write keeps head_parts (r5 as stated) | violated: NoLostWrite | 3,284,805 |
| `unw-mono` | un-write, one replica never runs an older connector after a newer one | pass | 3,252,312 |
| `unw-mono-witness` | witness | violated: WitnessUnwrite | 330,633 |
| `unw-mono-M-keeps-parts` | mutant: un-write keeps head_parts | violated: NoLostWrite | 2,130,137 |
| `unw-end` | (a) end-time refusal, overlapping runs allowed | violated: NoLostWrite | 3,016,614 |
| `unw-seq` | (a) end-time refusal, one run at a time per replica | pass | 1,802,646 |
| `unw-seq-witness` | witness | violated: WitnessUnwrite | 377,789 |
| `unw-seq-M-none` | mutant: no end-time refusal | violated: NoLostWrite | 1,995,287 |
| `unw-seq-M-head` | mutant: refuse only against the head | violated: NoLostWrite | 1,816,831 |
| `unw-seq-M-local` | mutant: refuse only against local unpublished runs | pass | 2,364,180 |
| `unw-seq-M-keeps-parts` | mutant: un-write keeps head_parts | violated: NoLostWrite | 1,220,836 |
| `unw-body` | body retention (keeps overwritten and shadowed rows), overlapping runs allowed | pass | 5,522,500 |
| `unw-body-witness` | witness | violated: WitnessUnwrite | 490,185 |
| `unw-body-M-overwritten-only` | mutant: retain overwritten rows but not shadowed ones | violated: NoLostWrite | 4,319,859 |
| `unw-body-M-keeps-parts` | mutant: un-write keeps head_parts | violated: NoLostWrite | 3,306,053 |
| `ret` | retry keeps rows and cursor: baseline | pass | 4,304,016 |
| `ret-M-drop-rows` | mutant: cursor saved, rows dropped | violated: NoLostWrite | 81,595 |
| `ret-noCursor-harmless` | old R19 shape (rows merged, cursor not saved): harmless | pass | 5,866,954 |
| `del` | delete, (b) tombstone always, (c) import refuses on local deleted | pass | 17,943,719 |
| `del-crash` | same with one crash | pass | 46,901,133 |
| `del-witness` | witness: delete completes | violated: WitnessDeleteDone | 1,267 |
| `del-M-no-run-fence` | mutant: run fence ignores delete | violated: NoResurrection | 1,678 |
| `del-M-seed-any-gen` | mutant: seeds publish into any generation | violated: NoResurrection | 174,586 |
| `del-M-no-intent` | mutant: intent not durable first | violated: DeleteDurable | 893 |
| `del-impcheck-off` | mutant (c): import ignores local deleted | violated: NoResurrection | 3,039 |
| `del-noctl-tomb-off-res` | mutant (b): no tombstone when no control row (NoResurrection) | violated: NoResurrection | 53,133 |
| `del-noctl-tomb-off` | mutant (b) (DeleteDurable) | violated: DeleteDurable | 503 |
| `del-noctl-tomb-off-impcheck-off` | mutants (b)+(c) (DeleteDurable) | violated: DeleteDurable | 538 |

Rows are from the final run on the final spec (raw output in `results/`). Switches added in this
revision: `EndRefuse` (`none|both|head|local`), `SeqRuns` (one run at a time per replica), `BodyKeep`
(`none|overwritten|all`); delete configs model (b) tombstone always and (c) import refuses on local `deleted`.

`unw-mono` limits one replica to non-decreasing connector versions (`MonoCV`).

### End-time refusal (a) versus body retention

- `unw-end`: refusing a run at `end` when its connector version is below any unpublished local run or the
  known head does NOT restore `NoLostWrite` if runs may overlap on one replica. A lower-version run that
  ends after a higher-version run is shadowed silently (its rows lose the stamp comparison), and the
  refusal never fires for it. Un-write then drops the head parts and the shadowed unpublished rows are gone.
- `unw-seq`: with one active run per connection per replica (`SeqRuns`), (a) restores `NoLostWrite`.
  Mutants: no refusal and head-only are caught; **local-only is NOT caught** (`unw-seq-M-local` passes): with
  `SeqRuns` the local clause carries the property and the head clause is redundant for `NoLostWrite`.
- `unw-body`: body retention (`BodyKeep="all"`) restores it with overlapping runs; retaining only
  overwritten rows (`unw-body-M-overwritten-only`) fails.

### Publish upload (C.2 step 4)

A merge during the upload is safe with the watermark taken at publish start: `pub` passes, and
`pub-M-wm-at-commit` is the only watermark variant that fails. The build need not hold the per-connection
queue across the upload. This assumes at most one publish per device and connection at a time.

## AccountGate ("Off then On must reach sync")

Two hosts share one Personal Server. The account answer is `(state, generation)`. Each host stores the
last answer it read, re-reads at start, at each attempt and on signals, and posts every answer to the
server first. The server record latches On at a generation; a higher generation replaces it. A failed
read gives unknown and never Off. A stored Off older than B does not admit a legacy run. Admit and
commit are separate steps. Fairness: weak on the re-read, the account turning On, and the commit.
Failed reads are bounded (`MaxFail`).

| Property | cfg `ag`, `ag-reset` (one Dev reset) |
|---|---|
| `Final`: eventually always, the account is On and every host is On at its generation | pass |
| `Live`: On leads to every host On at that generation | pass |
| `NoLegacyAfterOn`: no legacy commit once the server holds On at the same or a higher generation | pass |
| `NoStaleAdmit`, `FailNeverOff` | pass |

States: 2,052 (`ag`), 19,184 (`ag-reset`). Mutants: `ag-M-stop-polling` and `-reset`
(`RereadAfterCleanOff=FALSE`) violate `Final`; `ag-M-admission-only` violates `NoLegacyAfterOn`;
`ag-M-fail-mints-off` violates `FailNeverOff`; `ag-M-retimestamp` violates `NoStaleAdmit`.

## Not covered

- One stream and two keys; no multi-stream or multi-connection interaction.
- Apply downloads all parts in one merge batch; no per-part crash points. Crash is modeled only as
  loss of in-flight publish and apply state (one crash, delete configs).
- No log compaction, no key-type conflicts, no blobs, no size limits.
- Registry unreachable at `begin` (deferred, `generation_unbound` runs) is not modeled.
- Retry cursor is a redelivery set, not a real source.
- Import is a one-shot merge of seed rows; the read-back and retire steps are not modeled.
- The time bound B is a fresh/stale flag, not a clock.
