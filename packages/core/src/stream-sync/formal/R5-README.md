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

| cfg | expectation | result | distinct states |
|---|---|---|---|
| `pub` | pass | pass | 538,002 |
| `pub-witnessQ`, `pub-witnessCas` | violated (non-vacuity) | violated | 128,598 / 92,460 |
| `pub-M-wm-at-commit` | caught | `NoLostWrite` violated | 137,191 |
| `pub-M-apply-no-guard` | caught | `NoLostWrite` violated | 322,486 |
| `pub-M-loser-overwrites` | caught | `NoLostWrite` violated | 369,717 |
| `rep` | pass | pass | 10,784,840 |
| `rep-witness` | violated | violated | 117,311 |
| `rep-M-no-fence` | caught | `ReplaceFenced` violated | 1,556,002 |
| `rep-M-no-fence-oracle` | caught | `NoLostWrite` violated | 5,231,186 |
| `unw` | pass | **`NoLostWrite` violated (counterexample in r5)** | 4,260,842 |
| `unw-mono` | pass | pass | 3,252,312 |
| `unw-witness`, `unw-mono-witness` | violated | violated | 489,773 / 330,934 |
| `unw-mono-M-keeps-parts` | caught | `NoLostWrite` violated | 2,130,036 |
| `ret` | pass | pass | 4,304,016 |
| `ret-M-drop-rows` | caught | `NoLostWrite` violated | 81,596 |
| `ret-noCursor-harmless` | pass | pass | 5,866,954 |
| `del` | pass | pass | 17,943,719 |
| `del-crash` (one crash) | pass | pass | 46,901,133 |
| `del-witness` | violated | violated | 1,222 |
| `del-M-no-run-fence` | caught | `NoResurrection` violated | 1,497 |
| `del-M-seed-any-gen` | caught | `NoResurrection` violated | 175,548 |
| `del-M-no-intent` | caught | `DeleteDurable` violated | 873 |
| `del-impcheck-off` | finding | `NoResurrection` violated | 3,143 |
| `del-noctl-tomb-off-res` | finding | `NoResurrection` violated | 49,979 |
| `del-noctl-tomb-off` (and `-impcheck-off`) | finding | `DeleteDurable` violated | 564 / 507 |
| `del-noctl-tomb-off-lost` | pass | pass | 17,773,056 |

`unw-mono` limits one replica to non-decreasing connector versions (`MonoCV`); it is the un-write
scenario without the counterexample below.

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
