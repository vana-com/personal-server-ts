# Covered full refresh: TLA+ model

`CoveredReplace.tla` models one stream, two devices and three runs. TLC picks
every assignment of "covered" and of run contents.

A covered run replaces the stream's published set only when the head it started
on (its basis) is still the head at publish. If another device published since,
the run merges, as a non-covered run does. This is the fence. A replacement keeps
base lines newer than the replacing run.

`CONSTANT InOrder` selects the arrival model, which gives two modes:

- `InOrder = TRUE`: runs arrive in stamp order.
- `InOrder = FALSE`: runs arrive in any order (an offline device).

## Invariants

- `NoWrongDrop`, `OnlyLateExtras`, `OnceEach`, `NoLostWrite`: in both modes.
- `ExactWhenInOrder`: `InOrder = TRUE` only. The head equals the fenced oracle
  `OracleFenced`. The oracle replaces only at covered runs whose basis matched at
  publish (`basis[r] = req[r].exp`). A covered run that merged because its basis
  went stale is an ordinary merge in the oracle, so its lines stay.
- `MergeNeverRemoves` (property): an uncovered run never removes a key.

The fence accepts extra rows as the fail-safe. A stale covered refresh merges, so
its older lines may remain. `OnlyLateExtras` bounds them.

## Configs and results

Run on the committed spec, with `-workers 4`:

| Cfg                            | Mode              | Invariants                                                                                                   | Result                                                        |
| ------------------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| `CoveredReplace.cfg`           | `InOrder = TRUE`  | `NoWrongDrop`, `OnlyLateExtras`, `OnceEach`, `ExactWhenInOrder`, `NoLostWrite`; property `MergeNeverRemoves` | No error. 1,691,648 generated, 598,016 distinct, depth 13.    |
| `CoveredReplace.any-order.cfg` | `InOrder = FALSE` | `NoWrongDrop`, `OnlyLateExtras`, `OnceEach`, `NoLostWrite`; property `MergeNeverRemoves`                     | No error. 15,101,056 generated, 4,983,168 distinct, depth 13. |

## Named mutants (each must fail)

Each mutant was made on a temporary copy of the spec, run, and then discarded.
The committed spec was not changed.

| Mutant | Change                                                                                                               | Cfg              | Result                                                                                                                                          |
| ------ | -------------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| M-A1   | Basis guard removed from `Apply` (`IF cov[r] THEN`)                                                                  | any-order        | `Invariant NoLostWrite is violated`, depth 7                                                                                                    |
| M-A2   | Key `a` kept at `Apply` (`IF k = "a" THEN h[k] ELSE ...`)                                                            | `InOrder = TRUE` | `Invariant NoWrongDrop is violated`, depth 4. With only `ExactWhenInOrder` in the invariants: `Invariant ExactWhenInOrder is violated`, depth 4 |
| M-A3   | Old invariant: `ExactWhenInOrder` uses `Oracle` (replaces on a stale basis)                                          | `InOrder = TRUE` | `Invariant ExactWhenInOrder is violated`, depth 7                                                                                               |
| M-A4   | Basis-matched covered refresh keeps an omitted base key `b` (`IF k = "b" /\ k \notin content[r] THEN h[k] ELSE ...`) | `InOrder = TRUE` | `Invariant ExactWhenInOrder is violated`, depth 7 (full cfg and exact-only cfg both report it)                                                  |

M-A3 shows the narrowing is needed. The old invariant fails on the real spec,
so the narrowed one is not vacuous. M-A4 shows the narrowed invariant still
catches an extra row kept on a basis-matched covered refresh.

## Commands

Run one job at a time, with `nice -n 19`, `-cleanup`, and metadata and temp
files outside `/tmp`:

    java -Djava.io.tmpdir=<scratch> -XX:+UseParallelGC -cp tla2tools.jar \
      tlc2.TLC -workers 4 -cleanup -metadir <scratch>/meta -config <cfg> CoveredReplace.tla

Delete the `states/` and metadata directories after each run.
