# Covered full refresh: TLA+ model

`CoveredReplace.tla` models one stream, two devices and three runs. TLC picks
every assignment of "covered" and of run contents. A covered run replaces only
when the head it started on (its basis) is still the head at publish; otherwise
it merges, as a non-covered run does. A replacement keeps base lines newer than
the replacing run.

`CONSTANT InOrder` selects the arrival model: `TRUE` means runs arrive in stamp
order; `FALSE` means any order.

## Configs

- `CoveredReplace.any-order.cfg` (`InOrder = FALSE`): invariants `NoWrongDrop`,
  `OnlyLateExtras`, `OnceEach`, `NoLostWrite`; property `MergeNeverRemoves`.
  TLC (`-workers 4`): 15,101,056 generated, 4,983,168 distinct, depth 13, no error.
- `CoveredReplace.cfg` (`InOrder = TRUE`): same as above plus `ExactWhenInOrder`.
  **Currently fails `ExactWhenInOrder`** (see below). Without that one invariant,
  the run is clean: 1,691,648 generated, 598,016 distinct, depth 13.

## Ghost variables

- `hv[k]`: the stamp of the last write to key `k`, as the model's oracle sees it.
- `lostN`: count of publishes where a covered refresh with an expected version
  equal to the current head deleted a key that a newer write had set. This counts
  as a lost write. `NoLostWrite == lostN = 0`.

`basis[r]` is set at Begin and is not changed by a retry.

## Open finding: `ExactWhenInOrder` fails under `InOrder = TRUE`

The fence works as designed here, but the invariant assumes it does not block
exact replacement. Trace (TLC, `CoveredReplace.cfg`, 7 steps, `hv` = write stamps):

```
State 2: Begin("r1")   basis = [r1 |-> 0, r2 |-> 99, r3 |-> 99]
State 3: Begin("r2")   basis = [r1 |-> 0, r2 |-> 0,  r3 |-> 99]   (r2 covered, empty content)
State 5: Post("r1")    ver = 1, head = [c |-> 1, a |-> 0, b |-> 0]
State 7: Post("r2")    ver = 2, head = [c |-> 1, a |-> 0, b |-> 0]
Error: Invariant ExactWhenInOrder is violated.
```

r2 started on version 0 and published after r1 moved the head to version 1. Its
basis no longer matches, so it merges, and `c` (written by r1) survives. The
oracle expects `c` gone because r2 is the last covered refresh in stamp order.
The fence is what keeps `c` there. Two readings are possible; this is a design
decision for the lane owner, not something the model settles:

1. Keep the fence. Narrow `ExactWhenInOrder` to runs whose basis matched at
   publish, so a stale covered refresh is only required to merge.
2. Keep the invariant as written. Then a stale covered refresh must still
   replace, which reopens the cross-device loss the fence closes.

The `ExactWhenInOrder` check is kept in the InOrder=TRUE config, not weakened.
Its mutant (below) also fails it, so the check is evaluated.

## Named mutants (must fail)

Both were run in a temporary copy of the spec, then restored.

1. Basis guard removed from `Apply` (any-order cfg): `NoLostWrite` violated,
   depth 7.
2. Keep one omitted key `a` at Apply (InOrder=TRUE cfg): `ExactWhenInOrder`
   violated, depth 7. The unmutated spec also fails this check (see above), so this
   mutant shows the check is evaluated; it does not isolate a separate break.

## Run

    java -XX:+UseParallelGC -Djava.io.tmpdir=<scratch> -cp tla2tools.jar \
      tlc2.TLC -workers 4 -cleanup -config <cfg> CoveredReplace.tla

Run one job at a time with `nice -n 19`, and delete the `states/` directory after
each run. Keep `-Djava.io.tmpdir` off `/tmp`.
