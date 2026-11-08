# Covered full refresh: TLA+ model

`CoveredReplace.tla` models one stream, two devices and three runs. TLC picks
every assignment of "covered" and of run contents. A covered run replaces; every
other run merges. A replacement keeps base lines newer than the replacing run.

- `CoveredReplace.cfg`: arrival follows stamp order (`InOrder == TRUE`). The view equals
  the oracle exactly. TLC: 164,640 states generated, 60,368 distinct, no error.
- `CoveredReplace.any-order.cfg`: any arrival order (`InOrder == FALSE`). TLC: 2,455,880
  generated, 812,224 distinct, no error. Safety only: no wrong drop; extras are only
  lines of a run that arrived late and is older than a newer covered refresh; a merge
  run never removes a key; replay is idempotent.

Known limit the model found: the head records no "replaced through" stamp, so a late,
older run's lines survive until the next covered refresh. They are a safe leftover,
never a wrong drop.

Run: `java -cp tla2tools.jar tlc2.TLC -workers 4 -cleanup -config <cfg> CoveredReplace.tla`
(set `InOrder` in the .tla to match the cfg).
