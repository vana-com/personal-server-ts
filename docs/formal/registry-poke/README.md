# Registry change push: TLC model

`RegistryPoke.tla` models the gateway's "the registry moved" signal as a held request with a fallback probe, and checks the one property that matters: a device is never behind the registry by more than a bound.

The gateway keeps one counter, `seq`, that rises on every committed registry write. A device keeps `applied`: the `seq` its last pull read. Only a pull moves `applied`. A held request, its reply, a reconnect and a probe are hints that start a pull. A reply may be lost; a request may break; the gateway may fail to wake a waiter.

`StaleBound` says `age[d] <= Bound` for every device, where `age` counts ticks since the oldest commit the device has not yet applied. One tick is about 10 s in the shipped settings: the held request waits `W` = 2 ticks (25 s) and is declared dead after `Slack` = 1 more (10 s); the probe period is `PL` = 1 (5 s, unhealthy) or `PH` = 6 (60 s, healthy).

Run one configuration (one TLC job, 4 workers, `nice 19`):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/registry-poke/run.sh P1-full-bound3

TLC 1.7.4, one device, two writes, 12 ticks. Raw output is in `out/`.

## Results

| config                                 | switches that differ from P1-full-bound3           | Bound (ticks) | result   | states                    |
| -------------------------------------- | -------------------------------------------------- | ------------- | -------- | ------------------------- |
| P0-healthy-bound0                      | PokesLost=FALSE, HubMiss=FALSE, Disconnects=FALSE  | 0             | pass     | 1843 gen, 1181 distinct   |
| P1-full-bound3                         | (the full design)                                  | 3             | pass     | 36704 gen, 14362 distinct |
| P1b-full-bound2-tight                  | (the full design)                                  | 2             | VIOLATED | 2593 gen, 1282 distinct   |
| P2-alllost-bound1                      | AllLost=TRUE                                       | 1             | pass     | 4949 gen, 1942 distinct   |
| P4-pullreconnect-resume-noprobe-bound3 | ProbeOn=FALSE                                      | 3             | pass     | 6534 gen, 2707 distinct   |
| V1-nothing-bound7                      | Resume=FALSE, PullOnReconnect=FALSE, ProbeOn=FALSE | 7             | VIOLATED | 3376 gen, 1637 distinct   |
| V2-edge-pullreconnect-noprobe-bound7   | Resume=FALSE, FinalCheck=FALSE, ProbeOn=FALSE      | 7             | VIOLATED | 6059 gen, 2925 distinct   |
| V3-nopull-noresume-probeonly-bound3    | Resume=FALSE, PullOnReconnect=FALSE                | 3             | VIOLATED | 4198 gen, 2110 distinct   |
| V3b-nopull-noresume-probeonly-bound6   | Resume=FALSE, PullOnReconnect=FALSE                | 6             | pass     | 56679 gen, 22493 distinct |
| V4-stretch-always-alllost-bound1       | AllLost=TRUE, StretchOnlyWhenHealthy=FALSE         | 1             | VIOLATED | 388 gen, 214 distinct     |
| V6-resume-only-noprobe-bound3          | PullOnReconnect=FALSE, ProbeOn=FALSE               | 3             | VIOLATED | 592 gen, 348 distinct     |

## Reading the table

- **P1-full-bound3** is the shipped design with every fault on (replies lost, wakes missed, connections broken). It holds at 3 ticks, and **P1b** shows 3 is tight: the same design violates 2. 3 ticks is `W` + `Slack`, the time to declare a silent request dead.
- **P2-alllost-bound1**: with every reply lost, the system degrades to the probe interval (1 tick) and no further. This is the liveness claim: the push can only make things faster.
- **V4-stretch-always-alllost-bound1** violates: if the probe stretched to 60 s even when the push is not healthy, lost replies would leave a device behind for a whole stretched period. This is why the manager stretches only while healthy.
- **V1, V2, V6** violate. Each removes the probe and then one more repair, and a lost reply is never found: V1 drops the cursor (`Resume`) and the pull on reconnect; V2 drops the cursor and the gateway's final read at the wait deadline; V6 drops the pull on reconnect. **P4** removes the probe alone and passes: the cursor, the final read and the pull on reconnect repair every loss within 3 ticks.
- **V3 / V3b**: with neither cursor nor pull on reconnect, only the probe repairs a loss, and it takes the stretched period (6 ticks): violated at 3, passes at 6.
- **P0**: with no faults a device is never behind at all (bound 0).
