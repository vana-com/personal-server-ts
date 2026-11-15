# Registry change push: TLC model

`RegistryPoke.tla` models the gateway's "the registry moved" signal as a held request with a fallback probe, and checks the one property that matters: a device is never behind the registry by more than a bound.

The gateway keeps one counter, `seq`, that rises on every committed registry write. A device keeps `applied`: the `seq` its last pull read. Only a pull moves `applied`. A held request, its reply, a reconnect and a probe are hints that start a pull. A reply may be lost; a request may break; the gateway may fail to wake a waiter.

The probe compares a marker that fingerprints one registry row. Another row stamped in the same millisecond leaves it equal, so a probe, or any pull that the marker gates, can find "nothing new" after a change (`ProbeBlind`). The model keeps that fault: the probe is not exact. What the device can rely on is the gateway's sequence: an answer whose sequence is above the device's cursor, and the first answer after a failure, start a cycle that does not look at the marker (`ForcedPull`). The manager's own timer cycle (`TimerOn`, every `PT` = 6 ticks, 60 s) reads the registry exactly whatever else happened.

`StaleBound` says `age[d] <= Bound` for every device, where `age` counts ticks since the oldest commit the device has not yet applied. One tick is about 10 s in the shipped settings: the held request waits `W` = 2 ticks (25 s) and is declared dead after `Slack` = 1 more (10 s); the probe period is `PL` = 1 (5 s, unhealthy) or `PH` = 6 (60 s, healthy); the timer cycle is `PT` = 6.

Run one configuration (one TLC job, 4 workers, `nice 19`):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/registry-poke/run.sh P1-full-bound3

TLC 1.7.4, one device, two writes, 12 ticks. Raw output is in `out/`. Configurations before P5 model an exact probe (`ProbeBlind=FALSE`) and no timer (`TimerOn=FALSE`); they show which repairs are necessary on their own.

## Results

| config                                     | switches that differ from P1-full-bound3           | Bound (ticks) | result   | states                     |
| ------------------------------------------ | -------------------------------------------------- | ------------- | -------- | -------------------------- |
| P0-healthy-bound0                          | PokesLost=FALSE, HubMiss=FALSE, Disconnects=FALSE  | 0             | pass     | 1843 gen, 1181 distinct    |
| P1-full-bound3                             | (exact probe, no timer)                            | 3             | pass     | 36704 gen, 14362 distinct  |
| P1b-full-bound2-tight                      | (same)                                             | 2             | VIOLATED | 2025 gen, 1010 distinct    |
| P2-alllost-bound1                          | AllLost=TRUE                                       | 1             | pass     | 4949 gen, 1942 distinct    |
| P4-pullreconnect-resume-noprobe-bound3     | ProbeOn=FALSE                                      | 3             | pass     | 6534 gen, 2707 distinct    |
| V1-nothing-bound7                          | Resume=FALSE, PullOnReconnect=FALSE, ProbeOn=FALSE | 7             | VIOLATED | 3425 gen, 1659 distinct    |
| V2-edge-pullreconnect-noprobe-bound7       | Resume=FALSE, FinalCheck=FALSE, ProbeOn=FALSE      | 7             | VIOLATED | 6283 gen, 3015 distinct    |
| V3-nopull-noresume-probeonly-bound3        | Resume=FALSE, PullOnReconnect=FALSE                | 3             | VIOLATED | 5068 gen, 2524 distinct    |
| V3b-nopull-noresume-probeonly-bound6       | Resume=FALSE, PullOnReconnect=FALSE                | 6             | pass     | 56679 gen, 22493 distinct  |
| V4-stretch-always-alllost-bound1           | AllLost=TRUE, StretchOnlyWhenHealthy=FALSE         | 1             | VIOLATED | 367 gen, 202 distinct      |
| V6-resume-only-noprobe-bound3              | PullOnReconnect=FALSE, ProbeOn=FALSE               | 3             | VIOLATED | 577 gen, 341 distinct      |
| P5-blindprobe-forced-bound3                | ProbeBlind=TRUE, TimerOn=TRUE                      | 3             | pass     | 53289 gen, 18283 distinct  |
| P6b-blindprobe-alllost-forced-bound3       | ProbeBlind=TRUE, TimerOn=TRUE, AllLost=TRUE        | 3             | pass     | 9318 gen, 2946 distinct    |
| P6c-blindprobe-alllost-forced-bound2-tight | ProbeBlind=TRUE, TimerOn=TRUE, AllLost=TRUE        | 2             | VIOLATED | 661 gen, 284 distinct      |
| V7-unforced-blindprobe-bound3              | ProbeBlind=TRUE, TimerOn=TRUE, ForcedPull=FALSE    | 3             | VIOLATED | 2949 gen, 1280 distinct    |
| V7b-unforced-blindprobe-bound6             | ProbeBlind=TRUE, TimerOn=TRUE, ForcedPull=FALSE    | 6             | pass     | 111767 gen, 35877 distinct |

## Reading the table

- **P1-full-bound3** is the design with every fault on (replies lost, wakes missed, connections broken) and an exact probe. It holds at 3 ticks, and **P1b** shows 3 is tight. 3 ticks is `W` + `Slack`, the time to declare a silent request dead.
- **P5-blindprobe-forced-bound3** removes the exact probe. The probe may miss any change, and the timer cycle is the only exact read besides the forced pulls. The bound is still 3 ticks: a device does not wait for the probe, because a changed answer and a reconnect each start a cycle that ignores the marker.
- **P6b / P6c**: with every reply lost and a blind probe, a device is behind by at most 3 ticks (the request deadline, then the forced pull on reconnect), not 1. The earlier "degrades to the probe interval" (P2) held only while the probe was exact; with the marker's limit the claim is the request deadline, and 6 ticks (the timer) behind that.
- **V7 / V7b**: the first version of the code sent a push answer through the marker gate, like a probe tick. The same faults then leave a device behind for the whole timer period: violated at 3, passes only at 6. This is the defect that `ForcedPull` removes, and the reason `onChange` forces a cycle.
- **V4-stretch-always-alllost-bound1** violates: if the probe stretched to 60 s even when the push is not healthy, lost replies would leave a device behind for a whole stretched period. This is why the manager stretches only while healthy.
- **V1, V2, V6** violate. Each removes the probe and then one more repair, and a lost reply is never found: V1 drops the cursor (`Resume`) and the pull on reconnect; V2 drops the cursor and the gateway's final read at the wait deadline; V6 drops the pull on reconnect. **P4** removes the probe alone and passes: the cursor, the final read and the pull on reconnect repair every loss within 3 ticks.
- **V3 / V3b**: with neither cursor nor pull on reconnect, only the probe repairs a loss, and it takes the stretched period (6 ticks): violated at 3, passes at 6.
- **P0**: with no faults a device is never behind at all (bound 0).

One change to the model's device rule, made with ForcedPull: a device pulls on an answer above its cursor (`lastSeen`), as the code does, not above what it applied. The device cannot see what it applied, so a pull that was discarded is not retried by a later answer that repeats the same sequence. The exact-probe results above did not change.
