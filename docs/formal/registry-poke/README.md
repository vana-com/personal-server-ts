# Registry change push: TLC model

`RegistryPoke.tla` models the gateway's "the registry moved" signal as a held request with a fallback probe, and checks the one property that matters: a device is never behind the registry by more than a bound.

The gateway keeps one counter, `seq`, that rises on every committed registry write. A device keeps `applied`: the `seq` its last pull read. Only a pull moves `applied`. A held request's reply and a probe are hints that start a pull. A reply may be lost; a request may break; the gateway may fail to wake a waiter.

The probe compares a marker that fingerprints one registry row. Another row stamped in the same millisecond leaves it equal, so a probe, or any pull that the marker gates, can find "nothing new" after a change (`ProbeBlind`). The model keeps that fault: the probe is not exact. What the device can rely on is the gateway's sequence: an answer whose sequence is above the device's cursor, and the first answer after a failure, start a cycle that does not look at the marker and does not wait for the probe (`ForcedPull`). Only a successful answer starts that cycle (`PullAfterFailure`); a failed or lost request and the re-subscription that follows call nothing, as in `change-push.ts`. After a failed request the device waits `BO` ticks before the next one (`BO` = 3, the 30 s cap of the shipped back-off, in every configuration except the ones marked `BO` = 0). The manager's own timer cycle (`TimerOn`, every `PT` = 6 ticks, 60 s) reads the registry exactly whatever else happened.

`StaleBound` says `age[d] <= Bound` for every device, where `age` counts ticks since the oldest commit the device has not yet applied. One tick is about 10 s in the shipped settings: the held request waits `W` = 2 ticks (25 s) and is declared dead after `Slack` = 1 more (10 s); the probe period is `PL` = 1 (5 s, unhealthy) or `PH` = 6 (60 s, healthy), re-read at every probe tick so that a push that just failed returns to the short period at once; the timer cycle is `PT` = 6.

Run one configuration (one TLC job, 4 workers, `nice 19`):

    TLA2TOOLS=/path/to/tla2tools.jar docs/formal/registry-poke/run.sh P1-full-bound3

TLC 1.7.4, one device, two writes, 12 ticks. Raw output is in `out/`. P0 to P3 model an exact probe (`ProbeBlind=FALSE`) and no timer (`TimerOn=FALSE`); P4 onward use the shipped combination: a blind probe is possible and the timer runs.

## Results

The second column names what differs from the shipped model: a blind probe possible, the timer on, every fault, `BO` = 3.

| config                                     | what it checks                                                        | Bound (ticks) | result   | states                    |
| ------------------------------------------ | --------------------------------------------------------------------- | ------------- | -------- | ------------------------- |
| P0-healthy-bound0                          | exact probe, no timer, no faults                                      | 0             | pass     | 1772 gen, 1125 distinct   |
| P1-full-bound3                             | exact probe, no timer, every fault                                    | 3             | pass     | 34306 gen, 14106 distinct |
| P1b-full-bound2-tight                      | same                                                                  | 2             | VIOLATED | 638 gen, 396 distinct     |
| P2-alllost-bound1                          | exact probe, no timer, every reply lost                               | 1             | pass     | 5062 gen, 2190 distinct   |
| P3-nopull-noresume-probeonly-bound3        | exact probe alone: no cursor resume, no pull after failure            | 3             | pass     | 41462 gen, 17038 distinct |
| P4-noprobe-timer-bound6                    | no probe: push and timer only                                         | 6             | pass     | 18842 gen, 7444 distinct  |
| P4b-noprobe-timer-bound5-tight             | same                                                                  | 5             | VIOLATED | 754 gen, 510 distinct     |
| P5-blindprobe-forced-bound6                | blind probe, any reply may be lost                                    | 6             | pass     | 59952 gen, 20608 distinct |
| P6-blindprobe-alllost-forced-bound6        | blind probe, every reply lost                                         | 6             | pass     | 13360 gen, 4582 distinct  |
| P6b-blindprobe-alllost-forced-bound5-tight | same                                                                  | 5             | VIOLATED | 2233 gen, 1045 distinct   |
| P7-blindprobe-noloss-backoff-bound5        | blind probe, no reply lost, connections break, wakes missed, `BO` = 3 | 5             | pass     | 35497 gen, 13723 distinct |
| P7b-blindprobe-noloss-backoff-bound4-tight | same                                                                  | 4             | VIOLATED | 2011 gen, 1113 distinct   |
| P8-blindprobe-nofaults-forced-bound0       | blind probe, no loss, no breaks, no missed wakes (`BO` = 0)           | 0             | pass     | 2887 gen, 1493 distinct   |
| V1-nothing-bound7                          | no cursor resume, no pull after failure, no probe                     | 7             | VIOLATED | 1960 gen, 1216 distinct   |
| V2-edge-pullafterfailure-noprobe-bound7    | no cursor resume, no final read at the deadline, no probe             | 7             | VIOLATED | 2098 gen, 1303 distinct   |
| V4-stretch-always-alllost-bound1           | exact probe stretched to 60 s even when unhealthy, every reply lost   | 1             | VIOLATED | 43 gen, 33 distinct       |
| V6-resume-only-noprobe-bound3              | no pull after failure, no probe                                       | 3             | VIOLATED | 331 gen, 232 distinct     |
| V7-unforced-nofaults-bound0                | answers go through the marker gate, no faults except the blind marker | 0             | VIOLATED | 69 gen, 55 distinct       |
| V7b-unforced-nofaults-bound6               | same                                                                  | 6             | pass     | 5915 gen, 2948 distinct   |
| V8-pushonly-noprobe-notimer-bound7         | push alone: no probe, no timer, replies may be lost                   | 7             | VIOLATED | 1906 gen, 1179 distinct   |

## Reading the table

- **What starts a pull.** Only an answer: one above the cursor, or the first one after a failure. A lost reply, a request that times out and the re-subscription that follows start nothing. An earlier version of this model started a cycle on every reconnect; the code does not, so the earlier "3 ticks with every reply lost" did not describe it.
- **P6 / P6b: every reply lost with a blind probe is bounded by the timer, 6 ticks (60 s).** Nothing the push does can help while no answer arrives, and the probe may keep reading an equal marker. P6b shows 5 is not enough. The timer's 6 ticks hold whatever the back-off, because the back-off only spaces requests that cannot answer. P5 (any reply may be lost) gives the same 6.
- **P7 / P7b: with replies delivered, connections that break and a 30 s back-off bound it at 5 ticks (50 s), and 4 is not enough.** The earlier model had no back-off, so it could not show this term, and I did not isolate which faults make up the 5. With the first-retry back-off (`BO` = 0) the same faults hold at 2.
- **P8 / V7 / V7b: what the forced cycle buys.** With no faults beyond the marker's blindness, a pushed change is applied at once (bound 0). If the answer went through the marker gate like a probe tick, a blind marker would discard it, and the device would wait for the timer (V7 violated at 0, V7b passes only at 6). This is the defect `ForcedPull` removes. The cycle also skips the probe read, so a probe that never answers cannot hold it (see `sync-manager.push.test.ts`).
- **The marker a forced cycle leaves behind is not modelled, and the code is more conservative than the model.** The model's forced pull has no marker to publish. The manager's forced cycle reads no marker and publishes none: `pulledMarker` moves only to a marker read before its own cycle started, so a probe that answers during a forced cycle cannot mark a later registry state applied that the cycle never read. The next timed probe sees a marker that differs and runs one extra cycle. An extra cycle can only shorten how far a device is behind, so every bound in the table holds without a rerun (see `sync-manager.push.test.ts`).
- **Entry points the model leaves out: it under-counts cycles, so its bounds are pessimistic.** The manager starts a cycle from more places than the model has actions. `Timer` is the 60 s interval. `Probe` and `PokePull` are the timed probe and a pushed answer. Startup, an explicit `trigger()` and the debounced cycle after local ingest (`notifyNewData`) are unconditional cycles that read the registry exactly, like `Timer`, at moments the model does not list. Focus and online (`requestPull`) are probe pulls with the marker gate, like `Probe`, started early. A requested follow-up after a running cycle (including one that failed) is one more such cycle. Each extra cycle can only apply the registry sooner, and none can leave the device further behind, so leaving them out makes every bound in the table an upper bound on the code. The model's cycle also always succeeds: a rejecting cycle and the one follow-up it still owes are a scheduler property, tested in `sync-manager.push.test.ts` rather than modelled. The follow-up adds no action and changes no bound, so TLC was not rerun.
- **P4 / P4b / V8: the timer is the guarantee.** With no probe, push and timer hold at 6 ticks, and 5 is not enough. Remove the timer as well (V8) and a lost reply is never found: the push alone has no bound.
- **P1 / P1b / P2 / P3.** With an exact probe the probe alone is the repair: it returns to the short period as soon as a push fails, so a stale device is found within the request deadline (3 ticks), or within 1 tick when every reply is lost and the push never became healthy (P2). These rows say nothing about a blind probe; the shipped marker can be blind, which is why P4 onward carry the timer.
- **V4** violates: if the probe stretched to 60 s even when the push is not healthy, lost replies would leave a device behind for a whole stretched period. This is why the manager stretches only while healthy.
- **V1, V2, V6** violate. Each removes the probe and then one more repair.
- **P0**: with no faults and an exact probe a device is never behind at all.

A device pulls on an answer above its cursor (`lastSeen`), as the code does, not above what it applied. The device cannot see what it applied, so a pull that was discarded is not retried by a later answer that repeats the same sequence.
