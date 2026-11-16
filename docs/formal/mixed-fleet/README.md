# Mixed fleet: one connection, devices that differ in build and log flag

`MixedFleet.tla` asks one question: when devices of one owner differ in their
build and in the local `logProtocol` flag, does a device ever show stale data as
current, or write beside the log, or lose a write?

## The rule modelled

The protocol a connection uses is a property of the connection, not of a
device. The log row in the registry records it: the first log write creates it
and nothing removes it. With `GateOn`:

- A device that can read the log follows it whatever its own flag says. The
  flag only lets a device start a log on a connection that has none.
- A device that cannot read the log's format keeps its pending write, writes
  nothing, and reports `update_required`.

`GateOn = FALSE` is the code before the gate: the flag decides whether a device
reads the log, and a flag-off device publishes per-stream heads.

## The registry rule the gate cannot supply (`Fence`)

A head written after the log row exists is outside the log. A device that
follows the log does not fold it in: applying it throws, or replaces rows the log
holds. Two writers produce such a head: a build without the gate, and a gated
device that read the registry just before another device's first log write.
Neither can be stopped by a client, because the registry accepts only conditions
of the form "this row has this version"; there is no condition "this row is
absent". `Fence = TRUE` models the missing rule: a per-stream commit loses while
the log row exists, and the loser reads again and follows the log.

## Properties

- `NoLostWrite`: every collected write is pending, or in the registry.
- `NoSilentStale`: a gated device that has read the current registry and says
  `ok` shows everything the registry holds; no log it cannot read exists; no head
  lies beside the log.

## Results (TLC 2.19, `tla2tools.jar` 1.7.4, one job, `-workers 4`, nice 19)

| Config             | Gate | Fence | Devices            | Expected | Result                                                                                                       |
| ------------------ | ---- | ----- | ------------------ | -------- | ------------------------------------------------------------------------------------------------------------ |
| `Today`            | off  | off   | on, off, older-on  | FAIL     | `NoSilentStale` violated, depth 6 (`traces/Today.txt`): a flag-off device reads, says ok, and misses the log |
| `TodayOffReader`   | off  | off   | on, off, older-off | FAIL     | `NoSilentStale` violated, depth 6                                                                            |
| `GateOnly`         | on   | off   | on, off, off       | FAIL     | `NoSilentStale` violated, depth 9 (`traces/GateOnly.txt`): the check-then-write race                         |
| `GatePreGate`      | on   | off   | on, off, older-off | FAIL     | `NoSilentStale` violated, depth 9: a build without the gate writes a head beside the log                     |
| `GateFence`        | on   | on    | on, off, older-on  | PASS     | 13,654 states generated, 3,001 distinct, depth 18                                                            |
| `GateFenceOldOff`  | on   | on    | on, off, older-off | PASS     | 44,234 generated, 10,329 distinct, depth 22                                                                  |
| `GateFenceNewOnly` | on   | on    | on, off, off       | PASS     | 66,132 generated, 15,639 distinct, depth 24                                                                  |

The state counts of the FAIL rows are what TLC had reached when it stopped on
the violation; they change between runs of a parallel search. Each PASS row
searched its whole space (0 states left on queue).

The gate alone (`GateOnly`, `GatePreGate`) is not complete. It makes every gated
device follow the log or refuse, which removes the divergence between gated
devices that differ only in flag. The residual cases need the registry rule.

## Not modelled

Log content and ordering (see `../log-protocol`), compaction, generations and
deletes, more than three devices, device crashes between a commit and its local
write, and a registry that loses the log row (a restore).
