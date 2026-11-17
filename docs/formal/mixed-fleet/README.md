# Mixed fleet: one connection, devices that differ in build and log flag

> **Status: historical.** The `logProtocol` flag and the per-stream head writer
> are removed: the connection log is the only publish and read protocol, so no
> device writes a head beside the log and a mixed fleet of flag settings no
> longer exists. The model and its traces stay as the record of why the gate
> was needed while both protocols ran. A device that holds only old heads
> reads nothing from them; its first log publish carries every record it holds.

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
A client cannot stop either: the registry accepts only conditions of the form
"this row has this version"; there is no condition "this row is absent".
`Fence = TRUE` models the missing rule: a per-stream commit loses while the log
row exists, and the loser reads again and follows the log.

The data gateway implements it (a stream row `pdpp.<connector>~[<ns>].<stream>`
loses with 409 `connection-log-exists` while `pdpp.<connector>~[<ns>].~log`
exists; a tombstone is never fenced). The check and the commit are atomic:
the fenced writer takes the shared form of the log row's per-scope advisory
lock, which the log writer already takes exclusively before it writes.

### Why not a client-only closure (`HeadCond`)

`HeadCond = TRUE` models the strongest closure a client can build from the
registry's positive conditions: the first log write requires every stream head
it read to be unchanged. `GateHeadCondNewOnly` and `GateHeadCondOldOff` show it
is not enough, for two reasons that each stand alone:

- It constrains only the device that creates the log. The racing per-stream
  write is the other device's, and it carries no condition on the log
  (`traces/GateHeadCondNewOnly.txt`: both devices read, the log is created over
  unchanged heads, the other commits its head late). It closes one order of the
  race and not the other.
- It binds only builds that send the condition. A build without the gate never
  reads the log row and never sends it (`GateHeadCondOldOff`).

Only the registry sees every writer, so only a registry rule closes every
interleaving.

## Properties

- `NoLostWrite`: every collected write is pending, or in the registry.
- `NoSilentStale`: a gated device that has read the current registry and says
  `ok` shows everything the registry holds; no log it cannot read exists; no head
  lies beside the log.

## Results (TLC 2.19, `tla2tools.jar` 1.7.4, one job, `-workers 4`, nice 19)

| Config                | Gate | Fence | HeadCond | Devices            | Expected | Result                                                                                                       |
| --------------------- | ---- | ----- | -------- | ------------------ | -------- | ------------------------------------------------------------------------------------------------------------ |
| `Today`               | off  | off   | off      | on, off, older-on  | FAIL     | `NoSilentStale` violated, depth 6 (`traces/Today.txt`): a flag-off device reads, says ok, and misses the log |
| `TodayOffReader`      | off  | off   | off      | on, off, older-off | FAIL     | `NoSilentStale` violated, depth 6                                                                            |
| `GateOnly`            | on   | off   | off      | on, off, off       | FAIL     | `NoSilentStale` violated, depth 9 (`traces/GateOnly.txt`): the check-then-write race                         |
| `GatePreGate`         | on   | off   | off      | on, off, older-off | FAIL     | `NoSilentStale` violated, depth 9: a build without the gate writes a head beside the log                     |
| `GateHeadCondNewOnly` | on   | off   | on       | on, off, off       | FAIL     | `NoSilentStale` violated, depth 9 (`traces/GateHeadCondNewOnly.txt`): the racing head commits after the log  |
| `GateHeadCondOldOff`  | on   | off   | on       | on, off, older-off | FAIL     | `NoSilentStale` violated, depth 9: a build without the gate sends no condition                               |
| `GateFence`           | on   | on    | off      | on, off, older-on  | PASS     | 31,993 states generated, 6,776 distinct, depth 19                                                            |
| `GateFenceOldOff`     | on   | on    | off      | on, off, older-off | PASS     | 253,918 generated, 56,312 distinct, depth 22                                                                 |
| `GateFenceNewOnly`    | on   | on    | off      | on, off, off       | PASS     | 295,291 generated, 66,038 distinct, depth 24                                                                 |

The state counts of the FAIL rows are what TLC had reached when it stopped on
the violation; they change between runs of a parallel search. Each PASS row
searched its whole space (0 states left on queue).

The gate alone (`GateOnly`, `GatePreGate`) is not complete. It makes every gated
device follow the log or refuse, which removes the divergence between gated
devices that differ only in flag. The residual cases need the registry rule; a
client-only condition does not replace it (`GateHeadCond*`).

## Not modelled

Log content and ordering (see `../log-protocol`), compaction, generations and
deletes (the gateway fence does not apply to a tombstone, so a per-stream delete
from a build without the gate is not stopped, and not modelled), more than three devices, device crashes between a commit and its local
write, and a registry that loses the log row (a restore).
