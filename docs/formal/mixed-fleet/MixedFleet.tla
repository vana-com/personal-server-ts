---------------------------- MODULE MixedFleet ----------------------------
(***************************************************************************)
(* One connection, three devices of one owner, with different builds and   *)
(* local flags. The question: does a device that cannot read the log       *)
(* protocol ever show stale data as current, or write beside it?           *)
(*                                                                         *)
(* The registry holds, for the connection:                                 *)
(*   heads   writes published as per-stream heads (any build reads them)   *)
(*   log2    writes in the current log format                              *)
(*   log1    writes in the older log format (cannot be read by this core)  *)
(*   logFmt  what the log row holds: 0 none, 1 older, 2 current. The log   *)
(*           row IS the connection's recorded protocol: the first log      *)
(*           write creates it, and nothing removes it.                     *)
(*                                                                         *)
(* A device kind is one of                                                 *)
(*   newOn   this core, flag on: may start the log                         *)
(*   newOff  this core, flag off: may not start the log                    *)
(*   oldOff  an older build that never reads the log row, writes heads     *)
(*   oldOn   an older build that writes the older log format               *)
(*                                                                         *)
(* GateOn = TRUE is the proposed rule: a new core follows the log whenever *)
(* the row exists, whatever its flag; and refuses to write (status         *)
(* "update_required", the write stays pending) when the row is in a format *)
(* it cannot read. GateOn = FALSE is today's code: the flag decides.       *)
(*                                                                         *)
(* A head written after the log row exists (`late`) is outside the log.    *)
(* A device that follows the log does not fold it in: applying it either   *)
(* fails or replaces rows the log holds. Two writers can produce one: a    *)
(* build without the gate (oldOff), and a new core that read the registry  *)
(* just before another device's first log write (the race of a check      *)
(* before a write). A client cannot stop either: it has no condition on    *)
(* a row being absent. Fence = TRUE is the one registry rule that does:    *)
(* a per-stream commit loses while the log row exists (the gateway checks  *)
(* it in the commit's transaction); the loser reads the registry again and *)
(* follows the log. The model shows the gate is complete exactly with it.  *)
(*                                                                         *)
(* HeadCond = TRUE is the strongest client-only alternative: the first log *)
(* write requires the heads it read to be unchanged. It is not enough:     *)
(* it binds only the device that creates the log, and only a build that    *)
(* sends it (see the README).                                              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS K1, K2, K3,   \* the kind of device 1, 2, 3
          GateOn,       \* TRUE: the proposed gate
          Fence,        \* TRUE: the registry refuses a head commit once the log row exists
          HeadCond,     \* TRUE: a client-only closure: the first log write requires the
                        \*       heads it read to be unchanged (positive conditions only)
          Writes        \* writes each device collects (1 or 2)

Devs == 1..3
Kind == <<K1, K2, K3>>
IsNew(d) == Kind[d] \in {"newOn", "newOff"}
Id(d, k) == (d - 1) * Writes + k          \* the k-th write of device d
Ids == 1..(3 * Writes)

VARIABLES heads, late, log2, log1, logFmt,
          seenHeads, \* the heads a device read before its commit
          view,      \* write ids a device shows
          pend,      \* the write a device holds, not yet published
          nextK,     \* writes a device has collected
          seen,      \* logFmt a device read before its commit; -1 = none in flight
          stale,     \* the registry changed since the device last read it
          status     \* "ok", "update_required" or "error"

vars == <<heads, late, log2, log1, logFmt, seenHeads, view, pend, nextK, seen, stale, status>>

Collected == UNION {{Id(d, k) : k \in 1..(nextK[d] - 1)} : d \in Devs}
\* What a device that follows the log can show: the heads written before the
\* log row, and the log. `late` is read only by a device that reads heads alone.
Readable == heads \cup log2

TypeOK ==
  /\ heads \subseteq Ids /\ late \subseteq Ids /\ log2 \subseteq Ids /\ log1 \subseteq Ids
  /\ logFmt \in 0..2
  /\ \A d \in Devs : view[d] \subseteq Ids /\ pend[d] \subseteq Ids
  /\ \A d \in Devs : status[d] \in {"ok", "update_required", "error"}

Init ==
  /\ heads = {} /\ late = {} /\ log2 = {} /\ log1 = {} /\ logFmt = 0
  /\ seenHeads = [d \in Devs |-> {}]
  /\ view = [d \in Devs |-> {}]
  /\ pend = [d \in Devs |-> {}]
  /\ nextK = [d \in Devs |-> 1]
  /\ seen = [d \in Devs |-> -1]
  /\ stale = [d \in Devs |-> FALSE]
  /\ status = [d \in Devs |-> "ok"]

Collect(d) ==
  /\ nextK[d] <= Writes /\ pend[d] = {} /\ seen[d] = -1
  /\ pend' = [pend EXCEPT ![d] = {Id(d, nextK[d])}]
  /\ view' = [view EXCEPT ![d] = @ \cup {Id(d, nextK[d])}]
  /\ nextK' = [nextK EXCEPT ![d] = @ + 1]
  /\ UNCHANGED <<heads, late, log2, log1, logFmt, seenHeads, seen, stale, status>>

\* Does this device read the log row's content?
FollowsLog(d) ==
  IF GateOn THEN IsNew(d) ELSE Kind[d] = "newOn"

Read(d) ==
  /\ seen[d] = -1
  /\ view' = [view EXCEPT ![d] =
        @ \cup heads
          \cup (IF FollowsLog(d) \/ Kind[d] = "oldOn" THEN {} ELSE late)
          \cup (IF FollowsLog(d) /\ logFmt = 2 THEN log2 ELSE {})
          \cup (IF Kind[d] = "oldOn" /\ logFmt = 1 THEN log1 ELSE {})]
  /\ status' = [status EXCEPT ![d] =
        IF ~IsNew(d) THEN "ok"
        ELSE IF logFmt = 1 /\ GateOn THEN "update_required"
        ELSE IF logFmt = 1 /\ Kind[d] = "newOn" THEN "error"   \* today: the cycle throws
        ELSE "ok"]
  /\ stale' = [stale EXCEPT ![d] = FALSE]
  /\ UNCHANGED <<heads, late, log2, log1, logFmt, seenHeads, pend, nextK, seen>>

\* Writes go through the log when the device may start it or (gate) the row exists.
WritesLog(d, fmt) ==
  CASE Kind[d] = "oldOn" -> TRUE
    [] Kind[d] = "oldOff" -> FALSE
    [] OTHER -> IF GateOn THEN (Kind[d] = "newOn" \/ fmt = 2) ELSE Kind[d] = "newOn"

\* The device reads the registry's log row, then decides.
PubRead(d) ==
  /\ pend[d] # {} /\ seen[d] = -1
  /\ IF GateOn /\ IsNew(d) /\ logFmt = 1
       THEN \* cannot read the log: refuse, keep the write pending, say so
            /\ status' = [status EXCEPT ![d] = "update_required"]
            /\ UNCHANGED seen
       ELSE /\ seen' = [seen EXCEPT ![d] = logFmt]
            /\ UNCHANGED status
  /\ seenHeads' = [seenHeads EXCEPT ![d] = heads]
  /\ UNCHANGED <<heads, late, log2, log1, logFmt, view, pend, nextK, stale>>

OthersStale(d) == [e \in Devs |-> IF e = d THEN stale[e] ELSE TRUE]

\* One commit. A log commit is a compare-and-set on the log position: it loses
\* when the log is in another format or the writer has not applied it.
PubCommit(d) ==
  /\ seen[d] # -1
  /\ LET fmt == seen[d] IN
     IF WritesLog(d, fmt)
     THEN LET mine == IF Kind[d] = "oldOn" THEN 1 ELSE 2 IN
          IF /\ logFmt \in {0, mine} /\ (mine = 1 \/ log2 \subseteq view[d])
             \* HeadCond: creating the log is conditional on the heads it read (a
             \* head's version moved => the condition fails). Positive conditions
             \* only: it cannot say "no head will be written after me".
             /\ (~HeadCond \/ logFmt # 0 \/ heads = seenHeads[d])
          THEN /\ logFmt' = mine
               /\ log1' = IF mine = 1 THEN log1 \cup pend[d] ELSE log1
               /\ log2' = IF mine = 2 THEN log2 \cup pend[d] ELSE log2
               /\ UNCHANGED <<heads, late>>
               /\ pend' = [pend EXCEPT ![d] = {}]
               /\ stale' = OthersStale(d)
               /\ UNCHANGED status
          ELSE \* lost the compare-and-set: nothing written, the write stays
               /\ UNCHANGED <<heads, late, log2, log1, logFmt, pend, stale, status>>
     ELSE IF Fence /\ logFmt # 0
          THEN \* the registry refuses the head: nothing written, the write stays
               /\ UNCHANGED <<heads, late, log2, log1, logFmt, pend, stale, status>>
          ELSE /\ IF logFmt = 0
                  THEN /\ heads' = heads \cup pend[d] /\ UNCHANGED late
                  ELSE /\ late' = late \cup pend[d] /\ UNCHANGED heads
               /\ pend' = [pend EXCEPT ![d] = {}]
               /\ stale' = OthersStale(d)
               /\ UNCHANGED <<log2, log1, logFmt, status>>
  /\ seen' = [seen EXCEPT ![d] = -1]
  /\ UNCHANGED <<view, nextK, seenHeads>>

Next == \E d \in Devs : Collect(d) \/ Read(d) \/ PubRead(d) \/ PubCommit(d)

Spec == Init /\ [][Next]_vars

\* Every write a device collected is held or published; none is dropped.
NoLostWrite ==
  \A i \in Collected : \E d \in Devs : i \in pend[d]
    \/ i \in heads \/ i \in late \/ i \in log1 \/ i \in log2

\* A new-core device that has read the current registry and says "ok" shows
\* everything the registry holds, and no log it cannot read and no head beside
\* the log exists. It never shows stale data as current.
NoSilentStale ==
  \A d \in Devs : (IsNew(d) /\ ~stale[d] /\ status[d] = "ok") =>
    (log1 = {} /\ late = {} /\ Readable \subseteq view[d])

\* A new-core device never writes into a log it cannot read.
NoWriteBesideUnreadable ==
  log1 # {} => \A d \in Devs :
    (IsNew(d) /\ pend[d] # {} /\ seen[d] # -1) => seen[d] # 1
=============================================================================
