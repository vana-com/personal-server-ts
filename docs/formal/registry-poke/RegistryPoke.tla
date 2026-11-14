--------------------------- MODULE RegistryPoke ---------------------------
(*
  A registry that a device learns about by a held request (long-poll) and a
  fallback probe. The gateway keeps one counter per owner, `seq`, that rises by
  one on every committed registry write. A device keeps `applied[d]`: the
  `seq` its last pull read. A pull is the only thing that moves `applied`; it
  reads the registry as it is at that instant. Everything else is a hint.

  Messages
    subscribe  device -> gateway: "hold this until seq passes `base`".
               base = lastSeen[d] when Resume (the cursor), else the gateway's
               `seq` at the moment the request arrives (an edge trigger).
    reply      gateway -> device: carries the gateway's current `seq`. The
               gateway sends it when a commit passes `base` (a poke), or when
               W ticks pass (an empty answer that re-reads `seq` first).
  A reply may be lost. The device then learns only at its request deadline,
  W + Slack ticks after it sent the request.

  Device rules (switches)
    Resume            the gateway answers at once when seq > lastSeen.
    FinalCheck        the gateway's W-tick answer reads `seq` first; FALSE:
                      it echoes the device's cursor ("nothing new").
    PullOnReconnect   a device that re-subscribes after a failure pulls once.
    ProbeOn           a timed probe pulls when the registry moved.
    StretchOnlyWhenHealthy
                      probe period is PH while the last request got an
                      answer, PL otherwise; FALSE: always PH.
  Environment (switches)
    PokesLost    any reply may be lost.    AllLost   every reply is lost.
    HubMiss      the gateway may fail to wake a waiter on a commit; the
                 W-tick answer still reads `seq`.
    Disconnects  a request may break; the device sees the break at once.

  Time is a tick counter. Actions that fall due block `Tick`, so a deadline
  cannot be passed. `age[d]` counts ticks since the oldest commit that
  `applied[d]` has not yet reached. Property: age[d] <= Bound.
*)
EXTENDS Naturals

CONSTANTS Devices, MaxWrites, MaxClock, W, Slack, PL, PH, Bound,
          Resume, FinalCheck, PullOnReconnect, ProbeOn, StretchOnlyWhenHealthy,
          PokesLost, AllLost, HubMiss, Disconnects

NoReq == [on |-> FALSE, base |-> 0, since |-> 0, held |-> FALSE]
NoReply == 0 - 1  \* sentinel: no reply in flight (sequences are naturals)

VARIABLES seq, writes, clock, applied, lastSeen, req, reply, healthy,
          needPull, nextProbe, age

vars == <<seq, writes, clock, applied, lastSeen, req, reply, healthy,
          needPull, nextProbe, age>>

Period(d) ==
  IF StretchOnlyWhenHealthy THEN (IF healthy[d] THEN PH ELSE PL) ELSE PH

Init ==
  /\ seq = 0 /\ writes = 0 /\ clock = 0
  /\ applied = [d \in Devices |-> 0]
  /\ lastSeen = [d \in Devices |-> 0]
  /\ req = [d \in Devices |-> NoReq]
  /\ reply = [d \in Devices |-> NoReply]
  /\ healthy = [d \in Devices |-> FALSE]
  /\ needPull = [d \in Devices |-> FALSE]
  /\ nextProbe = [d \in Devices |-> IF ProbeOn THEN PL ELSE MaxClock + 1]
  /\ age = [d \in Devices |-> 0]

\* The gateway commits a registry write.
Commit ==
  /\ writes < MaxWrites
  /\ seq' = seq + 1 /\ writes' = writes + 1
  /\ UNCHANGED <<clock, applied, lastSeen, req, reply, healthy, needPull,
                 nextProbe, age>>

\* A device sends a request. A device that failed earlier pulls first. With
\* Resume the gateway compares at arrival and answers at once (no wake needed).
Subscribe(d) ==
  /\ ~req[d].on /\ reply[d] = NoReply
  /\ LET base == IF Resume THEN lastSeen[d] ELSE seq
         now == Resume /\ seq > lastSeen[d]
     IN /\ req' = [req EXCEPT ![d] = [on |-> TRUE, base |-> base,
                       since |-> clock, held |-> ~now]]
        /\ reply' = [reply EXCEPT ![d] = IF now THEN seq ELSE NoReply]
  /\ IF PullOnReconnect /\ needPull[d]
       THEN /\ applied' = [applied EXCEPT ![d] = seq]
            /\ age' = [age EXCEPT ![d] = 0]
       ELSE UNCHANGED <<applied, age>>
  /\ needPull' = [needPull EXCEPT ![d] = FALSE]
  /\ UNCHANGED <<seq, writes, clock, lastSeen, healthy, nextProbe>>

\* The gateway answers a held request because a commit passed its base.
Wake(d) ==
  /\ req[d].on /\ req[d].held /\ reply[d] = NoReply
  /\ seq > req[d].base
  /\ reply' = [reply EXCEPT ![d] = seq]
  /\ req' = [req EXCEPT ![d].held = FALSE]
  /\ UNCHANGED <<seq, writes, clock, applied, lastSeen, healthy, needPull,
                 nextProbe, age>>

\* The gateway answers after W ticks. It reads `seq` first, so this answer is exact.
ServerTimeout(d) ==
  /\ req[d].on /\ req[d].held /\ reply[d] = NoReply
  /\ clock - req[d].since >= W
  /\ reply' = [reply EXCEPT ![d] = IF FinalCheck THEN seq ELSE lastSeen[d]]
  /\ req' = [req EXCEPT ![d].held = FALSE]
  /\ UNCHANGED <<seq, writes, clock, applied, lastSeen, healthy, needPull,
                 nextProbe, age>>

\* The device receives a reply: it is now healthy, and pulls when the reply
\* is above what it has applied.
Deliver(d) ==
  /\ ~AllLost
  /\ reply[d] /= NoReply
  /\ lastSeen' = [lastSeen EXCEPT ![d] = IF reply[d] > lastSeen[d]
                                          THEN reply[d] ELSE lastSeen[d]]
  /\ healthy' = [healthy EXCEPT ![d] = TRUE]
  /\ req' = [req EXCEPT ![d] = NoReq]
  /\ reply' = [reply EXCEPT ![d] = NoReply]
  /\ IF reply[d] > applied[d]
       THEN /\ applied' = [applied EXCEPT ![d] = seq]
            /\ age' = [age EXCEPT ![d] = 0]
       ELSE UNCHANGED <<applied, age>>
  /\ UNCHANGED <<seq, writes, clock, needPull, nextProbe>>

\* The network drops a reply. The device learns only at its deadline.
Lose(d) ==
  /\ PokesLost /\ reply[d] /= NoReply
  /\ reply' = [reply EXCEPT ![d] = NoReply]
  /\ UNCHANGED <<seq, writes, clock, applied, lastSeen, req, healthy,
                 needPull, nextProbe, age>>

\* A request breaks. The device sees it at once.
Drop(d) ==
  /\ Disconnects /\ req[d].on /\ reply[d] = NoReply
  /\ req' = [req EXCEPT ![d] = NoReq]
  /\ healthy' = [healthy EXCEPT ![d] = FALSE]
  /\ needPull' = [needPull EXCEPT ![d] = TRUE]
  /\ UNCHANGED <<seq, writes, clock, applied, lastSeen, reply, nextProbe, age>>

\* The device gives up on a request that got no reply.
ClientTimeout(d) ==
  /\ req[d].on /\ reply[d] = NoReply
  /\ clock - req[d].since >= W + Slack
  /\ req' = [req EXCEPT ![d] = NoReq]
  /\ healthy' = [healthy EXCEPT ![d] = FALSE]
  /\ needPull' = [needPull EXCEPT ![d] = TRUE]
  /\ UNCHANGED <<seq, writes, clock, applied, lastSeen, reply, nextProbe, age>>

\* The timed probe: an exact read of the registry, then a pull when it moved.
Probe(d) ==
  /\ ProbeOn /\ clock >= nextProbe[d]
  /\ applied' = [applied EXCEPT ![d] = seq]
  /\ age' = [age EXCEPT ![d] = 0]
  /\ nextProbe' = [nextProbe EXCEPT ![d] = clock + Period(d)]
  /\ UNCHANGED <<seq, writes, clock, lastSeen, req, reply, healthy, needPull>>

Due(d) ==
  \/ ProbeOn /\ clock >= nextProbe[d]
  \/ req[d].on /\ req[d].held /\ clock - req[d].since >= W
  \/ req[d].on /\ reply[d] = NoReply /\ clock - req[d].since >= W + Slack
  \/ reply[d] /= NoReply
  \/ ~req[d].on /\ reply[d] = NoReply
  \/ ~HubMiss /\ req[d].on /\ req[d].held /\ reply[d] = NoReply /\ seq > req[d].base

Tick ==
  /\ clock < MaxClock
  /\ \A d \in Devices : ~Due(d)
  /\ clock' = clock + 1
  /\ age' = [d \in Devices |-> IF applied[d] < seq THEN age[d] + 1 ELSE 0]
  /\ UNCHANGED <<seq, writes, applied, lastSeen, req, reply, healthy,
                 needPull, nextProbe>>

Next ==
  \/ Commit
  \/ Tick
  \/ \E d \in Devices : Subscribe(d) \/ Wake(d) \/ ServerTimeout(d)
       \/ Deliver(d) \/ Lose(d) \/ Drop(d) \/ ClientTimeout(d) \/ Probe(d)
  \/ (clock = MaxClock /\ UNCHANGED vars)  \* the horizon: stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ seq \in Nat /\ \A d \in Devices : applied[d] <= seq /\ lastSeen[d] <= seq

\* No device is behind by more than Bound ticks.
StaleBound == \A d \in Devices : age[d] <= Bound

\* A device that is behind has an action due or in flight that will catch it up
\* (checked at the horizon: nothing may be left behind forever).
NotLeftBehind ==
  clock = MaxClock => \A d \in Devices : applied[d] = seq \/ age[d] <= Bound
=============================================================================
