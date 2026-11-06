----------------------- MODULE StreamSyncConformance -----------------------
(***************************************************************************)
(* Trace export for the conformance harness (conformance/README.md).      *)
(*                                                                         *)
(* This module adds no variables and no actions, so TLC reports the       *)
(* model's own action names.  It adds:                                     *)
(*   - TraceAlias: the ALIAS that `-dumpTrace json` writes for each state. *)
(*     It holds the variables the replay reads, plus model operators      *)
(*     evaluated in that state (the admission table, liveness, reads and  *)
(*     readiness), so the replay never re-implements them.                *)
(*   - SimEnd: the end of a simulated behaviour (every run started and   *)
(*     every outbox entry finished, discarded or kept pending).            *)
(*     Simulation reports it as an invariant violation, which makes TLC   *)
(*     dump the behaviour.                                                 *)
(*   - Witness states for the fixed traces.                                *)
(***************************************************************************)
EXTENDS StreamSync

\* The admission table as device d acts on it, with its two inputs.
NoState == [k |-> "none", g |-> 0]
XDev(d) ==
  IF ob[d] = NoEntry
  THEN [t |-> 0, S |-> NoState, C |-> NoState, key |-> Key(d)]
  ELSE [t |-> EffTable(d, ob[d]), S |-> EffStart(d, ob[d]),
        C |-> CtlNow(ob[d].n, Key(d)), key |-> Key(d)]

\* Registry view of a reader (owner key k1) on the current registry state.
XReg(n) ==
  [ctl   |-> StP(Lens, n),
   liveP |-> [s \in Streams |-> LiveP(Lens, n, s)],
   live  |-> [s \in Streams |-> Live(n, s)],
   stamp |-> IF n \in LiveNS(Lens) THEN Stamp(Lens, n) ELSE -1]

\* eligible(c, name) and readiness for one legacy file and every name.
RdOut(L, name) ==
  [k     |-> Read(Lens, L, name)[1],
   vns   |-> ViewNS(Lens, name),
   ready |-> Readiness(Lens, L, name),
   file  |-> File(L, name).present]
RdAll(L) == [name \in Names |-> RdOut(L, name)]
LegAt(a, t) == [FileOf(a, "legacy", "none") EXCEPT !.at = t]
XRead ==
  [a \in {"none"} \cup Acct |->
     IF a = "none" THEN [old |-> RdAll(NoFile)]
     ELSE [old |-> RdAll(LegAt(a, 0)), new |-> RdAll(LegAt(a, clock + 1))]]

TraceAlias ==
  [ctl |-> ctl, hd |-> hd, ob |-> ob, ckpt |-> ckpt, needsFull |-> needsFull,
   rcpt |-> rcpt, seedTarget |-> seedTarget, rawF |-> rawF, listing |-> listing,
   known |-> known, stopped |-> stopped, login |-> login, inflight |-> inflight,
   clock |-> clock, cnt |-> cnt,
   xdev |-> [d \in Devices |-> XDev(d)],
   xreg |-> [n \in NS |-> XReg(n)],
   xsel |-> Sel(Lens),
   xdel |-> AnyDeletedP(Lens),
   xread |-> XRead]

\* End of a simulated behaviour: every run started, and every outbox entry
\* finished, discarded, or kept pending by the admission table (a pending
\* entry may wait forever, so a behaviour that ends only when every entry
\* is finished would never include one).
SimEnd ==
  ~(/\ cnt.runs = MaxRuns
    /\ \A d \in Devices : ob[d] = NoEntry \/ (~ob[d].dead /\ XDev(d).t = -1))

\* Fixed trace "split-run" (revision 4 counterexample): a userConnect run
\* committed a stream at generation 1, a delete landed, and another stream
\* of the run is still to decide.  Revision 4.1 must discard it.
NotSplitRunPoint ==
  ~\E d \in Devices :
     /\ ob[d] # NoEntry /\ ob[d].uc /\ Deleted(ob[d].n)
     /\ \E s \in Streams : ob[d].st[s] = "planned"
     /\ \E c \in commits : c[4] = ob[d].rid /\ c[3] = 1

\* Fixed trace "late-head": a stream bound to T has just made its base
\* decision while the latest stream row has a higher generation.  The last
\* step of the trace is that decision (publish onto an empty base, or
\* stale_generation where the model has it).
NotLateBasePoint ==
  ~\E d \in Devices, s \in Streams :
     /\ ob[d] # NoEntry /\ ob[d].T > 0 /\ ob[d].g[s] = ob[d].T
     /\ ob[d].st[s] \in {"posted", "planned"}
     /\ Latest(ob[d].n, s).g > ob[d].T
=============================================================================
