--------------------- MODULE StreamSyncConformanceR3 ---------------------
(***************************************************************************)
(* Witnesses for model revisions from ruling R3 on (the NoOpNeedsFull     *)
(* guard and the `seen` and `fin` fields).  Kept apart from               *)
(* StreamSyncConformance so that the trace export still loads older       *)
(* revisions.                                                              *)
(***************************************************************************)
EXTENDS StreamSyncConformance

\* Fixed trace "stale-generation": a stream bound to T has just read a
\* stream row of a higher generation and stopped (PlanStale, ruling F1).
NotStaleGenPoint ==
  ~\E d \in Devices, s \in Streams :
     /\ ob[d] # NoEntry /\ ob[d].st[s] = "planned" /\ ob[d].req[s] = NoReq
     /\ ob[d].g[s] > 0 /\ ob[d].T = ob[d].g[s]
     /\ ~IsTomb(Latest(ob[d].n, s)) /\ Latest(ob[d].n, s).g > ob[d].g[s]

\* Fixed trace "q9-noop": a run has just counted a stream as a no-op onto
\* a complete:false head of its generation T that another run wrote.
NotQ9NoopPoint ==
  ~\E d \in Devices, s \in Streams :
     /\ ob[d] # NoEntry /\ ob[d].st[s] = "done" /\ ob[d].seen[s] > 0
     /\ LET h == hd[ob[d].n][s][ob[d].seen[s]] IN
          /\ ~IsTomb(h) /\ h.g = ob[d].T /\ ~h.complete /\ h.at # ob[d].rid

\* Fixed trace "incomplete-plan-lost-to-409": a run has just finished with
\* control active(T), its seed receipts in place and every stream row it
\* saw complete, yet holds no checkpoint.
NotSkipAllCompletePoint ==
  ~\E d \in Devices :
     LET f == fin[d] IN
     /\ ob[d] = NoEntry /\ f.n # "none" /\ ckpt[d] = NoCk
     /\ CtlNow(f.n, Key(d)) = [k |-> "active", g |-> f.T]
     /\ (d = Desktop /\ f.n = seedTarget) => \A s \in Streams : <<f.n, s>> \in rcpt
     /\ \E s \in Streams : f.seen[s] > 0
     /\ \A s \in Streams :
          f.seen[s] > 0 =>
            /\ Len(hd[f.n][s]) >= f.seen[s]
            /\ ~IsTomb(hd[f.n][s][f.seen[s]])
            /\ hd[f.n][s][f.seen[s]].complete
=============================================================================
