--------------------------- MODULE HeadCursor ---------------------------
(***************************************************************************)
(* A per-stream registry head committed BEFORE the log exists, a device    *)
(* that turns the log on, and the number the apply skip rule reads.        *)
(*                                                                         *)
(* One stream. A device keeps `lver`, the local head_version. Log rounds   *)
(* (a writer's own rounds and a reader's applied segments) add one to it.  *)
(* `cons` is the version of the last registry head the device consumed.    *)
(*                                                                         *)
(* Mode "today":   skip a registry head when lver > its version.           *)
(* Mode "todayRebase": today's skip rule, plus the log replay from position 0 *)
(*                 after a head is admitted. It isolates the skip rule.    *)
(* Mode "fixed":   skip it only when its version is <= cons (consumed or   *)
(*                 older than a consumed head); admitting an unseen head   *)
(*                 sets cons and restarts the log replay from position 0.  *)
(* Mode "fixedNoRebase": the same skip rule, no replay after admission.    *)
(*                                                                         *)
(* Mode "fixedSplit": the fixed rule, but the head step and the log step are *)
(*                 two operations (a single-stream apply returns after the  *)
(*                 head step). InvReplayed refuses the state between them.  *)
(*                                                                         *)
(* A row is [rank, live]. The larger rank wins; live=FALSE is a tombstone. *)
(* A head apply merges the head's rows, then drops the rows the head does  *)
(* not hold whose rank is <= the head's cutoff (applyDelete/omission).     *)
(* Pending unpublished local changes are not modelled.                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC
CONSTANTS Mode
ASSUME Mode \in {"today","todayRebase","fixed","fixedNoRebase","fixedSplit"}

Devices == {"A","C","R"}   \* A: log writer. C: reader. R: reader that starts late.
Keys == {1,2,3}            \* 1 = x (in both heads), 2 = z (only in head 2), 3 = a (A's own)
Empty == [k \in Keys |-> [rank |-> 0, live |-> FALSE]]
Row(r,l) == [rank |-> r, live |-> l]

\* Head v1 holds x. Head v2, committed by another device, adds z at rank 4.
Heads == << [ver |-> 1, rows |-> (1 :> Row(1,TRUE)) ,
             cutoff |-> 1],
            [ver |-> 2, rows |-> (1 :> Row(1,TRUE)) @@ (2 :> Row(4,TRUE)),
             cutoff |-> 4] >>
\* The log writer's two rounds: a new key a at rank 2, then a delete of x at rank 5.
Rounds == << (3 :> Row(2,TRUE)), (1 :> Row(5,FALSE)) >>

MergeRow(a,b) == IF b.rank > a.rank THEN b ELSE a
MergeRows(d, rows) ==
  [k \in Keys |-> IF k \in DOMAIN rows THEN MergeRow(d[k], rows[k]) ELSE d[k]]
\* Drop rows the head does not hold whose rank is <= its cutoff.
Omit(d, h) ==
  [k \in Keys |-> IF k \notin DOMAIN h.rows /\ d[k].rank > 0 /\ d[k].rank <= h.cutoff
                  THEN Empty[k] ELSE d[k]]
RECURSIVE FoldLog(_,_,_,_)
FoldLog(d, log, from, to) ==
  IF from > to THEN d ELSE FoldLog(MergeRows(d, log[from]), log, from+1, to)

VARIABLES regV, log, stopped, data, lver, cons, pos
vars == <<regV,log,stopped,data,lver,cons,pos>>

Init == /\ regV = 0 /\ log = <<>> /\ stopped = FALSE
        /\ data = [d \in Devices |-> Empty]
        /\ lver = [d \in Devices |-> 0] /\ cons = [d \in Devices |-> 0]
        /\ pos = [d \in Devices |-> 0]

\* Another device commits the next per-stream head. The gateway refuses it once the log exists.
CommitHead ==
  /\ ~stopped /\ regV < Len(Heads) /\ log = <<>>
  /\ regV' = regV + 1
  /\ UNCHANGED <<log,stopped,data,lver,cons,pos>>

\* The writer's next round: needs the writer caught up on the log. It is LOCAL work for the
\* device: it moves lver, not cons, and reads no registry head.
LogRound ==
  /\ ~stopped /\ Len(log) < Len(Rounds) /\ pos["A"] = Len(log)
  /\ log' = Append(log, Rounds[Len(log)+1])
  /\ data' = [data EXCEPT !["A"] = MergeRows(@, Rounds[Len(log)+1])]
  /\ lver' = [lver EXCEPT !["A"] = @ + 1]
  /\ pos' = [pos EXCEPT !["A"] = Len(log) + 1]
  /\ UNCHANGED <<regV,stopped,cons>>

Skip(d) == IF Mode \in {"today","todayRebase"} THEN lver[d] > regV ELSE regV <= cons[d]

\* One apply job: the registry head first, then the log from the device's position.
HeadStep(d) ==
  LET h == Heads[regV]
      admit == regV > 0 /\ ~Skip(d)
      d1 == IF admit THEN MergeRows(Omit(data[d], h), h.rows) ELSE data[d]
      lver1 == IF admit THEN (IF Mode \in {"today","todayRebase"} \/ lver[d] < regV THEN regV ELSE lver[d] + 1)
               ELSE lver[d]
      cons1 == IF admit THEN regV ELSE cons[d]
      pos1 == IF admit /\ Mode \in {"fixed","fixedSplit","todayRebase"} THEN 0 ELSE pos[d]
  IN [d1 |-> d1, lver1 |-> lver1, cons1 |-> cons1, pos1 |-> pos1]
LogStep(d, hs) ==
  [d2 |-> FoldLog(hs.d1, log, hs.pos1 + 1, Len(log)),
   lver2 |-> hs.lver1 + (Len(log) - hs.pos1)]
Apply(d) ==
  LET hs == HeadStep(d)
      ls == LogStep(d, hs)
  IN /\ Mode # "fixedSplit"
     /\ data' = [data EXCEPT ![d] = ls.d2]
     /\ lver' = [lver EXCEPT ![d] = ls.lver2]
     /\ cons' = [cons EXCEPT ![d] = hs.cons1]
     /\ pos' = [pos EXCEPT ![d] = Len(log)]
     /\ data' # data \/ lver' # lver \/ cons' # cons \/ pos' # pos
     /\ UNCHANGED <<regV,log,stopped>>
\* fixedSplit: a single-stream apply admits the head and returns.
ApplyHead(d) ==
  LET hs == HeadStep(d)
  IN /\ Mode = "fixedSplit"
     /\ data' = [data EXCEPT ![d] = hs.d1]
     /\ lver' = [lver EXCEPT ![d] = hs.lver1]
     /\ cons' = [cons EXCEPT ![d] = hs.cons1]
     /\ pos' = [pos EXCEPT ![d] = hs.pos1]
     /\ data' # data \/ lver' # lver \/ cons' # cons \/ pos' # pos
     /\ UNCHANGED <<regV,log,stopped>>
ApplyLogOnly(d) ==
  LET ls == LogStep(d, [d1 |-> data[d], lver1 |-> lver[d], pos1 |-> pos[d]])
  IN /\ Mode = "fixedSplit" /\ pos[d] < Len(log)
     /\ data' = [data EXCEPT ![d] = ls.d2]
     /\ lver' = [lver EXCEPT ![d] = ls.lver2]
     /\ pos' = [pos EXCEPT ![d] = Len(log)]
     /\ UNCHANGED <<regV,log,stopped,cons>>

Stop == ~stopped /\ stopped' = TRUE /\ UNCHANGED <<regV,log,data,lver,cons,pos>>

Next == CommitHead \/ LogRound \/ Stop \/ \E d \in Devices : Apply(d) \/ ApplyHead(d) \/ ApplyLogOnly(d)
Spec == Init /\ [][Next]_vars /\ WF_vars(Stop) /\ \A d \in Devices : WF_vars(Apply(d)) /\ WF_vars(ApplyHead(d)) /\ WF_vars(ApplyLogOnly(d))

\* What a device that reads head and log from nothing holds.
Truth == IF regV = 0 THEN FoldLog(Empty, log, 1, Len(log))
         ELSE FoldLog(MergeRows(Omit(Empty, Heads[regV]), Heads[regV].rows), log, 1, Len(log))
\* After the writers stop and every device has read, all hold the same rows.
EventuallyConverged == <>[](stopped /\ \A d \in Devices : data[d] = Truth)
\* A device that holds the current head holds the head's rows with the log's rows
\* of its position over them: no state keeps the head and lacks the replay.
InvReplayed ==
  \A d \in Devices : (regV > 0 /\ cons[d] = regV) =>
     data[d] = FoldLog(MergeRows(Omit(Empty, Heads[regV]), Heads[regV].rows), log, 1, pos[d])
TypeOK == /\ regV \in 0..Len(Heads) /\ Len(log) <= Len(Rounds)
          /\ \A d \in Devices : lver[d] \in Nat /\ cons[d] \in 0..Len(Heads)
=============================================================================
