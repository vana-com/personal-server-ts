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
(* Modes "durable" and "memory" model the commit rules of the code: the   *)
(* head batch (omission, consumed identity, cursor reset) is one step; the *)
(* log pass is a later step, so a crash or a failed first log read can lie *)
(* between them (`Replay` need not follow `AdmitHead`). Registry rollbacks *)
(* (`Rollback`, then rounds of another history) are modelled.              *)
(* "durable": the head batch also writes a replay obligation `owed` and    *)
(*                 the previous cursor (`evPos`,`evId`) as continuity      *)
(*                 evidence, whether or not a cursor row existed. `Replay` *)
(*                 validates the registry against cursor AND evidence and  *)
(*                 clears both only after a validated replay.              *)
(* "memory":  the obligation is held only for a device that had a cursor, *)
(*                 only in memory (`MemCrash` loses it), and the cursor row *)
(*                 (and its evidence) is deleted with the head.            *)
(*                                                                         *)
(* A row is [rank, live]. The larger rank wins; live=FALSE is a tombstone. *)
(* A head apply merges the head's rows, then drops the rows the head does  *)
(* not hold whose rank is <= the head's cutoff (applyDelete/omission).     *)
(* Pending unpublished local changes are not modelled.                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC
CONSTANTS Mode, AllowRollback
ASSUME Mode \in {"today","todayRebase","fixed","fixedNoRebase","fixedSplit","durable","memory"}
ASSUME AllowRollback \in BOOLEAN
NewModes == {"durable","memory"}

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

VARIABLES regV, log, stopped, data, lver, cons, pos,
          logIds, rolled, owed, evPos, evId, pid, hwPos, hwId
\* What the commit rules add. `logIds[i]` names the history entry i belongs to
\* ("m" main, "f" a log that grew again after a rollback); `pid[d]` is the id of
\* the entry at the device's position; `hw*` is a ghost: the highest position
\* the device ever applied, with its id.
extra == <<logIds,rolled,owed,evPos,evId,pid,hwPos,hwId>>
vars == <<regV,log,stopped,data,lver,cons,pos,logIds,rolled,owed,evPos,evId,pid,hwPos,hwId>>

Init == /\ regV = 0 /\ log = <<>> /\ stopped = FALSE
        /\ data = [d \in Devices |-> Empty]
        /\ lver = [d \in Devices |-> 0] /\ cons = [d \in Devices |-> 0]
        /\ pos = [d \in Devices |-> 0]
        /\ logIds = <<>> /\ rolled = FALSE
        /\ owed = [d \in Devices |-> FALSE]
        /\ evPos = [d \in Devices |-> 0] /\ evId = [d \in Devices |-> "-"]
        /\ pid = [d \in Devices |-> "-"]
        /\ hwPos = [d \in Devices |-> 0] /\ hwId = [d \in Devices |-> "-"]

\* Another device commits the next per-stream head. The gateway refuses it once the log exists.
CommitHead ==
  /\ ~stopped /\ regV < Len(Heads) /\ log = <<>>
  /\ regV' = regV + 1
  /\ UNCHANGED <<log,stopped,data,lver,cons,pos,logIds,rolled,owed,evPos,evId,pid,hwPos,hwId>>

\* The writer's next round: needs the writer caught up on the log. It is LOCAL work for the
\* device: it moves lver, not cons, and reads no registry head.
LogRound ==
  /\ ~stopped /\ Len(log) < Len(Rounds) /\ pos["A"] = Len(log)
  /\ log' = Append(log, Rounds[Len(log)+1])
  /\ data' = [data EXCEPT !["A"] = MergeRows(@, Rounds[Len(log)+1])]
  /\ lver' = [lver EXCEPT !["A"] = @ + 1]
  /\ pos' = [pos EXCEPT !["A"] = Len(log) + 1]
  /\ logIds' = Append(logIds, "m")
  /\ pid' = [pid EXCEPT !["A"] = "m"]
  /\ hwPos' = [hwPos EXCEPT !["A"] = Len(log) + 1]
  /\ hwId' = [hwId EXCEPT !["A"] = "m"]
  /\ UNCHANGED <<regV,stopped,cons,rolled,owed,evPos,evId>>

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
  IN /\ Mode # "fixedSplit" /\ Mode \notin NewModes
     /\ data' = [data EXCEPT ![d] = ls.d2]
     /\ lver' = [lver EXCEPT ![d] = ls.lver2]
     /\ cons' = [cons EXCEPT ![d] = hs.cons1]
     /\ pos' = [pos EXCEPT ![d] = Len(log)]
     /\ data' # data \/ lver' # lver \/ cons' # cons \/ pos' # pos
     /\ UNCHANGED <<regV,log,stopped,extra>>
\* fixedSplit: a single-stream apply admits the head and returns.
ApplyHead(d) ==
  LET hs == HeadStep(d)
  IN /\ Mode = "fixedSplit"
     /\ data' = [data EXCEPT ![d] = hs.d1]
     /\ lver' = [lver EXCEPT ![d] = hs.lver1]
     /\ cons' = [cons EXCEPT ![d] = hs.cons1]
     /\ pos' = [pos EXCEPT ![d] = hs.pos1]
     /\ data' # data \/ lver' # lver \/ cons' # cons \/ pos' # pos
     /\ UNCHANGED <<regV,log,stopped,extra>>
ApplyLogOnly(d) ==
  LET ls == LogStep(d, [d1 |-> data[d], lver1 |-> lver[d], pos1 |-> pos[d]])
  IN /\ Mode = "fixedSplit" /\ pos[d] < Len(log)
     /\ data' = [data EXCEPT ![d] = ls.d2]
     /\ lver' = [lver EXCEPT ![d] = ls.lver2]
     /\ pos' = [pos EXCEPT ![d] = Len(log)]
     /\ UNCHANGED <<regV,log,stopped,cons,extra>>

\* The device's cursor and its continuity evidence both fit the registry's log:
\* the log reaches the held position on the same history.
Valid(d) ==
  /\ Len(log) >= pos[d] /\ IF pos[d] = 0 THEN TRUE ELSE logIds[pos[d]] = pid[d]
  /\ Len(log) >= evPos[d] /\ IF evPos[d] = 0 THEN TRUE ELSE logIds[evPos[d]] = evId[d]

\* The head batch: omission, consumed identity and cursor reset are one write. In
\* "durable" it also writes the obligation and the previous cursor as evidence
\* (kept if one is already held), for a device with a cursor row or without.
\* The registry log is read just before the batch (`Valid`).
AdmitHead(d) ==
  LET hs == HeadStep(d)
      useCursor == pos[d] > evPos[d]
  IN /\ Mode \in NewModes /\ regV > 0 /\ ~Skip(d)
     /\ (Mode = "memory" \/ Valid(d))
     /\ data' = [data EXCEPT ![d] = hs.d1]
     /\ lver' = [lver EXCEPT ![d] = hs.lver1]
     /\ cons' = [cons EXCEPT ![d] = hs.cons1]
     /\ pos' = [pos EXCEPT ![d] = 0]
     /\ pid' = [pid EXCEPT ![d] = "-"]
     /\ owed' = [owed EXCEPT ![d] = IF Mode = "durable" THEN TRUE ELSE pos[d] > 0]
     /\ evPos' = [evPos EXCEPT ![d] = IF Mode = "durable" /\ useCursor THEN pos[d]
                                      ELSE IF Mode = "durable" THEN evPos[d] ELSE 0]
     /\ evId' = [evId EXCEPT ![d] = IF Mode = "durable" /\ useCursor THEN pid[d]
                                    ELSE IF Mode = "durable" THEN evId[d] ELSE "-"]
     /\ UNCHANGED <<regV,log,stopped,logIds,rolled,hwPos,hwId>>

\* The log pass: runs whenever the obligation exists or the log is ahead; refuses
\* a registry that does not fit cursor and evidence; clears both after a
\* validated replay.
Replay(d) ==
  LET n == Len(log)
  IN /\ Mode \in NewModes /\ (owed[d] \/ pos[d] < n) /\ Valid(d)
     /\ data' = [data EXCEPT ![d] = FoldLog(@, log, pos[d] + 1, n)]
     /\ lver' = [lver EXCEPT ![d] = @ + (n - pos[d])]
     /\ pos' = [pos EXCEPT ![d] = n]
     /\ pid' = [pid EXCEPT ![d] = IF n = 0 THEN "-" ELSE logIds[n]]
     /\ hwPos' = [hwPos EXCEPT ![d] = IF n >= @ THEN n ELSE @]
     /\ hwId' = [hwId EXCEPT ![d] = IF n >= hwPos[d] /\ n > 0 THEN logIds[n] ELSE @]
     /\ owed' = [owed EXCEPT ![d] = FALSE]
     /\ evPos' = [evPos EXCEPT ![d] = 0] /\ evId' = [evId EXCEPT ![d] = "-"]
     /\ UNCHANGED <<regV,log,stopped,cons,logIds,rolled>>

\* A crash loses what lives only in memory.
MemCrash(d) ==
  /\ Mode = "memory" /\ owed[d]
  /\ owed' = [owed EXCEPT ![d] = FALSE]
  /\ UNCHANGED <<regV,log,stopped,data,lver,cons,pos,logIds,rolled,evPos,evId,pid,hwPos,hwId>>

\* The registry's log loses its newest entry; later rounds are another history.
Rollback ==
  /\ AllowRollback /\ Mode \in NewModes /\ ~rolled /\ ~stopped /\ Len(log) >= 1
  /\ log' = SubSeq(log, 1, Len(log) - 1) /\ logIds' = SubSeq(logIds, 1, Len(log) - 1)
  /\ rolled' = TRUE
  /\ UNCHANGED <<regV,stopped,data,lver,cons,pos,owed,evPos,evId,pid,hwPos,hwId>>
ForeignRound ==
  /\ AllowRollback /\ Mode \in NewModes /\ rolled /\ ~stopped /\ Len(log) < Len(Rounds)
  /\ log' = Append(log, Rounds[Len(log) + 1]) /\ logIds' = Append(logIds, "f")
  /\ UNCHANGED <<regV,stopped,data,lver,cons,pos,rolled,owed,evPos,evId,pid,hwPos,hwId>>

Stop == ~stopped /\ stopped' = TRUE /\ UNCHANGED <<regV,log,data,lver,cons,pos,extra>>

Next == CommitHead \/ LogRound \/ Stop \/ Rollback \/ ForeignRound
        \/ \E d \in Devices : Apply(d) \/ ApplyHead(d) \/ ApplyLogOnly(d) \/ AdmitHead(d) \/ Replay(d) \/ MemCrash(d)
Spec == Init /\ [][Next]_vars /\ WF_vars(Stop) /\ \A d \in Devices : WF_vars(Apply(d)) /\ WF_vars(ApplyHead(d)) /\ WF_vars(ApplyLogOnly(d)) /\ WF_vars(AdmitHead(d)) /\ WF_vars(Replay(d))

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
\* The device fits the registry log it holds a cursor on.
Foldable(d) == pos[d] <= Len(log) /\ IF pos[d] = 0 THEN TRUE ELSE logIds[pos[d]] = pid[d]
\* A device holding the current head either owes the log pass (durably) or already
\* holds the head's rows with the log's rows over them.
InvReplayedOrOwed ==
  Mode \in NewModes =>
    \A d \in Devices : (regV > 0 /\ cons[d] = regV /\ Foldable(d)) =>
       (owed[d] \/ data[d] = FoldLog(MergeRows(Omit(Empty, Heads[regV]), Heads[regV].rows), log, 1, pos[d]))
\* A cursor that sits below the highest position the device applied (it was reset
\* by a head) keeps that position and its segment as evidence, with the obligation.
InvKept ==
  Mode \in NewModes =>
    \A d \in Devices : pos[d] < hwPos[d] =>
       (owed[d] /\ evPos[d] = hwPos[d] /\ evId[d] = hwId[d])
TypeOK == /\ regV \in 0..Len(Heads) /\ Len(log) <= Len(Rounds)
          /\ \A d \in Devices : lver[d] \in Nat /\ cons[d] \in 0..Len(Heads)
=============================================================================
