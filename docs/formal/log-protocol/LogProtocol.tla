--------------------------- MODULE LogProtocol ---------------------------
EXTENDS Naturals, Integers, Sequences, FiniteSets, TLC
CONSTANTS MaxSteps, Mode, AllowReset, AllowRollback, KeepTail
ASSUME /\ MaxSteps \in 6..8
       /\ KeepTail = 1
       /\ Mode \in {"good","gap","outOfOrder","droppedDeleteEffect","forgetTombstone",
                    "omitNoCutoff","omitInclusive","dropKind","replayFromBase"}
Devices == {1,2,3}
Keys == {1,2}
Writers == {1,2}
\* Keys stand for (stream A,key a) and (stream B,key b).
\* A row is (stamp, rank, body, first): first = firstSeen, the smallest batch position at
\* which an observation with this row's rank was applied (0 for the empty row).
EmptyRow == [stamp |-> 0, rank |-> 0, body |-> 0, first |-> 0]
Empty == [k \in Keys |-> EmptyRow]
Op(k,s,b,w,c,kind) ==
  [key |-> k, stamp |-> s, body |-> b, writer |-> w, counter |-> c,
   kind |-> kind]
\* Finite independent writers; stamps encode ordered (o,r) pairs as s=2*o+r, r in {0,1}. The stamp
\* order is deliberately different from the Lamport counter order.
Batches ==
 << <<Op(1,3,11,1,1,"upsert"), Op(2,1,21,1,1,"upsert")>>,
    <<Op(1,2,12,2,2,"upsert"), Op(2,2,0,2,2,"delete")>>,
    <<Op(1,5,13,1,3,"upsert")>>,
    <<Op(1,4,0,2,4,"omit")>>,
    <<Op(2,1,21,1,5,"upsert")>>,
    \* Equal cutoff: stamp 5 omission on key 1 meets the live batch-3 row (stamp 5).
    \* Older observation: stamp 1 omission on key 2 is below the live delete (stamp 2).
    <<Op(1,5,0,2,6,"omit"), Op(2,1,0,2,6,"omit")>>,
    \* Equal stamp, same key, same batch: an upsert and an explicit delete at stamp 4.
    \* Only the kind rank decides the outcome (delete > upsert), in either order.
    <<Op(2,4,22,1,7,"upsert"), Op(2,4,0,2,7,"delete")>> >>
\* Rank at a stamp: omission < upsert < explicit delete (the registry's tombstone kinds).
\* omitInclusive mutant: an omission at a cutoff also beats an observation AT that cutoff.
\* dropKind mutant: an explicit delete ranks with an upsert, so equal-stamp order matters.
Rank(op) == IF op.kind = "omit"
            THEN (IF Mode = "omitInclusive" THEN 2 * op.stamp + 1 ELSE 2 * op.stamp - 1)
            ELSE IF op.kind = "delete"
            THEN (IF Mode = "dropKind" THEN 2 * op.stamp ELSE 2 * op.stamp + 1)
            ELSE 2 * op.stamp
Min2(a,b) == IF a < b THEN a ELSE b
\* An omission cutoff is a strict boundary: an observation AT cutoff wins.
Merge(state,op,bad,fs) ==
 IF bad /\ op.kind = "omit"
 THEN [state EXCEPT ![op.key] = [stamp |-> op.stamp,rank |-> Rank(op),body |-> 0,first |-> fs]]
 ELSE IF Rank(op) > state[op.key].rank
      THEN [state EXCEPT ![op.key] =
             [stamp |-> op.stamp,rank |-> Rank(op),body |-> op.body,first |-> fs]]
      ELSE IF Rank(op) = state[op.key].rank /\ Rank(op) > 0
      THEN [state EXCEPT ![op.key].first = Min2(state[op.key].first, fs)]
      ELSE state
\* Install merge: a reader's row meets the snapshot's row for the same key. The snapshot
\* is the fold of a prefix the reader has only partly applied, so its rank is never lower.
MergeRow(a,b) ==
 IF b.rank > a.rank THEN b
 ELSE IF b.rank = a.rank /\ a.rank > 0 THEN [a EXCEPT !.first = Min2(a.first, b.first)]
 ELSE a
RECURSIVE FoldOps(_,_,_,_)
FoldOps(state,ops,bad,fs) ==
 IF Len(ops)=0 THEN state
 ELSE FoldOps(Merge(state,Head(ops),bad,fs),Tail(ops),bad,fs)
RECURSIVE FoldLogAt(_,_,_)
FoldLogAt(state,log,p) ==
 IF Len(log)=0 THEN state
 ELSE FoldLogAt(FoldOps(state,Head(log),FALSE,p),Tail(log),p+1)
FoldLog(state,log) == FoldLogAt(state,log,1)
RECURSIVE WithoutDeletes(_)
WithoutDeletes(ops) ==
 IF Len(ops)=0 THEN <<>>
 ELSE IF Head(ops).kind = "delete" THEN WithoutDeletes(Tail(ops))
 ELSE <<Head(ops)>> \o WithoutDeletes(Tail(ops))
RECURSIVE BadSnapshotAt(_,_,_)
BadSnapshotAt(state,log,p) ==
 IF Len(log)=0 THEN state
 ELSE BadSnapshotAt(FoldOps(state,WithoutDeletes(Head(log)),FALSE,p),Tail(log),p+1)
BadSnapshot(state,log) == BadSnapshotAt(state,log,1)
Visible(state) == [k \in Keys |-> state[k].body]
\* forgetTombstone mutant: a correct delete leaves no tombstone row in the snapshot.
ForgetTombstones(state) ==
 [k \in Keys |-> IF state[k].body = 0 THEN EmptyRow ELSE state[k]]
Prefix(log,n) == SubSeq(log,1,n)
RECURSIVE RevOps(_)
RevOps(s) == IF Len(s)=0 THEN <<>> ELSE RevOps(Tail(s)) \o <<Head(s)>>
\* Equal-stamp corpus is order-insensitive: each batch folds the same forwards and backwards.
OrderOK ==
 \A i \in 1..Len(Batches) :
   FoldOps(Empty,Batches[i],FALSE,1) = FoldOps(Empty,RevOps(Batches[i]),FALSE,1)
\* P6 deliberately tests a restricted profile-v1 comparison: distinct counters,
\* so all remaining compareRevisions tie fields are irrelevant in this witness.
RECURSIVE LamportOps(_,_)
LamportOps(state,ops) ==
 IF Len(ops)=0 THEN state ELSE
 LET op == Head(ops)
     next == IF op.counter > state[op.key].counter
             THEN [state EXCEPT ![op.key] = [counter |-> op.counter,body |-> op.body]]
             ELSE state
 IN LamportOps(next,Tail(ops))
RECURSIVE LamportLog(_,_)
LamportLog(state,log) ==
 IF Len(log)=0 THEN state ELSE LamportLog(LamportOps(state,Head(log)),Tail(log))
LamportVisible(log) ==
 [k \in Keys |->
   LamportLog([j \in Keys |-> [counter |-> 0,body |-> 0]],log)[k].body]

VARIABLES epoch, log, retained, cut, snapshot, budget, stopped,
          deviceEpoch, position, known, data, hints, prefixOK, monotoneOK, omissionOK
vars == <<epoch,log,retained,cut,snapshot,budget,stopped,
          deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK>>
Init ==
 /\ epoch = 1 /\ log = <<>> /\ retained = {} /\ cut = 0 /\ snapshot = Empty
 /\ budget = 0 /\ stopped = FALSE
 /\ deviceEpoch = [d \in Devices |-> 1]
 /\ position = [d \in Devices |-> 0]
 /\ known = [d \in Devices |-> 0]
 /\ data = [d \in Devices |-> Empty]
 /\ hints = {}
 /\ prefixOK = TRUE /\ monotoneOK = TRUE /\ omissionOK = TRUE

AllOps(history) == UNION { {history[i][j] : j \in 1..Len(history[i])} :
                           i \in 1..Len(history) }
Admissible(batch) ==
 \A incoming \in {batch[i] : i \in 1..Len(batch)}, old \in AllOps(log) :
  (incoming.key=old.key /\ incoming.stamp=old.stamp /\
   incoming.kind#"omit" /\ old.kind#"omit") => incoming.body=old.body

Commit ==
 /\ ~stopped /\ budget < MaxSteps /\ Len(log) < Len(Batches)
 /\ LET p == Len(log)+1 IN
    /\ Admissible(Batches[p])
    /\ log' = Append(log,Batches[p])
    /\ retained' = retained \cup {p}
    /\ hints' = hints \cup {[generation |-> epoch, at |-> p]}
 /\ budget' = budget+1
 /\ UNCHANGED <<epoch,cut,snapshot,stopped,deviceEpoch,position,known,data,
                prefixOK,monotoneOK,omissionOK>>
Stop ==
 /\ ~stopped /\ stopped' = TRUE
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK>>
\* Reset is an authoritative new lifetime, not wall-clock inference.
\* Offline devices do not learn it instantly; their old view remains until read.
Reset ==
 /\ AllowReset /\ ~stopped /\ epoch=1 /\ Len(log)>=2 /\ budget<MaxSteps
 /\ epoch'=2 /\ log' = <<>> /\ retained'={} /\ cut'=0 /\ snapshot'=Empty
 /\ budget'=budget+1
 /\ UNCHANGED <<stopped,deviceEpoch,position,known,data,hints,
                prefixOK,monotoneOK,omissionOK>>
\* Registry rollback (at most one: it needs epoch 1 and leaves epoch 2). The authoritative head
\* moves back one batch and may be replaced by another corpus batch, so a device ahead of the
\* head or holding the replaced batch is diverged. The new lifetime rebases the snapshot to
\* Empty (cut 0), so no snapshot of the rolled-back history survives.
Rollback ==
 /\ AllowRollback /\ ~stopped /\ epoch=1 /\ Len(log)>=2 /\ budget<MaxSteps
 /\ \E alt \in {0} \cup {p \in 1..Len(Batches) : Admissible(Batches[p])} :
     LET kept == SubSeq(log,1,Len(log)-1)
         newLog == IF alt = 0 THEN kept ELSE Append(kept,Batches[alt])
     IN /\ log' = newLog
        /\ epoch' = 2 /\ cut' = 0 /\ snapshot' = Empty
        /\ retained' = {p \in 1..Len(newLog) : p > 0}
 /\ budget' = budget+1
 /\ UNCHANGED <<stopped,deviceEpoch,position,known,data,hints,
                prefixOK,monotoneOK,omissionOK>>
\* A full check adopts the current lifetime and resets a device that was on another one.
\* replayFromBase mutant: the device keeps its rows and position and replays from there.
FullCheck(d) ==
 /\ (deviceEpoch[d] # epoch \/ known[d] # Len(log))
 /\ deviceEpoch' = [deviceEpoch EXCEPT ![d]=epoch]
 /\ known' = [known EXCEPT ![d]=Len(log)]
 /\ LET relabel == deviceEpoch[d] # epoch /\ Mode # "replayFromBase"
    IN /\ position' = IF relabel THEN [position EXCEPT ![d]=0] ELSE position
       /\ data' = IF relabel THEN [data EXCEPT ![d]=Empty] ELSE data
 /\ monotoneOK' = (monotoneOK /\ epoch >= deviceEpoch[d])
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,hints,prefixOK,omissionOK>>
\* Deliver does NOT consume the hint, permitting duplicate/reordered delivery.
\* Stale lifetime hints carry no authority to roll a device back.
Deliver(d,h) ==
 /\ h \in hints
 /\ known' = IF h.generation=deviceEpoch[d] /\ h.at>known[d]
             THEN [known EXCEPT ![d]=h.at] ELSE known
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,data,hints,prefixOK,monotoneOK,omissionOK>>
Drop(h) ==
 /\ h \in hints /\ hints'=hints \ {h}
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,prefixOK,monotoneOK,omissionOK>>
Compact ==
 /\ Len(log)>KeepTail /\ cut < Len(log)-KeepTail
 /\ cut'=Len(log)-KeepTail
 /\ snapshot'=IF Mode="droppedDeleteEffect"
              THEN BadSnapshot(Empty,Prefix(log,cut'))
              ELSE IF Mode="forgetTombstone"
              THEN ForgetTombstones(FoldLog(Empty,Prefix(log,cut')))
              ELSE FoldLog(Empty,Prefix(log,cut'))
 /\ retained'={p \in retained : p>cut'}
 /\ UNCHANGED <<epoch,log,budget,stopped,deviceEpoch,position,known,data,hints,
                prefixOK,monotoneOK,omissionOK>>
\* A reader behind the snapshot merges it into the rows it already has.
Install(d) ==
 /\ deviceEpoch[d]=epoch /\ position[d]<cut /\ known[d]>=cut
 /\ data'=[data EXCEPT ![d]=[k \in Keys |-> MergeRow(data[d][k],snapshot[k])]]
 /\ position'=[position EXCEPT ![d]=cut]
 /\ monotoneOK'=(monotoneOK /\ cut>=position[d])
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints,prefixOK,omissionOK>>
OmissionSafeFor(state,ops) ==
 \A i \in 1..Len(ops):
   LET op == ops[i]
       before == FoldOps(state,SubSeq(ops,1,i-1),Mode="omitNoCutoff",1)
       after == Merge(before,op,Mode="omitNoCutoff",1)
   IN (op.kind="omit" /\ before[op.key].stamp>=op.stamp /\ before[op.key].body#0)
      => after[op.key]=before[op.key]
Apply(d,p) ==
 /\ deviceEpoch[d]=epoch /\ position[d]>=cut
 /\ p \in retained /\ p<=known[d] /\ p>position[d]
 /\ (Mode="outOfOrder" \/ p=position[d]+1)
 /\ data'=[data EXCEPT ![d]=FoldOps(data[d],log[p],Mode="omitNoCutoff",p)]
 /\ position'=[position EXCEPT ![d]=p]
 /\ prefixOK'=(prefixOK /\ p=position[d]+1)
 /\ monotoneOK'=(monotoneOK /\ p>=position[d])
 /\ omissionOK'=(omissionOK /\ OmissionSafeFor(data[d],log[p]))
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints>>
\* Mutant: treating a later position hint as an applied checkpoint without
\* detecting/fetching its missing predecessors.
SkipGap(d) ==
 /\ Mode="gap" /\ deviceEpoch[d]=epoch /\ known[d]>position[d]+1
 /\ position'=[position EXCEPT ![d]=known[d]]
 /\ prefixOK'=FALSE
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,data,hints,monotoneOK,omissionOK>>
Recover(d) == Install(d) \/ (\E p \in retained : Apply(d,p)) \/ SkipGap(d)
Next ==
 \/ Commit \/ Stop \/ Reset \/ Compact \/ Rollback
 \/ \E d \in Devices : FullCheck(d) \/ Recover(d)
 \/ \E d \in Devices, h \in hints : Deliver(d,h)
 \/ \E h \in hints : Drop(h)
Spec == Init /\ [][Next]_vars
        /\ WF_vars(Stop)
        /\ \A d \in Devices : WF_vars(FullCheck(d)) /\ WF_vars(Recover(d))

NoPushNext ==
 \/ Commit \/ Stop \/ Reset \/ Compact
 \/ \E d \in Devices : FullCheck(d) \/ Recover(d)
 \/ \E h \in hints : Drop(h)
NoPushSpec == Init /\ [][NoPushNext]_vars
        /\ WF_vars(Stop)
        /\ \A d \in Devices : WF_vars(FullCheck(d)) /\ WF_vars(Recover(d))

TypeOK ==
 /\ epoch \in 1..2 /\ budget \in 0..MaxSteps /\ stopped \in BOOLEAN
 /\ cut \in 0..Len(log) /\ retained = (cut+1)..Len(log)
 /\ \A d \in Devices : position[d] \in 0..MaxSteps /\ known[d] \in 0..MaxSteps
                       /\ deviceEpoch[d] \in 1..epoch
P1 == \A d \in Devices :
       (deviceEpoch[d]=epoch /\ position[d]=Len(log))
       => Visible(data[d])=Visible(FoldLog(Empty,log))
P2 == prefixOK /\ monotoneOK
P3 == omissionOK
P4 == snapshot=FoldLog(Empty,Prefix(log,cut))
\* Exact agreement: every current device holds exactly the fold of its prefix (body, stamp,
\* rank and firstSeen on every row). A position past the head is a failure, not a value.
P5 == \A d \in Devices :
       deviceEpoch[d]=epoch =>
         IF position[d] > Len(log) THEN FALSE
         ELSE data[d]=FoldLog(Empty,Prefix(log,position[d]))
CaughtUp == \A d \in Devices : deviceEpoch[d]=epoch /\ position[d]=Len(log)
EventuallyConverged == <>[](stopped /\ CaughtUp /\ P1)
\* Expected FALSE: evidence that the two conflict orders are not equivalent.
StampEqualsLamport ==
 (epoch=1 /\ Len(log)=2) =>
 Visible(FoldLog(Empty,log))=LamportVisible(log)
=============================================================================
