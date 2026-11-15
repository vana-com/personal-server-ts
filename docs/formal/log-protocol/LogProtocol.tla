--------------------------- MODULE LogProtocol ---------------------------
EXTENDS Naturals, Integers, Sequences, FiniteSets, TLC
CONSTANTS MaxSteps, Mode, AllowReset, KeepTail
ASSUME /\ MaxSteps \in 6..8
       /\ KeepTail = 1
       /\ Mode \in {"good","gap","outOfOrder","dropTombstone","omitNoCutoff"}
Devices == {1,2,3}
Keys == {1,2}
Writers == {1,2}
\* Keys stand for (stream A,key a) and (stream B,key b).
EmptyRow == [stamp |-> 0, rank |-> 0, body |-> 0]
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
    <<Op(2,1,21,1,5,"upsert")>> >>
Rank(op) == IF op.kind = "omit" THEN 2 * op.stamp - 1 ELSE 2 * op.stamp
\* An omission cutoff is a strict boundary: an observation AT cutoff wins.
Merge(state,op,bad) ==
 IF bad /\ op.kind = "omit"
 THEN [state EXCEPT ![op.key] = [stamp |-> op.stamp,rank |-> Rank(op),body |-> 0]]
 ELSE IF Rank(op) > state[op.key].rank
      THEN [state EXCEPT ![op.key] =
             [stamp |-> op.stamp,rank |-> Rank(op),body |-> op.body]]
      ELSE state
RECURSIVE FoldOps(_,_,_)
FoldOps(state,ops,bad) ==
 IF Len(ops)=0 THEN state
 ELSE FoldOps(Merge(state,Head(ops),bad),Tail(ops),bad)
RECURSIVE FoldLog(_,_)
FoldLog(state,log) ==
 IF Len(log)=0 THEN state
 ELSE FoldLog(FoldOps(state,Head(log),FALSE),Tail(log))
RECURSIVE WithoutDeletes(_)
WithoutDeletes(ops) ==
 IF Len(ops)=0 THEN <<>>
 ELSE IF Head(ops).kind = "delete" THEN WithoutDeletes(Tail(ops))
 ELSE <<Head(ops)>> \o WithoutDeletes(Tail(ops))
RECURSIVE BadSnapshot(_,_)
BadSnapshot(state,log) ==
 IF Len(log)=0 THEN state
 ELSE BadSnapshot(FoldOps(state,WithoutDeletes(Head(log)),FALSE),Tail(log))
Visible(state) == [k \in Keys |-> state[k].body]
Prefix(log,n) == SubSeq(log,1,n)
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
FullCheck(d) ==
 /\ (deviceEpoch[d] # epoch \/ known[d] # Len(log))
 /\ deviceEpoch' = [deviceEpoch EXCEPT ![d]=epoch]
 /\ known' = [known EXCEPT ![d]=Len(log)]
 /\ position' = IF deviceEpoch[d] # epoch THEN [position EXCEPT ![d]=0] ELSE position
 /\ data' = IF deviceEpoch[d] # epoch THEN [data EXCEPT ![d]=Empty] ELSE data
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
 /\ snapshot'=IF Mode="dropTombstone"
              THEN BadSnapshot(Empty,Prefix(log,cut'))
              ELSE FoldLog(Empty,Prefix(log,cut'))
 /\ retained'={p \in retained : p>cut'}
 /\ UNCHANGED <<epoch,log,budget,stopped,deviceEpoch,position,known,data,hints,
                prefixOK,monotoneOK,omissionOK>>
Install(d) ==
 /\ deviceEpoch[d]=epoch /\ position[d]<cut /\ known[d]>=cut
 /\ data'=[data EXCEPT ![d]=snapshot]
 /\ position'=[position EXCEPT ![d]=cut]
 /\ monotoneOK'=(monotoneOK /\ cut>=position[d])
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints,prefixOK,omissionOK>>
OmissionSafeFor(state,ops) ==
 \A i \in 1..Len(ops):
   LET op == ops[i]
       before == FoldOps(state,SubSeq(ops,1,i-1),Mode="omitNoCutoff")
       after == Merge(before,op,Mode="omitNoCutoff")
   IN (op.kind="omit" /\ before[op.key].stamp>=op.stamp /\ before[op.key].body#0)
      => after[op.key]=before[op.key]
Apply(d,p) ==
 /\ deviceEpoch[d]=epoch /\ position[d]>=cut
 /\ p \in retained /\ p<=known[d] /\ p>position[d]
 /\ (Mode="outOfOrder" \/ p=position[d]+1)
 /\ data'=[data EXCEPT ![d]=FoldOps(@,log[p],Mode="omitNoCutoff")]
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
 \/ Commit \/ Stop \/ Reset \/ Compact
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
\* Source-limited fence: after adopting the authoritative lifetime, every
\* installed prefix consists only of that lifetime. No instant offline reset.
P5 == \A d \in Devices :
       deviceEpoch[d]=epoch => data[d]=FoldLog(Empty,Prefix(log,position[d]))
CaughtUp == \A d \in Devices : deviceEpoch[d]=epoch /\ position[d]=Len(log)
EventuallyConverged == <>[](stopped /\ CaughtUp /\ P1)
\* Expected FALSE: evidence that the two conflict orders are not equivalent.
StampEqualsLamport ==
 (epoch=1 /\ Len(log)=2) =>
 Visible(FoldLog(Empty,log))=LamportVisible(log)
=============================================================================
