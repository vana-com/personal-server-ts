--------------------------- MODULE LogProtocol ---------------------------
EXTENDS Naturals, Integers, Sequences, FiniteSets, TLC
CONSTANTS MaxSteps, Mode, AllowReset, AllowRollback, KeepTail
\* Every mode of the key-ordered first load. keyedRebase and keyedStuck are one device only
\* (see Devices); keyedStuck is the load without the Rebaseline step.
KeyedModes == {"keyed","keyedSkip","keyedEarly","keyedLeak","keyedBypass",
               "keyedRebase","keyedStuck"}
\* Every mode of a registry that loses log rows a device applied (no new lifetime). recommit:
\* the registry loses one or two positions, and the writers that continue write the same
\* segments. recommitOther: a writer may continue with another segment. recommitForeign
\* (mutant): the device commits its segments again without checking that the registry's row
\* is one it applied. noRecommit (mutant): no Recommit step, the code before it.
RecommitModes == {"recommit","recommitOther","recommitForeign","noRecommit"}
ASSUME /\ MaxSteps \in 6..8
       /\ KeepTail = 1
       /\ Mode \in {"good","gap","outOfOrder","droppedDeleteEffect","forgetTombstone",
                    "omitNoCutoff","omitInclusive","dropKind","replayFromBase",
                    "grouped","groupedSkip","equalStamp","equalStampToday",
                    "keyed","keyedSkip","keyedEarly","keyedLeak","keyedBypass",
                    "keyedRebase","keyedStuck",
                    "recommit","recommitOther","recommitForeign","noRecommit"}
\* A device's recovery does not depend on another device's: the liveness runs use one.
Devices == IF Mode \in {"keyedRebase","keyedStuck"} THEN {1}
           ELSE IF Mode \in RecommitModes THEN {1,2} ELSE {1,2,3}
Keys == {1,2}
Writers == {1,2}
\* Keys stand for (stream A,key a) and (stream B,key b).
\* A row is (stamp, rank, body, first): first = firstSeen, the smallest batch position at
\* which an observation with this row's rank was applied (0 for the empty row).
EmptyRow == [stamp |-> 0, rank |-> 0, body |-> 0, first |-> 0]
Empty == [k \in Keys |-> EmptyRow]
\* ord is the intake batch ordinal of the run that observed the body (0 when the entry
\* carries none). It is the third component of the observation order: (stamp, ord, kind).
OpN(k,s,b,w,c,kind,n) ==
  [key |-> k, stamp |-> s, body |-> b, writer |-> w, counter |-> c,
   kind |-> kind, ord |-> n]
Op(k,s,b,w,c,kind) == OpN(k,s,b,w,c,kind,0)
\* Finite independent writers; stamps encode ordered (o,r) pairs as s=2*o+r, r in {0,1}. The stamp
\* order is deliberately different from the Lamport counter order.
BaseBatches ==
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
\* One run (stamp 3, writer 1) re-emits keys in later intake batches, each published as soon
\* as it commits (publish while collecting). Ordinal = the intake batch index, carried by
\* upserts only. Key 1: body 11 at ordinal 0, replaced by body 12 at ordinal 1 (same stamp).
\* Key 2: body 21 at ordinal 0, body 22 at ordinal 1, then the run's end deletes it. An
\* explicit delete exists only at run end (intake admits upserts only), so it carries no
\* ordinal and its kind rank puts it above every upsert of its run; the omission at the run's
\* own cutoff (also a run-end entry) erases nothing the run observed. Batch 4: a later run
\* (stamp 5, ordinal 0) beats every ordinal of the earlier run. Batch 5: a clone (another
\* writer with the same run id, so the same stamp and ordinal) emits a different body.
EqualStampBatches ==
 << <<OpN(1,3,11,1,1,"upsert",0), OpN(2,3,21,1,1,"upsert",0)>>,
    <<OpN(1,3,12,1,2,"upsert",1), OpN(2,3,22,1,2,"upsert",1)>>,
    <<OpN(2,3,0,1,3,"delete",0), OpN(1,3,0,2,3,"omit",0)>>,
    <<OpN(1,5,13,2,4,"upsert",0)>>,
    <<OpN(1,5,14,1,5,"upsert",0)>> >>
Batches == IF Mode \in {"equalStamp","equalStampToday"} THEN EqualStampBatches ELSE BaseBatches
\* Rank: the observation order (stamp, kind, ord, body) as one number; absent is rank 0 and
\* every real operation ranks above it. Kind: omission < upsert < explicit delete (the
\* registry's tombstone kinds). Deletes and omissions are run-end entries and carry no ordinal. The body
\* is the last tie-break (the real comparator uses the canonical body's hash, a total order
\* on bodies), so two entries with equal stamp, ordinal and kind but different bodies
\* (writers that share a run id) still have one winner at every reader.
\* omitInclusive mutant: an omission at a cutoff also beats an observation AT that cutoff.
\* dropKind mutant: an explicit delete ranks with an upsert and the body tie-break is
\* absent, so equal-stamp order matters.
\* equalStampToday mutant: the comparator of the code before the ordinal: ord and body are
\* ignored, so a later batch's body at the same stamp ties the earlier one and the first
\* applied wins.
OrdOf(op) == IF Mode = "equalStampToday" THEN 0 ELSE op.ord
TieOf(op) == IF Mode \in {"equalStampToday","dropKind"} THEN 0 ELSE op.body
KindRank(op) == IF op.kind = "omit" THEN (IF Mode = "omitInclusive" THEN 2 ELSE 0)
                ELSE IF op.kind = "delete" THEN (IF Mode = "dropKind" THEN 1 ELSE 2)
                ELSE 1
\* The packing into one number is exact by construction: each radix is one more than the
\* largest value the corpus uses in that field (kinds have three ranks), so no field can
\* carry into the next. SqlRank.tla compares the tuple instead and needs no packing.
CorpusOps == UNION {{Batches[i][j] : j \in 1..Len(Batches[i])} : i \in 1..Len(Batches)}
MaxOf(S) == CHOOSE m \in S : \A x \in S : x <= m
KindBase == 3
OrdBase == MaxOf({o.ord : o \in CorpusOps}) + 1
BodyBase == MaxOf({o.body : o \in CorpusOps}) + 1
Rank(op) == BodyBase * (OrdBase * (KindBase * op.stamp + KindRank(op)) + OrdOf(op)) + TieOf(op)
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
          deviceEpoch, position, known, data, hints, prefixOK, monotoneOK, omissionOK,
          stage, stageAt, dur, durAt, durEp, applied
\* applied[d]: the segments device d applied, in position order (the code's `log_state.refs`;
\* the snapshot install keeps the registry's refs up to the snapshot position).
vars == <<epoch,log,retained,cut,snapshot,budget,stopped,
          deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,
          applied>>
Init ==
 /\ epoch = 1 /\ log = <<>> /\ retained = {} /\ cut = 0 /\ snapshot = Empty
 /\ budget = 0 /\ stopped = FALSE
 /\ deviceEpoch = [d \in Devices |-> 1]
 /\ position = [d \in Devices |-> 0]
 /\ known = [d \in Devices |-> 0]
 /\ data = [d \in Devices |-> Empty]
 /\ hints = {}
 /\ prefixOK = TRUE /\ monotoneOK = TRUE /\ omissionOK = TRUE
 /\ stage = [d \in Devices |-> Empty]
 /\ stageAt = [d \in Devices |-> [k \in Keys |-> 0]]
 /\ dur = [d \in Devices |-> Empty]
 /\ durAt = [d \in Devices |-> 0]
 /\ durEp = [d \in Devices |-> 1]
 /\ applied = [d \in Devices |-> <<>>]

AllOps(history) == UNION { {history[i][j] : j \in 1..Len(history[i])} :
                           i \in 1..Len(history) }
Commit ==
 /\ ~stopped /\ budget < MaxSteps /\ Len(log) < Len(Batches)
 /\ LET p == Len(log)+1 IN
    /\ log' = Append(log,Batches[p])
    /\ retained' = retained \cup {p}
    /\ hints' = hints \cup {[generation |-> epoch, at |-> p]}
 /\ budget' = budget+1
 /\ UNCHANGED <<epoch,cut,snapshot,stopped,deviceEpoch,position,known,data,
                prefixOK,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
Stop ==
 /\ ~stopped /\ stopped' = TRUE
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
\* Reset is an authoritative new lifetime, not wall-clock inference.
\* Offline devices do not learn it instantly; their old view remains until read.
Reset ==
 /\ AllowReset /\ ~stopped /\ epoch=1 /\ Len(log)>=2 /\ budget<MaxSteps
 /\ epoch'=2 /\ log' = <<>> /\ retained'={} /\ cut'=0 /\ snapshot'=Empty
 /\ budget'=budget+1
 /\ stage' = [d \in Devices |-> Empty]
 /\ stageAt' = [d \in Devices |-> [k \in Keys |-> 0]]
 /\ UNCHANGED <<stopped,deviceEpoch,position,known,data,hints,
                prefixOK,monotoneOK,omissionOK,dur,durAt,durEp,applied>>
\* Registry rollback (at most one: it needs epoch 1 and leaves epoch 2). The authoritative head
\* moves back one batch and may be replaced by another corpus batch, so a device ahead of the
\* head or holding the replaced batch is diverged. The new lifetime rebases the snapshot to
\* Empty (cut 0), so no snapshot of the rolled-back history survives.
\* In RecommitModes the registry loses one or two rows and keeps at least one; epoch 2 then
\* marks only that the registry's history moved under the devices, which each device
\* reconciles (`FullCheck` or `Recommit`). In recommit and noRecommit no other segment
\* replaces them.
Rollback ==
 /\ AllowRollback /\ ~stopped /\ epoch=1 /\ budget<MaxSteps
 /\ \E n \in (IF Mode \in RecommitModes THEN 1..2 ELSE 1..1),
       alt \in (IF Mode \in {"recommit","noRecommit"} THEN {0} ELSE 0..Len(Batches)) :
     LET kept == SubSeq(log,1,Len(log)-n)
         newLog == IF alt = 0 THEN kept ELSE Append(kept,Batches[alt])
     IN /\ Len(log) >= n+1
        /\ log' = newLog
        /\ epoch' = 2 /\ cut' = 0 /\ snapshot' = Empty
        /\ retained' = {p \in 1..Len(newLog) : p > 0}
 /\ budget' = budget+1
 /\ stage' = [d \in Devices |-> Empty]
 /\ stageAt' = [d \in Devices |-> [k \in Keys |-> 0]]
 /\ UNCHANGED <<stopped,deviceEpoch,position,known,data,hints,
                prefixOK,monotoneOK,omissionOK,dur,durAt,durEp,applied>>
\* A device that holds durable unpublished rows (`durAt[d] # 0`: the code's `log_keyed_pending`
\* marker) takes no other way to move its position or its rows: not a segment, a group, a
\* snapshot, a lifetime change. Each of those would publish a cursor over rows it did not
\* write or cannot account for, so the code refuses them (`LogDivergedError`) until a
\* key-ordered load that covers the rows publishes. keyedBypass mutant: no such refusal.
NoPending(d) == Mode = "keyedBypass" \/ durAt[d] = 0
\* The rows a device physically holds: the durable unpublished rows are in the live table, so
\* a segment applied over them merges with them (the code's `records`). With the refusal
\* above `dur` is Empty whenever one applies, and this equals `data[d]`.
LiveRows(d) == [k \in Keys |-> MergeRow(data[d][k], dur[d][k])]
\* A full check adopts the current lifetime and resets a device that was on another one.
\* replayFromBase mutant: the device keeps its rows and position and replays from there.
\* In RecommitModes a device keeps its rows when the registry's log holds, at every position
\* the device applied, the segment it applied there (`Explains`); otherwise it is refused
\* (`LogDivergedError`) and takes no step: the code's fail-closed rule.
Explains(d) == position[d] <= Len(log) /\ Prefix(log,position[d]) = applied[d]
FullCheck(d) ==
 /\ (deviceEpoch[d] # epoch \/ known[d] # Len(log))
 /\ (deviceEpoch[d] # epoch => NoPending(d))
 /\ (Mode \in RecommitModes /\ deviceEpoch[d] # epoch) => Explains(d)
 /\ deviceEpoch' = [deviceEpoch EXCEPT ![d]=epoch]
 /\ known' = [known EXCEPT ![d]=Len(log)]
 /\ LET relabel == deviceEpoch[d] # epoch /\ Mode \notin ({"replayFromBase"} \cup RecommitModes)
    IN /\ position' = IF relabel THEN [position EXCEPT ![d]=0] ELSE position
       /\ data' = IF relabel THEN [data EXCEPT ![d]=Empty] ELSE data
       /\ applied' = IF relabel THEN [applied EXCEPT ![d] = <<>>] ELSE applied
 /\ monotoneOK' = (monotoneOK /\ epoch >= deviceEpoch[d])
 /\ stage' = IF deviceEpoch[d] # epoch THEN [stage EXCEPT ![d]=Empty] ELSE stage
 /\ stageAt' = IF deviceEpoch[d] # epoch
               THEN [stageAt EXCEPT ![d]=[k \in Keys |-> 0]] ELSE stageAt
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,hints,prefixOK,omissionOK,dur,durAt,durEp>>
\* Deliver does NOT consume the hint, permitting duplicate/reordered delivery.
\* Stale lifetime hints carry no authority to roll a device back.
Deliver(d,h) ==
 /\ h \in hints
 /\ known' = IF h.generation=deviceEpoch[d] /\ h.at>known[d]
             THEN [known EXCEPT ![d]=h.at] ELSE known
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,data,hints,prefixOK,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
Drop(h) ==
 /\ h \in hints /\ hints'=hints \ {h}
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,prefixOK,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
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
                prefixOK,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
\* A reader behind the snapshot merges it into the rows it already has.
Install(d) ==
 /\ NoPending(d)
 /\ deviceEpoch[d]=epoch /\ position[d]<cut /\ known[d]>=cut
 /\ data'=[data EXCEPT ![d]=[k \in Keys |-> MergeRow(LiveRows(d)[k],snapshot[k])]]
 /\ position'=[position EXCEPT ![d]=cut]
 /\ applied'=[applied EXCEPT ![d]=Prefix(log,cut)]
 /\ monotoneOK'=(monotoneOK /\ cut>=position[d])
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints,prefixOK,omissionOK,stage,stageAt,dur,durAt,durEp>>
OmissionSafeFor(state,ops) ==
 \A i \in 1..Len(ops):
   LET op == ops[i]
       before == FoldOps(state,SubSeq(ops,1,i-1),Mode="omitNoCutoff",1)
       after == Merge(before,op,Mode="omitNoCutoff",1)
   IN (op.kind="omit" /\ before[op.key].stamp>=op.stamp /\ before[op.key].body#0)
      => after[op.key]=before[op.key]
Apply(d,p) ==
 /\ NoPending(d)
 /\ deviceEpoch[d]=epoch /\ position[d]>=cut
 /\ p \in retained /\ p<=known[d] /\ p>position[d]
 /\ (Mode="outOfOrder" \/ p=position[d]+1)
 /\ data'=[data EXCEPT ![d]=FoldOps(LiveRows(d),log[p],Mode="omitNoCutoff",p)]
 /\ position'=[position EXCEPT ![d]=p]
 /\ applied'=[applied EXCEPT ![d]=Append(applied[d],log[p])]
 /\ prefixOK'=(prefixOK /\ p=position[d]+1)
 /\ monotoneOK'=(monotoneOK /\ p>=position[d])
 /\ omissionOK'=(omissionOK /\ OmissionSafeFor(data[d],log[p]))
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints,stage,stageAt,dur,durAt,durEp>>
\* Mutant: treating a later position hint as an applied checkpoint without
\* detecting/fetching its missing predecessors.
SkipGap(d) ==
 /\ NoPending(d)
 /\ Mode="gap" /\ deviceEpoch[d]=epoch /\ known[d]>position[d]+1
 /\ position'=[position EXCEPT ![d]=known[d]]
 /\ prefixOK'=FALSE
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,data,hints,monotoneOK,omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
\* Group commit (a first load applies the segments it holds in few transactions): ONE
\* transaction applies the retained segments position+1..q in order, and writes position q
\* with the last of them (as `Apply` writes it with one). No state between them is committed,
\* so no reader or crash sees one. Each segment still sees the rows of the ones before it,
\* so the fold is the same as q-position separate `Apply` steps.
\* groupedSkip mutant: the transaction omits the segments between the first and the last
\* (it commits position q over rows that lack them), which P5 and P1 must refuse.
RECURSIVE FoldRun(_,_,_)
FoldRun(state,from,to) ==
 IF from > to THEN state
 ELSE FoldRun(FoldOps(state,log[from],FALSE,from),from+1,to)
ApplyRun(d,q) ==
 /\ Mode \in ({"grouped","groupedSkip"} \cup KeyedModes)
 /\ NoPending(d)
 /\ deviceEpoch[d]=epoch /\ position[d]>=cut
 /\ q \in retained /\ q<=known[d] /\ q>position[d]+1
 /\ \A p \in (position[d]+1)..q : p \in retained
 /\ data'=[data EXCEPT ![d]=
      IF Mode="groupedSkip"
      THEN FoldOps(FoldOps(data[d],log[position[d]+1],FALSE,position[d]+1),log[q],FALSE,q)
      ELSE FoldRun(LiveRows(d),position[d]+1,q)]
 /\ position'=[position EXCEPT ![d]=q]
 /\ applied'=[applied EXCEPT ![d]=applied[d] \o SubSeq(log,position[d]+1,q)]
 \* Each constituent segment is the next position, so the prefix rule holds step by step.
 /\ prefixOK'=prefixOK
 /\ monotoneOK'=(monotoneOK /\ q>=position[d])
 /\ omissionOK'=(omissionOK /\ \A p \in (position[d]+1)..q :
       OmissionSafeFor(FoldRun(data[d],position[d]+1,p-1),log[p]))
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints,stage,stageAt,dur,durAt,durEp>>
\* Keyed first load (a device with no rows and no position loads a log that has never compacted
\* key by key instead of segment by segment). The host stages the run's operations by key
\* (`KeyedLoad`: key k folded over segments 1..q), then writes them bucket by bucket
\* (`KeyedBucket`). A bucket's rows are in the live table at once, but their keys have no
\* stream version and the position is still 0, so no reader serves them. They are DURABLE:
\* a crash (`StageLost`, the next start) drops the stage and keeps them. `dur` holds them and
\* `durAt` is the pending target: the run end q of the stage the newest bucket came from,
\* stored in the same transaction as the bucket. `KeyedPublish` writes the position and the
\* last rows in ONE transaction; the rows the live table then holds are the merge of the
\* durable ones with this stage.
\*
\* The rule (`keyed`): nothing is written, and no position is published, from a stage whose
\* run end q is below `durAt` (a retry that verified a shorter prefix), nor over durable rows
\* of another lifetime. Durable rows then always lie inside the prefix a publish names.
\* keyedLeak mutant: no such rule, so a shorter retry publishes q over rows from beyond it.
\* keyedSkip mutant: a key's fold leaves out the segment before the last (as a stage that
\* lost rows would). keyedEarly mutant: the position is written while a key is not yet folded.
KeyedGate(d) ==
 /\ Mode \in KeyedModes
 /\ deviceEpoch[d]=epoch /\ cut=0 /\ position[d]=0 /\ data[d]=Empty
\* The pending target admits a stage that ends at q.
PendingAdmits(d,q) ==
 Mode = "keyedLeak" \/ durAt[d] = 0 \/ (durEp[d] = epoch /\ q >= durAt[d])
RECURSIVE KeyOps(_,_)
KeyOps(ops,k) == IF Len(ops)=0 THEN <<>>
                 ELSE IF Head(ops).key=k THEN <<Head(ops)>> \o KeyOps(Tail(ops),k)
                 ELSE KeyOps(Tail(ops),k)
RECURSIVE FoldKeyRun(_,_,_,_)
FoldKeyRun(state,k,from,to) ==
 IF from > to THEN state
 ELSE FoldKeyRun(FoldOps(state,KeyOps(log[from],k),FALSE,from),k,from+1,to)
KeyedLoad(d,k,q) ==
 /\ KeyedGate(d)
 /\ q \in retained /\ q<=known[d] /\ q>=2
 /\ \A j \in Keys : stageAt[d][j] \in {0,q}
 /\ stage' = [stage EXCEPT ![d][k] =
      IF Mode="keyedSkip" /\ q>=3
      THEN FoldKeyRun(FoldKeyRun(Empty,k,1,q-2),k,q,q)[k]
      ELSE FoldKeyRun(Empty,k,1,q)[k]]
 /\ stageAt' = [stageAt EXCEPT ![d][k]=q]
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,
                dur,durAt,durEp,applied>>
\* One bucket's rows become durable (the live table merges them), with the pending target
\* in the same transaction. The position does not move.
KeyedBucket(d,k) ==
 /\ KeyedGate(d)
 /\ stageAt[d][k] # 0 /\ PendingAdmits(d,stageAt[d][k])
 /\ dur' = [dur EXCEPT ![d] = [dur[d] EXCEPT ![k] = MergeRow(dur[d][k], stage[d][k])]]
 /\ durAt' = [durAt EXCEPT ![d] = IF durAt[d] > stageAt[d][k] /\ durEp[d] = epoch
                                  THEN durAt[d] ELSE stageAt[d][k]]
 /\ durEp' = [durEp EXCEPT ![d] = epoch]
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,
                stage,stageAt,applied>>
\* A page of a bucket's complex rows (the code's `complexPages`): a run of one key's
\* operations, committed alone, so the durable row holds a PARTIAL fold of the key (segments
\* 1..j of the stage's 1..q, j < q), with the same pending target. Folding the rest at
\* publish gives the whole fold, whatever page was or was not written before a crash.
KeyedPage(d,k,j) ==
 /\ KeyedGate(d)
 /\ stageAt[d][k] # 0 /\ j \in 1..(stageAt[d][k]-1) /\ PendingAdmits(d,stageAt[d][k])
 /\ dur' = [dur EXCEPT ![d] = [dur[d] EXCEPT ![k] = MergeRow(dur[d][k], FoldKeyRun(Empty,k,1,j)[k])]]
 /\ durAt' = [durAt EXCEPT ![d] = IF durAt[d] > stageAt[d][k] /\ durEp[d] = epoch
                                  THEN durAt[d] ELSE stageAt[d][k]]
 /\ durEp' = [durEp EXCEPT ![d] = epoch]
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,
                stage,stageAt,applied>>
KeyedPublish(d,q) ==
 /\ KeyedGate(d)
 /\ q \in retained /\ q<=known[d]
 /\ PendingAdmits(d,q)
 /\ IF Mode="keyedEarly" THEN \E k \in Keys : stageAt[d][k]=q
    ELSE \A k \in Keys : stageAt[d][k]=q
 /\ data' = [data EXCEPT ![d] = [k \in Keys |-> MergeRow(dur[d][k], stage[d][k])]]
 /\ position' = [position EXCEPT ![d]=q]
 /\ applied' = [applied EXCEPT ![d]=Prefix(log,q)]
 /\ prefixOK' = prefixOK
 /\ monotoneOK' = (monotoneOK /\ q>=position[d])
 /\ omissionOK' = (omissionOK /\ \A p \in 1..q :
       OmissionSafeFor(FoldRun(Empty,1,p-1),log[p]))
 /\ stage' = [stage EXCEPT ![d]=Empty]
 /\ stageAt' = [stageAt EXCEPT ![d]=[k \in Keys |-> 0]]
 /\ dur' = [dur EXCEPT ![d]=Empty]
 /\ durAt' = [durAt EXCEPT ![d]=0]
 /\ durEp' = [durEp EXCEPT ![d]=epoch]
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,known,hints>>
\* A crash, or the next start: the stage goes, the durable rows and the pending target stay.
StageLost(d) ==
 /\ Mode \in KeyedModes
 /\ \E k \in Keys : stageAt[d][k] # 0
 /\ stage' = [stage EXCEPT ![d]=Empty]
 /\ stageAt' = [stageAt EXCEPT ![d]=[k \in Keys |-> 0]]
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,
                dur,durAt,durEp,applied>>
\* A load of this log can no longer finish the durable rows (`durAt[d] # 0`) a stopped
\* key-ordered load left: the log is of another lifetime (a reset or a rewrite) or it compacted,
\* so a snapshot and a new base stand in for the prefix those rows came from. The code decides
\* this from the marker alone (`keyedLoadBlocked` in log-keyed.ts: a snapshot, another base, a
\* different segment at a position the marker names, the flag off, no segment past the marker).
\* A log that is only shorter and agrees (`Len(log) < durAt[d]` with no reset or compaction:
\* a segment that cannot be fetched now, a registry that lags) is NOT unfinishable: the device
\* is refused by `PendingAdmits` with its rows kept, and finishes when the log is whole.
Unfinishable(d) ==
 /\ durAt[d] # 0
 /\ (durEp[d] # epoch \/ cut > 0)
\* The rebaseline: the durable rows, the pending target and the stage go together, in one
\* transaction, and the load starts again from what the log now holds. The position is 0
\* here already (a keyed device never published), so nothing a reader serves changes. What the
\* device wrote itself and has not published is not in this model: the code keeps it (the
\* rows that are the latest unpublished change of their key), and its tests state that.
\* keyedStuck mutant: no such step, so a device that holds durable rows of a log that
\* compacted or was rewritten can take no other step (EventuallyConverged fails).
Rebaseline(d) ==
 /\ Mode \in KeyedModes /\ Mode # "keyedStuck"
 /\ Unfinishable(d)
 /\ dur' = [dur EXCEPT ![d]=Empty]
 /\ durAt' = [durAt EXCEPT ![d]=0]
 /\ durEp' = [durEp EXCEPT ![d]=epoch]
 /\ stage' = [stage EXCEPT ![d]=Empty]
 /\ stageAt' = [stageAt EXCEPT ![d]=[k \in Keys |-> 0]]
 /\ UNCHANGED <<epoch,log,retained,cut,snapshot,budget,stopped,
                deviceEpoch,position,known,data,hints,prefixOK,monotoneOK,omissionOK,applied>>
\* The recommit (`log-recommit.ts`): a device the registry is behind, whose segments agree with
\* every row the registry still holds, commits its next segment again at the registry's next
\* position, against the registry's head. It adopts the registry's history once the registry is
\* at its position. Its rows do not change: they are the fold of the segments it applied, and
\* the log now holds those segments. Other devices then read them like any commit.
\* recommitForeign mutant: no agreement check (the code's check that the segment the registry
\* names at its position is the one this device applied there).
Recommit(d) ==
 /\ Mode \in RecommitModes /\ Mode # "noRecommit"
 /\ NoPending(d)
 /\ deviceEpoch[d] # epoch /\ Len(log) >= 1 /\ Len(log) < position[d]
 /\ Len(applied[d]) = position[d]
 /\ Mode = "recommitForeign" \/ Prefix(applied[d],Len(log)) = log
 /\ LET p == Len(log)+1 IN
    /\ log' = Append(log,applied[d][p])
    /\ retained' = retained \cup {p}
    /\ hints' = hints \cup {[generation |-> epoch, at |-> p]}
    /\ deviceEpoch' = IF p = position[d] THEN [deviceEpoch EXCEPT ![d]=epoch] ELSE deviceEpoch
    /\ known' = IF p = position[d] THEN [known EXCEPT ![d]=p] ELSE known
 /\ UNCHANGED <<epoch,cut,snapshot,budget,stopped,position,data,prefixOK,monotoneOK,
                omissionOK,stage,stageAt,dur,durAt,durEp,applied>>
Recover(d) == Recommit(d) \/ Install(d) \/ (\E p \in retained : Apply(d,p)) \/ SkipGap(d)
              \/ Rebaseline(d)
              \/ (\E q \in retained : ApplyRun(d,q))
              \/ (\E k \in Keys, q \in retained : KeyedLoad(d,k,q))
              \/ (\E k \in Keys : KeyedBucket(d,k))
              \/ (\E k \in Keys, j \in 1..MaxSteps : KeyedPage(d,k,j))
              \/ (\E q \in retained : KeyedPublish(d,q))
              \/ StageLost(d)
Next ==
 \/ Commit \/ Stop \/ Reset \/ Compact \/ Rollback
 \/ \E d \in Devices : FullCheck(d) \/ Recover(d)
 \/ \E d \in Devices, h \in hints : Deliver(d,h)
 \/ \E h \in hints : Drop(h)
Spec == Init /\ [][Next]_vars
        /\ WF_vars(Stop)
        /\ \A d \in Devices : WF_vars(FullCheck(d)) /\ WF_vars(Recover(d))

\* A smaller space for an exhaustive run: the corpus past its fourth batch adds no new
\* interleaving of the pending-target rule.
ShortLog == Len(log) <= 3

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
\* The intended winner of a key, from the log alone and independent of apply order: the
\* operation greatest in (stamp, ord, kind). Computed with the ordinal in every mode, so the
\* equalStampToday mutant is judged against the intended order and not its own.
IntendedRank(op) == BodyBase * (OrdBase * (KindBase * op.stamp + KindRank(op)) + op.ord) + op.body
IntendedBody(k) ==
  LET ops == {o \in AllOps(log) : o.key = k}
  IN IF ops = {} THEN 0
     ELSE LET top == CHOOSE o \in ops : \A q \in ops : IntendedRank(q) <= IntendedRank(o)
          IN top.body
\* P7: a caught-up replica of the current lifetime shows the intended winner of every key.
P7 == \A d \in Devices :
       (deviceEpoch[d]=epoch /\ position[d]=Len(log))
       => \A k \in Keys : data[d][k].body = IntendedBody(k)
EventuallyConverged == <>[](stopped /\ CaughtUp /\ P1)
\* The crash that drops a stage (`StageLost`) is the environment's, and a device that is
\* crashed again before every step never finishes a load, in any design. The liveness claim for
\* the key-ordered load is therefore made for the runs in which crashes end: the connection
\* eventually serves (`EventuallyConverged`) once no further crash occurs.
CrashesEnd == <>[][~(\E d \in Devices : StageLost(d))]_vars
LiveWhenCrashesEnd == CrashesEnd => EventuallyConverged
\* Expected FALSE: evidence that the two conflict orders are not equivalent.
StampEqualsLamport ==
 (epoch=1 /\ Len(log)=2) =>
 Visible(FoldLog(Empty,log))=LamportVisible(log)
=============================================================================
