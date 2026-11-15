------------------------- MODULE BatchVisibilityR4 -------------------------
EXTENDS Naturals, Integers, FiniteSets
CONSTANTS Design, Coverage, Mutant, MaxSteps, NewVersion, NewKey, DeleteMode
ASSUME /\ Design \in {"TODAY", "PROPOSED"}
       /\ Coverage \in {"full_inventory", "checkpoint_window"}
       /\ Mutant \in {0,7,8,9,10,11}
       /\ NewVersion \in {1,2} /\ NewKey \in {1,2}
       /\ DeleteMode \in {"both","explicit","omission"}
Runs == {1,2}
Keys == {1,2}
Version(r) == IF r=1 THEN 1 ELSE NewVersion
PK(r) == IF r=1 THEN 1 ELSE NewKey
Zero == [stamp |-> 0, batch |-> 0, value |-> 0, pk |-> 0,
         generation |-> 0, deletedAt |-> 0]
Empty == [k \in Keys |-> Zero]
VARIABLE s
vars == <<s>>
Open(q) == {r \in Runs : q.state[r]="collecting"}
Horizon(q) == IF Open(q)={} THEN 3
              ELSE IF 1 \in Open(q) THEN 1 ELSE 2
Compact(q) == IF Design="TODAY" THEN q ELSE [q EXCEPT !.tomb =
  [k \in Keys |-> IF q.tomb[k] < Horizon(q) THEN 0 ELSE q.tomb[k]]]
Step(q) == /\ s.n < MaxSteps /\ s'=Compact([q EXCEPT !.n=s.n+1])
Fence(r) == ~s.deleted /\ s.generation=1 /\ s.deletedAt=0
Compatible(r) ==
  /\ Version(r)>=s.floorVersion
  /\ Version(r)>=s.headVersion
  /\ (PK(r)=s.headKey \/ Version(r)>s.headVersion)
Wins(a,r,b) == r>a.stamp \/ (r=a.stamp /\ b>a.batch)
Observation(r,k,b) ==
  [stamp |-> r, batch |-> b, value |-> r*100+b*10+k, pk |-> PK(r),
   generation |-> 1, deletedAt |-> 0]
Merge(a,r,k,b,t,equal) ==
  IF r<t[k] THEN a
  ELSE IF r>a[k].stamp \/ (equal /\ r=a[k].stamp)
       THEN [a EXCEPT ![k]=Observation(r,k,b)] ELSE a
Init ==
  s=[n |-> 0, generation |-> 1, deleted |-> FALSE, deletedAt |-> 0,
     state |-> [r \in Runs |-> "collecting"],
     batch |-> [r \in Runs |-> 0],
     staged |-> [r \in Runs |-> [k \in Keys |-> 0]],
     accepted |-> {}, checkpoint |-> {}, full |-> {},
     updateRequired |-> {}, rows |-> Empty,
     tomb |-> [k \in Keys |-> 0], high |-> [k \in Keys |-> 0],
     floorVersion |-> 1, committed |-> 0, headVersion |-> 1, headKey |-> 1,
     admissionOK |-> TRUE, sameRunOK |-> TRUE, endOK |-> TRUE]
\* A positive staged value is the last upsert's batch; -1 is an explicit delete.
\* Values are distinct per run/batch/key: equal-body SEEN ownership is excluded.
Batch(r,k,isDelete) ==
  /\ s.state[r]="collecting" /\ s.batch[r]<3
  /\ (DeleteMode#"omission" \/ ~isDelete)
  /\ LET b == s.batch[r]+1
         passFence == Fence(r) \/ Mutant=7
         passCompat == Design="TODAY" \/ Compatible(r) \/ Mutant=8
         admitted == passFence /\ passCompat
         emits == admitted /\ Design="PROPOSED" /\ ~isDelete
         nextRows == IF emits
                     THEN Merge(s.rows,r,k,b,s.tomb,Mutant#11) ELSE s.rows
         shouldWin == emits /\ r>=s.tomb[k] /\ r>=s.rows[k].stamp
         q == [s EXCEPT
           !.batch[r]=b,
           !.staged[r][k]=IF admitted THEN (IF isDelete THEN -1 ELSE b)
                          ELSE @,
           !.rows=nextRows,
           !.high[k]=IF emits /\ r>=s.tomb[k] /\ r>s.high[k]
                     THEN r ELSE @,
           !.updateRequired=IF passFence /\ ~passCompat
                            THEN @ \cup {r} ELSE @,
           !.admissionOK=(@ /\ (~emits \/ Compatible(r))),
           !.sameRunOK=(@ /\ (~shouldWin \/ nextRows[k]=Observation(r,k,b)))]
     IN Step(q)
\* Finite scalar r is the order embedding of two fixed (o,r) stamps.
\* End accepts only a complete single-stream success; partial/retry excluded.
End(r,success,proof) ==
  /\ s.state[r]="collecting"
  /\ LET accept == success /\ Fence(r) /\ Compatible(r)
                  /\ r>=s.committed /\ r \notin s.updateRequired
         ups == [k \in Keys |->
           IF accept /\ Design="TODAY" /\ s.staged[r][k]>0
              /\ r>=s.tomb[k] /\ r>s.rows[k].stamp
           THEN Observation(r,k,s.staged[r][k]) ELSE s.rows[k]]
         deletes == IF accept
                    THEN {k \in Keys : s.staged[r][k]=-1} ELSE {}
         rows == [k \in Keys |->
           IF k \in deletes /\ ups[k].stamp<=r THEN Zero ELSE ups[k]]
         t == [k \in Keys |->
           IF k \in deletes /\ r>s.tomb[k] /\ Mutant#9 THEN r
           ELSE s.tomb[k]]
         q == [s EXCEPT
           !.state[r]=IF accept THEN "accepted" ELSE "refused",
           !.accepted=IF accept THEN @ \cup {r} ELSE @,
           !.checkpoint=IF accept THEN @ \cup {r} ELSE @,
           !.full=IF accept /\ proof /\ Coverage="full_inventory"
                    /\ DeleteMode#"explicit"
                  THEN @ \cup {r} ELSE @,
           !.rows=rows, !.tomb=t,
           !.sameRunOK=(@ /\ (\A k \in Keys :
             (accept /\ Design="TODAY" /\ s.staged[r][k]>0
              /\ r>=s.tomb[k] /\ r>s.rows[k].stamp)
             => rows[k]=Observation(r,k,s.staged[r][k]))),
           !.high=[k \in Keys |->
             IF k \in deletes /\ r>s.high[k] THEN r
             ELSE IF accept /\ Design="TODAY" /\ s.staged[r][k]>0
                     /\ r>s.high[k] THEN r ELSE s.high[k]],
           !.floorVersion=IF accept /\ Version(r)>s.floorVersion
                          THEN Version(r) ELSE @,
           !.committed=IF accept THEN r ELSE @,
           !.endOK=(@ /\ (deletes={} \/ accept))]
     IN Step(q)
\* Publication may refuse a previously accepted end. TODAY unwrites that run;
\* no preimages are invented. The following remote apply is outside this model.
Publish(r) ==
  /\ s.state[r]="accepted"
  /\ LET ok == Fence(r) /\ Compatible(r) /\ r>=s.committed
         omitted == IF ok /\ r \in s.full
                    THEN {k \in Keys : s.staged[r][k]<=0
                                       /\ s.rows[k].stamp<r} ELSE {}
         rows == [k \in Keys |->
           IF k \in omitted THEN Zero
           ELSE IF ~ok /\ Design="TODAY" /\ s.rows[k].stamp=r
                THEN Zero ELSE s.rows[k]]
         tombs == [k \in Keys |->
           IF k \in omitted /\ Design="PROPOSED" /\ Mutant#9
              /\ r>s.tomb[k] THEN r ELSE s.tomb[k]]
         q == [s EXCEPT
           !.state[r]=IF ok THEN "published" ELSE "refused",
           !.rows=rows,
           !.tomb=IF Mutant=10 THEN [k \in Keys |-> 0]
                  ELSE IF Design="TODAY" /\ ok
                       THEN [k \in Keys |-> IF tombs[k]<=r THEN 0 ELSE tombs[k]]
                       ELSE tombs,
           !.high=[k \in Keys |->
             IF k \in omitted /\ r>s.high[k] THEN r ELSE s.high[k]],
           !.headVersion=IF ok THEN Version(r) ELSE @,
           !.headKey=IF ok THEN PK(r) ELSE @,
           !.endOK=(@ /\ (omitted={} \/ r \in s.accepted))]
     IN Step(q)
\* Three concrete fence causes are distinct transitions; all purge this one stream.
Purge(cause) ==
  /\ s.generation=1 /\ s.deletedAt=0 /\ ~s.deleted
  /\ Step([s EXCEPT
       !.generation=IF cause="generation_moved_by_delete" THEN 2 ELSE @,
       !.deleted=(cause="control_deleted"),
       !.deletedAt=IF cause="stream_deleted_after_start" THEN 1 ELSE @,
       !.rows=Empty, !.tomb=[k \in Keys |-> 0],
       !.high=[k \in Keys |-> 0], !.checkpoint={}])
Next ==
  \/ \E r \in Runs, k \in Keys, d \in BOOLEAN : Batch(r,k,d)
  \/ \E r \in Runs, success \in BOOLEAN, proof \in BOOLEAN : End(r,success,proof)
  \/ \E r \in Runs : Publish(r)
  \/ \E c \in {"control_deleted","generation_moved_by_delete",
               "stream_deleted_after_start"} : Purge(c)
Spec == Init /\ [][Next]_vars
TypeOK ==
  /\ s.state \in [Runs -> {"collecting","accepted","refused","published"}]
  /\ s.batch \in [Runs -> 0..3]
  /\ s.tomb \in [Keys -> 0..2] /\ s.high \in [Keys -> 0..2]
  /\ s.accepted \subseteq Runs /\ s.checkpoint \subseteq s.accepted
  /\ s.n \in 0..MaxSteps
AcceptedEndOnly == s.endOK /\ s.checkpoint \subseteq s.accepted
NoPurgedRows == \A k \in Keys :
  s.rows[k].stamp>0 => (~s.deleted /\ s.rows[k].generation=s.generation
                                   /\ s.rows[k].deletedAt=s.deletedAt)
CompatibleAdmission == s.admissionOK
NoOlderResurrection == \A k \in Keys :
  s.rows[k].stamp>0 => s.rows[k].stamp>=s.high[k]
SameRunLaterBatch == s.sameRunOK
TombstoneBound ==
  /\ \A k \in Keys : s.tomb[k]=0 \/ s.tomb[k]>=Horizon(s)
  /\ Cardinality({k \in Keys : s.tomb[k]>0})<=Cardinality(Keys)
\* Expected failure, not part of the D1-D4 safety claim: pk change is not a purge.
CurrentPrimaryKeyOnly == \A k \in Keys :
  (s.headKey=2 /\ s.rows[k].stamp>0) => s.rows[k].pk=s.headKey
=============================================================================
