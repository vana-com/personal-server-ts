-------------------------- MODULE BatchVisibility --------------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANTS K, Values, Design, Coverage, Mutant, MaxSteps
ASSUME /\ Design \in {"TODAY", "PROPOSED"}
       /\ Coverage \in {"full_inventory", "checkpoint_window"}
       /\ Mutant \in 0..5
       /\ MaxSteps \in Nat
VARIABLES source, d, r, best, del, rdel, log, cursor, active, cutoff,
          seen, staged, merged, checkpoint, proof, clock, steps,
          omissionOK, failureOK, laterOK
vars == <<source,d,r,best,del,rdel,log,cursor,active,cutoff,
          seen,staged,merged,checkpoint,proof,clock,steps,
          omissionOK,failureOK,laterOK>>
Zero == [stamp |-> 0, value |-> "absent"]
Empty == [k \in K |-> Zero]
Present(x) == {k \in K : x[k].value # "absent"}
Join(a,b) == [k \in K |-> IF b[k].stamp > a[k].stamp THEN b[k] ELSE a[k]]
One(k,v,s) == [j \in K |-> IF j=k THEN [stamp |-> s,value |-> v] ELSE Zero]
DeleteFloor(a,b) ==
  [k \in K |-> IF b[k].value="absent" /\ b[k].stamp > a[k]
              THEN b[k].stamp ELSE a[k]]
Safe(x,f) == \A k \in K : x[k].value # "absent" => x[k].stamp > f[k]
\* Keep an independent maximum-stamp oracle, even when a mutant corrupts d.
Commit(candidate,observations) ==
  /\ d' = candidate
  /\ best' = Join(best,observations)
  /\ del' = DeleteFloor(del,observations)
  /\ log' = Append(log, [rows |-> candidate, floor |-> del'])
  /\ UNCHANGED <<r,rdel,cursor>>
Tick == /\ steps < MaxSteps /\ steps'=steps+1
Init ==
  /\ source \in [K -> (Values \cup {"absent"})]
  /\ d=Empty /\ r=Empty /\ best=Empty
  /\ del=[k \in K |-> 0] /\ rdel=del
  /\ log = <<>> /\ cursor=0
  /\ active=FALSE /\ cutoff=0 /\ seen={}
  /\ staged=Empty /\ merged={} /\ checkpoint={} /\ proof=FALSE
  /\ clock=0 /\ steps=0
  /\ omissionOK=TRUE /\ failureOK=TRUE /\ laterOK=TRUE
ChangeSource(k,v) ==
  /\ Tick /\ source'=[source EXCEPT ![k]=v]
  /\ UNCHANGED <<d,r,best,del,rdel,log,cursor,active,cutoff,seen,staged,
                merged,checkpoint,proof,clock,omissionOK,failureOK,laterOK>>
Begin ==
  /\ Tick /\ ~active
  /\ active'=TRUE /\ clock'=clock+1 /\ cutoff'=clock+1
  /\ seen'={} /\ staged'=Empty /\ merged'={} /\ checkpoint'={}
  /\ proof'=FALSE
  /\ UNCHANGED <<source,d,r,best,del,rdel,log,cursor,
                omissionOK,failureOK,laterOK>>
\* One key per batch; arbitrary key order. Source may change between batches.
Batch(k) ==
  /\ Tick /\ active /\ ~proof /\ k \notin seen
  /\ source[k] # "absent"
  /\ LET obs == One(k,source[k],cutoff)
         normal == Join(d,obs)
         up == IF Mutant=4
               THEN [d EXCEPT ![k]=obs[k]] ELSE normal
         omitted == {j \in K \ {k}: up[j].stamp < cutoff}
         bad == [j \in K |-> IF j \in omitted
                             THEN [stamp |-> cutoff,value |-> "absent"]
                             ELSE Zero]
         emits == Design="PROPOSED"
     IN /\ IF emits
           THEN Commit(IF Mutant=1 THEN Join(up,bad) ELSE up,
                       IF Mutant=1 THEN Join(obs,bad) ELSE obs)
           ELSE UNCHANGED <<d,r,best,del,rdel,log,cursor>>
        /\ omissionOK'=(omissionOK /\ ~(emits /\ Mutant=1 /\
                                          (Present(up) \cap omitted)# {}))
        /\ merged'=IF emits THEN merged \cup {k} ELSE merged
  /\ seen'=seen \cup {k}
  /\ staged'=[staged EXCEPT ![k]=[stamp |-> cutoff,value |-> source[k]]]
  /\ UNCHANGED <<source,active,cutoff,checkpoint,proof,clock,failureOK,laterOK>>
\* Proof is an explicit producer/server fact, not inferred from an empty batch.
\* A changing source need not be a consistent snapshot; this is a scope model.
Prove ==
  /\ Tick /\ active /\ ~proof
  /\ Coverage="full_inventory"
  /\ {k \in K: source[k] # "absent"} \subseteq seen
  /\ proof'=TRUE
  /\ UNCHANGED <<source,d,r,best,del,rdel,log,cursor,active,cutoff,seen,
                staged,merged,checkpoint,clock,omissionOK,failureOK,laterOK>>
Checkpoint ==
  /\ Tick /\ active /\ Coverage="checkpoint_window"
  /\ checkpoint # (IF Mutant=5 THEN seen ELSE merged)
  /\ checkpoint'=(IF Mutant=5 THEN seen ELSE merged)
  /\ UNCHANGED <<source,d,r,best,del,rdel,log,cursor,active,cutoff,seen,
                staged,merged,proof,clock,omissionOK,failureOK,laterOK>>
End(success) ==
  /\ Tick /\ active
  /\ LET up == IF success /\ Design="TODAY" THEN Join(d,staged) ELSE d
         replacing == Coverage="full_inventory" /\ proof /\
                       (success \/ Mutant=2)
         targets == IF replacing
                    THEN {k \in K \ seen: Mutant=3 \/ up[k].stamp < cutoff}
                    ELSE {}
         omissions == [k \in K |-> IF k \in targets
                                  THEN [stamp |-> cutoff,value |-> "absent"]
                                  ELSE Zero]
         final == IF Mutant=3
                  THEN [k \in K |-> IF k \in targets THEN omissions[k] ELSE up[k]]
                  ELSE Join(up,omissions)
         observations == IF success /\ Design="TODAY"
                         THEN Join(staged,omissions) ELSE omissions
     IN /\ Commit(final,observations)
        /\ omissionOK'=(omissionOK /\
             ((Present(up) \cap targets)={} \/ (success /\ proof)))
        /\ failureOK'=(failureOK /\ (success \/ Present(d) \subseteq Present(final)))
        /\ laterOK'=(laterOK /\
             (\A k \in K: up[k].stamp > cutoff => final[k]=up[k]))
  /\ active'=FALSE /\ proof'=FALSE
  /\ merged'=IF success THEN seen ELSE merged
  /\ checkpoint'=IF success /\ Coverage="checkpoint_window" THEN seen ELSE checkpoint
  /\ UNCHANGED <<source,cutoff,seen,staged,clock>>
\* Remote writes/deletes have fresh total-order stamps; run batches may then
\* arrive with their older, fixed run stamp.
Remote(k,v) ==
  /\ Tick
  /\ Commit(Join(d,One(k,v,clock+1)),One(k,v,clock+1))
  /\ clock'=clock+1
  /\ UNCHANGED <<source,active,cutoff,seen,staged,merged,checkpoint,proof,
                omissionOK,failureOK,laterOK>>
Publish ==
  /\ cursor < Len(log)
  /\ cursor'=cursor+1
  /\ r'=log[cursor+1].rows /\ rdel'=log[cursor+1].floor
  /\ UNCHANGED <<source,d,best,del,log,active,cutoff,seen,staged,merged,
                checkpoint,proof,clock,steps,omissionOK,failureOK,laterOK>>
Next ==
  \/ \E k \in K, v \in Values \cup {"absent"}: ChangeSource(k,v) \/ Remote(k,v)
  \/ \E k \in K: Batch(k)
  \/ Begin \/ Prove \/ Checkpoint \/ End(TRUE) \/ End(FALSE) \/ Publish
Spec == Init /\ [][Next]_vars
TypeOK ==
  /\ source \in [K -> (Values \cup {"absent"})]
  /\ active \in BOOLEAN /\ proof \in BOOLEAN
  /\ seen \subseteq K /\ merged \subseteq K /\ checkpoint \subseteq K
  /\ cursor \in 0..Len(log) /\ steps \in 0..MaxSteps
  /\ \A k \in K: d[k].stamp \in Nat /\ r[k].stamp \in Nat
NoOmissionBeforeProof == omissionOK
FailedRunNeverDeletes == failureOK
NoResurrection == Safe(d,del) /\ Safe(r,rdel)
LaterWriteKept == laterOK
StampConvergence == (~active /\ cursor=Len(log)) => (d=best /\ r=best)
CheckpointSoundness == Coverage="checkpoint_window" => checkpoint \subseteq merged
\* TODO: BRIEF.md line 27 is redacted. No missing obligation reconstructed.
=============================================================================
