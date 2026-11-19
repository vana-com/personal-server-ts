------------------------------ MODULE Workspace ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC
CONSTANT Mutant
R == INSTANCE SqlRank WITH Mode <- "good", MaxSteps <- 6, row <- 0, log <- <<>>, nextOrd <- 0, steps <- 0
Keys == {1,2}
Op(k,s,n,b,f,t) == [key |-> k, stamp |-> s, ord |-> n, body |-> b,
                       first_o |-> f, kind |-> t]
\* Same-body higher ordinal, equal-ordinal hash tie, strict omission boundary,
\* explicit tombstone then resurrection with NULL first_o, and a deleted key.
Units == <<Op(1,1,0,1,1,"up"), Op(1,1,1,1,2,"up"),
           Op(1,1,1,2,0,"up"), Op(1,1,0,0,0,"omit"),
           Op(1,2,0,0,0,"delete"), Op(1,3,0,3,0,"up"),
           Op(2,3,0,0,0,"delete")>>
N == Len(Units)
Empty == [k \in Keys |-> R!CellEmpty]
Step(c,o) == [c EXCEPT ![o.key] = R!CellStep(@,o)]
Entries(c) == [k \in Keys |-> R!CellEntries(c[k])]
\* Independent set-based reference, not the incremental step under test.
Oracle(n) == [k \in Keys |->
  LET ups == {Units[i] : i \in {j \in 1..n : Units[j].key=k /\ Units[j].kind="up"}}
      dels == {Units[i] : i \in {j \in 1..n : Units[j].key=k /\ Units[j].kind#"up"}}
      u == IF ups={} THEN R!CellNone ELSE CHOOSE a \in ups : \A b \in ups : ~R!UpAfter(b,a)
      d == IF dels={} THEN R!CellNone ELSE CHOOSE a \in dels : \A b \in dels : ~R!DelAfter(b,a)
  IN [up |-> u, del |-> d]]
Identity(i) == <<i,"digest",1,"key-check">>
VARIABLE w
vars == <<w>>
Init == w = [at |-> 0, chunks |-> 0, inputSeal |-> FALSE,
  input |-> {}, receipts |-> {}, cells |-> Empty, visible |-> Empty,
  cursor |-> 0, complete |-> FALSE, phase |-> "collect",
  output |-> 0, uploaded |-> FALSE, uploadReceipt |-> FALSE,
  remote |-> "old", reply |-> "none", watermark |-> 0,
  seedReady |-> FALSE, seed |-> {}, reset |-> FALSE, oldCursor |-> N,
  fence |-> "valid", available |-> TRUE, retry |-> 0, retryDigest |-> "digest", skipped |-> FALSE, finishOK |-> TRUE]
Bound == w.fence="valid"
Collect ==
 /\ Bound /\ w.phase="collect" /\ w.at<N /\ w.available
 /\ IF w.chunks<2
     THEN w'=[w EXCEPT !.chunks=@+1]
     ELSE IF ~w.inputSeal THEN w'=[w EXCEPT !.inputSeal=TRUE]
     ELSE LET i==w.at+1
              c==IF Mutant="droppedTombstone" /\ Units[i].kind#"up"
                 THEN w.cells ELSE Step(w.cells,Units[i])
          IN w'=[w EXCEPT !.at=i, !.chunks=0, !.inputSeal=FALSE,
                !.input=@ \cup {i}, !.receipts=@ \cup {Identity(i)},
                !.cells=IF Mutant="receiptWithoutFold" THEN @ ELSE c,
                !.visible=IF Mutant="receiptWithoutFold" THEN @ ELSE c,
                !.cursor=IF i=N THEN N ELSE @, !.complete=(i=N)]
\* Matching receipts are a no-op. A mismatched retry is refused, never skipped.
Replay ==
 /\ w.at>0
 /\ \E i \in 1..w.at, digest \in {"digest","corrupt"} :
     w'=[w EXCEPT !.retry=i, !.retryDigest=digest,
       !.skipped=(<<i,digest,1,"key-check">> \in w.receipts)]
Unavailable == /\ w.available /\ w.phase="collect"
               /\ w'=[w EXCEPT !.available=FALSE]
Repair == /\ ~w.available /\ w'=[w EXCEPT !.available=TRUE]
PrepareSeed == /\ Bound /\ w.at=N /\ w.phase="collect"
               /\ w'=[w EXCEPT !.seedReady=TRUE, !.phase="seed"]
\* Seed includes all winner/tombstone obligations plus an unpublished local write.
Obligation == UNION {{Entries(Oracle(N))[k][j] : j \in 1..Len(Entries(Oracle(N))[k])} : k \in Keys} \cup {Op(3,4,0,4,0,"up")}
Rebase == /\ Bound /\ w.phase="seed" /\ w.seedReady
          /\ w'=[w EXCEPT !.seed=IF Mutant="splitSeed" THEN {} ELSE Obligation,
                 !.oldCursor=0, !.reset=TRUE, !.phase="folded"]
LateSeed == /\ Mutant="splitSeed" /\ w.reset /\ w.seed={}
            /\ w'=[w EXCEPT !.seed=Obligation]
SealOutput == /\ Bound /\ w.phase="folded"
              /\ IF w.output=0 THEN w'=[w EXCEPT !.output=1]
                 ELSE w'=[w EXCEPT !.output=2, !.phase="sealed"]
Upload == /\ Bound /\ w.phase="sealed" /\ ~w.uploaded
          /\ w.output=2 /\ w'=[w EXCEPT !.uploaded=TRUE]
Receipt == /\ Bound /\ w.phase="sealed" /\ w.uploaded
           /\ w'=[w EXCEPT !.uploadReceipt=TRUE, !.phase="ready"]
Send == /\ Bound /\ (w.phase="ready" \/
                     (Mutant="omittedUpload" /\ w.phase="sealed"))
        /\ w'=[w EXCEPT !.phase="sent", !.reply="unknown"]
\* CAS may land, lose to a competitor, or not land. Reply may be lost at any point.
Land == /\ Bound /\ w.phase="sent" /\ w.remote="old"
        /\ \E result \in {"ours","other"} : w'=[w EXCEPT !.remote=result]
ReadOutcome == /\ Bound /\ w.phase="sent"
               /\ w'=[w EXCEPT !.reply=w.remote,
                 !.phase=IF w.remote="ours" THEN "accepted"
                         ELSE IF w.remote="other" THEN "aborted" ELSE "ready"]
Finish == /\ Bound /\ w.phase="accepted"
          /\ w'=[w EXCEPT !.watermark=N, !.phase="finished",
                 !.finishOK=(@ /\ Bound /\ w.remote="ours")]
Fence == /\ w.fence="valid"
         /\ \E cause \in {"deleted","generation","key-check"} :
            w'=[w EXCEPT !.fence=cause]
Abandon == /\ ~Bound /\ w.phase \notin {"aborted","clean"}
           /\ w'=[w EXCEPT !.phase="aborted"]
Cleanup == /\ w.phase \in {"finished","aborted"}
           /\ w'=[w EXCEPT !.input={}, !.output=0, !.phase="clean"]
\* A crash at EVERY action boundary loses only volatile ingest bytes and reply.
\* Committed input, fold, output seals, receipts, seed and authority survive a lost reply.
Crash == w'=[w EXCEPT !.chunks=0, !.inputSeal=FALSE, !.reply="none"]
EarlyCursor == /\ Mutant="earlyCursor" /\ w.at<N
               /\ w'=[w EXCEPT !.cursor=N]
EarlyCleanup == /\ Mutant="earlyCleanup" /\ w.at>0 /\ w.phase="collect"
                /\ w'=[w EXCEPT !.input={}]
Work == Collect \/ PrepareSeed \/ Rebase \/ LateSeed \/ SealOutput \/ Upload
        \/ Receipt \/ Send \/ Land \/ ReadOutcome \/ Finish \/ Abandon \/ Cleanup
Next == Work \/ Crash \/ Replay \/ Unavailable \/ Repair \/ Fence
        \/ EarlyCursor \/ EarlyCleanup
Spec == Init /\ [][Next]_vars /\ WF_vars(Work) /\ WF_vars(Repair)
        /\ SF_vars(Land)
TypeOK == w.at \in 0..N /\ w.cursor \in {0,N} /\ w.output \in 0..2
ReceiptedFold == w.cells=Oracle(w.at) /\ w.visible=w.cells
NoGap == w.cursor<=w.at /\ w.receipts={Identity(i) : i \in 1..w.at}
Visibility == w.complete => w.at=N /\ Entries(w.visible)=Entries(Oracle(N))
UploadBeforeCAS == w.remote="ours" => w.uploaded /\ w.uploadReceipt
RemoteAuthority == w.watermark>0 => w.remote="ours" /\ w.finishOK
SeedAtomic == w.reset => w.oldCursor=0 /\ w.seed=Obligation
LiveInputs == w.phase \notin {"finished","aborted","clean"} => 1..w.at \subseteq w.input
LiveOutputs == w.phase \in {"sealed","ready","sent","accepted"} => w.output=2
ReplayIdentity == w.skipped =>
  <<w.retry,w.retryDigest,1,"key-check">> \in w.receipts /\ w.retryDigest="digest"
NoLocalAcceptance == w.phase="accepted" => w.remote="ours"
FenceStops == [][(~Bound) => UNCHANGED <<w.cells,w.cursor,w.watermark,w.oldCursor>>]_vars
OnlyAcceptedAdvance == [][w.watermark'>w.watermark =>
                         Bound /\ w.phase="accepted" /\ w.remote="ours"]_vars
OneLease == /\ w.chunks \in 0..2
            /\ (w.output>0 => w.chunks=0 /\ ~w.inputSeal)
\* Explicit expected vectors detect a shared renderer/comparator mistake.
FoldVectors == /\ Oracle(2)[1].up.ord=1 /\ Oracle(2)[1].up.first_o=2
               /\ Oracle(3)[1].up.body=2 /\ Oracle(3)[1].up.first_o=0
               /\ Len(Entries(Oracle(4))[1])=1
               /\ Entries(Oracle(5))[1][1].kind="delete"
               /\ Entries(Oracle(6))[1]= <<Units[5],Units[6]>>
               /\ Entries(Oracle(7))[2]= <<Units[7]>>
\* Assumes corrupt/missing storage eventually repairs; no infinite crashes.
CrashesEnd == <>[][~Crash]_vars
StorageSettles == <>[](w.available)
Settles == (CrashesEnd /\ StorageSettles) => <>(w.phase="clean")
=============================================================================
