-------------------------- MODULE PartialWorkspace --------------------------
EXTENDS PartialView
CONSTANT EarlyCompletion
VARIABLES buffered, partialMark, completeMark, snapshotCursor
allvars == <<ops,says,applied,shown,buffered,partialMark,completeMark,snapshotCursor>>
DurableInit == Init /\ buffered=0 /\ partialMark=FALSE
                    /\ completeMark=FALSE /\ snapshotCursor=0
ReadChunk == /\ applied<N /\ buffered<2 /\ buffered'=buffered+1
             /\ UNCHANGED <<ops,says,applied,shown,partialMark,completeMark,snapshotCursor>>
\* Two chunks stand for a fully validated body. Rows, receipt position and
\* visibility markers commit together. No chunk becomes a visible body.
CommitPart == /\ buffered=2 /\ Apply /\ buffered'=0
              /\ completeMark'=(EarlyCompletion \/ applied+1=N)
              /\ partialMark'=(applied+1<N)
              /\ snapshotCursor'=IF applied+1=N THEN N ELSE 0
Restart == /\ buffered'=0
           /\ UNCHANGED <<ops,says,applied,shown,partialMark,completeMark,snapshotCursor>>
DurableNext == ReadChunk \/ CommitPart \/ Restart
DurableSpec == DurableInit /\ [][DurableNext]_allvars
              /\ WF_allvars(ReadChunk) /\ WF_allvars(CommitPart)
TruthfulMarkers == /\ completeMark=(applied=N)
                   /\ partialMark=(applied>0 /\ applied<N)
                   /\ snapshotCursor=IF applied=N THEN N ELSE 0
CrashesStop == <>[][~Restart]_allvars
Settles == CrashesStop => <>(completeMark)
=============================================================================
