------------------------- MODULE RetirementPipeline -------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Mode, MaxB, MaxW
VARIABLES pc, authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done
vars == <<pc, authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>
Old == {1, 2}
Replacement == {3}
Keys == {1, 2}
Gate == authority \/ (Mode = "GateBlobBatchOnce" /\ pc \in {"blobSign", "blobRequest", "receipt"})
LocalGate == authority \/ Mode = "GateLocalLoopOnce"
Init ==
  /\ pc = "capture"
  /\ authority = TRUE
  /\ captured = {}
  /\ rows = {1, 2, 3}
  /\ removed = {}
  /\ observed = FALSE
  /\ receipts = {}
  /\ blobs = {1, 2}
  /\ signed = FALSE
  /\ requested = FALSE
  /\ hooks = 0
  /\ unauth = FALSE
  /\ at = 1
  /\ done = FALSE

Capture ==
  /\ pc = "capture" /\ authority
  /\ captured' = IF Mode = "CaptureReadds" THEN rows ELSE Old
  /\ pc' = "sign"
  /\ UNCHANGED <<authority, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

Sign ==
  /\ pc = "sign" /\ authority
  /\ signed' = TRUE
  /\ pc' = "request"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, requested, hooks, unauth, at, done>>

Request ==
  /\ pc = "request" /\ authority /\ signed
  /\ requested' = TRUE
  /\ pc' = "final"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, hooks, unauth, at, done>>

Finality ==
  /\ pc = "final" /\ requested
  /\ pc' = "blobStart"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

BlobStart ==
  /\ pc = "blobStart" /\ authority
  /\ pc' = "blobSign"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

BlobSign ==
  /\ pc = "blobSign" /\ Gate
  /\ pc' = "blobRequest"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

BlobRequest ==
  /\ pc = "blobRequest" /\ Gate
  /\ pc' = "blobErase"
  /\ unauth' = (unauth \/ ~authority)
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, at, done>>

BlobErase ==
  /\ pc = "blobErase"
  /\ pc' = "receipt"
  /\ blobs' = blobs \ {at}
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, signed, requested, hooks, unauth, at, done>>

Receipt ==
  /\ pc = "receipt" /\ Gate
  /\ receipts' = receipts \cup {at}
  /\ unauth' = (unauth \/ ~authority)
  /\ at' = IF at = 2 THEN 1 ELSE at + 1
  /\ pc' = IF at = 2 THEN "localStart" ELSE "blobSign"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, blobs, signed, requested, hooks, done>>

LocalStart ==
  /\ pc = "localStart" /\ authority
  /\ pc' = "local"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

LocalErase ==
  /\ pc = "local" /\ LocalGate
  /\ rows' = rows \ {at}
  /\ removed' = removed \cup {at}
  /\ unauth' = (unauth \/ ~authority)
  /\ pc' = IF at = 2 THEN "observe" ELSE "local"
  /\ at' = at + 1
  /\ UNCHANGED <<authority, captured, observed, receipts, blobs, signed, requested, hooks, done>>

LocalSkip ==
  /\ pc = "local" /\ authority
  /\ pc' = "observe"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

Observe ==
  /\ pc = "observe"
  /\ observed' = (captured \cap rows = {})
  /\ pc' = "complete"
  /\ UNCHANGED <<authority, captured, rows, removed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

Complete ==
  /\ pc = "complete" /\ authority /\ receipts = Keys /\ (observed \/ Mode = "SkippedMeansClean")
  /\ done' = TRUE
  /\ pc' = "done"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at>>

AbsentMeansDone ==
  /\ pc = "local" /\ authority /\ Mode = "AbsentMeansDone"
  /\ done' = TRUE
  /\ pc' = "done"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at>>

Revoke ==
  /\ authority /\ pc # "capture"
  /\ authority' = FALSE
  /\ UNCHANGED <<pc, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done>>

RunHook ==
  /\ ~authority /\ Mode = "RunAdditionsAfterRevoke" /\ hooks = 0
  /\ hooks' = 1
  /\ UNCHANGED <<pc, authority, captured, rows, removed, observed, receipts, blobs, signed, requested, unauth, at, done>>

CapturedOnly == captured \subseteq Old /\ removed \subseteq captured /\ Replacement \subseteq rows
DoneImpliesObservedAbsence == done => (observed /\ captured \cap rows = {})
NoRetirementHooks == hooks = 0
AuthorityAtEveryEffect == ~unauth
Next == Capture \/ Sign \/ Request \/ Finality \/ BlobStart \/ BlobSign \/ BlobRequest \/ BlobErase \/ Receipt \/ LocalStart \/ LocalErase \/ LocalSkip \/ Observe \/ Complete \/ AbsentMeansDone \/ Revoke \/ RunHook
Spec == Init /\ [][Next]_vars
=============================================================================
