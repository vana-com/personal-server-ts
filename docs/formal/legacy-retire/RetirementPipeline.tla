------------------------- MODULE RetirementPipeline -------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Mode, MaxB, MaxW
VARIABLES pc, authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign
vars == <<pc, authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>
\* Row 1 is registered at the pin; row 2 is unsynced with a high
\* device-local counter and no causal re-add; row 3 is a deliberate re-add.
RowVersion == [r \in {1, 2, 3} |-> IF r = 1 THEN 2 ELSE 99]
Registered == {1}
AfterTombstone == [r \in {1, 2, 3} |-> IF r = 3 THEN 3 ELSE 0]
Eligible == {r \in {1, 2, 3} :
  IF r \in Registered THEN RowVersion[r] <= 2 ELSE AfterTombstone[r] < 3}
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
  /\ ack = "none"
  /\ malformed = FALSE
  /\ foreign = FALSE

Capture ==
  /\ pc = "capture" /\ authority
  /\ captured' = IF Mode = "CaptureReadds" THEN rows ELSE IF Mode = "UnsyncedByCounter" THEN {r \in rows : RowVersion[r] <= 2} ELSE Eligible
  /\ pc' = "sign"
  /\ UNCHANGED <<authority, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

Sign ==
  /\ pc = "sign" /\ authority
  /\ signed' = TRUE
  /\ pc' = "request"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, requested, hooks, unauth, at, done, ack, malformed, foreign>>

JournalRequest ==
  /\ pc = "request" /\ authority /\ signed
  /\ ack' = "unconfirmed"
  /\ pc' = "send"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, malformed, foreign>>

Request ==
  /\ pc = "send" /\ authority
  /\ requested' = TRUE
  /\ pc' = "reply"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, hooks, unauth, at, done, ack, malformed, foreign>>

\* An earlier send lost its reply while the head still appears live.
RetryNoReply ==
  /\ pc = "reply" /\ authority /\ ack = "unconfirmed"
  /\ pc' = "send"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

\* Another writer installs pin+1 before transport preflight; no new DELETE is sent.
NotSent ==
  /\ pc = "send" /\ authority
  /\ ack' = IF requested THEN ack ELSE "none"
  /\ foreign' = TRUE
  /\ pc' = "readForeign"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, malformed>>

ReadForeign ==
  /\ pc = "readForeign" /\ authority /\ foreign
  /\ pc' = IF requested THEN "blocked" ELSE "final"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

Reply ==
  /\ pc = "reply" /\ authority
  /\ ack' = "accepted"
  /\ pc' = "final"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, malformed, foreign>>

MalformedReply ==
  /\ pc = "reply" /\ authority
  /\ malformed' = TRUE
  /\ pc' = "restart"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, foreign>>

Restart ==
  /\ pc \in {"reply", "restart"}
  /\ pc' = IF ack = "accepted" \/ (Mode = "MalformedEchoRetried" /\ malformed) THEN "final" ELSE "blocked"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

Finality ==
  /\ pc = "final" /\ ((requested /\ (ack = "accepted" \/ (Mode = "MalformedEchoRetried" /\ malformed))) \/ (foreign /\ ack = "none"))
  /\ pc' = "blobStart"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

BlobStart ==
  /\ pc = "blobStart" /\ authority
  /\ pc' = "blobSign"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

BlobSign ==
  /\ pc = "blobSign" /\ Gate
  /\ pc' = "blobRequest"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

BlobRequest ==
  /\ pc = "blobRequest" /\ Gate
  /\ pc' = "blobErase"
  /\ unauth' = (unauth \/ ~authority)
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, at, done, ack, malformed, foreign>>

BlobErase ==
  /\ pc = "blobErase"
  /\ pc' = "receipt"
  /\ blobs' = blobs \ {at}
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

Receipt ==
  /\ pc = "receipt" /\ Gate
  /\ receipts' = receipts \cup {at}
  /\ unauth' = (unauth \/ ~authority)
  /\ at' = IF at = 2 THEN 1 ELSE at + 1
  /\ pc' = IF at = 2 THEN "localStart" ELSE "blobSign"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, blobs, signed, requested, hooks, done, ack, malformed, foreign>>

LocalStart ==
  /\ pc = "localStart" /\ authority
  /\ pc' = "local"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

LocalErase ==
  /\ pc = "local" /\ LocalGate
  /\ rows' = rows \ ({at} \cap captured)
  /\ removed' = removed \cup ({at} \cap captured)
  /\ unauth' = (unauth \/ ~authority)
  /\ pc' = IF at = 2 THEN "observe" ELSE "local"
  /\ at' = at + 1
  /\ UNCHANGED <<authority, captured, observed, receipts, blobs, signed, requested, hooks, done, ack, malformed, foreign>>

LocalSkip ==
  /\ pc = "local" /\ authority
  /\ pc' = "observe"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

Observe ==
  /\ pc = "observe"
  /\ observed' = (captured \cap rows = {})
  /\ pc' = "complete"
  /\ UNCHANGED <<authority, captured, rows, removed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

Complete ==
  /\ pc = "complete" /\ authority /\ receipts = Keys /\ (observed \/ Mode = "SkippedMeansClean")
  /\ done' = TRUE
  /\ pc' = "done"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, ack, malformed, foreign>>

AbsentMeansDone ==
  /\ pc = "local" /\ authority /\ Mode = "AbsentMeansDone"
  /\ done' = TRUE
  /\ pc' = "done"
  /\ UNCHANGED <<authority, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, ack, malformed, foreign>>

Revoke ==
  /\ authority /\ pc # "capture"
  /\ authority' = FALSE
  /\ UNCHANGED <<pc, captured, rows, removed, observed, receipts, blobs, signed, requested, hooks, unauth, at, done, ack, malformed, foreign>>

RunHook ==
  /\ ~authority /\ Mode = "RunAdditionsAfterRevoke" /\ hooks = 0
  /\ hooks' = 1
  /\ UNCHANGED <<pc, authority, captured, rows, removed, observed, receipts, blobs, signed, requested, unauth, at, done, ack, malformed, foreign>>

CapturedOnly == captured \subseteq Old /\ removed \subseteq captured /\ Replacement \subseteq rows
DoneImpliesObservedAbsence == done => (observed /\ captured \cap rows = {})
NoRetirementHooks == hooks = 0
AuthorityAtEveryEffect == ~unauth
AcknowledgedBeforeErase == (blobs # Keys \/ removed # {} \/ done) => ((ack = "accepted" \/ (foreign /\ ack = "none")) /\ ~malformed)
UnsyncedCaptured == pc # "capture" => Old \subseteq captured
DefiniteNotSentDoesNotIssue == (foreign /\ ack = "none") => ~requested
NotSentPreservesAmbiguity == (foreign /\ requested) => ack = "unconfirmed"
Next == RetryNoReply \/ NotSent \/ ReadForeign \/ JournalRequest \/ Reply \/ MalformedReply \/ Restart \/ Capture \/ Sign \/ Request \/ Finality \/ BlobStart \/ BlobSign \/ BlobRequest \/ BlobErase \/ Receipt \/ LocalStart \/ LocalErase \/ LocalSkip \/ Observe \/ Complete \/ AbsentMeansDone \/ Revoke \/ RunHook
Spec == Init /\ [][Next]_vars
=============================================================================
