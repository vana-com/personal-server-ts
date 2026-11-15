---------------------------- MODULE PublishSnapshot ----------------------------
(***************************************************************************)
(* One stream's publish: what rows may a version contain?                  *)
(*                                                                         *)
(* `records` changes only inside the connection's slot turns. The publish  *)
(* reads the watermark W in its turn and sends the rows as of W. The       *)
(* version must be exactly the rows as of W: no row newer than W, no       *)
(* change at or below W missing (the commit acknowledges W).               *)
(*                                                                         *)
(* Mode "spool"       copy each row into the spool inside the turn         *)
(*      "view"        pin a read view in the turn; check its MAX(seq) = W  *)
(*      "viewNoCheck" pin a read view in the turn; no check (control)      *)
(*      "live"        read `records` during the transfer (control)         *)
(* NonSlot allows a write that ignores the slot, inside the turn.          *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS Rows, MaxSeq, Mode, NonSlot
VARIABLES seq, rec, hist, pc, w, src, copied, pub

vars == <<seq, rec, hist, pc, w, src, copied, pub>>

Unread == -1

Init ==
  /\ seq = 0
  /\ rec = [r \in Rows |-> 0]
  /\ hist = [s \in 0..MaxSeq |-> [r \in Rows |-> 0]]
  /\ pc = "idle"
  /\ w = 0
  /\ src = [r \in Rows |-> 0]
  /\ copied = {}
  /\ pub = [r \in Rows |-> Unread]

Write(r) ==
  /\ seq < MaxSeq
  /\ LET new == [rec EXCEPT ![r] = seq + 1]
     IN /\ rec' = new
        /\ hist' = [hist EXCEPT ![seq + 1] = new]
  /\ seq' = seq + 1

\* A writer takes the slot: never while the publish holds it.
SlotWrite(r) == /\ pc # "turn" /\ Write(r)
  /\ UNCHANGED <<pc, w, src, copied, pub>>

\* A write that ignores the slot (what the W check guards against).
RogueWrite(r) == /\ NonSlot /\ pc = "turn" /\ Write(r)
  /\ UNCHANGED <<pc, w, src, copied, pub>>

ReadW ==
  /\ pc = "idle"
  /\ w' = seq
  /\ pc' = "turn"
  /\ UNCHANGED <<seq, rec, hist, src, copied, pub>>

Pin ==
  /\ pc = "turn" /\ Mode \in {"view", "viewNoCheck"}
  /\ IF Mode = "view" /\ seq # w
       THEN pc' = "idle"                \* the view disagrees with W: start over
       ELSE pc' = "transfer"
  /\ src' = rec
  /\ UNCHANGED <<seq, rec, hist, w, copied, pub>>

Copy(r) ==
  /\ pc = "turn" /\ Mode = "spool" /\ r \notin copied
  /\ src' = [src EXCEPT ![r] = rec[r]]
  /\ copied' = copied \cup {r}
  /\ UNCHANGED <<seq, rec, hist, pc, w, pub>>

CopyDone ==
  /\ pc = "turn" /\ Mode = "spool" /\ copied = Rows
  /\ pc' = "transfer"
  /\ UNCHANGED <<seq, rec, hist, w, src, copied, pub>>

LiveTurn ==
  /\ pc = "turn" /\ Mode = "live"
  /\ pc' = "transfer"
  /\ UNCHANGED <<seq, rec, hist, w, src, copied, pub>>

Read(r) ==
  /\ pc = "transfer" /\ pub[r] = Unread
  /\ pub' = [pub EXCEPT ![r] = IF Mode = "live" THEN rec[r] ELSE src[r]]
  /\ UNCHANGED <<seq, rec, hist, pc, w, src, copied>>

Commit ==
  /\ pc = "transfer" /\ \A r \in Rows : pub[r] # Unread
  /\ pc' = "done"
  /\ UNCHANGED <<seq, rec, hist, w, src, copied, pub>>

Next ==
  \/ \E r \in Rows : SlotWrite(r) \/ RogueWrite(r) \/ Copy(r) \/ Read(r)
  \/ ReadW \/ Pin \/ CopyDone \/ LiveTurn \/ Commit
  \/ (pc = "done" /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ pc \in {"idle", "turn", "transfer", "done"}
  /\ seq \in 0..MaxSeq

\* The published version is the rows as of the acknowledged watermark.
VersionIsCut == pc = "done" => pub = hist[w]
=============================================================================
