---------------------------- MODULE RegistryDelta ----------------------------
(***************************************************************************)
(* The registry change feed with deltas: writers commit registry rows for  *)
(* one owner, and a reader holding a cursor asks for "every row that       *)
(* changed after my cursor". The question this model answers: can a reader *)
(* that applies such answers ever skip a committed change, and is a reset  *)
(* always followed by a full listing?                                      *)
(*                                                                         *)
(* The gateway numbers changes with one counter row per owner. A writer    *)
(* takes the next number by updating that row, which holds the row lock    *)
(* until its transaction ends (Numbering = "counter"). Each changed row    *)
(* keeps one change record: its scope and the number of its latest change. *)
(* A hard-deleted row keeps its record. A delta answer reads the counter   *)
(* and the records above the reader's cursor in one snapshot, and joins    *)
(* each record to the row's current state. A cursor below the floor (the   *)
(* number from which records are complete) is answered "reset": the       *)
(* reader lists everything.                                                *)
(*                                                                         *)
(* The owner has one connection: its control row "ctl" (active, a         *)
(* tombstone after a delete, or active again after a reconnect) and its    *)
(* log row "log". The reader applies a delta itself or hands it to the     *)
(* full cycle (a listing). It applies a log row of a connection it holds   *)
(* active and a control tombstone (it purges; a log row of a deleted       *)
(* connection is skipped, as the cycle's apply returns before the log).    *)
(* It hands to the cycle a control row active again (a new lifetime), a    *)
(* gone row, and a log row of a connection it does not hold.               *)
(*                                                                         *)
(* Each mutation switches off one of those choices:                        *)
(*   Numbering = "sequence"  a number taken at write time with no lock,    *)
(*                           as nextval() would give                       *)
(*   OneSnapshot = FALSE     records and counter read in two statements    *)
(*   ResetLists = FALSE      a reset moves the cursor without a listing    *)
(*   HonorFloor = FALSE      no reset for a cursor below the floor         *)
(*   GoneRecords = FALSE     a hard delete removes the change record       *)
(*   ControlRows = "reconnect"  a control row active again is applied from *)
(*                           the delta, without the cycle's listing        *)
(*   ControlRows = "ignore"  a control tombstone in the delta is skipped   *)
(* ControlRows = "handoff" is the earlier design: every control row hands  *)
(* the delta to the cycle.                                                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Writers, MaxTxns, NoWriter,
          Numbering, OneSnapshot, ResetLists, HonorFloor, GoneRecords,
          ControlRows

Scopes == {"ctl", "log"}
\* What a write does to each row. "gone": a hard delete (a failed
\* registration's rollback). "tomb": the connection's delete. "act": the
\* control row active again, a new lifetime (a reconnect).
Ops == [ctl |-> {"tomb", "act", "gone"}, log |-> {"app", "gone"}]

VARIABLES
  counter,   \* the owner's committed number
  nextSeq,   \* Numbering = "sequence" only: the next nextval()
  lock,      \* the writer holding the counter row lock, or NoWriter
  txn,       \* per writer: phase, scope, op, number
  ver,       \* per scope: committed version (every write or delete bumps it)
  kind,      \* per scope: the op of its latest committed change
  chg,       \* per scope: number of the change record, 0 = none
  hist,      \* committed changes: <<number, scope, version>>
  txns,      \* transactions begun (bounds the model)
  floor,     \* records are complete for changes numbered above this
  floored,   \* the floor moved (once)
  since,     \* reader: its cursor
  view,      \* reader: the version it holds per scope
  rkind,     \* reader: its connection's control as it holds it ("act", "tomb", "gone")
  rphase,    \* reader: idle, rows, applying, settling, or listing
  rbuf,      \* reader: the snapshot decision awaiting apply
  rcursor    \* reader: the cursor a pending apply or listing will set

vars == <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored,
          since, view, rkind, rphase, rbuf, rcursor>>

Max(a, b) == IF a > b THEN a ELSE b

\* The version of `s` as of number `n`: its latest change numbered <= n.
VerAt(s, n) ==
  LET at == {h[3] : h \in {x \in hist : x[2] = s /\ x[1] <= n}}
  IN IF at = {} THEN 0 ELSE CHOOSE v \in at : \A u \in at : u <= v

Init ==
  /\ counter = 0 /\ nextSeq = 1 /\ lock = NoWriter
  /\ txn = [w \in Writers |-> [phase |-> "idle", scope |-> "log", op |-> "app", seq |-> 0]]
  /\ ver = [s \in Scopes |-> 0] /\ chg = [s \in Scopes |-> 0]
  /\ kind = [ctl |-> "act", log |-> "app"]
  /\ hist = {} /\ txns = 0 /\ floor = 0 /\ floored = FALSE
  /\ since = 0 /\ view = [s \in Scopes |-> 0] /\ rkind = "act"
  /\ rphase = "idle" /\ rcursor = 0
  /\ rbuf = [handoff |-> FALSE, view |-> [s \in Scopes |-> 0], rkind |-> "act"]

-----------------------------------------------------------------------------
(* Writers *)

Begin(w) ==
  /\ txn[w].phase = "idle" /\ txns < MaxTxns
  /\ \E s \in Scopes : \E o \in Ops[s] :
       txn' = [txn EXCEPT ![w] = [phase |-> "open", scope |-> s, op |-> o, seq |-> 0]]
  /\ txns' = txns + 1
  /\ UNCHANGED <<counter, nextSeq, lock, ver, kind, chg, hist, floor, floored,
                 since, view, rkind, rphase, rbuf, rcursor>>

\* Take the number: at the write (trigger IMMEDIATE) or at COMMIT (DEFERRED);
\* the interleavings cover both.
Number(w) ==
  /\ txn[w].phase = "open"
  /\ IF Numbering = "counter"
       THEN /\ lock = NoWriter /\ lock' = w
            /\ txn' = [txn EXCEPT ![w].phase = "numbered", ![w].seq = counter + 1]
            /\ UNCHANGED nextSeq
       ELSE /\ txn' = [txn EXCEPT ![w].phase = "numbered", ![w].seq = nextSeq]
            /\ nextSeq' = nextSeq + 1 /\ UNCHANGED lock
  /\ UNCHANGED <<counter, ver, kind, chg, hist, txns, floor, floored,
                 since, view, rkind, rphase, rbuf, rcursor>>

Commit(w) ==
  /\ txn[w].phase = "numbered"
  /\ LET s == txn[w].scope
         n == txn[w].seq
     IN /\ ver' = [ver EXCEPT ![s] = @ + 1]
        /\ kind' = [kind EXCEPT ![s] = txn[w].op]
        /\ chg' = [chg EXCEPT ![s] = IF txn[w].op = "gone" /\ ~GoneRecords THEN 0 ELSE n]
        /\ counter' = IF Numbering = "counter" THEN n ELSE Max(counter, n)
        /\ hist' = hist \cup {<<n, s, ver[s] + 1>>}
  /\ lock' = IF lock = w THEN NoWriter ELSE lock
  /\ txn' = [txn EXCEPT ![w].phase = "idle"]
  /\ UNCHANGED <<nextSeq, txns, floor, floored, since, view, rkind, rphase, rbuf, rcursor>>

Abort(w) ==
  /\ txn[w].phase \in {"open", "numbered"}
  /\ lock' = IF lock = w THEN NoWriter ELSE lock
  /\ txn' = [txn EXCEPT ![w].phase = "idle"]
  /\ UNCHANGED <<counter, nextSeq, ver, kind, chg, hist, txns, floor, floored,
                 since, view, rkind, rphase, rbuf, rcursor>>

\* History below here was never recorded (the migration that adds records).
RaiseFloor ==
  /\ ~floored /\ lock = NoWriter
  /\ floor' = counter /\ floored' = TRUE
  /\ chg' = [s \in Scopes |-> IF chg[s] <= counter THEN 0 ELSE chg[s]]
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, hist, txns,
                 since, view, rkind, rphase, rbuf, rcursor>>

-----------------------------------------------------------------------------
(* Reader *)

ResetDue == (HonorFloor /\ since < floor) \/ since > counter

\* What the reader does with the rows changed after `since`, each joined to
\* its row as it is now: hand the delta to the cycle, or the view it applies.
Decide ==
  LET rows == {s \in Scopes : chg[s] > since}
      ctlIn == "ctl" \in rows
      ck == kind["ctl"]
      newKind ==
        IF ctlIn /\ ck = "tomb" /\ ControlRows \in {"apply", "reconnect"} THEN "tomb"
        ELSE IF ctlIn /\ ck = "act" /\ ControlRows = "reconnect" THEN "act"
        ELSE rkind
      handoff ==
        \/ \E s \in rows : kind[s] = "gone"
        \/ ctlIn /\ ControlRows = "handoff"
        \/ ctlIn /\ ck = "act" /\ ControlRows \in {"apply", "ignore"}
        \* a log of a connection this device does not hold
        \/ "log" \in rows /\ newKind = "gone"
      newView == [s \in Scopes |->
        IF s \notin rows THEN view[s]
        ELSE IF s = "ctl" THEN (IF ControlRows = "ignore" THEN view[s] ELSE ver[s])
        \* a log row under a deleted connection is skipped
        ELSE IF newKind = "act" THEN ver[s] ELSE view[s]]
  IN [handoff |-> handoff, view |-> newView, rkind |-> newKind]

\* One snapshot: the counter and the records above `since`, each joined to
\* its row's current version. A handoff runs the full cycle in the same pass:
\* a listing, which settles at the delta's number.
Delta ==
  /\ rphase = "idle" /\ OneSnapshot
  /\ IF ResetDue
       THEN IF ResetLists
              THEN /\ rphase' = "listing" /\ rcursor' = counter
                   /\ UNCHANGED <<since, view, rkind>>
              ELSE /\ since' = counter
                   /\ UNCHANGED <<view, rkind, rphase, rcursor>>
       ELSE LET d == Decide IN
            IF d.handoff
              THEN /\ rphase' = "listing" /\ rcursor' = counter
                   /\ UNCHANGED <<since, view, rkind>>
              ELSE /\ rphase' = "applying" /\ rcursor' = counter
                   /\ UNCHANGED <<since, view, rkind>>
  /\ rbuf' = Decide
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored>>

\* The host serializes answers. Persist every connection before settling;
\* no second answer is admitted while either stage is unfinished.
ApplyDelta ==
  /\ rphase = "applying"
  /\ view' = rbuf.view /\ rkind' = rbuf.rkind /\ rphase' = "settling"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored,
                 since, rbuf, rcursor>>

SettleDelta ==
  /\ rphase = "settling"
  /\ since' = rcursor /\ rphase' = "idle"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored,
                 view, rkind, rbuf, rcursor>>

\* Mutation: the records first, the counter in a later statement.
DeltaRows ==
  /\ rphase = "idle" /\ ~OneSnapshot
  /\ rbuf' = Decide
  /\ rphase' = "rows"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored,
                 since, view, rkind, rcursor>>

DeltaCounter ==
  /\ rphase = "rows"
  /\ IF rbuf.handoff
       THEN /\ rphase' = "listing" /\ rcursor' = counter
            /\ UNCHANGED <<since, view, rkind>>
       ELSE /\ view' = rbuf.view /\ rkind' = rbuf.rkind /\ since' = counter
            /\ rphase' = "idle" /\ UNCHANGED rcursor
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored,
                 rbuf>>

\* The full listing a reset or a handoff owes: every row as it is now. The
\* cursor is the one the answer carried, which is no later than this read.
Listing ==
  /\ rphase = "listing"
  /\ view' = ver /\ rkind' = kind["ctl"] /\ since' = rcursor /\ rphase' = "idle"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, kind, chg, hist, txns, floor, floored,
                 rbuf, rcursor>>

Next ==
  \/ \E w \in Writers : Begin(w) \/ Number(w) \/ Commit(w) \/ Abort(w)
  \/ RaiseFloor
  \/ Delta \/ DeltaRows \/ DeltaCounter \/ ApplyDelta \/ SettleDelta \/ Listing

Spec == Init /\ [][Next]_vars /\ WF_vars(Delta \/ DeltaRows \/ DeltaCounter \/ ApplyDelta \/ SettleDelta \/ Listing)
             /\ \A w \in Writers : WF_vars(Number(w) \/ Commit(w))

-----------------------------------------------------------------------------
(* Properties *)

\* The reader holds every change numbered at or below its cursor: the control
\* row always, and the log row while it holds the connection active (a deleted
\* connection shows nothing; a new lifetime is listed before it is held).
NoSkip ==
  /\ view["ctl"] >= VerAt("ctl", since)
  /\ rkind = "act" => view["log"] >= VerAt("log", since)

\* A reset is never answered by moving the cursor alone: while a reset is
\* owed the cursor stays put, and the listing is the only way out of it.
ResetThenListing == [][rphase = "listing" => (since' = since \/ Listing)]_vars

\* Once writers stop, the reader ends holding what the registry shows: its
\* control row, and the log row too while the connection is active.
CatchUp == <>[](/\ view["ctl"] = ver["ctl"] /\ rkind = kind["ctl"]
               /\ (rkind = "act" => view["log"] = ver["log"]))

=============================================================================
