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
(* Each mutation switches off one of those choices:                        *)
(*   Numbering = "sequence"  a number taken at write time with no lock,    *)
(*                           as nextval() would give                       *)
(*   OneSnapshot = FALSE     records and counter read in two statements    *)
(*   ResetLists = FALSE      a reset moves the cursor without a listing    *)
(*   HonorFloor = FALSE      no reset for a cursor below the floor         *)
(*   GoneRecords = FALSE     a hard delete removes the change record       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Writers, Scopes, MaxTxns, NoWriter,
          Numbering, OneSnapshot, ResetLists, HonorFloor, GoneRecords

VARIABLES
  counter,   \* the owner's committed number
  nextSeq,   \* Numbering = "sequence" only: the next nextval()
  lock,      \* the writer holding the counter row lock, or NoWriter
  txn,       \* per writer: phase, scope, hard delete or not, number
  ver,       \* per scope: committed version (every write or delete bumps it)
  chg,       \* per scope: number of the change record, 0 = none
  hist,      \* committed changes: <<number, scope, version>>
  txns,      \* transactions begun (bounds the model)
  floor,     \* records are complete for changes numbered above this
  floored,   \* the floor moved (once)
  since,     \* reader: its cursor
  view,      \* reader: the version it holds per scope
  rphase,    \* reader: "idle", "rows" (between two reads), "listing" (reset owed)
  rbuf,      \* reader: rows of the first of two reads
  rcursor    \* reader: the cursor a pending listing will set

vars == <<counter, nextSeq, lock, txn, ver, chg, hist, txns, floor, floored,
          since, view, rphase, rbuf, rcursor>>

Max(a, b) == IF a > b THEN a ELSE b

\* The version of `s` as of number `n`: its latest change numbered <= n.
VerAt(s, n) ==
  LET at == {h[3] : h \in {x \in hist : x[2] = s /\ x[1] <= n}}
  IN IF at = {} THEN 0 ELSE CHOOSE v \in at : \A u \in at : u <= v

Init ==
  /\ counter = 0 /\ nextSeq = 1 /\ lock = NoWriter
  /\ txn = [w \in Writers |-> [phase |-> "idle", scope |-> CHOOSE s \in Scopes : TRUE,
                                del |-> FALSE, seq |-> 0]]
  /\ ver = [s \in Scopes |-> 0] /\ chg = [s \in Scopes |-> 0]
  /\ hist = {} /\ txns = 0 /\ floor = 0 /\ floored = FALSE
  /\ since = 0 /\ view = [s \in Scopes |-> 0]
  /\ rphase = "idle" /\ rbuf = [s \in Scopes |-> 0] /\ rcursor = 0

-----------------------------------------------------------------------------
(* Writers *)

Begin(w) ==
  /\ txn[w].phase = "idle" /\ txns < MaxTxns
  /\ \E s \in Scopes, d \in BOOLEAN :
       txn' = [txn EXCEPT ![w] = [phase |-> "open", scope |-> s, del |-> d, seq |-> 0]]
  /\ txns' = txns + 1
  /\ UNCHANGED <<counter, nextSeq, lock, ver, chg, hist, floor, floored,
                 since, view, rphase, rbuf, rcursor>>

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
  /\ UNCHANGED <<counter, ver, chg, hist, txns, floor, floored,
                 since, view, rphase, rbuf, rcursor>>

Commit(w) ==
  /\ txn[w].phase = "numbered"
  /\ LET s == txn[w].scope
         n == txn[w].seq
     IN /\ ver' = [ver EXCEPT ![s] = @ + 1]
        /\ chg' = [chg EXCEPT ![s] = IF txn[w].del /\ ~GoneRecords THEN 0 ELSE n]
        /\ counter' = IF Numbering = "counter" THEN n ELSE Max(counter, n)
        /\ hist' = hist \cup {<<n, s, ver[s] + 1>>}
  /\ lock' = IF lock = w THEN NoWriter ELSE lock
  /\ txn' = [txn EXCEPT ![w].phase = "idle"]
  /\ UNCHANGED <<nextSeq, txns, floor, floored, since, view, rphase, rbuf, rcursor>>

Abort(w) ==
  /\ txn[w].phase \in {"open", "numbered"}
  /\ lock' = IF lock = w THEN NoWriter ELSE lock
  /\ txn' = [txn EXCEPT ![w].phase = "idle"]
  /\ UNCHANGED <<counter, nextSeq, ver, chg, hist, txns, floor, floored,
                 since, view, rphase, rbuf, rcursor>>

\* History below here was never recorded (the migration that adds records).
RaiseFloor ==
  /\ ~floored /\ lock = NoWriter
  /\ floor' = counter /\ floored' = TRUE
  /\ chg' = [s \in Scopes |-> IF chg[s] <= counter THEN 0 ELSE chg[s]]
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, hist, txns,
                 since, view, rphase, rbuf, rcursor>>

-----------------------------------------------------------------------------
(* Reader *)

ResetDue == (HonorFloor /\ since < floor) \/ since > counter

\* One snapshot: the counter and the records above `since`, each joined to
\* its row's current version.
Delta ==
  /\ rphase = "idle" /\ OneSnapshot
  /\ IF ResetDue
       THEN IF ResetLists
              THEN /\ rphase' = "listing" /\ rcursor' = counter
                   /\ UNCHANGED <<since, view>>
              ELSE /\ since' = counter
                   /\ UNCHANGED <<view, rphase, rcursor>>
       ELSE /\ view' = [s \in Scopes |-> IF chg[s] > since THEN ver[s] ELSE view[s]]
            /\ since' = counter
            /\ UNCHANGED <<rphase, rcursor>>
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, chg, hist, txns, floor, floored, rbuf>>

\* Mutation: the records first, the counter in a later statement.
DeltaRows ==
  /\ rphase = "idle" /\ ~OneSnapshot
  /\ rbuf' = [s \in Scopes |-> IF chg[s] > since THEN ver[s] ELSE view[s]]
  /\ rphase' = "rows"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, chg, hist, txns, floor, floored,
                 since, view, rcursor>>

DeltaCounter ==
  /\ rphase = "rows"
  /\ view' = rbuf /\ since' = counter /\ rphase' = "idle"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, chg, hist, txns, floor, floored,
                 rbuf, rcursor>>

\* The full listing a reset owes: every row as it is now. The cursor is the
\* one the reset answer carried, which is no later than this read.
Listing ==
  /\ rphase = "listing"
  /\ view' = ver /\ since' = rcursor /\ rphase' = "idle"
  /\ UNCHANGED <<counter, nextSeq, lock, txn, ver, chg, hist, txns, floor, floored,
                 rbuf, rcursor>>

Next ==
  \/ \E w \in Writers : Begin(w) \/ Number(w) \/ Commit(w) \/ Abort(w)
  \/ RaiseFloor
  \/ Delta \/ DeltaRows \/ DeltaCounter \/ Listing

Spec == Init /\ [][Next]_vars /\ WF_vars(Delta \/ DeltaRows \/ DeltaCounter \/ Listing)
             /\ \A w \in Writers : WF_vars(Number(w) \/ Commit(w))

-----------------------------------------------------------------------------
(* Properties *)

\* The reader holds every change numbered at or below its cursor.
NoSkip == \A s \in Scopes : view[s] >= VerAt(s, since)

\* A reset is never answered by moving the cursor alone: while a reset is
\* owed the cursor stays put, and the listing is the only way out of it.
ResetThenListing == [][rphase = "listing" => (since' = since \/ Listing)]_vars

\* Once writers stop, the reader ends holding exactly the registry.
CatchUp == <>[](\A s \in Scopes : view[s] = ver[s])

=============================================================================
