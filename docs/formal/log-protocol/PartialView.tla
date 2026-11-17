------------------------------ MODULE PartialView ------------------------------
\* The rows a progressive first load shows before it ends (row 3b of the stream-sync
\* plan). A reader applies the segments of a log tail in position order, and shows
\* the applied prefix's rows, except for the keys a LATER segment removes. It knows
\* those from the head: each ref says whether its segment removes anything
\* (`removes`), and the reader reads the removing segments first, before it
\* applies any batch. It does not read the segments that remove nothing first;
\* they arrive in any order while the batches apply.
\*
\* Property: every row the view shows is in the finished fold (`Exact`), at
\* every step, for every corpus of N segments over Keys (TLC chooses it). A
\* removal fact that is false (a segment that removes but says it does not)
\* breaks it: `PartialViewLie.cfg`. A view that ignores the later removals breaks
\* it: `PartialViewNoHold.cfg`. The facts are the head's, so a writer that
\* states them wrongly is the only way a shown row can leave.
EXTENDS Naturals, FiniteSets

CONSTANTS Keys, N,   \* the keys; the number of segments (positions 1..N)
          Lie,       \* whether a head may state a removal fact that is false
          Hold       \* whether the view keeps out the keys a later segment removes

VARIABLES ops, says, applied, shown
vars == <<ops, says, applied, shown>>

Kinds == Keys \X {"up", "del"}
Removes(i) == \E o \in ops[i] : o[2] = "del"

\* An operation's stamp is its segment's position: later wins; within one
\* segment a delete outranks an upsert of the key (the log's rank).
LastOp(k, upto) ==
  LET at == {i \in 1..upto : \E o \in ops[i] : o[1] = k}
  IN IF at = {} THEN "none"
     ELSE LET m == CHOOSE i \in at : \A j \in at : j <= i
          IN IF <<k, "del">> \in ops[m] THEN "del" ELSE "up"

Fold(upto) == {k \in Keys : LastOp(k, upto) = "up"}
Final == Fold(N)

\* The segments the reader reads first: those whose head fact says they remove.
\* The last position at which each of them removes a key is what it learns.
Pre == {i \in 1..N : says[i]}
RemovedAt(k) ==
  LET at == {i \in Pre : <<k, "del">> \in ops[i]}
  IN IF at = {} THEN 0 ELSE CHOOSE i \in at : \A j \in at : j <= i

Held(i) == IF Hold THEN {k \in Keys : RemovedAt(k) > i} ELSE {}

Init == /\ ops \in [1..N -> SUBSET Kinds]
        /\ says \in [1..N -> BOOLEAN]
        /\ (\A i \in 1..N : (~Lie) => (says[i] = Removes(i)))
        /\ applied = 0
        /\ shown = {}

Apply == /\ applied < N
         /\ applied' = applied + 1
         /\ shown' = Fold(applied + 1) \ Held(applied + 1)
         /\ UNCHANGED <<ops, says>>

Next == Apply \/ (applied = N /\ UNCHANGED vars)

Exact == shown \subseteq Final
Complete == applied = N => shown = Final

Spec == Init /\ [][Next]_vars
================================================================================
