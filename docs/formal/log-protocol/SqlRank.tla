------------------------------ MODULE SqlRank ------------------------------
EXTENDS Naturals, Sequences, TLC
\* Refinement scenario for the equal-stamp order (see LogProtocol.tla and the README).
\* LogProtocol.tla folds a log with the max of one total order. The local database does not
\* fold: it applies one observation at a time to a stored row, through SQL (`mergeIncoming`
\* for a pulled or imported operation, `replaceOwnRunRows` for the run's own intake). This
\* module models that incremental step on one key at one stamp, and asks whether the stored
\* row always equals the fold of the operations the database holds in its log.
\*
\* Scope. All operations carry one stamp, so the order is (ord, body hash). The SEEN stamp,
\* `promoteSeen` and an older stored stamp are not modelled: they act only between different
\* stamps. Bodies are small integers and their order stands for the order of body hashes.
CONSTANTS Mode, MaxSteps
ASSUME Mode \in {"good", "sameBodyKeep", "ownReplace"}
Ords == 0..2
Bodies == 1..3
None == [body |-> 0, ord |-> 0]
\* One order, lexicographic. No numeric packing, so no bound on ord or body.
Gt(a,b) == \/ a.ord > b.ord \/ (a.ord = b.ord /\ a.body > b.body)

VARIABLES row, log, nextOrd, steps
vars == <<row, log, nextOrd, steps>>

RECURSIVE FoldMax(_,_)
FoldMax(best, ops) ==
  IF Len(ops) = 0 THEN best
  ELSE FoldMax(IF Gt(Head(ops), best) THEN Head(ops) ELSE best, Tail(ops))

\* An operation pulled from the log (written by another device, a clone of this run).
\*   good:         the greater (ord, body) wins, an identical body included, so a higher
\*                 ordinal of the same body advances the row.
\*   sameBodyKeep: mutant, the code at the first fix. An identical body never advances the
\*                 row at an equal stamp, so a higher ordinal is dropped.
ApplyRemote(r, op) ==
  IF Mode = "sameBodyKeep" /\ r.body = op.body THEN r
  ELSE IF Gt(op, r) THEN op ELSE r

\* This run's own next batch, with the run's next ordinal.
\*   good:       a different body replaces the row only when it ranks above it; an identical
\*               body is a sighting, not a change, and is neither stored nor published.
\*   ownReplace: mutant, the code at the first fix: a different body at the run's stamp
\*               replaces the row whatever it holds.
ApplyLocal(r, op) ==
  IF r.body = op.body THEN r
  ELSE IF Mode = "ownReplace" THEN op
  ELSE IF Gt(op, r) THEN op ELSE r

Init == row = None /\ log = <<>> /\ nextOrd = 0 /\ steps = 0
Pull ==
  /\ steps < MaxSteps
  /\ \E o \in Ords, b \in Bodies :
       LET op == [body |-> b, ord |-> o]
       IN /\ log' = Append(log, op) /\ row' = ApplyRemote(row, op)
  /\ steps' = steps + 1 /\ UNCHANGED nextOrd
\* Intake batches are strictly increasing per writer. A changed row is published.
Intake ==
  /\ steps < MaxSteps /\ nextOrd \in Ords
  /\ \E b \in Bodies :
       LET op == [body |-> b, ord |-> nextOrd]
           new == ApplyLocal(row, op)
       IN /\ row' = new
          /\ log' = IF new # row THEN Append(log, op) ELSE log
  /\ nextOrd' = nextOrd + 1 /\ steps' = steps + 1
Next == Pull \/ Intake
Spec == Init /\ [][Next]_vars

TypeOK == row \in [body : 0..3, ord : 0..2] /\ steps \in 0..MaxSteps
\* The stored row is the fold of the log, whatever order its operations arrived in.
RowIsFold == row = FoldMax(None, log)

\* Disk-fold vocabulary, shared with Workspace.tla. Unlike the historical
\* LogProtocol.first field, first_o belongs to the winning upsert, NULL included.
\* Scalar stamps embed the pair order; Gt above owns equal-stamp ordinal/body ties.
CellNone == [stamp |-> 0, ord |-> 0, body |-> 0, first_o |-> 0, kind |-> "none"]
CellEmpty == [up |-> CellNone, del |-> CellNone]
UpAfter(a,b) == a.stamp > b.stamp \/ (a.stamp = b.stamp /\ Gt(a,b))
DelAfter(a,b) == a.stamp > b.stamp \/
                 (a.stamp = b.stamp /\ a.kind = "delete" /\ b.kind # "delete")
CellStep(c,o) ==
  IF o.kind = "up" THEN
    IF UpAfter(o,c.up) THEN [c EXCEPT !.up = o] ELSE c
  ELSE IF DelAfter(o,c.del) THEN [c EXCEPT !.del = o] ELSE c
CellEntries(c) ==
  IF c.up.stamp > c.del.stamp \/
     (c.up.stamp > 0 /\ c.up.stamp = c.del.stamp /\ c.del.kind = "omit")
  THEN (IF c.del.stamp > 0 /\ c.up.stamp > c.del.stamp
        THEN <<c.del,c.up>> ELSE <<c.up>>)
  ELSE IF c.del.stamp > 0 THEN <<c.del>> ELSE <<>>
=============================================================================
