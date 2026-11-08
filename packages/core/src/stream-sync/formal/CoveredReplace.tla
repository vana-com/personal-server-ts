---- MODULE CoveredReplace ----
\* Covered full refresh replaces a stream's published set; every other run merges.
\* One stream, two devices, head = whole manifest (key -> stamp of the winning line).
\* A replacement keeps base lines whose stamp is newer than the replacing run's stamp
\* (the reducer's newest-stamp rule). Which runs are covered, and what they hold, is
\* chosen by TLC over every assignment (Init).
EXTENDS Naturals, FiniteSets

Keys == {"a", "b", "c"}
Runs == {"r1", "r2", "r3"}
Stamp == [r \in Runs |-> CASE r = "r1" -> 1 [] r = "r2" -> 2 [] r = "r3" -> 3]
\* TRUE: arrival follows stamp order. FALSE: any arrival order (an offline device).
InOrder == FALSE

VARIABLES head, ver, state, req, done, cov, content
\* cov[r]: the intake-validated replacement decision. content[r]: the run's keys.
\* head: [Keys -> 0..3]  0 = absent, else stamp of the winning line.
\* state[r]: "new" | "planned" | "posted" | "recorded".

vars == <<head, ver, state, req, done, cov, content>>

Apply(h, r) ==
  LET lines == [k \in Keys |-> IF k \in content[r] /\ Stamp[r] > h[k] THEN Stamp[r] ELSE h[k]]
  IN IF cov[r] THEN [k \in Keys |-> IF lines[k] >= Stamp[r] THEN lines[k] ELSE 0]
     ELSE lines

Init == /\ head = [k \in Keys |-> 0] /\ ver = 0
        /\ state = [r \in Runs |-> "new"] /\ req = [r \in Runs |-> [exp |-> 0, new |-> head]]
        /\ done = {}
        /\ cov \in [Runs -> BOOLEAN]
        /\ content \in [Runs -> SUBSET Keys \ {{}}]

Earlier(r) == {x \in Runs : Stamp[x] < Stamp[r]}

Plan(r) == /\ state[r] = "new"
           /\ (InOrder => \A x \in Earlier(r) : state[x] \in {"posted", "recorded"})
           /\ state' = [state EXCEPT ![r] = "planned"]
           /\ req' = [req EXCEPT ![r] = [exp |-> ver, new |-> Apply(head, r)]]
           /\ UNCHANGED <<head, ver, done, cov, content>>

\* Registry post: compare-and-set on the version. A lost race re-plans.
Post(r) == /\ state[r] = "planned"
           /\ IF ver = req[r].exp
                THEN /\ head' = req[r].new /\ ver' = ver + 1
                     /\ done' = done \cup {r} /\ state' = [state EXCEPT ![r] = "posted"]
                ELSE /\ state' = [state EXCEPT ![r] = "new"]
                     /\ UNCHANGED <<head, ver, done>>
           /\ UNCHANGED <<req, cov, content>>

\* Crash before the answer is recorded; replay resends the same request. The registry
\* already holds the commit, so the CAS fails and nothing is applied twice.
Replay(r) == /\ state[r] = "posted"
             /\ state' = [state EXCEPT ![r] = "recorded"]
             /\ UNCHANGED <<head, ver, req, done, cov, content>>
ReplayResend(r) == /\ state[r] = "posted" /\ ver # req[r].exp
                   /\ UNCHANGED vars   \* the resend is refused by the CAS

Finished == \A r \in Runs : state[r] = "recorded"
Next == (\E r \in Runs : Plan(r) \/ Post(r) \/ Replay(r) \/ ReplayResend(r)) \/ (Finished /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars

\* Oracle, independent of the fold: k is present iff a committed run holds it at or
\* after the newest committed covered stamp.
CoverMax == LET cs == {Stamp[r] : r \in {x \in done : cov[x]}}
            IN IF cs = {} THEN 0 ELSE CHOOSE m \in cs : \A c \in cs : c <= m
Oracle(k) == \E r \in done : k \in content[r] /\ Stamp[r] >= CoverMax

\* Nothing the oracle holds is ever missing (a covered run drops only what it omits).
NoWrongDrop == \A k \in Keys : Oracle(k) => head[k] > 0
\* An extra key can only be a line of a run that arrived after a newer covered refresh
\* and is older than it. The head records no "replaced through" stamp, so that line stays
\* until the next covered refresh: a safe leftover, never a wrong drop. Nothing else.
OnlyLateExtras == \A k \in Keys : (head[k] > 0 /\ ~Oracle(k)) =>
    \E r \in done : k \in content[r] /\ Stamp[r] = head[k] /\ Stamp[r] < CoverMax
\* With arrival in stamp order the view equals the oracle exactly.
ExactWhenInOrder == \A k \in Keys : InOrder => ((head[k] > 0) <=> Oracle(k))

\* An uncovered run never removes a key.
MergeNeverRemoves == [][\A r \in Runs :
    (~cov[r] /\ state[r] = "planned" /\ state'[r] = "posted")
      => \A k \in Keys : head[k] > 0 => head'[k] > 0]_vars
\* Replay is idempotent: the version moves once per committed run.
OnceEach == ver = Cardinality(done)
====
