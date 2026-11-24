------------------------------ MODULE SeedRank ------------------------------
\* Which body does a seed leave for a key that two legacy instances both hold?
\*
\* `LateSeed.tla` has no bodies: a seed is "a row at stamp (0, seed)". That is
\* enough for fill-only safety, but it cannot say which of two seed bodies a key
\* ends with. This module adds the body and asks the question the older-instance
\* import (O2) needs answered.
\*
\* One key. An instance is one legacy copy of the same upstream source. It has a
\* rank (newer = higher) and, for its body of the key, a hash. The hash order is
\* the opposite of the rank order, so a result that follows the hash and one that
\* follows the rank cannot be mistaken for each other.
\*
\* What the real code does, and the model copies:
\*   - An import never replaces a held row (`mergeIncoming`, origin `import`):
\*     the first seed body of a key on a device stays.
\*   - A segment from another device applies at origin `remote`. At equal stamps
\*     the greater body hash wins (`rankAfter`). Both seeds have stamp (0, seed).
\*
\* Two ways to import a device's instances:
\*   "arrival"  one import per instance, in any order (what submitting each
\*              instance on its own does). The first body in stays.
\*   "ranked"   one import for the device: the instances are folded newest first
\*              into one row set before anything is merged (`foldLayers`).
\*
\* Two layouts of which device holds which instance:
\*   "same"     every device holds every instance.
\*   "split"    d1 holds both instances, d2 holds only the older one.
EXTENDS Naturals, FiniteSets

CONSTANTS Devs, Insts, Mode, Layout

Rank(i) == IF i = "i1" THEN 1 ELSE 2
Hash(i) == IF i = "i1" THEN 2 ELSE 1

Hold(d) == IF Layout = "same" \/ d = "d1" THEN Insts ELSE {"i1"}
Newest(S) == CHOOSE i \in S : \A j \in S : Rank(j) <= Rank(i)

VARIABLES rec,       \* rec[d]: the instance whose body d holds for the key, or "none"
          imported,  \* imported[d]: instances d has imported
          log,       \* bodies published to the connection log (as source instances)
          applied,   \* applied[d]: log bodies d has applied
          touched,   \* devices that applied a log body at some point
          pub        \* devices that published their seed
vars == <<rec, imported, log, applied, touched, pub>>

Done(d) == imported[d] = Hold(d)

\* One import per instance, any order. Fill-only: a held row stays.
Import(d, i) ==
  /\ Mode = "arrival"
  /\ i \in Hold(d) \ imported[d]
  /\ rec' = [rec EXCEPT ![d] = IF rec[d] = "none" THEN i ELSE rec[d]]
  /\ imported' = [imported EXCEPT ![d] = @ \cup {i}]
  /\ UNCHANGED <<log, applied, touched, pub>>

\* One import for the whole device: newest instance first, then the rest.
ImportAll(d) ==
  /\ Mode = "ranked"
  /\ imported[d] = {}
  /\ rec' = [rec EXCEPT ![d] = IF rec[d] = "none" THEN Newest(Hold(d)) ELSE rec[d]]
  /\ imported' = [imported EXCEPT ![d] = Hold(d)]
  /\ UNCHANGED <<log, applied, touched, pub>>

Publish(d) ==
  /\ Done(d) /\ d \notin pub /\ rec[d] # "none"
  /\ log' = log \cup {rec[d]}
  /\ pub' = pub \cup {d}
  /\ UNCHANGED <<rec, imported, applied, touched>>

\* A log body applies at origin `remote`: at equal stamps the greater hash wins.
Apply(d, b) ==
  /\ b \in log /\ b \notin applied[d]
  /\ applied' = [applied EXCEPT ![d] = @ \cup {b}]
  /\ rec' = [rec EXCEPT ![d] =
       IF rec[d] = "none" \/ Hash(b) > Hash(rec[d]) THEN b ELSE rec[d]]
  /\ touched' = touched \cup {d}
  /\ UNCHANGED <<imported, log, pub>>

Init ==
  /\ rec = [d \in Devs |-> "none"]
  /\ imported = [d \in Devs |-> {}]
  /\ log = {}
  /\ applied = [d \in Devs |-> {}]
  /\ touched = {}
  /\ pub = {}

Next ==
  \E d \in Devs :
    \/ \E i \in Insts : Import(d, i)
    \/ ImportAll(d)
    \/ Publish(d)
    \/ \E b \in Insts : Apply(d, b)

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ \A d \in Devs : rec[d] \in Insts \cup {"none"}
  /\ \A d \in Devs : imported[d] \subseteq Hold(d)

Quiet ==
  \A d \in Devs : Done(d) /\ d \in pub /\ applied[d] = log

\* A device that has applied nothing from the log holds, once it has imported
\* everything, the body of its newest instance.
LocalRank ==
  \A d \in Devs :
    (Done(d) /\ d \notin touched /\ Hold(d) # {}) => rec[d] = Newest(Hold(d))

\* Devices that hold everything the log holds hold one body.
Convergence ==
  Quiet => \A d1, d2 \in Devs : rec[d1] = rec[d2]

\* The settled body is the body of the newest instance any device holds.
GlobalRank ==
  Quiet => \A d \in Devs : rec[d] = Newest(UNION {Hold(x) : x \in Devs})
=============================================================================
