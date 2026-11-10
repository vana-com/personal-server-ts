---- MODULE StreamSyncR5 ----
\* r5 stream sync over the local database: one connection, one stream, two replicas
\* (a device and an in-memory embed frame are both replicas with their own database).
\* Extends the CoveredReplace conventions: a stamp per run (newest wins), the start basis
\* (head version at Begin), covered runs chosen by TLC, a fence at publish.
\* New here: per-replica records + change log + publish watermark, head_parts, apply,
\* publish (snapshot W, CAS), un-write, delete (intent, heads, tombstone, purge), import
\* seeds, retry cursor. Stamps: 0 absent, 1 seed, run r has stamp r+1.
EXTENDS Naturals, Sequences, FiniteSets

Keys == {1, 2}
CONSTANT NRuns
Runs == 1..NRuns
Devs == {"d1", "d2"}
SEED == 1
St(r) == r + 1
Z == [k \in Keys |-> 0]
Pub == {"L", "I", "R"}
Mx(a, b) == IF a > b THEN a ELSE b

CONSTANTS OWN, COV, CV, RET, CONT, SEEDS          \* sets TLC chooses from
CONSTANTS MaxDel, MaxRecon, MaxCrash, AllowImport
CONSTANTS SeqRuns,   \* scenario limit: a replica runs one run at a time, in stamp order
          BodyKeep    \* "off" | "all" | "overwrittenOnly"   keep losers of the stamp merge while the winner is unpublished
CONSTANT MonoCV   \* scenario limit: one replica never runs an older connector version after a newer one
\* Mutant switches. The r5 value is first.
CONSTANTS WmAt,            \* "start" | "commit"
          ApplyGuard,      \* TRUE | FALSE   apply keeps rows with unpublished changes
          UnwDropsParts,   \* TRUE | FALSE   un-write drops head_parts
          Fence,           \* TRUE | FALSE   replace needs basis = head version
          LoserApplies,    \* TRUE | FALSE   CAS loser applies the winner before retry
          RetryMode,       \* "r5" | "dropRows" | "noCursor"
          DelIntentFirst,  \* TRUE | FALSE   intent durable before first registry write
          DelFence,        \* TRUE | FALSE   run fence checks delete
          SeedGenOnly,     \* TRUE | FALSE   seeds publish only into generation 1
          TombAbsent,      \* TRUE | FALSE   delete writes a tombstone even with no control row
          ImpChecksLocal,  \* TRUE | FALSE   import refuses on a locally deleted connection
          EndRefuse        \* "both" | "none" | "head" | "local"   refuse an older connector version at end

VARIABLES own, cov, cv, ret, content, sd,
          rctl, rgen, rver, rhead, rhcv, hvk,
          dcount, nrec, ncrash, lostN, rep, imported,
          rec, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, dint, redel, hold,
          pph, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv,
          rs, basis, gen0, dsnap, ep0, dc, rseq, rpub

fixedv == <<own, cov, cv, ret, content, sd>>
regv   == <<rctl, rgen, rver, rhead, rhcv, hvk>>
ghostv == <<dcount, nrec, ncrash, lostN, rep, imported>>
locv   == <<rec, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, dint, redel, hold>>
phv    == <<pph, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv>>
runv   == <<rs, basis, gen0, dsnap, ep0, dc, rseq, rpub>>
vars == <<fixedv, regv, ghostv, locv, phv, runv>>

\* rctl: registry control row "none" | "live" | "deleted".  rhead: key -> stamp of the head.
\* rhcv: highest connector version in the head.  hvk: ghost, version that last wrote a key.
\* rec[d]: records (key -> stamp).  log[d]: change log entries [k,s,o].  wm[d]: publish watermark.
\* hver/hc/hpe/hcv: head_version, the head's content, head_parts empty, head connector version.
\* lctl/lgen/ldelv: local control state, generation, last_delete_version.
\* dint[d]: delete intent "none" | "saved" | "heads" | "done".  redel[d]: keys the next run redelivers
\* (cursor not saved).  pph..: publish phase.  apl..: apply phase.

AppEnt(lg, ch, s, o) ==
  lg \o (IF 1 \in ch THEN <<[k |-> 1, s |-> s, o |-> o]>> ELSE <<>>)
     \o (IF 2 \in ch THEN <<[k |-> 2, s |-> s, o |-> o]>> ELSE <<>>)

AppF(lg, f, o) ==
  lg \o (IF f[1] > 0 THEN <<[k |-> 1, s |-> f[1], o |-> o]>> ELSE <<>>)
     \o (IF f[2] > 0 THEN <<[k |-> 2, s |-> f[2], o |-> o]>> ELSE <<>>)
MaxSet(S) == IF S = {} THEN 0 ELSE CHOOSE m \in S : \A x \in S : x <= m

ECov(r) == cov[r] /\ ~ret[r]
Guarded(d, k) == \E i \in (wm[d] + 1)..Len(log[d]) : log[d][i].k = k /\ log[d][i].o \in Pub

Init ==
  /\ own \in [Runs -> OWN] /\ cov \in [Runs -> COV] /\ cv \in [Runs -> CV] /\ ret \in [Runs -> RET]
  /\ content \in [Runs -> CONT] /\ sd \in [Devs -> SEEDS]
  /\ MonoCV => \A a, b \in Runs : (a < b /\ own[a] = own[b]) => cv[a] <= cv[b]
  /\ rctl = "none" /\ rgen = 1 /\ rver = 0 /\ rhead = Z /\ rhcv = 0 /\ hvk = Z
  /\ dcount = 0 /\ nrec = 0 /\ ncrash = 0 /\ lostN = 0 /\ rep = {} /\ imported = {}
  /\ rec = [d \in Devs |-> Z] /\ log = [d \in Devs |-> <<>>] /\ wm = [d \in Devs |-> 0]
  /\ hver = [d \in Devs |-> 0] /\ hc = [d \in Devs |-> Z] /\ hpe = [d \in Devs |-> FALSE]
  /\ hcv = [d \in Devs |-> 0] /\ lctl = [d \in Devs |-> "none"] /\ lgen = [d \in Devs |-> 0]
  /\ hold = [d \in Devs |-> [k \in Keys |-> {}]] /\ ldelv = [d \in Devs |-> 0] /\ dint = [d \in Devs |-> "none"] /\ redel = [d \in Devs |-> {}]
  /\ pph = [d \in Devs |-> "idle"] /\ pW = [d \in Devs |-> 0] /\ pBase = [d \in Devs |-> 0]
  /\ pPr = [d \in Devs |-> 0] /\ pEnc = [d \in Devs |-> Z] /\ pRep = [d \in Devs |-> FALSE]
  /\ apl = [d \in Devs |-> "idle"] /\ aVer = [d \in Devs |-> 0] /\ aHead = [d \in Devs |-> Z]
  /\ aCv = [d \in Devs |-> 0]
  /\ rs = [r \in Runs |-> "new"] /\ basis = [r \in Runs |-> 0] /\ gen0 = [r \in Runs |-> 0]
  /\ dsnap = [r \in Runs |-> 0] /\ ep0 = [r \in Runs |-> 0] /\ dc = [r \in Runs |-> {}]
  /\ rseq = [r \in Runs |-> 0] /\ rpub = [r \in Runs |-> FALSE]

\* ---------- intake ----------
RBegin(r) == LET d == own[r] IN
  /\ rs[r] = "new" /\ lctl[d] # "deleted" /\ rctl # "deleted"
  /\ SeqRuns => \A x \in Runs : own[x] = d => (rs[x] # "begun" /\ (x < r => rs[x] # "new"))
  /\ rctl = "live" => (lctl[d] = "live" /\ lgen[d] = rgen /\ hver[d] = rver /\ ~hpe[d])
  /\ rs' = [rs EXCEPT ![r] = "begun"]
  /\ basis' = [basis EXCEPT ![r] = hver[d]]
  /\ gen0' = [gen0 EXCEPT ![r] = IF lctl[d] = "none" THEN 1 ELSE lgen[d]]
  /\ lgen' = [lgen EXCEPT ![d] = IF lctl[d] = "none" THEN 1 ELSE lgen[d]]
  /\ lctl' = [lctl EXCEPT ![d] = "live"]
  /\ dsnap' = [dsnap EXCEPT ![r] = ldelv[d]] /\ ep0' = [ep0 EXCEPT ![r] = dcount]
  /\ dc' = [dc EXCEPT ![r] = content[r] \cup redel[d]]
  /\ redel' = [redel EXCEPT ![d] = {}]
  /\ UNCHANGED <<fixedv, regv, ghostv, phv, rec, log, wm, hver, hc, hpe, hcv, ldelv, dint, rseq, rpub, hold>>

RBeginRefused(r) == LET d == own[r] IN
  /\ rs[r] = "new" /\ lctl[d] = "deleted"
  /\ rs' = [rs EXCEPT ![r] = "disc"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, phv, basis, gen0, dsnap, ep0, dc, rseq, rpub>>

RunFenced(r) == LET d == own[r] IN
  DelFence /\ (lctl[d] = "deleted" \/ ldelv[d] > dsnap[r] \/ lgen[d] # gen0[r])

REndDisc(r) ==
  /\ rs[r] = "begun" /\ RunFenced(r)
  /\ rs' = [rs EXCEPT ![r] = "disc"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, phv, basis, gen0, dsnap, ep0, dc, rseq, rpub>>

\* End-time refusal: a run older than an unpublished run on this replica, or older than the head it knows,
\* is refused before its merge, so it never overwrites an unpublished row.
LocalMaxCv(d) == LET U == {x \in Runs : own[x] = d /\ rs[x] = "merged" /\ ~rpub[x]}
                 IN IF U = {} THEN 0 ELSE CHOOSE m \in {cv[x] : x \in U} : \A y \in {cv[x] : x \in U} : y <= m
EndRefused(r) == LET d == own[r]
                     lim == IF EndRefuse = "both" THEN Mx(LocalMaxCv(d), hcv[d])
                            ELSE IF EndRefuse = "head" THEN hcv[d]
                            ELSE IF EndRefuse = "local" THEN LocalMaxCv(d) ELSE 0
                 IN cv[r] < lim

REndRefuse(r) ==
  /\ rs[r] = "begun" /\ ~RunFenced(r) /\ EndRefused(r)
  /\ rs' = [rs EXCEPT ![r] = "ref"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, phv, basis, gen0, dsnap, ep0, dc, rseq, rpub>>

REndMerge(r) == LET d == own[r]
    ks == IF RetryMode = "dropRows" /\ ret[r] THEN {} ELSE dc[r]
    ch == {k \in ks : St(r) > rec[d][k]}
    nl == AppEnt(log[d], ch, St(r), "L")
  IN
  /\ rs[r] = "begun" /\ ~RunFenced(r) /\ ~EndRefused(r)
  /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> IF k \in ch THEN St(r) ELSE rec[d][k]]]
  /\ log' = [log EXCEPT ![d] = nl]
  /\ rseq' = [rseq EXCEPT ![r] = Len(nl)]
  /\ hold' = [hold EXCEPT ![d] = [k \in Keys |->
        IF BodyKeep = "off" THEN hold[d][k]
        ELSE IF k \in ch /\ rec[d][k] > 0 /\ Guarded(d, k) THEN hold[d][k] \cup {rec[d][k]}
        ELSE IF BodyKeep = "all" /\ k \in ks /\ k \notin ch /\ rec[d][k] > St(r) /\ Guarded(d, k) THEN hold[d][k] \cup {St(r)}
        ELSE hold[d][k]]]
  /\ redel' = [redel EXCEPT ![d] = IF RetryMode = "noCursor" /\ ret[r] THEN redel[d] \cup dc[r] ELSE redel[d]]
  /\ rs' = [rs EXCEPT ![r] = "merged"]
  /\ UNCHANGED <<fixedv, regv, ghostv, phv, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, dint, basis, gen0, dsnap, ep0, dc, rpub>>

\* ---------- legacy import (seeds) ----------
Import(d) ==
  /\ AllowImport /\ d \notin imported /\ sd[d] # {}
  /\ ImpChecksLocal => lctl[d] # "deleted"
  /\ LET ch == {k \in sd[d] : rec[d][k] = 0} IN
     /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> IF k \in ch THEN SEED ELSE rec[d][k]]]
     /\ log' = [log EXCEPT ![d] = AppEnt(log[d], ch, SEED, "I")]
  /\ lctl' = [lctl EXCEPT ![d] = IF lctl[d] = "none" THEN "live" ELSE lctl[d]]
  /\ lgen' = [lgen EXCEPT ![d] = IF lctl[d] = "none" THEN (IF rctl = "live" THEN rgen ELSE 1) ELSE lgen[d]]
  /\ imported' = imported \cup {d}
  /\ UNCHANGED <<fixedv, regv, dcount, nrec, ncrash, lostN, rep, wm, hver, hc, hpe, hcv, ldelv, dint, redel, phv, runv, hold>>

\* ---------- bootstrap from the registry (C.0) ----------
LocalPurge(d) ==
  /\ rec' = [rec EXCEPT ![d] = Z] /\ wm' = [wm EXCEPT ![d] = Len(log[d])]
  /\ hver' = [hver EXCEPT ![d] = 0] /\ hc' = [hc EXCEPT ![d] = Z] /\ hpe' = [hpe EXCEPT ![d] = FALSE]
  /\ hcv' = [hcv EXCEPT ![d] = 0] /\ ldelv' = [ldelv EXCEPT ![d] = ldelv[d] + 1]
  /\ redel' = [redel EXCEPT ![d] = {}] /\ hold' = [hold EXCEPT ![d] = [k \in Keys |-> {}]]
  /\ pph' = [pph EXCEPT ![d] = "idle"] /\ apl' = [apl EXCEPT ![d] = "idle"]

RefreshDeleted(d) ==
  /\ rctl = "deleted" /\ lctl[d] # "deleted"
  /\ LocalPurge(d)
  /\ lctl' = [lctl EXCEPT ![d] = "deleted"]
  /\ UNCHANGED <<fixedv, regv, ghostv, log, lgen, dint, pW, pBase, pPr, pEnc, pRep, aVer, aHead, aCv, runv>>

RefreshLive(d) ==
  /\ rctl = "live" /\ (lctl[d] # "live" \/ lgen[d] # rgen)
  /\ IF lgen[d] < rgen /\ lctl[d] # "none"
       THEN LocalPurge(d)
       ELSE UNCHANGED <<rec, wm, hver, hc, hpe, hcv, ldelv, redel, hold, pph, apl>>
  /\ lctl' = [lctl EXCEPT ![d] = "live"] /\ lgen' = [lgen EXCEPT ![d] = rgen]
  /\ UNCHANGED <<fixedv, regv, ghostv, log, dint, pW, pBase, pPr, pEnc, pRep, aVer, aHead, aCv, runv>>

\* ---------- apply (C.3), two batches ----------
ApplyStart(d) ==
  /\ apl[d] = "idle" /\ lctl[d] = "live" /\ rctl = "live" /\ lgen[d] = rgen
  /\ rver # hver[d] \/ (hpe[d] /\ hver[d] > 0)
  /\ aVer' = [aVer EXCEPT ![d] = rver] /\ aHead' = [aHead EXCEPT ![d] = rhead] /\ aCv' = [aCv EXCEPT ![d] = rhcv]
  /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> Mx(rec[d][k], rhead[k])]]
  /\ apl' = [apl EXCEPT ![d] = "merged"]
  /\ UNCHANGED <<fixedv, regv, ghostv, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, dint, redel, pph, pW, pBase, pPr, pEnc, pRep, runv, hold>>

ApplyFinish(d) ==
  /\ apl[d] = "merged" /\ lctl[d] = "live"
  /\ rec' = [rec EXCEPT ![d] = [k \in Keys |->
        IF aHead[d][k] = 0 /\ ~(ApplyGuard /\ Guarded(d, k)) THEN 0 ELSE rec[d][k]]]
  /\ hver' = [hver EXCEPT ![d] = aVer[d]] /\ hc' = [hc EXCEPT ![d] = aHead[d]]
  /\ hpe' = [hpe EXCEPT ![d] = FALSE] /\ hcv' = [hcv EXCEPT ![d] = aCv[d]]
  /\ apl' = [apl EXCEPT ![d] = "idle"]
  /\ UNCHANGED <<fixedv, regv, ghostv, log, wm, lctl, lgen, ldelv, dint, redel, pph, pW, pBase, pPr, pEnc, pRep, aVer, aHead, aCv, runv, hold>>

\* ---------- publish (C.2) ----------
PSnap(d) ==
  /\ pph[d] = "idle" /\ lctl[d] = "live" /\ Len(log[d]) > wm[d]
  /\ pW' = [pW EXCEPT ![d] = Len(log[d])] /\ pph' = [pph EXCEPT ![d] = "snap"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv, runv>>

Aligned(d) == (rctl # "deleted") /\ lctl[d] = "live" /\ hver[d] = rver /\ ~(hpe[d] /\ hver[d] > 0)
              /\ (rctl = "live" => lgen[d] = rgen)

\* Not aligned with the registry: stop; apply or bootstrap runs first.
PAbort(d) ==
  /\ pph[d] \in {"snap", "enc"} /\ (~Aligned(d) \/ (pph[d] = "enc" /\ hver[d] # pBase[d]))
  /\ pph' = [pph EXCEPT ![d] = "idle"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv, runv>>

Refused(d) == {r \in Runs : own[r] = d /\ rs[r] = "merged" /\ ~rpub[r] /\ cv[r] < hcv[d]}
Replacers(d) == {r \in Runs : own[r] = d /\ rs[r] = "merged" /\ ~rpub[r] /\ ECov(r) /\ rseq[r] <= pW[d]}
SeedRows(d) == {k \in Keys : rec[d][k] = SEED}

\* Step 3a: a refused run is un-written; its stream's head_parts go too.
PUnwrite(d) ==
  /\ pph[d] = "snap" /\ Aligned(d) /\ Refused(d) # {}
  /\ LET r == CHOOSE x \in Refused(d) : TRUE
         back == [k \in Keys |-> IF rec[d][k] = St(r) /\ BodyKeep # "off" THEN MaxSet(hold[d][k] \ {St(r)}) ELSE 0]
         newrec == [k \in Keys |-> IF rec[d][k] = St(r) THEN back[k] ELSE rec[d][k]]
     IN /\ rec' = [rec EXCEPT ![d] = newrec]
        /\ log' = [log EXCEPT ![d] = AppF(log[d], back, "L")]
        /\ hold' = [hold EXCEPT ![d] = [k \in Keys |-> (hold[d][k] \ {St(r)}) \ {back[k]}]]
        /\ rs' = [rs EXCEPT ![r] = "unw"]
  /\ hpe' = [hpe EXCEPT ![d] = IF UnwDropsParts THEN TRUE ELSE hpe[d]]
  /\ pph' = [pph EXCEPT ![d] = "idle"]
  /\ UNCHANGED <<fixedv, regv, ghostv, wm, hver, hc, hcv, lctl, lgen, ldelv, dint, redel, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv, basis, gen0, dsnap, ep0, dc, rseq, rpub>>

\* Seeds publish only into generation 1; otherwise they are purged.
PSeedPurge(d) ==
  /\ pph[d] = "snap" /\ Aligned(d) /\ Refused(d) = {}
  /\ SeedGenOnly /\ lgen[d] # 1 /\ SeedRows(d) # {}
  /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> IF rec[d][k] = SEED THEN 0 ELSE rec[d][k]]]
  /\ pph' = [pph EXCEPT ![d] = "idle"]
  /\ UNCHANGED <<fixedv, regv, ghostv, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, dint, redel, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv, runv, hold>>

PPlan(d) ==
  /\ pph[d] = "snap" /\ Aligned(d) /\ Refused(d) = {}
  /\ ~(SeedGenOnly /\ lgen[d] # 1 /\ SeedRows(d) # {})
  /\ \E pr \in Replacers(d) \cup {0} :
       /\ pPr' = [pPr EXCEPT ![d] = pr]
       /\ pBase' = [pBase EXCEPT ![d] = hver[d]]
       /\ pph' = [pph EXCEPT ![d] = "enc"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, pW, pEnc, pRep, apl, aVer, aHead, aCv, runv>>

PEnc(d) ==
  /\ pph[d] = "enc" /\ Aligned(d) /\ hver[d] = pBase[d]
  /\ LET pr == pPr[d]
         replacing == pr # 0 /\ (pBase[d] = basis[pr] \/ ~Fence)
         wk == {log[d][i].k : i \in {j \in (wm[d] + 1)..pW[d] : log[d][j].o \in Pub}}
     IN /\ pRep' = [pRep EXCEPT ![d] = replacing]
        /\ pEnc' = [pEnc EXCEPT ![d] =
             IF replacing
               THEN [k \in Keys |-> IF rec[d][k] >= St(pr) THEN rec[d][k] ELSE 0]
               ELSE [k \in Keys |-> IF k \in wk /\ rec[d][k] > 0 THEN Mx(rec[d][k], hc[d][k]) ELSE hc[d][k]]]
  /\ pph' = [pph EXCEPT ![d] = "cas"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, pW, pBase, pPr, apl, aVer, aHead, aCv, runv>>

PCasOK(d) ==
  /\ pph[d] = "cas" /\ lctl[d] = "live" /\ rctl # "deleted" /\ (rctl = "live" => lgen[d] = rgen)
  /\ rver = pBase[d]
  /\ LET pr == pPr[d]
         P == {r \in Runs : own[r] = d /\ rs[r] = "merged" /\ ~rpub[r] /\ rseq[r] <= pW[d]}
         mcv == IF P = {} THEN 0 ELSE CHOOSE m \in {cv[r] : r \in P} : \A x \in {cv[r] : r \in P} : x <= m
         skip == (pEnc[d] = rhead)
         newv == IF skip THEN rver ELSE rver + 1
         wmNew == IF WmAt = "commit" THEN Len(log[d]) ELSE pW[d]
     IN /\ rhead' = pEnc[d] /\ rver' = newv
        /\ rctl' = IF skip /\ rctl = "none" THEN "none" ELSE "live"
        /\ rhcv' = Mx(rhcv, mcv)
        /\ hvk' = [k \in Keys |-> IF pEnc[d][k] # rhead[k] THEN rver + 1 ELSE hvk[k]]
        /\ lostN' = lostN + (IF pRep[d] /\ (\E k \in Keys : rhead[k] > 0 /\ pEnc[d][k] = 0 /\ hvk[k] > basis[pr]) THEN 1 ELSE 0)
        /\ rep' = IF pRep[d] /\ basis[pr] = rver THEN rep \cup {pr} ELSE rep
        /\ rec' = [rec EXCEPT ![d] = IF pRep[d] THEN [k \in Keys |-> IF rec[d][k] < St(pr) THEN 0 ELSE rec[d][k]] ELSE rec[d]]
        /\ wm' = [wm EXCEPT ![d] = wmNew]
        /\ hold' = [hold EXCEPT ![d] = [k \in Keys |-> {x \in hold[d][k] : x > pEnc[d][k]}]]
        /\ hver' = [hver EXCEPT ![d] = newv] /\ hc' = [hc EXCEPT ![d] = pEnc[d]]
        /\ hpe' = [hpe EXCEPT ![d] = FALSE] /\ hcv' = [hcv EXCEPT ![d] = Mx(rhcv, mcv)]
        /\ rpub' = [r \in Runs |-> IF r \in P THEN TRUE ELSE rpub[r]]
        /\ pph' = [pph EXCEPT ![d] = "idle"]
  /\ UNCHANGED <<fixedv, dcount, nrec, ncrash, imported, log, lctl, lgen, ldelv, dint, redel, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv, rgen, rs, basis, gen0, dsnap, ep0, dc, rseq>>

\* CAS lost: the loser applies the winner (idle, apply follows); the mutant skips that.
PCasLost(d) ==
  /\ pph[d] = "cas" /\ lctl[d] = "live" /\ rctl # "deleted" /\ (rctl = "live" => lgen[d] = rgen)
  /\ rver # pBase[d]
  /\ IF LoserApplies
       THEN /\ pph' = [pph EXCEPT ![d] = "idle"] /\ UNCHANGED pBase
       ELSE /\ pBase' = [pBase EXCEPT ![d] = rver] /\ UNCHANGED pph
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, pW, pPr, pEnc, pRep, apl, aVer, aHead, aCv, runv>>

PCasStop(d) ==
  /\ pph[d] = "cas" /\ (lctl[d] # "live" \/ rctl = "deleted" \/ (rctl = "live" /\ lgen[d] # rgen))
  /\ pph' = [pph EXCEPT ![d] = "idle"]
  /\ UNCHANGED <<fixedv, regv, ghostv, locv, pW, pBase, pPr, pEnc, pRep, apl, aVer, aHead, aCv, runv>>

\* ---------- delete (F.5) ----------
DelLocal(d) ==
  /\ dcount < MaxDel /\ lctl[d] = "live" /\ dint[d] \in {"none", "done"}
  /\ LocalPurge(d)
  /\ lctl' = [lctl EXCEPT ![d] = "deleted"] /\ dint' = [dint EXCEPT ![d] = "saved"]
  /\ dcount' = dcount + 1
  /\ UNCHANGED <<fixedv, regv, nrec, ncrash, lostN, rep, imported, log, lgen, pW, pBase, pPr, pEnc, pRep, aVer, aHead, aCv, runv>>

DelHeads(d) ==
  /\ dint[d] = "saved" /\ rctl = "live"
  /\ rhead' = Z /\ rver' = rver + 1 /\ hvk' = [k \in Keys |-> rver + 1]
  /\ dint' = [dint EXCEPT ![d] = "heads"]
  /\ UNCHANGED <<fixedv, rctl, rgen, rhcv, ghostv, rec, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, redel, phv, runv, hold>>

DelCtl(d) ==
  /\ \/ dint[d] = "heads"
     \/ (dint[d] = "saved" /\ rctl # "live")
  /\ rctl' = IF rctl = "live" THEN "deleted"
             ELSE IF rctl = "none" /\ TombAbsent THEN "deleted" ELSE rctl
  /\ dint' = [dint EXCEPT ![d] = "done"]
  /\ UNCHANGED <<fixedv, rgen, rver, rhead, rhcv, hvk, ghostv, rec, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, redel, phv, runv, hold>>

Reconnect(d) ==
  /\ nrec < MaxRecon /\ rctl = "deleted" /\ lctl[d] = "deleted" /\ dint[d] \in {"none", "done"}
  /\ rctl' = "live" /\ rgen' = rgen + 1 /\ rhead' = Z /\ rver' = rver + 1 /\ rhcv' = 0
  /\ hvk' = [k \in Keys |-> rver + 1]
  /\ nrec' = nrec + 1
  /\ lctl' = [lctl EXCEPT ![d] = "live"] /\ lgen' = [lgen EXCEPT ![d] = rgen + 1]
  /\ hver' = [hver EXCEPT ![d] = rver + 1] /\ hc' = [hc EXCEPT ![d] = Z]
  /\ UNCHANGED <<fixedv, dcount, ncrash, lostN, rep, imported, rec, log, wm, hpe, hcv, ldelv, dint, redel, phv, runv, hold>>

Crash(d) ==
  /\ ncrash < MaxCrash
  /\ pph' = [pph EXCEPT ![d] = "idle"] /\ apl' = [apl EXCEPT ![d] = "idle"]
  /\ dint' = [dint EXCEPT ![d] = IF ~DelIntentFirst /\ dint[d] \in {"saved", "heads"} THEN "none" ELSE dint[d]]
  /\ ncrash' = ncrash + 1
  /\ UNCHANGED <<fixedv, regv, dcount, nrec, lostN, rep, imported, rec, log, wm, hver, hc, hpe, hcv, lctl, lgen, ldelv, redel, pW, pBase, pPr, pEnc, pRep, aVer, aHead, aCv, runv, hold>>

Terminal(r) == rs[r] \in {"merged", "disc", "unw", "ref"}
Pending(d) == lctl[d] = "live" /\ Len(log[d]) > wm[d]
AlignedQ(d) ==
  IF rctl = "live" THEN lctl[d] = "live" /\ lgen[d] = rgen /\ hver[d] = rver /\ ~hpe[d]
  ELSE IF rctl = "deleted" THEN lctl[d] = "deleted"
  ELSE TRUE
Q == /\ \A r \in Runs : Terminal(r)
     /\ \A d \in Devs : pph[d] = "idle" /\ apl[d] = "idle" /\ ~Pending(d) /\ dint[d] \in {"none", "done"} /\ AlignedQ(d)

Next == \/ \E r \in Runs : RBegin(r) \/ RBeginRefused(r) \/ REndDisc(r) \/ REndRefuse(r) \/ REndMerge(r)
        \/ \E d \in Devs : Import(d) \/ RefreshDeleted(d) \/ RefreshLive(d) \/ ApplyStart(d) \/ ApplyFinish(d)
                           \/ PSnap(d) \/ PAbort(d) \/ PUnwrite(d) \/ PSeedPurge(d) \/ PPlan(d) \/ PEnc(d)
                           \/ PCasOK(d) \/ PCasLost(d) \/ PCasStop(d)
                           \/ DelLocal(d) \/ DelHeads(d) \/ DelCtl(d) \/ Reconnect(d) \/ Crash(d)
        \/ (Q /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars

\* ---------- properties ----------
Cur(r) == ep0[r] = dcount /\ gen0[r] = rgen
CMrep == LET cs == {St(r) : r \in {x \in rep : Cur(x)}}
         IN IF cs = {} THEN 0 ELSE CHOOSE m \in cs : \A c \in cs : c <= m
Expected(k) ==
  /\ rctl # "deleted"
  /\ \/ \E r \in Runs : rs[r] = "merged" /\ k \in dc[r] /\ Cur(r) /\ St(r) >= CMrep
     \/ (dcount = 0 /\ CMrep = 0 /\ \E d \in imported : k \in sd[d])

TypeOK == /\ rctl \in {"none", "live", "deleted"} /\ rver \in Nat
          /\ \A d \in Devs : \A k \in Keys : rec[d][k] \in 0..4

\* No lost write: after quiescence, every expected row is readable on every replica.
NoLostWrite == Q => \A d \in Devs : \A k \in Keys : Expected(k) => rec[d][k] > 0
\* Replace deletes only rows the fence proves were covered (ghost counter, any state).
ReplaceFenced == lostN = 0
\* No resurrection: after quiescence every row traces to a run (or seed) from after the last delete.
NoResurrection == Q => \A d \in Devs : \A k \in Keys : rec[d][k] > 0 =>
    IF rec[d][k] = SEED THEN dcount = 0
    ELSE LET r == rec[d][k] - 1 IN rs[r] = "merged" /\ ep0[r] = dcount
\* A started delete reaches the registry (or is superseded by a reconnect).
DeleteDurable == (Q /\ dcount > 0) => (rctl = "deleted" \/ nrec > 0)
\* Witnesses (expected to be violated: prove the properties are not vacuous).
WitnessQ == ~(Q /\ \E d \in Devs : \E k \in Keys : rec[d][k] > 0)
WitnessUnwrite == ~(\E r \in Runs : rs[r] = "unw")
WitnessReplace == ~(rep # {})
WitnessDeleteDone == ~(Q /\ rctl = "deleted")
WitnessCasLost == ~(\E d \in Devs : pph[d] = "cas" /\ rver # pBase[d])
====
