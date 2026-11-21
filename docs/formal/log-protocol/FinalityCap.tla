---------------------------- MODULE FinalityCap ----------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC
\* A proposed upper cap on record stamps, checked before it is built. See the README section
\* "Finality cap" for the scope, the exact claims and the results.
\*
\* What is already built, and modelled as built. A run takes the start stamp `o` from its
\* device clock. `clampRunStart` (packages/core/src/localdb/admit.ts) raises it above the
\* newest stamp (o, run_id) the device holds: if (clock, run_id) is above the held stamp the
\* run keeps the clock; else if run_id sorts after the held run id it starts AT the held `o`;
\* else one above. Record bodies are ordered "latest wins" by (stamp_o, stamp_r), then the
\* kind (delete above upsert), the intake ordinal and the body, as in LogProtocol.tla.
\*
\* What is proposed. Each segment gets finality[seg], the time of ONE registry clock when it
\* became final. A device that applies a segment orders it by eff = min(stamp_o, finality),
\* so the order is the same on every device. The lower clamp then reads eff, not raw stamps.
\*
\* Scope. Two devices (device 1 may run fast), two keys, one connection, bounded registry
\* time. The log is a sequence; a device holds a prefix of it, and a writer appends only when
\* its device holds the whole log (the registry compare-and-swap). A run publishes segments
\* while it collects; a delete is the run's last segment. The seed is one upsert per key at
\* stamp (0, run id 0), below every run. NOT modelled: the compaction watermark and stream
\* floors of the lower clamp (each is a maximum over stamps already held, so the model's
\* held-stamp maximum stands for them, ONLY IF every stored copy of a stamp is eff), the
\* SEEN stamp, omissions, clones (two writers with one run id), clock steps backwards,
\* crashes, and a mixed rollout of devices with and without the cap.
CONSTANTS Mode, MaxT, SkewA, SkewB, RunsA, RunsB, MaxSegs
\* good            the proposal.
\* noCap           mutant: eff = stamp. The lower clamp reads the same (raw) stamps.
\* rawClamp        mutant: eff caps the order, but the lower clamp reads raw stamps.
\* noClamp         mutant: eff caps the order, no lower clamp (the clock alone).
\* localFinality   mutant: each device takes finality from its OWN clock when it applies.
\* ownRaw          mutant: the author device keeps its own segment's raw stamp.
\* tieFinality     mutant: the registry may give two segments one finality value.
\* midDelete       mutant: a run may publish upserts AFTER its delete.
ASSUME /\ Mode \in {"good","noCap","rawClamp","noClamp","localFinality","ownRaw",
                    "tieFinality","midDelete"}
       /\ MaxSegs \in 1..2
       /\ RunsA + RunsB \in 1..7
       /\ MaxT \in 1..8
       /\ SkewA \in 0..4 /\ SkewB \in 0..4

Devs == {1,2}
Keys == {1,2}
Skew(d) == IF d = 1 THEN SkewA ELSE SkewB
Runs(d) == IF d = 1 THEN RunsA ELSE RunsB
RunIds == 1..(RunsA + RunsB)
Max2(a,b) == IF a > b THEN a ELSE b
Min2(a,b) == IF a < b THEN a ELSE b
\* A device clock reads the registry time plus its fixed skew. It never reads below 0.
Clk(d,x) == Max2(0, x + Skew(d))

\* Segment fields: key, kind (up or del), r (run id, 0 = seed), ord (intake ordinal of an
\* upsert, 0 for a delete), dev (author, 0 = seed), o (the run's raw start stamp),
\* F (the registry time at which the segment became final).
Seed(k) == [key |-> k, kind |-> "up", r |-> 0, ord |-> 0, dev |-> 0, o |-> 0, F |-> 0]

VARIABLES t,     \* registry time
          log,   \* the registry's log: a sequence of segments, positions 1..Len(log)
          h,     \* h[d]: device d holds log positions 1..h[d]
          fin,   \* fin[d][i]: the finality device d applied to position i (localFinality only)
          run,   \* run[r]: the run with id r
          lastF  \* the finality of the newest segment
vars == <<t, log, h, fin, run, lastF>>
NewRun == [st |-> "new", dev |-> 0, o |-> 0, bt |-> 0, n |-> 0, snap |-> 0]

\* The stamp device d orders position i by. It is the one place the modes differ.
Eff(d,i) ==
  LET s == log[i] IN
  CASE Mode = "noCap" -> s.o
    [] Mode = "localFinality" -> Min2(s.o, fin[d][i])
    [] Mode = "ownRaw" -> IF s.dev = d THEN s.o ELSE Min2(s.o, s.F)
    [] OTHER -> Min2(s.o, s.F)

\* The order of one key's segments as one number. Radices: run id < 8, kind rank < 3,
\* ordinal < 2, position < 32. The last field, the position, stands for the body tie-break
\* (bodies are unique per segment). Delete ranks above upsert.
KindRank(s) == IF s.kind = "del" THEN 2 ELSE 1
RankAt(stamp,s,i) == (((stamp * 8 + s.r) * 3 + KindRank(s)) * 2 + s.ord) * 32 + i
Rk(d,i) == RankAt(Eff(d,i), log[i], i)
RawRk(i) == RankAt(log[i].o, log[i], i)

Held(d) == 1..h[d]
\* The newest (stamp, run id) pair the device holds, as stamp * 8 + run id. The lower clamp
\* reads eff, or the raw stamp in the rawClamp and noCap modes (noCap has eff = raw).
HeldPair(d,i) == IF Mode = "rawClamp" THEN log[i].o * 8 + log[i].r
                 ELSE Eff(d,i) * 8 + log[i].r
Hwm(d) == LET S == {HeldPair(d,i) : i \in Held(d)}
          IN CHOOSE m \in S : \A x \in S : x <= m
\* `clampRunStart`: keep the clock when above the held stamp; at a tie on the stamp, start AT
\* the held `o` when the run id sorts after the held run id, else one above.
StartO(d,r) ==
  LET c == Clk(d,t) IN
  IF Mode = "noClamp" THEN c
  ELSE LET hv == Hwm(d) IN
       IF c * 8 + r > hv THEN c
       ELSE IF r > hv % 8 THEN hv \div 8 ELSE hv \div 8 + 1

Init == /\ t = 1
        /\ log = <<Seed(1), Seed(2)>>
        /\ h = [d \in Devs |-> 2]
        /\ fin = [d \in Devs |-> <<0,0>>]
        /\ run = [r \in RunIds |-> NewRun]
        /\ lastF = 0

Tick == /\ t < MaxT /\ t' = t + 1
        /\ UNCHANGED <<log, h, fin, run, lastF>>

\* A device begins a run; it has no other run open and has runs left.
Begin(d,r) ==
  /\ run[r].st = "new"
  /\ \A q \in RunIds : ~(run[q].st = "open" /\ run[q].dev = d)
  /\ Cardinality({q \in RunIds : run[q].st # "new" /\ run[q].dev = d}) < Runs(d)
  /\ run' = [run EXCEPT ![r] = [st |-> "open", dev |-> d, o |-> StartO(d,r), bt |-> t,
                                n |-> 0, snap |-> h[d]]]
  /\ UNCHANGED <<t, log, h, fin, lastF>>

\* The run's device holds the whole log (the compare-and-swap), appends a segment, and the
\* registry stamps it final at the registry's time. One registry clock gives distinct values
\* (one segment per tick) unless the mode is tieFinality. A delete ends the run.
Publish(r,k,kind) ==
  LET d == run[r].dev IN
  /\ run[r].st = "open" /\ run[r].n < MaxSegs
  /\ h[d] = Len(log)
  /\ (Mode = "tieFinality" \/ lastF < t)
  /\ LET s == [key |-> k, kind |-> kind, r |-> r,
               ord |-> IF kind = "up" THEN run[r].n ELSE 0,
               dev |-> d, o |-> run[r].o, F |-> t]
     IN /\ log' = Append(log, s)
        /\ h' = [h EXCEPT ![d] = Len(log) + 1]
        /\ fin' = [fin EXCEPT ![d] = Append(fin[d], IF Mode = "localFinality" THEN Clk(d,t) ELSE 0)]
  /\ run' = [run EXCEPT ![r].n = run[r].n + 1,
                        ![r].st = IF (kind = "del" /\ Mode # "midDelete")
                                     \/ run[r].n + 1 = MaxSegs
                                  THEN "closed" ELSE "open"]
  /\ lastF' = t
  /\ UNCHANGED t

Close(r) == /\ run[r].st = "open" /\ run[r].n >= 1
            /\ run' = [run EXCEPT ![r].st = "closed"]
            /\ UNCHANGED <<t, log, h, fin, lastF>>

\* A device applies the next position of the log.
Apply(d) ==
  /\ h[d] < Len(log)
  /\ h' = [h EXCEPT ![d] = h[d] + 1]
  /\ fin' = [fin EXCEPT ![d] = Append(fin[d], IF Mode = "localFinality" THEN Clk(d,t) ELSE 0)]
  /\ UNCHANGED <<t, log, run, lastF>>

Next == \/ Tick
        \/ \E d \in Devs, r \in RunIds : Begin(d,r)
        \/ \E r \in RunIds, k \in Keys, kind \in {"up","del"} : Publish(r,k,kind)
        \/ \E r \in RunIds : Close(r)
        \/ \E d \in Devs : Apply(d)
Spec == Init /\ [][Next]_vars

TypeOK == /\ t \in 1..MaxT
          /\ \A d \in Devs : h[d] \in 2..Len(log) /\ Len(fin[d]) = h[d]
          /\ Len(log) <= 2 + (RunsA + RunsB) * MaxSegs

\* The winner of a key on a device: the position of the greatest segment it holds. A
\* delete that wins means the key is deleted.
Win(d,k) == CHOOSE i \in Held(d) : log[i].key = k /\ \A j \in Held(d) : log[j].key = k => Rk(d,j) <= Rk(d,i)

\* (a) Convergence: two devices holding the same segments hold the same winners.
Converged == \A d1, d2 \in Devs : h[d1] = h[d2] => \A k \in Keys : Win(d1,k) = Win(d2,k)

\* (b) A run that begins after applying version v ranks above v at every device that holds
\* both: its write ends as the winner or a successor wins. `snap` is the prefix the run's
\* device held when the run began.
BeginAfterWins ==
  \A e \in Devs : \A i \in Held(e) :
    log[i].r > 0 => \A j \in 1..run[log[i].r].snap :
      log[j].key = log[i].key => Rk(e,i) > Rk(e,j)

\* (c) The equal-stamp rules, read under eff.
\* c1: later segments of one run rank above earlier ones of the same key (ordinals; a delete
\*     is last).
SameRunOrder ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[i].r > 0 /\ log[i].r = log[j].r /\ log[i].key = log[j].key)
      => Rk(e,j) > Rk(e,i)
\* c2: a delete outranks an upsert of the same run on the same key (delete wins the tie).
DeleteWinsTie ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (log[i].kind = "del" /\ log[j].kind = "up" /\ log[i].r > 0 /\ log[i].r = log[j].r
       /\ log[i].key = log[j].key) => Rk(e,i) > Rk(e,j)
\* c3: the seed (stamp 0, run id 0) ranks below every run's segment on its key.
SeedLoses ==
  \A e \in Devs : \A i \in Held(e) : log[i].r > 0 => Rk(e,i) > Rk(e,log[i].key)

\* (d) Bounded drag. A run's raw start is at most its own clock or one above the registry
\* time at its begin, whichever is greater. The "one above" is the tie rule of the lower
\* clamp. DragRaw is the bound for every run. DragSlow is the same bound for a run on a device
\* whose clock is not the fastest: another device's skew must not enter it.
DragRaw ==
  \A r \in RunIds : run[r].st # "new" =>
    run[r].o <= Max2(Clk(run[r].dev, run[r].bt), run[r].bt + 1)
DragSlow ==
  \A r \in RunIds : (run[r].st # "new" /\ Skew(run[r].dev) = Min2(SkewA, SkewB)) =>
    run[r].o <= Max2(Clk(run[r].dev, run[r].bt), run[r].bt + 1)
\* d2: no stamp a device orders by is above the registry time now.
DragEff == \A d \in Devs : \A i \in Held(d) : Eff(d,i) <= t

\* Does capping reorder two writes of one key? Raw order is the order by the raw stamps (what
\* a device orders by without the cap); eff order is the order under the cap.
\* CausalNoFlip: for a pair where j's run began after i was applied, the cap never puts j
\*   below i when the raw order has j above i.
\* ConcurrentNoFlip: for two writes of different runs where neither run began after applying
\*   the other, raw order and eff order agree. Expected to FAIL: concurrent writes can flip.
CausalNoFlip ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[j].r > 0 /\ i <= run[log[j].r].snap /\ log[i].key = log[j].key)
      => ~(RawRk(j) > RawRk(i) /\ Rk(e,j) < Rk(e,i))
\* RawCausalMonotone: for such a pair the RAW order also has j above i, that is, the raw stamps
\*   stay causally monotone. The built lower clamp keeps it. The cap-aware clamp does NOT (it
\*   reads eff, so a run's raw stamp may sit below the raw stamp it follows): a reader that
\*   orders by raw stamps would then be wrong. Expected to FAIL with the cap, PASS without.
RawCausalMonotone ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[j].r > 0 /\ i <= run[log[j].r].snap /\ log[i].key = log[j].key)
      => RawRk(j) > RawRk(i)
ConcurrentNoFlip ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[i].r > 0 /\ log[j].r > 0 /\ log[i].r # log[j].r
       /\ i > run[log[j].r].snap /\ log[i].key = log[j].key)
      => (RawRk(i) > RawRk(j) <=> Rk(e,i) > Rk(e,j))
=============================================================================
