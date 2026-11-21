---------------------------- MODULE SourceClock ----------------------------
EXTENDS Integers, Sequences, FiniteSets, TLC
\* An alternative to the finality cap of FinalityCap.tla, checked before anything is built. It
\* fixes fast device clocks at the SOURCE: a device corrects its stamp with the offset to the
\* registry clock, and the registry refuses a stamp from the future. See the README section
\* "Source clock" for the scope, the exact claims and the results. This module reuses the
\* shape of FinalityCap.tla (two devices, two keys, one log, the lower clamp as built).
\*
\* Design D, in four rules.
\*  1. Offset. Device d keeps off[d] = registry time - device clock, measured at its last
\*     contact with the registry (an append, a refused append, or reading a log position). A
\*     run takes its start stamp `o` from the device clock PLUS that offset, then the built
\*     lower clamp (`clampRunStart`) raises it above the newest held (stamp, run id). The device
\*     clock may jump ahead after the last contact, so the corrected stamp can still be ahead.
\*  2. Refusal. The registry refuses an append whose run stamp is greater than the registry
\*     time at acceptance. There is no fixed margin. A refused run changes nothing in the log.
\*  3. Retry. On refusal the device measures the offset again and the run takes a NEW stamp
\*     (offset, then the clamp over everything the device holds now). Its causal snapshot
\*     becomes the whole log it holds now. Only a run's first append can be refused: a later
\*     append comes later in registry time than the stamp.
\*  4. Order. A stored stamp is never rewritten. Every device orders by the RAW stored stamp
\*     (stamp, run id, kind, ordinal, position), as it does today. There is no eff, no finality.
\*
\* Bound. OnePerTick = TRUE lets the registry accept at most one append per registry tick. It
\* is NOT part of D: it is the bound FinalityCap.tla uses (one registry clock value per
\* segment), kept as an option because it shrinks the state space to a size TLC finishes.
\* OnePerTick = FALSE allows several appends at one registry time, which includes the ties.
\*
\* Modes. Mode "good" is D. Every other mode removes or breaks one rule, to show the checks
\* can fail. The registry time `t` is bounded by MaxT; MaxJump bounds how far one device clock
\* jumps ahead in total (in steps of one); Flip = "off" switches the whole protocol off once,
\* Flip = "on" switches it on once from a log written without it (while it is off a device
\* stamps with its raw clock, no offset, and the registry does not refuse).
\*
\* NOT modelled: a clock that steps backwards or runs slow, the delay between the registry's
\* reading and the device's use of it, more than two devices or keys, clones, crashes, the
\* compaction watermark and stream floors, the SEEN stamp, omissions, the author's own
\* pending rows before the registry accepts them, and devices that run old code at the same
\* time (a mixed rollout).
CONSTANTS Mode, MaxT, SkewA, SkewB, RunsA, RunsB, MaxSegs, MaxJump, Flip, OnePerTick
\* good            design D.
\* noRefuse        mutant: the registry never refuses.
\* noRemeasure     mutant: a refused run retries with its old offset (it is not measured again).
\* noOffset        mutant: the device never applies the offset (refusal stays on).
\* devTime         mutant: the registry compares the stamp with the DEVICE time, not its own.
\* slack           mutant: the registry allows a stamp one above its time (a fixed margin of 1).
\* noClamp         mutant: no lower clamp at begin or retry.
\* retakeNoClamp   mutant: the lower clamp is skipped on the retry only.
\* capOrder        control: the finality cap of FinalityCap.tla in this module: no offset, no
\*                 refusal, order by min(stamp, finality), one append per tick.
ASSUME /\ Mode \in {"good","noRefuse","noRemeasure","noOffset","devTime","slack",
                    "noClamp","retakeNoClamp","capOrder"}
       /\ MaxSegs \in 1..2
       /\ RunsA + RunsB \in 1..7
       /\ MaxT \in 1..8
       /\ SkewA \in 0..4 /\ SkewB \in 0..4
       /\ MaxJump \in 0..3
       /\ Flip \in {"none","off","on"}
       /\ OnePerTick \in BOOLEAN

Devs == {1,2}
Keys == {1,2}
Skew(d) == IF d = 1 THEN SkewA ELSE SkewB
Runs(d) == IF d = 1 THEN RunsA ELSE RunsB
RunIds == 1..(RunsA + RunsB)
Max2(a,b) == IF a > b THEN a ELSE b
Min2(a,b) == IF a < b THEN a ELSE b

\* Segment fields: key, kind (up or del), r (run id, 0 = seed), ord (intake ordinal of an
\* upsert, 0 for a delete), dev (author, 0 = seed), o (the run's stored start stamp), F (the
\* registry time at which the registry accepted it), acc (the protocol was on when it was
\* accepted). F and acc are never read by the order, except in the capOrder control.
Seed(k) == [key |-> k, kind |-> "up", r |-> 0, ord |-> 0, dev |-> 0, o |-> 0, F |-> 0,
            acc |-> TRUE]

VARIABLES t,     \* registry time
          log,   \* the registry's log: a sequence of segments, positions 1..Len(log)
          h,     \* h[d]: device d holds log positions 1..h[d]
          run,   \* run[r]: the run with id r (rt: registry time of its last retry while its first append is
                 \* still pending, else 0)
          off,   \* off[d]: the offset device d measured at its last contact (never positive)
          jmp,   \* jmp[d]: how far device d's clock has jumped ahead of its fixed skew
          on,    \* is design D on (Flip may switch it once)
          lastF  \* the registry time of the newest append (only read when appends are spaced)
vars == <<t, log, h, run, off, jmp, on, lastF>>
NewRun == [st |-> "new", dev |-> 0, o |-> 0, n |-> 0, snap |-> 0, rt |-> 0]

\* Device clock now, and the offset it would measure now (registry time - device clock).
Clk(d) == t + Skew(d) + jmp[d]
Meas(d) == t - Clk(d)
UseOffset == on /\ Mode \notin {"noOffset","capOrder"}
Spaced == OnePerTick \/ Mode = "capOrder"
Refuses == on /\ Mode \notin {"noRefuse","capOrder"}
\* The stamp the device reads off its clock, corrected by the offset `od` when D is on.
Raw(d,od) == IF UseOffset THEN Clk(d) + od ELSE Clk(d)
\* The registry's check. In devTime the reference is the device's clock.
Limit(d) == IF Mode = "devTime" THEN Clk(d) ELSE t
Over(d,o) == Refuses /\ (IF Mode = "slack" THEN o > Limit(d) + 1 ELSE o > Limit(d))

\* The stamp a device orders a position by. Only capOrder differs from the stored stamp.
OrdIn(L,i) == IF Mode = "capOrder" THEN Min2(L[i].o, L[i].F) ELSE L[i].o
Ord(i) == OrdIn(log, i)

\* The order of one key's segments as one number. Radices: run id < 8, kind rank < 3,
\* ordinal < 2, position < 32. The last field, the position, stands for the body tie-break.
\* Delete ranks above upsert.
KindRank(s) == IF s.kind = "del" THEN 2 ELSE 1
RankAt(stamp,s,i) == (((stamp * 8 + s.r) * 3 + KindRank(s)) * 2 + s.ord) * 32 + i
RkIn(L,i) == RankAt(OrdIn(L,i), L[i], i)
Rk(i) == RkIn(log, i)
RawRk(i) == RankAt(log[i].o, log[i], i)

Held(d) == 1..h[d]
\* The newest (stamp, run id) pair the device holds, as stamp * 8 + run id.
HeldPair(i) == Ord(i) * 8 + log[i].r
Hwm(d) == LET S == {HeldPair(i) : i \in Held(d)}
          IN CHOOSE m \in S : \A x \in S : x <= m
\* `clampRunStart`: keep the stamp when above the held one; at a tie on the stamp, start AT the
\* held `o` when the run id sorts after the held run id, else one above.
Clamp(d,r,c) ==
  LET hv == Hwm(d) IN
  IF c * 8 + r > hv THEN c ELSE IF r > hv % 8 THEN hv \div 8 ELSE hv \div 8 + 1
StartO(d,r,od,doClamp) == LET c == Raw(d,od) IN IF doClamp THEN Clamp(d,r,c) ELSE c
BeginClamp == Mode # "noClamp"
RetryClamp == Mode \notin {"noClamp","retakeNoClamp"}

Init == /\ t = 1
        /\ log = <<Seed(1), Seed(2)>>
        /\ h = [d \in Devs |-> 2]
        /\ run = [r \in RunIds |-> NewRun]
        \* A device starts with no measured offset (0) or the exact offset at time 1.
        /\ off \in {f \in [Devs -> -4..0] : \A d \in Devs : f[d] = 0 \/ f[d] = -Skew(d)}
        /\ jmp = [d \in Devs |-> 0]
        /\ on = (Flip # "on")
        /\ lastF = 0

Tick == /\ t < MaxT /\ t' = t + 1
        /\ UNCHANGED <<log, h, run, off, jmp, on, lastF>>

\* A device clock jumps ahead by one. The offset it measured earlier is now stale.
Jump(d) == /\ jmp[d] < MaxJump
           /\ jmp' = [jmp EXCEPT ![d] = jmp[d] + 1]
           /\ UNCHANGED <<t, log, h, run, off, on, lastF>>

\* The whole protocol is switched, once: off (Flip = "off", it starts on) or on (Flip = "on", it
\* starts off).
SwitchProtocol == /\ ((Flip = "off" /\ on) \/ (Flip = "on" /\ ~on))
                  /\ on' = ~on
                  /\ UNCHANGED <<t, log, h, run, off, jmp, lastF>>

\* A device begins a run; it has no other run open and has runs left.
Begin(d,r) ==
  /\ run[r].st = "new"
  /\ \A q \in RunIds : ~(run[q].st = "open" /\ run[q].dev = d)
  /\ Cardinality({q \in RunIds : run[q].st # "new" /\ run[q].dev = d}) < Runs(d)
  /\ run' = [run EXCEPT ![r] = [st |-> "open", dev |-> d, o |-> StartO(d,r,off[d],BeginClamp),
                                n |-> 0, snap |-> h[d], rt |-> 0]]
  /\ UNCHANGED <<t, log, h, off, jmp, on, lastF>>

\* The run's device holds the whole log (the compare-and-swap) and the registry accepts the
\* append: the stamp is not above the registry time. The device measures the offset again.
\* A delete ends the run.
Publish(r,k,kind) ==
  LET d == run[r].dev IN
  /\ run[r].st = "open" /\ run[r].n < MaxSegs
  /\ h[d] = Len(log)
  /\ ~Over(d, run[r].o)
  /\ (~Spaced \/ lastF < t)
  /\ LET s == [key |-> k, kind |-> kind, r |-> r,
               ord |-> IF kind = "up" THEN run[r].n ELSE 0,
               dev |-> d, o |-> run[r].o, F |-> t, acc |-> on]
     IN /\ log' = Append(log, s)
        /\ h' = [h EXCEPT ![d] = Len(log) + 1]
  /\ off' = [off EXCEPT ![d] = Meas(d)]
  /\ run' = [run EXCEPT ![r].n = run[r].n + 1,
                        ![r].st = IF kind = "del" \/ run[r].n + 1 = MaxSegs
                                  THEN "closed" ELSE "open",
                        ![r].rt = 0]
  /\ lastF' = IF Spaced THEN t ELSE lastF
  /\ UNCHANGED <<t, jmp, on>>

\* The registry refuses the first append of a run whose stamp is above its time. The log does
\* not change. The device measures the offset again (not in noRemeasure) and the run takes a
\* new stamp over everything the device holds; its causal snapshot is that whole log.
Refuse(r) ==
  LET d == run[r].dev
      od == IF Mode = "noRemeasure" THEN off[d] ELSE Meas(d) IN
  /\ run[r].st = "open" /\ run[r].n = 0
  /\ h[d] = Len(log)
  /\ Over(d, run[r].o)
  /\ off' = [off EXCEPT ![d] = od]
  /\ run' = [run EXCEPT ![r].o = StartO(d,r,od,RetryClamp), ![r].snap = h[d], ![r].rt = t]
  /\ UNCHANGED <<t, log, h, jmp, on, lastF>>

Close(r) == /\ run[r].st = "open" /\ run[r].n >= 1
            /\ run' = [run EXCEPT ![r].st = "closed"]
            /\ UNCHANGED <<t, log, h, off, jmp, on, lastF>>

\* A device applies the next position of the log (a read: it measures the offset).
Apply(d) ==
  /\ h[d] < Len(log)
  /\ h' = [h EXCEPT ![d] = h[d] + 1]
  /\ off' = [off EXCEPT ![d] = Meas(d)]
  /\ UNCHANGED <<t, log, run, jmp, on, lastF>>

Next == \/ Tick
        \/ \E d \in Devs : Jump(d)
        \/ SwitchProtocol
        \/ \E d \in Devs, r \in RunIds : Begin(d,r)
        \/ \E r \in RunIds, k \in Keys, kind \in {"up","del"} : Publish(r,k,kind)
        \/ \E r \in RunIds : Refuse(r)
        \/ \E r \in RunIds : Close(r)
        \/ \E d \in Devs : Apply(d)
Spec == Init /\ [][Next]_vars

TypeOK == /\ t \in 1..MaxT
          /\ \A d \in Devs : h[d] \in 2..Len(log) /\ off[d] <= 0 /\ jmp[d] \in 0..MaxJump
          /\ Len(log) <= 2 + (RunsA + RunsB) * MaxSegs

\* The winner of a key on a device: the position of the greatest segment it holds. A delete
\* that wins means the key is deleted.
Win(d,k) == CHOOSE i \in Held(d) : log[i].key = k /\ \A j \in Held(d) : log[j].key = k => Rk(j) <= Rk(i)

\* (a) Convergence: two devices holding the same segments hold the same winners.
Converged == \A d1, d2 \in Devs : h[d1] = h[d2] => \A k \in Keys : Win(d1,k) = Win(d2,k)

\* (b) A run that begins (or retries) after applying version v ranks above v at every device
\* that holds both. `snap` is the prefix the run's device held at its begin or last retry.
BeginAfterWins ==
  \A e \in Devs : \A i \in Held(e) :
    log[i].r > 0 => \A j \in 1..run[log[i].r].snap :
      log[j].key = log[i].key => Rk(i) > Rk(j)

\* (c) The equal-stamp rules.
SameRunOrder ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[i].r > 0 /\ log[i].r = log[j].r /\ log[i].key = log[j].key) => Rk(j) > Rk(i)
DeleteWinsTie ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (log[i].kind = "del" /\ log[j].kind = "up" /\ log[i].r > 0 /\ log[i].r = log[j].r
       /\ log[i].key = log[j].key) => Rk(i) > Rk(j)
SeedLoses ==
  \A e \in Devs : \A i \in Held(e) : log[i].r > 0 => Rk(i) > Rk(log[i].key)

\* (d) Drag. DragAccepted: no stamp accepted while the protocol was on is above the registry
\* time at its acceptance. DragEff: no stamp a device orders by is above the registry time now
\* (the same name and meaning as in FinalityCap.tla).
DragAccepted == \A i \in 1..Len(log) : log[i].acc => log[i].o <= log[i].F
DragEff == \A d \in Devs : \A i \in Held(d) : Ord(i) <= t

\* Progress, as an invariant. A retried run's new stamp is at most one above the registry time
\* of the retry, whatever the clock skew is. So the next attempt after one tick is accepted.
\* (A refusal is only ever caused by a stamp above the registry time.)
RetryBound == \A r \in RunIds :
  (run[r].st # "new" /\ run[r].rt > 0 /\ run[r].n = 0) => run[r].o <= run[r].rt + 1
\* RetryAccepts: one registry tick after a retry, the run's first append is acceptable (the
\* registry would not refuse it), if its device holds the whole log. This is the enabledness
\* half of "eventually accepted": the registry time passes, nothing else is needed.
RetryAccepts == \A r \in RunIds :
  (run[r].st = "open" /\ run[r].rt > 0 /\ run[r].n = 0 /\ t > run[r].rt /\ h[run[r].dev] = Len(log))
    => ~Over(run[r].dev, run[r].o)

\* No-flip. RawRk is the order by the stamp the author took. Rk is the order every device uses.
\* CausalNoFlip: for a pair where j's run began after i was applied, no device puts j below i
\*   when the author's stamps have j above i.
\* ConcurrentNoFlip: for two writes of different runs where neither run began after applying
\*   the other, the author-stamp order and the device order agree.
\* ReaderAgrees: for EVERY pair of one key, a reader that orders by the raw stored stamps
\*   (for example a device with the protocol switched off) agrees with the protocol's order.
\* RawCausalMonotone: for a causal pair, the raw stamps have the later write above.
CausalNoFlip ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[j].r > 0 /\ i <= run[log[j].r].snap /\ log[i].key = log[j].key)
      => ~(RawRk(j) > RawRk(i) /\ Rk(j) < Rk(i))
ConcurrentNoFlip ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[i].r > 0 /\ log[j].r > 0 /\ log[i].r # log[j].r
       /\ i > run[log[j].r].snap /\ log[i].key = log[j].key)
      => (RawRk(i) > RawRk(j) <=> Rk(i) > Rk(j))
ReaderAgrees ==
  \A i \in 1..Len(log), j \in 1..Len(log) :
    log[i].key = log[j].key => (RawRk(i) > RawRk(j) <=> Rk(i) > Rk(j))
RawCausalMonotone ==
  \A e \in Devs : \A i \in Held(e), j \in Held(e) :
    (i < j /\ log[j].r > 0 /\ i <= run[log[j].r].snap /\ log[i].key = log[j].key)
      => RawRk(j) > RawRk(i)

\* A winner a device has applied only ever changes to a higher-ranked segment. Checked as a
\* property of every step.
WinIn(L,H,d,k) ==
  CHOOSE i \in 1..H[d] : L[i].key = k /\ \A j \in 1..H[d] : L[j].key = k => RkIn(L,j) <= RkIn(L,i)
WinnerOnlyRises ==
  [][\A d \in Devs, k \in Keys :
       RkIn(log', WinIn(log', h', d, k)) >= RkIn(log, WinIn(log, h, d, k))]_vars
=============================================================================
