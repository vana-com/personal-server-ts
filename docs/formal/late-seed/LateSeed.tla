------------------------------ MODULE LateSeed ------------------------------
\* A late, fill-only seed of legacy records into a stream that already has a
\* real write (`legacy-import.ts` once refused this with a "seed window"; the
\* model decides what replaces the window).
\*
\* The seed is one more writer of the connection log. Each device that sees the
\* switch converts every legacy record it has a `$pdpp` identity for. A converted
\* record enters as an upsert at the seed stamp (0, 'seed'), which ranks below
\* every real stamp (a real stamp is >= 1). The model asks whether a device can
\* decide, from what it holds, which keys it may fill, without a protocol change.
\*
\* What a device holds, per key:
\*   rec    the stored row (`records`): present or not, its stamp, its source;
\*   tomb   the tombstone it learned by applying the log (`log_tombstones`);
\*   pend   its pending changes above the publish watermark (`record_changes`),
\*          which publish deletes once the log acknowledges them.
\* The log keeps every tombstone for ever (compaction folds into the snapshot and
\* keeps them), so the log's fold is the truth a device converges to.
\*
\* The point of the model: a device that publishes its own delete or omission
\* keeps no tombstone of it (`log_tombstones` is filled by APPLYING a segment,
\* and a device does not apply its own). After the publish acknowledges, the
\* pending change is pruned, so the device has no trace of the delete. A late
\* seed that checks only `rec`, `tomb` and `pend` brings the record back on the
\* device that deleted it. `OwnTomb` is the repair: the commit that publishes a
\* delete or omission also writes the device's own tombstone. It is local state,
\* not a wire fact.
\*
\* The upgrade. The build before this one wrote no own tombstone, so a device that
\* published a delete or omission then holds no trace of it once compaction prunes
\* the pending change. The log still holds every deletion. `bld[d]` is the build
\* of device d: "old" (publishes write no own tombstone), "new" (they do) and
\* "rec" (new, and `Recover` has written a tombstone for every deletion in the
\* log d holds, `recoverLogTombstones` in log-tombstone-recovery.ts). Modes
\* "upgraded" and "upgradedNoRecover" start every device "old"; `Upgrade` and
\* `Recover` are enabled only there, so the other configs keep their states.
\* In "upgraded" a seed waits for "rec"; the mutant lets it run once "new".
\*
\* Mutants: each `Mode` breaks one rule; TLC must reject it.
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Keys,     \* the legacy keys (every key has a legacy record)
          Devs,     \* the devices that see the switch
          MaxO,     \* the highest real stamp
          MaxEv,    \* the most real events (live write, delete, omission, wipe)
          MaxLog,   \* the longest log
          Mode      \* "good" or one mutant

ASSUME MaxO >= 1

\* Rank of an operation beside its stamp: omission < upsert < explicit delete.
Rank(kind) == IF kind = "omit" THEN 0 ELSE IF kind = "up" THEN 1 ELSE 2

VARIABLES log,         \* the connection log: a sequence of segments (sets of ops)
          rec,         \* rec[d][k]: [on, stamp, src]
          tomb,        \* tomb[d][k]: [on, stamp, rank]
          pend,        \* pend[d]: set of [key, kind, stamp]
          pos,         \* the log position each device applied
          done,        \* done[d]: keys the seed pass of d has handled
          wiped,       \* the person deleted the connection
          knows,       \* knows[d]: d has learned of the wipe
          gdel,        \* ghost: deletions and omissions d authored or applied
          clobbered,   \* ghost: a seed step changed a row a live write made
          nev,         \* real events so far
          bld          \* bld[d]: "old", "new" or "rec" (see the upgrade above)
vars == <<log, rec, tomb, pend, pos, done, wiped, knows, gdel, clobbered, nev, bld>>

Upgrading == Mode \in {"upgraded", "upgradedNoRecover"}

Stamps == 0..MaxO
NoRow == [on |-> FALSE, stamp |-> 0, src |-> "none"]
NoTomb == [on |-> FALSE, stamp |-> 0, rank |-> 0]

\* ---- order ---------------------------------------------------------------
After(s1, r1, s2, r2) == s1 > s2 \/ (s1 = s2 /\ r1 > r2)

\* The fold of the whole log for one key: the greatest (stamp, rank) operation.
OpsOf(k) == {op \in UNION {log[i] : i \in 1..Len(log)} : op.key = k}
Best(k) ==
  CHOOSE op \in OpsOf(k) :
    \A o2 \in OpsOf(k) :
      ~After(o2.stamp, Rank(o2.kind), op.stamp, Rank(op.kind))
Fold(k) ==
  IF OpsOf(k) = {} THEN NoRow
  ELSE LET b == Best(k)
       IN IF b.kind = "up" THEN [on |-> TRUE, stamp |-> b.stamp, src |-> b.src]
          ELSE NoRow

\* ---- what a device knows of a key ----------------------------------------
PendDel(d, k) == {p \in pend[d] : p.key = k /\ p.kind \in {"del", "omit"}}
Known(d, k) ==
  LET xs == {rec[d][k].stamp} \cup {tomb[d][k].stamp}
            \cup {p.stamp : p \in PendDel(d, k)}
            \cup {g.stamp : g \in {x \in gdel[d] : x.key = k}}
  IN CHOOSE m \in xs : \A y \in xs : y <= m
TombBeats(d, k, s, rk) ==
  tomb[d][k].on /\ After(tomb[d][k].stamp, tomb[d][k].rank, s, rk)

\* ---- the seed ------------------------------------------------------------
\* May the seed fill key k on device d? Fill-only: the stream has never seen k
\* as far as the device can tell.
SeedOK(d, k) ==
  /\ (Mode = "seedIgnoresWipe" \/ ~knows[d])
  /\ (Mode = "seedOverwrite" \/ ~rec[d][k].on)
  /\ (Mode = "seedIgnoresTomb" \/ ~tomb[d][k].on)
  /\ (Mode = "seedIgnoresPend" \/ PendDel(d, k) = {})
  /\ (Mode # "windowClosed" \/ nev = 0)

\* A seed pass of device d may begin: after the upgrade, only once the device
\* has recovered its tombstones (the import recovers before it fills, so the
\* pass, its skips and its receipt all follow it).
Pass(d) ==
  /\ (Mode # "upgraded" \/ bld[d] = "rec")
  /\ (Mode # "upgradedNoRecover" \/ bld[d] # "old")

SeedStamp == IF Mode = "seedStampLive" THEN MaxO + 1 ELSE 0

Receipt(d) == Mode # "noReceipt" /\ done[d] = Keys

Seed(d, k) ==
  /\ Pass(d)
  /\ ~Receipt(d)
  /\ SeedOK(d, k)
  /\ rec' = [rec EXCEPT ![d][k] = [on |-> TRUE, stamp |-> SeedStamp, src |-> "seed"]]
  /\ pend' = IF Mode = "seedNotPublished" THEN pend
             ELSE [pend EXCEPT ![d] = @ \cup {[key |-> k, kind |-> "up", stamp |-> SeedStamp]}]
  /\ done' = [done EXCEPT ![d] = @ \cup {k}]
  /\ clobbered' = (clobbered \/ (rec[d][k].on /\ rec[d][k].src = "live"))
  /\ UNCHANGED <<bld, log, tomb, pos, wiped, knows, gdel, nev>>

\* A seed pass finds nothing to fill for a key it must leave (the guard says no):
\* the key is handled, and the pass can end.
SeedSkip(d, k) ==
  /\ Pass(d)
  /\ ~Receipt(d)
  /\ ~SeedOK(d, k)
  /\ k \notin done[d]
  /\ done' = [done EXCEPT ![d] = @ \cup {k}]
  /\ UNCHANGED <<bld, log, rec, tomb, pend, pos, wiped, knows, gdel, clobbered, nev>>

\* ---- real writes ---------------------------------------------------------
LiveUp(d, k, o) ==
  /\ nev < MaxEv /\ ~knows[d] /\ o \in 1..MaxO /\ o > Known(d, k)
  /\ rec' = [rec EXCEPT ![d][k] = [on |-> TRUE, stamp |-> o, src |-> "live"]]
  /\ pend' = [pend EXCEPT ![d] = @ \cup {[key |-> k, kind |-> "up", stamp |-> o]}]
  /\ nev' = nev + 1
  /\ UNCHANGED <<bld, log, tomb, pos, done, wiped, knows, gdel, clobbered>>

LiveRemove(d, k, o, kind) ==
  /\ nev < MaxEv /\ ~knows[d] /\ o \in 1..MaxO /\ o > Known(d, k)
  /\ rec[d][k].on
  /\ rec' = [rec EXCEPT ![d][k] = NoRow]
  /\ pend' = [pend EXCEPT ![d] = @ \cup {[key |-> k, kind |-> kind, stamp |-> o]}]
  /\ gdel' = [gdel EXCEPT ![d] = @ \cup {[key |-> k, kind |-> kind, stamp |-> o]}]
  /\ nev' = nev + 1
  /\ UNCHANGED <<bld, log, tomb, pos, done, wiped, knows, clobbered>>

\* ---- publish and apply ---------------------------------------------------
\* The ops a device publishes from its pending changes: an upsert goes as what the
\* device holds of the key now (and not at all if it holds none), a delete or
\* omission as itself (`operationsFor` in log-publish.ts).
OpsOfPend(d) ==
  {[key |-> p.key, kind |-> p.kind, stamp |-> p.stamp, src |-> "none"] :
     p \in {x \in pend[d] : x.kind \in {"del", "omit"}}}
  \cup
  {[key |-> p.key, kind |-> "up", stamp |-> rec[d][p.key].stamp,
    src |-> rec[d][p.key].src] :
     p \in {x \in pend[d] : x.kind = "up" /\ rec[d][x.key].on}}

MergeTomb(t, s, rk) ==
  IF ~t.on \/ After(s, rk, t.stamp, t.rank)
  THEN [on |-> TRUE, stamp |-> s, rank |-> rk] ELSE t

Publish(d) ==
  /\ ~wiped /\ pos[d] = Len(log) /\ Len(log) < MaxLog
  /\ OpsOfPend(d) # {}
  /\ log' = Append(log, OpsOfPend(d))
  /\ pos' = [pos EXCEPT ![d] = Len(log) + 1]
  /\ pend' = [pend EXCEPT ![d] = {}]
  /\ tomb' = IF Mode = "ownTombOff" \/ bld[d] = "old" THEN tomb
             ELSE [tomb EXCEPT ![d] = [k \in Keys |->
                    LET dels == {op \in OpsOfPend(d) : op.key = k /\ op.kind # "up"}
                    IN IF dels = {} THEN @[k]
                       ELSE MergeTomb(@[k],
                              (CHOOSE op \in dels : \A o2 \in dels : o2.stamp <= op.stamp).stamp,
                              Rank((CHOOSE op \in dels : \A o2 \in dels : o2.stamp <= op.stamp).kind))]]
  /\ UNCHANGED <<bld, rec, done, wiped, knows, gdel, clobbered, nev>>

\* Nothing to send: the pending upserts are for keys the device no longer holds.
\* Publish drops them (`commitIdle` in log-publish.ts).
Drop(d) ==
  /\ pend[d] # {} /\ OpsOfPend(d) = {}
  /\ pend' = [pend EXCEPT ![d] = {}]
  /\ UNCHANGED <<bld, log, rec, tomb, pos, done, wiped, knows, gdel, clobbered, nev>>

\* An applied operation of segment i on device d.
ApplyOp(d, op, t, r) ==
  \* returns <<tomb', rec'>> for one key's row and tombstone
  IF op.kind = "up" THEN
    IF t.on /\ After(t.stamp, t.rank, op.stamp, 1) THEN <<t, r>>
    ELSE IF \E p \in pend[d] : p.key = op.key /\ p.kind = "del" /\ p.stamp >= op.stamp THEN <<t, r>>
    ELSE IF \E p \in pend[d] : p.key = op.key /\ p.kind = "omit" /\ p.stamp > op.stamp THEN <<t, r>>
    ELSE IF ~r.on \/ op.stamp > r.stamp
         THEN <<t, [on |-> TRUE, stamp |-> op.stamp, src |-> op.src]>>
         ELSE <<t, r>>
  ELSE
    LET t2 == MergeTomb(t, op.stamp, Rank(op.kind))
        gone == r.on /\ (IF op.kind = "del" THEN r.stamp <= op.stamp ELSE r.stamp < op.stamp)
    IN <<t2, IF gone THEN NoRow ELSE r>>

Apply(d) ==
  /\ ~wiped /\ pos[d] < Len(log)
  /\ LET seg == log[pos[d] + 1]
         ops(k) == {op \in seg : op.key = k}
         \* deletions first (tombstones before upserts), then upserts
         dels(k) == {op \in ops(k) : op.kind # "up"}
         ups(k) == {op \in ops(k) : op.kind = "up"}
         afterDels(k) ==
           LET best == CHOOSE op \in dels(k) : \A o2 \in dels(k) :
                         ~After(o2.stamp, Rank(o2.kind), op.stamp, Rank(op.kind))
           IN IF dels(k) = {} THEN <<tomb[d][k], rec[d][k]>>
              ELSE ApplyOp(d, best, tomb[d][k], rec[d][k])
         afterAll(k) ==
           IF ups(k) = {} THEN afterDels(k)
           ELSE LET up == CHOOSE op \in ups(k) : TRUE
                IN ApplyOp(d, up, afterDels(k)[1], afterDels(k)[2])
     IN /\ tomb' = [tomb EXCEPT ![d] = [k \in Keys |-> afterAll(k)[1]]]
        /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> afterAll(k)[2]]]
        /\ gdel' = [gdel EXCEPT ![d] = @ \cup
              {[key |-> op.key, kind |-> op.kind, stamp |-> op.stamp] :
                 op \in {x \in seg : x.kind # "up"}}]
  /\ pos' = [pos EXCEPT ![d] = @ + 1]
  /\ UNCHANGED <<bld, log, pend, done, wiped, knows, clobbered, nev>>

\* ---- the upgrade ---------------------------------------------------------
Upgrade(d) ==
  /\ Upgrading /\ bld[d] = "old"
  /\ bld' = [bld EXCEPT ![d] = "new"]
  /\ UNCHANGED <<log, rec, tomb, pend, pos, done, wiped, knows, gdel, clobbered, nev>>

\* Write the tombstone of every deletion and omission in the log d holds
\* (positions 1..pos[d]): the greatest (stamp, rank) per key, merged into what d
\* already has.
LogDels(d, k) ==
  {op \in UNION {log[i] : i \in 1..pos[d]} : op.key = k /\ op.kind # "up"}

Recover(d) ==
  /\ Upgrading /\ bld[d] = "new"
  /\ tomb' = [tomb EXCEPT ![d] = [k \in Keys |->
        IF LogDels(d, k) = {} THEN @[k]
        ELSE LET best == CHOOSE op \in LogDels(d, k) :
                           \A o2 \in LogDels(d, k) :
                             ~After(o2.stamp, Rank(o2.kind), op.stamp, Rank(op.kind))
             IN MergeTomb(@[k], best.stamp, Rank(best.kind))]]
  /\ bld' = [bld EXCEPT ![d] = "rec"]
  /\ UNCHANGED <<log, rec, pend, pos, done, wiped, knows, gdel, clobbered, nev>>

\* ---- the person deletes the connection -----------------------------------
Wipe(d) ==
  /\ ~wiped /\ nev < MaxEv /\ ~knows[d]
  /\ wiped' = TRUE
  /\ knows' = [knows EXCEPT ![d] = TRUE]
  /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> NoRow]]
  /\ pend' = [pend EXCEPT ![d] = {}]
  /\ nev' = nev + 1
  /\ UNCHANGED <<bld, log, tomb, pos, done, gdel, clobbered>>

LearnWipe(d) ==
  /\ wiped /\ ~knows[d]
  /\ knows' = [knows EXCEPT ![d] = TRUE]
  /\ rec' = [rec EXCEPT ![d] = [k \in Keys |-> NoRow]]
  /\ pend' = [pend EXCEPT ![d] = {}]
  /\ UNCHANGED <<bld, log, tomb, pos, done, wiped, gdel, clobbered, nev>>

Init ==
  /\ log = <<>>
  /\ rec = [d \in Devs |-> [k \in Keys |-> NoRow]]
  /\ tomb = [d \in Devs |-> [k \in Keys |-> NoTomb]]
  /\ pend = [d \in Devs |-> {}]
  /\ pos = [d \in Devs |-> 0]
  /\ done = [d \in Devs |-> {}]
  /\ wiped = FALSE
  /\ knows = [d \in Devs |-> FALSE]
  /\ gdel = [d \in Devs |-> {}]
  /\ clobbered = FALSE
  /\ nev = 0
  /\ bld = [d \in Devs |-> IF Upgrading THEN "old" ELSE "new"]

Next ==
  \E d \in Devs :
    \/ \E k \in Keys : Seed(d, k) \/ SeedSkip(d, k)
    \/ \E k \in Keys, o \in 1..MaxO : LiveUp(d, k, o)
    \/ \E k \in Keys, o \in 1..MaxO : LiveRemove(d, k, o, "del") \/ LiveRemove(d, k, o, "omit")
    \/ Publish(d) \/ Drop(d) \/ Apply(d) \/ Wipe(d) \/ LearnWipe(d)
    \/ Upgrade(d) \/ Recover(d)

Spec == Init /\ [][Next]_vars

\* ---- properties ----------------------------------------------------------
TypeOK ==
  /\ \A d \in Devs, k \in Keys : rec[d][k].stamp \in 0..(MaxO + 1)
  /\ \A d \in Devs : pos[d] \in 0..Len(log)
  /\ \A d \in Devs : bld[d] \in {"old", "new", "rec"}

\* A record a device deleted or saw deleted never comes back on that device: a
\* row it holds for the key is newer than the deletion.
NoResurrection ==
  \A d \in Devs : \A g \in gdel[d] :
    rec[d][g.key].on => After(rec[d][g.key].stamp, Rank("up"), g.stamp, Rank(g.kind))

\* A seed step never changes a row a live write made.
SeedNeverClobbersLive == ~clobbered

\* A device that learned of the connection's deletion holds no row.
WipeStays == \A d \in Devs : knows[d] => \A k \in Keys : ~rec[d][k].on

\* The fold never lets a seed outrank a surviving live upsert of the same key.
LiveWins ==
  \A k \in Keys :
    (OpsOf(k) # {} /\ Best(k).kind = "up"
       /\ \E op \in OpsOf(k) : op.kind = "up" /\ op.src = "live")
    => Best(k).src = "live"

Quiet == ~wiped /\ \A d \in Devs : pend[d] = {} /\ pos[d] = Len(log)

\* Devices that hold everything the log holds hold the log's fold.
Convergence ==
  Quiet => \A d \in Devs, k \in Keys : rec[d][k] = Fold(k)

\* A device that finished its pass has nothing left a retry could add: every key
\* it may still fill it holds.
RetryAddsNothing ==
  \A d \in Devs : (Receipt(d) /\ ~knows[d]) =>
    \A k \in Keys : ~SeedOK(d, k) \/ rec[d][k].on

\* The seed fills: when every device finished and the log is quiet, a key no
\* deletion or omission ever named is in the fold.
Fills ==
  (Quiet /\ \A d \in Devs : done[d] = Keys) =>
    \A k \in Keys :
      (\A op \in OpsOf(k) : op.kind = "up") => Fold(k).on

=============================================================================
