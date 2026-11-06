----------------------------- MODULE StreamSync -----------------------------
(***************************************************************************)
(* Bounded model of whole-file stream sync, design revision 4.1, section  *)
(* 4, with the three-outcome base rule (stale_generation), and the run    *)
(* intake contract v2 (section 9 of that contract, as reduced by the      *)
(* owner's decisions: no tombstones, no absence deletion, no restricted   *)
(* streams).  README.md states the bounds, the abstractions, how each     *)
(* property reads here, and the results.  Section numbers refer to the    *)
(* design.                                                                 *)
(*                                                                         *)
(* One connector c.  A connection is a namespace n: the account itself,   *)
(* or "" for an identity-less connector.  ctl[n] is the control row chain *)
(* (index = registry version); hd[n][s] is the stream row chain of heads. *)
(* A line is <<pk, rid, acct, origin>>: rid is the run id (run start      *)
(* order, so (o, r) order is rid order); seed lines have rid 0.          *)
(* Legacy-file lines use origin "legacy".                                 *)
(*                                                                         *)
(* Action -> package function or host step:                               *)
(*   StartRun, Rerun  run intake begin + batches + end: the writer issues *)
(*                    the START mode and state; copy of `controls`        *)
(*                    (start), userConnect, full; the outcome, covered    *)
(*                    streams and checkpoint candidate; identity is known *)
(*                    at start                                            *)
(*   List             sync loop: registry listing, generation change,     *)
(*                    stopped and resume                                  *)
(*   NewSession       app restart or crash: listing and in-memory         *)
(*                    decisions lost, outbox kept                         *)
(*   Decide           decide(start, control), the table of 2.4            *)
(*   CtlPost          create / reconnect POST with exact resend           *)
(*   PlanPublish      read stream row, base, merge, seed, upload parts,   *)
(*                    PUT head, persist request (2.6, 2.7, 2.9); covered  *)
(*                    streams only                                        *)
(*   PlanStale        the stream row has a higher generation:             *)
(*                    stale_generation, decide again (2.7)                *)
(*   Post             head POST: commit, replay, 409, lost reply          *)
(*   LateApply        a request whose reply was lost reaches the registry *)
(*   OldDelete        an old app's non-exclusive DELETE tombstones a      *)
(*                    stream row (limitation L11)                         *)
(*   Leave            a device stops forever and loses its local state    *)
(*   SettleFail       a head row fails settlement after its ack           *)
(*   Finish           checkpoint save with control re-check (2.4): the    *)
(*                    covered streams' cursors merged into the stored     *)
(*                    checkpoint of the same (n, generation)              *)
(*   RetryPending     end{retry_pending}: checkpoint-only save, with the  *)
(*                    same admission; nothing declared or published       *)
(*   Abort            end{failed|cancelled} or abort: abortRun            *)
(*   FailEntry        an outbox entry fails permanently                   *)
(*   Import           sync-loop import of live verified heads (2.9)       *)
(*   UserDelete       tombstone every control row of the connector (2.11) *)
(*   (old install)    writes the legacy file at any time: reads are       *)
(*                    checked against every legacy file (Legacies)        *)
(*   Cleanup          best-effort cleanup of deleted generations (2.11)   *)
(*   PsSync           a reader PS syncs its registry view                 *)
(*   Read, Readiness  eligible(c, name) of 2.10 (operators, not actions)  *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
  Devices, Desktop, Readers, Acct, PK, Streams,
  IdLess,          \* the connector declares no account identity: ns = ""
  OtherKey,        \* devices that hold another owner key (key profile)
  LegacyFrom,      \* the stream the legacy name projects; its raw file is pdpp.c.<LegacyFrom>
  FullStreams,     \* streams declared incremental: false (collected whole every run)
  MaxRuns, MaxReruns, MaxDeletes, MaxLost, MaxSessions, MaxSettleFail,
  MaxFail, MaxVer,
  MaxRetry,        \* runs that end retry_pending
  MaxAbort,        \* runs that end failed or cancelled (abortRun)
  MaxLeave,        \* devices that may leave (stop forever, local state lost)
  MaxOldDelete,    \* old non-exclusive stream DELETEs (limitation L11)
  Views,           \* model device imports (key and liveness profiles)
  \* --- guards, all TRUE in the design; each control turns one off ---
  GenInNames,        \* part names carry the generation (2.1)
  ClearOnGenChange,  \* checkpoints and entries cleared on a generation change (2.4)
  ExclusiveHeads,    \* head commits use exclusive: true (2.3)
  OneConnectionRead, \* a plain read serves one connection (2.10)
  SeedOnlyGen1,      \* the Desktop seed only at generation 1 (2.9)
  CheckpointAfterAll,\* checkpoint after every stream commits, with re-check (2.4)
  ReReadAfterCtl,    \* re-read and decide again after a create/reconnect reply (2.3)
  NoRebind,          \* a spool is published only under its own start's target (2.4)
  NeedListing,       \* start = null (no listing this session) is unknown (2.4)
  LegacyHonoursDelete, \* no legacy fallback while a connection is deleted (2.10)
  OneWay,            \* a live complete view is never compared with a legacy file (2.10)
  NeedsFull,         \* complete:false sets needsFull (2.7)
  ImportPastPending, \* pending entries never block import (2.9)
  SeedWhateverBase,  \* the Desktop seed merges into any base (2.9)
  AckImmutable,      \* an acknowledged row stays at its version (2.3, GW (a))
  ReadinessSame,     \* readiness and reads use one predicate (2.10)
  StaleGenStops,     \* a stream row of a higher generation stops the publish (2.7)
  NoOpNeedsFull,     \* a no-op onto a complete:false base sets needsFull (2.6, Q9)
  NullBasePublishes, \* a run onto an empty base never no-ops (M3)
  NeedsFullForcesFull,\* any needsFull of the connector makes a run full
  \* --- run intake v2 guards ---
  PublishCoveredOnly,\* only covered streams are declared and published (v2 3.5)
  WriterIssuesStart, \* START state is the writer's issue, not the producer's (v2 2.1, R16)
  RetryQuietOnly,    \* retry_pending saves no cursor of a stream with spooled records
  FullMerges         \* a stream-full run merges into its base; it never replaces it

ASSUME Desktop \in Devices /\ LegacyFrom \in Streams /\ OtherKey \subseteq Devices
ASSUME FullStreams \subseteq Streams

VARIABLES
  ctl,       \* ctl[n]: Seq of [k |-> "A" or "T", key]
  hd,        \* hd[n][s]: Seq of heads [g, lines, complete, key, at]
  failed,    \* <<n, s, version>> head rows whose settlement failed
  store,     \* names of the stored blobs
  login,     \* login[d]: the account d last ran for
  listing,   \* listing[d]: control lengths from the last listing this session, or Null
  known,     \* known[d][n]: control length the sync loop last saw (persisted)
  stopped,   \* stopped[d][n]: 0, or the tombstone version d stopped at
  needsFull, \* needsFull[d]: set of <<n, s>>
  ckpt,      \* ckpt[d]: [n, g, cur, ctlOk] or NoCk; cur[s] is the run whose cursor is saved
  ob,        \* ob[d]: the outbox entry (one run at a time), or NoEntry
  view,      \* view[d][n][s]: imported head version, 0 = none
  psv,       \* psv[p][n]: [c |-> control length, h |-> [s |-> head length]]
  inflight,  \* requests whose reply was lost
  seedTarget,\* the Desktop's seedTarget(c), or "none"
  rcpt,      \* Desktop seed receipts <<n, s>>
  clock,     \* run ids
  commits,   \* ghost: <<n, s, g, rid, pks>> per committed (or no-op) stream of a run
  admitted,  \* ghost: <<rid, g>> when a run was bound to g and decide(start, control) = g
  inserted,  \* ghost: <<n, s, version, head>> for every head row written
  lateOld,   \* ghost: a head was written while control was not active(its generation)
  left,      \* devices that left for good
  fin,       \* fin[d]: (n, T, stream row version seen per stream) of d's last finished run
  acked,     \* ghost: <<n, s, version, head>> for every head commit acknowledged
  selfConflict, \* ghost: a request was refused because of its own row
  quiet,     \* ghost: <<rid, s>> when a retry_pending save kept a cursor of a stream with no records
  cnt

vars == <<ctl, hd, failed, store, login, listing, known,
          stopped, needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock,
          commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, cnt>>

----------------------------------------------------------------------------
Null == [x \in {} |-> 0]  \* no listing this session (a function, so it compares with listings)
NSOf(a) == IF IdLess THEN "" ELSE a
NS == {NSOf(a) : a \in Acct}
Key(d) == IF d \in OtherKey THEN "k2" ELSE "k1"
ReaderKey == "k1"

NoFile == [present |-> FALSE, at |-> 0, lines |-> {}, id |-> "none"]
FileOf(a, origin, id) ==
  [present |-> TRUE, at |-> 0, lines |-> {<<p, 0, a, origin>> : p \in PK}, id |-> id]
\* A head.  oc (ghost): a run published it for a stream it did not cover,
\* and not as the Desktop seed (only controls set it).
NoHead == [g |-> 0, lines |-> {}, complete |-> FALSE, key |-> "", at |-> 0, oc |-> FALSE]
NoReq == [ver |-> 0, h |-> NoHead]
NoCur == [s \in Streams |-> 0]
NoCk == [n |-> "none", g |-> 0, cur |-> NoCur, ctlOk |-> FALSE]
\* An entry.  full: the issued collection mode is full_refresh (never read
\* from the state).  sw: the issued state belongs to another namespace.
\* stOk: the START state the connector used is the writer's issue.  cov:
\* covered streams; emit: streams with records in the spool; cand: the
\* retry_pending candidate's streams; out: "ok" (succeeded or partial),
\* "retry" (retry_pending) or "abort" (failed, cancelled).
NoEntry == [rid |-> 0, a |-> "none", n |-> "none", start |-> Null, uc |-> FALSE,
            full |-> FALSE, sw |-> FALSE, pks |-> {}, emit |-> {}, dead |-> FALSE,
            incomp |-> FALSE, T |-> 0, cov |-> {}, cand |-> {}, out |-> "ok",
            stOk |-> TRUE,
            st |-> [s \in Streams |-> "none"], g |-> [s \in Streams |-> 0],
            req |-> [s \in Streams |-> NoReq], seeding |-> {},
            seen |-> [s \in Streams |-> 0]]
NoFin == [n |-> "none", T |-> 0, seen |-> [s \in Streams |-> 0], cov |-> {}]
\* An old app's non-exclusive DELETE writes this row (limitation L11).
TombHead == [g |-> 0, lines |-> {}, complete |-> FALSE, key |-> "old", at |-> 0, oc |-> FALSE]
IsTomb(h) == h.key = "old"

Max(a, b) == IF a > b THEN a ELSE b
SetMax(S) == IF S = {} THEN 0 ELSE CHOOSE x \in S : \A y \in S : y <= x

\* Control state at a given length of the chain, as a holder of key k sees it.
StateAt(n, len, k) ==
  IF len = 0 THEN [k |-> "absent", g |-> 0]
  ELSE IF ctl[n][len].k = "T" THEN [k |-> "deleted", g |-> len]
  ELSE IF ctl[n][len].key # k THEN [k |-> "foreign", g |-> len]
  ELSE [k |-> "active", g |-> len]
CtlLen(n) == Len(ctl[n])
CtlNow(n, k) == StateAt(n, CtlLen(n), k)
ActiveAny(n) == CtlLen(n) > 0 /\ ctl[n][CtlLen(n)].k = "A"
Deleted(n) == CtlLen(n) > 0 /\ ctl[n][CtlLen(n)].k = "T"
CurGen(n) == IF ActiveAny(n) THEN CtlLen(n) ELSE 0
DeletedGens(n) == {v - 1 : v \in {i \in 1..CtlLen(n) : ctl[n][i].k = "T"}}

Latest(n, s) == IF hd[n][s] = <<>> THEN NoHead ELSE hd[n][s][Len(hd[n][s])]
\* Liveness rule (2.4): control active(g) and the latest head has generation g.
Live(n, s) == ActiveAny(n) /\ hd[n][s] # <<>> /\ Latest(n, s).g = CurGen(n)
LatestOfGen(n, s, g) ==
  LET is == {i \in 1..Len(hd[n][s]) : hd[n][s][i].g = g}
  IN IF is = {} THEN NoHead ELSE hd[n][s][SetMax(is)]

\* Merge (2.6): per pk the greatest (o, r) wins.  Seed lines have o = 0.
ORank(o) == CASE o = "run" -> 2 [] o = "seed" -> 1 [] OTHER -> 0
Rank(l) == l[2] * 3 + ORank(l[4])
PKsOf(L) == {l[1] : l \in L}
Best(L, p) == CHOOSE l \in L : l[1] = p /\ \A m \in L : m[1] = p => Rank(m) <= Rank(l)
Merge(L) == {Best(L, p) : p \in PKsOf(L)}

\* Blob names (2.1).  Parts are named by content.  Record values are not
\* modelled, so the worst case holds: a record of key pk has the same
\* content in every run, and its part name is (n, s, g, pk).  Without the
\* generation in the name (control C01), equal records of two generations
\* share a part.
PartName(n, s, g, l) == IF GenInNames THEN <<"p", n, s, g, l[1]>> ELSE <<"p", n, s, 0, l[1]>>
Objects(n, s, h) == {<<"h", n, s, h>>} \cup {PartName(n, s, h.g, l) : l \in h.lines}

----------------------------------------------------------------------------
\* Decide (2.4).  S is the start state, C the current state (as device d
\* sees them).  The table gives the target generation: > 0 publish, 0
\* discard, -1 keep pending, -2 create, -3 reconnect.
StartState(d, e) ==
  IF e.start = Null THEN [k |-> "unknown", g |-> 0] ELSE StateAt(e.n, e.start[e.n], Key(d))

Table(S, C, uc, full) ==
  CASE C.k = "foreign" -> -1
    [] S.k = "unknown" -> 0
    [] S.k = "absent" /\ C.k = "absent" -> -2
    [] S.k = "absent" /\ C.k = "active" /\ C.g = 1 -> 1
    [] S.k = "active" /\ C.k = "active" /\ C.g = S.g -> S.g
    [] S.k = "active" /\ (C.k = "absent" \/ (C.k = "active" /\ C.g < S.g)) -> -1
    [] S.k = "deleted" /\ uc /\ full /\ C.k = "deleted" /\ C.g = S.g -> -3
    [] S.k = "deleted" /\ uc /\ full /\ C.k = "active" /\ C.g = S.g + 1 -> S.g + 1
    [] OTHER -> 0

\* The design's admission: the target the table gives this run now.
Admits(d, e) == Table(StartState(d, e), CtlNow(e.n, Key(d)), e.uc, e.full)

\* What the device acts on.  Only the controls make it differ from Admits.
\* Without NoRebind (control C08) a userConnect entry decides as if it had
\* started at the current generation: it reconnects a deleted connection
\* and publishes under whatever generation is current.
EffStart(d, e) ==
  LET C == CtlNow(e.n, Key(d)) IN
  IF ~NoRebind /\ e.uc /\ C.k = "deleted" THEN C
  ELSE IF ~NoRebind /\ e.uc /\ C.k = "active" THEN [k |-> "deleted", g |-> C.g - 1]
  ELSE IF e.start = Null /\ ~NeedListing THEN [k |-> "absent", g |-> 0]
  ELSE StartState(d, e)
EffTable(d, e) == Table(EffStart(d, e), CtlNow(e.n, Key(d)), e.uc, e.full)

\* Bind stream s of d's entry to generation t, recording admission.
Bind(d, s, t) ==
  /\ ob' = [ob EXCEPT ![d].st[s] = "decided", ![d].g[s] = t, ![d].T = t]
  /\ admitted' = IF Admits(d, ob[d]) = t THEN admitted \cup {<<ob[d].rid, t>>} ELSE admitted
  /\ known' = [known EXCEPT ![d][ob[d].n] = Max(@, CtlLen(ob[d].n))]

Discard(d, clear) ==
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ ckpt' = IF clear /\ ckpt[d].n = ob[d].n THEN [ckpt EXCEPT ![d] = NoCk] ELSE ckpt

Decide(d, s) ==
  LET e == ob[d]
      t == EffTable(d, e)
      S == EffStart(d, e)
  IN /\ ~e.dead /\ e.st[s] = "planned"
     /\ t # -1
     /\ CASE t > 0 -> Bind(d, s, t) /\ UNCHANGED ckpt
          [] t = -2 -> /\ ob' = [ob EXCEPT ![d].st[s] = "creating", ![d].g[s] = 1]
                       /\ UNCHANGED <<ckpt, admitted, known>>
          [] t = -3 -> /\ ob' = [ob EXCEPT ![d].st[s] = "reconnecting",
                                           ![d].g[s] = CtlLen(e.n) + 1]
                       /\ UNCHANGED <<ckpt, admitted, known>>
          [] OTHER -> /\ Discard(d, ClearOnGenChange /\ S.k = "active")
                      /\ UNCHANGED <<admitted, known>>
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, stopped,
                 needsFull, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 inserted, lateOld, left, fin, acked, selfConflict, quiet, cnt>>

\* Create or reconnect POST (2.3): exclusive, identical bytes, exact resend
\* after a lost reply.  A success or replay is followed by a re-read: the
\* stream goes back to Decide.  Without ReReadAfterCtl it binds at once.
CtlRow(d) == [k |-> "A", key |-> Key(d)]
CtlOutcome(n, ver, row) ==
  IF CtlLen(n) = ver - 1 THEN "insert"
  ELSE IF CtlLen(n) >= ver /\ ctl[n][ver] = row THEN "replay"
  ELSE "conflict"

CtlPost(d, s) ==
  LET e == ob[d]
      n == e.n
      ver == e.g[s]
      row == CtlRow(d)
      out == CtlOutcome(n, ver, row)
  IN /\ ~e.dead /\ e.st[s] \in {"creating", "reconnecting"}
     /\ \/ /\ ctl' = IF out = "insert" THEN [ctl EXCEPT ![n] = Append(@, row)] ELSE ctl
           /\ IF out = "conflict"
              THEN /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
                   /\ UNCHANGED <<admitted, known>>
              ELSE IF ReReadAfterCtl
              THEN /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
                   /\ known' = [known EXCEPT ![d][n] = Max(@, ver)]
                   /\ UNCHANGED admitted
              ELSE /\ ob' = [ob EXCEPT ![d].st[s] = "decided", ![d].T = ver]
                   /\ admitted' = IF Admits(d, e) = ver THEN admitted \cup {<<e.rid, ver>>}
                                  ELSE admitted
                   /\ known' = [known EXCEPT ![d][n] = Max(@, ver)]
           /\ UNCHANGED <<inflight, cnt>>
        \/ /\ cnt.lost < MaxLost
           /\ inflight' = inflight \cup {[kind |-> "ctl", n |-> n, ver |-> ver, row |-> row]}
           /\ cnt' = [cnt EXCEPT !.lost = @ + 1]
           /\ UNCHANGED <<ctl, ob, admitted, known>>
  /\ UNCHANGED <<hd, failed, store, login, listing, stopped,
                 needsFull, ckpt, view, psv, seedTarget, rcpt, clock, commits, inserted, lateOld, left, fin,
                 acked, selfConflict, quiet>>

----------------------------------------------------------------------------
\* The head row version to write after (2.3).  The design: the latest row,
\* whatever its settlement.  Without AckImmutable: the latest non-failed row.
BaseVer(n, s) ==
  IF AckImmutable THEN Len(hd[n][s])
  ELSE SetMax({i \in 1..Len(hd[n][s]) : <<n, s, i>> \notin failed})

HeadOutcome(n, s, ver, h) ==
  LET rows == hd[n][s]
      occ == Len(rows) >= ver
  IN IF occ /\ rows[ver] = h THEN "replay"
     ELSE IF occ /\ ~ExclusiveHeads THEN "overwrite"
     ELSE IF occ /\ ~AckImmutable /\ <<n, s, ver>> \in failed THEN "overwrite"
     ELSE IF occ THEN "conflict"
     ELSE IF Len(rows) = ver - 1 THEN "insert"
     ELSE "conflict"

WriteHead(n, s, ver, h, rid, pks, out) ==
  IF out \in {"insert", "overwrite"}
  THEN /\ hd' = [hd EXCEPT ![n][s] = IF out = "insert" THEN Append(@, h)
                                       ELSE [@ EXCEPT ![ver] = h]]
       /\ commits' = commits \cup {<<n, s, h.g, rid, pks>>}
       /\ inserted' = inserted \cup {<<n, s, ver, h>>}
       /\ lateOld' = (lateOld \/ ~(ActiveAny(n) /\ CurGen(n) = h.g))
       /\ failed' = failed \ {<<n, s, ver>>}
  ELSE UNCHANGED <<hd, commits, inserted, lateOld, failed>>

\* The record keys a run collected for stream s (none if it emitted nothing).
RunPKs(e, s) == IF s \in e.emit THEN e.pks ELSE {}

\* Read the stream row, plan and upload (2.6, 2.7, 2.9), persist the
\* request.  Base (2.7), three outcomes on the row at BaseVer:
\*   generation < T, or no row      -> empty base;
\*   generation = T                 -> that row is the base;
\*   generation > T                 -> stale_generation: publish nothing,
\*                                     re-read control and decide again.
\* Without StaleGenStops (control) a higher generation gives an empty base.
PlanStale(d, s) ==
  LET e == ob[d]
      N == BaseVer(e.n, s)
      top == IF N = 0 THEN NoHead ELSE hd[e.n][s][N]
  IN /\ ~e.dead /\ e.st[s] = "decided"
     /\ StaleGenStops /\ top.g > e.g[s]
     /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
  /\ UNCHANGED <<store, needsFull, ckpt, commits, rcpt>>
  /\ UNCHANGED <<ctl, hd, failed, login, listing, known, stopped,
                 view, psv, inflight, seedTarget, clock, admitted, inserted, lateOld, left, fin, acked,
                 selfConflict, quiet, cnt>>

\* The publish half: the row's generation is at most T.
\*
\* Run intake v2 (3.5): only covered streams are declared and published.
\* A stream that is not covered gets no head, its spool lines are dropped
\* with the run, and its cursor is not saved.  The Desktop seed (2.9) is
\* not a run output: a Desktop run to seedTarget also plans every stream
\* that has no receipt yet, and a stream it plans only for the seed
\* publishes only if the seed merges (generation 1); otherwise the stream
\* is skipped with a "skipped" receipt.  Without PublishCoveredOnly
\* (control) every stream is published, covered or not.
PubCov(e) == IF PublishCoveredOnly THEN e.cov ELSE Streams
\* "Full" per stream (v2 3.0): the run's issued mode is full_refresh, or
\* the stream is declared incremental: false.
FullS(e, s) == e.full \/ s \in FullStreams

PlanPublish(d, s) ==
  LET e == ob[d]
      n == e.n
      T == e.g[s]
      N == BaseVer(n, s)
      top == IF N = 0 THEN NoHead ELSE hd[n][s][N]
      base == IF top.g = T THEN top ELSE NoHead
      covered == s \in PubCov(e)
      first == d = Desktop /\ n = seedTarget /\ <<n, s>> \notin rcpt
      seeded == /\ first /\ (T = 1 \/ ~SeedOnlyGen1)
                /\ (SeedWhateverBase \/ base = NoHead)
      seedLines == IF seeded THEN {<<p, 0, "desk", "seed">> : p \in PK} ELSE {}
      runLines == IF covered THEN {<<p, e.rid, e.a, "run">> : p \in RunPKs(e, s)} ELSE {}
      fullS == covered /\ FullS(e, s)
      \* The merge keeps every base line (2.6).  Without FullMerges
      \* (control) a stream-full run replaces the stream, as Desktop's
      \* local snapshot does today.
      kept == IF FullMerges \/ ~fullS THEN base.lines ELSE {}
      lines == Merge(kept \cup seedLines \cup runLines)
      complete == ~e.sw /\ (fullS \/ base.complete \/ seeded)
      h == [g |-> T, lines |-> lines, complete |-> complete, key |-> Key(d),
            at |-> e.rid, oc |-> (s \notin e.cov /\ ~seeded)]
      seeding == IF first THEN e.seeding \cup {s} ELSE e.seeding
      \* Q9: a no-op onto a complete:false base of generation T
      q9 == NoOpNeedsFull /\ base # NoHead /\ ~base.complete
  IN /\ ~e.dead /\ e.st[s] = "decided"
     /\ ~(StaleGenStops /\ top.g > T)
     /\ IF ~covered /\ ~seeded
        THEN \* planned for the seed only, and the seed does not apply:
             \* no head, a "skipped" receipt
             /\ ob' = [ob EXCEPT ![d].st[s] = "done", ![d].g[s] = 0,
                                 ![d].seeding = seeding, ![d].seen[s] = N]
             /\ rcpt' = IF first THEN rcpt \cup {<<n, s>>} ELSE rcpt
             /\ UNCHANGED <<store, commits, needsFull, ckpt>>
        \* No-op (2.6): a base of generation T, and every part and
        \* `complete` unchanged, or an empty spool with no seed (generation
        \* > 1: the receipt records "skipped", 2.9).  No upload and no
        \* POST.  An empty base (no row, an L11 tombstone, an older
        \* generation) never gives a no-op (M3, the package's isNoop is
        \* false for a null base): the run publishes, at least an empty
        \* complete:false head, so needsFull is set and the checkpoint is
        \* not saved.
        ELSE IF /\ base # NoHead \/ ~NullBasePublishes
                /\ \/ lines = base.lines /\ complete = base.complete
                   \/ runLines = {} /\ ~seeded
        THEN \* the stream counts as committed at (n, T)
             /\ ob' = [ob EXCEPT ![d].st[s] = "done", ![d].g[s] = 0,
                                 ![d].seeding = seeding, ![d].seen[s] = N,
                                 ![d].incomp = @ \/ q9]
             /\ commits' = commits \cup {<<n, s, T, e.rid, RunPKs(e, s)>>}
             /\ rcpt' = IF first THEN rcpt \cup {<<n, s>>} ELSE rcpt
             /\ needsFull' = IF q9 THEN [needsFull EXCEPT ![d] = @ \cup {<<n, s>>}]
                             ELSE needsFull
             /\ ckpt' = IF q9 THEN [ckpt EXCEPT ![d] = NoCk] ELSE ckpt
             /\ UNCHANGED store
        ELSE /\ store' = store \cup Objects(n, s, h)
             /\ ob' = [ob EXCEPT ![d].st[s] = "posted", ![d].seeding = seeding,
                                 ![d].req[s] = [ver |-> N + 1, h |-> h],
                                 ![d].incomp = @ \/ ~complete]
             /\ needsFull' = IF ~complete /\ NeedsFull
                             THEN [needsFull EXCEPT ![d] = @ \cup {<<n, s>>}]
                             ELSE needsFull
             /\ ckpt' = IF ~complete THEN [ckpt EXCEPT ![d] = NoCk] ELSE ckpt
             /\ UNCHANGED <<commits, rcpt>>
  /\ UNCHANGED <<ctl, hd, failed, login, listing, known, stopped,
                 view, psv, inflight, seedTarget, clock, admitted, inserted, lateOld, left, fin, acked,
                 selfConflict, quiet, cnt>>

\* Save cursors for the streams S of run rid into d's checkpoint, tagged
\* (n, g) (v2 3.6): value = {...prev, ...candidate}, where prev is the
\* stored value when the stored (n, g) equals the run's, else empty.
SaveCk(d, n, g, S, rid, ok) ==
  LET prev == IF ckpt[d] # NoCk /\ ckpt[d].n = n /\ ckpt[d].g = g THEN ckpt[d].cur ELSE NoCur
  IN [n |-> n, g |-> g, cur |-> [s \in Streams |-> IF s \in S THEN rid ELSE prev[s]],
      ctlOk |-> ok]

\* Without CheckpointAfterAll the checkpoint is saved at the first commit.
EarlyCkpt(d) ==
  IF CheckpointAfterAll THEN ckpt
  ELSE [ckpt EXCEPT ![d] = SaveCk(d, ob[d].n, ob[d].T,
                                  {s \in ob[d].cov : ob[d].st[s] # "none"}, ob[d].rid,
                                  CtlNow(ob[d].n, Key(d)) = [k |-> "active", g |-> ob[d].T])]

Post(d, s) ==
  LET e == ob[d]
      n == e.n
      r == e.req[s]
      out == HeadOutcome(n, s, r.ver, r.h)
  IN /\ ~e.dead /\ e.st[s] = "posted"
     /\ \/ /\ WriteHead(n, s, r.ver, r.h, e.rid, RunPKs(e, s), out)
           /\ IF out = "conflict"
              THEN /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
                   /\ selfConflict' = (selfConflict \/
                                       (Len(hd[n][s]) >= r.ver /\ hd[n][s][r.ver] = r.h))
                   /\ UNCHANGED <<ckpt, acked, rcpt, needsFull>>
              ELSE /\ ob' = [ob EXCEPT ![d].st[s] = "done", ![d].g[s] = 0,
                                        ![d].req[s] = NoReq, ![d].seen[s] = r.ver]
                   /\ acked' = acked \cup {<<n, s, r.ver, r.h>>}
                   /\ rcpt' = IF s \in e.seeding THEN rcpt \cup {<<n, s>>} ELSE rcpt
                   \* afterCommit (v2 3.0): clear needsFull only after a
                   \* complete head of a covered, stream-full stream
                   /\ needsFull' = IF r.h.complete /\ s \in PubCov(e) /\ FullS(e, s)
                                   THEN [needsFull EXCEPT ![d] = @ \ {<<n, s>>}]
                                   ELSE needsFull
                   /\ ckpt' = EarlyCkpt(d)
                   /\ UNCHANGED selfConflict
           /\ UNCHANGED <<inflight, cnt>>
        \/ /\ cnt.lost < MaxLost
           /\ inflight' = inflight \cup {[kind |-> "head", n |-> n, s |-> s, ver |-> r.ver,
                                         h |-> r.h, rid |-> e.rid, pks |-> RunPKs(e, s)]}
           /\ cnt' = [cnt EXCEPT !.lost = @ + 1]
           /\ UNCHANGED <<hd, commits, inserted, lateOld, failed, ob, ckpt, acked, rcpt, needsFull,
                          selfConflict>>
  /\ UNCHANGED <<ctl, store, login, listing, known, stopped,
                 view, psv, seedTarget, clock, admitted, left, fin, quiet>>

LateApply ==
  \E x \in inflight :
    /\ inflight' = inflight \ {x}
    /\ IF x.kind = "ctl"
       THEN /\ ctl' = IF CtlOutcome(x.n, x.ver, x.row) = "insert"
                      THEN [ctl EXCEPT ![x.n] = Append(@, x.row)] ELSE ctl
            /\ UNCHANGED <<hd, commits, inserted, lateOld, failed>>
       ELSE /\ WriteHead(x.n, x.s, x.ver, x.h, x.rid, x.pks, HeadOutcome(x.n, x.s, x.ver, x.h))
            /\ UNCHANGED ctl
    /\ UNCHANGED <<store, login, listing, known, stopped, needsFull,
                   ckpt, ob, view, psv, seedTarget, rcpt, clock, admitted, left, fin, acked,
                   selfConflict, quiet, cnt>>

\* end{succeeded|partial}: every planned stream committed, no-op or
\* skipped.  Re-read control; save the covered streams' cursors (the
\* candidate holds covered streams only, v2 3.6), tagged (n, T), only if
\* control is active(T), no stream was published complete:false, and the
\* Desktop's seed receipts are all there (2.4, 2.9).  An empty candidate
\* saves nothing.
Finish(d) ==
  LET e == ob[d]
      ctlOk == CtlNow(e.n, Key(d)) = [k |-> "active", g |-> e.T]
      rcptOk == (d = Desktop /\ e.n = seedTarget) => \A s \in Streams : <<e.n, s>> \in rcpt
      save == CheckpointAfterAll /\ ctlOk /\ ~e.incomp /\ rcptOk /\ e.cov # {}
  IN /\ e # NoEntry /\ ~e.dead /\ e.out = "ok"
     /\ \A s \in Streams : e.st[s] \in {"none", "done"}
     /\ ob' = [ob EXCEPT ![d] = NoEntry]
     /\ ckpt' = IF save THEN [ckpt EXCEPT ![d] = SaveCk(d, e.n, e.T, e.cov, e.rid, ctlOk)]
                ELSE ckpt
     /\ fin' = [fin EXCEPT ![d] = [n |-> e.n, T |-> e.T, seen |-> e.seen, cov |-> e.cov]]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, acked, selfConflict, quiet, cnt>>

\* end{retry_pending} (v2 3.6, saveCheckpointOnly): the same admission as
\* a normal end, then a checkpoint-only save; nothing is declared or
\* published and the spool is discarded.  The admission is the table of
\* 2.4 on (start, control): a target generation t > 0 with control
\* active(t) saves; keep pending waits; any other row discards the run
\* (and, as Decide does, clears the checkpoint when the start was active).
\* A connection with no control row yet (create) saves nothing (the hand-
\* back lists this as an open point).  With RetryQuietOnly the candidate
\* keeps only streams that have no records in the discarded spool; without
\* it (control: v2 2.3 as written) every candidate cursor is saved.
RetryPending(d) ==
  LET e == ob[d]
      t == EffTable(d, e)
      S == EffStart(d, e)
      ctlOk == t > 0 /\ CtlNow(e.n, Key(d)) = [k |-> "active", g |-> t]
      keep == IF RetryQuietOnly THEN e.cand \ e.emit ELSE e.cand
      save == ctlOk /\ keep # {}
  IN /\ e # NoEntry /\ ~e.dead /\ e.out = "retry"
     /\ t # -1
     /\ ob' = [ob EXCEPT ![d] = NoEntry]
     /\ ckpt' = IF save THEN [ckpt EXCEPT ![d] = SaveCk(d, e.n, t, keep, e.rid, TRUE)]
                ELSE IF t = 0 /\ ClearOnGenChange /\ S.k = "active" /\ ckpt[d].n = e.n
                THEN [ckpt EXCEPT ![d] = NoCk]
                ELSE ckpt
     /\ quiet' = IF save THEN quiet \cup {<<e.rid, s>> : s \in keep \ e.emit} ELSE quiet
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, cnt>>

\* end{failed|cancelled} or abort (v2 3.7, abortRun): the entry is
\* removed; no head, no checkpoint.
Abort(d) ==
  /\ ob[d] # NoEntry /\ ~ob[d].dead /\ ob[d].out = "abort"
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known, stopped, needsFull, ckpt,
                 view, psv, inflight, seedTarget, rcpt, clock, commits, admitted, inserted,
                 lateOld, left, fin, acked, selfConflict, quiet, cnt>>

Progress(d) ==
  \/ \E s \in Streams : Decide(d, s) \/ CtlPost(d, s) \/ PlanStale(d, s) \/ PlanPublish(d, s)
     \/ Post(d, s)
  \/ Finish(d) \/ RetryPending(d) \/ Abort(d)

----------------------------------------------------------------------------
\* Run start (2.4, 2.12) through end (run intake v2).  The collection is
\* atomic here: the run's outcome, covered streams, spool and candidate
\* are chosen at once, and the end's effects follow in Progress.
\*
\* begin (v2 2.1, R16): the run is full when the writer forces it
\* (runMustBeFull: no checkpoint, or any needsFull of the connector) or
\* the owner started it with a full_refresh profile (wantFull; only an
\* explicit connect, uc, is owner-started here).  The writer issues the
\* START state: none when it forces the run full, else the stored
\* checkpoint, also for an owner-started full run.  `full` comes from the
\* issued mode, never from the state.  Without WriterIssuesStart
\* (control) the producer puts any state it holds into START.  An issued
\* state of another namespace makes the run's heads complete:false (sw).
\*
\* A scheduled run does not start while stopped; an explicit connect
\* clears stopped.  The Desktop's first identified run fixes seedTarget.
\*
\* end: out "ok" (succeeded or partial) publishes the covered streams cov;
\* "retry" (retry_pending) saves the candidate cand only; "abort" removes
\* the entry.  E: the streams with records in the spool; P: the keys
\* collected.  A covered stream may have no records (a confirmed-empty
\* stream); a stream with records may be uncovered (its spool is
\* dropped).  A key the run does not emit is a record the source no
\* longer has, or one outside the increment.  allCov (the scheduler's
\* rerun) covers every stream: the fairness "a covered full run of s
\* eventually happens" of L3.
Outs == {"ok", "retry", "abort"}

StartRunFor(d, a, uc, out, allCov) ==
  LET n == NSOf(a)
      forced == ckpt[d] = NoCk \/ (NeedsFullForcesFull /\ needsFull[d] # {})
      iss == IF forced THEN NoCk ELSE ckpt[d]
      rid == clock + 1
      tgt == IF d = Desktop /\ seedTarget = "none" THEN n ELSE seedTarget
      seedS == IF d = Desktop /\ n = tgt THEN {s \in Streams : <<n, s>> \notin rcpt} ELSE {}
  IN /\ d \notin left /\ ob[d] = NoEntry
     /\ uc \/ stopped[d][n] = 0
     \* Choices with identical futures are made canonical: wantFull on a
     \* run the writer already forces full; records of a stream whose
     \* spool is dropped unread (an uncovered stream of an "ok" run, a
     \* stream outside a retry candidate); keys of an empty spool.
     /\ \E wf \in IF uc /\ out = "ok" /\ ~forced THEN BOOLEAN ELSE {FALSE},
           st \in IF WriterIssuesStart THEN {iss} ELSE {NoCk, ckpt[d]},
           E \in SUBSET Streams, P \in (SUBSET PK) \ {{}},
           cov \in SUBSET Streams, cand \in SUBSET Streams :
          /\ E = {} => P = PK
          /\ out # "ok" => cov = {} /\ P = PK
          /\ out # "retry" => cand = {}
          /\ out = "ok" /\ PublishCoveredOnly => E \subseteq cov
          /\ out = "retry" /\ RetryQuietOnly => E \subseteq cand
          /\ out = "abort" => E = {}
          /\ allCov => E = Streams /\ cov = Streams
          /\ LET e == [NoEntry EXCEPT
                      !.rid = rid, !.a = a, !.n = n, !.start = listing[d], !.uc = uc,
                      !.full = forced \/ wf, !.sw = (st # NoCk /\ st.n # n),
                      !.stOk = (st = iss), !.pks = P, !.emit = E,
                      !.cov = cov, !.cand = cand, !.out = out]
                 planned == IF out = "ok" THEN PubCov(e) \cup seedS ELSE {}
             IN /\ ob' = [ob EXCEPT ![d] = [e EXCEPT
                            !.st = [s \in Streams |-> IF s \in planned THEN "planned" ELSE "none"]]]
     /\ login' = [login EXCEPT ![d] = a]
     /\ stopped' = IF uc THEN [stopped EXCEPT ![d][n] = 0] ELSE stopped
     /\ seedTarget' = tgt
     /\ clock' = rid
  /\ UNCHANGED <<ctl, hd, failed, store, listing, known, needsFull,
                 ckpt, view, psv, inflight, rcpt, commits, admitted, inserted, lateOld, left, fin, acked,
                 selfConflict, quiet>>

StartRun(d, a, uc) ==
  /\ cnt.runs < MaxRuns
  /\ \E out \in Outs :
       /\ out = "retry" => cnt.retries < MaxRetry
       /\ out = "abort" => cnt.aborts < MaxAbort
       /\ StartRunFor(d, a, uc, out, FALSE)
       /\ cnt' = [cnt EXCEPT !.runs = @ + 1,
                             !.retries = @ + (IF out = "retry" THEN 1 ELSE 0),
                             !.aborts = @ + (IF out = "abort" THEN 1 ELSE 0)]

\* The scheduler's next run for an account with an incomplete live head
\* (liveness configs only: MaxReruns > 0).  It covers every stream.
Rerun(d, a) ==
  /\ cnt.reruns < MaxReruns
  /\ listing[d] # Null
  /\ \E s \in Streams : Live(NSOf(a), s) /\ ~Latest(NSOf(a), s).complete
  /\ StartRunFor(d, a, FALSE, "ok", TRUE)
  /\ cnt' = [cnt EXCEPT !.reruns = @ + 1]

\* Registry listing and sync-loop observation (2.4).  Any new control
\* version for n is a generation change: clear checkpoints and pending
\* entries for n.  A device stops on a tombstone of its login's n and
\* resumes on a newer active row.
StopNext(d, n) ==
  LET st == CtlNow(n, Key(d)) IN
  IF st.k = "deleted" /\ n = NSOf(login[d]) /\ stopped[d][n] = 0 THEN st.g
  ELSE IF stopped[d][n] > 0 /\ st.k \in {"active", "foreign"} /\ st.g > stopped[d][n] THEN 0
  ELSE stopped[d][n]

List(d) ==
  LET lens == [n \in NS |-> CtlLen(n)]
      clear(n) == ClearOnGenChange /\ known[d][n] > 0 /\ lens[n] > known[d][n]
  IN /\ d \notin left
     /\ listing[d] # lens \/ known[d] # lens \/ \E n \in NS : StopNext(d, n) # stopped[d][n]
     /\ listing' = [listing EXCEPT ![d] = lens]
     /\ known' = [known EXCEPT ![d] = lens]
     /\ ckpt' = IF ckpt[d] # NoCk /\ clear(ckpt[d].n) THEN [ckpt EXCEPT ![d] = NoCk] ELSE ckpt
     /\ ob' = IF ob[d] # NoEntry /\ clear(ob[d].n) THEN [ob EXCEPT ![d] = NoEntry] ELSE ob
     /\ stopped' = [stopped EXCEPT ![d] = [n \in NS |-> StopNext(d, n)]]
  /\ UNCHANGED <<ctl, hd, failed, store, login, needsFull, view,
                 psv, inflight, seedTarget, rcpt, clock, commits, admitted, inserted, lateOld, left, fin, acked,
                 selfConflict, quiet, cnt>>

\* App restart or crash: no listing this session; decisions in memory are
\* lost; persisted requests stay.
NewSession(d) ==
  /\ d \notin left /\ cnt.sessions < MaxSessions
  /\ listing' = [listing EXCEPT ![d] = Null]
  /\ ob' = IF ob[d] = NoEntry THEN ob
           ELSE [ob EXCEPT ![d].st = [s \in Streams |->
                   IF ob[d].st[s] \in {"decided", "creating", "reconnecting"} THEN "planned"
                   ELSE ob[d].st[s]]]
  /\ cnt' = [cnt EXCEPT !.sessions = @ + 1]
  /\ UNCHANGED <<ctl, hd, failed, store, login, known, stopped,
                 needsFull, ckpt, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet>>

\* A permanent failure of the entry: it stays, never publishes, and its
\* local rows stay a read-time overlay (2.9).
FailEntry(d) ==
  /\ cnt.fails < MaxFail /\ ob[d] # NoEntry /\ ~ob[d].dead
  /\ ob' = [ob EXCEPT ![d].dead = TRUE]
  /\ cnt' = [cnt EXCEPT !.fails = @ + 1]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, ckpt, view, psv, inflight, seedTarget, rcpt, clock,
                 commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet>>

\* Import (2.9): one pass of the sync loop.  Every stream's local rows
\* become the live verified head (own key), or are purged.  Without
\* ImportPastPending a pending or failed entry blocks its stream.  `view`
\* is read by no other action, so profiles whose properties do not read it
\* set Views = FALSE and skip this action.
Want(d, n, s) == IF Live(n, s) /\ Latest(n, s).key = Key(d) THEN Len(hd[n][s]) ELSE 0
Pending(d, n, s) == ob[d] # NoEntry /\ ob[d].n = n /\ ob[d].st[s] \notin {"none", "done"}
Blocked(d, n, s) == ~ImportPastPending /\ Pending(d, n, s)
Import(d) ==
  /\ Views /\ d \notin left
  /\ \E n \in NS, s \in Streams : view[d][n][s] # Want(d, n, s) /\ ~Blocked(d, n, s)
  /\ view' = [view EXCEPT ![d] = [n \in NS |-> [s \in Streams |->
                 IF Blocked(d, n, s) THEN view[d][n][s] ELSE Want(d, n, s)]]]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, ckpt, ob, psv, inflight, seedTarget, rcpt, clock,
                 commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, cnt>>

\* Delete the connector (2.11): tombstone every active control row of c,
\* foreign ones too; purge local rows, entries and the checkpoint; stop.
\* (The legacy delete loop is not modelled: reads are checked against
\* every legacy file, deleted or not.)
UserDelete(d) ==
  LET on == {n \in NS : ActiveAny(n)} IN
  /\ d \notin left /\ cnt.deletes < MaxDeletes /\ on # {}
  /\ ctl' = [n \in NS |-> IF n \in on THEN Append(ctl[n], [k |-> "T", key |-> ""]) ELSE ctl[n]]
  /\ view' = [view EXCEPT ![d] = [n \in NS |-> [s \in Streams |-> 0]]]
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ ckpt' = [ckpt EXCEPT ![d] = NoCk]
  /\ stopped' = [stopped EXCEPT ![d] = [n \in NS |-> IF n \in on THEN CtlLen(n) + 1 ELSE stopped[d][n]]]
  /\ known' = [known EXCEPT ![d] = [n \in NS |-> IF n \in on THEN CtlLen(n) + 1 ELSE known[d][n]]]
  /\ cnt' = [cnt EXCEPT !.deletes = @ + 1]
  /\ UNCHANGED <<hd, failed, store, login, listing, needsFull, psv, inflight,
                 seedTarget, rcpt, clock, commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet>>

\* A device stops forever (uninstall, cleared browser storage): its
\* outbox entry, needsFull and checkpoint are gone.
Leave(d) ==
  /\ d \notin left /\ cnt.leaves < MaxLeave
  /\ left' = left \cup {d}
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ needsFull' = [needsFull EXCEPT ![d] = {}]
  /\ ckpt' = [ckpt EXCEPT ![d] = NoCk]
  /\ view' = [view EXCEPT ![d] = [n \in NS |-> [s \in Streams |-> 0]]]
  /\ fin' = [fin EXCEPT ![d] = NoFin]
  /\ cnt' = [cnt EXCEPT !.leaves = @ + 1]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known, stopped,
                 psv, inflight, seedTarget, rcpt, clock, commits, admitted, inserted,
                 lateOld, acked, selfConflict, quiet>>

\* Limitation L11: an old app's non-exclusive DELETE writes a tombstone at
\* the next stream version; earlier versions stay.
OldDelete(n, s) ==
  /\ cnt.olddel < MaxOldDelete
  /\ hd[n][s] # <<>> /\ ~IsTomb(Latest(n, s))
  /\ hd' = [hd EXCEPT ![n][s] = Append(@, TombHead)]
  /\ cnt' = [cnt EXCEPT !.olddel = @ + 1]
  /\ UNCHANGED <<ctl, failed, store, login, listing, known, stopped,
                 needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet>>

\* Best-effort cleanup (2.11): the objects of every head of generation
\* <= a deleted D, all streams of n in one step.
Cleanup(n, D) ==
  /\ D \in DeletedGens(n)
  /\ LET old(s) == {i \in 1..Len(hd[n][s]) : hd[n][s][i].g <= D}
         gone == UNION {UNION {Objects(n, s, hd[n][s][i]) : i \in old(s)} : s \in Streams}
     IN /\ store \cap gone # {}
        /\ store' = store \ gone
  /\ UNCHANGED <<ctl, hd, failed, login, listing, known, stopped,
                 needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, cnt>>

SettleFail(n, s, i) ==
  /\ cnt.settle < MaxSettleFail
  /\ i \in 1..Len(hd[n][s]) /\ <<n, s, i>> \notin failed
  /\ failed' = failed \cup {<<n, s, i>>}
  /\ cnt' = [cnt EXCEPT !.settle = @ + 1]
  /\ UNCHANGED <<ctl, hd, store, login, listing, known, stopped,
                 needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet>>

Lens == [n \in NS |-> [c |-> CtlLen(n), h |-> [s \in Streams |-> Len(hd[n][s])]]]
PsSync(p) ==
  /\ psv[p] # Lens
  /\ psv' = [psv EXCEPT ![p] = Lens]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, ckpt, ob, view, inflight, seedTarget, rcpt, clock,
                 commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, cnt>>

----------------------------------------------------------------------------
Init ==
  /\ ctl = [n \in NS |-> <<>>]
  /\ hd = [n \in NS |-> [s \in Streams |-> <<>>]]
  /\ failed = {}
  /\ store = {}
  /\ login \in [Devices -> Acct]
  /\ listing = [d \in Devices |-> Null]
  /\ known = [d \in Devices |-> [n \in NS |-> 0]]
  /\ stopped = [d \in Devices |-> [n \in NS |-> 0]]
  /\ needsFull = [d \in Devices |-> {}]
  /\ ckpt = [d \in Devices |-> NoCk]
  /\ ob = [d \in Devices |-> NoEntry]
  /\ view = [d \in Devices |-> [n \in NS |-> [s \in Streams |-> 0]]]
  /\ psv = [p \in Readers |-> [n \in NS |-> [c |-> 0, h |-> [s \in Streams |-> 0]]]]
  /\ inflight = {}
  /\ seedTarget = "none"
  /\ rcpt = {}
  /\ clock = 0
  /\ commits = {}
  /\ admitted = {}
  /\ inserted = {}
  /\ lateOld = FALSE
  /\ left = {}
  /\ fin = [d \in Devices |-> NoFin]
  /\ acked = {}
  /\ selfConflict = FALSE
  /\ quiet = {}
  /\ cnt = [runs |-> 0, reruns |-> 0, deletes |-> 0, lost |-> 0, sessions |-> 0,
            settle |-> 0, fails |-> 0, leaves |-> 0, olddel |-> 0, retries |-> 0, aborts |-> 0]

Next ==
  \/ \E d \in Devices, a \in Acct, uc \in BOOLEAN : StartRun(d, a, uc)
  \/ \E d \in Devices, a \in Acct : Rerun(d, a)
  \/ \E d \in Devices : Progress(d) \/ List(d) \/ NewSession(d) \/ FailEntry(d)
  \/ LateApply
  \/ \E d \in Devices : Import(d)
  \/ \E d \in Devices : UserDelete(d)
  \/ \E d \in Devices : Leave(d)
  \/ \E n \in NS, s \in Streams : OldDelete(n, s)
  \/ \E n \in NS, D \in 1..MaxVer : Cleanup(n, D)
  \/ \E n \in NS, s \in Streams, i \in 1..MaxVer : SettleFail(n, s, i)
  \/ \E p \in Readers : PsSync(p)

Fairness ==
  /\ \A d \in Devices : WF_vars(Progress(d)) /\ WF_vars(List(d))
  /\ \A d \in Devices, a \in Acct : WF_vars(Rerun(d, a))
  /\ \A d \in Devices : WF_vars(Import(d))
  /\ \A p \in Readers : WF_vars(PsSync(p))
  /\ WF_vars(LateApply)

Spec == Init /\ [][Next]_vars /\ Fairness

\* Symmetry on accounts, record keys and the streams other than LegacyFrom,
\* within and outside FullStreams (safety configs only).
Symmetry == Permutations(Acct) \cup Permutations(PK)
            \cup Permutations(Streams \ ({LegacyFrom} \cup FullStreams))
            \cup Permutations(FullStreams \ {LegacyFrom})

\* Bounds every chain (safety configs only).
VerBound == \A n \in NS : CtlLen(n) <= MaxVer /\ \A s \in Streams : Len(hd[n][s]) <= MaxVer

----------------------------------------------------------------------------
\* Reads (2.10) through a registry snapshot v: a reader PS's last synced
\* view psv[p], or the current registry.  Rows are append-only in the
\* design, so a snapshot is a past registry state; checking the read on
\* every reachable current state covers every snapshot a reader can hold,
\* with the legacy file's state at read time (README.md, "Readers").
\* Profiles with Readers = {} check reads on the current state only.
Snaps == {psv[p] : p \in Readers} \cup {Lens}
StP(v, n) == StateAt(n, v[n].c, ReaderKey)
HeadP(v, n, s) == IF v[n].h[s] = 0 THEN NoHead ELSE hd[n][s][v[n].h[s]]
LiveP(v, n, s) == StP(v, n).k = "active" /\ v[n].h[s] > 0 /\ HeadP(v, n, s).g = StP(v, n).g
LiveNS(v) == {n \in NS : \E s \in Streams : LiveP(v, n, s)}
Stamp(v, n) == SetMax({HeadP(v, n, s).at : s \in {t \in Streams : LiveP(v, n, t)}})
Sel(v) == IF LiveNS(v) = {} THEN "none"
          ELSE CHOOSE n \in LiveNS(v) : \A m \in LiveNS(v) : Stamp(v, m) <= Stamp(v, n)
Names == {"legacy"} \cup Streams
Needs(name) == IF name = "legacy" THEN {LegacyFrom} ELSE {name}
\* An old install may write the legacy file for any account at any time,
\* after a delete or after cutover, so every read is checked against
\* every legacy file: none, or one account's, written long ago (at 0) or
\* just now (newer than every head).
Legacies == {NoFile} \cup {[FileOf(a, "legacy", "none") EXCEPT !.at = t] : a \in Acct, t \in {0, clock + 1}}
\* The old raw file pdpp.c.<LegacyFrom> stays readable under the stream's
\* own name (the raw seed is gone, v2 3.12).  An old install may write it
\* at any time too, so it ranges over Legacies like the legacy file.
File(L, name) == IF name \in {"legacy", LegacyFrom} THEN L ELSE NoFile
ViewOKn(v, n, name) == \A s \in Needs(name) : LiveP(v, n, s) /\ HeadP(v, n, s).complete
AnyDeletedP(v) == \E n \in NS : StP(v, n).k = "deleted"
Unavailable == <<"unavailable", {}>>
\* The part of a read that does not depend on the legacy file, computed
\* once per snapshot and name (TLC does not cache operator calls).
RV(v, name) ==
  LET sel == Sel(v)
      selOK == sel # "none" /\ ViewOKn(v, sel, name)
      ns == IF OneConnectionRead THEN IF selOK THEN {sel} ELSE {}
            ELSE {n \in NS : ViewOKn(v, n, name)}
  IN [ns |-> ns, selOK |-> selOK,
      selLive |-> sel # "none" /\ \A s \in Needs(name) : LiveP(v, sel, s),
      lines |-> UNION {HeadP(v, n, s).lines : n \in ns, s \in Needs(name)},
      at |-> SetMax({HeadP(v, n, s).at : n \in ns, s \in Needs(name)}),
      del |-> AnyDeletedP(v)]
\* A read with view part r and legacy file F.
ReadR(r, F) ==
  IF r.ns # {} /\ (OneWay \/ ~F.present \/ F.at <= r.at)
  THEN <<"view", r.lines>>
  ELSE IF LegacyHonoursDelete /\ r.del THEN Unavailable
  ELSE IF F.present THEN <<"legacy", F.lines>>
  ELSE Unavailable
ReadinessR(r, F) ==
  IF ReadinessSame THEN ReadR(r, F) # Unavailable
  ELSE \/ r.selLive
       \/ ~(LegacyHonoursDelete /\ r.del) /\ F.present

----------------------------------------------------------------------------
\* Safety properties (README.md gives the reading of each).
AcctLine(l) == l[4] \in {"run", "legacy"}

\* An L11 tombstone above version v (an accepted limitation).
TombAfter(n, s, v) == \E i \in v + 1..Len(hd[n][s]) : IsTomb(hd[n][s][i])

\* S1 against the current stream row: while control is active(g), every
\* acknowledged head of generation g is covered by the current row, which
\* is a head of generation g holding each of its lines or a greater one.
S1_NoLostCommit ==
  \A x \in acked :
    LET n == x[1]  s == x[2]  v == x[3]  h == x[4] IN
    (CurGen(n) = h.g /\ ~TombAfter(n, s, v)) =>
      /\ Latest(n, s).g = h.g
      /\ \A l \in h.lines : \E m \in Latest(n, s).lines : m[1] = l[1] /\ Rank(m) >= Rank(l)

S2a_DeleteHolds ==
  \A v \in Snaps, name \in Names :
    LET r == RV(v, name) IN
    \A L \in Legacies, n \in NS :
      StP(v, n).k = "deleted" => \A l \in ReadR(r, File(L, name))[2] : AcctLine(l) => NSOf(l[3]) # n

S3_CleanGeneration ==
  \A n \in NS, s \in Streams : \A i \in 1..Len(hd[n][s]) :
    \A l \in hd[n][s][i].lines :
      /\ l[4] = "run" => <<l[2], hd[n][s][i].g>> \in admitted
      /\ l[4] = "seed" => hd[n][s][i].g = 1

S4_NoAccountMix ==
  ~IdLess =>
    /\ \A n \in NS, s \in Streams : \A i \in 1..Len(hd[n][s]) :
         \A l \in hd[n][s][i].lines : l[4] = "run" => l[3] = n
    /\ \A v \in Snaps, name \in Names :
         LET r == RV(v, name) IN
         \A L \in Legacies :
           LET x == ReadR(r, File(L, name)) IN
           x[1] = "view" =>
             Cardinality({l[3] : l \in {m \in x[2] : m[4] = "run"}}) <= 1

S5_CleanupSafety ==
  \A n \in NS, s \in Streams : Live(n, s) => Objects(n, s, Latest(n, s)) \subseteq store

S6_ExactOnce ==
  /\ \A x, y \in inserted : x[1] = y[1] /\ x[2] = y[2] /\ x[3] = y[3] => x = y
  /\ ~selfConflict

\* S7 per stream (v2 3.6 merges cursors of several runs): a saved cursor
\* for s comes from a run that committed s at the checkpoint's generation,
\* or from a retry_pending run that had no records for s.  So a cursor
\* never passes records that were collected and then dropped.
S7_CheckpointSafety ==
  \A d \in Devices :
    ckpt[d] # NoCk =>
      /\ ckpt[d].ctlOk
      /\ \A s \in Streams : ckpt[d].cur[s] # 0 =>
           \/ \E c \in commits : c[1] = ckpt[d].n /\ c[2] = s /\ c[3] = ckpt[d].g
                                /\ c[4] = ckpt[d].cur[s]
           \/ <<ckpt[d].cur[s], s>> \in quiet

S8_AckImmutable ==
  \A x \in acked : Len(hd[x[1]][x[2]]) >= x[3] /\ hd[x[1]][x[2]][x[3]] = x[4]

S9_OneWay ==
  \A v \in Snaps, name \in Names :
    LET r == RV(v, name) IN
    \A L \in Legacies : ReadR(r, File(L, name))[1] = "legacy" => ~r.selOK

S10_ReadinessMatchesRead ==
  \A v \in Snaps, name \in Names :
    LET r == RV(v, name) IN
    \A L \in Legacies : ReadinessR(r, File(L, name)) <=> ReadR(r, File(L, name)) # Unavailable

S11_SeedCoverage ==
  \A x \in rcpt :
    (CurGen(x[1]) = 1 /\ ~TombAfter(x[1], x[2], 0)) =>
      (Live(x[1], x[2]) /\ PK \subseteq PKsOf(Latest(x[1], x[2]).lines))

S12_KeyIsolation ==
  /\ \A n \in NS, s \in Streams : \A i \in 1..Len(hd[n][s]) :
       LET h == hd[n][s][i] IN
       (h.g > 0 /\ h.g <= CtlLen(n) /\ ctl[n][h.g].k = "A") => h.key = ctl[n][h.g].key
  /\ \A d \in Devices, n \in NS, s \in Streams :
       view[d][n][s] > 0 => hd[n][s][view[d][n][s]].key = Key(d)

\* Head generations never exceed the control chain, so stale_generation
\* never meets a control that still reads active(T).
NoHeadAboveControl ==
  \A n \in NS, s \in Streams : \A i \in 1..Len(hd[n][s]) : hd[n][s][i].g <= CtlLen(n)

\* Along a stream row chain the generation never goes down: no head of an
\* old generation lands above a head of a newer one.
HeadGenMonotone ==
  \A n \in NS, s \in Streams : \A i, j \in 1..Len(hd[n][s]) :
    (i < j /\ ~IsTomb(hd[n][s][i]) /\ ~IsTomb(hd[n][s][j])) => hd[n][s][i].g <= hd[n][s][j].g

\* L3 and M3 as bounded safety (Q9, M3).  After a device that stays
\* finishes a run at (n, T), a stream row of a stream the run covered
\* (v2: an uncovered stream is not read or published) that is still current and
\* is live and complete:false, an L11 tombstone, or no row at all, is one
\* it holds needsFull for, so its next run is full.
IncompleteOwned ==
  \A d \in Devices \ left :
    (ob[d] = NoEntry /\ fin[d].n # "none") =>
      \A s \in fin[d].cov :
        LET n == fin[d].n  v == fin[d].seen[s] IN
        (/\ Len(hd[n][s]) = v /\ CurGen(n) = fin[d].T
         /\ \/ v > 0 /\ Live(n, s) /\ ~Latest(n, s).complete
            \/ v = 0
            \/ v > 0 /\ IsTomb(hd[n][s][v])) => <<n, s>> \in needsFull[d]

\* A run for a connection the device holds needsFull for is full.  The
\* package's rule (any needsFull of the connector) is stronger.  A run that
\* published complete:false itself (incomp) may hold needsFull it added.
NeedsFullRunIsFull ==
  \A d \in Devices :
    LET e == ob[d] IN
    (e # NoEntry /\ ~e.full /\ ~e.incomp) =>
      \A s \in Streams : <<e.n, s>> \notin needsFull[d]

\* The registry_inconsistent row of the table never applies.
NeverInconsistent ==
  \A d \in Devices : (ob[d] # NoEntry /\ ob[d].start # Null) =>
    LET S == StartState(d, ob[d])  C == CtlNow(ob[d].n, Key(d)) IN
    ~(S.k = "active" /\ (C.k = "absent" \/ (C.k = "active" /\ C.g < S.g)))

TypeOK ==
  /\ \A d \in Devices : \A s \in Streams :
       ob[d].st[s] \in {"none", "planned", "creating", "reconnecting", "decided", "posted", "done"}
  /\ \A d \in Devices : ob[d].out \in Outs
  /\ \A n \in NS : \A i \in 1..CtlLen(n) : ctl[n][i].k \in {"A", "T"}

\* Run intake v2 (3.5): no head is committed for a stream the run did not
\* cover.  The only exception is the Desktop seed (2.9), which is not a
\* run output.
CoveredOnly == \A x \in inserted : ~x[4].oc

\* Run intake v2 (2.1, R16): the START state the connector used is the
\* writer's issue: the stored checkpoint, or none when the writer forced
\* the run full.
IssuedStart == \A d \in Devices : ob[d] # NoEntry => ob[d].stOk

\* The row a head was written over: the row just below it, when it has the
\* head's generation (an older generation or an L11 tombstone is an empty
\* base, 2.7).
BaseOf(x) ==
  LET n == x[1]  s == x[2]  v == x[3]  g == x[4].g IN
  IF v > 1 /\ hd[n][s][v - 1].g = g /\ ~IsTomb(hd[n][s][v - 1]) THEN hd[n][s][v - 1] ELSE NoHead

\* A run never removes a key from its base: no deletion, by owner decision
\* (no tombstones, no absence deletion).  This covers incremental,
\* stream-full, uncovered and seed-only publishes.
NoFalseDelete == \A x \in inserted : PKsOf(BaseOf(x).lines) \subseteq PKsOf(x[4].lines)

\* A base line written by a later run (a greater (o, r)) is still the
\* line for its key after an earlier run publishes over it.
LaterWriteSurvives ==
  \A x \in inserted : \A l \in BaseOf(x).lines : l[2] > x[4].at => l \in x[4].lines

\* Control 18: deletion is not immediate (limitation 8); this must fail.
S2_Immediate ==
  \A v \in Snaps, name \in Names :
    LET r == RV(v, name) IN
    \A L \in Legacies, n \in NS :
      Deleted(n) => \A l \in ReadR(r, File(L, name))[2] : AcctLine(l) => NSOf(l[3]) # n

----------------------------------------------------------------------------
\* Liveness.
CleanFor(n) ==
  \A v \in Snaps, name \in Names :
    LET r == RV(v, name) IN
    \A L \in Legacies : \A l \in ReadR(r, File(L, name))[2] : AcctLine(l) => NSOf(l[3]) # n
L1_EventualDelete == \A n \in NS : Deleted(n) ~> (~Deleted(n) \/ CleanFor(n))

Converged == \A d \in Devices \ left, n \in NS, s \in Streams : view[d][n][s] = Want(d, n, s)
L2_Convergence == <>[]Converged

L3_NoStuckIncomplete ==
  \A n \in NS, s \in Streams, v \in 1..MaxVer :
    (Live(n, s) /\ ~Latest(n, s).complete /\ CtlLen(n) = v)
      ~> ((Live(n, s) /\ Latest(n, s).complete) \/ CtlLen(n) # v)

\* A device that stays resumes (one that leaves is exempt from then on).
L4_Resume ==
  \A d \in Devices, n \in NS :
    (d \notin left /\ stopped[d][n] > 0 /\ ActiveAny(n) /\ CtlLen(n) > stopped[d][n])
      ~> (stopped[d][n] = 0 \/ d \in left)

----------------------------------------------------------------------------
\* Scenario witnesses (section 4 "must be reachable").  Each NotX is the
\* negation of a state that shows scenario X; a witness config checks NotX
\* as an invariant, so TLC's violation trace is a run of the scenario.
\* Ordering in time uses run ids (heads).
HasSeed(h) == \E l \in h.lines : l[4] = "seed"

\* Trace A: a create was lost, landed, and was deleted; the device's resend
\* will now replay it.
NotTraceA ==
  ~\E d \in Devices, s \in Streams :
     /\ ob[d] # NoEntry /\ ob[d].st[s] = "creating" /\ Deleted(ob[d].n)
     /\ CtlLen(ob[d].n) >= 2 /\ ctl[ob[d].n][1] = CtlRow(d)

\* Trace B: a userConnect entry that started at active(g) meets a later
\* generation made by a delete and a reconnect.
NotTraceB ==
  ~\E d \in Devices :
     /\ ob[d] # NoEntry /\ ob[d].uc /\ ob[d].start # Null
     /\ StartState(d, ob[d]).k = "active"
     /\ CtlNow(ob[d].n, Key(d)).k = "active"
     /\ CtlNow(ob[d].n, Key(d)).g > StartState(d, ob[d]).g

\* A run that started at active(1) is still pending against active(5).
NotOfflineVs5 ==
  ~\E d \in Devices :
     /\ ob[d] # NoEntry /\ ob[d].start # Null
     /\ StartState(d, ob[d]) = [k |-> "active", g |-> 1]
     /\ CtlNow(ob[d].n, Key(d)) = [k |-> "active", g |-> 5]

\* A head of an old generation lands after control left that generation.
\* (Above a head of a newer generation it cannot: HeadGenMonotone.)
NotLateOldHead == ~lateOld

\* Delete and reconnect twice.
NotTwice == ~\E n \in NS : CtlLen(n) >= 5 /\ ActiveAny(n)

\* A stream's first head is in flight across a delete.
NotFirstWriteDuringDelete ==
  ~\E x \in inflight : x.kind = "head" /\ x.ver = 1 /\ hd[x.n][x.s] = <<>> /\ Deleted(x.n)

\* A phone publishes first; the Desktop seed merges into its head later.
NotPhoneFirstThenSeed ==
  ~\E n \in NS, s \in Streams : \E i, j \in 1..Len(hd[n][s]) :
     /\ i < j /\ hd[n][s][i].g = 1 /\ hd[n][s][j].g = 1
     /\ ~HasSeed(hd[n][s][i]) /\ HasSeed(hd[n][s][j])

\* The seed alone publishes a stream the Desktop run did not emit.
NotZeroEmissionSeed ==
  ~\E n \in NS, s \in Streams : \E i \in 1..Len(hd[n][s]) :
     hd[n][s][i].lines # {} /\ \A l \in hd[n][s][i].lines : l[4] = "seed"

\* A row fails settlement after its commit was acknowledged.
NotSettleAfterAck == ~\E x \in acked : <<x[1], x[2], x[3]>> \in failed

\* An incremental run after an account switch reuses the checkpoint.
NotSwitchReusedCkpt == ~\E d \in Devices : ob[d] # NoEntry /\ ob[d].sw

\* A device holds needsFull and a checkpoint at once (runMustBeFull
\* decides the next run).
NotNeedsFullWithCkpt ==
  ~\E d \in Devices : ob[d] = NoEntry /\ needsFull[d] # {} /\ ckpt[d] # NoCk

\* A permanently failed entry while newer heads arrive.
NotFailedEntryNewerHeads ==
  ~\E d \in Devices, s \in Streams :
     ob[d] # NoEntry /\ ob[d].dead /\ Latest(ob[d].n, s).at > ob[d].rid
=============================================================================
