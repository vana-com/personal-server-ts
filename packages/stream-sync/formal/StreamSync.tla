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
(*   RetryEmpty       end{retry_pending} with no record: checkpoint-only  *)
(*                    save with the same admission, and retry provenance  *)
(*   RetryEarly       control only: a retry checkpoint saved before its   *)
(*                    records are published                               *)
(*   BudgetRerun      the scheduler's next run of a budgeted connector    *)
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
  Budgeted,        \* streams of a budgeted connector: the data needs Len(Pages) pages,
                   \* one page per run, and the saved cursor is the next page
  Page1, Page2,    \* the keys of page 1 and page 2 of a budgeted stream
  MaxRetry,        \* runs that end retry_pending
  MaxAbort,        \* runs that end failed or cancelled (abortRun)
  MaxLeave,        \* devices that may leave (stop forever, local state lost)
  MaxOldDelete,    \* old non-exclusive stream DELETEs (limitation L11)
  Views,           \* model device imports (key and liveness profiles)
  PartialCover,    \* a bound, not a guard: FALSE makes every "ok" run cover every stream
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
  WriterIssuesStart, \* START state is the writer's issue, not the producer's (v2 2.1)
  FullMerges,        \* a stream-full run merges into its base; it never replaces it
  \* --- R28 (retry-pending publishes progress) guards ---
  RetryCkptAfterPublish, \* a retry checkpoint is saved after its records commit
  RetryHeadIncomplete,   \* an uncovered retry head is complete:false
  RetryMerges,           \* a retry publish merges into its base
  FullRefreshNoCursor,   \* a stream issued full_refresh has no cursor (R24)
  KeepProvOnSuccess,     \* retry provenance survives a later succeeded run
  PerStreamRetryResume,  \* an eligible retry cursor is issued under needsFull
  \* --- R30 (amendments to R28) guards ---
  RetrySeedDeferred,     \* a retry run plans no seed-only stream; its receipt is deferred (R30.1)
  RetryGuardFull,        \* retry completeness needs covered AND actually read full (R30.2)
  EffFullFact,           \* completeness and debt clearing read the mode issued per stream (R30.3)
  TwoProvStates,         \* active_attempt and history_tail are separate states (R30.4)
  WitnessAtBegin,        \* a head tombstone invalidates a continuation before START (R30.5, R29)
  WitnessAtSave,         \* ... and before the save (R30.5)
  TailEndsWhenDone,      \* history_tail ends when a covered, non-budgeted incremental read ends (R30.4 gap)
  CoveredEndsAttempt,    \* a covered incremental:false stream in the saved candidate saves no active_attempt (R30.4)
  CoveredEndsNoSave,     \* an end that saves no checkpoint still retires a covered snapshot stream's attempt (R30.4)
  CoveredEndsKept,       \* a covered incremental:false stream outside the candidate loses its kept active_attempt (R30.4)
  RetryNeedsReceipt,     \* a retry end saves a checkpoint only once the Desktop seed receipts are in (F3); FALSE waives it
  PerStreamClear,        \* an incomplete stream clears only its own checkpoint entry (R30.7)
  ReceivedCount,         \* "all empty" counts received upserts, not spooled rows (R30.8)
  Oversized,             \* a bound, not a guard: a retry run may receive oversized upserts
  SerialRuns,            \* a bound, not a guard: no run starts while another device's run is in flight
  Periodic               \* a bound, not a guard: scheduled covering reruns (snapshot liveness)

\* Desktop may be a model value outside Devices (profiles with no seeding device).
ASSUME LegacyFrom \in Streams /\ OtherKey \subseteq Devices
ASSUME FullStreams \subseteq Streams /\ Budgeted \subseteq Streams

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
  ckpt,      \* ckpt[d]: [n, g, cur, pg, prov, ctlOk] or NoCk; cur[s] is the run whose cursor
             \* is saved, pg[s] its page, prov[s] the run whose cursor carries retry provenance
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
  sib,       \* ghost (R30.7): an incomplete stream's publish cleared a sibling stream's checkpoint entry
  cnt

vars == <<ctl, hd, failed, store, login, listing, known,
          stopped, needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock,
          commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib, cnt>>

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
NoHead == [g |-> 0, lines |-> {}, complete |-> FALSE, key |-> "", at |-> 0, oc |-> FALSE,
           gr |-> FALSE, sr |-> FALSE]
NoReq == [ver |-> 0, h |-> NoHead]
NoCur == [s \in Streams |-> 0]
\* A checkpoint: cur[s] is the run whose cursor is saved, pg[s] the page it
\* names (budgeted streams), prov[s] the run whose cursor carries retry
\* provenance (R28; 0 = none), all tagged (n, g).
\* R30.4: ph[s] is the provenance state of the cursor: "n" none, "A" active_attempt
\* (an unfinished export attempt), "H" history_tail (incomplete history that
\* later incremental pages keep).  wv[s] is the history witness (stream row
\* length at save, R30.5); tw[s] (ghost) records a tombstone above the
\* run's anchor at save time.
NoPh == [s \in Streams |-> "n"]
NoTw == [s \in Streams |-> FALSE]
NoCk == [n |-> "none", g |-> 0, cur |-> NoCur, pg |-> NoCur, prov |-> NoCur,
         ph |-> NoPh, wv |-> NoCur, tw |-> NoTw, ctlOk |-> FALSE]
\* R30.7: one stream's checkpoint entry is cleared alone.
ClearS(ck, s) == [ck EXCEPT !.cur[s] = 0, !.pg[s] = 0, !.prov[s] = 0, !.ph[s] = "n",
                            !.wv[s] = 0, !.tw[s] = FALSE]
NormCk(ck) == IF \A s \in Streams : ck.cur[s] = 0 THEN NoCk ELSE ck
\* An entry.  full: the issued collection mode is full_refresh (never read
\* from the state).  sw: the issued state belongs to another namespace.
\* stOk: the START state the connector used is the writer's issue.  cov:
\* covered streams; emit: streams with records in the spool; cand: the
\* retry_pending candidate's streams; out: "ok" (succeeded or partial),
\* "retry" (retry_pending) or "abort" (failed, cancelled).  full is the
\* run-wide START mode: full_refresh when no stream is issued a state.
NoEntry == [rid |-> 0, a |-> "none", n |-> "none", start |-> Null, uc |-> FALSE,
            full |-> FALSE, sw |-> FALSE, pks |-> {}, emit |-> {}, dead |-> FALSE,
            incomp |-> FALSE, T |-> 0, cov |-> {}, cand |-> {}, out |-> "ok",
            stOk |-> TRUE,
            \* R28: iss, the host's issued state per stream (0 = none, a full
            \* read of that stream); el, streams issued from retry
            \* provenance; nf, streams with needsFull at begin; pg, the page
            \* a budgeted stream read; rs, a budgeted stream restarted from
            \* page 1 though its device has published it; early (control).
            iss |-> NoCur, el |-> {}, nf |-> {}, pg |-> NoCur, rs |-> FALSE, early |-> FALSE,
            \* R30: ovz, streams whose received upserts were all oversized
            \* (excluded, never spooled); ep, the provenance state each
            \* stream was issued from; wb, the witness anchor of each
            \* stream's continuation; rb (ghost), streams issued a cursor
            \* whose witness was already broken.
            ovz |-> {}, ep |-> NoPh, wb |-> NoCur, rb |-> {}, cb |-> {},
            st |-> [s \in Streams |-> "none"], g |-> [s \in Streams |-> 0],
            req |-> [s \in Streams |-> NoReq], seeding |-> {},
            seen |-> [s \in Streams |-> 0]]
\* cvs (ghost, round 3): the incremental:false streams an end has covered since
\* a retry end last opened an attempt for them; written by Finish from the end
\* alone, never by the save.
NoFin == [n |-> "none", T |-> 0, seen |-> [s \in Streams |-> 0], cov |-> {}, cvs |-> {}]
\* An old app's non-exclusive DELETE writes this row (limitation L11).
TombHead == [g |-> 0, lines |-> {}, complete |-> FALSE, key |-> "old", at |-> 0, oc |-> FALSE,
             gr |-> FALSE, sr |-> FALSE]
IsTomb(h) == h.key = "old"
\* An L11 tombstone above version v (an accepted limitation).
TombAfter(n, s, v) == \E i \in v + 1..Len(hd[n][s]) : IsTomb(hd[n][s][i])
\* R30.5: the history witness of a continuation saved when the stream row had v
\* versions: no tombstone (or incompatible replacement, modelled as one) above
\* it, and the row at v is not one.  v = 0 is a pre-head absence witness: it
\* holds only while the stream has never been tombstoned.
WitNow(n, s, v) == ~TombAfter(n, s, v) /\ (v = 0 \/ ~IsTomb(hd[n][s][v]))

Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b
KP == 2
PagesOf(q) == IF q = 1 THEN Page1 ELSE IF q = 2 THEN Page2 ELSE {}
AllPageKeys == Page1 \cup Page2
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
                 inserted, lateOld, left, fin, acked, selfConflict, quiet, sib, cnt>>

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
                 acked, selfConflict, quiet, sib>>

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
RunPKs(e, s) == IF s \notin e.emit THEN {} ELSE IF s \in Budgeted THEN PagesOf(e.pg[s]) ELSE e.pks

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
                 selfConflict, quiet, sib, cnt>>

\* The publish half: the row's generation is at most T.
\*
\* Run intake v2 (3.5) with R28: an succeeded or partial run declares and
\* publishes its covered streams only.  A retry_pending end that received
\* records also publishes its record-bearing uncovered streams, as merges
\* that are never complete:true.  A stream with no records and no coverage
\* gets no head.  The Desktop seed (2.9) is
\* not a run output: a Desktop run to seedTarget also plans every stream
\* that has no receipt yet, and a stream it plans only for the seed
\* publishes only if the seed merges (generation 1); otherwise the stream
\* is skipped with a "skipped" receipt.  Without PublishCoveredOnly
\* (control) every stream is published, covered or not.
\* R28: a retry_pending end that received records also publishes its
\* record-bearing uncovered streams (as merges, complete:false).
\* R30.1: the retry publication set is the covered streams plus the streams
\* with accepted upserts (an oversized upsert is received, not accepted).
PubSet(e) == IF ~PublishCoveredOnly THEN Streams
             ELSE IF e.out = "retry" THEN e.cov \cup (e.emit \ e.ovz) ELSE e.cov
\* R30.8: "all empty" is the received-upsert count, not the spooled rows.
AllEmpty(e) == IF ReceivedCount THEN e.emit = {} ELSE (e.emit \ e.ovz) = {}
\* The stream's actual coverage result (the producer's coveredStreams).
CovD(e, s) == s \in e.cov \/ ~PublishCoveredOnly \/ (e.out = "retry" /\ ~RetryHeadIncomplete)
\* "Full" per stream (R28, v2 3.0): the run's issued mode is full_refresh, the
\* stream was issued no state (a null state is a full read of it), or the
\* stream is declared incremental: false.
\* R30.3: the mode actually issued for the stream, never the declaration.
FullS(e, s) == IF EffFullFact THEN e.iss[s] = 0
               ELSE e.full \/ e.iss[s] = 0 \/ s \in FullStreams
\* A retry-progress stream: its incomplete history keeps its cursor (R28).
RP(e, s) == e.out = "retry" \/ (KeepProvOnSuccess /\ s \in e.el)
\* The streams whose cursors the run saves.
\* R30.8: a stream whose upserts were all oversized is excluded from the
\* retained set, so its cursor never passes a dropped record.
KeepSet(e) == IF e.out = "retry" THEN e.cand \ e.ovz ELSE e.cov
\* R30.4: an end that saves nothing still ends the attempt of every
\* incremental:false stream it covered (the old pair otherwise survives).
RetireCovered(ck, e) ==
  IF ~CoveredEndsNoSave \/ ck = NoCk \/ ck.n # e.n THEN ck
  ELSE [ck EXCEPT !.ph = [s \in Streams |-> IF s \in FullStreams /\ s \in e.cov THEN "n" ELSE @[s]],
                  !.prov = [s \in Streams |-> IF s \in FullStreams /\ s \in e.cov THEN 0 ELSE @[s]],
                  !.wv = [s \in Streams |-> IF s \in FullStreams /\ s \in e.cov THEN 0 ELSE @[s]],
                  !.tw = [s \in Streams |-> IF s \in FullStreams /\ s \in e.cov THEN FALSE ELSE @[s]]]
\* R30.7: clearing an incomplete stream's entry.
ClearFor(d, n, s) ==
  IF ckpt[d] # NoCk /\ ckpt[d].n = n /\ PerStreamClear
  THEN NormCk(ClearS(ckpt[d], s)) ELSE NoCk
SibLoss(d, n, s) ==
  /\ ckpt[d] # NoCk /\ ckpt[d].n = n
  /\ \E t \in Streams \ {s} :
       /\ ckpt[d].cur[t] # 0
       /\ LET c == ClearFor(d, n, s) IN c = NoCk \/ c.cur[t] = 0

PlanPublish(d, s) ==
  LET e == ob[d]
      n == e.n
      T == e.g[s]
      N == BaseVer(n, s)
      top == IF N = 0 THEN NoHead ELSE hd[n][s][N]
      base == IF top.g = T THEN top ELSE NoHead
      pub == s \in PubSet(e)
      covd == CovD(e, s)
      rp == RP(e, s)
      first == d = Desktop /\ n = seedTarget /\ <<n, s>> \notin rcpt
      seeded == /\ first /\ (T = 1 \/ ~SeedOnlyGen1)
                /\ (SeedWhateverBase \/ base = NoHead)
      seedLines == IF seeded THEN {<<p, 0, "desk", "seed">> : p \in PK} ELSE {}
      runLines == IF pub THEN {<<p, e.rid, e.a, "run">> : p \in RunPKs(e, s)} ELSE {}
      fullS == covd /\ FullS(e, s)
      \* The merge keeps every base line (2.6).  Without FullMerges
      \* (control) a stream-full run replaces the stream, as Desktop's
      \* local snapshot does today; without RetryMerges (control) a retry
      \* publish replaces it.
      kept == IF (FullMerges \/ ~fullS) /\ (RetryMerges \/ e.out # "retry")
              THEN base.lines ELSE {}
      lines == Merge(kept \cup seedLines \cup runLines)
      \* Covered is necessary, not sufficient (R28).  An uncovered retry
      \* head is never complete:true, whatever its base or mode.
      \* R30.2: on the retry path a head is complete only if covered AND
      \* actually read full (or onto a complete base); "uncovered" alone is
      \* not the guard.
      complete == ~e.sw /\ (seeded \/ (covd /\ (fullS \/ base.complete
                                              \/ (~RetryGuardFull /\ e.out = "retry"))))
      \* Ghost: what the head may honestly claim.
      grounded == seeded \/ (s \in e.cov /\ (e.iss[s] = 0 \/ base.complete))
      h == [g |-> T, lines |-> lines, complete |-> complete, key |-> Key(d),
            at |-> e.rid, oc |-> (s \notin e.cov /\ ~seeded),
            gr |-> grounded, sr |-> (seeded /\ e.out = "retry" /\ ~pub)]
      seeding == IF first THEN e.seeding \cup {s} ELSE e.seeding
      \* Q9: a no-op onto a complete:false base of generation T
      q9 == NoOpNeedsFull /\ base # NoHead /\ ~base.complete
  IN /\ ~e.dead /\ e.st[s] = "decided"
     /\ ~(StaleGenStops /\ top.g > T)
     /\ IF ~pub /\ ~seeded
        THEN \* planned for the seed only, and the seed does not apply:
             \* no head, a "skipped" receipt
             /\ ob' = [ob EXCEPT ![d].st[s] = "done", ![d].g[s] = 0,
                                 ![d].seeding = seeding, ![d].seen[s] = N]
             /\ rcpt' = IF first THEN rcpt \cup {<<n, s>>} ELSE rcpt
             /\ UNCHANGED <<store, commits, needsFull, ckpt, sib>>
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
                                 ![d].incomp = @ \/ (q9 /\ ~rp)]
             /\ commits' = commits \cup {<<n, s, T, e.rid, RunPKs(e, s)>>}
             /\ rcpt' = IF first THEN rcpt \cup {<<n, s>>} ELSE rcpt
             /\ needsFull' = IF q9 THEN [needsFull EXCEPT ![d] = @ \cup {<<n, s>>}]
                             ELSE needsFull
             /\ ckpt' = IF q9 /\ ~rp THEN [ckpt EXCEPT ![d] = ClearFor(d, n, s)] ELSE ckpt
             /\ sib' = (sib \/ (q9 /\ ~rp /\ SibLoss(d, n, s)))
             /\ UNCHANGED store
        ELSE /\ store' = store \cup Objects(n, s, h)
             /\ ob' = [ob EXCEPT ![d].st[s] = "posted", ![d].seeding = seeding,
                                 ![d].req[s] = [ver |-> N + 1, h |-> h],
                                 ![d].incomp = @ \/ (~complete /\ ~rp)]
             /\ needsFull' = IF ~complete /\ NeedsFull
                             THEN [needsFull EXCEPT ![d] = @ \cup {<<n, s>>}]
                             ELSE needsFull
             \* R28: the debt (needsFull) stays visible, but a retry-progress
             \* stream keeps its safe cursor and provenance.
             /\ ckpt' = IF ~complete /\ ~rp THEN [ckpt EXCEPT ![d] = ClearFor(d, n, s)] ELSE ckpt
             /\ sib' = (sib \/ (~complete /\ ~rp /\ SibLoss(d, n, s)))
             /\ UNCHANGED <<commits, rcpt>>
  /\ UNCHANGED <<ctl, hd, failed, login, listing, known, stopped,
                 view, psv, inflight, seedTarget, clock, admitted, inserted, lateOld, left, fin, acked,
                 selfConflict, quiet, cnt>>

\* Save cursors for the streams S of run e into d's checkpoint, tagged
\* (n, g) (v2 3.6): value = {...prev, ...candidate}, where prev is the
\* stored value when the stored (n, g) equals the run's, else empty.  R28:
\* the retry provenance of a stream is saved in the same update, as the run
\* that wrote its cursor: a retry end gives it to a stream with needsFull
\* debt, a later succeeded run keeps it (KeepProvOnSuccess) while the debt
\* remains, and a stream whose debt is gone (a covered full repair) has none.
SaveCk(d, n, g, S, e, ok) ==
  LET same == ckpt[d] # NoCk /\ ckpt[d].n = n /\ ckpt[d].g = g
      prev == IF same THEN ckpt[d] ELSE NoCk
      debt(s) == <<n, s>> \in needsFull[d]
      \* R30.4: the provenance state a stream's new cursor carries.  A retry
      \* end opens an active attempt: an incremental:false stream always, an
      \* incremental-capable stream while it holds debt.  A later succeeded
      \* run that resumed it ends the attempt of an incremental:false stream
      \* (the next begin is full/null) and turns an incremental-capable
      \* stream's into history_tail while the debt remains.  Without
      \* TwoProvStates (control) there is one bit and no attempt ever ends.
      rawPh(s) ==
        IF e.out = "retry"
        THEN (IF s \in FullStreams
              THEN (IF CoveredEndsAttempt /\ s \in e.cov THEN "n" ELSE "A")
              ELSE IF debt(s) THEN "A" ELSE "n")
        ELSE IF s \in e.el /\ KeepProvOnSuccess
             THEN (IF s \in FullStreams /\ TwoProvStates THEN "n"
                   ELSE IF debt(s) /\ (~TailEndsWhenDone \/ s \in Budgeted \/ s \notin e.cov \/ s \in FullStreams)
                        THEN "H" ELSE "n")
             ELSE "n"
      carry(s) == rawPh(s) # "n" \/ s \in e.el
      \* R30.5: a tombstone above the run's anchor (checked at save).
      broken(s) == carry(s) /\ TombAfter(n, s, e.wb[s])
      wok(s) == ~WitnessAtSave \/ ~broken(s)
      Sv == {s \in S : wok(s)}
      phv(s) == IF s \in Sv THEN rawPh(s) ELSE "n"
      \* Streams not saved by this run keep their pair while it stays eligible.
      \* R30.4: a covered incremental:false stream's attempt ends at that end,
      \* even when the stream is outside the saved candidate.
      kph(s) == IF prev.ph[s] = "n" THEN "n"
                ELSE IF CoveredEndsKept /\ s \in FullStreams /\ s \in e.cov THEN "n"
                ELSE IF debt(s) \/ s \in FullStreams THEN prev.ph[s] ELSE "n"
  IN [n |-> n, g |-> g,
      cur |-> [s \in Streams |-> IF s \in Sv THEN e.rid ELSE IF s \in S THEN 0 ELSE prev.cur[s]],
      pg |-> [s \in Streams |-> IF s \in Sv THEN e.pg[s] ELSE IF s \in S THEN 0 ELSE prev.pg[s]],
      prov |-> [s \in Streams |-> IF s \in S THEN (IF phv(s) # "n" THEN e.rid ELSE 0)
                                  ELSE (IF kph(s) # "n" THEN prev.prov[s] ELSE 0)],
      ph |-> [s \in Streams |-> IF s \in S THEN phv(s) ELSE kph(s)],
      wv |-> [s \in Streams |-> IF s \in S THEN (IF phv(s) # "n" THEN Len(hd[n][s]) ELSE 0)
                                 ELSE (IF kph(s) # "n" THEN prev.wv[s] ELSE 0)],
      tw |-> [s \in Streams |-> IF s \in S THEN (phv(s) # "n" /\ TombAfter(n, s, e.wb[s]))
                                 ELSE (kph(s) # "n" /\ prev.tw[s])],
      ctlOk |-> ok]

\* Without CheckpointAfterAll the checkpoint is saved at the first commit.
EarlyCkpt(d) ==
  IF CheckpointAfterAll THEN ckpt
  ELSE [ckpt EXCEPT ![d] = SaveCk(d, ob[d].n, ob[d].T,
                                  {s \in KeepSet(ob[d]) : ob[d].st[s] # "none"}, ob[d],
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
                   /\ needsFull' = IF r.h.complete /\ CovD(e, s) /\ FullS(e, s)
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
                 view, psv, seedTarget, clock, admitted, left, fin, quiet, sib>>

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
                   selfConflict, quiet, sib, cnt>>

\* end{succeeded|partial}, or end{retry_pending} that received records (R28):
\* every planned stream committed, no-op or skipped.  Re-read control; save
\* the retained streams' cursors (covered streams for a succeeded or partial
\* end, the candidate for a retry end), tagged (n, T), only if control is
\* active(T), no non-retry-progress stream was published complete:false, and
\* the Desktop's seed receipts are all there (2.4, 2.9).  An empty
\* retained set saves nothing.
Finish(d) ==
  LET e == ob[d]
      ctlOk == CtlNow(e.n, Key(d)) = [k |-> "active", g |-> e.T]
      rcptOk == (d = Desktop /\ e.n = seedTarget /\ (RetryNeedsReceipt \/ e.out # "retry")) => \A s \in Streams : <<e.n, s>> \in rcpt
      keep == KeepSet(e)
      save == CheckpointAfterAll /\ ctlOk /\ ~e.incomp /\ rcptOk /\ keep # {}
  IN /\ e # NoEntry /\ ~e.dead /\ (e.out = "ok" \/ (e.out = "retry" /\ ~AllEmpty(e)))
     /\ \A s \in Streams : e.st[s] \in {"none", "done"}
     /\ ob' = [ob EXCEPT ![d] = NoEntry]
     /\ ckpt' = IF save THEN [ckpt EXCEPT ![d] = SaveCk(d, e.n, e.T, keep, e, ctlOk)]
                ELSE [ckpt EXCEPT ![d] = RetireCovered(@, e)]
     /\ fin' = [fin EXCEPT ![d] = [n |-> e.n, T |-> e.T, seen |-> e.seen,
                                   cov |-> IF e.out = "retry" THEN PubSet(e) ELSE e.cov,
                                   cvs |-> (fin[d].cvs \cup (FullStreams \cap e.cov))
                                           \ (IF save /\ e.out = "retry"
                                              THEN {s \in FullStreams \cap keep : s \notin e.cov} ELSE {})]]
     /\ quiet' = IF save /\ e.out = "retry" THEN quiet \cup {<<e.rid, s>> : s \in keep \ e.emit}
                 ELSE quiet
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, acked, selfConflict, sib, cnt>>

\* end{retry_pending} with no record (R28, saveCheckpointOnly): the same
\* admission as a normal end, then a checkpoint-only save of the candidate
\* with its retry provenance; nothing is declared or published.  The
\* admission is the table of 2.4 on (start, control): a target generation
\* t > 0 with control active(t) saves; keep pending waits; any other row
\* discards the run (and, as Decide does, clears the checkpoint when the
\* start was active).  A connection with no control row yet (create) saves
\* nothing (R27: one re-export).
RetryEmpty(d) ==
  LET e == ob[d]
      t == EffTable(d, e)
      S == EffStart(d, e)
      ctlOk == t > 0 /\ CtlNow(e.n, Key(d)) = [k |-> "active", g |-> t]
      keep == e.cand
      save == ctlOk /\ keep # {}
  IN /\ e # NoEntry /\ ~e.dead /\ e.out = "retry" /\ AllEmpty(e)
     /\ t # -1
     /\ ob' = [ob EXCEPT ![d] = NoEntry]
     /\ ckpt' = IF save THEN [ckpt EXCEPT ![d] = SaveCk(d, e.n, t, keep, e, TRUE)]
                ELSE IF t = 0 /\ ClearOnGenChange /\ S.k = "active" /\ ckpt[d].n = e.n
                THEN [ckpt EXCEPT ![d] = NoCk]
                ELSE ckpt
     /\ quiet' = IF save THEN quiet \cup {<<e.rid, s>> : s \in keep \ e.emit} ELSE quiet
     \* a saved token-only retry opens an attempt for its uncovered snapshot streams
     /\ fin' = [fin EXCEPT ![d].cvs = IF save THEN @ \ (FullStreams \cap keep) ELSE @]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, acked, selfConflict, sib, cnt>>

\* Control only (RetryCkptAfterPublish = FALSE): the retry end saves its
\* candidate at intake.end, before the records are published.
RetryEarly(d) ==
  LET e == ob[d]
      t == EffTable(d, e)
      ctlOk == t > 0 /\ CtlNow(e.n, Key(d)) = [k |-> "active", g |-> t]
  IN /\ ~RetryCkptAfterPublish
     /\ e # NoEntry /\ ~e.dead /\ e.out = "retry" /\ ~AllEmpty(e) /\ ~e.early
     /\ ctlOk /\ e.cand # {}
     /\ ckpt' = [ckpt EXCEPT ![d] = SaveCk(d, e.n, t, e.cand, e, TRUE)]
     /\ ob' = [ob EXCEPT ![d].early = TRUE]
     /\ quiet' = quiet \cup {<<e.rid, s>> : s \in e.cand \ e.emit}
     /\ fin' = [fin EXCEPT ![d].cvs = @ \ (FullStreams \cap (e.cand \ e.cov))]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, acked, selfConflict, sib, cnt>>

\* end{failed|cancelled} or abort (v2 3.7, abortRun): the entry is
\* removed; no head, no checkpoint.
Abort(d) ==
  /\ ob[d] # NoEntry /\ ~ob[d].dead /\ ob[d].out = "abort"
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known, stopped, needsFull, ckpt,
                 view, psv, inflight, seedTarget, rcpt, clock, commits, admitted, inserted,
                 lateOld, left, fin, acked, selfConflict, quiet, sib, cnt>>

Progress(d) ==
  \/ \E s \in Streams : Decide(d, s) \/ CtlPost(d, s) \/ PlanStale(d, s) \/ PlanPublish(d, s)
     \/ Post(d, s)
  \/ Finish(d) \/ RetryEmpty(d) \/ RetryEarly(d) \/ Abort(d)

----------------------------------------------------------------------------
\* Run start (2.4, 2.12) through end (run intake v2).  The collection is
\* atomic here: the run's outcome, covered streams, spool and candidate
\* are chosen at once, and the end's effects follow in Progress.
\*
\* begin (v2 2.1): the run is full when the writer forces it
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
      K0 == ckpt[d]
      cur0(s) == IF K0 = NoCk THEN 0 ELSE K0.cur[s]
      \* A stream is eligible when its stored cursor carries retry
      \* provenance of the same namespace (the generation is checked at
      \* publish, as in the F2 model).
      \* R30.4/5: a stream is eligible when its stored cursor carries a
      \* provenance state of the same namespace whose history witness still
      \* holds; an incremental:false stream resumes only an active attempt.
      elig(s) == /\ K0 # NoCk /\ K0.n = n /\ K0.ph[s] # "n"
                 /\ (~WitnessAtBegin \/ WitNow(n, s, K0.wv[s]))
                 /\ (~TwoProvStates \/ s \notin FullStreams \/ K0.ph[s] = "A")
      nfd(s) == <<n, s>> \in needsFull[d]
      \* The host's issued state for stream s (R28 runPlan): explicit
      \* wantFull wins and issues nothing; a needsFull stream is issued
      \* nothing unless it holds an eligible retry cursor.  Without
      \* PerStreamRetryResume (control) any needsFull of the connector hides
      \* every cursor, as today; without NeedsFullForcesFull none does.
      issue(w, s) ==
        IF cur0(s) = 0 THEN 0
        ELSE IF w /\ FullRefreshNoCursor THEN 0
        \* R29/R30.5: a head tombstone above the continuation's witness
        \* invalidates it; the stream begins full/null.
        ELSE IF WitnessAtBegin /\ K0.ph[s] # "n" /\ ~WitNow(n, s, K0.wv[s]) THEN 0
        \* intake issues no state to an incremental:false stream, unless
        \* it continues an active attempt (R30.4)
        ELSE IF s \in FullStreams /\ ~elig(s) THEN 0
        ELSE IF ~NeedsFullForcesFull THEN cur0(s)
        ELSE IF PerStreamRetryResume
             THEN (IF nfd(s) /\ ~elig(s) THEN 0 ELSE cur0(s))
             ELSE (IF needsFull[d] # {} THEN 0 ELSE cur0(s))
      resumable == \E s \in Streams : issue(FALSE, s) # 0
      rid == clock + 1
      tgt == IF d = Desktop /\ seedTarget = "none" THEN n ELSE seedTarget
      seedS == IF d = Desktop /\ n = tgt THEN {s \in Streams : <<n, s>> \notin rcpt} ELSE {}
  IN /\ d \notin left /\ ob[d] = NoEntry
     /\ (~SerialRuns \/ \A x \in Devices : ob[x] = NoEntry)
     /\ uc \/ stopped[d][n] = 0
     \* Choices with identical futures are made canonical: wantFull on a
     \* run that resumes no cursor anyway; records of a stream whose spool
     \* is dropped unread (an uncovered stream of an "ok" run); keys of an
     \* empty spool; the covered set of an all-empty retry end.
     /\ \E wf \in IF uc /\ resumable THEN BOOLEAN ELSE {FALSE} :
        \E use \in IF WriterIssuesStart THEN {[s \in Streams |-> issue(wf, s)]}
                   ELSE {NoCur, [s \in Streams |-> cur0(s)]} :
        \E E \in SUBSET Streams, P \in (SUBSET PK) \ {{}},
           cov \in SUBSET Streams, cand \in SUBSET Streams :
        \E O \in IF Oversized /\ out = "retry" THEN SUBSET E ELSE {{}} :
          LET hi == [s \in Streams |-> issue(wf, s)]
              \* the page a budgeted stream reads: the one after its used cursor
              pgS(s) == IF s \in Budgeted
                        THEN Min(IF use[s] # 0 THEN K0.pg[s] + 1 ELSE 1, KP + 1) ELSE 0
          IN
          /\ E = {} => P = PK
          /\ out = "abort" => cov = {} /\ P = PK
          /\ out = "retry" /\ E = {} => cov = {}
          /\ out # "retry" => cand = {}
          /\ out = "ok" /\ PublishCoveredOnly => E \subseteq cov
          /\ out = "abort" => E = {}
          \* R30.8: oversized upserts are received and excluded; their stream
          \* is not covered (the client fails a session that skips one).
          /\ O \cap cov = {}
          /\ allCov => E = Streams /\ cov = Streams
          /\ out = "ok" /\ ~PartialCover => cov = Streams
          \* A budgeted stream reads its next page and emits it; before its
          \* last page the budget ends the run with a retryable skip.
          /\ \A s \in Budgeted :
               /\ out # "abort" => ((s \in E) <=> (pgS(s) <= KP))
               /\ pgS(s) < KP => out # "ok" /\ s \notin cov
               /\ out = "retry" /\ pgS(s) <= KP => s \in cand
          /\ LET e == [NoEntry EXCEPT
                      !.rid = rid, !.a = a, !.n = n, !.start = listing[d], !.uc = uc,
                      !.full = wf \/ \A s \in Streams : hi[s] = 0,
                      !.sw = (K0 # NoCk /\ K0.n # n /\ \E s \in Streams : use[s] # 0),
                      !.stOk = (use = hi), !.pks = P, !.emit = E,
                      !.cov = cov, !.cand = cand, !.out = out,
                      !.iss = hi, !.ovz = O,
                      !.el = IF wf THEN {} ELSE {s \in Streams : elig(s) /\ hi[s] # 0},
                      !.ep = [s \in Streams |-> IF ~wf /\ elig(s) /\ hi[s] # 0 THEN K0.ph[s] ELSE "n"],
                      !.wb = [s \in Streams |-> IF ~wf /\ elig(s) /\ hi[s] # 0 THEN K0.wv[s]
                                                ELSE Len(hd[n][s])],
                      !.rb = IF wf THEN {}
                             ELSE {s \in Streams : K0 # NoCk /\ K0.n = n /\ K0.ph[s] # "n" /\ hi[s] # 0
                                                   /\ ~WitNow(n, s, K0.wv[s])},
                      !.cb = IF wf THEN {}
                             ELSE {s \in FullStreams : K0 # NoCk /\ K0.n = n /\ K0.ph[s] = "A" /\ s \in fin[d].cvs /\ hi[s] # 0},
                      !.nf = {s \in Streams : nfd(s)},
                      !.pg = [s \in Streams |-> pgS(s)],
                      !.rs = \E s \in Budgeted :
                               /\ hi[s] = 0 /\ ~wf /\ Live(n, s)
                               /\ Latest(n, s).key = Key(d) /\ Latest(n, s).lines # {}]
                 \* R30.1: a retry run plans no seed-only stream (its
                 \* receipt is deferred); the seed enriches only streams
                 \* the run publishes anyway.
                 planned == IF out = "abort" \/ (out = "retry" /\ AllEmpty(e)) THEN {}
                            ELSE PubSet(e) \cup (IF out = "retry" /\ RetrySeedDeferred THEN {} ELSE seedS)
             IN /\ ob' = [ob EXCEPT ![d] = [e EXCEPT
                            !.st = [s \in Streams |-> IF s \in planned THEN "planned" ELSE "none"]]]
     /\ login' = [login EXCEPT ![d] = a]
     /\ stopped' = IF uc THEN [stopped EXCEPT ![d][n] = 0] ELSE stopped
     /\ seedTarget' = tgt
     /\ clock' = rid
  /\ UNCHANGED <<ctl, hd, failed, store, listing, known, needsFull,
                 ckpt, view, psv, inflight, rcpt, commits, admitted, inserted, lateOld, left, fin, acked,
                 selfConflict, quiet, sib>>

\* A scheduled rerun starts from a current listing (the scheduler lists, then
\* runs); a rerun on a stale listing is discarded and wastes the bounded
\* supply of reruns, which the liveness assumption takes as unbounded.
FreshListing(d) == listing[d] # Null /\ listing[d] = [n \in NS |-> CtlLen(n)]

\* The scheduler's next covering run of a connector with incremental: false
\* streams (liveness configs: Periodic).  It ends succeeded and covers every
\* stream: the assumption of L6, that the connector eventually completes the
\* attempt it keeps resuming.
SnapRerun(d, a) ==
  /\ Periodic /\ cnt.reruns < MaxReruns /\ FreshListing(d)
  /\ StartRunFor(d, a, FALSE, "ok", TRUE)
  /\ cnt' = [cnt EXCEPT !.reruns = @ + 1]

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
  /\ FreshListing(d)
  /\ \E s \in Streams : Live(NSOf(a), s) /\ ~Latest(NSOf(a), s).complete
  /\ StartRunFor(d, a, FALSE, "ok", TRUE)
  /\ cnt' = [cnt EXCEPT !.reruns = @ + 1]

\* The scheduler's next run of a budgeted connector (liveness configs): a
\* periodic run, bounded by MaxReruns, that ends succeeded or retry_pending
\* and never uses an explicit full request.  It keeps running after every
\* page is published, so a restart at page 1 is observable.
PagesPub(n, s) == Live(n, s) /\ AllPageKeys \subseteq PKsOf(Latest(n, s).lines)
BudgetRerun(d, a) ==
  /\ Budgeted # {} /\ cnt.reruns < MaxReruns /\ FreshListing(d)
  /\ \E out \in {"ok", "retry"} :
       StartRunFor(d, a, FALSE, out, FALSE) /\ cnt' = [cnt EXCEPT !.reruns = @ + 1]

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
                 selfConflict, quiet, sib, cnt>>

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
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib>>

\* A permanent failure of the entry: it stays, never publishes, and its
\* local rows stay a read-time overlay (2.9).
FailEntry(d) ==
  /\ cnt.fails < MaxFail /\ ob[d] # NoEntry /\ ~ob[d].dead
  /\ ob' = [ob EXCEPT ![d].dead = TRUE]
  /\ cnt' = [cnt EXCEPT !.fails = @ + 1]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, ckpt, view, psv, inflight, seedTarget, rcpt, clock,
                 commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib>>

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
                 commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib, cnt>>

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
                 seedTarget, rcpt, clock, commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib>>

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
                 lateOld, acked, selfConflict, quiet, sib>>

\* Limitation L11: an old app's non-exclusive DELETE writes a tombstone at
\* the next stream version; earlier versions stay.
OldDelete(n, s) ==
  /\ cnt.olddel < MaxOldDelete
  /\ hd[n][s] # <<>> /\ ~IsTomb(Latest(n, s))
  /\ hd' = [hd EXCEPT ![n][s] = Append(@, TombHead)]
  /\ cnt' = [cnt EXCEPT !.olddel = @ + 1]
  /\ UNCHANGED <<ctl, failed, store, login, listing, known, stopped,
                 needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib>>

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
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib, cnt>>

SettleFail(n, s, i) ==
  /\ cnt.settle < MaxSettleFail
  /\ i \in 1..Len(hd[n][s]) /\ <<n, s, i>> \notin failed
  /\ failed' = failed \cup {<<n, s, i>>}
  /\ cnt' = [cnt EXCEPT !.settle = @ + 1]
  /\ UNCHANGED <<ctl, hd, store, login, listing, known, stopped,
                 needsFull, ckpt, ob, view, psv, inflight, seedTarget, rcpt, clock, commits,
                 admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib>>

Lens == [n \in NS |-> [c |-> CtlLen(n), h |-> [s \in Streams |-> Len(hd[n][s])]]]
PsSync(p) ==
  /\ psv[p] # Lens
  /\ psv' = [psv EXCEPT ![p] = Lens]
  /\ UNCHANGED <<ctl, hd, failed, store, login, listing, known,
                 stopped, needsFull, ckpt, ob, view, inflight, seedTarget, rcpt, clock,
                 commits, admitted, inserted, lateOld, left, fin, acked, selfConflict, quiet, sib, cnt>>

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
  /\ sib = FALSE
  /\ cnt = [runs |-> 0, reruns |-> 0, deletes |-> 0, lost |-> 0, sessions |-> 0,
            settle |-> 0, fails |-> 0, leaves |-> 0, olddel |-> 0, retries |-> 0, aborts |-> 0]

Next ==
  \/ \E d \in Devices, a \in Acct, uc \in BOOLEAN : StartRun(d, a, uc)
  \/ \E d \in Devices, a \in Acct : Rerun(d, a) \/ BudgetRerun(d, a) \/ SnapRerun(d, a)
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
  /\ \A d \in Devices, a \in Acct : WF_vars(Rerun(d, a)) /\ WF_vars(BudgetRerun(d, a))
                                    /\ WF_vars(SnapRerun(d, a))
  /\ \A d \in Devices : WF_vars(Import(d))
  /\ \A p \in Readers : WF_vars(PsSync(p))
  /\ WF_vars(LateApply)

Spec == Init /\ [][Next]_vars /\ Fairness

\* Symmetry on accounts, record keys and the streams other than LegacyFrom,
\* within and outside FullStreams (safety configs only).
Symmetry == Permutations(Acct) \cup (IF Budgeted = {} THEN Permutations(PK) ELSE {})
            \cup Permutations(Streams \ ({LegacyFrom} \cup FullStreams \cup Budgeted))
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

\* A stream the device held needsFull for at begin is issued no state, unless
\* it was issued from retry provenance (R28; per stream, so a retrying
\* stream is not reset by a sibling's debt).
NeedsFullRunIsFull ==
  \A d \in Devices :
    LET e == ob[d] IN
    e # NoEntry => \A s \in e.nf : e.iss[s] = 0 \/ s \in e.el

\* The registry_inconsistent row of the table never applies.
NeverInconsistent ==
  \A d \in Devices : (ob[d] # NoEntry /\ ob[d].start # Null) =>
    LET S == StartState(d, ob[d])  C == CtlNow(ob[d].n, Key(d)) IN
    ~(S.k = "active" /\ (C.k = "absent" \/ (C.k = "active" /\ C.g < S.g)))

TypeOK ==
  /\ \A d \in Devices : \A s \in Streams :
       ob[d].st[s] \in {"none", "planned", "creating", "reconnecting", "decided", "posted", "done"}
  /\ \A d \in Devices : ob[d].out \in Outs
  /\ \A d \in Devices : ckpt[d] # NoCk =>
       \A s \in Streams : /\ ckpt[d].pg[s] \in 0..(KP + 1) /\ ckpt[d].prov[s] \in 0..clock
                          /\ ckpt[d].ph[s] \in {"n", "A", "H"} /\ ckpt[d].wv[s] \in 0..MaxVer
  /\ \A n \in NS : \A i \in 1..CtlLen(n) : ctl[n][i].k \in {"A", "T"}

\* R28: a head committed for a stream the run did not cover (a record-bearing
\* retry stream) is never complete:true.  A succeeded or partial run
\* publishes covered streams only (PublishCoveredOnly).  The Desktop seed
\* (2.9) is not a run output.
CoveredOnly == \A x \in inserted : x[4].oc => ~x[4].complete

\* Run intake v2 (2.1): the START state the connector used is the
\* writer's issue: the stored checkpoint, or none when the writer forced
\* the run full.
IssuedStart == \A d \in Devices : ob[d] # NoEntry => ob[d].stOk

\* R24: a stream issued a cursor is issued incremental: the run-wide START
\* mode is full_refresh only when no stream holds an issued state.
R24_CursorImpliesIncremental ==
  \A d \in Devices : ob[d] # NoEntry =>
    \A s \in Streams : ob[d].iss[s] # 0 => ~ob[d].full

\* The provenance of a stream is the run of its saved cursor, saved with it
\* under the checkpoint's (n, g) and a re-checked control.
\* R30.4: both provenance states.  A stream has a provenance state exactly
\* when it has a provenance run, and that run is the run of its saved cursor,
\* saved under a re-checked control.
ProvenanceAtomic ==
  \A d \in Devices : ckpt[d] # NoCk =>
    \A s \in Streams :
      /\ (ckpt[d].ph[s] = "n") <=> (ckpt[d].prov[s] = 0)
      /\ ckpt[d].ph[s] # "n" =>
           (ckpt[d].prov[s] = ckpt[d].cur[s] /\ ckpt[d].ctlOk /\ ckpt[d].cur[s] # 0)

\* R30.2 + R30.3: a complete head is grounded: seeded, or covered and actually
\* read full (the stream was issued no state), or merged onto a complete base.
\* A false complete:true is a false delete of every row the head lacks.
NoFalseComplete == \A x \in inserted : x[4].complete => x[4].gr

\* R30.1: a retry run publishes no seed-only stream.
RetryPubSetOnly == \A x \in inserted : ~x[4].sr

\* R30.4: an incremental:false stream is issued a state only from an active
\* attempt, and never holds history_tail provenance.
StreamKindEligibility ==
  \A d \in Devices :
    /\ ob[d] # NoEntry => \A s \in FullStreams : ob[d].iss[s] # 0 => ob[d].ep[s] = "A"
    /\ ckpt[d] # NoCk => \A s \in FullStreams : ckpt[d].ph[s] # "H"

\* R29 + R30.5: no stream resumes a cursor whose published history was
\* tombstoned, at START or at save.
NoResumeAfterTombstone ==
  \A d \in Devices :
    /\ ob[d] # NoEntry => ob[d].rb = {}
    /\ ckpt[d] # NoCk => \A s \in Streams : ~ckpt[d].tw[s]

\* R30.4: no begin issues an active_attempt cursor to an incremental:false
\* stream that an earlier end covered.
NoResumeAfterCoveredAttempt ==
  \A d \in Devices : ob[d] # NoEntry => ob[d].cb = {}

\* R30.7: an incomplete stream's publish never clears a sibling's entry.
SiblingContinuationKept == ~sib

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

\* A budgeted stream is never restarted at page 1 by a device that has
\* published it (no explicit full request, no invalidation).  Meaningful
\* only on the single-device budget profile.
NoRestart == \A d \in Devices : ob[d] = NoEntry \/ ~ob[d].rs

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
\* L5, conditional liveness of a budgeted backfill: the stream's pages are
\* eventually published, one page per run, and no run restarts at page 1
\* (profile bud-live: one device, no delete, no leave, no explicit full
\* request, no permanent failure, a bounded number of scheduled runs).
L5_BudgetProgress == []NoRestart /\ <>(\A n \in NS, s \in Budgeted : PagesPub(n, s))

\* L6, conditional liveness for an incremental:false stream: once its
\* attempt is covered by a succeeded run, its next begin is full/null, so it
\* holds no provenance (profile snap-live: one device, no delete, no leave,
\* no explicit full request, no permanent failure; scheduled covering reruns).
L6_SnapshotReturns ==
  \A d \in Devices, s \in FullStreams :
    \* the antecedent needs one scheduled rerun left in the bound: the
    \* assumption is an unbounded supply of covering reruns
    (ckpt[d] # NoCk /\ ckpt[d].ph[s] # "n" /\ cnt.reruns < MaxReruns)
      ~> (ckpt[d] = NoCk \/ ckpt[d].ph[s] = "n")

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

\* A budgeted stream resumes at page 2 from its saved cursor, incremental.
NotBudgetResume ==
  ~\E d \in Devices, s \in Budgeted :
     ob[d] # NoEntry /\ ob[d].iss[s] # 0 /\ ob[d].pg[s] = 2 /\ ~ob[d].full

\* A retry token is issued incremental although its stream holds needsFull.
NotTokenResume ==
  ~\E d \in Devices, s \in Streams :
     ob[d] # NoEntry /\ s \in ob[d].nf /\ s \in ob[d].el /\ ob[d].iss[s] # 0 /\ ~ob[d].full

\* One stream resumes from retry provenance while a sibling with needsFull
\* is issued nothing (a mixed run).
NotMixedModes ==
  ~\E d \in Devices, s, t \in Streams :
     ob[d] # NoEntry /\ s \in ob[d].el /\ ob[d].iss[s] # 0 /\ t \in ob[d].nf /\ ob[d].iss[t] = 0

\* A record-bearing uncovered retry stream is published as a merge.
NotRetryMerge ==
  ~\E x \in inserted : x[4].oc /\ x[4].lines # {}

\* R30 witnesses.
\* An incremental:false stream is issued its cursor from an active attempt.
NotSnapshotResume ==
  ~\E d \in Devices, s \in FullStreams : ob[d] # NoEntry /\ ob[d].iss[s] # 0
\* R30.4: a retry end covers an incremental:false stream that is in its saved
\* candidate, with both streams emitted and the sibling uncovered (the dot's
\* two-run shape, run 1: emit={s1,s2}, cov={s2}, cand={s1,s2}).
NotCoveredSnapshotInCand ==
  ~\E d \in Devices, s \in FullStreams :
     ob[d] # NoEntry /\ ob[d].out = "retry" /\ s \in ob[d].cov /\ s \in ob[d].emit
     /\ ob[d].cand = Streams
     /\ \E t \in Streams \ {s} : t \in ob[d].emit /\ t \notin ob[d].cov
\* R30.4: a retry end covers an incremental:false stream that holds a saved
\* active_attempt and omits it from the candidate.
NotCoveredSnapshotOmitted ==
  ~\E d \in Devices, s \in FullStreams :
     ob[d] # NoEntry /\ ob[d].out = "retry" /\ s \in ob[d].cov /\ s \notin ob[d].cand
     /\ ckpt[d] # NoCk /\ ckpt[d].n = ob[d].n /\ ckpt[d].ph[s] = "A"
\* R30.4: a record-bearing retry end covers an incremental:false stream while
\* its candidate is empty (so Finish saves no checkpoint) and the old pair holds
\* an active_attempt for it.
NotCoveredSnapshotEmptyCand ==
  ~\E d \in Devices, s \in FullStreams :
     ob[d] # NoEntry /\ ob[d].out = "retry" /\ s \in ob[d].cov /\ ob[d].cand = {}
     /\ ckpt[d] # NoCk /\ ckpt[d].n = ob[d].n /\ ckpt[d].ph[s] = "A"
\* A begin is full/null for a stream whose saved continuation a tombstone invalidated.
NotTombInvalidates ==
  ~\E d \in Devices, s \in Streams :
     ob[d] # NoEntry /\ ckpt[d] # NoCk /\ ckpt[d].n = ob[d].n /\ ckpt[d].ph[s] # "n"
     /\ ob[d].iss[s] = 0 /\ TombAfter(ob[d].n, s, ckpt[d].wv[s])
\* A retry run whose received upserts were all oversized.
NotOversizedOnly == ~\E d \in Devices : ob[d] # NoEntry /\ ob[d].ovz # {}
\* A retry run on the seeding Desktop leaves a stream's seed receipt pending.
NotRetrySeedDeferred ==
  ~\E d \in Devices :
     ob[d] # NoEntry /\ ob[d].out = "retry" /\ d = Desktop /\ ob[d].n = seedTarget
     /\ \E s \in Streams : ob[d].st[s] = "none" /\ <<ob[d].n, s>> \notin rcpt
\* A stream's incomplete head is published while a sibling holds a saved cursor.
NotSiblingCursor ==
  ~\E d \in Devices, s, t \in Streams :
     s # t /\ ckpt[d] # NoCk /\ ckpt[d].cur[t] # 0 /\ ob[d] # NoEntry /\ ob[d].incomp
     /\ ob[d].n = ckpt[d].n

\* A permanently failed entry while newer heads arrive.
NotFailedEntryNewerHeads ==
  ~\E d \in Devices, s \in Streams :
     ob[d] # NoEntry /\ ob[d].dead /\ Latest(ob[d].n, s).at > ob[d].rid
=============================================================================
