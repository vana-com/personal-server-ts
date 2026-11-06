----------------------------- MODULE StreamSync -----------------------------
(***************************************************************************)
(* Bounded model of whole-file stream sync, design revision 4, section 4. *)
(* README.md states the status, the modelling choices and the trace.     *)
(* Section numbers in comments refer to that design revision.             *)
(*                                                                         *)
(* One connector.  A connection is one namespace n (one upstream          *)
(* account).  It has a control row chain ctl[n] (version g active = the   *)
(* connection is at generation g; a tombstone version = deleted) and one  *)
(* stream row chain per stream.  A stream row is a head: generation,      *)
(* lines, complete flag.  A line is <<ns, key, runId>>; runIds grow with  *)
(* run start, so the merge order (o, r) is the runId order.  The Desktop  *)
(* seed lines have runId 0 (o = 0, r = "seed").  Parts are one per line   *)
(* (one bucket per primary key), named by generation and content.        *)
(*                                                                         *)
(* Each guard of the design is a constant that is TRUE in the design.     *)
(* A control sets one of them FALSE and must fail one property.           *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
  Devices, NS, Streams, Keys,
  Desktop,             \* the device with a retained snapshot to seed from
  MaxRuns, MaxDeletes, MaxConnects, MaxLost, MaxCrashes,
  \* --- guards (all TRUE in the design) ---
  GenInNames,          \* part names carry the generation           (section 2.11)
  ClearOnGenChange,    \* checkpoints and entries cleared on a new generation (2.4)
  Exclusive,           \* registry writes use exclusive: true      (2.3, F1)
  OneConnectionRead,   \* a read returns one connection             (2.10)
  SeedOnlyGen1,        \* the Desktop seeds only at generation 1    (2.9)
  CheckpointAfterAll,  \* checkpoint only after every stream commits (2.7)
  \* --- environment ---
  EmptyParts           \* a head lists an empty part for each key it lacks (a split
                       \* bucket with no records); empty parts have equal bytes

VARIABLES
  ctl,       \* ctl[n]: control rows; row i is version i: "A" active or "T" tombstone
  srow,      \* srow[n][s]: stream rows; row i is version i, a head record
  objs,      \* names of the objects present in storage
  kg,        \* kg[d][n]: knownGen of device d for connection n
  stopped,   \* stopped[d][n]
  chk,       \* chk[d]: the connector checkpoint of device d, or NoChk
  ob,        \* ob[d]: the outbox entry of device d (one run at a time), or NoEntry
  view,      \* view[d][n][s]: the imported (read) copy: [g, lines]
  inflight,  \* POSTs whose reply was lost; each may still reach the registry
  seedNs,    \* the connection the Desktop snapshot seeds ("none" until used)
  commits,   \* ghost: <<n, s, g, runId, keys>> for each stream row a run inserted
  inserted,  \* ghost: <<n, s, head, version>> for every row written (S6)
  selfConflict, \* ghost: a request was refused because of its own row (S6)
  purged,    \* ghost: purged[d][n] = d's sync loop (or d's delete) purged a deleted n
  cnt        \* bounded counters

vars == <<ctl, srow, objs, kg, stopped, chk, ob, view, inflight, seedNs, commits,
          inserted, selfConflict, purged, cnt>>

----------------------------------------------------------------------------
NoHead == [n |-> "none", s |-> "none", g |-> 0, lines |-> {}, complete |-> FALSE]
NoReq == [ver |-> 0, h |-> NoHead]
NoChk == [n |-> "none", g |-> 0, rid |-> 0, streams |-> {}]
NoEntry == [rid |-> 0, n |-> "none", bound |-> 0, uc |-> FALSE, full |-> FALSE,
            sw |-> FALSE, incomp |-> FALSE, keys |-> {},
            st |-> [s \in Streams |-> "none"], g |-> [s \in Streams |-> 0],
            req |-> [s \in Streams |-> NoReq]]
NoView == [g |-> 0, lines |-> {}]

Max(a, b) == IF a > b THEN a ELSE b

\* Control state of connection n.
CtlLen(n) == Len(ctl[n])
Absent(n) == CtlLen(n) = 0
Active(n) == CtlLen(n) > 0 /\ ctl[n][CtlLen(n)] = "A"
Deleted(n) == CtlLen(n) > 0 /\ ctl[n][CtlLen(n)] = "T"
CurGen(n) == IF Active(n) THEN CtlLen(n) ELSE 0
\* Generations that were deleted: a tombstone at version v deletes generation v-1.
DeletedGens(n) == {v - 1 : v \in {i \in 1..CtlLen(n) : ctl[n][i] = "T"}}

\* Liveness rule (2.4): control active(g), and the latest stream head has generation g.
Latest(n, s) == IF srow[n][s] = <<>> THEN NoHead ELSE srow[n][s][Len(srow[n][s])]
Live(n, s) == Active(n) /\ srow[n][s] # <<>> /\ Latest(n, s).g = CurGen(n)
LiveLines(n, s) == IF Live(n, s) THEN Latest(n, s).lines ELSE {}

\* Merge (2.6): for each key the line with the greatest (o, r) wins.
KeysOf(L) == {l[2] : l \in L}
Best(L, k) == CHOOSE l \in L : l[2] = k /\ \A m \in L : m[2] = k => m[3] <= l[3]
Merge(L) == {Best(L, k) : k \in KeysOf(L)}

\* Object names (2.1, 2.11): head h-<hash of clear head>, part g<gen>-p-<hash>.
HeadObj(h) == <<"h", h>>
PartObj(n, s, g, l) == IF GenInNames THEN <<"p", n, s, g, l>> ELSE <<"p", n, s, 0, l>>
EmptyPart(n, s, g) == IF GenInNames THEN <<"e", n, s, g>> ELSE <<"e", n, s, 0>>
Objects(h) ==
  {HeadObj(h)} \cup {PartObj(h.n, h.s, h.g, l) : l \in h.lines}
    \cup (IF EmptyParts /\ KeysOf(h.lines) # Keys THEN {EmptyPart(h.n, h.s, h.g)} ELSE {})

----------------------------------------------------------------------------
Init ==
  /\ ctl = [n \in NS |-> <<>>]
  /\ srow = [n \in NS |-> [s \in Streams |-> <<>>]]
  /\ objs = {}
  /\ kg = [d \in Devices |-> [n \in NS |-> 0]]
  /\ stopped = [d \in Devices |-> [n \in NS |-> FALSE]]
  /\ chk = [d \in Devices |-> NoChk]
  /\ ob = [d \in Devices |-> NoEntry]
  /\ view = [d \in Devices |-> [n \in NS |-> [s \in Streams |-> NoView]]]
  /\ inflight = {}
  /\ seedNs = "none"
  /\ commits = {}
  /\ inserted = {}
  /\ selfConflict = FALSE
  /\ purged = [d \in Devices |-> [n \in NS |-> FALSE]]
  /\ cnt = [runs |-> 0, deletes |-> 0, connects |-> 0, lost |-> 0, crashes |-> 0]

----------------------------------------------------------------------------
\* Registry write of a stream head (2.3, F1).  With Exclusive: the same head
\* at that version is a replay (success, checked before staleness); another
\* head at that version is a 409.  Without: an occupied version is replaced.
Outcome(r) ==
  LET rows == srow[r.h.n][r.h.s]
      occ == Len(rows) >= r.ver
  IN IF occ /\ rows[r.ver] = r.h THEN "replay"
     ELSE IF occ /\ Exclusive THEN "conflict"
     ELSE IF occ THEN "overwrite"
     ELSE "insert"

\* The registry effect of request r carrying run rid's keys.
Write(r, rid, keys, out) ==
  LET n == r.h.n
      s == r.h.s
  IN IF out \in {"insert", "overwrite"}
     THEN /\ srow' = [srow EXCEPT ![n][s] = IF out = "insert" THEN Append(@, r.h)
                                            ELSE [@ EXCEPT ![r.ver] = r.h]]
          /\ commits' = commits \cup {<<n, s, r.h.g, rid, keys>>}
          /\ inserted' = inserted \cup {<<n, s, r.h, r.ver>>}
     ELSE UNCHANGED <<srow, commits, inserted>>

----------------------------------------------------------------------------
\* Run start and identity resolution (2.4, 2.12).  A run on a device with a
\* checkpoint is incremental; without one it is full.  The run's ns becomes
\* known here; boundGen = knownGen.  An explicit connect (uc) is the first
\* run on a connection the device has not seen, or a connect on a stopped one.
Collect(d, n) ==
  /\ ob[d] = NoEntry /\ cnt.runs < MaxRuns
  /\ \E uc \in BOOLEAN, S \in (SUBSET Streams) \ {{}}, K \in (SUBSET Keys) \ {{}} :
       /\ IF stopped[d][n] THEN uc /\ cnt.connects < MaxConnects
          ELSE uc => kg[d][n] = 0
       /\ chk[d] = NoChk => K = Keys
       /\ LET rid == cnt.runs + 1 IN
          /\ ob' = [ob EXCEPT ![d] = [NoEntry EXCEPT !.rid = rid, !.n = n, !.bound = kg[d][n],
                                        !.uc = uc, !.full = (chk[d] = NoChk),
                                        !.sw = (chk[d] # NoChk /\ chk[d].n # n), !.keys = K,
                                        !.st = [s \in Streams |-> IF s \in S THEN "planned" ELSE "none"]]]
          /\ cnt' = [cnt EXCEPT !.runs = rid, !.connects = IF stopped[d][n] THEN @ + 1 ELSE @]
  /\ UNCHANGED <<ctl, srow, objs, kg, stopped, chk, view, inflight, seedNs, commits,
                 inserted, selfConflict, purged>>

\* Drop device d's run and clear its checkpoint (the "discard run" rows of 2.4).
Discard(d, n, clear) ==
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ chk' = IF clear /\ chk[d].n = n THEN [chk EXCEPT ![d] = NoChk] ELSE chk

\* Read control, then decide (2.4 table).  "Join": an entry with boundGen 0
\* that publishes at g is bound to g from then on (it joined the connection).
Decide(d, s) ==
  LET e == ob[d]
      n == e.n
      L == CtlLen(n)
  IN /\ e.st[s] = "planned"
     /\ CASE Absent(n) /\ e.bound = 0 ->
               /\ ob' = [ob EXCEPT ![d].st[s] = "creating"]
               /\ UNCHANGED <<chk, kg, stopped>>
          [] Active(n) /\ e.bound \in {0, L} ->
               /\ ob' = [ob EXCEPT ![d].st[s] = "decided", ![d].g[s] = L, ![d].bound = L]
               /\ kg' = [kg EXCEPT ![d][n] = Max(@, L)]
               /\ UNCHANGED <<chk, stopped>>
          [] Active(n) /\ 0 < e.bound /\ e.bound < L ->
               /\ Discard(d, n, ClearOnGenChange)
               /\ kg' = [kg EXCEPT ![d][n] = L]
               /\ UNCHANGED stopped
          [] Deleted(n) /\ e.uc ->
               /\ ob' = [ob EXCEPT ![d].st[s] = "reconnecting", ![d].g[s] = L + 1]
               /\ UNCHANGED <<chk, kg, stopped>>
          [] Deleted(n) /\ ~e.uc ->
               /\ Discard(d, n, TRUE)
               /\ stopped' = [stopped EXCEPT ![d][n] = TRUE]
               /\ UNCHANGED kg
     \* Absent with boundGen > 0 ("registry_inconsistent") has no step: the
     \* entry waits.  NeverInconsistent shows this state is unreachable.
  /\ UNCHANGED <<ctl, srow, objs, view, inflight, seedNs, commits, inserted, selfConflict,
                 purged, cnt>>

\* Create (2.3): POST control version 1 ACTIVE.  Identical bytes from every
\* creator, so a second creator gets a replay, even after later versions.
Create(d, s) ==
  LET n == ob[d].n IN
  /\ ob[d].st[s] = "creating"
  /\ ctl' = IF Absent(n) THEN [ctl EXCEPT ![n] = <<"A">>] ELSE ctl
  /\ ob' = [ob EXCEPT ![d].st[s] = "decided", ![d].g[s] = 1, ![d].bound = 1]
  /\ kg' = [kg EXCEPT ![d][n] = Max(@, 1)]
  /\ UNCHANGED <<srow, objs, stopped, chk, view, inflight, seedNs, commits, inserted,
                 selfConflict, purged, cnt>>

\* Reconnect (2.3): POST control version v+1 ACTIVE over the tombstone at v.
\* Success, or a replay of an identical reconnect, starts generation v+1;
\* anything else is a 409 and the stream is decided again.
ReconnectPost(d, s) ==
  LET n == ob[d].n
      t == ob[d].g[s]
  IN /\ ob[d].st[s] = "reconnecting"
     /\ IF CtlLen(n) = t - 1 \/ (CtlLen(n) >= t /\ ctl[n][t] = "A")
        THEN /\ ctl' = IF CtlLen(n) = t - 1 THEN [ctl EXCEPT ![n] = Append(@, "A")] ELSE ctl
             /\ ob' = [ob EXCEPT ![d].st[s] = "decided", ![d].bound = t]
             /\ kg' = [kg EXCEPT ![d][n] = Max(@, t)]
             /\ stopped' = [stopped EXCEPT ![d][n] = FALSE]
             /\ chk' = IF chk[d].n = n THEN [chk EXCEPT ![d] = NoChk] ELSE chk
        ELSE /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
             /\ UNCHANGED <<ctl, kg, stopped, chk>>
  /\ UNCHANGED <<srow, objs, view, inflight, seedNs, commits, inserted, selfConflict,
                 purged, cnt>>

\* Read the stream row, plan, upload parts and head, persist the request
\* (2.4 base rule, 2.6 merge, 2.7 order, 2.9 seed).  A head of a newer
\* generation sends the stream back to "read control".
Plan(d, s) ==
  LET e == ob[d]
      n == e.n
      g == e.g[s]
      rows == srow[n][s]
      N == Len(rows)
      top == Latest(n, s)
      base == IF N > 0 /\ top.g = g THEN top ELSE NoHead
      seeded == /\ d = Desktop /\ base = NoHead /\ seedNs \in {"none", n}
                /\ SeedOnlyGen1 => g = 1
      seedLines == IF seeded THEN {<<n, k, 0>> : k \in Keys} ELSE {}
      runLines == {<<n, k, e.rid>> : k \in e.keys}
      lines == Merge(base.lines \cup seedLines \cup runLines)
      complete == ~e.sw /\ (e.full \/ base.complete \/ seeded)
      h == [n |-> n, s |-> s, g |-> g, lines |-> lines, complete |-> complete]
  IN /\ e.st[s] = "decided"
     /\ IF N > 0 /\ top.g > g
        THEN /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
             /\ UNCHANGED <<objs, seedNs, commits>>
        ELSE IF lines = base.lines /\ complete = base.complete
        THEN \* no-op (2.6): the live head already holds the run (its lines
             \* are there or lost to a greater (o, r)); nothing to upload.
             \* The stream counts as committed at (ns, g).
             /\ ob' = [ob EXCEPT ![d].st[s] = "done"]
             /\ commits' = commits \cup {<<n, s, g, e.rid, e.keys>>}
             /\ UNCHANGED <<objs, seedNs>>
        ELSE /\ objs' = objs \cup Objects(h)
             /\ seedNs' = IF seeded THEN n ELSE seedNs
             /\ UNCHANGED commits
             /\ ob' = [ob EXCEPT ![d].st[s] = "posted", ![d].req[s] = [ver |-> N + 1, h |-> h],
                                 ![d].incomp = @ \/ (~complete /\ ~e.full)]
  /\ UNCHANGED <<ctl, srow, kg, stopped, chk, view, inflight, inserted,
                 selfConflict, purged, cnt>>

\* Without CheckpointAfterAll, the checkpoint is saved at the first commit.
EarlyCheckpoint(d) ==
  IF CheckpointAfterAll THEN chk
  ELSE [chk EXCEPT ![d] = [n |-> ob[d].n, g |-> ob[d].bound, rid |-> ob[d].rid,
                           streams |-> {s \in Streams : ob[d].st[s] # "none"}]]

\* POST the persisted request (2.3).  The reply arrives (2xx/replay = done,
\* 409 = read control again), or it is lost: the request may still reach the
\* registry, and the device resends the same bytes (Post again).
Post(d, s) ==
  LET e == ob[d]
      r == e.req[s]
      out == Outcome(r)
  IN /\ e.st[s] = "posted"
     /\ \/ /\ Write(r, e.rid, e.keys, out)
           /\ IF out = "conflict"
              THEN /\ ob' = [ob EXCEPT ![d].st[s] = "planned"]
                   /\ selfConflict' = (selfConflict \/ srow[r.h.n][r.h.s][r.ver] = r.h)
                   /\ UNCHANGED chk
              ELSE /\ ob' = [ob EXCEPT ![d].st[s] = "done"]
                   /\ chk' = EarlyCheckpoint(d)
                   /\ UNCHANGED selfConflict
           /\ UNCHANGED <<inflight, cnt>>
        \/ /\ cnt.lost < MaxLost
           /\ inflight' = inflight \cup {[r |-> r, rid |-> e.rid, keys |-> e.keys]}
           /\ cnt' = [cnt EXCEPT !.lost = @ + 1]
           /\ UNCHANGED <<srow, commits, inserted, ob, chk, selfConflict>>
  /\ UNCHANGED <<ctl, objs, kg, stopped, view, seedNs, purged>>

\* A request whose reply was lost reaches the registry.
LateApply ==
  \E x \in inflight :
    /\ inflight' = inflight \ {x}
    /\ Write(x.r, x.rid, x.keys, Outcome(x.r))
    /\ UNCHANGED <<ctl, objs, kg, stopped, chk, ob, view, seedNs, selfConflict, purged, cnt>>

\* Every stream of the run is committed or a no-op: save the checkpoint
\* candidate, unless the account switched or an incremental run published an
\* incomplete head (2.7, 2.12); then the next run is full.
Finish(d) ==
  LET e == ob[d] IN
  /\ e # NoEntry
  /\ \A s \in Streams : e.st[s] \in {"none", "done"}
  /\ ob' = [ob EXCEPT ![d] = NoEntry]
  /\ chk' = [chk EXCEPT ![d] = IF e.sw \/ e.incomp THEN NoChk
                               ELSE [n |-> e.n, g |-> e.bound, rid |-> e.rid,
                                     streams |-> {s \in Streams : e.st[s] = "done"}]]
  /\ UNCHANGED <<ctl, srow, objs, kg, stopped, view, inflight, seedNs, commits, inserted,
                 selfConflict, purged, cnt>>

\* The device process dies.  The outbox and checkpoint are on disk; a
\* decision held in memory is made again from "read control".
Crash(d) ==
  /\ cnt.crashes < MaxCrashes
  /\ \E s \in Streams : ob[d].st[s] \in {"decided", "creating", "reconnecting"}
  /\ ob' = [ob EXCEPT ![d].st = [s \in Streams |->
              IF @[s] \in {"decided", "creating", "reconnecting"} THEN "planned" ELSE @[s]]]
  /\ cnt' = [cnt EXCEPT !.crashes = @ + 1]
  /\ UNCHANGED <<ctl, srow, objs, kg, stopped, chk, view, inflight, seedNs, commits, inserted,
                 selfConflict, purged>>

\* Sync-loop observation and import (2.4, 2.9, 2.10).  A new generation
\* clears checkpoints and pending entries and purges old rows; a stopped
\* device resumes.  A deleted connection is purged and stops the device.
\* A stream with an uncommitted local entry is not imported.
Pending(d, n, s) == ob[d].n = n /\ ob[d].st[s] \notin {"none", "done"}
Imported(d, n) ==
  [s \in Streams |-> IF Pending(d, n, s) THEN view[d][n][s]
                     ELSE [g |-> CurGen(n), lines |-> LiveLines(n, s)]]

Sync(d, n) ==
  /\ ~Absent(n)
  /\ IF Active(n)
     THEN LET g == CtlLen(n)
              \* knownGen 0 -> g is a first sighting, not a change (the
              \* device has nothing of an older generation; its entries join).
              change == kg[d][n] > 0 /\ g > kg[d][n]
              clear == change /\ ClearOnGenChange
              resume == stopped[d][n] /\ g > kg[d][n]
          IN /\ kg' = [kg EXCEPT ![d][n] = Max(@, g)]
             /\ stopped' = IF resume THEN [stopped EXCEPT ![d][n] = FALSE] ELSE stopped
             /\ chk' = IF clear /\ chk[d].n = n THEN [chk EXCEPT ![d] = NoChk] ELSE chk
             /\ ob' = IF clear /\ ob[d].n = n THEN [ob EXCEPT ![d] = NoEntry] ELSE ob
             /\ view' = [view EXCEPT ![d][n] =
                           IF clear /\ ob[d].n = n
                           THEN [s \in Streams |-> [g |-> g, lines |-> LiveLines(n, s)]]
                           ELSE Imported(d, n)]
             /\ purged' = [purged EXCEPT ![d][n] = FALSE]
     ELSE /\ stopped' = [stopped EXCEPT ![d][n] = TRUE]
          /\ view' = [view EXCEPT ![d][n] = [s \in Streams |-> NoView]]
          /\ purged' = [purged EXCEPT ![d][n] = TRUE]
          /\ UNCHANGED <<kg, chk, ob>>
  /\ <<kg', stopped', chk', ob', view', purged'>> # <<kg, stopped, chk, ob, view, purged>>
  /\ UNCHANGED <<ctl, srow, objs, inflight, seedNs, commits, inserted, selfConflict,
                 cnt>>

\* Delete on device d (2.11): control tombstone, purge local state, stop.
Delete(d, n) ==
  /\ cnt.deletes < MaxDeletes /\ Active(n)
  /\ ctl' = [ctl EXCEPT ![n] = Append(@, "T")]
  /\ stopped' = [stopped EXCEPT ![d][n] = TRUE]
  /\ view' = [view EXCEPT ![d][n] = [s \in Streams |-> NoView]]
  /\ ob' = IF ob[d].n = n THEN [ob EXCEPT ![d] = NoEntry] ELSE ob
  /\ chk' = IF chk[d].n = n THEN [chk EXCEPT ![d] = NoChk] ELSE chk
  /\ purged' = [purged EXCEPT ![d][n] = TRUE]
  /\ cnt' = [cnt EXCEPT !.deletes = @ + 1]
  /\ UNCHANGED <<srow, objs, kg, inflight, seedNs, commits, inserted, selfConflict>>

\* Best-effort cleanup by any host (2.11), possibly late: for a deleted
\* generation D, delete the parts and head of every head of generation <= D.
Cleanup(n, s, D) ==
  /\ D \in DeletedGens(n)
  /\ LET old == {i \in 1..Len(srow[n][s]) : srow[n][s][i].g <= D}
         gone == UNION {Objects(srow[n][s][i]) : i \in old}
     IN /\ objs \cap gone # {}
        /\ objs' = objs \ gone
  /\ UNCHANGED <<ctl, srow, kg, stopped, chk, ob, view, inflight, seedNs, commits, inserted,
                 selfConflict, purged, cnt>>

Progress(d) ==
  \/ \E s \in Streams : Decide(d, s) \/ Create(d, s) \/ ReconnectPost(d, s)
                        \/ Plan(d, s) \/ Post(d, s)
  \/ Finish(d)

Next ==
  \/ \E d \in Devices, n \in NS : Collect(d, n)
  \/ \E d \in Devices : Progress(d)
  \/ LateApply
  \/ \E d \in Devices : Crash(d)
  \/ \E d \in Devices, n \in NS : Sync(d, n)
  \/ \E d \in Devices, n \in NS : Delete(d, n)
  \/ \E n \in NS, s \in Streams, D \in 1..(MaxDeletes * 2) : Cleanup(n, s, D)

Fairness ==
  /\ \A d \in Devices : WF_vars(Progress(d))
  /\ \A d \in Devices, n \in NS : WF_vars(Sync(d, n))

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Properties (README.md states each in plain words).

\* S1 No lost commit: every committed run's lines stay in the live head, or a
\* line with a greater (o, r) replaced them, unless that generation was deleted.
S1_NoLostCommit ==
  \A c \in commits :
    LET n == c[1]  s == c[2]  g == c[3]  rid == c[4]  keys == c[5] IN
    CurGen(n) = g =>
      \A k \in keys : \E l \in LiveLines(n, s) : l[2] = k /\ l[3] >= rid

\* S2 Delete holds: once a device's sync loop (or its own delete) has seen
\* deleted(v), and no reconnect followed, it shows nothing of the connection.
\* (Other devices show old rows until their next sync: accepted limitation
\* 8.)  No head of a deleted generation is live.
S2_DeleteHolds ==
  /\ \A d \in Devices, n \in NS, s \in Streams :
       Deleted(n) /\ purged[d][n] => view[d][n][s].lines = {}
  /\ \A n \in NS, s \in Streams : Live(n, s) => Latest(n, s).g \notin DeletedGens(n)

\* S3 Reconnect is clean: a head of generation g holds only lines of runs
\* that committed at g in that stream, no run commits at two generations, and
\* seed lines appear only at generation 1.
S3_ReconnectClean ==
  /\ \A n \in NS, s \in Streams : \A i \in 1..Len(srow[n][s]) :
       LET h == srow[n][s][i] IN
       \A l \in h.lines :
         IF l[3] = 0 THEN h.g = 1
         ELSE \E c \in commits : c[1] = n /\ c[2] = s /\ c[3] = h.g /\ c[4] = l[3]
  /\ \A x, y \in commits : x[4] = y[4] => x[3] = y[3]

\* S4 No account mix: no head, imported view or read response holds lines of
\* two namespaces.  A plain-name read returns one connection (2.10).
Readable(s) == {n \in NS : Live(n, s)}
PlainRead(s) ==
  IF OneConnectionRead
  THEN IF Readable(s) = {} THEN {} ELSE LiveLines(CHOOSE n \in Readable(s) : TRUE, s)
  ELSE UNION {LiveLines(n, s) : n \in NS}
S4_NoAccountMix ==
  /\ \A n \in NS, s \in Streams : \A i \in 1..Len(srow[n][s]) : \A l \in srow[n][s][i].lines : l[1] = n
  /\ \A d \in Devices, n \in NS, s \in Streams : \A l \in view[d][n][s].lines : l[1] = n
  /\ \A s \in Streams : Cardinality({l[1] : l \in PlainRead(s)}) <= 1

\* S5 Cleanup safety: every object a live head lists is in storage.
S5_CleanupSafe == \A n \in NS, s \in Streams : Live(n, s) => Objects(Latest(n, s)) \subseteq objs

\* S6 Exact resend: a registry row version is written with one head only, so
\* a resent request commits at most once; and no request is refused because
\* of its own row.
S6_ExactResend ==
  /\ \A x, y \in inserted : x[1] = y[1] /\ x[2] = y[2] /\ x[4] = y[4] => x = y
  /\ ~selfConflict

\* S7 Checkpoint safety: a saved checkpoint means every stream of its run is
\* committed under the checkpoint's (ns, generation).
S7_CheckpointSafe ==
  \A d \in Devices :
    chk[d] # NoChk =>
      \A s \in chk[d].streams :
        \E c \in commits : c[1] = chk[d].n /\ c[2] = s /\ c[3] = chk[d].g /\ c[4] = chk[d].rid

\* X1 (not in the design's list) Honest complete flag: a head marked complete
\* has a line for every key (full runs and the seed collect every key).
X1_CompleteHonest ==
  \A n \in NS, s \in Streams : \A i \in 1..Len(srow[n][s]) :
    srow[n][s][i].complete => KeysOf(srow[n][s][i].lines) = Keys

\* Absent control with boundGen > 0 ("registry_inconsistent") never happens.
NeverInconsistent == \A d \in Devices : ob[d].bound > 0 => ~Absent(ob[d].n)

TypeOK ==
  /\ \A d \in Devices, s \in Streams :
       ob[d].st[s] \in {"none", "planned", "creating", "reconnecting", "decided", "posted", "done"}
  /\ \A n \in NS : \A i \in 1..CtlLen(n) : ctl[n][i] \in {"A", "T"}

\* L1 Convergence: once runs stop, every device's view equals the live heads,
\* and a device is stopped exactly when the connection is deleted.
Converged ==
  \A d \in Devices, n \in NS :
    /\ ~Absent(n) => \A s \in Streams : view[d][n][s].lines = LiveLines(n, s)
    /\ ~Absent(n) => (stopped[d][n] <=> Deleted(n))
L1_Convergence == <>[]Converged
=============================================================================
