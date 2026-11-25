---------------------------- MODULE LegacyRetire ----------------------------
\* The standalone retirement of a connector's legacy copy
\* (`DELETE /v1/owner/connectors/:id/legacy`). Code owners:
\*   packages/core/src/localdb/legacy-retire-intent.ts   request, resume, pass
\*   packages/core/src/localdb/legacy-delete.ts          `retireLegacyScope`, `pinHolds`
\*   packages/core/src/localdb/legacy-import.ts          `importFence`, `guardImport`
\*
\* One owner, one connector, `Scopes` bound legacy scopes. The model has five
\* actors:
\*   request   `request`: read every bound head (the pin), then INSERT OR IGNORE
\*             the one intent row (`legacy_retirements`, PK owner+connector);
\*   worker    per scope: read the head, tombstone fenced to the head it read,
\*             read again, then erase the blobs; the intent is `done` after
\*             every scope is erased;
\*   importer  `importLegacySource`: the preflight `importFence`, then the merge
\*             batch, whose own guard (`guardImport`) runs in the same SQL
\*             transaction as the merge. The two are separate steps; the guard
\*             and the merge are one step;
\*   crash     a restart: every in-flight step is lost, durable rows stay;
\*   gateway   the legacy head, which another writer can publish to or
\*             tombstone. In the real system it stays still; the model moves it
\*             to cover the blocked path and the tombstone-bypass path.
\* A current-connection writer (stream sync) keeps writing.
\*
\* Head versions. A live head is at version v. A tombstone of it has version v+1
\* (`LegacyGatewayFake`, `TombstoneOutcome.version`: "previous current + 1").
\* Erasing a tombstone at version t frees every blob slot <= t (`confirmErased`),
\* so a tombstone that does not directly follow the pinned head frees slots that
\* the pin never named.
\*
\* Modes: "good" and one mutant per broken control.
\*   noBatchFence    the merge batch has no guard of its own (only the preflight)
\*   noPin           the worker does not compare a head read to the pin
\*   doneBeforeErase the intent is marked done once tombstoned, before the erase
\*   newIntentOnRestart a restart makes a new intent for an open one
\*   touchesCurrent  the erase also writes the current connection
\*   oldPinHolds     the code before the fix: a tombstone satisfies any live pin
\*   adapterCleansFirst the code before round 4: the delete adapter accepts any deleted head and cleans up before the worker's pin check
\*   absentCleans    the code before round 5: a fenced delete whose adapter sees the head absent still queues cleanup and erases local entries
\*   doneLiftsFence  the code before the fix: a done intent no longer fences its scopes
\*   gateOnce        the code before round 7: the host's write authority is read when the
\*                   pass calls the delete, not again before each destructive step
\*   echoCleans      the code before round 7: a 2xx tombstone answer that echoes a later
\*                   version bounds the cleanup (queue and local erase)
\*   resumeSkipsLocal the code before round 7: a pass that finds the tombstone landed
\*                   checks the remote copy only and never retries the local erase
EXTENDS Naturals, FiniteSets

CONSTANTS Scopes,     \* the bound legacy scopes
          MaxVer,     \* the highest gateway version
          MaxReq,     \* the most owner requests
          MaxB,       \* the most import batches
          MaxCrash,   \* the most restarts
          MaxW,       \* the most current-connection writes
          MaxRev,     \* the most times the host's write authority closes
          Mode

VARIABLES
  ver, tomb, tombBy, tombVer,   \* gateway head per scope
  erased,                       \* blobs of the scope are gone (confirmed)
  cleanTo,                      \* highest version storage cleanup was queued or done for (0: none)
  localTo,                      \* highest version the local erase went through (0: none)
  wr, revokes, unauth,          \* the host's write authority, its closings, a destructive step run without it
  exists, st, pins, nIntents,   \* the intent row(s)
  pc, snap, blk,                \* worker per scope
  rpc, rsnap, reqs,             \* request
  ipc, batches, isc, freeMerged,      \* importer
  mergedWhileOpen, staleAfterDone,
  cc, writes,                   \* the current connection
  crashes, lastActor

vars == <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents,
          pc, snap, blk, rpc, rsnap, reqs, ipc, batches, isc, freeMerged,
          mergedWhileOpen, staleAfterDone, cc, writes, crashes, lastActor>>

Open == exists /\ st = "open"

\* Whether a head read is one the pin allows (`pinHolds`, plus the live check).
PinHolds(s, hLive, hVer, hTombVer) ==
  IF Mode = "noPin" THEN TRUE
  ELSE IF hLive THEN hVer = pins[s]
  ELSE IF Mode = "oldPinHolds" THEN TRUE      \* any tombstone satisfies a live pin
  ELSE hTombVer = pins[s] + 1                 \* only the tombstone that follows it

Init ==
  /\ ver = [s \in Scopes |-> 1]
  /\ tomb = [s \in Scopes |-> FALSE]
  /\ tombBy = [s \in Scopes |-> "none"]
  /\ tombVer = [s \in Scopes |-> 0]
  /\ erased = [s \in Scopes |-> FALSE]
  /\ cleanTo = [s \in Scopes |-> 0]
  /\ localTo = [s \in Scopes |-> 0]
  /\ wr = TRUE /\ revokes = 0 /\ unauth = FALSE
  /\ exists = FALSE /\ st = "none" /\ nIntents = 0
  /\ pins = [s \in Scopes |-> 0]
  /\ pc = [s \in Scopes |-> "idle"]
  /\ snap = [s \in Scopes |-> 0]
  /\ blk = [s \in Scopes |-> FALSE]
  /\ rpc = "idle" /\ rsnap = [s \in Scopes |-> 0] /\ reqs = 0
  /\ ipc = "idle" /\ batches = 0 /\ isc = "none" /\ freeMerged = FALSE
  /\ mergedWhileOpen = FALSE /\ staleAfterDone = FALSE
  /\ cc = [control |-> "active", head |-> 0, records |-> 0] /\ writes = 0
  /\ crashes = 0 /\ lastActor = "init"

\* ---- gateway: another writer -------------------------------------------
Publish(s) ==
  /\ ~tomb[s] /\ ver[s] < MaxVer
  /\ ver' = [ver EXCEPT ![s] = @ + 1]
  /\ lastActor' = "gateway"
  /\ UNCHANGED <<tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

ForeignTomb(s) ==
  /\ ~tomb[s]
  /\ tomb' = [tomb EXCEPT ![s] = TRUE]
  /\ tombBy' = [tombBy EXCEPT ![s] = "other"]
  /\ tombVer' = [tombVer EXCEPT ![s] = ver[s] + 1]
  /\ lastActor' = "gateway"
  /\ UNCHANGED <<ver, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* ---- current-connection writer (stream sync) ---------------------------
CWrite ==
  /\ writes < MaxW
  /\ cc' = [cc EXCEPT !.head = @ + 1, !.records = @ + 1]
  /\ writes' = writes + 1
  /\ lastActor' = "sync"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, crashes>>

\* ---- request -----------------------------------------------------------
\* Reads every head; heads that are tombstoned at request time (a pin of a
\* deleted head) are not modelled.
RRead ==
  /\ rpc = "idle" /\ reqs < MaxReq /\ \A s \in Scopes : ~tomb[s]
  /\ rpc' = "read" /\ rsnap' = ver /\ reqs' = reqs + 1
  /\ lastActor' = "req"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 ipc, batches, isc, freeMerged, mergedWhileOpen, staleAfterDone,
                 cc, writes, crashes>>

\* INSERT OR IGNORE: the first row stands, a later request resumes it.
RInsert ==
  /\ rpc = "read"
  /\ rpc' = "idle"
  /\ IF exists
       THEN UNCHANGED <<exists, st, pins, nIntents>>
       ELSE /\ exists' = TRUE /\ st' = "open" /\ pins' = rsnap /\ nIntents' = nIntents + 1
  /\ lastActor' = "req"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, pc, snap, blk, rsnap, reqs,
                 ipc, batches, isc, freeMerged, mergedWhileOpen, staleAfterDone,
                 cc, writes, crashes>>

\* ---- worker, per scope -------------------------------------------------
\* The host's write authority (`writeReady`). The pass reads it at its start and,
\* since round 7, again right before each destructive step: the tombstone post,
\* the blob queue write, the local erase, the storage deletes and the done verdict.
\* `gateOnce` is the code before: only the pass's start (`WRead`) read it.
Auth == IF Mode = "gateOnce" THEN TRUE ELSE wr
Unauth == unauth' = (unauth \/ ~wr)

WRead(s) ==
  /\ Open /\ pc[s] = "idle" /\ ~blk[s] /\ ~erased[s] /\ wr
  /\ snap' = [snap EXCEPT ![s] = ver[s]]
  /\ IF PinHolds(s, ~tomb[s], ver[s], tombVer[s])
       THEN /\ pc' = [pc EXCEPT ![s] = IF tomb[s] THEN "tombd" ELSE "decided"]
            /\ UNCHANGED blk
       ELSE /\ blk' = [blk EXCEPT ![s] = TRUE]   \* legacy_head_changed
            /\ UNCHANGED pc
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* The delete adapter (`createDeleteDataPort.tombstone` under `deleteScope`) reads
\* the head itself, after the worker's read. A live head that is still the one the
\* fence names is tombstoned (version + 1) and its blobs are queued for cleanup
\* through that version. A head already deleted answers "already deleted", and the
\* worker's `deleteScope` queues or performs cleanup through the tombstone's
\* version at once. The good adapter accepts a deleted head only when its tombstone
\* directly follows the fence; `adapterCleansFirst` is the code before the fix, which
\* accepted any (the worker's pin check ran only after, in `WReread`). A moved live
\* head refuses the fenced tombstone and writes nothing. The adapter reads the
\* write authority again right before it posts (`Auth`): a closed gate sends
\* nothing and the pass ends (`WAbandon`).
WSend(s) ==
  /\ pc[s] = "decided" /\ Auth
  /\ IF ~tomb[s]
       THEN IF ver[s] = snap[s]
              THEN /\ tomb' = [tomb EXCEPT ![s] = TRUE]
                   /\ tombBy' = [tombBy EXCEPT ![s] = "ours"]
                   /\ tombVer' = [tombVer EXCEPT ![s] = ver[s] + 1]
                   /\ cleanTo' = [cleanTo EXCEPT ![s] = ver[s] + 1]
                   /\ pc' = [pc EXCEPT ![s] = "tombed"]
              ELSE /\ UNCHANGED <<tomb, tombBy, tombVer, cleanTo>>
                   /\ pc' = [pc EXCEPT ![s] = "sent"]
       ELSE IF Mode = "adapterCleansFirst" \/ tombVer[s] = snap[s] + 1
              THEN /\ cleanTo' = [cleanTo EXCEPT ![s] = tombVer[s]]
                   /\ UNCHANGED <<tomb, tombBy, tombVer>>
                   /\ pc' = [pc EXCEPT ![s] = "tombed"]
              ELSE /\ UNCHANGED <<tomb, tombBy, tombVer, cleanTo>>
                   /\ pc' = [pc EXCEPT ![s] = "sent"]
  /\ Unauth
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, erased, localTo, wr, revokes, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* The same tombstone post answered 2xx with an `expectedVersion` above the one
\* signed. The good adapter checks a fenced answer against the version it signed and
\* throws: the tombstone landed, nothing is queued or erased, the worker reads again.
\* `echoCleans` is the code before round 7: the echo bounded the cleanup (queue and
\* local erase), a bound no pin names.
WSendEcho(s) ==
  /\ pc[s] = "decided" /\ Auth
  /\ ~tomb[s] /\ ver[s] = snap[s]
  /\ tomb' = [tomb EXCEPT ![s] = TRUE]
  /\ tombBy' = [tombBy EXCEPT ![s] = "ours"]
  /\ tombVer' = [tombVer EXCEPT ![s] = ver[s] + 1]
  /\ IF Mode = "echoCleans"
       THEN /\ cleanTo' = [cleanTo EXCEPT ![s] = MaxVer + 10]
            /\ localTo' = [localTo EXCEPT ![s] = MaxVer + 10]
       ELSE UNCHANGED <<cleanTo, localTo>>
  /\ pc' = [pc EXCEPT ![s] = "sent"]
  /\ Unauth
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, erased, wr, revokes, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* The local erase of the adapter's own call, after the tombstone and the queue
\* write. It may fail (the disk): the local copy stays and the pass goes on to read
\* the head again. A crash between `WSend` and this step is `Crash` from "tombed".
\* The erase covers the versions the tombstone covers: the version it wrote.
WSendLocal(s) ==
  /\ pc[s] = "tombed" /\ Auth
  /\ \/ localTo' = [localTo EXCEPT ![s] = tombVer[s]]
     \/ UNCHANGED localTo
  /\ pc' = [pc EXCEPT ![s] = "sent"]
  /\ Unauth
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, wr, revokes, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* The adapter's lookup or tombstone POST answers "head absent" although the
\* worker just read the pinned head live (the registry lost the point, or a replica
\* behind the writer answered). The good adapter, given a fence, throws and writes
\* nothing: the worker reads again. `absentCleans` is the code before round 5: the
\* adapter reports "not registered" and the shared worker queues blob keys and
\* erases local entries (modelled as a cleanup mark no pin names).
WSendAbsent(s) ==
  /\ pc[s] = "decided"
  /\ ~tomb[s]
  /\ cleanTo' = IF Mode = "absentCleans"
                  THEN [cleanTo EXCEPT ![s] = MaxVer + 10]
                  ELSE cleanTo
  /\ pc' = [pc EXCEPT ![s] = "sent"]
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, localTo, wr, revokes, unauth, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

WReread(s) ==
  /\ pc[s] = "sent"
  /\ IF ~PinHolds(s, ~tomb[s], ver[s], tombVer[s])
       THEN /\ blk' = [blk EXCEPT ![s] = TRUE] /\ pc' = [pc EXCEPT ![s] = "idle"]
       ELSE /\ UNCHANGED blk
            /\ pc' = [pc EXCEPT ![s] = IF tomb[s] THEN "tombd" ELSE "idle"]
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, snap,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* A pass that found the pinned tombstone landed runs the fenced delete again over
\* it (`cleanLocal`): the queue is not queued twice, and the local erase covers the
\* versions up to the pinned tombstone. The tombstone may have landed in a pass or a
\* process that stopped before its local erase, or whose erase failed. It may fail
\* again, which leaves `localTo` as it was.
WLocal(s) ==
  /\ pc[s] = "tombd" /\ Auth /\ localTo[s] # pins[s] + 1
  /\ \/ localTo' = [localTo EXCEPT ![s] = tombVer[s]]
     \/ UNCHANGED localTo
  /\ Unauth
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, wr, revokes, exists, st, pins, nIntents, snap, blk, pc,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* Storage deletes every slot <= the tombstone, then answers for all of them. A
\* pinned scope reaches it only once its local copy is gone (`resumeSkipsLocal` is
\* the code before: the remote copy alone was enough).
WErase(s) ==
  /\ pc[s] = "tombd" /\ Auth
  /\ Mode = "resumeSkipsLocal" \/ localTo[s] = pins[s] + 1
  /\ erased' = [erased EXCEPT ![s] = TRUE]
  /\ pc' = [pc EXCEPT ![s] = "idle"]
  /\ IF Mode = "touchesCurrent"
       THEN cc' = [cc EXCEPT !.head = @ + 1]
       ELSE UNCHANGED cc
  /\ Unauth
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, cleanTo, localTo, wr, revokes, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, writes, crashes>>

WDone ==
  /\ Open /\ Auth
  /\ IF Mode = "doneBeforeErase"
       THEN \A s \in Scopes : tomb[s] /\ (erased[s] \/ pc[s] = "tombd")
       ELSE \A s \in Scopes : erased[s]
  /\ st' = "done"
  /\ Unauth
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, exists, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* The write authority closed: the pass ends at its next host call, and a later
\* pass starts again from a head read. Nothing more is sent.
WAbandon(s) ==
  /\ ~wr /\ pc[s] # "idle"
  /\ pc' = [pc EXCEPT ![s] = "idle"] /\ snap' = [snap EXCEPT ![s] = 0]
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* ---- host: write authority ---------------------------------------------
\* A registration hold closes the authority; the registration comes back later.
Revoke ==
  /\ wr /\ revokes < MaxRev
  /\ wr' = FALSE /\ revokes' = revokes + 1
  /\ lastActor' = "host"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

Restore ==
  /\ ~wr
  /\ wr' = TRUE
  /\ lastActor' = "host"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, isc, freeMerged, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* ---- importer ----------------------------------------------------------
\* The import's legacy scope: a bound scope, or "free" (a stream no bound scope feeds).
\* `importFence` refuses while the intent is open (whole connector), and for good
\* a stream a bound scope of a retired intent feeds. `doneLiftsFence` is the
\* code before the fix: only an open intent fenced.
Fenced(sc) ==
  \/ Open
  \/ (exists /\ st = "done" /\ sc \in Scopes /\ Mode # "doneLiftsFence")

IPre ==
  /\ ipc = "idle" /\ batches < MaxB
  /\ \E sc \in Scopes \cup {"free"} :
       /\ ~Fenced(sc)
       /\ isc' = sc
  /\ ipc' = "checked"
  /\ lastActor' = "importer"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, batches, freeMerged, mergedWhileOpen, staleAfterDone,
                 cc, writes, crashes>>

\* The merge batch. `guardImport` and the merge share one transaction (db.batch):
\* the guard's CHECK fails and the whole batch rolls back if the fence holds now.
IMerge ==
  /\ ipc = "checked"
  /\ ipc' = "idle" /\ batches' = batches + 1
  /\ IF Mode = "noBatchFence" \/ ~Fenced(isc)
       THEN /\ cc' = [cc EXCEPT !.head = @ + 1, !.records = @ + 1]
            /\ mergedWhileOpen' = (mergedWhileOpen \/ Open)
            /\ staleAfterDone' = (staleAfterDone \/ (exists /\ st = "done" /\ isc \in Scopes))
            /\ freeMerged' = (freeMerged \/ (st = "done" /\ isc = "free"))
       ELSE UNCHANGED <<cc, mergedWhileOpen, staleAfterDone, freeMerged>>
  /\ lastActor' = "importer"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, isc, writes, crashes>>

\* ---- restart -----------------------------------------------------------
Crash ==
  /\ crashes < MaxCrash
  /\ crashes' = crashes + 1
  /\ pc' = [s \in Scopes |-> "idle"] /\ snap' = [s \in Scopes |-> 0]
  /\ rpc' = "idle" /\ ipc' = "idle" /\ isc' = "none"
  /\ IF Mode = "newIntentOnRestart" /\ Open
       THEN /\ nIntents' = nIntents + 1 /\ pins' = ver /\ st' = "open"
       ELSE UNCHANGED <<nIntents, pins, st>>
  /\ lastActor' = "crash"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, cleanTo, localTo, wr, revokes, unauth, exists, blk, rsnap, reqs,
                 batches, freeMerged, mergedWhileOpen, staleAfterDone, cc, writes>>

Next ==
  \/ \E s \in Scopes : Publish(s) \/ ForeignTomb(s) \/ WRead(s) \/ WSend(s) \/ WSendEcho(s) \/ WSendLocal(s) \/ WSendAbsent(s) \/ WReread(s) \/ WLocal(s) \/ WErase(s) \/ WAbandon(s)
  \/ CWrite \/ Revoke \/ Restore \/ RRead \/ RInsert \/ WDone \/ IPre \/ IMerge \/ Crash

Spec == Init /\ [][Next]_vars

\* ---- invariants --------------------------------------------------------
TypeOK ==
  /\ ver \in [Scopes -> 0..MaxVer]
  /\ tombBy \in [Scopes -> {"none", "ours", "other"}]
  /\ st \in {"none", "open", "done"}
  /\ pc \in [Scopes -> {"idle", "decided", "tombed", "sent", "tombd"}]
  /\ wr \in BOOLEAN
  /\ nIntents \in 0..2

\* No importer batch merges while the intent is open.
NoLegacyMergeWhileOpen == ~mergedWhileOpen

\* A retire action never changes the current connection (control, head, records).
CurrentConnectionUntouched ==
  [][(lastActor' \in {"req", "worker", "crash"}) => cc' = cc]_vars

\* Done means every bound head is confirmed tombstoned and its blobs are erased.
\* Its local copy is gone through the pinned tombstone too: the remote state alone
\* does not say so (a process that stopped after the tombstone left it behind).
DoneOnlyAfterConfirm ==
  st = "done" => \A s \in Scopes : tomb[s] /\ erased[s] /\ localTo[s] = pins[s] + 1

\* A restart or a repeat never makes a second intent.
OneIntent == nIntents <= 1

\* A tombstone of ours is never written over a head that moved since the pin.
NoTombstoneOverMovedHead ==
  \A s \in Scopes : (tombBy[s] = "ours") => tombVer[s] = pins[s] + 1

\* A scope's blobs are erased only for the tombstone that follows the pinned head
\* (the erase frees every slot up to the tombstone, so a later one frees slots
\* the pin never named).
NoEraseOfUnpinnedVersion ==
  \A s \in Scopes :
    /\ erased[s] => tombVer[s] = pins[s] + 1
    /\ cleanTo[s] \in {0, pins[s] + 1}
    /\ localTo[s] \in {0, pins[s] + 1}

\* No destructive step (tombstone post, queue write, local erase, storage delete,
\* done verdict) ran while the host had no write authority.
NoDestructiveWithoutAuthority == ~unauth

\* A retired scope stays refused: no batch merges a bound scope once the intent
\* is done (a batch read before the retirement finished would bring back what it
\* deleted).
NoStaleMergeAfterDone == ~staleAfterDone

\* Reachability probes: each config must FAIL, which proves the path is reachable.
NotDone == st /= "done"
NotBlocked == \A s \in Scopes : ~blk[s]
NotFreeMergedAfterDone == ~freeMerged   \* an unbound stream still imports after done
NotBlockedByForeignTomb == \A s \in Scopes : ~(blk[s] /\ tombBy[s] = "other")
=============================================================================
