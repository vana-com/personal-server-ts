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
EXTENDS Naturals, FiniteSets

CONSTANTS Scopes,     \* the bound legacy scopes
          MaxVer,     \* the highest gateway version
          MaxReq,     \* the most owner requests
          MaxB,       \* the most import batches
          MaxCrash,   \* the most restarts
          MaxW,       \* the most current-connection writes
          Mode

VARIABLES
  ver, tomb, tombBy, tombVer,   \* gateway head per scope
  erased,                       \* blobs of the scope are gone (confirmed)
  exists, st, pins, nIntents,   \* the intent row(s)
  pc, snap, blk,                \* worker per scope
  rpc, rsnap, reqs,             \* request
  ipc, batches, sawIntent,      \* importer
  mergedWhileOpen, staleAfterDone,
  cc, writes,                   \* the current connection
  crashes, lastActor

vars == <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents,
          pc, snap, blk, rpc, rsnap, reqs, ipc, batches, sawIntent,
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
  /\ exists = FALSE /\ st = "none" /\ nIntents = 0
  /\ pins = [s \in Scopes |-> 0]
  /\ pc = [s \in Scopes |-> "idle"]
  /\ snap = [s \in Scopes |-> 0]
  /\ blk = [s \in Scopes |-> FALSE]
  /\ rpc = "idle" /\ rsnap = [s \in Scopes |-> 0] /\ reqs = 0
  /\ ipc = "idle" /\ batches = 0 /\ sawIntent = FALSE
  /\ mergedWhileOpen = FALSE /\ staleAfterDone = FALSE
  /\ cc = [control |-> "active", head |-> 0, records |-> 0] /\ writes = 0
  /\ crashes = 0 /\ lastActor = "init"

\* ---- gateway: another writer -------------------------------------------
Publish(s) ==
  /\ ~tomb[s] /\ ver[s] < MaxVer
  /\ ver' = [ver EXCEPT ![s] = @ + 1]
  /\ lastActor' = "gateway"
  /\ UNCHANGED <<tomb, tombBy, tombVer, erased, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

ForeignTomb(s) ==
  /\ ~tomb[s]
  /\ tomb' = [tomb EXCEPT ![s] = TRUE]
  /\ tombBy' = [tombBy EXCEPT ![s] = "other"]
  /\ tombVer' = [tombVer EXCEPT ![s] = ver[s] + 1]
  /\ lastActor' = "gateway"
  /\ UNCHANGED <<ver, erased, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* ---- current-connection writer (stream sync) ---------------------------
CWrite ==
  /\ writes < MaxW
  /\ cc' = [cc EXCEPT !.head = @ + 1, !.records = @ + 1]
  /\ writes' = writes + 1
  /\ lastActor' = "sync"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, crashes>>

\* ---- request -----------------------------------------------------------
\* Reads every head; heads that are tombstoned at request time (a pin of a
\* deleted head) are not modelled.
RRead ==
  /\ rpc = "idle" /\ reqs < MaxReq /\ \A s \in Scopes : ~tomb[s]
  /\ rpc' = "read" /\ rsnap' = ver /\ reqs' = reqs + 1
  /\ lastActor' = "req"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents, pc, snap, blk,
                 ipc, batches, sawIntent, mergedWhileOpen, staleAfterDone,
                 cc, writes, crashes>>

\* INSERT OR IGNORE: the first row stands, a later request resumes it.
RInsert ==
  /\ rpc = "read"
  /\ rpc' = "idle"
  /\ IF exists
       THEN UNCHANGED <<exists, st, pins, nIntents>>
       ELSE /\ exists' = TRUE /\ st' = "open" /\ pins' = rsnap /\ nIntents' = nIntents + 1
  /\ lastActor' = "req"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, pc, snap, blk, rsnap, reqs,
                 ipc, batches, sawIntent, mergedWhileOpen, staleAfterDone,
                 cc, writes, crashes>>

\* ---- worker, per scope -------------------------------------------------
WRead(s) ==
  /\ Open /\ pc[s] = "idle" /\ ~blk[s] /\ ~erased[s]
  /\ snap' = [snap EXCEPT ![s] = ver[s]]
  /\ IF PinHolds(s, ~tomb[s], ver[s], tombVer[s])
       THEN /\ pc' = [pc EXCEPT ![s] = IF tomb[s] THEN "tombd" ELSE "decided"]
            /\ UNCHANGED blk
       ELSE /\ blk' = [blk EXCEPT ![s] = TRUE]   \* legacy_head_changed
            /\ UNCHANGED pc
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* The tombstone is fenced to the head the read saw: it lands only if the head is
\* still that one. A moved head refuses it; a deleted one answers "already deleted".
WSend(s) ==
  /\ pc[s] = "decided"
  /\ IF ~tomb[s] /\ ver[s] = snap[s]
       THEN /\ tomb' = [tomb EXCEPT ![s] = TRUE]
            /\ tombBy' = [tombBy EXCEPT ![s] = "ours"]
            /\ tombVer' = [tombVer EXCEPT ![s] = ver[s] + 1]
       ELSE UNCHANGED <<tomb, tombBy, tombVer>>
  /\ pc' = [pc EXCEPT ![s] = "sent"]
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, erased, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

WReread(s) ==
  /\ pc[s] = "sent"
  /\ IF ~PinHolds(s, ~tomb[s], ver[s], tombVer[s])
       THEN /\ blk' = [blk EXCEPT ![s] = TRUE] /\ pc' = [pc EXCEPT ![s] = "idle"]
       ELSE /\ UNCHANGED blk
            /\ pc' = [pc EXCEPT ![s] = IF tomb[s] THEN "tombd" ELSE "idle"]
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents, snap,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* Storage deletes every slot <= the tombstone, then answers for all of them.
WErase(s) ==
  /\ pc[s] = "tombd"
  /\ erased' = [erased EXCEPT ![s] = TRUE]
  /\ pc' = [pc EXCEPT ![s] = "idle"]
  /\ IF Mode = "touchesCurrent"
       THEN cc' = [cc EXCEPT !.head = @ + 1]
       ELSE UNCHANGED cc
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, exists, st, pins, nIntents, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, writes, crashes>>

WDone ==
  /\ Open
  /\ IF Mode = "doneBeforeErase"
       THEN \A s \in Scopes : tomb[s] /\ (erased[s] \/ pc[s] = "tombd")
       ELSE \A s \in Scopes : erased[s]
  /\ st' = "done"
  /\ lastActor' = "worker"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, ipc, batches, sawIntent, mergedWhileOpen,
                 staleAfterDone, cc, writes, crashes>>

\* ---- importer ----------------------------------------------------------
\* `importFence`: refused while the intent is open.
IPre ==
  /\ ipc = "idle" /\ batches < MaxB /\ ~Open
  /\ ipc' = "checked" /\ sawIntent' = exists
  /\ lastActor' = "importer"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, batches, mergedWhileOpen, staleAfterDone,
                 cc, writes, crashes>>

\* The merge batch. `guardImport` and the merge share one transaction (db.batch):
\* the guard's CHECK fails and the whole batch rolls back if the intent is open.
IMerge ==
  /\ ipc = "checked"
  /\ ipc' = "idle" /\ batches' = batches + 1
  /\ IF Mode = "noBatchFence" \/ ~Open
       THEN /\ cc' = [cc EXCEPT !.head = @ + 1, !.records = @ + 1]
            /\ mergedWhileOpen' = (mergedWhileOpen \/ Open)
            /\ staleAfterDone' = (staleAfterDone \/ (exists /\ st = "done" /\ ~sawIntent))
       ELSE UNCHANGED <<cc, mergedWhileOpen, staleAfterDone>>
  /\ lastActor' = "importer"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, st, pins, nIntents, pc, snap, blk,
                 rpc, rsnap, reqs, sawIntent, writes, crashes>>

\* ---- restart -----------------------------------------------------------
Crash ==
  /\ crashes < MaxCrash
  /\ crashes' = crashes + 1
  /\ pc' = [s \in Scopes |-> "idle"] /\ snap' = [s \in Scopes |-> 0]
  /\ rpc' = "idle" /\ ipc' = "idle"
  /\ IF Mode = "newIntentOnRestart" /\ Open
       THEN /\ nIntents' = nIntents + 1 /\ pins' = ver /\ st' = "open"
       ELSE UNCHANGED <<nIntents, pins, st>>
  /\ lastActor' = "crash"
  /\ UNCHANGED <<ver, tomb, tombBy, tombVer, erased, exists, blk, rsnap, reqs,
                 batches, sawIntent, mergedWhileOpen, staleAfterDone, cc, writes>>

Next ==
  \/ \E s \in Scopes : Publish(s) \/ ForeignTomb(s) \/ WRead(s) \/ WSend(s) \/ WReread(s) \/ WErase(s)
  \/ CWrite \/ RRead \/ RInsert \/ WDone \/ IPre \/ IMerge \/ Crash

Spec == Init /\ [][Next]_vars

\* ---- invariants --------------------------------------------------------
TypeOK ==
  /\ ver \in [Scopes -> 0..MaxVer]
  /\ tombBy \in [Scopes -> {"none", "ours", "other"}]
  /\ st \in {"none", "open", "done"}
  /\ pc \in [Scopes -> {"idle", "decided", "sent", "tombd"}]
  /\ nIntents \in 0..2

\* No importer batch merges while the intent is open.
NoLegacyMergeWhileOpen == ~mergedWhileOpen

\* A retire action never changes the current connection (control, head, records).
CurrentConnectionUntouched ==
  [][(lastActor' \in {"req", "worker", "crash"}) => cc' = cc]_vars

\* Done means every bound head is confirmed tombstoned and its blobs are erased.
DoneOnlyAfterConfirm == st = "done" => \A s \in Scopes : tomb[s] /\ erased[s]

\* A restart or a repeat never makes a second intent.
OneIntent == nIntents <= 1

\* A tombstone of ours is never written over a head that moved since the pin.
NoTombstoneOverMovedHead ==
  \A s \in Scopes : (tombBy[s] = "ours") => tombVer[s] = pins[s] + 1

\* A scope's blobs are erased only for the tombstone that follows the pinned head
\* (the erase frees every slot up to the tombstone, so a later one frees slots
\* the pin never named).
NoEraseOfUnpinnedVersion ==
  \A s \in Scopes : erased[s] => tombVer[s] = pins[s] + 1

\* Observation, not a requirement of the protocol: an import that passed its
\* preflight before the intent existed merges after the intent is done.
NoStaleMergeAfterDone == ~staleAfterDone

\* Reachability probes: each config must FAIL, which proves the path is reachable.
NotDone == st /= "done"
NotBlocked == \A s \in Scopes : ~blk[s]
NotBlockedByForeignTomb == \A s \in Scopes : ~(blk[s] /\ tombBy[s] = "other")
=============================================================================
