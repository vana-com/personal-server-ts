\* Who may write the account-mode record, with up to three process lifetimes
\* over one record folder. R3 = TRUE models the pid, host and rename lock, an
\* early release on close, and a corrupt record read as "never seen". R3 = FALSE
\* models the kernel-held lock, close that drains before it releases, and a
\* corrupt record read as a "history unknown" tombstone.
\*
\* Run (one job; TLC stops at the first violation, so check each invariant
\* alone to see its own witness):
\*   java -cp tla2tools.jar tlc2.TLC -workers 4 -cleanup -config AccountModeOwnerR4.cfg AccountModeOwner
\*   java -cp tla2tools.jar tlc2.TLC -workers 4 -cleanup -config AccountModeOwnerR3.cfg AccountModeOwner
\* Results: R4 passes (7,994 states generated, 1,442 distinct, depth 22). R3
\* violates each invariant when it is checked alone.
\*
\* Abstraction limits: one account, one callback and one pending save per
\* process, atomic claim/load/publish steps, "corrupt" means parse-invalid
\* bytes. Crash kills local pending work. Startup racing close, revision ABA
\* and liveness are not modelled.
---------------------- MODULE AccountModeOwner ----------------------
EXTENDS Naturals, FiniteSets, TLC
CONSTANTS Processes, NoOwner, DeadToken, R3
ASSUME /\ IsFiniteSet(Processes) /\ Cardinality(Processes) \in 1..3
       /\ NoOwner \notin Processes /\ DeadToken \notin Processes
       /\ NoOwner # DeadToken /\ R3 \in BOOLEAN
Tokens == Processes \cup {NoOwner, DeadToken}
Kinds == {"none", "legacy", "stream"}
Records == [mode : {"none", "off", "on", "bad", "unknown"}, debt : BOOLEAN]
Empty == [mode |-> "none", debt |-> FALSE]
Unknown == [mode |-> "unknown", debt |-> TRUE]
VARIABLES alive, owners, slot, closing, loaded, cache, tickets, jobs, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy
vars == <<alive, owners, slot, closing, loaded, cache, tickets, jobs, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Held(p) == p \in alive \cap owners /\ slot = p
Ready(p) == p \in alive \cap owners \cap loaded /\ p \notin closing
Allowed(p, k) == IF k = "legacy" THEN cache[p].mode = "off"
                ELSE cache[p].mode = "on" /\ ~cache[p].debt
ReadHeld(p) == jobs[p] # "none" /\ (~R3 \/ jobs[p] = "legacy")
Recovered == IF disk.mode = "bad" THEN IF R3 THEN Empty ELSE Unknown ELSE disk
NextRecord(v) == [mode |-> IF v = "off" THEN "off" ELSE "on",
                 debt |-> IF v \in {"off", "done"} THEN FALSE
                          ELSE IF disk.mode = "on" THEN disk.debt ELSE TRUE]
Init ==
  /\ alive = Processes /\ owners = {} /\ closing = {} /\ loaded = {}
  /\ slot = (IF R3 THEN DeadToken ELSE NoOwner)
  /\ cache = [p \in Processes |-> Unknown]
  /\ tickets = [p \in Processes |-> "none"] /\ jobs = tickets
  /\ saving = {} /\ writers = {} /\ saveKind = tickets
  /\ target = [p \in Processes |-> Empty] /\ disk = Empty
  /\ seen = [p \in Processes |-> NoOwner] /\ moved = seen
  /\ everOn = FALSE /\ unreadableOn = FALSE /\ debtOwed = FALSE
  /\ wrongOwner = FALSE /\ lateLegacy = FALSE
Acquire(p) ==
  /\ p \in alive \ (owners \cup closing) /\ slot = NoOwner
  /\ seen[p] = NoOwner /\ moved[p] = NoOwner /\ (R3 \/ owners = {})
  /\ owners' = owners \cup {p} /\ slot' = p /\ loaded' = loaded \ {p}
  /\ cache' = [cache EXCEPT ![p] = Unknown]
  /\ UNCHANGED <<alive, closing, tickets, jobs, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Load(p) ==
  /\ p \in alive \cap owners /\ p \notin closing \cup saving /\ jobs[p] = "none"
  /\ disk' = Recovered /\ cache' = [cache EXCEPT ![p] = Recovered]
  /\ loaded' = loaded \cup {p}
  /\ wrongOwner' = (wrongOwner \/ (disk.mode = "bad" /\ ~Held(p)))
  /\ UNCHANGED <<alive, owners, slot, closing, tickets, jobs, saving, writers, saveKind, target, seen, moved, everOn, unreadableOn, debtOwed, lateLegacy>>
Admit(p, k) ==
  /\ Ready(p) /\ k \in {"legacy", "stream"} /\ Allowed(p, k)
  /\ tickets[p] = "none" /\ jobs[p] = "none"
  /\ tickets' = [tickets EXCEPT ![p] = k]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, cache, jobs, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
BeginCommit(p) ==
  /\ Ready(p) /\ jobs[p] = "none" /\ p \notin writers
  /\ tickets[p] # "none" /\ Allowed(p, tickets[p])
  /\ jobs' = [jobs EXCEPT ![p] = tickets[p]]
  /\ tickets' = [tickets EXCEPT ![p] = "none"]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, cache, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Commit(p, k) ==
  /\ p \in alive /\ jobs[p] = k /\ k \in {"legacy", "stream"}
  /\ jobs' = [jobs EXCEPT ![p] = "none"]
  /\ wrongOwner' = (wrongOwner \/ ~Held(p))
  /\ lateLegacy' = (lateLegacy \/ (k = "legacy" /\ everOn))
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, cache, tickets, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed>>
CommitLegacy(p) == Commit(p, "legacy")
CommitStream(p) == Commit(p, "stream")
StartSave(p, v) ==
  /\ Ready(p) /\ p \notin saving \cup writers /\ ~ReadHeld(p)
  /\ v \in {"off", "on", "done"} /\ disk.mode # "bad" /\ cache[p] = disk
  /\ (v = "off" => cache[p].mode \in {"none", "off"})
  /\ (v = "done" => (cache[p].mode = "on" /\ cache[p].debt))
  /\ saving' = saving \cup {p} /\ writers' = writers \cup {p}
  /\ saveKind' = [saveKind EXCEPT ![p] = v]
  /\ target' = [target EXCEPT ![p] = NextRecord(v)]
  /\ cache' = [cache EXCEPT ![p] = Unknown]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, tickets, jobs, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
ImportDone(p) == StartSave(p, "done")
Save(p) ==
  /\ p \in alive \cap saving
  /\ disk' = target[p] /\ cache' = [cache EXCEPT ![p] = target[p]]
  /\ wrongOwner' = (wrongOwner \/ ~Held(p))
  /\ everOn' = (everOn \/ target[p].mode = "on")
  /\ debtOwed' = (IF saveKind[p] = "done" THEN FALSE ELSE debtOwed \/ target[p].debt)
  /\ saving' = saving \ {p} /\ writers' = writers \ {p}
  /\ saveKind' = [saveKind EXCEPT ![p] = "none"]
  /\ target' = [target EXCEPT ![p] = Empty]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, tickets, jobs, seen, moved, unreadableOn, lateLegacy>>
TimeoutSave(p) ==
  /\ p \in alive \cap saving \cap writers
  /\ writers' = writers \ {p} /\ cache' = [cache EXCEPT ![p] = Unknown]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, tickets, jobs, saving, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
SaveFailed(p) ==
  /\ p \in alive \cap saving
  /\ saving' = saving \ {p} /\ writers' = writers \ {p}
  /\ saveKind' = [saveKind EXCEPT ![p] = "none"]
  /\ target' = [target EXCEPT ![p] = Empty] /\ cache' = [cache EXCEPT ![p] = Unknown]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, tickets, jobs, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Close(p) ==
  /\ p \in alive \cap owners /\ p \notin closing
  /\ closing' = closing \cup {p} /\ loaded' = loaded \ {p}
  /\ cache' = [cache EXCEPT ![p] = Unknown] /\ tickets' = [tickets EXCEPT ![p] = "none"]
  /\ owners' = (IF R3 THEN owners \ {p} ELSE owners)
  /\ slot' = (IF R3 /\ slot = p THEN NoOwner ELSE slot)
  /\ UNCHANGED <<alive, jobs, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
DrainClose(p) ==
  /\ ~R3 /\ p \in alive \cap owners \cap closing
  /\ jobs[p] = "none" /\ p \notin saving \cup writers
  /\ owners' = owners \ {p} /\ slot' = (IF slot = p THEN NoOwner ELSE slot)
  /\ cache' = [cache EXCEPT ![p] = Unknown]
  /\ UNCHANGED <<alive, closing, loaded, tickets, jobs, saving, writers, saveKind, target, disk, seen, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Crash(p) ==
  /\ p \in alive
  /\ alive' = alive \ {p} /\ owners' = owners \ {p}
  /\ closing' = closing \ {p} /\ loaded' = loaded \ {p}
  /\ saving' = saving \ {p} /\ writers' = writers \ {p}
  /\ cache' = [cache EXCEPT ![p] = Unknown] /\ target' = [target EXCEPT ![p] = Empty]
  /\ tickets' = [tickets EXCEPT ![p] = "none"] /\ jobs' = [jobs EXCEPT ![p] = "none"]
  /\ saveKind' = [saveKind EXCEPT ![p] = "none"]
  /\ seen' = [seen EXCEPT ![p] = NoOwner] /\ moved' = [moved EXCEPT ![p] = NoOwner]
  /\ slot' = (IF ~R3 /\ slot = p THEN NoOwner ELSE slot)
  /\ UNCHANGED <<disk, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Corrupt ==
  /\ disk.mode \in {"off", "on", "unknown"}
  /\ disk' = [mode |-> "bad", debt |-> FALSE]
  /\ unreadableOn' = (unreadableOn \/ disk.mode = "on")
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, cache, tickets, jobs, saving, writers, saveKind, target, seen, moved, everOn, debtOwed, wrongOwner, lateLegacy>>
ReadStale(p) ==
  /\ R3 /\ p \in alive \ (owners \cup closing)
  /\ slot \in ({DeadToken} \cup (Processes \ alive))
  /\ seen[p] = NoOwner /\ moved[p] = NoOwner
  /\ seen' = [seen EXCEPT ![p] = slot]
  /\ UNCHANGED <<alive, owners, slot, closing, loaded, cache, tickets, jobs, saving, writers, saveKind, target, disk, moved, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
MoveStale(p) ==
  /\ R3 /\ p \in alive /\ seen[p] # NoOwner /\ moved[p] = NoOwner /\ slot # NoOwner
  /\ moved' = [moved EXCEPT ![p] = slot] /\ slot' = NoOwner
  /\ UNCHANGED <<alive, owners, closing, loaded, cache, tickets, jobs, saving, writers, saveKind, target, disk, seen, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
FinishMove(p) ==
  /\ R3 /\ p \in alive /\ moved[p] # NoOwner
  /\ slot' = (IF moved[p] # seen[p] /\ slot = NoOwner THEN moved[p] ELSE slot)
  /\ seen' = [seen EXCEPT ![p] = NoOwner] /\ moved' = [moved EXCEPT ![p] = NoOwner]
  /\ UNCHANGED <<alive, owners, closing, loaded, cache, tickets, jobs, saving, writers, saveKind, target, disk, everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy>>
Next ==
  \/ Corrupt
  \/ \E p \in Processes :
       \/ Acquire(p) \/ Load(p) \/ Close(p) \/ DrainClose(p) \/ Crash(p)
       \/ BeginCommit(p) \/ CommitLegacy(p) \/ CommitStream(p)
       \/ Save(p) \/ TimeoutSave(p) \/ SaveFailed(p) \/ ImportDone(p)
       \/ ReadStale(p) \/ MoveStale(p) \/ FinishMove(p)
       \/ \E k \in {"legacy", "stream"} : Admit(p, k)
       \/ \E v \in {"off", "on"} : StartSave(p, v)
Spec == Init /\ [][Next]_vars
TypeOK ==
  /\ alive \subseteq Processes /\ owners \subseteq alive
  /\ closing \subseteq alive /\ loaded \subseteq owners
  /\ writers \subseteq saving /\ saving \subseteq alive /\ slot \in Tokens
  /\ cache \in [Processes -> Records] /\ target \in [Processes -> Records]
  /\ tickets \in [Processes -> Kinds] /\ jobs \in [Processes -> Kinds]
  /\ saveKind \in [Processes -> {"none", "off", "on", "done"}]
  /\ seen \in [Processes -> Tokens] /\ moved \in [Processes -> Tokens]
  /\ disk \in Records
  /\ {everOn, unreadableOn, debtOwed, wrongOwner, lateLegacy} \subseteq BOOLEAN
OneOwner == Cardinality(owners) <= 1
NoWriteWithoutOwnership == ~wrongOwner
NoLegacyWriteAfterOn == ~lateLegacy
NoOffAfterUnreadableOn == ~(unreadableOn /\ disk.mode = "off")
ImportDebtNeverLost == debtOwed => (disk.debt \/ disk.mode = "bad")
Symmetry == Permutations(Processes)
=====================================================================

