---- MODULE AccountGate ----
\* "Off then On must reach sync".
\* The Account answer is (state, generation). Two hosts share one Personal Server (PS), for example a
\* Desktop app and a second window, or a tab and the embed frame. Each host stores the last answer it read
\* (Off, On or unknown), re-reads it at start, at each attempt and on account-change signals, and posts every
\* answer to the PS first. The PS record latches On at a generation; a higher generation replaces it.
\* A failed read gives unknown and never Off. A stored Off older than B does not admit a legacy write.
EXTENDS Naturals, FiniteSets

Hosts == {"h1", "h2"}
CONSTANTS MaxReset, MaxFail
CONSTANTS
  RereadAfterCleanOff,  \* TRUE r5.2; FALSE = STOP_POLLING_AFTER_CLEAN_OFF
  CheckAtCommit,        \* TRUE r5.2 (PS refuses a legacy commit under On); FALSE = CHECK_AT_ADMISSION_ONLY
  FailGivesUnknown,     \* TRUE r5.2; FALSE = REREAD_FAILURE_MINTS_OFF
  StaleOffBlocks        \* TRUE r5.2; FALSE = RETIMESTAMP_CACHED_OFF (a cached Off admits after B)

VARIABLES acct, agen, nreset, psS, psG, hS, hG, fresh, clean, infl, runG, nfail, bad, staleAdm, ncommit
vars == <<acct, agen, nreset, psS, psG, hS, hG, fresh, clean, infl, runG, nfail, bad, staleAdm, ncommit>>

Init == /\ acct = "Off" /\ agen = 1 /\ nreset = 0
        /\ psS = "Off" /\ psG = 1
        /\ hS \in [Hosts -> {"Off", "unknown"}] /\ hG = [h \in Hosts |-> 1]
        /\ fresh = [h \in Hosts |-> TRUE] /\ clean = [h \in Hosts |-> TRUE]
        /\ infl = [h \in Hosts |-> FALSE] /\ runG = [h \in Hosts |-> 0]
        /\ nfail = 0 /\ bad = FALSE /\ staleAdm = FALSE /\ ncommit = 0

\* PS record rule (L1, PS #605): a lower generation is ignored; a higher one replaces; at the same
\* generation On latches and a later Off is ignored.
PsPost(s, g) == IF g < psG THEN <<psS, psG>>
                ELSE IF g > psG THEN <<s, g>>
                ELSE IF psS = "On" THEN <<psS, psG>> ELSE <<s, g>>

\* Environment.
TurnOn == /\ acct = "Off" /\ acct' = "On"
          /\ UNCHANGED <<agen, nreset, psS, psG, hS, hG, fresh, clean, infl, runG, nfail, bad, staleAdm, ncommit>>
DevReset == /\ nreset < MaxReset /\ acct = "On" /\ acct' = "Off" /\ agen' = agen + 1 /\ nreset' = nreset + 1
            /\ UNCHANGED <<psS, psG, hS, hG, fresh, clean, infl, runG, nfail, bad, staleAdm, ncommit>>
Tick(h) == /\ fresh[h] /\ fresh' = [fresh EXCEPT ![h] = FALSE]
           /\ UNCHANGED <<acct, agen, nreset, psS, psG, hS, hG, clean, infl, runG, nfail, bad, staleAdm, ncommit>>

\* A successful read: the host posts the answer to the PS first, then cancels its own legacy run if On.
RereadOK(h) ==
  /\ (RereadAfterCleanOff \/ ~(hS[h] = "Off" /\ clean[h]))
  /\ hS' = [hS EXCEPT ![h] = acct] /\ hG' = [hG EXCEPT ![h] = agen]
  /\ fresh' = [fresh EXCEPT ![h] = TRUE] /\ clean' = [clean EXCEPT ![h] = TRUE]
  /\ psS' = PsPost(acct, agen)[1] /\ psG' = PsPost(acct, agen)[2]
  /\ infl' = [infl EXCEPT ![h] = IF acct = "On" THEN FALSE ELSE infl[h]]
  /\ UNCHANGED <<acct, agen, nreset, runG, nfail, bad, staleAdm, ncommit>>
RereadFail(h) ==
  /\ nfail < MaxFail /\ (RereadAfterCleanOff \/ ~(hS[h] = "Off" /\ clean[h]))
  /\ nfail' = nfail + 1
  /\ IF FailGivesUnknown
       THEN /\ hS' = [hS EXCEPT ![h] = IF hS[h] = "On" THEN "On" ELSE "unknown"] /\ UNCHANGED <<fresh, clean>>
       ELSE /\ hS' = [hS EXCEPT ![h] = "Off"] /\ fresh' = [fresh EXCEPT ![h] = TRUE] /\ clean' = [clean EXCEPT ![h] = FALSE]
  /\ UNCHANGED <<acct, agen, nreset, psS, psG, hG, infl, runG, bad, staleAdm, ncommit>>

\* A legacy run is admitted on a stored Off; the commit is a separate later step (the read-to-send gap).
Admit(h) ==
  /\ ncommit < 2 /\ ~infl[h] /\ hS[h] = "Off" /\ (fresh[h] \/ ~StaleOffBlocks)
  /\ infl' = [infl EXCEPT ![h] = TRUE] /\ runG' = [runG EXCEPT ![h] = hG[h]]
  /\ staleAdm' = (staleAdm \/ ~fresh[h])
  /\ UNCHANGED <<acct, agen, nreset, psS, psG, hS, hG, fresh, clean, nfail, bad, ncommit>>
Commit(h) ==
  /\ infl[h]
  /\ LET fenced == psS = "On" /\ psG >= runG[h] IN
     /\ bad' = (bad \/ (fenced /\ ~CheckAtCommit))        \* a legacy commit after the PS holds On
     /\ ncommit' = IF fenced /\ CheckAtCommit THEN ncommit ELSE ncommit + 1
  /\ infl' = [infl EXCEPT ![h] = FALSE]
  /\ UNCHANGED <<acct, agen, nreset, psS, psG, hS, hG, fresh, clean, runG, nfail, staleAdm>>

Next == UNCHANGED vars \/ TurnOn \/ DevReset \/ \E h \in Hosts : Tick(h) \/ RereadOK(h) \/ RereadFail(h) \/ Admit(h) \/ Commit(h)
Spec == Init /\ [][Next]_vars /\ WF_vars(TurnOn) /\ \A h \in Hosts : WF_vars(RereadOK(h)) /\ WF_vars(Commit(h))

TypeOK == acct \in {"Off", "On"} /\ \A h \in Hosts : hS[h] \in {"Off", "On", "unknown"}
\* Safety (b): no legacy commit after the PS holds On at the same or a higher generation.
NoLegacyAfterOn == ~bad
\* An Off older than B never admits a legacy write.
NoStaleAdmit == ~staleAdm
\* (c) a stored Off always comes from a read that returned Off, never from a failed read.
FailNeverOff == \A h \in Hosts : clean[h]
\* Liveness (a)+(d): the Account ends On at its last generation, and every host then syncs through streams.
Final == <>[](acct = "On" /\ \A h \in Hosts : hS[h] = "On" /\ hG[h] = agen)
Live == \A h \in Hosts : (acct = "On") ~> (hS[h] = "On" /\ hG[h] = agen)
====
