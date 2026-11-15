------------------------------ MODULE XConnBatch ------------------------------
(*
  One sync cycle commits the dirty streams of several connections to the
  registry in as few batch requests as the gateway's bound allows.

  Registry. A stream owns two rows, `head` and `pos`. Every writer moves both
  rows of a stream in one request, so they stay at one version (StreamLockstep).
  A connection owns a control row `ctrl[c]`; `FALSE` is a deleted connection.

  One batch request is one gateway transaction over a set `K` of rows, which
  can name rows of several connections:
    - `requires`: every connection of `K` must have `ctrl[c]`; if one does
      not, nothing is written (all or nothing, `reqMode = "txn"`).
    - per-row compare-and-set: a row is written only if its version is the one
      the cycle planned over (`planV`); a refused row is skipped and its
      siblings still commit.
  The cycle sends the streams it planned as a sequence of requests, each with
  at most `B` rows (`B` is the gateway's advertised bound). A request holds
  whole streams (`MidStream = FALSE`).

  Other writers: `OtherWrite(s)` moves both rows of a stream in their own
  request (guarded by the same control row); `Delete(c)` deletes a connection.

  A reader takes a snapshot of every row in one statement, so each state of
  the model is a possible snapshot. Visibility is a version comparison:
  `reg[r] >= v` means a snapshot of that state sees the write of version `v`.

  Switches (each one is a mutant when it is not the shipped setting)
    AtomicApply  TRUE: a request's writes appear in one step. FALSE: one row
                 per step (a gateway that does not use one transaction).
    MidStream    FALSE: a request holds whole streams. TRUE: the cycle splits
                 at the row bound, so the two rows of a stream may travel in
                 different requests.
    reqMode      "txn" | "perConn" (conditions judged per connection, the
                 writes of the connections that pass stay) | "none" (no
                 conditions).

  Invariants
    CommitAtomic          if a snapshot sees any write of a request it sees
                          every write of that request (across connections).
    StreamLockstep        no snapshot shows a stream's head and pos at
                          different versions (no partial stream).
    NoMidStreamSplit      every request the cycle sends holds both rows of each
                          stream it names.
    RequiresAllOrNothing  a request whose conditions failed wrote nothing.
    NoWriteAfterDelete    a deleted connection's rows never move again.
  Reach checks (expected to be VIOLATED, to show the property is not vacuous):
    NoCrossConnWrite      no request wrote rows of two connections.
    NoSplitCycle          no cycle needed more than one request.
*)
EXTENDS Naturals, FiniteSets

CONSTANTS B, MaxV, AtomicApply, MidStream, reqMode

Conns == {"a", "b"}
Streams == {"s1", "s2", "s3"}
ConnOf == [s \in Streams |-> IF s = "s3" THEN "b" ELSE "a"]
Rows == Streams \X {"head", "pos"}
connOf(r) == ConnOf[r[1]]
RowsOf(T) == {r \in Rows : r[1] \in T}
StreamsIn(S) == {r[1] : r \in S}

ASSUME B \in Nat /\ B >= 2 /\ MaxV \in Nat /\ reqMode \in {"txn", "perConn", "none"}

VARIABLES reg, ctrl, frozen, planV, remaining, phase, hist, sent, inflight

vars == <<reg, ctrl, frozen, planV, remaining, phase, hist, sent, inflight>>

Init ==
  /\ reg = [r \in Rows |-> 0]
  /\ ctrl = [c \in Conns |-> TRUE]
  /\ frozen = [r \in Rows |-> 0]
  /\ planV = [s \in Streams |-> 0]
  /\ remaining = {}
  /\ phase = "idle"
  /\ hist = {}
  /\ sent = {}
  /\ inflight = {}

\* The cycle snapshots every stream's version and queues all rows.
Plan ==
  /\ phase = "idle"
  /\ planV' = [s \in Streams |-> reg[<<s, "head">>]]
  /\ remaining' = Rows
  /\ phase' = "sending"
  /\ UNCHANGED <<reg, ctrl, frozen, hist, sent, inflight>>

\* The next request: whole streams, or (mutant) any rows, at most B of them.
Cands ==
  IF MidStream
  THEN {K \in SUBSET remaining : K /= {} /\ Cardinality(K) <= B}
  ELSE {RowsOf(T) : T \in {T2 \in SUBSET StreamsIn(remaining) :
                            T2 /= {} /\ Cardinality(RowsOf(T2)) <= B}}

ConnsOf(K) == {connOf(r) : r \in K}

Pairs(W) == {[row |-> r, ver |-> reg[r] + 1] : r \in W}

Send ==
  /\ phase = "sending"
  /\ inflight = {}
  /\ remaining /= {}
  /\ \E K \in Cands :
       LET cas(r) == reg[r] = planV[r[1]] /\ reg[r] < MaxV
           condOk == \A c \in ConnsOf(K) : ctrl[c]
           W == CASE reqMode = "txn"     -> IF condOk THEN {r \in K : cas(r)} ELSE {}
                  [] reqMode = "perConn" -> {r \in K : ctrl[connOf(r)] /\ cas(r)}
                  [] OTHER               -> {r \in K : cas(r)}
           failed == reqMode /= "none" /\ ~condOk
           one == CHOOSE x \in W : TRUE
       IN /\ remaining' = remaining \ K
          /\ sent' = sent \cup {[rows |-> K, W |-> W, reqFail |-> failed]}
          /\ hist' = IF W = {} THEN hist ELSE hist \cup {Pairs(W)}
          /\ IF AtomicApply \/ W = {}
               THEN /\ reg' = [r \in Rows |-> IF r \in W THEN reg[r] + 1 ELSE reg[r]]
                    /\ inflight' = {}
               ELSE /\ reg' = [r \in Rows |-> IF r = one THEN reg[r] + 1 ELSE reg[r]]
                    /\ inflight' = W \ {one}
          /\ UNCHANGED <<ctrl, frozen, planV, phase>>

\* Without AtomicApply the gateway lands the rest of a request one row at a time.
Land ==
  /\ inflight /= {}
  /\ \E x \in inflight :
       /\ reg' = [r \in Rows |-> IF r = x THEN reg[r] + 1 ELSE reg[r]]
       /\ inflight' = inflight \ {x}
  /\ UNCHANGED <<ctrl, frozen, planV, remaining, phase, hist, sent>>

OtherWrite(s) ==
  /\ ctrl[ConnOf[s]]
  /\ reg[<<s, "head">>] = reg[<<s, "pos">>]
  /\ reg[<<s, "head">>] < MaxV
  /\ reg' = [r \in Rows |-> IF r[1] = s THEN reg[r] + 1 ELSE reg[r]]
  /\ hist' = hist \cup {{[row |-> <<s, "head">>, ver |-> reg[<<s, "head">>] + 1],
                         [row |-> <<s, "pos">>,  ver |-> reg[<<s, "pos">>] + 1]}}
  /\ UNCHANGED <<ctrl, frozen, planV, remaining, phase, sent, inflight>>

Delete(c) ==
  /\ ctrl[c]
  /\ ctrl' = [x \in Conns |-> IF x = c THEN FALSE ELSE ctrl[x]]
  /\ frozen' = [r \in Rows |-> IF connOf(r) = c THEN reg[r] ELSE frozen[r]]
  /\ UNCHANGED <<reg, planV, remaining, phase, hist, sent, inflight>>

Finish ==
  /\ phase = "sending" /\ remaining = {} /\ inflight = {}
  /\ phase' = "done"
  /\ UNCHANGED <<reg, ctrl, frozen, planV, remaining, hist, sent, inflight>>

Idle == phase = "done" /\ UNCHANGED vars

Next ==
  \/ Plan \/ Send \/ Land
  \/ \E s \in Streams : OtherWrite(s)
  \/ \E c \in Conns : Delete(c)
  \/ Finish \/ Idle

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ reg \in [Rows -> 0..MaxV]
  /\ ctrl \in [Conns -> BOOLEAN]
  /\ phase \in {"idle", "sending", "done"}

\* A snapshot that sees one write of a request sees all of them.
CommitAtomic ==
  \A k \in hist :
    (\E p \in k : reg[p.row] >= p.ver) => (\A q \in k : reg[q.row] >= q.ver)

StreamLockstep == \A s \in Streams : reg[<<s, "head">>] = reg[<<s, "pos">>]

NoMidStreamSplit ==
  \A k \in sent : \A r \in k.rows :
    <<r[1], "head">> \in k.rows /\ <<r[1], "pos">> \in k.rows

RequiresAllOrNothing == \A k \in sent : k.reqFail => k.W = {}

NoWriteAfterDelete ==
  \A r \in Rows : ~ctrl[connOf(r)] => reg[r] = frozen[r]

\* Reach checks.
NoCrossConnWrite == \A k \in sent : Cardinality(ConnsOf(k.W)) <= 1
NoSplitCycle == Cardinality(sent) <= 1
=============================================================================
