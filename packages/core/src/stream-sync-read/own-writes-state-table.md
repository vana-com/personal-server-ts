# Own-writes state table

What the reader shows for a person's own collected runs, in every state a run
can be in. `own-writes-state-table.test.ts` drives the real writer and reads
through its overlay source for every row. The test checks that this
document's outcome columns equal the test's expectations, so the table and
the test change together.

## Rules (every row)

1. **One owner decides.** The writer's publish plan
   (`stream-sync/publish-plan.ts`) decides what each retained run does: it
   publishes (with the head it leaves and the rows that head holds), is a
   no-op, is refused, or is deferred. The writer executes the same step when
   it publishes. The reader reads the plan and decides nothing about
   publication. The test checks, pass after pass until no pass changes
   anything, that the head the plan predicts is the head the writer
   registers.
2. **Shown = the plan's result, or less with a marker.** A run the plan
   refuses or defers is withheld with the plan's reason. A deferred run holds
   back every later run of its stream (`earlier_run_pending`).
3. **The owner never reads fewer records than a grant of the same stream.**
   Every key a grant reads, the owner reads; its payload may be newer. So a
   run that replaces the imported base (a key reset) is withheld
   (`key_reset_pending`) until the reader imports it, and the owner keeps the
   base, marked incomplete. A run whose publish merges seed rows the overlay
   does not hold is withheld too (`seed_pending`, or `seed_unresolved` while
   admission has not decided the seed).
4. **Partial views are marked.** When no complete view serves, the owner reads
   the live imported heads, complete or not, with the runs the plan shows on
   them: `"origin":"local-pending"` and `"complete"` in the body,
   `X-Stream-Sync-Origin` and `X-Stream-Sync-Complete` in the headers. A
   deferred run makes the view incomplete; a refused run does not, since it
   changes nothing the writer publishes.
5. **The owner is told; a grant is not.** Withheld runs ride every owner
   response (`X-Stream-Sync-Withheld` with the reasons, and the `withheld`
   body field) on a served view, the legacy body, the missing-body contract
   error and the named-connection refusal. A grant reads only published data
   and gets no marker on any path.
6. **A stored body answers the owner exactly where it answers a grant.** If a
   grant reads a published view, so does the owner, whatever is pending: no
   legacy body over a pending key reset. Otherwise the stored body answers
   both, and the owner is told `X-Stream-Sync-Pending`: U. This holds even
   when the owner's own view is complete (D5, N1): a predicted head does not
   contain a different stored body. The test checks it over HTTP with a stored
   record that shares no key with the rows, before the writer publishes, after
   one pass the reader has not imported, and after the import.
7. **U counts distinct unpublished runs**: runs with a requested stream that
   has no publish receipt, with or without records, shown or withheld. A run
   counts once across streams; a run with receipts on every requested stream
   counts zero.
8. **Every stream of a legacy name is scanned.** A run withheld on one stream
   is reported even when another stream has no local run. When the projector
   refuses a partial input, no partial view serves and the answer that does
   carries the markers, and every run the view would have shown is withheld
   `projection_unavailable`. Its rows stay in the raw `pdpp.<connector>.<stream>`
   stream. A stored body answers without projecting, so it carries no such
   marker (the pending count tells the owner).

## Writer policies the rows exercise

- **Version floor** (V1, S6, S7, S9, S10, A2, A3, B2): a run from a connector
  older than every version that ran on the stream on this writer is refused
  (`connector_update_required`) whatever it changes, so the published profile
  never goes back. A changed key is accepted only from a connector newer than
  that floor. The floor never goes down; a no-op counts.
- **Commit order** (O1, S7, A2, A3): runs commit by (observedAt, runId). A run
  older than the newest commit on the stream is refused `out_of_order`, and it
  stays retained with that marker.
- **Re-projection** (R1, S10): a step that changes the primary key or the
  projector profile publishes even when no row changes.
- **Full runs merge** (F1): a same-key full run keeps base rows it does not
  deliver, as the legacy path does.

## Rows

Base: an imported complete head, key `id`, rows `a`, `b` (`v` 1), version
`1.0.0`, unless the row says otherwise. "Before" is before the writer
publishes; "after" is after it publishes until stable and the reader imports.
Rows list keys; `a@2` is row `a` with `v` 2. `—` = no view serves; `∅` = an
empty view. Withheld lists `run:reason`. U is the pending count the legacy
body carries; it is observable only where the stored body answers (rule 6).
S11 to S13 replace earlier rows for descriptor fields that the plan made
obsolete.

| Row | Setup (local runs, in commit order)                                                                                          | Writer does (until stable)                               | Owner before | Complete | Withheld                                                      | Owner after | Complete after | Withheld after                                                | Grant before | Grant after | U   |
| --- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------ | -------- | ------------------------------------------------------------- | ----------- | -------------- | ------------------------------------------------------------- | ------------ | ----------- | --- |
| S1  | same key, new row `c`                                                                                                        | publishes; head `a b c` complete                         | `a b c`      | yes      | none                                                          | `a b c`     | yes            | none                                                          | `a b`        | `a b c`     | 1   |
| S2  | same key and profile, no record                                                                                              | no-op                                                    | `a b`        | yes      | none                                                          | `a b`       | yes            | none                                                          | `a b`        | `a b`       | 1   |
| S3  | newer connector `2.0.0`, key `uid`, full                                                                                     | replaces the base; head `u1` complete                    | `a b`        | no       | `r1:key_reset_pending`                                        | `u1`        | yes            | none                                                          | `a b`        | `u1`        | 1   |
| S4  | newer connector `2.0.0`, key `uid`, partial                                                                                  | replaces the base; head `u1` incomplete                  | `a b`        | no       | `r1:key_reset_pending`                                        | `u1`        | no             | none                                                          | `a b`        | —           | 1   |
| S5  | resumed from another namespace, row `c`                                                                                      | merges; head `a b c` incomplete                          | `a b c`      | no       | none                                                          | `a b c`     | no             | none                                                          | `a b`        | —           | 1   |
| S6  | base `2.0.0`; older connector `1.0.0`, key `uid`, full                                                                       | refuses (below the floor)                                | `a b`        | yes      | `r1:connector_update_required`                                | `a b`       | yes            | `r1:connector_update_required`                                | `a b`        | `a b`       | 1   |
| S7  | base `2.0.0`; A `id 2.0.0` row `x`; B `uid 2.0.0` full; C `id 2.0.0` full row `z`                                            | A, C publish; B refused, then out of order               | `a b x z`    | yes      | `rB:connector_update_required`                                | `a b x z`   | yes            | `rB:out_of_order`                                             | `a b`        | `a b x z`   | 3   |
| S8  | `uid 2.0.0` full `u1`, then `id 3.0.0` full `c`                                                                              | both reset the head; head `c` complete                   | `a b`        | no       | `r1:key_reset_pending` `r2:earlier_run_pending`               | `c`         | yes            | none                                                          | `a b`        | `c`         | 2   |
| S9  | base `2.0.0`; empty `id 1.0.0`; `uid 1.5.0` full                                                                             | refuses both (below the floor `2.0.0`)                   | `a b`        | yes      | `r1:connector_update_required` `r2:connector_update_required` | `a b`       | yes            | `r1:connector_update_required` `r2:connector_update_required` | `a b`        | `a b`       | 2   |
| S10 | base `2.0.0`; empty `id 3.0.0`; `uid 2.5.0` full                                                                             | re-projects to `3.0.0`; refuses (floor `3.0.0`)          | `a b`        | yes      | `r2:connector_update_required`                                | `a b`       | yes            | `r2:connector_update_required`                                | `a b`        | `a b`       | 2   |
| S11 | base `2.0.0`; `id 3.0.0` row `c`; `uid 3.5.0` full                                                                           | merges, then replaces; head `u1` complete                | `a b c`      | no       | `r2:key_reset_pending`                                        | `u1`        | yes            | none                                                          | `a b`        | `u1`        | 2   |
| S12 | resumed from another namespace, row `a` v2                                                                                   | merges; head `a@2 b` incomplete                          | `a@2 b`      | no       | none                                                          | `a@2 b`     | no             | none                                                          | `a b`        | —           | 1   |
| S13 | ordinary incremental, newer connector `2.0.0`, row `c`                                                                       | merges; head `a b c` complete                            | `a b c`      | yes      | none                                                          | `a b c`     | yes            | none                                                          | `a b`        | `a b c`     | 1   |
| S14 | incomplete imported base `2.0.0`; `uid 1.0.0` full                                                                           | refuses                                                  | `a b`        | no       | `r1:connector_update_required`                                | `a b`       | no             | `r1:connector_update_required`                                | —            | —           | 1   |
| S15 | no base; seed merged at first publish; row `c`                                                                               | publishes seed and `c`, complete                         | —            | —        | `r1:seed_unresolved`                                          | `c seed`    | yes            | none                                                          | —            | `c seed`    | 1   |
| A2  | base `2.0.0`; A empty `id 2.0.0`; B `uid 2.0.0` full; C `id 2.0.0` full row `z`                                              | A no-op, C merges; B refused, then out of order          | `a b z`      | yes      | `rB:connector_update_required`                                | `a b z`     | yes            | `rB:out_of_order`                                             | `a b`        | `a b z`     | 3   |
| A3  | as A2, C empty                                                                                                               | A, C no-op; B refused, then out of order                 | `a b`        | yes      | `rB:connector_update_required`                                | `a b`       | yes            | `rB:out_of_order`                                             | `a b`        | `a b`       | 3   |
| B2  | base `2.0.0`; X `uid 3.0.0` full; Y `id 3.0.0` full                                                                          | X replaces; Y refused (equal version)                    | `a b`        | no       | `rX:key_reset_pending` `rY:connector_update_required`         | `u1`        | yes            | `rY:connector_update_required`                                | `a b`        | `u1`        | 2   |
| C3  | full stream read from another namespace's checkpoint, row `c`                                                                | merges; incomplete                                       | `a b c`      | no       | none                                                          | `a b c`     | no             | none                                                          | `a b`        | —           | 1   |
| D2  | empty, same key, another namespace's checkpoint                                                                              | publishes incomplete (completeness changes)              | `a b`        | no       | none                                                          | `a b`       | no             | none                                                          | `a b`        | —           | 1   |
| D3  | empty, newer `uid 2.0.0`, full                                                                                               | publishes an empty head, complete                        | `a b`        | no       | `rX:key_reset_pending`                                        | ∅           | yes            | none                                                          | `a b`        | ∅           | 1   |
| D4  | base `2.0.0`; empty, older `uid 1.0.0`, full                                                                                 | refuses                                                  | `a b`        | yes      | `rX:connector_update_required`                                | `a b`       | yes            | `rX:connector_update_required`                                | `a b`        | `a b`       | 1   |
| D5  | incomplete base; empty full run                                                                                              | publishes complete                                       | `a b`        | yes      | none                                                          | `a b`       | yes            | none                                                          | —            | `a b`       | 1   |
| N1  | no imported base; full run, row `c`                                                                                          | publishes `c`, complete                                  | `c`          | yes      | none                                                          | `c`         | yes            | none                                                          | —            | `c`         | 1   |
| D6  | another device's newer head `a b`; older local row `a` v0                                                                    | no-op (every row loses)                                  | `a b`        | yes      | none                                                          | `a b`       | yes            | none                                                          | `a b`        | `a b`       | 1   |
| P2  | another device's incomplete head; empty run, published, not imported                                                         | no-op                                                    | `a b`        | no       | none                                                          | `a b`       | no             | none                                                          | —            | —           | 0   |
| E2  | no base; seed; empty run                                                                                                     | publishes the seed, complete                             | —            | —        | `rE:seed_unresolved`                                          | `seed`      | yes            | none                                                          | —            | `seed`      | 1   |
| E3  | no base; seed of `items`; run delivers only `other`                                                                          | publishes the seed on `items`                            | —            | —        | none                                                          | `seed`      | yes            | none                                                          | —            | `seed`      | 0   |
| E4  | no base; seed of `items` (key `uid`, `3.0.0`); A delivers only `other`; B delivers `items` (key `id`, `3.0.0`) full, row `d` | publishes the seed on `items`; refuses B (equal version) | —            | —        | `rB:seed_unresolved`                                          | `s1`        | yes            | `rB:connector_update_required`                                | —            | `s1`        | 1   |
| F1  | same key, full run with row `a` v2 only                                                                                      | merges; `b` stays                                        | `a@2 b`      | yes      | none                                                          | `a@2 b`     | yes            | none                                                          | `a b`        | `a@2 b`     | 1   |
| V1  | `id 3.0.0` row `c`; `id 2.0.0` row `d`; `uid 2.5.0` full                                                                     | merges `c`; refuses the other two (floor `3.0.0`)        | `a b c`      | yes      | `r2:connector_update_required` `r3:connector_update_required` | `a b c`     | yes            | `r2:connector_update_required` `r3:connector_update_required` | `a b`        | `a b c`     | 3   |
| O1  | a run stamped before the base's commit, row `c`                                                                              | refuses (out of order)                                   | `a b`        | yes      | `r1:out_of_order`                                             | `a b`       | yes            | `r1:out_of_order`                                             | `a b`        | `a b`       | 1   |
| R1  | empty run, profile `1.1.0`                                                                                                   | re-projects to `1.1.0`                                   | `a b`        | yes      | none                                                          | `a b`       | yes            | none                                                          | `a b`        | `a b`       | 1   |
| S16 | legacy name over `posts` + `post_likes`, both bases incomplete; refused run on `post_likes`                                  | refuses                                                  | —            | —        | `r1:connector_update_required`                                | —           | —              | `r1:connector_update_required`                                | —            | —           | 1   |
| S17 | as S16, a refused run on each stream                                                                                         | refuses both                                             | —            | —        | `r1:connector_update_required` `r2:connector_update_required` | —           | —              | `r1:connector_update_required` `r2:connector_update_required` | —            | —           | 2   |
| M1  | as S16, one run refused on both streams                                                                                      | refuses both streams of the run                          | —            | —        | `r1:connector_update_required` `r1:connector_update_required` | —           | —              | `r1:connector_update_required` `r1:connector_update_required` | —            | —           | 1   |
| M2  | as S16, one run: `posts` publishes, `post_likes` refused; published, not imported                                            | publishes one stream, refuses the other                  | —            | —        | `r1:connector_update_required` `r1:projection_unavailable`    | —           | —              | `r1:connector_update_required`                                | —            | —           | 1   |

Oracle cases this table covers: A2, A3, B2, C3, D2 to D6, P2, E2, E3, F1, one
run across two streams (M1) and a mixed-state run (M2). Where the oracle's
conservative view showed no rows for a pending key reset, rule 3 keeps the
base instead.

- **E3** is a contract boundary: before the first publish the overlay does not
  list a stream that only a seed fills, so the owner reads no view and no
  marker. The seed is decided when the writer admits the first run.
- **E4** is what that publish leaves behind. Once the writer has committed a
  seed-only stream, the overlay lists it by metadata (no rows) and keeps its
  executed plan step until the reader imports it, so a later run meets the
  head the writer's registry holds. After one publish pass and before the
  import, the owner reads no view; `rA:seed_pending` and
  `rB:connector_update_required` are withheld (B changes the key at the
  seed's version, so the writer refuses it).
- **M1** reports the run once per stream it is withheld on; it counts once in
  U.

## Response paths (every row)

| Path                            | No view serves                                             | A view serves                                                         |
| ------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| No stored body, no `connection` | `404` contract error, with the owner's markers             | `200` view, with the owner's markers                                  |
| Stored body                     | `200` legacy body, with the owner's markers and U (rule 6) | `200` view, when a grant reads a view or the owner's view is complete |
| `connection=` named             | `404 CONNECTION_NOT_FOUND`, with the owner's markers       | `200` view                                                            |

Grant on any path: the same status, no marker. Other tests in this file cover
the cases that need more than one read: a pending view's cursor
goes stale once a new head is imported; the owner keeps reading an
incomplete head's rows after its run is retired; a stored body never
answers the owner over a pending key reset.
