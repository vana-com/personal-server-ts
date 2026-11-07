# Own-writes state table

What the reader shows for a person's own collected runs, in every state a run
can be in. The expected outcome of each row follows from what the writer
publishes. `own-writes-state-table.test.ts` drives the real writer and its
overlay producer for every row; this table and that test change together.

## Rules (every row)

1. **Shown = published or less.** The reader merges a run only if the writer
   publishes it from every head the writer could be in. Where the overlay
   cannot tell, the run is withheld and reported, never merged.
2. **A run the writer refuses (`connector_update_required`) is never shown.**
   It is reported as withheld until the connector is newer.
3. **The owner is told; a grant is not.** Withheld runs and the pending marker
   go to the owner on every response path. A grant reads only published data
   and receives neither header nor body field on any path.
4. **Owner diagnostics ride every owner response:** `X-Stream-Sync-Withheld`
   (header) and `withheld` (body field), on a served view, on the legacy body,
   on the missing-body contract error, and on the named-connection refusal.
   `X-Stream-Sync-Pending` rides the legacy body when pending runs hold
   records.
5. **A descriptor field the producer leaves out is read on the cautious side.**
   `recordCount` absent = the run may hold records. `incompleteOverBase` absent =
   the head is complete only by the run's own `complete`.
6. **Every stream of a legacy name is scanned.** A run withheld on one stream is
   reported even when another stream has no local run.

## Dimensions

| Dimension         | Values                                                                                                                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Run state         | published; withheld for a key change; incomplete head (view not complete); refused (`connector_update_required`)                                                                     |
| Descriptor fields | `recordCount`, `incompleteOverBase`: present (the writer emits both) or absent (a producer that emits neither)                                                                       |
| Path              | **fold** (rows, completeness, markers); **scan** (legacy name over several streams); **success response** (view, legacy body); **refusal response** (missing body, named connection) |
| Caller            | owner; grant                                                                                                                                                                         |

## Rows

Base: an imported complete head, key `id`, rows `a`, `b`, version `1.0.0`
unless the row says otherwise. "Owner reads" is before the writer publishes.
"Withheld" lists run ids reported to the owner; "after" is after the writer
publishes and the reader imports. The pending marker is the number of local runs
holding records that a legacy body does not supersede; it is sent only when the
legacy body answers, that is, when no complete view serves.

| Row | Setup (local runs, in publish order)                                                                               | Writer does                        | Owner reads: rows | Complete          | Withheld | Withheld after | Pending marker (legacy body) |
| --- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------- | ----------------- | ----------------- | -------- | -------------- | ---------------------------- |
| S1  | same key, new row `c`                                                                                              | publishes; head `a b c` complete   | `a b c`           | yes               | none     | none           | none                         |
| S2  | same key, no record                                                                                                | no-op                              | `a b`             | yes               | none     | none           | none                         |
| S3  | newer connector, key `uid`, full                                                                                   | `empty_base`; head `u1` complete   | `u1`              | yes               | none     | none           | none                         |
| S4  | newer connector, key `uid`, partial                                                                                | `empty_base`; head `u1` incomplete | `u1`              | no                | none     | none           | 1                            |
| S5  | resumed from another namespace, row `c`                                                                            | head `a b c` incomplete            | `c` (1)           | no                | none     | none           | 1                            |
| S6  | base `2.0.0`; older connector `1.0.0`, key `uid`, full                                                             | refuses                            | `a b`             | yes               | `r1`     | `r1`           | none                         |
| S7  | base `2.0.0`; A `id 1.0.0` + row `x`; B `uid 1.5.0` full; C `id 1.4.0` full                                        | publishes A, B; refuses C          | `a b x`           | yes               | `rB rC`  | `rC`           | none                         |
| S8  | `uid 2.0.0` full, then `id 3.0.0` full + row `c`                                                                   | publishes both; head `c` complete  | `c`               | yes               | none     | none           | none                         |
| S9  | base `2.0.0`; empty `1.0.0`; `uid 1.5.0` full                                                                      | no-op; refuses                     | `a b`             | yes               | `r2`     | `r2`           | none                         |
| S10 | base `2.0.0`; empty `3.0.0`; `uid 2.5.0` full                                                                      | no-op; publishes (`empty_base`)    | `u1`              | yes               | none     | none           | none                         |
| S11 | S10 with `recordCount` absent                                                                                      | as S10                             | `a b`             | yes               | `r2` (2) | none           | none                         |
| S12 | S5 with `incompleteOverBase` absent                                                                                | as S5                              | `c`               | no                | none     | none           | 1                            |
| S13 | S1 with `incompleteOverBase` absent                                                                                | as S1 (complete)                   | `a b c`           | no (3)            | none     | none           | 1                            |
| S14 | incomplete imported base `2.0.0`; `uid 1.0.0` full                                                                 | refuses                            | no view           | no                | `r1`     | `r1`           | none                         |
| S15 | no base; seed merged at first publish; row `c`                                                                     | head `c` + seed, complete          | `c`               | no connection (4) | none     | none           | 1                            |
| S16 | legacy name, streams `posts` + `post_likes`, both bases incomplete; no run on `posts`; refused run on `post_likes` | refuses                            | no view           | no                | `r1`     | `r1`           | none                         |
| S17 | as S16, refused run on each stream                                                                                 | refuses both                       | no view           | no                | `r1 r2`  | `r1 r2`        | none                         |

1. S5, S12: the head the writer publishes is incomplete, and an incomplete head
   is not a view (§2.10). The owner reads the run's own rows only; the base rows
   `a b` are not shown beside it. **Open design question**: the reader
   hides published base rows from the owner while an incomplete run is
   pending. Not decided here.
2. S11: `r2` is withheld although the writer publishes it. The reader cannot
   tell that `r1` holds no record, so it cannot tell which version the head has.
3. S13: the writer publishes a complete head; without `incompleteOverBase` the
   reader cannot tell this run from S12's and takes the incomplete side. The
   writer on this branch emits the field, so this row is for a producer that does
   not.
4. S15: no connection is imported yet. The seed is merged at publish time and is
   invisible to the overlay, so the reader makes no claim of completeness.

## Response paths (every row, owner)

| Path                            | No view serves                                             | A view serves                          |
| ------------------------------- | ---------------------------------------------------------- | -------------------------------------- |
| No stored body, no `connection` | `404` contract error, with header and `withheld`           | `200` view, with header and `withheld` |
| Stored body                     | `200` legacy body, with header, `withheld`, pending marker | `200` view                             |
| `connection=` named             | `404 CONNECTION_NOT_FOUND`, with header and `withheld`     | `200` view                             |

Grant on any path: the same status, no header, no `withheld`, no pending marker.
After publish, a grant reads the imported head the owner reads, whenever the
owner reads a view and nothing is withheld.
