# Authorization privacy tests: entry points, variants, timing, limits

Record required by PDPP Core v0.1.0 §9 AS item 55 for
`pdpp-auth-privacy.test.ts` (items 52, 54, 57) and the related cases in
`pdpp-auth-wp4.test.ts` (items 2, 53). Spec: spec-core §6 "Authorization
privacy boundary" (L1212-L1241).

## Entry points

| Entry point                                                                            | Who calls it                                             | Exercised             | Result                                                                                                                                            |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /pdpp/v1/authorize` without owner token                                          | anyone                                                   | yes                   | 401, identical across variants (status, headers, body bytes)                                                                                      |
| `POST /pdpp/v1/authorize` with a client token                                          | client                                                   | yes                   | 401, identical across variants                                                                                                                    |
| `POST /pdpp/v1/authorize` with the owner token                                         | consent broker (Account/Web) for the authenticated owner | yes                   | 201, identical shape, size and headers across variants                                                                                            |
| `GET /authorize/:id/review`                                                            | broker, owner token                                      | yes                   | owner-only: 200 (S0) or 403 `access_denied` with an owner-only explanation (S1-S4). Allowed to differ: it is inside authenticated review (L1228). |
| `POST /authorize/:id/approve`                                                          | broker, owner token                                      | yes (S1-S4)           | 403, no grant                                                                                                                                     |
| `POST /authorize/:id/deny`                                                             | broker, owner token                                      | yes                   | 200, byte-identical callback `redirect_uri` `?error=access_denied&state=…` and headers across variants                                            |
| `POST /pdpp/v1/token`, `/introspect`, `/token/revoke`                                  | client / RS                                              | not part of this case | consult no protected owner state before the code or token is presented                                                                            |
| `POST /pdpp/v1/owner/token`                                                            | owner wallet proof                                       | not exercised         | owner-facing: answers 404 for a source with no declaration and no connection. Only the authenticated owner's own broker sees it.                  |
| Pushed authorization requests, noninteractive requests, front-channel `GET /authorize` | —                                                        | n/a                   | not offered by this AS                                                                                                                            |

## Protected-state variants

One fixed request R (required stream `plays`, `view: "summary"`,
`time_range.since`) under five owner states:

| Variant | Protected state that differs                                               |
| ------- | -------------------------------------------------------------------------- |
| S0      | none: matched owner refusal (the owner declines a valid, eligible request) |
| S1      | private declaration acceptance: no declaration is accepted for the source  |
| S2      | temporal capability: the stream declares no `consent_time_field`           |
| S3      | view availability: view `summary` is not defined                           |
| S4      | instance eligibility: the required stream has no eligible instance         |

Per variant the tests check: `/authorize` status, sorted header list, JSON
shape (values reduced to types) and byte length; the session ends `denied`
and no grant or code is issued; the client callback after the interaction
concludes is byte-identical to S0's.

## Timing method

- In-process, around `app.request(...)` with `performance.now()`. No network,
  no TLS, no broker.
- 30 warm-up rounds, then 150 rounds; each round sends one request per variant
  in fixed order (round-robin), so drift hits every variant alike.
- Statistic: median per variant. Spread: median absolute deviation (MAD),
  pooled as the median of the per-variant MADs.
- Pass: every variant's median is within
  `max(0.02 ms, 0.15 × S0 median, 3 × pooled MAD)` of S0's.
- UNVERIFIED: when the pooled MAD exceeds `max(0.02 ms, 0.15 × S0 median)`
  the run cannot resolve the bound, and the test is skipped with an
  `UNVERIFIED` note instead of passing.
- Paths timed: authenticated `/authorize`, unauthenticated `/authorize`, and
  `/authorize` + `/deny` (the client-visible eligibility denial).

Sample run (2026-11-26, developer laptop, two runs agreed):

| Path                   | S0       | S1       | S2       | S3       | S4       | pooled MAD | bound    |
| ---------------------- | -------- | -------- | -------- | -------- | -------- | ---------- | -------- |
| `/authorize` (owner)   | 0.054 ms | 0.051 ms | 0.053 ms | 0.052 ms | 0.052 ms | 0.007 ms   | 0.022 ms |
| `/authorize` (no auth) | 0.009 ms | 0.009 ms | 0.009 ms | 0.009 ms | 0.009 ms | 0.001 ms   | 0.020 ms |
| `/authorize` + `/deny` | 0.087 ms | 0.086 ms | 0.085 ms | 0.085 ms | 0.086 ms | 0.004 ms   | 0.020 ms |

S1 (no declaration) ran about 3 µs faster than S0 in both runs, inside the
bound. The test inventory is an in-memory stub; with the production SQLite
inventory the S1 gap is expected to be larger, because a source with no
declaration makes no `eligibleFor` lookups. That gap is not measured here. The route runs every owner-dependent check on every request, so no
check is skipped because an earlier one failed.

## Observation limits

- **The consent broker is not observed.** This AS is reached through an
  owner-authenticated broker (Account/Web). The client's own pre-authentication
  observables live at the broker, outside this repository: UNVERIFIED.
  The broker must relay `/authorize` 400 `invalid_authorization_details`
  (public invalidity only) and the `/deny` callback, and must not relay the
  owner-only review explanation or the `/owner/token` 404.
- **Timing is in-process only.** It bounds the AS's own processing; it says
  nothing about broker, network or database-cache effects in deployment.
  A difference below the bound (tens of microseconds) is not claimed to be
  zero.
- **Review is owner-only by design.** Its status and body differ across
  variants (L1228 permits explaining the failure to the authenticated owner).
- **The v0.2 type** uses the same entry point and the same deferral, but its
  bound grammar is the pre-lock one; it is not part of this differential case.
