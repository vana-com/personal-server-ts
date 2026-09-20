# Lorebook #3 merge + canonical consent proof — 2026-09-14

Hosts contacted: `app-dev.vana.org` (55), `lorebook-opendatalabs.vercel.app` (17),
`dp-rpc.moksha.vana.org` (7), amplitude (3). **Zero preview/mainnet hosts.**

## Merge and deploy

|             |                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------- |
| PR          | vana-com/lorebook#3 `chore(deps): pin @opendatalabs/vana-sdk 4.0.0`, MERGEABLE/CLEAN, Vercel check SUCCESS      |
| Merge       | squash (repo history is linear) → `main` **5ae1c6c**                                                            |
| Prod deploy | `dpl_7rbuBShejZacsGEBR4WiD7XgH5of` (lorebook-211qy2ksb), Ready 22 s, aliased `lorebook-opendatalabs.vercel.app` |
| Rollback    | previous prod `dpl_CKRdqvUfC2XqoenGYvRjX4SRPGxF` (lorebook-57ccj1fp5)                                           |

**Env check (read-only, production) — all canonical, unchanged:**
`VANA_DEFAULT_NETWORK=moksha`, `VANA_DEFAULT_ENV=dev`,
`VANA_GATEWAY_URL=https://dp-rpc.moksha.vana.org`,
`VANA_ACCESS_REQUEST_BASE_URL=VANA_APPROVAL_APP_BASE_URL=https://app-dev.vana.org`,
`APP_URL=https://lorebook-opendatalabs.vercel.app`, `VANA_READ_MODE=enclave`.

## Consent proof (owner mk-a `0x38c0…433c`, profile signed in to app-dev)

| Row                             | Result                                          | Evidence                                                                                                                                                                                                                                                   |
| ------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| dcr-create                      | **PASS** `dcr_a95eb9bfec5e4140bb35d303471b75b5` | `POST /api/vana/request 200` → popup `app-dev.vana.org/data-connection-requests/<id>?mode=page`; `out/lorebook/dcr-create/*.png`                                                                                                                           |
| consent                         | **PASS** approve completed                      | `POST app-dev/api/personal-server/prewarm 200`; gateway `GET /v1/data`×2, `GET /v1/identity`, `GET /v1/builders/0x6a9A…68a4`, `POST /v1/prewarm 202`, `GET /v1/grants`, `POST /v1/grants 201`; `POST app-dev/api/…/complete`; `out/lorebook/consent/*.png` |
| grant on Gateway                | **PASS**                                        | `GET dp-rpc.moksha.vana.org/v1/grants?user=…&builder=…` → grant `0xb6b68d45…9094`, scopes `[spotify.profile]`, grantor mk-a, expires 2027-09-14                                                                                                            |
| grant-read (job → result → ACK) | **FAIL**                                        | Lorebook errors: "That page stayed blank. No new data was added to Lorebook." No job, no result, no ACK                                                                                                                                                    |

Driver `scratchpad/lorebook-consent.mjs` (browser-e2e conventions),
outputs `…/launch-handoff-260914/browser-e2e/out/lorebook/{results,network,hosts}.json`.

## Blocker — production Lorebook has no enclave read path

Exact error (Vercel runtime log, 17:13:15.75, `GET /api/vana/status` → 409):

    [vana/status] Status failed for dcr_a95eb9bfec5e4140bb35d303471b75b5
    n: The approved grant is not ready to read. code: 'DIRECT_ACCESS_NOT_APPROVED'

`main` has no `src/lib/vana/enclave.ts` and never reads `VANA_READ_MODE`; its
`assertGrantReadReady` still requires `status.personalServerUrl`, which the enclave
route does not mint. The env is right — the code shipped to production is the
direct-read build. **No env change would fix this**; the enclave read path lives on
unmerged `feat/enclave-jobs-read` (16 commits ahead, incl. `fix(read): resume the same
enclave job across requests`). Merging + deploying that branch is the next step; consent
itself is proven above.
