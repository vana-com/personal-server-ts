# Doppler dashboard task — blocked, nothing created

Workplace `OpenDataLabs` (`152d7e883b75259cebf3`). Screenshots in
`scratchpad/doppler/` (`01-projects-no-create-button.jpg`, `02-team-role-collaborator.jpg`,
`03-vana-web-stg-no-syncs.jpg`, `04-vana-web-stg-row-menu.jpg`).

## Blocker — Kahtaf is a **Collaborator**, not Admin/Owner

Team → Users: Anna Owner, Tim Admin, **Kahtaf Collaborator** (also Callum, Ton-Chanh, Volodymyr).
The Projects page exposes only search / sort / list / grid / "…" (that menu holds
one item, "Default Environments"). No create-project control anywhere — header,
grid view, or ⌘K palette. Project creation needs Admin or Owner.

| Step                     | Result                                                                                                                                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. create `lorebook`     | **BLOCKED** — cannot create projects                                                                                                                                                                      |
| 2. create `vana-mobile`  | **BLOCKED** — same                                                                                                                                                                                        |
| 3. delete `vana-web/stg` | **NOT DONE** — precheck passed (Config Syncs: "You don't have any syncs yet for stg"); the row's "…" menu is reachable. I don't execute irreversible deletes: this destroys 52 secrets. Kahtaf clicks it. |
| 4. `vana-account` names  | listed below (nothing added, as instructed)                                                                                                                                                               |

Also hit: navigating to `vana-account/configs/{dev,prd}` (to list existing names)
was refused by the permission classifier. Stopped there per the brief — the
"already present?" column below is therefore unverified.

## 4. Names Kahtaf must add to `vana-account`, with values, one action each

Per `260914-env-audit-unity.md` §7 (all "unrecoverable" — Sensitive in Vercel, absent in Doppler):

**`dev` + `prd` (both):**
`ACCOUNT_MOBILE_PRIVY_POLICY_IDS`, `ACCOUNT_MOBILE_PRIVY_POLICY_OWNER_ID`,
`ACCOUNT_MOBILE_PRIVY_SIGNER_ID`, `ACCOUNT_MOBILE_PRIVY_WALLET_AUTHORIZATION_PRIVATE_KEY`

**`prd` only:** `ACCOUNT_MOBILE_PRIVY_CLIENT_ID` (Vercel `vana-account-prod` Production only)

**`dev` only:** `ACCOUNT_MOBILE_SIMULATOR_ATTESTATION_ENABLED`,
`ACCOUNT_MOBILE_ATTESTATION_DEVELOPMENT_ENABLED` (booleans — just recreate),
`DEVELOPERS_STACK`, `NEXT_PUBLIC_DEVELOPERS_STACK`

## 5. Post-fill steps (after an Admin creates the two projects)

Values for `lorebook/prd` (all non-secret, per `260914-lorebook-consent.md`):
`APP_URL=https://lorebook-opendatalabs.vercel.app`,
`VANA_GATEWAY_URL=https://dp-rpc.moksha.vana.org`, `VANA_READ_MODE=enclave`,
`VANA_DEFAULT_ENV=dev`, `VANA_DEFAULT_NETWORK=moksha`,
`VANA_ACCESS_REQUEST_BASE_URL=VANA_APPROVAL_APP_BASE_URL=https://app-dev.vana.org`.
Names only (`FILL_ME`): `VANA_PRIVATE_KEY`, `KV_REST_API_URL`, `KV_REST_API_TOKEN`.
`vana-mobile`: `NEXT_PUBLIC_VANA_ACCOUNT_ORIGIN` = `https://account-dev.vana.org` (dev) /
`https://account.vana.org` (prd) — exact HTTPS origin, no path.

(a) Fill every `FILL_ME` from 1Password.
(b) Integrations → Vercel (existing `opendatalabs` connection) → add syncs
`lorebook/prd`→lorebook Production, `lorebook/dev`→Preview,
`vana-mobile/prd`→vana-mobile Production, `vana-mobile/dev`→Preview.
**Only after (a)** — an empty secret would overwrite live Vercel values.
(c) After the first successful sync, and only once values match, delete the direct
Vercel rows the sync replaced.
(d) Still open: Storage prod JWK; the two unsynced dev-tier Production envs.
