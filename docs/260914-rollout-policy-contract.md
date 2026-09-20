# Rollout policy contract — September 14, 2026

One Account-owned JSON policy, keyed by chain. Read-only study of Unity `df5618f3` (`unity-surfaces-fold`), Gateway `c7c73ba` (`data-gateway-fold`). Requirements: [orchestrator runbook](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/orchestrator-runbook.md) "One rollout contract" + acceptance matrix; [launch detail](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/launch-plan-detail.md); [flag review](../../e2e-proof-2026-09-09/fleet-overnight/reviews/260914-flag-architecture.md).

## 1. Policy shape

Env var `ENCLAVE_ROLLOUT_POLICY` (Account; same value and parser on Gateway — see §4).

```json
{
  "version": "2026-09-14.1",
  "chains": {
    "1480": { "defaultMode": "legacy", "owners": {} },
    "14800": { "defaultMode": "tee", "owners": {} }
  }
}
```

| Rule                             | Requirement                                                                                    |
| -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `version`                        | non-empty string ≤64 chars; changes on every flip; echoed to clients and logs                  |
| `chains` key                     | decimal positive safe integer as string                                                        |
| `defaultMode`                    | exactly `legacy` or `tee`                                                                      |
| `owners`                         | address → mode map; keys must match `/^0x[0-9a-fA-F]{40}$/`, compared lowercased; `{}` allowed |
| unknown keys                     | rejected (strict-key precedent: `owner-ingestion.ts:255-262`)                                  |
| any violation, unset, unparsable | policy = **unavailable**, not empty; parsed once at module load; never log contents            |

## 2. Resolution

Input: authenticated owner address (session → Privy wallet, `personal-server-intent-service.ts:116,1019`), operation-pinned `chainId`. Never `body.ownerAddress`, never a caller account id, never the browser's current network.

| Condition                               | Effective mode                                   |
| --------------------------------------- | ------------------------------------------------ |
| policy unavailable                      | **deny** (`rollout_policy_unavailable`), no mode |
| `chains[chainId].owners[owner]` present | that value (override wins)                       |
| else `chains[chainId].defaultMode`      | that value                                       |
| chainId absent from `chains`            | `legacy` (never `tee`)                           |

`legacy` and `deny` both stop new TEE setup; `deny` is an error state, `legacy` is a route.

## 3. Eligibility response

`GET /api/v1/personal-server/enclave-eligibility?chainId=…` → `{ mode, policyVersion, expiresAt, chainId }`.

Authenticated by the existing intent-session machinery, not a new channel: `resolvePersonalServerIntentSession` + `intentSigningExpectedAudiences` + `intentCorsHeadersFor` (`apps/account/src/lib/signing/personal-server-intent-service.ts:83,116,170`). The response is UI state, not a bearer token: nothing accepts it as authorization.

TTL 300 s, matching the Gateway's existing short read-signature bound `MAX_READ_SIGNATURE_LIFETIME_SECONDS` (`data-gateway-fold/lib/web3-signed.ts:32`). Covers one setup flow; an off-flip drains ≤5 min after Account redeploy.

Never returned: the `owners` map or its size, other owners' modes, other chains' defaults, raw policy JSON.

## 4. Gateway consumption

Gateway evaluates the same policy document from its own `ENCLAVE_ROLLOUT_POLICY` env — it does **not** call Account. No Account→Gateway service-auth channel exists today (only owner-signed audience-bound claims, `owner-ingestion.ts:86-92` verified Gateway-side, and service bearer tokens, `lib/fleet/controller-client.ts:10`), and a synchronous Account dependency in the admission path adds an outage mode. Cost: a flip is two redeploys; `version` makes drift detectable. No lookup ⇒ no cache; if a fetch is ever adopted, cache ≤300 s and deny new admission on expiry. **Eligibility ≠ signature authorization**: every existing owner/signature/evidence/epoch check stays.

| Route (`data-gateway-fold`)                    | Check                                                                                                                                                                                                                                                                                     |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api/v1/identity.ts:69-84` POST prepare        | **no policy check** (decided 2026-09-14 after review): prepare is unauthenticated at base, so a decision there is an anonymous allowlist oracle. A prepared row is not enrollment; register/secret decide. Authenticating prepare is a follow-up.                                         |
| `api/v1/identity/[userPsId]/register.ts:53-76` | authoritative: after the signature recovers to `row.ownerAddress`, decide when `row.state === 'prepared'`; already-registered path `:68-75` untouched                                                                                                                                     |
| `api/v1/identity/[userPsId]/secret.ts:66-93`   | decide on `row.ownerAddress`/`row.chainId` for an unsealed epoch; the route binds nothing (no signature, public fields only), so a denial is the route's generic 404 with no code and no `policyVersion`, indistinguishable from an unknown identity. Owner-bound sealing is a follow-up. |
| not gated                                      | `identity.ts:136` GET status, retire/revoke, jobs, access, execution — no per-job lookup                                                                                                                                                                                                  |

## 5. Account enforcement points

| Path (`unity-surfaces-fold/apps/account/src`)                                   | On (`tee`)                                                                                     | Off (`legacy`/deny)                                                                     |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `lib/signing/personal-server-intent-service.ts:963` `signEnclaveIntent`         | proceeds                                                                                       | 403 `rollout_not_enabled` after session+evidence parse, before `findEnclaveOwner`/Privy |
| `app/api/v1/intents/personal-server-enclave-delivery/sign/route.ts:65`          | inherits                                                                                       | inherits                                                                                |
| `app/api/v1/signing-exchanges/route.ts:64-131` create                           | creates                                                                                        | denies `ENCLAVE_DELIVERY_INTENT`                                                        |
| `app/api/v1/signing-exchanges/[id]/approve/route.ts:105-145`                    | approves                                                                                       | denies                                                                                  |
| `app/api/v1/signing-exchanges/redeem/route.ts:197`                              | signs                                                                                          | denies — recheck at issuance, not only at create                                        |
| `personal-server-intent-service.ts:989-1000` desktop branch                     | hands off                                                                                      | denial precedes `confirmation_required`                                                 |
| mobile (`:972` scope, `:1274` session kind)                                     | same resolver                                                                                  | scope possession is not an exemption                                                    |
| `lib/signing/owner-ingestion.ts:227,251`                                        | TEE-path ingestion derives from policy; the `ACCOUNT_OWNER_INGESTION_ENABLED` check is deleted | denied; hard 14800 check stays until the mainnet slice                                  |
| registration / grant-registration / grant-revocation / deregistration / prewarm | unchanged                                                                                      | unchanged — legacy signing must not regress                                             |

## 6. Enrollment state semantics

| State                                                            | Meaning                   | Rollout-off                                         |
| ---------------------------------------------------------------- | ------------------------- | --------------------------------------------------- |
| `sealed` / `registered` (`lib/identity-types.ts:53`)             | enrolled; durable routing | fully preserved                                     |
| `prepared` only                                                  | **not** enrolled          | completion denied; actionable paused-setup response |
| no row / 404                                                     | unknown                   | not legacy; deny TEE; never implicit Lite           |
| `fleetOwners.mode !== 'fleet'` (`lib/fleet/repository.ts:52-53`) | operator recovery         | explicit authorized resume only                     |

`enrollOwner` already requires a current sealed identity (`repository.ts:43-44`). Off preserves: identity row and epoch (`lib/identity.ts:19-37`), sealed envelope, `serverId`, recorded DCR routing (`apps/web/src/lib/data-connection-requests/store.ts:276`), MCP authority, status/revoke/resume.

## 7. Unity/Web behavior

| Concern         | Required                                                                                                                                                                                                                                                                                                                                                                              | Today (`df5618f3`)                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| selection       | authenticated owner + pinned chain + effective decision                                                                                                                                                                                                                                                                                                                               | build-time `NEXT_PUBLIC_PS_ENCLAVE_ENABLED` (`apps/web/src/features/personal-server/ps-environment.ts:68-69`)         |
| DCR consent     | recorded delivery wins, else effective mode                                                                                                                                                                                                                                                                                                                                           | every un-ready DCR selects enclave (`…/data-connection-requests/[id]/hooks/use-enclave-consent-readiness.ts:146-152`) |
| DCR complete    | resolve owner + `record.network` + policy server-side                                                                                                                                                                                                                                                                                                                                 | trusts `body.delivery` (`apps/web/src/app/api/data-connection-requests/[id]/complete/route.ts:704`)                   |
| provider        | consumes the one decision                                                                                                                                                                                                                                                                                                                                                             | independent flag read (`web-personal-server-provider.tsx:647`)                                                        |
| MCP             | approval links: authority = the link's minter (`ps_origin` equals a configured fleet ⇒ enclave on that network; another origin ⇒ the owner's own Lite runtime; absent ⇒ pause), confirmed by that backend holding the authorization — never inferred from the other backend or from policy (decided 2026-09-14 after review). Policy decides only new MCP setup on the endpoint page. | unscoped config read (`enclave/mcp-endpoint.ts:14-24`), always-enclave approval (`mcp/mcp-page-controller.tsx:39-53`) |
| network pin     | a browser switch must not re-resolve a pinned op; mainnet has no fleet (`packages/app-runtime/src/personal-server/environments.json` `prod.mcpOrigin: ""`)                                                                                                                                                                                                                            | unscoped MCP origin override (`ps-environment.ts:101-104`)                                                            |
| legacy adapters | `mode=legacy` must actually import/read/consent                                                                                                                                                                                                                                                                                                                                       | owner-data session built unconditionally, no Lite runtime (`use-booted-personal-server.ts:1-9,281-293`)               |

## 8. Acceptance matrix → layer → first failing test

| Runbook case                        | Layer   | Test file / assertion                                                                                                                                                 |
| ----------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mainnet off, new legacy owner       | Web     | `apps/web/src/features/personal-server/__tests__/rollout-selection.test.ts` — chain 1480 owner resolves `legacy` and issues no `prepareIdentity` call                 |
| Moksha selected on                  | Account | `apps/account/src/lib/signing/__tests__/rollout-policy.test.ts` — allowlisted owner on 14800 gets `status: "signed"` from `signEnclaveIntent`                         |
| Unselected / wrong chain            | Gateway | `tests/identity-rollout.test.ts` — register for a non-eligible owner returns 409 `rollout_setup_paused`, row stays `prepared` (prepare itself is not gated; see §4)   |
| Missing/malformed policy            | Gateway | `tests/identity-rollout.test.ts` — malformed env ⇒ register/secret 403 `rollout_policy_unavailable` while prepare and GET on an existing live row still return 200    |
| Unknown / prepared-only row         | Gateway | `tests/identity-rollout.test.ts` — register on a `prepared` row of a non-eligible owner returns paused-setup and leaves state `prepared`                              |
| Switch network with pending work    | Web     | `apps/web/src/app/api/data-connection-requests/[id]/complete/__tests__/rollout-pinning.test.ts` — completion uses `record.network`, unchanged by the selected network |
| Recorded legacy DCR after on        | Web     | same file — a record with recorded Lite delivery completes legacy while policy is `tee`                                                                               |
| Existing TEE identity/DCR after off | Gateway | `tests/identity-rollout.test.ts` — policy `legacy` leaves GET identity, revoke and job paths unaffected                                                               |
| Off→on→off                          | Account | `…/__tests__/rollout-policy.test.ts` — eligibility response and signing decision report the same `policyVersion`                                                      |
| Explicit smoke disable/revoke       | Gateway | `tests/identity-revocation.test.ts` — after an explicit revoke the next request is denied **while policy still says `tee`**                                           |

Each row is one slice: write the failing test, then the minimal enforcement.

## 9. Decisions (Kahtaf, 2026-09-14)

| Question                          | Decision                                                                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Policy distribution to Gateway    | Gateway reads its own `ENCLAVE_ROLLOUT_POLICY` copy; no Account call. Flip = Account + Gateway redeploy; `version` detects drift. |
| `ACCOUNT_OWNER_INGESTION_ENABLED` | Folded into the policy and deleted. One switch; both it and Lite are removed after rollout proof.                                 |
| Moksha opening shape              | `defaultMode: "tee"`, empty `owners`. Mainnet `legacy`, empty `owners`.                                                           |

Proof preference: end-to-end route/browser proofs over unit tests; unit tests only where an e2e cannot reach the branch.
