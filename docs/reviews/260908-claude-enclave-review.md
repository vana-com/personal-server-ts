> Archive note (2026-09-08): User-supplied Claude review. Preserved as received; its proposals and individual claims are not automatically accepted. See the reconciliation and consolidated plan for corrections.
>
> Current index and plan: [Review response and PS Lite decommission plan](../260908-review-and-ps-lite-decommission-plan.md).

# PS-in-TEE: feedback on the six PRs

Reviewed at PR heads: `personal-server-ts#245` 2f1915b, `vana-sdk#211` fa01520, `data-gateway#100` 30d13db, `vana-storage#24` f442653, `unity-surfaces#987` bd8f2fe6, `lorebook#1` ff49c73. Reference: `docs/260901-personal-server-gateway-enclave-architecture.md` and `docs/260902-identity-contract.md` as merged in #242, plus the revisions on `codex/personal-server-architecture` (260904, 260906).

Overall: the trust core matches the design. The sandbox holds no signing key. The Personal Server recovers the owner's signature on the grant and the builder's signature on the registration and on the request, and takes the owner identity from the master signature rather than from a Gateway row. Sealing, identity derivation, and the sandbox flags match the identity contract and decision 13. Results are written before completion and cannot be overwritten in storage.

The list below is split by cost of change, not by severity. Section A is what becomes expensive or impossible once real users and builders are on it. Section B is code we can change in normal iteration.

## A. Settle before the first mainnet user

These touch data at rest, on-chain identity, user consent, or the builder wire contract. Each one gets more expensive with every user or builder added.

### A1. Put a random data root key between the signature and the data

Today `scope key = HKDF(master signature, scope)` and every blob is encrypted under that. The signature is the only input to every data key. It cannot rotate: a new signature strands every blob. A compromised node exposes the data root with no re-key. Revocation of the enclave is deletion plus refusal, because dstack cannot revoke a key it can re-derive.

Ask: envelope encryption before any mainnet user.

- Per user, a random 32-byte data root key (DRK). Scope keys derive from `DRK || scope`. Blobs are encrypted under those.
- The DRK is wrapped under a key derived from the signature. The wrapped copy is small ciphertext; store it where every PS (desktop, enclave) can fetch it, with a version.
- Password rotation = the wallet signs `vana-master-key-v2`, the DRK is re-wrapped under the new key, and the v1 wrapper is deleted. Cost: bytes per user, no re-encryption.
- Deletion alone is not reliable: the wrapper is small ciphertext and it will exist in Neon backups, agent memory, and caches. Wrap the DRK under two keys, the signature-derived key and a random per-user server key. Unwrapping needs both. Rotation destroys the old server key, so an old wrapper in a backup is inert to a holder of the old signature. Requirements on the server key: non-exportable, destroyable on demand, excluded from database backups (a cloud KMS or HSM; a dstack-derived path only if the chosen KMS mode can destroy a key, which the current one cannot). Without the split, exposure after a leaked signature is bounded only by the backup retention window.
- Effect on the "Vana never holds a path to the data root" claim: with the split, Vana holds one of two required factors. The accurate statement is that Vana has no unilateral offline access without the signature-derived factor. Since Account can trigger the signature today (A6), the two factors are not independent until signing moves off Vana's servers.
- DRK compromise (sandbox or node) = new epoch: new DRK for new writes, background re-encryption of old blobs. This is the only case that re-encrypts. Data the attacker already read stays exposed.
- Enclave revocation: deleting the enclave's wrapped DRK is sufficient only if no unwrapped DRK is live in a sandbox or agent memory and the server key is destroyed with it. Drain before delete.
- Wallet-loss recovery becomes possible with a second wrap under a recovery secret. That is a new authority path and needs its own authentication, rate limits, entropy requirement, and revocation; list it as an option, not a free side effect.

Correction to the note's "Compromise and rotation" section: it says rotation is a new epoch plus background re-encryption. That is the DRK-compromise case. Signature rotation needs no re-encryption once the DRK exists.

Installing it: the one unavoidable re-encryption is moving existing blobs from signature-derived keys to DRK-derived keys. Shortcut: declare the current signature epoch zero's DRK and wrap it under the new scheme. Holders of the v1 signature then keep access to pre-migration data until it is re-encrypted, so the shortcut is a migration mode with a ledger: which blobs are still v1-derived, when each is re-encrypted, and the date after which the old signature opens nothing. Cheapest now, while the data set is small.

### A2. Identity is bound to Phala's KMS root, the fleet `app_id`, and the dstack 0.5 KDF

The enclave wallet is `getKey(users/{userPsId}/wallet/ethereum/secp256k1/v{epoch})` under the fleet `app_id`. That address is the on-chain `serverAddress`, a permanent claim. Changing the KMS mode (Phala off-chain to on-chain), moving to dstack 0.6 (different KDF), or leaving Phala changes every user's wallet. Each is a re-registration and re-consent event for every user, and the old sealed secrets are recoverable only while the old KMS is alive (no second wrap, by decision 26 and the "Vendor exit" paragraph).

Asks:

- Pick the KMS mode now, on the record. If contract-owned approval of measurements is a requirement we expect within a year, on-chain KMS before mainnet is cheaper than a fleet migration after.
- Make revoke plus re-enable a first-class, tested flow. It is the migration primitive for KMS change, dstack major bump, node compromise, and KMS-root compromise. Today the Revoke button is `disabled` with `onAction={() => undefined}` (`always-on-panel.tsx:394-413`).
- The no-second-wrap stance needs Anna's approval before mainnet; it is listed in the note as "proposed". As written, vendor exit depends on Phala's KMS being alive and cooperating. A1's server-held wrapping key changes this stance and should go to her in the same decision.

### A3. Freeze the builder wire contract while nobody is in production

`vana-sdk#211` is a `!` change and the PR body is right that it is free today. Four things to put into the contract in the same window, because each becomes a deprecation cycle after the first builder integrates:

- `price` and `payer` inside what the builder signs (`JobSubmission`, `protocol/jobs.ts:67-78`). Today the Gateway sets `price='0'`, `payer='builder'`, `paymentState='none'` unilaterally (`lib/jobs/admission.ts:30-34`). A builder that never signed the price it accepts cannot be charged later without a breaking change.
- The server URL in the DCR response. `complete/route.ts:576-583` stores `{delivery:"enclave", lifetime:"durable", owner_address}` with no URL; the builder supplies `VANA_GATEWAY_URL` out of band. Any later option to route around the Gateway, or to run more than one, needs every builder to update unless the DCR carries the URL now.
- `ClaimResponse.job.chainId`: absent in the SDK, required in `data-gateway lib/jobs-types.ts:101`, optional in `packages/enclave/src/jobs/types.ts:23-25`. One definition.
- A hook for enclave evidence verification in the jobs client (`jobs-client.ts:615` skips it by design while anchors are empty), so it can be switched on without an API change.

Related: decision 8 says one SDK read call with the migration hidden behind a flag. Today the builder chooses via `VANA_READ_MODE` and `status.delivery`, and lorebook carries about 400 lines of glue (`src/lib/vana/enclave.ts`). Builders will code against whichever shape ships first.

### A4. Revocation copy and revocation semantics disagree

`enclave-copy.ts:14-15`: "Revoking this Personal Server will stop it from serving your approved data." The design's sign-off section requires: revoking deletes Vana's sealed copy of the secret and retires the identity. The file header says "copy: draft, product review pending". Consent text shown to a user cannot be revised retroactively for data exposed under it. Two options: the copy states what the code does today (delete plus node refusal), or the code lands first. A1 is what makes the guarantee cryptographic rather than operational.

Anna's sign-off on the June reversal is still the open item that blocks ratification. No trace of it since 09-01.

### A5. V2 registrations made now are replayable until V3

`ServerRegistration` is still the four-field V2 struct (`protocol/eip712.ts:139-146`); `version:'v3'` returns 400 `UNSUPPORTED_VERSION` (`register.ts:35-36`). With a deterministic address and a fixed URL, every enclave registration signed now is a permanent re-activation capability. The bridge (Gateway refuses retired enclave addresses, `lib/servers.ts` +1097-1103) covers enclave rows; legacy re-registration still accepts the original signature. Every user enabled before V3 lands carries that signature forever. If V3 is more than a few weeks out, the bridge needs to refuse any already-settled signature, not only retired addresses.

### A6. Where the plaintext signature lives

Data flow in code: the Account service asks Privy to sign `vana-master-key-v1`, holds the raw signature in memory, and encrypts it to the enclave key (`personal-server-intent-service.ts:709-815`). The browser carries ciphertext only. The design's "owner surface delivers the signature over an attested channel" is implemented by a Vana server. Tests assert the raw signature is absent from the response body and nothing logs it. This is a design choice worth recording as one, because changing it later (sign and encrypt in the browser with the embedded wallet) changes the silent-signing model and the Account intent contract. Two consequences to write down: compromise of Account or its Privy authorization key yields the data root of every user who enables from then on; a hijacked Account session can enable the enclave and mint an owner-signed grant, so the Account device-code finding becomes a data-read path that no longer needs the user's device online.

## B. Change in normal iteration

Code-only. No data migration, no re-consent, no builder update. Ordered by risk, not by effort. The first four are the design's own "must hold" exceptions, so they should land early, but nothing about them gets harder with time.

### B1. `POST /v1/grants` still accepts a grant signed by any registered server

`data-gateway api/v1/grants.ts:294-322`, unchanged. The sandbox cannot sign (`public-only-account.ts:24-29`), but the agent derives the enclave wallet key per call (`identity/wallet.ts`), so a Vana-run node can mint a grant the Gateway honours. Exception 2. Smallest fix: refuse any signer that is an enclave identity. Full fix: owner-signed only, and remove the delegate path for desktop on the schedule decision 10 gives. Code-only while no enclave-signed grant exists; after the first one, refusing them invalidates issued artifacts, so this belongs before the first real user.

### B2. Revocation and registration liveness are Gateway rows

`packages/core/src/policy/signed-artifacts.ts:52-55` checks `grant.revokedAt` from the Gateway row, marked `TODO(step-4)`. `worker.ts:211-223` checks the PS's own registration as row fields, never the signature. No RPC client exists in core or server. The Gateway's own on-chain revocation is behind `GRANT_REVOCATION_ONCHAIN_ENABLED=false`. Decision 9. Ask: chain read before result release, fail closed on RPC failure. The 5-minute Gateway fallback in decision 9 gives the Gateway positive authorization authority over liveness. Code-only today; once builders and users rely on Gateway-row semantics for revocation, changing the source of truth becomes a trust-model change.

### B3. Prewarm unseals on the operator secret alone

`packages/enclave/src/agent/http.ts:177-181, 360-402`: the body carries `sealedEnvelope` and `scope`, authenticated by `ENCLAVE_AGENT_SECRET`; the agent unseals, boots, hydrates. The owner-signed `PrewarmRequest` is verified at the Gateway (`api/v1/prewarm.ts`), never at the node. Ask: pass the owner's signature through and verify it in the agent before unsealing. Note for the record: in the job path too, decryption happens at sandbox boot and the signed-artifact checks gate result release, not decryption. The invariant "reauthorize against signed artifacts immediately before plaintext" should say what it means.

### B4. Retired-epoch refusal uses a Gateway-supplied `minEpoch`

`packages/enclave/src/agent/seal.ts:34-38`; `data-gateway api/v1/identity/[userPsId]/secret.ts:88-94`. The agent has no epoch state, so a Gateway that omits or lowers `minEpoch` re-enables a retired identity's sealing path. Exception 3 says the node refuses. A signed retirement record, or a monotonic per-`userPsId` floor the agent persists, closes it.

### B5. Enclave DCR completion still requires a booted, relay-reachable PS Lite

`use-data-connection-request-flow.ts:1340` calls `waitForRequiredCompletionRouting` unconditionally after the enclave grant; `complete/route.ts:127` requires `ps_url` and `:583` discards it; `registerIfNeeded` (`web-personal-server-session.ts:849-890`) still registers PS Lite; approve still calls `reconnect()`. Decision 4 in reverse order. Until this is done the always-on server is not always on.

### B6. The agent is not measured

`deploy/dstack/docker-compose.enclave.yml:58-94`: `apk add docker-cli git`, `git fetch GIT_REF`, `npm ci`, `npm run build` at every CVM boot; `GIT_REF` and `PS_IMAGE` are encrypted-env passthroughs; `runsc` is curl'd at boot (sha512-pinned). `scripts/tee/README.md:35-36` says production uses a digest-pinned agent image. Production plan B6 already lists it. Code-only until a measurement is published or consented to; after that, changing what the compose hash covers is a governance step, so land it before mainnet. The spike results doc says both that env values do not enter `compose_hash` (line 28) and that env updates rotate it (line 119); worth settling which is true before relying on either.

### B7. Node admission is operator-asserted

`data-gateway lib/tee/nodes.ts:129-158,173-187`; `api/v1/tee-nodes.ts:56-78`: register is an operator POST, heartbeat self-reports `composeHash`, admit is a flag gated on a fresh heartbeat; `appId` is never checked against `ENCLAVE_APP_ID_ALLOWLIST`; no quote, no nonce challenge, no canary. `lib/operator-auth.ts:46-49` falls back to `CRON_SECRET`. Workflow 5 and decision 22.

### B8. Builder-side trust in the Gateway

`vana-sdk protocol/jobs-client.ts:615` skips evidence verification; `ENCLAVE_TRUST_ANCHORS` empty for both chains (`identity.ts:185-192`); `ResultHandle.url` accepted for `http:` or `https:` with no host pin (`:469-471`, fetched at `:799-803`). Bounded: the request carries no user data and the result decrypts only for the builder. Pin the host to the storage origin and refuse `http:` outside loopback. The verification hook itself is in A3, because adding it after builders ship is a builder update.

### B9. Storage write check is the pre-existing one

`vana-storage src/auth/gateway-client.ts:25-52`: owner-match on `GET /v1/servers/{signer}`, 60 s positive cache, no liveness or revocation awareness. The design's `auth/gateway-client ~` line asks for the inference relay's predicate. Bounded by `If-None-Match` no-overwrite and the SDK hash check.

### B10. Agent surface and secrets hygiene

- Inbound routes on the public dstack domain beyond the designed identity/seal/health: `drain`, `sandboxes`, `sandboxes/:id/logs` (`agent/http.ts:107-184`).
- `PS_ACCESS_TOKEN` maps to `ownerTokenResult(serverOwner, "control-plane-token")` (`core/auth/request.ts:133-138`): the agent's per-sandbox bearer is accepted as the owner on every PS route, including `GET /v1/data/:scope`, MCP, and sync. The 09-04 note describes the agent's access as one signing route.
- The master signature persists in the dind container config and `/proc/1/environ` for the sandbox lifetime (`docker-runtime.ts:187-208,442-466`; compose `:124-128`).
- Test levers in the production binary and compose passthrough: `WORK_DELAY_MS`, `SANDBOX_DEBUG`, `VERCEL_PROTECTION_BYPASS` allowlisted into every sandbox env (`sandbox/runtime.ts:35,41`; `jobs/run.ts:879`), `SANDBOX_SYNC=disabled`, fake dstack/runtime selectable.
- `provision.sh:151 --public-logs`; `update.sh:20` defaults to the build-in-CVM inline compose; `docker.yml` publishes images on `feat/**` and `perf/**`.

### B11. Rate limits, receipts, and liveness are placeholders

The builder-signed price and payer belong to A3. What remains here is code-only: `lib/jobs/admission.ts:105-108` writes no receipt on commit. No `lib/rate-limit`, `lib/receipts`, `lib/liveness`. `POST /v1/identity` and `/secret` are unauthenticated and unlimited, and each call reaches the agent (derive plus quote, or unseal). Decisions 15 and 18 say before launch. Admission also admits a `raw_read` for a scope with no `data_points` row (`admission.ts:91-105`).

### B12. Product surface

- "Ready for apps" = `serverStatus ∈ {confirmed, finalized}` (`enclave-client.ts:570-594`), not scope hydration. The copy "Apps can now use the data you approve" shows before any sandbox exists.
- Web external wallets return `external_wallet_not_supported` (`enclave-client.ts:527-529`); the exchange path is desktop-bearer only. Decision 5 puts them in scope.
- Prewarm is a fourth silent Privy signature after consent (`constrained-silent-signing.ts:55-62,168-187`); workflow 1 step 3 says no background signing afterwards. Silent signing after consent is consent-sensitive: if it ships, the consent copy has to name it. Mobile policy (5 rules) is enforced unconditionally (`mobile-signer-bootstrap.ts:273`), so flag-off is not byte-identical.
- One PS screen (decision 1): `AlwaysOnPanel` sits above the existing PS Lite UI (`page.tsx:100-102`).

### B13. Hydration and version pinning

`sync-manager.ts:162-197`: scope-first, then owner-wide `downloadAll`. Hydration has no version parameter; the pinned version is checked afterwards (`worker.ts:249-277`, `VERSION_MISMATCH` retryable), so a pinned older version can never be served. `pinnedVersion` is builder-supplied inside the signed request, not pinned at admission. TTL destroys everything; no manifest or index cache survives (`registry.ts:452-485`). All follow the 09-06 notes; the merged text (J3, J7, J9) says otherwise.

### B14. Process and hygiene

- Four PR bodies (#245, #100, #987, #1) describe the first commit only. Review sign-off has to be against the branch.
- No human review on any of the six; codex on #211 and #987. The gpt-5.6 P3 on #987 (`null` JSON body to `personal-server-enclave-delivery/sign/route.ts:46-51` gives a TypeError 500) is unaddressed.
- The 09-04 and 09-06 design revisions (object-storage results, agent signing oracle, prewarm, scope-first hydration, systrap, bundling) are on `codex/personal-server-architecture` and were not posted. The merged doc still says private R2 bucket and purge cron. Ratify or reject them on the record and merge the docs with the code.
- Four SDK builds across the six PRs: `3.23.0-pr.211.fa01520` (lorebook, PS, gateway devDep), `3.23.0` (web), `3.22.0-pr.208.e9c19e9` (account), `3.18.1` (desktop).
- `RESULT-*.md` committed in personal-server-ts and data-gateway; `.env.example` changes `DATA_REGISTRY_CONTRACT` unrelated to the work; gateway migrations README says 0048–0050 unapplied while the production plan says 0048–0051.
- `packages/enclave` imports nothing from `core`/`server`; decision 23 says it would. Safe; correct the doc.
- Runtime named `runsc-ptrace` runs on systrap (`docker-runtime.ts:24`).

## What not to reopen

- Signature recovery on grant, builder registration, and request inside the sandbox; owner from the master signature; result key from the builder-signed request.
- Sealing envelope, path layout with epoch, AAD binding, raw scalar wallet key zeroed in `finally`, dstack-sdk 0.5.8 pinned.
- Sandbox flags, dind holding the Docker socket, iptables to 2375, secrets via 0600 env file.
- K7 server-side order: resolve owner, verify evidence, wallet equals owner, sign, ECIES to the post-verification key; raw signature absent from the response.
- Write-object-then-complete, `If-None-Match: *`, lease plus fencing, sweep-before-claim, `?wait=25` on submit and claim.
- E4 revoke: retire rows and hard-delete `sealed_secrets` in one transaction; D19 rollback to `prepared` on settle failure.
