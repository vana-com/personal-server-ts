# PLAN — Chatbot-first MCP: scoped read surface for third-party apps

**Date:** 2026-07-23
**Status:** Draft for review (v2 — pivoted to self-signing chatbot identity)
**Owner:** TBD

## 1. Goal

Let chatbot-first third-party apps (Maple AI, CancerDAO) integrate a user's
personal data over MCP, limited to **only the scopes the owner granted to that
app** — never full user-data access. POST /session/initFunctionally: expose the **read surface of
the HTTP data API** as grant-scoped MCP tools, where each app connects under a
**stable, verified identity** rather than an ephemeral per-connection one.

### Decisions locked (from review)

| Decision             | Choice                                                                                                                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Operation surface    | **Read-only, broadened** — read scope data, list scopes, list versions, read historic versions, search. No writes, no owner/management ops.                                                      |
| App identity keypair | **Chatbot owns its keypair and signs its own requests** — one stable registered-builder identity reused across all connections/users. Not a PS-minted per-connection grantee.                    |
| App onboarding       | **Verified onboarding / registry** — chatbots register a known public key + metadata once; enables safe identity reuse and recognizable consent. (Reverses the earlier "dynamic DCR only" idea.) |
| Read-path reuse      | Shares the core read tools + `verifyDataReadPolicy` with the existing `/mcp`, but the **identity / connection / consent layer is distinct** (a chatbot-first surface).                           |

> **Note — this refines two earlier answers.** The owner's Claude MCP correctly
> uses per-connection ephemeral grantees + dynamic DCR. The chatbot-first surface
> is the inverse: stable, verified, self-signing identities. The two share the
> read tools and policy path but diverge in identity/consent. If instead you want
> everything forced through the _existing_ `/mcp` routes verbatim, flag it — this
> plan treats it as a sibling surface reusing core.

## 2. How this differs from the current user-facing MCP

| Aspect                | Current user-facing MCP (owner's Claude)                                                                          | Chatbot-first MCP (this plan)                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Grantee identity      | Fresh secp256k1 keypair per connection ([connection-api.ts:336](../packages/core/src/mcp/connection-api.ts#L336)) | Chatbot's own registered-builder keypair, stable + reused |
| Key custody           | PS generates, holds, and signs with it                                                                            | Chatbot holds and signs; PS never holds it                |
| Who signs reads       | PS, as the per-connection grantee                                                                                 | Chatbot, as itself                                        |
| Builder registration  | On-chain, minted per connection (`ensureMcpGranteeRegistered`)                                                    | Once, at onboarding                                       |
| Grant target          | The PS-minted grantee address                                                                                     | The chatbot's registered address                          |
| App identity to owner | Unrecognizable ("connection #47")                                                                                 | Recognizable ("Maple AI"), from the registry              |
| Reconnect             | New key + new registration + re-consent                                                                           | Same identity; existing grant still valid                 |

**Consequence:** for the chatbot-first surface we **drop** the PS-held grantee
machinery ([`grantee.ts`](../packages/core/src/mcp/grantee.ts),
per-connection keypair generation, `ensureMcpGranteeRegistered`, grantee-key
encryption-at-rest). It exists only to let keyless clients satisfy the
builder+signature requirement — a self-signing chatbot makes it unnecessary.

## 3. Target architecture

1. **Chatbot = registered builder with a stable identity.**
   Onboarded once via a **chatbot registry**: `{ builderAddress/publicKey,
name, logo, homepage, redirect URIs, default requested scopes }`. This is the
   verified identity the consent UI displays and the address grants are issued to.

2. **Consent → grant to the chatbot's own address.**
   Reuse the OAuth consent dance for the user handshake, but at approval mint the
   on-chain grant to the **chatbot's registered address** instead of a
   freshly-generated grantee. This is a targeted change to
   `approveMcpOAuthAuthorizationWithScopes`
   ([connection-api.ts:494](../packages/core/src/mcp/connection-api.ts#L494)):
   skip `ensureMcpGranteeRegistered` (already registered at onboarding) and pass
   the chatbot address as `granteeAddress` into `createGrantContract`
   ([contracts/grants.ts:151](../packages/core/src/contracts/grants.ts#L151)).
   The grant (its `grantId` + scopes) **is** the durable authorization — no
   per-connection secret to persist.

3. **Reads are signed by the chatbot; policy path unchanged.**
   Because the chatbot signs as itself and the grant is issued to its address,
   `verifyDataReadPolicy` passes with `signer == grantee`
   ([data-read.ts:119](../packages/core/src/policy/data-read.ts#L119)) with **no
   modification** — the same gate as any external builder read. The chatbot-first
   MCP tools become a thin adapter over the existing builder read path
   (`authorizeBuilderRead` → `handlePersonalServerDataRequest`), scoped by the
   chatbot's grant.

4. **Revocation = revoke the grant.**
   Owner revokes the chatbot's access by revoking the on-chain grant
   (`DELETE /v1/grants/:grantId`), not by deleting a PS-side connection record.

### MCP session establishment — DECIDED: signed handshake → session token

**Decision:** the chatbot signs **once** to mint a short-lived session token, then
connects with an **unmodified MCP client** using that token as a normal bearer.
(Chosen over per-request `Web3Signed` for MCP-client ergonomics; the key still
never leaves the chatbot — the PS only ever recovers a public address.)

**Transport context.** The PS `/mcp` endpoint is **stateless**
(`sessionIdGenerator: undefined`, fresh `McpServer` per request,
[mcp/server.ts](../packages/core/src/mcp/server.ts)) — no retained server-side MCP
session; auth rides on each request's header. So "session" here is an **auth**
session (the token), not MCP protocol state.

**Step 1 — mint (new `POST ${psUrl}/mcp/session`).** Body carries a `Web3Signed`
proof over `{ aud: psUrl, grantId, nonce, exp }`. The PS:

1. `verifyWeb3Signed(proof)` → recover signer
   ([auth/request.ts](../packages/core/src/auth/request.ts));
2. assert `signer == grant.grantee` **and** `signer ∈ chatbot registry` **and**
   `nonce` unused **and** `exp` not passed **and** `aud == this PS origin`;
3. mint an opaque token, persist `hash(token) → { granteeAddress, grantId,
scopes, exp }`, return `{ session_token, expires_in }`.

**Step 2 — connect.** Chatbot points a stock `StreamableHTTPClientTransport` at
`${psUrl}/mcp` with `Authorization: Bearer <session_token>` and calls
`client.connect()` → `listTools()` / `callTool()`.

**Step 3 — resolve.** `/mcp`'s existing `handleToken` does `getByTokenHash` →
record ([mcp.ts:693](../packages/server/src/routes/mcp.ts#L693)) — **reused
almost verbatim**; the only difference is the record was minted from a signature,
not the OAuth-approval connection token.

**Step 4 — authorize reads.** Because the PS holds no grantee key, reads are
authorized **from the session record** via a new `AuthMechanism`
(e.g. `mcp-session`) that `verifyDataReadPolicy` treats as `signer == grantee`.
This is the one contained policy addition; it is _not_ a PS-held delegate key —
the chatbot's own signature (Step 1) is what the session stands in for.

**Step 5 — refresh.** Re-run Step 1 as `exp` nears (cheap; a fresh signature).

This resolves the former open question; no `/plan-eng-review` gate remains before
Phase 1.

## 4. Reuse / drop / build

- **Reuse:** the read tools (`read_scope`, `get_scope_file`,
  `search_personal_context`, `list_granted_scopes`) and the read-client/policy
  path; the OAuth consent scaffolding for the user handshake; grant
  create/list/revoke contracts.
- **Drop (for this surface):** per-connection grantee generation, PS-side grantee
  key custody + encryption-at-rest, per-connection builder registration, and the
  per-connection record as the authorization of record (the on-chain grant is the
  durable authority). Note the web surface's stores are already IndexedDB-backed,
  so this is a modeling change, not a persistence rewrite.
- **Build:** the chatbot registry + verified onboarding; consent that grants to
  the chatbot's address; the transport↔identity binding; the two missing read
  tools (§5).

## 5. Read-surface gap analysis

Every HTTP **read** endpoint mapped to its MCP tool. (Write/owner endpoints are
out of scope per the read-only decision.)

| HTTP read endpoint                               | Existing tool                                     | Gap                                                                                                                                       |
| ------------------------------------------------ | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /v1/data` (list scopes)                     | `list_granted_scopes`                             | **Covered** — grant-filtered view is exactly right for a scoped app.                                                                      |
| `GET /v1/data/:scope` (latest)                   | `read_scope`                                      | **Covered.**                                                                                                                              |
| `GET /v1/data/:scope?at=<ts>` (historic version) | `read_scope` — no `at` param                      | **GAP 1:** add `at` to `read_scope` (read-client already threads it, [read-client.ts:242](../packages/core/src/mcp/read-client.ts#L242)). |
| `GET /v1/data/:scope/versions`                   | none                                              | **GAP 2:** new `list_scope_versions` tool + new `listVersions` read-client method (no equivalent exists).                                 |
| `GET /v1/data/:scope?fileId=…&content=raw`       | `get_scope_file` (already supports `at`+`fileId`) | **Covered.**                                                                                                                              |
| (MCP-only nicety)                                | `search_personal_context`                         | Keep.                                                                                                                                     |

**Net tool-side delta: one new tool + one new param + one read-client method** —
unchanged from v1; identity is where the real work moved.

## 6. Workstreams

### Phase 0 — Stable MCP endpoint (prerequisite)

A chatbot integration is long-lived, so the PS's MCP endpoint URL **must be
stable** — the current PS Lite relay URL rotates (`https://<sessionId>.psrelay.…`,
where `sessionId` is a random per-boot value unless persisted state is reused).
This is what produced the "MCP approval link was created for an old Personal
Server URL" failure; for a chatbot it would silently break every reconnect.

- Derive the relay `sessionId` **deterministically from the owner key/wallet**
  (mirroring the Node tunnel's wallet-derived subdomain,
  [tunnel/manager.ts:86](../packages/server/src/tunnel/manager.ts#L86)) so every
  boot for an owner reproduces the same endpoint, instead of relying on an
  easily-invalidated saved random id.
- The stale-URL check itself lives in the **unity-surfaces** web app
  (`readiness-diagnostics.ts` / `use-mcp-authorization.ts`); the fix is either an
  explicit owner-derived `sessionId` in that app's `relayOptions`, or relaxing
  `savedRelaySessionId` in the lite client so transport drift (`controlUrl` /
  `publicSuffix`) no longer discards the persisted session.
- **Note:** the OAuth authorization + connection stores are **already durable**
  (IndexedDB) on the web surface (`createIndexedDbMcpOAuthAuthorizationStore`), so
  the v1 "in-memory store" durability concern applies only to bare
  `personal-server-ts` Node defaults, not to the deployed web chatbot surface.

### Phase 1 — Chatbot identity & consent (the pivot)

1. **Chatbot registry + verified onboarding** — storage + admin/registration path
   for `{ builderAddress, publicKey, name, logo, homepage, redirectUris,
defaultScopes }`; validation that the address is a registered builder.
2. **Consent grants to the chatbot address** — branch/extend
   `approveMcpOAuthAuthorizationWithScopes` to issue the grant to the registered
   chatbot address and skip grantee generation/registration.
3. **Session handshake + read authorization** — implement `POST /mcp/session`
   (verify `Web3Signed` proof → mint token, per §3), the `mcp-session`
   `AuthMechanism` in `verifyDataReadPolicy`, and token resolution reusing
   `/mcp`'s `handleToken` path. Tests: a valid signed handshake mints a token;
   a tool call under that token is attributed to the chatbot's address and passes
   policy; replayed/expired/wrong-`aud` proofs are rejected.

### Phase 2 — Read-surface parity

1. `listVersions` on `McpDataReadClient` → `GET /v1/data/:scope/versions`
   (shape from `listDataVersionsContract`,
   [contracts/data.ts:204](../packages/core/src/contracts/data.ts#L204)).
2. `list_scope_versions` tool — grant-gated like every other tool.
3. `at` (collectedAt) param on `read_scope`; default = latest.
4. Tests, including the **isolation guarantee**: a chatbot granted only `scopeA`
   cannot read `scopeB`'s data or versions via any tool.

### Phase 3 — Consent UX & developer docs

- Consent screen shows the **verified** chatbot (name/logo from registry) and the
  exact scopes requested; owner approves the set; chatbot can never self-grant.
- Integration guide for app builders: onboarding (register keypair + metadata),
  the consent/OAuth handshake, the session/signing binding, the tool catalog, and
  `request_scope_access` for widening scopes in-band.

### Phase 4 — Validation & hardening

- **E2E:** Maple AI onboarded with a fixed identity → user approves a narrow scope
  set → chatbot reads only those scopes (incl. versions/historic) signing as
  itself → access logs attribute to the chatbot's registered address → grant
  revocation fails the chatbot closed immediately.
- **Adversarial:** a chatbot cannot exceed its grant via any new tool, cannot reach
  write/owner routes, cannot impersonate another registered chatbot, and an
  unregistered/anonymous caller is rejected at onboarding.
- Confirm `list_scope_versions` inherits sane size/timeout bounds.

### Phase 5 — Pay-per-read (x402 over MCP)

Chatbot pays the user per chargeable read; **payer = chatbot/grantee, payee =
data owner**, settled into gateway escrow against the grant's fee. This is
feasible _only_ in the chatbot-first model because the self-signing, funded
chatbot can produce the EIP-712 payment signature — the keyless owner's-Claude
MCP cannot. **Today MCP reads never pay** (the payment cycle is bypassed), so this
is net-new. Surfacing model: **per-read tool challenge** (decided).

1. **Wire payment deps** into the chatbot-first MCP `dataApiDeps` —
   `paymentEnabled`, `gateway`, `gatewayConfig`, `gatewayUrl`, `serverSigner`,
   `serverAddress`, `network` (omitted today, [mcp.ts:206](../packages/server/src/routes/mcp.ts#L206) /
   [lite/runtime.ts:1469](../packages/lite/src/runtime.ts#L1469); mirror
   [data.ts:100](../packages/server/src/routes/data.ts#L100)).
2. **Route paid reads through the x402 cycle** — the bounded-block reads behind
   `read_scope`/`search_personal_context` currently skip
   `handlePersonalServerDataRequest`/`handleX402Cycle`
   ([api/index.ts:358](../packages/core/src/api/index.ts#L358)) entirely, so add
   the payment cycle to that path.
3. **Per-read tool challenge** — a chargeable read tool returns
   `{ payment_required, challenge }` (amount/asset/EIP-712 message/`accessRecord`
   from `buildChallenge`); the chatbot EIP-712-signs the `GenericPayment` message
   with its key and re-invokes the tool with an optional `payment` argument
   (the `X-PAYMENT` payload); the PS verifies + settles via
   `POST {gateway}/v1/escrow/pay` and returns data + the `X-PAYMENT-RESPONSE`
   receipt. Mirrors the x402 challenge/retry at the tool layer.
4. **Tests:** free when `payment.enabled=false`; 402-style `payment_required` when
   on; a valid signed `payment` settles and returns data; wrong amount / stale
   nonce / wrong payer rejected; access still grant-gated independent of payment.

> Sequencing: Phase 5 depends on Phase 1 (self-signing identity — the payer) and
> Phase 2 (the read tools it augments). It is the last phase.

## 7. Out of scope (explicit)

- **Writes** (`POST /v1/data`) and mutations — needs a `vana:write` scope tier.
- **Owner/management tools** — grants CRUD, sync, delete, access-logs stay
  owner-only.
- **Finer OAuth scope strings** — stays coarse `vana:read` at the OAuth layer;
  fine-grained scoping is at grant-approval time.
- **Anonymous dynamic DCR for chatbots** — replaced by verified onboarding for
  this surface (the owner's Claude MCP keeps DCR).

## 8. Risks & open questions

1. **Session handshake (§3) — RESOLVED.** Signed handshake → session token
   (Option A). Residual implementation care: nonce replay store, `exp` window,
   `aud` binding, and keeping the new `mcp-session` `AuthMechanism` strictly
   scoped to grant-gated reads (never owner ops).
2. **Registry trust & governance** — who approves a chatbot into the registry, how
   keys rotate, how a compromised chatbot key is revoked network-wide. A stable
   global identity means a leaked key is higher-impact than an ephemeral grantee.
3. **`list_scope_versions` payload size** — default + max `limit`, offset
   pagination, mirror existing `maxBytes`/`timeoutMs` guards.
4. **`at` validation** — reject malformed/future timestamps as typed errors.
5. **Read-only vs. "same endpoints"** — narrower than the full HTTP API by design;
   confirm partners don't need write-back (e.g. Maple AI persisting chat history).
   If they do, reopens the write-tool + `vana:write` workstream.
6. **Endpoint stability (Phase 0)** — a rotating relay URL breaks any long-lived
   chatbot connection; owner-derived `sessionId` is the fix and is a prerequisite,
   not a nice-to-have.

## 9. Effort estimate

- Phase 0 (endpoint stability): **~1–2 days** — owner-derived `sessionId`; mostly
  in unity-surfaces + lite client.
- Phase 1 (identity & consent): **~3–5 days** — the pivot; new registry + consent
  branch + transport binding.
- Phase 2 (read parity): **~1–2 days** — small, patterned.
- Phase 3 (UX + docs): **~1–2 days.**
- Phase 4 (validation): **~1–2 days.**
- Phase 5 (pay-per-read x402 over MCP): **~3–5 days** — dep wiring + routing
  bounded-block reads through the x402 cycle + per-read challenge surfacing + tests.

The self-signing + verified-identity model _removes_ the durable per-connection
key-custody/encryption work that dominated v1's Phase 2, and shifts effort into
registry + consent + the transport binding.
