# PDPP identifiers and chain-enforced grants: operator notes

What a Personal Server operator needs to know about two PDPP Core v0.1.0
behaviours: the identifiers clients receive (AS item 29), and the design-2
chain registration of grants (`pdpp.chainGrants.enabled`).

## Identifiers clients receive (AS item 29)

- Every grant issued by this build carries a pairwise `subject.id` for its
  client: `pws_` plus 32 random bytes. It is assigned once per (owner,
  client), recorded before any grant discloses it, and never reassigned.
- Locked-rule (v0.1.0) grants also carry pairwise instance handles: `pwi_`
  plus 32 random bytes, one per (owner, client, connection). The client sees
  only its handles: in its grant, in every record and tombstone
  `instance_id`, and in blob `fetch_url`. It names an instance only by its
  handle (`instance_id` on a single-record or blob read, `instance_ids` in a
  later authorization request). Owner surfaces show the stored ids.
- The RS-only introspection response carries `pdpp_instance_bindings`
  (handle → stored instance). A separated RS resolves handles only through
  it.

### Grants issued before pairwise identifiers

Grants are immutable, so grants issued before pairwise identifiers were
introduced keep the identifiers they were issued with:

- `subject.id` is the internal subject, which on a Personal Server is the
  owner's wallet address (lowercase). Any client holding such a grant holds
  that address.
- Instance handles are the stored connection ids, shared by every client.

Where such grants can exist: the locked v0.1.0 rules are new in this
branch (introduced by b8731ffa, not in `origin/main` at 431dc501), so no
locked-rule grant was issued by a released build; old locked-rule grants
exist only in development or test data. `origin/main` can issue pre-lock
v0.1 and v0.2 grants, but only on a deployment that turned on the opt-in
`pdpp.enabled` (default off), and those carry the wallet address as
`subject.id`. Pre-lock v0.1 grants are refused by this build (AS item 21);
v0.2 grants issued there keep the address. Which production deployments, if
any, enabled PDPP was not checked from this repository.

A client that holds an old grant and a new one sees two different
`subject.id` values and two different handles for the same instance. No new
grant is issued with the wallet address or with stored instance ids. Owners
who want the old identifiers withdrawn must revoke those grants and approve
again.

## Chain-enforced grants (design 2)

Off by default. When on, each issued grant is registered as a salted entry
(`pdpp:sha256:…`) in the owner's PermissionsV2 slot for the app, and client
record and blob reads require that entry to be live on chain.

- **Each client needs `granteeAddress`** in `pdpp.clients`. Approval for a
  client without one is refused.
- **What the PS signs.** Only its own entries, plus scopes the finalized
  chain already lists for that slot. A scope that only the gateway's answer
  lists is dropped, never signed. The slot id is derived from the contract's
  domain separator, the owner and the app's builder id, and a gateway answer
  for another id is refused.
- **New registrations wait for another surface's settling scope.** When
  the gateway lists scopes for the slot that are neither this PS's entries
  nor on the finalized chain, and the slot's latest registration is still
  `pending`, `sent` or `confirmed`, the PS does not register a new grant: it
  retries on the reconcile timer until that registration is finalized (its
  scopes are then kept) or has failed or reverted (they are then not kept).
  Meanwhile the new grant answers "retry later". It never signs over that
  scope, also after 24 hours: from then on GET /pdpp/v1/grants shows the
  grant's `chain` as `waiting_on_other_grant` with the other registration's
  `registration_outcome` and `past_bound: true`, so the owner's app can say
  "waiting for another grant to this app to settle".
- **A grant end never waits.** An owner's revocation outranks another
  surface's settling registration. On grant end the PS signs at once, at
  `currentGrantVersion + 1`, over its own remaining live entries plus
  finalized-chain scopes. A registration from another surface still
  settling in that slot is overtaken, and that other grant must be signed
  again by its surface. The PS's own pending registrations for the app are
  re-queued. If another writer later puts the ended entry back on the
  finalized chain at a higher version, the PS signs the removal again, and
  it never re-signs an entry of an ended grant, whatever the gateway lists.
- **What a gateway paid read releases.** The gateway authorizes payment
  only. The bytes are released by this PS: legacy and stream-sync scopes by
  `/v1/data/:scope` (and the MCP and job read paths), which require the slot
  to list the requested scope itself or a wildcard covering it, so a PDPP
  fingerprint never releases anything there; PDPP data by the record and
  blob routes, under the client token, which enforce the grant's fields,
  time bounds, resources and instance. A label binding therefore lets a
  PDPP grant pay at the gateway, never read more than the grant allows.
- **Slot expiry.** When the slot holds a scope that is not one of this PS's
  PDPP entries (a legacy scope), the signed expiry is the earliest of the
  gateway's and the finalized chain's expiry. A PDPP grant that would last
  longer is then cut off on chain at that time. When the slot holds only
  this PS's entries, it lasts as long as its longest grant; each grant is
  also bounded by its own `expires_at` at the PS and at the gateway.
- **Window after approval, and after turning the setting on.** A grant is
  readable only once its registration is final on chain. Until then reads
  answer 500 with `Retry-After` ("retry"), not `grant_revoked`. At boot with
  the setting on, every active locked-rule or v0.2 grant without a registration is
  queued (a client without `granteeAddress` is skipped and its grants stay
  unreadable). The window lasts until the gateway's `/v1/settle` lands the
  slot, which can also wait for the registration fee.
- **Grant end.** A grant that ends (owner end, revocation, erasure,
  expiry, a consumed single-use grant whose last token is gone) has its entry
  removed: a removal-only upsert when other entries remain, a V2 revocation
  when none do. The PS records the end as final only when the finalized
  chain no longer lists the entry (or holds no slot, or the slot's expiry has
  passed there). A failed or reverted removal is signed
  again. Reconciliation runs at boot, every minute, and after each write to
  `/pdpp/v1`; every gateway call times out after 10 s.
- **Scope labels.** The PS binds each stream-sync per-stream row
  (`pdpp.<c>~<ns>.<stream>` → that stream), the connection log row
  (`pdpp.<c>~<ns>.~log` → every declared stream of the source) and each
  legacy readable scope it projects (→ every stream the projection reads).
  It sends them in batches of at most 100 labels and under 1 MiB, and reads
  the gateway's per-label result (`bound`, `unchanged`, `conflict`); a
  conflict does not stop the other labels. Gateway bindings are immutable.
  When a source's declaration later adds a stream, the log label keeps its
  first, smaller stream set (`conflict`): a paid read of the log is then
  checked against the old set, so a grant covering only the old streams can
  pay for a log that also carries the new stream's operations. A label over
  256 streams (the gateway's limit) is not sent. Labels not bound are shown
  on GET /pdpp/v1/grants as `chain.unbound_labels`, with
  `chain.bindable: false` when one was over the limit: paid reads under that
  label cannot resolve. This PS publishes no design-2 meaningless labels; a
  paid read under a label the PS never bound gets the gateway's
  `SCOPE_UNBOUND`, except the unbound stream-sync physical scopes the
  gateway accepts under a slot that also holds a legacy scope.
- **The finalized chain decides; the gateway is a hint.** For each grant
  the PS records `seen_version`: the highest slot `grantVersion` at which
  the finalized chain listed the grant's entry in a live slot, or at which
  this PS itself signed a write listing it. A gateway answer never raises it.
  - **Confirmed removal.** When the finalized chain, at a version above
    `seen_version`, omits the entry or holds the slot revoked or expired (a
    V2 revocation keeps the scopes and sets a past expiry), another signer
    removed it (for example the owner dropping one grant, or ending the
    whole app, through Vana Account). The registration becomes
    `dropped_elsewhere` and the grant ends (ending reason
    `dropped_elsewhere`, no disposition change), so client reads are
    refused whatever the chain-grants setting, GET /pdpp/v1/grants shows
    `chain.status: "dropped_elsewhere"`, and nothing registers it again; the
    owner can approve the app again. A whole-slot revocation ends every own
    grant of that slot this way.
  - **Hinted removal.** When only the gateway says so (its view omits the
    entry, or the slot is revoked or expired there, at a version above
    `seen_version`), the PS does not end anything. It stops carrying the
    entry, answers its reads "retry later", and shows
    `chain.status: "pending_confirmation"`. On the reconcile timer it checks
    the finalized chain again: a confirmation ends the grant as above; a
    chain that still lists the entry at a version at least the gateway's
    restores it, with no lasting effect.
  - **New grants wait for an unconfirmed sibling.** While any of the PS's
    own grants in a slot is `pending_confirmation`, a new registration for
    that slot waits (its reads answer "retry later"), so it never signs a
    list that silently leaves that grant out; it proceeds once the chain
    confirms or contradicts the hint. A grant end does not wait: it is sent
    at once and leaves the unconfirmed grant out (if the chain later
    contradicts the hint, that grant must be registered again by approving
    it again).
  - A grant bound after a lost answer from before the PS recorded its signed
    versions has no `seen_version` (`unknown`): it is not checked for
    removals until the finalized chain lists it.
  - **Never into a dead slot.** The PS carries its own entries only into a
    slot that is live at the gateway and live on the finalized chain, and
    only entries the finalized chain lists. A new approval for an app whose
    slot was revoked elsewhere therefore signs only the new grant's entry.
  - If another signer later lists a dropped entry again, the PS's next
    write leaves it out, which removes it. If the gateway refuses a carried
    entry (`PDPP_ENTRY_BOUND_ELSEWHERE` or `PDPP_GRANT_DOCUMENT_REQUIRED`),
    the PS drops it the same way and sends the write without it; this path
    only ever drops entries. A stale-version 409 is not a refusal of the
    entry: the PS reads the slot again and retries the same write. An entry
    bound under another slot or contract is never sent.
- **Reads never wait for the gateway.** A read of a grant whose
  registration is pending answers "retry later" at once; the registration
  is retried in the background.
- **Turning the setting off after use.** With the setting off, the PS stops
  all on-chain registration and removal, so entries already on chain stay
  there and a paid read at the gateway can still resolve them after their
  grants end. A server with any grant still `bound` or `ending` on chain
  therefore runs PDPP chain grants fail closed when booted with the setting
  off: the server starts, but PDPP approvals are refused and PDPP client
  reads are denied, with an error that names the remedy. Operators should
  keep the setting on, or end those grants first (and let reconciliation
  finish). Setting `pdpp.chainGrants.allowDisableWithRegistrations: true`
  serves PDPP without chain grants and leaves those entries on chain.
