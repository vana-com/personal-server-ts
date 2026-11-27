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
- **Slot expiry.** When the slot holds a scope that is not one of this PS's
  PDPP entries (a legacy scope), the signed expiry is the earliest of the
  gateway's and the finalized chain's expiry. A PDPP grant that would last
  longer is then cut off on chain at that time. When the slot holds only
  this PS's entries, it lasts as long as its longest grant; each grant is
  also bounded by its own `expires_at` at the PS and at the gateway.
- **Window after approval, and after turning the setting on.** A grant is
  readable only once its registration is final on chain. Until then reads
  answer 500 with `Retry-After` ("retry"), not `grant_revoked`. At boot with
  the setting on, every active locked-rule grant without a registration is
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
- **Scope labels.** The PS binds, one label per request, each stream-sync
  per-stream row (`pdpp.<c>~<ns>.<stream>` → that stream), the connection
  log row (`pdpp.<c>~<ns>.~log` → every declared stream of the source) and
  each legacy readable scope it projects (→ every stream the projection
  reads). Gateway bindings are immutable. When a source's declaration later
  adds a stream, the log label keeps its first, smaller stream set (the
  gateway answers 409 and the PS records it): a paid read of the log is then
  checked against the old set, so a grant covering only the old streams can
  pay for a log that also carries the new stream's operations. The other
  labels are bound regardless. This PS publishes no design-2 meaningless
  labels; a paid read under a label the PS never bound gets the gateway's
  `SCOPE_UNBOUND`, except the unbound stream-sync physical scopes the
  gateway accepts under a slot that also holds a legacy scope.
- **Turning the setting off** stops all on-chain registration and removal.
  Entries already on chain stay there.
