# Single-CVM MCP demo

This opt-in demo serves `https://mcp-dev.vana.org/mcp` through Phala's native
TLS passthrough. The released `dstack-ingress` sidecar creates its TLS and ACME
keys inside the existing CVM, terminates TLS there, and forwards to the agent's
unpublished port 8788. The agent resolves each bearer connection to an owner,
checks signed grants and the current identity epoch, and invokes the existing
MCP engine in that owner's gVisor sandbox. MCP request and result plaintext
remain on the CVM's private network until the response is encrypted by TLS.

## State and consent

The agent derives a separate `mcp/ingress/state/v1` key from dstack and stores
AES-256-GCM ciphertext on the `mcp-state` volume. This single-writer store keeps
connection grantees, hashed bearer tokens, OAuth authorization/code-use state,
immutable owner bindings, and sealed owner wakeup envelopes. Owner sandboxes
remain ephemeral. TLS certificates and ACME account state persist on the CVM's
encrypted disk in a separate volume; private keys must never be exported.

OAuth uses the existing PKCE S256 implementation. The demo allowlists callback
URLs explicitly. Web consent reads the pending authorization's public grantee
metadata directly from the TEE, creates grants with the existing owner signer,
and triggers the existing authenticated prewarm. The TEE records that prewarm's
sealed envelope. Web polls `/v1/mcp/readiness?owner=<address>&chainId=14800`, then
approves with `{ owner, chainId, grants: [{ grantId, scopes }] }`. Approval
verifies the Gateway's owner-signed grant and signed builder against the actual
connection grantee. The master signature never passes through this API.

Every MCP call checks the signed grants again and compares the persisted
identity with the Gateway's currently sealed owner/chain/epoch before unseal.
Missing or replaced identity state fails closed. An owner who has no cached
envelope must prewarm while signed in. The same registry and runtime used by
encrypted jobs wake the sandbox, hydrate the approved scopes, and execute the
existing bounded MCP tools. Revoked grants stop further calls.

## Deployment boundary

`docker-compose.mcp-demo.yml` is a template. Before deployment, render the
public agent/runtime image digests, Personal Server image digest, exact source
commit, Gateway/storage URLs, and demo settings into literals in a separate
deployment copy. This makes those choices visible in the measured compose.
Only authentication secrets remain encrypted environment inputs. Preserve the
existing CVM application ID and capture its prior compose and encrypted-env
recovery references before updating it. Never start another CVM for this demo.

The TLS sidecar uses `tls-alpn-01`, with no DNS credentials. It prints the exact
DNS-only CNAME, instance-specific TXT mapping, and ACME-account CAA records to
configure. Check the records against the existing CVM and the emitted public
attestation evidence before creating them. A proxied/CDN record would change
the intended TLS boundary. Port 8788 must remain unpublished.

This is a single-instance demo, not a fleet state store or failover mechanism.
TLS-ALPN pins one CVM instance; instance replacement needs a DNS update. The
current MCP engine uses stateless POST/JSON responses; long-lived GET sessions
and resumable streams are not introduced here. Persistent encrypted state does
not itself provide protection against operator disk-snapshot rollback.

## Proof required before calling the demo complete

- Full repository checks and independent review against the immediate parent.
- Certificate issuance inside the CVM, public certificate/evidence binding,
  reviewed compose measurement, and public DNS verification.
- Ordinary client OAuth and tools against an existing owner data scope.
- Browser closed, owner sandbox evicted/recreated, same connection still works.
- Ingress restart retains OAuth state; code replay and revoked/wrong-owner
  requests fail, and no key or MCP payload appears in external logs.

The implementation and local tests alone do not establish these live results.
