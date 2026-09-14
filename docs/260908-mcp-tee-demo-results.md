# Single-TEE MCP demo results — 2026-09-08

The ordinary Claude Desktop client completed OAuth, discovered the existing
seven MCP tools, and read the owner's approved `spotify.profile` scope through
`https://mcp-dev.vana.org/mcp`. A second fresh read succeeded after the owner
Web, Account, and Lorebook pages were closed and the previous sandbox had been
evicted. This is a single-CVM demonstration, with the limits below.

## Tested deployment

| Item                           | Value                                                                                                                                                         |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Personal Server runtime source | `a16fd5b56430353b3b1ca9bede0a9eda849a3bef`                                                                                                                    |
| Personal Server image          | `vanaorg/personal-server@sha256:11db47f890dee98c705c8f8cea18e471483a2629ffab79078df00838e7a49614`                                                             |
| TLS ingress image              | `dstacktee/dstack-ingress:2.5@sha256:97285855a83ce6682447eb1f36e59c1927b9188a51b213e34d79acadd8425c78`                                                        |
| CVM                            | `87c32ca4-49c9-4a83-b0af-ef5465cbbe18`                                                                                                                        |
| Application ID                 | `ec9a39de98c760e1ded9f1e97016dc5f0e357cf2`                                                                                                                    |
| Instance ID                    | `1ac22335a2da1ca6a024396c4a557907279403ab`                                                                                                                    |
| Measured compose               | `9886a4d0f119bf6914caf9c4e62c620aefaa4c46310da5153c971bfa33f98d85`                                                                                            |
| OS image                       | `dstack-0.5.9`, `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033`                                                                            |
| Gateway worker                 | `spike-mcp-demo-a1`, admitted with current heartbeat                                                                                                          |
| Web consent preview            | `vana-web-enclave-preview.vercel.app`, deployment `dpl_H2cJo4rh2NgNqcnApFfL5yoThnga`, Unity source `7cb42e0f` plus the isolated preview Gateway configuration |

Only the existing demo CVM was updated. Its application ID and KMS identity
were retained; its previous compose and credential recovery references were
saved before the update. The previous worker, `spike-b3-f1`, was drained after
the new worker was admitted. No extra CVM or wildcard certificate sharing was
introduced.

## Transport and certificate evidence

Cloudflare serves DNS only for this name. The records are:

- CNAME `mcp-dev.vana.org` → `_.dstack-pha-prod5.phala.network`.
- TXT `_dstack-app-address.mcp-dev.vana.org` →
  `1ac22335a2da1ca6a024396c4a557907279403ab:443`.
- CAA `mcp-dev.vana.org` → `0 issue
"letsencrypt.org;validationmethods=tls-alpn-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/3725271346"`.

The released ingress generated the ACME account and certificate key inside
the CVM. No DNS credentials were installed in that container. TLS terminates
there, and port 8788 is unpublished; onward MCP traffic stays on the CVM's
private Docker network. Public logs inspected during the run contain transport
metadata and lifecycle milestones, not MCP bodies or key material. No private
key, master signature, OAuth code, or bearer token was extracted for this proof.

The served Let's Encrypt certificate SHA-256 fingerprint is
`52992356aa20525f30b2521b135e3ede7597a97db24de480c3e5d224197be4ef`.
It matches the certificate in the [public TEE evidence](https://mcp-dev.vana.org/evidences/).
The manifest checksums pass and its SHA-256 digest matches the hardware quote's
`report_data`. Phala's verification API returned `quote.verified: true`, checksum
`aa931db8e9b33ff09dea6795185732c82c599657586b6a5daba397ea756c0627`.
All four RTMR registers were independently replayed from the event log and
matched the verified quote; the application, compose and OS events match the
values above. The SHA-256 hash of the exact fetched `app_compose` string also
matches that measurement, and its embedded Docker compose is byte-identical to
the deployment copy. The verification response and collateral were retained.

This verification uses Phala's remote signature-verification service; a local
QVL run was not performed. Certificate-transparency history retrieval failed
with timeout/502, so this report does not claim a completed historical
certificate audit. DNS and WebPKI remain trust assumptions: an operator can
change DNS/CAA, and existing wildcard certificates were not independently
ruled out. The demonstrated endpoint used the certificate bound to this TEE.

## Ordinary client and browser-closed execution

Claude Desktop created a custom connector named **Vana TEE demo**, using DCR,
PKCE S256, and the normal Claude callback. The authenticated Web owner approved
only `spotify.profile`; the grantee was created and held inside the TEE.

The first prewarm attempt hit the existing five-second Web/Account helper
limit and failed closed before grant signing. A manual retry succeeded: the
owner sandbox became healthy in 5.1 seconds and completed Spotify hydration in
8.9 seconds. This cold signing timeout remains a usability limitation.

Claude then discovered these seven existing tools: `get_scope_file`,
`list_granted_scopes`, `list_granted_sources`, `list_scope_blocks`, `read_scope`,
`request_scope_access`, and `search_personal_context`.

The actual `list_granted_scopes` response contained exactly `spotify.profile`,
`dataStatus: ready`, and `sizeBytes: 310`. The actual `read_scope` response
contained two `vana-envelope` blocks, collected at `2026-09-08T21:22:24Z`.
The public fixture profile contained `display_name: kahtaf`, `id: kahtaf`,
`uri: spotify:user:kahtaf`, `following: 19`, and one public avatar URL.

For the second call, the fresh-owner Web, Account, Lorebook, and completed
callback pages were closed. At `22:58:40 UTC` the agent's sandbox list was empty.
A fresh Claude `read_scope` call, with the same existing connection, started
container `e449def5e62bc2dd68e831cd1122b297f4f9191b92d847ef9b6dce29ab950aad`
and returned the same original grant and profile. The first read had used
container `03e8f4b299c96d37244a257299d86affff45957cea77d7cc4374c7bc69e1d390`.
No owner page was reopened and no additional grant or OAuth flow was used.

The client conversation is [Vana TEE demo connector scope testing](https://claude.ai/chat/8f86500d-ca84-4490-95ad-bb07cb561a4f).
Access to that conversation depends on the user's Claude account.

## Full CVM restart and denied scope

A restart of the same CVM was requested at `23:00:34 UTC`. At `23:05:29 UTC`,
the agent was healthy with the same app ID, instance ID, measured compose, and
certificate fingerprint. The owner readiness endpoint returned `true` from
persisted encrypted state while the sandbox list was empty. The demo's
boot-time package installation/build contributed to roughly four to five
minutes of interruption; this is not a measured production recovery target.

Claude made another fresh `read_scope` call with the existing connection,
without reauthorization or an owner browser page. It succeeded with the same
original grant and profile. The agent recorded a newly created sandbox,
`a4dcd8f8ccfd9b688e0ec1fb87cabc08a5d55bcc38b43ec71c4fe8ae10cb792c`, at
`23:06:20 UTC`. This exercises persisted connection/grantee, bearer lookup,
owner binding, wakeup envelope, and TLS certificate state after ingress and
CVM restart. It reads the previously stored Spotify snapshot; it does not
prove an upstream Spotify recollection.

A final live Claude call to the unapproved scope `spotify.playlists` returned
this actual MCP error, without creating another grant:

```json
{
  "error": "scope_not_granted",
  "message": "Scope 'spotify.playlists' is not covered by any grant on this MCP connection.",
  "grantedScopes": ["spotify.profile"]
}
```

Public HTTPS probes also returned 401 for anonymous/invalid-bearer MCP calls,
with the expected protected-resource metadata challenge, and 400
`invalid_redirect_uri` for an unallowlisted DCR callback.

## Validation and scope

The runtime source passed TypeScript, ESLint, formatting, the production build,
and 1,935 tests across 152 files. The independent local review reported no P0
findings. Native Compose validation also passed. Focused tests cover encrypted
state reopen, single-use code replay rejection, grant revocation, wrong-owner
rejection, connection-grantee binding, expanded-scope rejection, and stale
identity epoch rejection before sandbox acquisition. These negative cases are
local automated tests unless a live result is explicitly stated above.

Encrypted state is a single-writer store without disk-snapshot rollback
protection. Instance replacement requires a DNS change. Fleet failover,
cross-CVM dispatch, shared ACME state, resumable MCP streams, and an accelerated
renewal exercise are outside this demonstration.
