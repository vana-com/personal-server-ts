# Own-app read fees

Personal Server core owns this payment decision (BUI-938). Keep this contract aligned with `own-app.ts`, the data API and Account's `/api/v1/apps/own-data-read-eligibility` endpoint.

A server can set `payment: { enabled: true, ownAppAccountUrl: "https://account-dev.vana.org" }` for the dev Account candidate. The URL is an operator-selected HTTPS origin, never a read parameter. Without this optional setting the existing payment policy remains in effect. Deploy the Account endpoint before enabling it on a server.

After the app signature and live grant pass the existing owner, grantee, scope, expiry and revocation checks, the server asks Account whether the authenticated app and its configured data-owner wallet belong to the same Account on the configured chain. It binds every response field and accepts only `eligible`. Matching apps skip the entire read-time x402 cycle (including any first-read registration component) and return `X-Vana-Payment-Exemption: own-app`, without a payment response or settlement. The grant, scoped/redacted view and access log remain unchanged. This never turns the app into the owner credential or authorizes writes/owner-only operations.

A different Account's app, missing attribution or an unlinked data-owner wallet remains payable. An unavailable, malformed, redirected or mismatched Account response returns 503 `OWN_APP_ELIGIBILITY_UNAVAILABLE`, rather than granting an exemption or unexpectedly charging the owner. No positive ownership result is cached. Owner-wallet reads keep their existing exemption.

The setting is wired through Node's config/bootstrap and data/MCP routes, and PS-Lite's data API. It does not disable payment globally. CLI and Desktop require a Personal Server build carrying this change and this setting; existing published runtime pins do not acquire the behavior from an Account deployment alone. PS-Lite installations with payment disabled already serve all granted reads free and cannot prove a selective exemption. Hosted/enclave workers, inference billing and independent servers are not established by the local dev candidate; they must adopt an authoritative policy before claiming the same guarantee.

This waives read-time data access payment, not unrelated transaction gas, storage, inference or registration costs incurred elsewhere. It creates no grant, funding allocation, credit or cross-network data transfer. Moksha test-credit funding (BUI-945) keeps normal fee metering and is independent of this exemption.
