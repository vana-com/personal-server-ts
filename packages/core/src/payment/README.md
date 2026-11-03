# Own-app read fees

Personal Server core owns this payment decision (BUI-938). Keep this contract aligned with `own-app.ts`, the data API and Account's `/api/v1/apps/own-data-read-eligibility` endpoint.

A server can set `payment: { enabled: true, ownAppAccountUrl: "https://account-dev.vana.org" }` for the dev Account candidate. The URL is an operator-selected HTTPS origin, never a read parameter. Without this optional setting the existing payment policy remains in effect. Deploy the Account endpoint before enabling it on a server.

After the app signature and live grant pass the existing owner, grantee, scope, expiry and revocation checks, the server asks Account whether the authenticated app and its configured data-owner wallet belong to the same Account on the configured chain. It binds every response field and accepts only `eligible`. Matching apps skip the entire read-time x402 cycle (including any first-read registration component) and return `X-Vana-Payment-Exemption: own-app`, without a payment response or settlement. The grant, scoped/redacted view and access log remain unchanged. This never turns the app into the owner credential or authorizes writes/owner-only operations.

A different Account's app, missing attribution or an unlinked data-owner wallet remains payable. An unavailable, malformed, redirected or mismatched Account response returns 503 `OWN_APP_ELIGIBILITY_UNAVAILABLE`, rather than granting an exemption or unexpectedly charging the owner. No positive ownership result is cached. Owner-wallet reads keep their existing exemption.

This local Desktop candidate wires the setting through Node's config/bootstrap and data/MCP routes. It does not disable payment globally. CLI and Desktop require a Personal Server build carrying this change and this setting; existing published runtime pins do not acquire the behavior from an Account deployment alone. PS-Lite, hosted/enclave workers, inference billing and independent servers are outside this candidate.

This waives read-time data access payment, not unrelated transaction gas, storage, inference or registration costs incurred elsewhere. It creates no grant, funding allocation, credit or cross-network data transfer. Moksha test-credit funding (BUI-945) keeps normal fee metering and is independent of this exemption.

## Release-review candidate

The implementation is forward-adopted from official dev revision `d87e6727d8160b1ec3a0593acf124b2357ae6f92` onto current upstream main `2df2ae99e4f0960c2337adf2f2c8984a8f3c6c68`. It retains the upstream storage, replica and recovery fixes, including #535 and #537. Desktop derives `payment.ownAppAccountUrl` from its selected Account configuration.

The rebased candidate passes its build and 198 focused data/MCP/schema tests locally. The earlier native Desktop and same-grant synthetic consumer proof belongs to implementation `392a3af` and Unity `4bc4ac6b3`; it is not relabelled as native proof of this newer base. Accept this change upstream, adopt the accepted merge SHA in Desktop's runtime lock, and verify the resulting distributed bundle through normal delivery. This source preparation creates no release or deployment.
