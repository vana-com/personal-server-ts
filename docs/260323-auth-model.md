# Personal Server Auth Model

This document freezes the intended meaning of Personal Server auth mechanisms.

## Auth Matrix

| Mechanism               | Issued by                                      | Used by                                      | Authenticated as | Policy bypass |
| ----------------------- | ---------------------------------------------- | -------------------------------------------- | ---------------- | ------------- |
| `devToken`              | local Personal Server dev mode                 | legacy local/dev clients such as DataConnect | server owner     | yes           |
| `/auth/device` token    | Personal Server                                | CLI self-hosted login                        | server owner     | no            |
| cloud CLI session token | account.vana.org via `POST /auth/device/token` | remote CLI sessions                          | server owner     | no            |
| `PS_ACCESS_TOKEN`       | deploy/operator config                         | cloud control plane / automation             | server owner     | no            |
| `Web3Signed`            | external signer                                | builders and owner-signed requests           | request signer   | no            |

## Route Intent

- Owner-session auth is for owner operations such as ingest, delete, listing scopes, listing versions, and revoking CLI tokens.
- The long-lived `PS_ACCESS_TOKEN` is the cloud control-plane credential. It is not the token returned to the CLI at login.
- Cloud and self-hosted CLI logins both end up with token-store-backed owner session tokens that can be revoked independently.
- Builder/grant reads stay separate. `GET /v1/data/:scope` still requires the normal builder + grant path unless a future product decision explicitly opens owner reads.
- `devToken` remains the explicit escape hatch for local testing and trusted development flows. It should not be the default semantic model for newer CLI bearer tokens.
