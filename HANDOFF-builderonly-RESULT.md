# Builder-only E2E result

## Files changed

- `scripts/e2e-job.ts` adds the builder-only validation, context, B1-B4 steps,
  scope threading, raw-read decryption summary, and optional wrong-auth check.
- `scripts/tee/README.md` documents an example builder-only invocation.
- `HANDOFF-builderonly-RESULT.md` records this implementation and validation.

## Environment contract

- `E2E_BUILDER_ONLY=1` enables builder-only mode.
- `E2E_REMOTE=1` is required; builder-only mode has no local fake-sandbox
  path.
- `E2E_SKIP_BUILDER_REGISTRATION=1` is required because no owner signature is
  available to register the builder.
- `OWNER_ADDRESS` is required and must be a valid EVM address.
- `GRANT_ID` is required and must be a bytes32 `0x`-prefixed hex value.
- `BUILDER_PRIVATE_KEY` is required and must be a 32-byte `0x`-prefixed hex
  private key.
- `GATEWAY_URL` is optional and retains the existing default.
- `SCOPE` is optional. When omitted, the first scope in the fetched grant is
  used; an explicitly selected scope must be present in the grant.
- `E2E_BUILDER_ONLY_NEGATIVES=1` optionally runs the wrong-builder-auth
  negative.
- `VERCEL_PROTECTION_BYPASS`, `CHAIN_ID`, `DATA_REGISTRY_CONTRACT`,
  `DATA_PORTABILITY_SERVER_CONTRACT`, `DATA_PORTABILITY_GRANTEES_CONTRACT`, and
  `DATA_PORTABILITY_PERMISSIONS_CONTRACT` retain their existing behavior.
- `OWNER_PRIVATE_KEY` and `E2E_RECOVERY` must be unset. `E2E_WARM_RUNS` must
  be unset or zero.

Builder-only mode does not require `E2E_NODE_IDS`, `OPERATOR_SECRET`,
`CRON_SECRET`, enclave-agent settings, or fake-runtime settings.

## No-network validation

Command:

```sh
env -u OWNER_PRIVATE_KEY -u E2E_RECOVERY -u E2E_WARM_RUNS \
  -u E2E_REMOTE -u E2E_SKIP_BUILDER_REGISTRATION -u OWNER_ADDRESS \
  -u GRANT_ID -u BUILDER_PRIVATE_KEY E2E_BUILDER_ONLY=1 \
  node_modules/.bin/tsx scripts/e2e-job.ts
```

Output:

```text
Job E2E setup failed: OWNER_ADDRESS is required in builder-only mode
```

The process exited with failure before any Gateway request.

## Deviations

No live Gateway or owner flow was invoked, and the existing normal-mode steps
and IDs remain unchanged.

The repository-wide Prettier check reports the pre-existing, user-owned
untracked `HANDOFF-builderonly.md`. That file was deliberately left untouched
and excluded from this change. Prettier passes for every file in this result's
change slice.

## Fix round 2

B1 incorrectly read `state` from the nested identity evidence, and B2 treated
the API's parsed `scopes` array as database JSON text. B1 now checks the
top-level response state, while B2 validates and uses the returned non-empty
string array directly. The no-network lint and formatting gates still pass.
