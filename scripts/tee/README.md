# TEE provisioning

Prerequisites: Phala CLI 1.1.21 logged in and Node.js 24.

```sh
ENCLAVE_AGENT_SECRET=... scripts/tee/provision.sh <name>
scripts/tee/destroy.sh <uuid>
node scripts/tee/kms-root.mjs
```

The inline compose clones `GIT_REF` (default `main`); pass `--ref <branch>` to `provision.sh` to test a branch.

Use the last command's output as `ENCLAVE_KMS_ROOT_PUBKEY`. Configure the Gateway with `ENCLAVE_AGENT_URL`, `ENCLAVE_AGENT_SECRET`, `ENCLAVE_KMS_ROOT_PUBKEY`, and `ENCLAVE_APP_ID_ALLOWLIST=0x<app_id>`.
