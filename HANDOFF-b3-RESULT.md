# Level B run 3 findings — result

## 1. logStageFailure / docker stderr

Commit `dbf329c` changes `packages/enclave/src/jobs/run.ts` to log a structured
root error (`name` and `message`) plus at most five structured causes. Cause
walking stops on repeated `Error` objects, so circular chains cannot loop.

`packages/enclave/src/sandbox/docker-runtime.ts` now includes the final 2,048
characters of trimmed Docker stderr in a wrapping error and retains a sanitized
copy of the original `execFile` error as its cause. Values supplied through the
secret environment (`PS_ACCESS_TOKEN` and `VANA_MASTER_KEY_SIGNATURE`) are
redacted from both messages. The Docker CLI arguments contain only the names of
those secret variables, not their values.

Regression coverage is in `jobs/run.test.ts` (message, cause, and circular-chain
handling) and `sandbox/docker-runtime.test.ts` (stderr tail, bound, and secret
redaction). The focused red tests failed with the old logger/runner, then passed
after the change. The commit gates passed.

## 2. replicate.sh --secret-out / --secret-keychain

Commit `2e6125a` makes exactly one secret destination mandatory:

- `--secret-out <path>` uses `noclobber` with `umask 077`, writes only the raw
  generated secret plus its terminating newline, and refuses existing files or
  symlinks.
- `--secret-keychain <service>/<account>` splits on the first slash and invokes
  `security add-generic-password` without `-U`. The local `security` help
  confirms that omitting `-U` makes an existing item an error instead of
  updating it.

The script never prints the secret. A scripted CLI exercise verified mode 0600,
65 output bytes (64 hex characters plus newline), overwrite refusal, first-slash
Keychain parsing, and absence of the fixed test secret from stdout. The README
now documents both destinations, retrieval from Keychain, and the value to use
for the registration placeholder. `bash -n scripts/tee/replicate.sh` and all
commit gates passed.

## 3. WORK_DELAY_MS

No TypeScript wiring defect was found. `readInteger` receives `fallback=0` and
`minimum=0`; `Number("120000")` resolves to 120000; `main.ts` passes the value
to `runJob` independently of runtime; and `runJob` sleeps after acquisition and
before sandbox execution.

Commit `1ec5dd7` adds the missing integrated Docker-path test. It constructs a
real `createDockerRuntime` around a scripted `DockerClient`, places it in a
`SandboxRegistry`, and proves that `runJob` calls the 120,000 ms sleep and does
not call the sandbox execute endpoint until that sleep resolves. Boot-log
coverage now runs for both fake and Docker configurations and verifies this
operator-visible record exactly:

```text
WORK_DELAY_MS=120000ms is set — this node artificially delays every job; do not use in production
```

The best remaining explanation is a platform-level Phala/dstack replication
constraint: `phala cvms replicate -e` may only replace encrypted-environment
keys already present in the source CVM's genesis environment. That fits the
observation that `NODE_ID` and `NODE_SECRET` changed while the newly introduced
`WORK_DELAY_MS` did not. This cannot be confirmed without a live CVM. A future
live check should provision the source with `WORK_DELAY_MS=0`, override it on a
replica, and compare the boot log. No platform assumption was encoded in the
script. All commit gates passed.

## 4. Density findings

Commit `15836d6` raises the Docker sandbox health default from 60 seconds to 120
seconds. Its red/green regression test proves a cold start can remain unhealthy
at 60,000 ms and subsequently become healthy instead of being removed at the
old boundary. This is evidence-based against the observed successful attempt's
approximately 72-second claim-to-completion duration under five-way contention
on one vCPU. `SANDBOX_MAX` remains 20.

Observed run facts:

- Five staggered fresh-owner submissions all returned HTTP 202 after the 25
  second synchronous wait ceiling.
- There were 10 `sandbox-acquire` warnings across five job IDs: two each for
  four jobs and one for the job that eventually succeeded.
- Four jobs reached attempt 3 after attempts 1 and 2 recorded `lease_lost`; one
  job succeeded on attempt 2 after approximately 72 seconds. Four remained
  unresolved when observation stopped.
- Peak reported `activeSandboxes` was 7, but ready/idle entries remain counted
  for the 600-second idle TTL, so this is not simultaneous-start concurrency.
- With five jobs, the claim-loop gate did not bind because `5 < capacity 20`.

The most plausible primary failure mode is five concurrent gVisor cold starts
competing on a `tdx.small` single vCPU and crossing the old 60-second readiness
deadline. The new item-1 diagnostics will distinguish that from Docker create,
runtime, pull, or resource errors on the next live run.

There is a secondary retry-latency issue: on acquisition failure, `runJob`
stops heartbeating and returns without a Gateway write, leaving the most
recently extended lease to expire naturally. Calling `gateway.fail()` was not
added because the available client/SDK contract describes a job failure, not a
transient release/requeue operation; treating infrastructure failure as a
terminal job failure could be worse. The Gateway should expose or document a
fenced transient-release operation before this changes.

The shared `SANDBOX_MAX` currently controls retained registry entries, claim
capacity, and therefore concurrent job starts. A separate concurrency limit may
be useful for CPU-constrained shapes, but no new setting was introduced without
live measurements to justify its default. All commit gates passed.

## 5. Stale-pending-row contract note

In the separate `data-gateway-identity` repository, `lib/tee/nodes.ts` returns a
still-`pending` row when the same node ID and secret are registered again, so a
new `appId`, `composeHash`, or `publicUrl` is silently discarded. The refresh
loop only handles `removed` rows. The live workaround was `POST
/v1/tee-nodes/<id>/remove` followed by a fresh registration. The main session
should decide whether same-secret pending registration should refresh mutable
metadata or return an explicit conflict. No Gateway code was changed here.

## Gates

- `npm run lint`: pass
- `npm test`: pass, 136 files / 1,684 tests total; enclave 19 files / 134
  tests; server 50 files / 650 tests
- `npm run format:check`: pass (the pre-existing untracked `HANDOFF-b3.md` was
  moved aside for the scan and restored unchanged)
- `bash -n` on touched scripts: pass, `scripts/tee/replicate.sh`

## Commits

- `dbf329c fix(enclave): preserve sandbox failure diagnostics`
- `2e6125a fix(tee): persist generated replica secrets`
- `1ec5dd7 test(enclave): verify docker work delay`
- `15836d6 fix(enclave): extend sandbox readiness timeout`
- Current result-file commit: `docs: record level B run 3 findings`
