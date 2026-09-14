# dstack 0.5.9 runtime event fixtures

These are public TCB register and event-log fields from the same staged Moksha
controller before and after its signed environment update on 2026-09-09.
The deployment's public certificate quotes were independently verified with
`@phala/dcap-qvl@0.6.1`: Intel UpToDate, no advisories, DEBUG disabled. All event
registers replayed correctly; only the runtime `mr-kms` payload changed.
Application compose content, certificates and quotes are omitted from these
sanitized unit fixtures; no credentials or protected state are included.

Source artifacts in the deployment evidence bundle are
`controller-failclosed-attestation.json` and `controller-signed-attestation.json`;
the corresponding independent results are
`controller-failclosed-independent-verification.json` and
`controller-signed-independent-verification.json`.

The co-located verifier tests **mock QVL** with these previously verified register
values to test event validation and policy independently. They do not themselves
exercise Intel cryptography or demonstrate a live fresh-key peer handshake.
Live peer verification still calls QVL on each challenge-bound quote.

`dstack-0.5.9-getquote.json` preserves the raw 30-record event log returned by a
real worker's fresh peer challenge on 2026-09-09. Its original public capture has
SHA-256 `41339dbc363df8dcda2db01b684adea82e17667a0640fe5b6592c2259e3a312c`.
The accompanying quote was independently verified UpToDate with its exact
64-byte challenge binding; the fixture retains those verified registers and
unaltered event records. Offline replay of the original quote is recorded in
`raw-getquote-regression-red.json` and `raw-getquote-regression-green.json`.

Unlike certificate TCB logs, GetQuote deliberately strips redundant fields:
runtime records retain their payload but have an empty digest, while firmware
records retain their digest and may omit their payload. The verifier reconstructs
only empty runtime digests using the documented event hash, then requires all
four quoted registers and the same exact runtime profile. It still rejects
missing firmware digests and inconsistent supplied runtime digests.

This behavior is defined by the deployed dstack source at
[`TdxEvent::stripped`](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/cc-eventlog/src/tdx.rs#L43)
and the
[runtime digest algorithm](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/cc-eventlog/src/runtime_events.rs#L84).
