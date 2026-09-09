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
