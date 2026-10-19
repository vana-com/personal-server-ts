/**
 * The single `PDPP-Version` value both the Authorization Server and Resource
 * Server surfaces of this Personal Server negotiate against (spec-core.md
 * §8 "API versioning").
 *
 * Spec-core.md's own normative example is a date string
 * (`PDPP-Version: 2026-04-06`), not a semver string — this constant follows
 * that convention. Both AS and RS route modules MUST import this one
 * constant rather than declaring their own local copy: an AS and RS that
 * hard-reject an unrecognized `PDPP-Version` (spec §8 requires this) but
 * accept mutually exclusive values make half the server unreachable to any
 * client that pins a version header.
 *
 * Found in an independent combined AS+RS review (2026-09-17): the AS lane's
 * `packages/core/src/pdpp/types.ts` previously declared its own
 * `PDPP_API_VERSION = "0.1.0"` (a semver-shaped grant/API contract version,
 * not the spec's `PDPP-Version` header value) alongside this module's
 * `PDPP-Version = "2026-04-06"` in the RS route files. A client sending
 * either header value could reach only one half of the server. Fix: one
 * shared constant, spec-date-shaped, imported by both surfaces. The AS lane
 * needs to adopt this constant (or reconcile `PDPP_API_VERSION`'s meaning to
 * something distinct from the `PDPP-Version` header, if that field is
 * actually meant to version the grant schema rather than the wire protocol)
 * — that reconciliation was not made unilaterally here since it touches
 * AS-owned files this lane does not edit.
 */
export const PDPP_VERSION = "2026-04-06";
