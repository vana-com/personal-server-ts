/**
 * Owner-facing statements about held data (spec-core §7).
 *
 *   - final owner review: what happens to held data after the grant ends
 *     (L1286-L1299, AS item 45), and the independent-recipient restriction
 *     (L1284);
 *   - `keep` on an ending path: the surviving-use terms and the retention
 *     limit (L1576);
 *   - `delete`: the stop-use and deletion statements Erasure requires
 *     (L1660-L1662, AS item 43);
 *   - narrowing: the effect of each disposition (L1529, AS item 46);
 *   - lifecycle recovery approval (L1804);
 *   - owner actions recorded while the history is unavailable (L1827).
 *
 * This build supports no processing permission (AS item 14, case O7), so the
 * processing-permission variants of these statements never apply. The
 * functions still take the permission set so a future profile cannot reach a
 * surface without its statement.
 *
 * Every statement describes duties of a conforming client, never proof of
 * remote deletion (L1660).
 */

import type { Retention } from "./types.js";

export interface HeldDataTermsInput {
  retention?: Retention;
  /** Processing permissions on the grant. Always empty in this build. */
  processingPermissions?: readonly string[];
}

function retentionLimit(retention?: Retention): string {
  if (!retention) {
    return "The app states no retention limit, so it may keep the data until it receives a deletion request.";
  }
  const days = /^P(\d+)D$/.exec(retention.max_duration)?.[1];
  const span = days ? `${days} days` : retention.max_duration;
  return `The app may keep each record for at most ${span} after it first received it, then must ${
    retention.on_expiry === "anonymize"
      ? "make it non-identifiable or delete it"
      : "delete it"
  }.`;
}

/** L1286-L1299 + L1284: final owner review, AS item 45. */
export function finalReviewHeldDataStatements(input: HeldDataTermsInput): {
  after_grant_ends: string[];
  onward_disclosure: string;
} {
  const processing = (input.processingPermissions ?? []).length > 0;
  const statements = [
    processing
      ? "After this access ends, the app may keep the data it received, but it has no ordinary use of it. Processing continues only under authority already issued, until that authority's stop time."
      : "After this access ends, the app may keep using the data it received for the approved purpose, unless you ask for deletion.",
    retentionLimit(input.retention),
    ...(input.retention
      ? []
      : ["You can decline a grant that states no retention limit."]),
    "You can ask for deletion at any time while the app may hold the data.",
    "The app learns of a deletion request you make here only when it next gets an answer from your server. It tries at least once a day while it runs, retries hourly after a failed try, and at least daily during a long outage.",
    "A try is not an answer, and there is no maximum delivery delay.",
    "An app that is not running does not check, and learns of a deletion request only when it next runs and checks.",
    processing
      ? "If your server stops answering for good, the app may keep the data, but your server's silence never extends processing authority or permits ordinary use."
      : `If your server stops answering for good, the app may keep using the data for the approved purpose${
          input.retention
            ? " until its retention limit"
            : " with no time limit, because it states no retention limit"
        }.`,
    "A deletion covers all data the app received under this grant, everything derived from it, and copies held by parties acting for the app and in backups, except learned model parameters, data made non-identifiable before the request, copies the app acquired independently under another grant, and copies the law requires it to keep.",
    "The app's stated retention limit, if any, bounds all of this.",
    "If the app offers deletion, choosing it inside the app binds the app at once as an instruction, but it is not instant physical deletion.",
  ];
  return {
    after_grant_ends: statements,
    // L1284: a client duty, not technical prevention.
    onward_disclosure:
      "This access does not allow the app to give your data to an independent recipient, such as a lender, adviser or another company that would use it for itself. Parties that only process the data for the app, bound by the same duties, are not independent recipients. This is a duty of the app; your server cannot technically prevent onward disclosure of a copy the app already holds.",
  };
}

/** L1576: what `keep` means on an ending path. */
export function keepStatement(input: HeldDataTermsInput): {
  surviving_use: string;
  retention_limit: string;
} {
  const processing = (input.processingPermissions ?? []).length > 0;
  return {
    surviving_use: processing
      ? "The app may keep the data it holds under this grant but has no ordinary use of it; processing continues only under authority already issued, until its stop time."
      : "The app may keep the data it already received and keep using it only for the approved purpose. It may not give it to an independent recipient.",
    retention_limit: retentionLimit(input.retention),
  };
}

function day(iso: string): string {
  return iso.slice(0, 10);
}

/**
 * L1660: the statements the AS makes when the owner chooses `delete`.
 * `stopUseBy` is the effective time plus the stop-use bound, or, for an
 * advance election, a description of the effective event.
 */
export function deleteStatements(
  input: HeldDataTermsInput & {
    stopUseBy?: string;
    advanceEvent?: string;
  },
): string[] {
  const processing = (input.processingPermissions ?? []).length > 0;
  const stopUse = input.advanceEvent
    ? `within 48 hours after ${input.advanceEvent} if it receives the request by then, and at once if it receives it later`
    : input.stopUseBy
      ? `by ${input.stopUseBy} if it receives it by then, and at once if it receives it later`
      : "within 48 hours after the request takes effect if it receives it by then, and at once if it receives it later";
  return [
    `The app must stop using covered data as soon as practicable after it receives this request: ${stopUse}.`,
    "It must delete covered data within 30 days of receiving the request, or earlier when a record reaches its retention limit.",
    "The app learns of this request only when it gets an answer from your server. While the app runs, it tries daily to check with your server, but a try is not a received request, and there is no maximum delivery delay.",
    "An app that is not running does not check, and learns of this request only when it next runs and checks.",
    "If your server is offline, the app cannot learn of the request until your server answers.",
    processing
      ? "If your server never answers again before the app receives this request, the app may keep the data but gains no use or processing authority."
      : `If your server never answers again before the app receives this request, the app may keep using the data for the approved purpose ${
          input.retention
            ? "until its retention limit"
            : "with no time limit, because it stated none"
        }.`,
    "If the app offers deletion, deleting inside it binds the app at once. That is an instruction, not instant physical deletion.",
    "The request covers all data the app received under this grant, its derivatives, and copies held by parties acting for the app and in backups. Learned model parameters, data made non-identifiable before the request, copies acquired independently under another grant, and legally required copies may remain.",
    "These are duties of a conforming app, not proof of remote deletion.",
  ];
}

/** L1529: the narrowing surface states the effect of each disposition. */
export function narrowingStatements(): { keep: string; delete: string } {
  return {
    delete:
      "Delete: the app must delete its copy from the old grant, subject to the stated exclusions. Only what the new grant covers can come back, by being read again under the new grant.",
    keep: "Keep: the app's existing copy stays usable under the old grant's terms after it ends, including data that the new grant does not cover.",
  };
}

/** L1804: what lifecycle recovery permits. */
export const RECOVERY_STATEMENT =
  "Approving lets this app check whether it may keep the data of the grants listed, report that it received and completed deletion requests, and pass on deletion requests you made inside the app. It gives the app no access to read your data and no processing authority.";

/** L1827: the owner surface for an action recorded while history is unavailable. */
export const PENDING_HISTORY_STATEMENT =
  "Your server cannot yet confirm that its authorization history is complete. Your request is recorded and pending: it will be applied before your server answers anything about the affected grants. Meanwhile your server issues no tokens and returns no positive answers for them. Read access ends within 60 seconds; a resource server may still use an answer it received earlier only until that answer's original cache lifetime ends.";

/** L1662: "sent on 2 November; no receipt reported". */
export function stageSummary(stage: {
  latest: string;
  acceptedAt: string;
  firstReturnedAt: string | null;
  receiptReportedAt: string | null;
  completedReportedAt: string | null;
  retainedReported: boolean;
}): string {
  if (stage.completedReportedAt)
    return `completion reported for ${day(stage.completedReportedAt)}`;
  if (stage.retainedReported)
    return "deletion reported complete except legally retained data";
  if (stage.receiptReportedAt)
    return `receipt reported for ${day(stage.receiptReportedAt)}`;
  if (stage.firstReturnedAt)
    return `sent on ${day(stage.firstReturnedAt)}; no receipt reported`;
  return `requested on ${day(stage.acceptedAt)}; not yet sent`;
}
