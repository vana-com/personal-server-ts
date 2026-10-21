/**
 * The delivery lease: the last authorization gate before a read body leaves
 * this server.
 *
 * A read is authorized when it starts, but its body is released later, after
 * awaited work (a chain check, an access-log write, a gateway round trip, a
 * storage read). A grant can be revoked, or a scope deleted, during that
 * work. The read-authorization owner therefore returns a lease with the
 * authorization, and every surface asks it once more immediately before it
 * releases a body (and, for a body released in parts, before each part).
 *
 * A failed lease aborts the delivery: the surface sends its usual refusal
 * instead of the body, or errors a body stream that is already open. Bytes
 * already sent are not recalled. The early checks stay where they are; the
 * lease does not replace them, it is the one final gate.
 */
export interface DeliveryLease {
  /** Throws the surface's refusal once the read may no longer be delivered. */
  assertDeliverable(): Promise<void>;
}

/**
 * How long a remote grant verification (a gateway or chain round trip) stays
 * valid at the release gate. Within this window the lease trusts the
 * verification that admitted the read, so a normal request makes no extra
 * remote call. A read whose body is released later than this re-verifies.
 * Local state (the PDPP token and grant store, the scope deletion tracker,
 * a known expiry time) is re-checked on every call, without this window.
 */
export const REMOTE_GRANT_REVERIFY_AFTER_MS = 30_000;

/** One lease that holds only while every given lease holds. */
export function allDeliveryLeases(
  ...leases: Array<DeliveryLease | undefined>
): DeliveryLease {
  const held = leases.filter(
    (lease): lease is DeliveryLease => lease !== undefined,
  );
  return {
    async assertDeliverable() {
      for (const lease of held) await lease.assertDeliverable();
    },
  };
}

/**
 * A check of a remote authority that runs again only when its last success
 * is older than `REMOTE_GRANT_REVERIFY_AFTER_MS`. The verification that
 * admitted the read counts as the first success.
 */
export function remoteReverification(
  reverify: () => Promise<void>,
  options: { now?: () => number; afterMs?: number } = {},
): () => Promise<void> {
  const now = options.now ?? Date.now;
  const afterMs = options.afterMs ?? REMOTE_GRANT_REVERIFY_AFTER_MS;
  let verifiedAtMs = now();
  return async () => {
    if (now() - verifiedAtMs < afterMs) return;
    await reverify();
    verifiedAtMs = now();
  };
}
