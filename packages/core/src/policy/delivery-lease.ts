/**
 * The delivery lease: the last authorization gate before a read body leaves
 * this server.
 *
 * A read is authorized when it starts, but its body is released later, after
 * awaited work (a chain check, an access-log write, a gateway round trip, a
 * storage read). A grant can be revoked, or a scope deleted, during that
 * work. The read-authorization owner therefore returns a lease with the
 * authorization, and every surface releases a body only through it:
 * `deliver` for a whole response, `leasedStream` for a body sent in parts.
 *
 * ## The ordering rule
 *
 * A lease has two halves. `refresh()` does every remote await (a gateway or
 * chain re-verification that is due). `assertLocal()` checks the evidence the
 * lease holds against local state (the PDPP token and grant store, refresh
 * families, connections, the scope deletion tracker, a carried expiry time)
 * and is synchronous, so nothing can be awaited between it and the release.
 * `deliver` runs them in that order and builds the response in the same
 * tick. A surface never calls the halves itself.
 *
 * ## Policy
 *
 * - Local revocation, expiry and deletion take effect at release, always.
 * - A remote (gateway or chain) revocation with no known expiry has bounded
 *   staleness: up to `REMOTE_GRANT_REVERIFY_AFTER_MS` (30 s) after the last
 *   remote verification. A known expiry is carried as evidence and checked
 *   locally on every release, so it is never stale.
 *
 * A failed lease aborts the delivery: the surface sends its usual refusal
 * instead of the body, or errors a body stream that is already open. Bytes
 * already sent are not recalled. The early checks stay where they are; the
 * lease does not replace them, it is the one final gate.
 */
export interface DeliveryLease {
  /** Remote half: every remote await that is due. Use `deliver`. */
  refresh(): Promise<void>;
  /** Local half: synchronous, throws the surface's refusal. Use `deliver`. */
  assertLocal(): void;
}

/**
 * How long a remote grant verification stays valid at the release gate.
 * Within this window the lease trusts the verification that admitted the
 * read, so a normal request makes no extra remote call.
 */
export const REMOTE_GRANT_REVERIFY_AFTER_MS = 30_000;

/**
 * Release a read: finish the lease's remote checks, check its local evidence,
 * then build the response, with no await between the last check and
 * `release`. Throws the lease's refusal instead of calling `release`.
 */
export async function deliver<T>(
  lease: DeliveryLease,
  release: () => T,
): Promise<T> {
  await lease.refresh();
  lease.assertLocal();
  return release();
}

/** One lease that holds only while every given lease holds. */
export function allDeliveryLeases(
  ...leases: Array<DeliveryLease | undefined>
): DeliveryLease {
  const held = leases.filter(
    (lease): lease is DeliveryLease => lease !== undefined,
  );
  return {
    async refresh() {
      for (const lease of held) await lease.refresh();
    },
    assertLocal() {
      for (const lease of held) lease.assertLocal();
    },
  };
}

/** A lease that gathers the leases of every read made for one result. */
export interface DeliveryLeaseCollector extends DeliveryLease {
  add(lease: DeliveryLease): void;
  readonly size: number;
}

/**
 * Collects the leases of the reads that build one aggregate result (an MCP
 * tool call that reads several scopes). The result is released through the
 * collector, so every read it contains is checked at the result boundary.
 */
export function collectDeliveryLeases(): DeliveryLeaseCollector {
  const leases: DeliveryLease[] = [];
  return {
    add(lease) {
      leases.push(lease);
    },
    get size() {
      return leases.length;
    },
    async refresh() {
      for (const lease of [...leases]) await lease.refresh();
    },
    assertLocal() {
      for (const lease of leases) lease.assertLocal();
    },
  };
}

/**
 * Evidence from a remote authority, re-fetched only when the last fetch is
 * older than `REMOTE_GRANT_REVERIFY_AFTER_MS`. The verification that
 * admitted the read is the first evidence. `refresh` throws the remote
 * refusal; `current` is what the local half checks (a carried expiry).
 */
export function remoteEvidence<T>(
  initial: T,
  reverify: () => Promise<T>,
  options: { now?: () => number; afterMs?: number } = {},
): { refresh(): Promise<void>; readonly current: T } {
  const now = options.now ?? Date.now;
  const afterMs = options.afterMs ?? REMOTE_GRANT_REVERIFY_AFTER_MS;
  let current = initial;
  let verifiedAtMs = now();
  return {
    async refresh() {
      if (now() - verifiedAtMs < afterMs) return;
      current = await reverify();
      verifiedAtMs = now();
    },
    get current() {
      return current;
    },
  };
}

/**
 * A body released in parts, each only through the lease. The next part is
 * read from `source` first; then the lease is checked; then the part is
 * released, with no await between the check and the release. When the lease
 * refuses, the stream errors with the refusal and the source is cancelled:
 * the receiver sees a failed, truncated transfer, never a clean end.
 */
export function leasedStream(
  lease: DeliveryLease,
  source: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        try {
          const next = await reader.read();
          if (next.done) {
            controller.close();
            return;
          }
          await deliver(lease, () => controller.enqueue(next.value));
        } catch (err) {
          controller.error(err);
          await reader.cancel(err).catch(() => undefined);
        }
      },
      async cancel(reason) {
        await reader.cancel(reason);
      },
    },
    { highWaterMark: 0 },
  );
}
