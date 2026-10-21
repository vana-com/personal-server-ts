import { ProtocolError } from "../errors/catalog.js";

/**
 * The delivery lease: the last authorization gate before a read result leaves
 * this server.
 *
 * A read is authorized when it starts, but its result is released later,
 * after awaited work (a chain check, an access-log write, a gateway round
 * trip, a storage read, other scopes of an aggregate). A grant can be
 * revoked, or a scope deleted, during that work. Read authorization therefore
 * returns a lease that carries every dependency of the release, and every
 * surface releases a result only through it: `deliver` for a whole response,
 * `leasedStream` for a body sent in parts.
 *
 * ## What a lease holds
 *
 * - **Remote evidence** (`evidence()`): each answer from a remote authority
 *   (the gateway grant, the chain permission, a remote AS introspection),
 *   with the time it was verified (`verifiedAt`).
 * - **Local checks** (`assertLocal()`, synchronous): the evidence's carried
 *   expiry, and local state (the PDPP token and grant store, refresh
 *   families, connections, the scope deletion tracker).
 *
 * ## The release rule (`deliver`)
 *
 * At release, every piece of evidence held by every composed lease must be
 * younger than `REMOTE_GRANT_REVERIFY_AFTER_MS`. `deliver` refreshes the
 * stale pieces in parallel, then measures again, until all are fresh at the
 * moment of the synchronous local check, within
 * `DELIVERY_FRESHNESS_ATTEMPTS`; otherwise it fails closed. The local check
 * and the release then run in the same tick, so nothing can be awaited
 * between them. A surface never runs the parts itself.
 *
 * ## Policy
 *
 * - Local revocation, expiry and deletion take effect at release, always.
 * - A remote (gateway, chain or remote AS) revocation with no known expiry
 *   has bounded staleness: at most `REMOTE_GRANT_REVERIFY_AFTER_MS` (30 s)
 *   at the moment of release. A known expiry is carried as evidence and
 *   checked locally on every release, so it is never stale.
 *
 * A failed lease aborts the delivery: the surface sends its usual refusal
 * instead of the result, or errors a body stream that is already open. Bytes
 * already sent are not recalled. Early checks stay where they are; the lease
 * is the one final gate.
 */
export interface DeliveryLease {
  /** Remote evidence the release depends on. Read by `deliver`. */
  evidence(): readonly RemoteEvidence[];
  /** Local checks: synchronous, throws the surface's refusal. Use `deliver`. */
  assertLocal(): void;
}

/** One answer from a remote authority, as of `verifiedAt`. */
export interface RemoteEvidence {
  /** When the remote check that produced it started (ms since epoch). */
  readonly verifiedAt: number;
  /** Ask the authority again; throws its refusal. */
  refresh(): Promise<void>;
}

/** The maximum age of remote evidence at the moment of release. */
export const REMOTE_GRANT_REVERIFY_AFTER_MS = 30_000;

/** Refresh rounds `deliver` makes before it fails closed. */
export const DELIVERY_FRESHNESS_ATTEMPTS = 3;

/** Remote evidence could not be made fresh enough to release. */
export class DeliveryNotFreshError extends ProtocolError {
  constructor() {
    super(
      503,
      "AUTHORIZATION_NOT_FRESH",
      "Read authorization could not be re-verified in time",
    );
  }
}

/**
 * Release a read under the release rule above: make every piece of remote
 * evidence fresh, then run the local checks and `release` in the same tick.
 * Throws the lease's refusal (or `DeliveryNotFreshError`) instead of calling
 * `release`.
 */
export async function deliver<T>(
  lease: DeliveryLease,
  release: () => T,
  options: { now?: () => number } = {},
): Promise<T> {
  const now = options.now ?? Date.now;
  for (let attempt = 0; ; attempt += 1) {
    const at = now();
    const stale = lease
      .evidence()
      .filter(
        (piece) => at - piece.verifiedAt >= REMOTE_GRANT_REVERIFY_AFTER_MS,
      );
    if (stale.length === 0) {
      lease.assertLocal();
      return release();
    }
    if (attempt >= DELIVERY_FRESHNESS_ATTEMPTS) {
      throw new DeliveryNotFreshError();
    }
    await Promise.all(stale.map((piece) => piece.refresh()));
  }
}

/** One lease that holds only while every given lease holds. */
export function allDeliveryLeases(
  ...leases: Array<DeliveryLease | undefined>
): DeliveryLease {
  const held = leases.filter(
    (lease): lease is DeliveryLease => lease !== undefined,
  );
  return {
    evidence: () => held.flatMap((lease) => lease.evidence()),
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
 * Collects the leases of the reads that build one result (a data API
 * response, an MCP tool call that reads several scopes). The result is
 * released through the collector, so every read it contains is checked at
 * the result boundary.
 */
export function collectDeliveryLeases(): DeliveryLeaseCollector {
  const leases: DeliveryLease[] = [];
  return {
    add(lease) {
      if (!leases.includes(lease)) leases.push(lease);
    },
    get size() {
      return leases.length;
    },
    evidence: () => leases.flatMap((lease) => lease.evidence()),
    assertLocal() {
      for (const lease of leases) lease.assertLocal();
    },
  };
}

/**
 * Remote evidence of type `T`: the admitting answer, then whatever
 * `reverify` returns when `deliver` finds it stale. `current` is what the
 * lease's local checks read (a carried expiry, an introspection result).
 * `verifiedAt` is when the check that produced `current` started, so a slow
 * answer is already old when it arrives.
 */
export function remoteEvidence<T>(
  initial: T,
  reverify: () => Promise<T>,
  options: { now?: () => number; verifiedAt?: number } = {},
): RemoteEvidence & { readonly current: T } {
  const now = options.now ?? Date.now;
  let current = initial;
  let verifiedAt = options.verifiedAt ?? now();
  return {
    get verifiedAt() {
      return verifiedAt;
    },
    async refresh() {
      const startedAt = now();
      current = await reverify();
      verifiedAt = startedAt;
    },
    get current() {
      return current;
    },
  };
}

/** A lease of local checks only (no remote evidence). */
export function localLease(assertLocal: () => void): DeliveryLease {
  return { evidence: () => [], assertLocal };
}

/**
 * A body released in parts, each only through the lease. The next part is
 * read from `source` first; then the part is released through `deliver`.
 * When the lease refuses, the stream errors with the refusal and the source is
 * cancelled: the receiver sees a failed, truncated transfer, never a clean
 * end.
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
