/**
 * Replica membership: the owner's ServerRegistration roster at the gateway.
 * A receiver imports only from servers that are registered now. It never
 * accepts on an unknown roster: an unavailable answer is a Wait, not absence.
 */

/** The gateway record of one server, as membership reads it. */
export interface ReplicaRosterRecord {
  /** The owner wallet the server is registered under. */
  owner: string;
  /** The gateway registration id (bytes32). A new id is a new incarnation. */
  id: string;
  revokedAt: string | null;
}

export interface ReplicaRosterCall {
  signal?: AbortSignal;
}

export interface ReplicaRosterPort {
  /** null only for a proven absent registration; unavailable answers throw. */
  server(
    address: `0x${string}`,
    call?: ReplicaRosterCall,
  ): Promise<ReplicaRosterRecord | null>;
}

/** The roster could not be read and no fresh answer is cached. Never absence. */
export class ReplicaRosterUnavailableError extends Error {
  readonly code = "replica_roster_unavailable";
  constructor(options?: { cause?: unknown }) {
    super("replica_roster_unavailable", options);
    this.name = "ReplicaRosterUnavailableError";
  }
}

/** The longest a receiver acts on one roster answer. */
export const REPLICA_ROSTER_MAX_AGE_MS = 5 * 60_000;
const DEFAULT_MAX_ENTRIES = 1024;

/**
 * A bounded roster cache. An answer, including a proven absence, is served
 * for at most `maxAgeMs` after it was read. After that the next lookup reads
 * the port again; if that read fails, the lookup throws
 * ReplicaRosterUnavailableError. An expired answer is never served, so a
 * deregistration reaches every check within `maxAgeMs` plus the gateway CDN TTL.
 */
export function createCachedReplicaRoster(
  port: ReplicaRosterPort,
  options: { maxAgeMs?: number; maxEntries?: number; now?: () => number } = {},
): ReplicaRosterPort & { invalidate(address?: string): void } {
  const maxAge = options.maxAgeMs ?? REPLICA_ROSTER_MAX_AGE_MS;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const now = options.now ?? Date.now;
  if (!(maxAge >= 0) || !(maxEntries >= 1))
    throw new RangeError("invalid roster cache bounds");
  const answers = new Map<
    string,
    { record: ReplicaRosterRecord | null; at: number }
  >();
  const reads = new Map<string, Promise<ReplicaRosterRecord | null>>();
  return {
    async server(address, call) {
      const key = address.toLowerCase();
      const cached = answers.get(key);
      if (cached && now() - cached.at < maxAge) return cached.record;
      answers.delete(key);
      let read = reads.get(key);
      if (!read) {
        const startedAt = now();
        read = port
          .server(key as `0x${string}`, call)
          .then((record) => {
            answers.set(key, { record, at: startedAt });
            while (answers.size > maxEntries)
              answers.delete(answers.keys().next().value!);
            return record;
          })
          .finally(() => reads.delete(key));
        reads.set(key, read);
      }
      try {
        return await read;
      } catch (error) {
        throw error instanceof ReplicaRosterUnavailableError
          ? error
          : new ReplicaRosterUnavailableError({ cause: error });
      }
    },
    invalidate(address) {
      if (address === undefined) answers.clear();
      else answers.delete(address.toLowerCase());
    },
  };
}

const hex = (length: number) => new RegExp(`^0x[0-9a-fA-F]{${length}}$`);

/**
 * GET /v1/servers/:address. Only the gateway's JSON "Server not found" 404
 * proves absence; any other status or shape is unavailable, so a generic
 * route or CDN 404 cannot refuse a registered server.
 */
export function createGatewayReplicaRoster(input: {
  gatewayUrl: string;
  fetch?: typeof fetch;
}): ReplicaRosterPort {
  const base = input.gatewayUrl.replace(/\/+$/, "");
  const get = input.fetch ?? fetch;
  return {
    async server(address, call) {
      let response: Response;
      let body: unknown;
      try {
        response = await get(`${base}/v1/servers/${address.toLowerCase()}`, {
          signal: call?.signal,
          headers: { accept: "application/json" },
        });
        body = await response.json();
      } catch (error) {
        throw new ReplicaRosterUnavailableError({ cause: error });
      }
      if (
        response.status === 404 &&
        (body as { error?: unknown } | null)?.error === "Server not found"
      )
        return null;
      const data = (body as { data?: Record<string, unknown> } | null)?.data;
      if (
        response.status !== 200 ||
        !data ||
        typeof data.id !== "string" ||
        !hex(64).test(data.id) ||
        typeof data.ownerAddress !== "string" ||
        !hex(40).test(data.ownerAddress) ||
        typeof data.serverAddress !== "string" ||
        data.serverAddress.toLowerCase() !== address.toLowerCase() ||
        (data.revokedAt !== null && typeof data.revokedAt !== "string")
      )
        throw new ReplicaRosterUnavailableError();
      return {
        owner: data.ownerAddress,
        id: data.id,
        revokedAt: data.revokedAt as string | null,
      };
    },
  };
}
