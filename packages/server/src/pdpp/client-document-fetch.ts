/**
 * Bounded production fetcher for a URL-hosted client identity document
 * (Core §6). Implements `ClientDocumentFetcher` from
 * `@opendatalabs/personal-server-ts-core/pdpp`.
 *
 * Invariants:
 *   - HTTPS only.
 *   - Every address actually dialed is checked: a hostname's DNS answers via
 *     a custom `lookup` on the `undici` dispatcher (defends DNS rebinding —
 *     `net`/`tls`/`undici` dial exactly the address `lookup` returns, so
 *     there is no separate resolution to race), and a literal-IP URL
 *     hostname separately, since that never reaches `dns.lookup` at all.
 *   - No redirect is followed; a redirect or an oversized/rejected body is
 *     drained (`discardBody`), never left dangling on the socket.
 *   - One `AbortSignal`/timeout spans connect + headers + body + cleanup.
 *   - The body is read incrementally and dropped past the byte cap.
 *   - No credentials are forwarded.
 */

import dns from "node:dns";
import net from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import type { Response as UndiciResponse } from "undici";
import type { LookupFunction } from "node:net";
import type { ClientDocumentFetcher } from "@opendatalabs/personal-server-ts-core/pdpp";

export const FETCH_TIMEOUT_MS = 5_000;
export const MAX_RESPONSE_BYTES = 64 * 1024;

/** Thrown by the connect-time guard; surfaces as a `fetch_failed` result. */
export class BlockedAddressError extends Error {}

/**
 * Non-public address space, checked against the literal address a DNS
 * answer resolved to — not the hostname string. `net.BlockList` normalizes
 * both IPv4-mapped IPv6 forms (`::ffff:a.b.c.d` and `::ffff:7f00:1`) and the
 * fully-expanded form (`0:0:0:0:0:0:0:1`) against the same IPv4/IPv6 rules,
 * so listing each CIDR once covers all three.
 */
const blockedAddresses = new net.BlockList();
for (const cidr of [
  "0.0.0.0/8", // "this network" / unspecified-as-source
  "10.0.0.0/8", // RFC1918 private
  "100.64.0.0/10", // shared address space / CGNAT (RFC6598)
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local, incl. cloud metadata
  "172.16.0.0/12", // RFC1918 private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // documentation (TEST-NET-1)
  "192.168.0.0/16", // RFC1918 private
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // documentation (TEST-NET-2)
  "203.0.113.0/24", // documentation (TEST-NET-3)
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved
  "255.255.255.255/32", // limited broadcast
]) {
  const [address, prefix] = cidr.split("/");
  blockedAddresses.addSubnet(address, Number(prefix), "ipv4");
}
for (const cidr of [
  "::/128", // unspecified
  "::1/128", // loopback
  "fc00::/7", // unique local (ULA)
  "fe80::/10", // link-local
  "ff00::/8", // multicast
]) {
  const [address, prefix] = cidr.split("/");
  blockedAddresses.addSubnet(address, Number(prefix), "ipv6");
}

export function isBlockedAddress(address: string): boolean {
  const version = net.isIP(address);
  if (version === 0) return true; // not a literal address — refuse, don't guess
  return blockedAddresses.check(address, version === 4 ? "ipv4" : "ipv6");
}

/**
 * A URL hostname that is itself a literal IP (e.g. `https://127.0.0.1/`,
 * `https://[::1]/`) never reaches `dns.lookup` — `net`/`tls`/`undici` dial it
 * directly, so the guarded `lookup` in {@link buildGuardedLookup} never runs.
 * Must be checked separately, before the dial, against the same predicate.
 */
function literalHostAddress(hostname: string): string | null {
  const unbracketed =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  return net.isIP(unbracketed) === 0 ? null : unbracketed;
}

/**
 * Build a `lookup`-compatible function (the shape `node:net`/`node:tls` and
 * `undici`'s connector accept) that refuses to resolve to a blocked address.
 * Delegates the actual resolution to `node:dns`, always requesting every
 * answer so a rebinding attempt cannot hide a blocked address behind a
 * permitted one that happens to sort first.
 *
 * `isBlocked` defaults to {@link isBlockedAddress}; overriding it is a
 * test-only seam (see `__testing`) so tests can run a real loopback server
 * without disabling the guard's own logic, which is what the override would
 * do if it replaced `lookup` entirely instead of only the address predicate.
 */
function buildGuardedLookup(
  isBlocked: (address: string) => boolean = isBlockedAddress,
): LookupFunction {
  return (hostname, options, callback) => {
    // Always ask `dns.lookup` for every answer so a blocked address cannot
    // hide behind a permitted one that happens to sort first, regardless of
    // whether the caller itself wanted `all`.
    dns.lookup(
      hostname,
      { ...options, all: true },
      (err: NodeJS.ErrnoException | null, addresses) => {
        if (err) return callback(err, "" as never, undefined as never);
        const list = addresses as { address: string; family: number }[];
        if (list.length === 0) {
          return callback(
            new BlockedAddressError(
              `${hostname} resolved to no addresses`,
            ) as NodeJS.ErrnoException,
            "" as never,
            undefined as never,
          );
        }
        const blocked = list.find((a) => isBlocked(a.address));
        if (blocked) {
          return callback(
            new BlockedAddressError(
              `${hostname} resolved to a blocked address: ${blocked.address}`,
            ) as NodeJS.ErrnoException,
            "" as never,
            undefined as never,
          );
        }
        // Reply in the shape the caller actually requested: the array form
        // when `options.all` was set (as undici's connector does), otherwise
        // the single-address form `net`/`tls` expect.
        if (options.all) {
          return callback(null, list as never, undefined as never);
        }
        callback(null, list[0]!.address, list[0]!.family);
      },
    );
  };
}

/**
 * Build a dispatcher that only ever connects to an address that passes the
 * guard, bundled with the exact predicate it was built with so a caller
 * can't pass a mismatched one to the pre-dial literal-IP check in
 * {@link createBoundedFetcher}. `tlsOpts` is exposed solely so tests can
 * trust a local self-signed certificate; `isBlocked` lets tests run against
 * loopback without disabling the guard mechanism itself. Production code
 * must call {@link boundedClientDocumentFetcher}, which passes neither.
 */
function buildGuardedAgent(tlsOpts?: {
  ca?: string | Buffer;
  isBlocked?: (address: string) => boolean;
}): { dispatcher: Agent; isBlocked: (address: string) => boolean } {
  const { isBlocked = isBlockedAddress, ...rest } = tlsOpts ?? {};
  return {
    dispatcher: new Agent({
      connect: { lookup: buildGuardedLookup(isBlocked), ...rest },
    }),
    isBlocked,
  };
}

/** One dispatcher, reused across calls; the guard is stateless per lookup. */
const guarded = buildGuardedAgent();

/**
 * Read a response body, aborting the moment it exceeds `limit` bytes.
 * Mirrors `readCapped` in core's `declaration.ts` — same bound, same
 * reasoning: `.text()` would buffer the whole body before the cap could act.
 */
async function readCapped(
  response: UndiciResponse,
  limit: number,
): Promise<string | null> {
  const stream = response.body;
  if (!stream) {
    const buffered = await response.text();
    return Buffer.byteLength(buffered, "utf8") > limit ? null : buffered;
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}

/**
 * Build a bounded `ClientDocumentFetcher`. HTTPS-only, no redirects, one
 * connect+headers+body timeout, a streamed byte cap, and address validation
 * on every DNS answer *and* on a literal-IP hostname (which never reaches
 * `dns.lookup`, so the dispatcher's guarded `lookup` alone would miss it).
 *
 * Takes {@link buildGuardedAgent}'s return value as a whole (not just its
 * `dispatcher`) so the pre-dial literal-IP check always uses the exact same
 * predicate the dispatcher's `lookup` guard was built with — there is no
 * call shape that lets the two diverge.
 */
function createBoundedFetcher({
  dispatcher,
  isBlocked,
}: ReturnType<typeof buildGuardedAgent>): ClientDocumentFetcher {
  return async (url) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      throw new Error(
        `client_id document fetch requires https, got ${parsed.protocol}`,
      );
    }

    const literal = literalHostAddress(parsed.hostname);
    if (literal && isBlocked(literal)) {
      throw new BlockedAddressError(
        `client_id document fetch refuses a blocked literal address: ${literal}`,
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const response = await undiciFetch(parsed.toString(), {
        redirect: "manual",
        signal: controller.signal,
        dispatcher,
        // No forwarded credentials: no cookies, no stored authorization.
      });

      if (response.status >= 300 && response.status < 400) {
        await discardBody(response);
        throw new Error(
          `client_id document fetch refuses to follow a redirect (status ${response.status})`,
        );
      }

      const declaredLength = response.headers.get("content-length");
      if (declaredLength && Number(declaredLength) > MAX_RESPONSE_BYTES) {
        await discardBody(response);
        return { status: response.status, body: "", finalUrl: url };
      }

      const body = await readCapped(response, MAX_RESPONSE_BYTES);
      if (body === null) {
        // Oversized: reported as a non-200 empty body so the resolver's
        // generic "unexpected status" handling covers it without a new code
        // path duplicating the size check `resolveUrlHostedClientIdentity`
        // already performs on the string it receives.
        return { status: 0, body: "", finalUrl: url };
      }

      return { status: response.status, body, finalUrl: parsed.toString() };
    } finally {
      // Cleared last: the deadline must still apply while a rejected
      // response's body is drained/destroyed above, not just during the
      // initial connect+headers await.
      clearTimeout(timer);
    }
  };
}

/**
 * Drop a response body we're not going to read, rather than leaving it
 * unconsumed. Called before `finally` clears the timer, so a hostile server
 * stalling this drain still hits the request's own deadline instead of
 * hanging past it.
 */
async function discardBody(response: UndiciResponse): Promise<void> {
  const stream = response.body;
  if (!stream) return;
  try {
    await stream.cancel();
  } catch {
    // A destroyed/errored stream may reject cancel(); the socket is already
    // gone either way.
  }
}

/** The production fetcher: no test-only overrides reach this path. */
export const boundedClientDocumentFetcher: ClientDocumentFetcher =
  createBoundedFetcher(guarded);

/** Test-only seam: same bounds, with a dispatcher that trusts a test CA. */
export const __testing = { createBoundedFetcher, buildGuardedAgent };
