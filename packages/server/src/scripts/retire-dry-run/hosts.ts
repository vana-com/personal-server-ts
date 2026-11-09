/**
 * NO_REMOTE_WRITES, the host half: the tool talks to the Dev gateway and the
 * Dev storage host and to nothing else. The two are constants of the tool.
 * The copy's runtime config (`server.json`, else `config.json`; see run.ts) and
 * the command-line flags may only select among them; a value outside the list
 * is refused, not trusted.
 *
 * The schema default for storage is the production host, so storage is never
 * taken from a missing config: the tool names the Dev host itself.
 *
 * Loopback is allowed only when the caller passes the test-only switch, and
 * then for the exact `host:port` it was given.
 */

import { DryRunSetupError } from "./setup-error.js";

// The Dev product environment: the gateway and storage the Desktop app passes
// to its runtime in the dev build (the public Dev hosts; prod hosts are never
// pinned here).
export const DEV_GATEWAY_HOSTS: readonly string[] = ["dp-rpc.moksha.vana.org"];
export const DEV_STORAGE_HOSTS: readonly string[] = ["storage-dev.vana.org"];
export const DEV_GATEWAY_URL = `https://${DEV_GATEWAY_HOSTS[0]}`;
export const DEV_STORAGE_URL = `https://${DEV_STORAGE_HOSTS[0]}`;

const LOOPBACK = new Set(["127.0.0.1", "localhost"]);

export interface PinnedHosts {
  readonly gatewayUrl: string;
  readonly storageUrl: string;
  /** Host names, for the report. */
  readonly hosts: { readonly gateway: string; readonly storage: string };
  /** What the network guard allows: `host` (default ports) or `host:port`. */
  readonly allowed: readonly string[];
}

function refuse(): never {
  throw new DryRunSetupError(
    "host_not_pinned",
    "Refusing: the gateway or storage URL is not a pinned Dev host.",
  );
}

function pin(
  candidate: string,
  pinned: readonly string[],
  testOnlyAllowLoopback: boolean,
): { url: string; host: string; allowed: string } {
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return refuse();
  }
  if (url.username || url.password) return refuse();
  if (
    pinned.includes(url.hostname) &&
    url.protocol === "https:" &&
    url.port === ""
  ) {
    return {
      url: `https://${url.hostname}`,
      host: url.hostname,
      allowed: url.hostname,
    };
  }
  if (
    testOnlyAllowLoopback &&
    LOOPBACK.has(url.hostname) &&
    url.protocol === "http:" &&
    url.port !== ""
  ) {
    return {
      url: `http://${url.host}`,
      host: url.hostname,
      allowed: url.host,
    };
  }
  return refuse();
}

export function pinHosts(input: {
  /** A flag value, or else the (copied) config's value, or else undefined. */
  readonly gatewayUrl: string | undefined;
  readonly storageUrl: string | undefined;
  readonly testOnlyAllowLoopback?: boolean;
}): PinnedHosts {
  const loopback = input.testOnlyAllowLoopback === true;
  const gateway = pin(
    input.gatewayUrl ?? DEV_GATEWAY_URL,
    DEV_GATEWAY_HOSTS,
    loopback,
  );
  const storage = pin(
    input.storageUrl ?? DEV_STORAGE_URL,
    DEV_STORAGE_HOSTS,
    loopback,
  );
  return {
    gatewayUrl: gateway.url,
    storageUrl: storage.url,
    hosts: { gateway: gateway.host, storage: storage.host },
    allowed: [gateway.allowed, storage.allowed],
  };
}
