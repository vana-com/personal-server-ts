/**
 * NO_REMOTE_WRITES: a guard on every route out of the process that the Personal
 * Server stack uses: global `fetch`, `http`/`https` `request`/`get`, and a
 * `ClientRequest` built directly.
 *
 * Any request that is not a GET, and any request to a host outside the allowed
 * list, throws at once. The guard also records the violation, so a caller that
 * swallows the error still finds it afterwards and aborts the run
 * (`assertNoViolations`).
 *
 * Install it before anything else starts. Only `GET` to an allowed host passes.
 * The host is the one Node connects to (options `hostname`, else `host`, over
 * the URL; a `socketPath` is refused), and the port must be a default port
 * unless the allowed entry names it. `fetch` never follows a redirect, so a
 * reply from an allowed host cannot send the request to another one.
 * (`http` and `https` never follow redirects on their own.)
 */

import http from "node:http";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";

export interface GuardViolation {
  readonly method: string;
  readonly host: string;
  readonly reason: "method_not_get" | "host_not_allowed";
}

export class NetworkGuardError extends Error {
  constructor(readonly violation: GuardViolation) {
    super(
      `Network guard: ${violation.method} to ${violation.host} refused (${violation.reason})`,
    );
    this.name = "NetworkGuardError";
  }
}

export interface NetworkGuard {
  readonly violations: readonly GuardViolation[];
  /** Throws `NetworkGuardError` if any request was refused. */
  assertNoViolations(): void;
  uninstall(): void;
}

type HttpModule = typeof http | typeof https;

interface Target {
  readonly host: string;
  /** Empty when the request uses the scheme's default port. */
  readonly port: string;
}

const isUrlLike = (value: unknown): value is string | URL =>
  typeof value === "string" || value instanceof URL;

function isOptions(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !(value instanceof URL);
}

/** The first non-empty string of a list, as `validateHost` in Node takes it. */
function firstHost(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === "string" && value !== "") return value;
    if (value !== undefined && value !== null && typeof value !== "string") {
      return ""; // Node throws for these; the guard refuses.
    }
  }
  return "localhost";
}

/**
 * The host Node connects to for `http.request(input, options)`. Node turns a
 * URL into options and merges the options argument over it (its keys win),
 * then connects to `hostname`, else `host`, else `localhost`.
 */
function targetOf(input: unknown, options: unknown): Target {
  let base: Record<string, unknown> = {};
  if (isUrlLike(input)) {
    try {
      const url = new URL(input);
      base = {
        hostname: url.hostname.replace(/^\[|\]$/g, ""),
        port: url.port,
      };
    } catch {
      return { host: "", port: "" };
    }
  }
  const given = isUrlLike(input)
    ? isOptions(options)
      ? options
      : {}
    : isOptions(input)
      ? input
      : {};
  const merged = { ...base, ...given };
  if (merged.socketPath !== undefined) return { host: "(socket)", port: "" };
  const port = merged.port;
  return {
    host: firstHost(merged.hostname, merged.host),
    port: port === undefined || port === null ? "" : String(port),
  };
}

function methodOf(input: unknown, options: unknown): string {
  for (const part of [options, input]) {
    if (isOptions(part)) {
      const m = part.method;
      if (typeof m === "string") return m.toUpperCase();
    }
  }
  return "GET";
}

export function installNetworkGuard(input: {
  /** `host` (default ports only) or `host:port`. */
  readonly allowedHosts: readonly string[];
}): NetworkGuard {
  const allowed = new Set(input.allowedHosts.map((h) => h.toLowerCase()));
  const violations: GuardViolation[] = [];

  const hostAllowed = ({ host, port }: Target): boolean => {
    const name = host.toLowerCase();
    if (port === "" || port === "80" || port === "443") {
      if (allowed.has(name)) return true;
    }
    return port !== "" && allowed.has(`${name}:${port}`);
  };

  const check = (method: string, target: Target): void => {
    const reason =
      method !== "GET"
        ? "method_not_get"
        : !hostAllowed(target)
          ? "host_not_allowed"
          : null;
    if (reason === null) return;
    const violation: GuardViolation = { method, host: target.host, reason };
    violations.push(violation);
    throw new NetworkGuardError(violation);
  };

  const realFetch = globalThis.fetch;
  globalThis.fetch = ((target: RequestInfo | URL, init?: RequestInit) => {
    try {
      const request = target instanceof Request ? target : null;
      const url =
        typeof target === "string"
          ? new URL(target)
          : target instanceof URL
            ? target
            : new URL(request!.url);
      check((init?.method ?? request?.method ?? "GET").toUpperCase(), {
        host: url.hostname,
        port: url.port,
      });
    } catch (error) {
      return Promise.reject(error);
    }
    // A redirect would leave the checked host unchecked: never follow one.
    return realFetch(target, { ...init, redirect: "error" });
  }) as typeof fetch;

  const restores: (() => void)[] = [() => void (globalThis.fetch = realFetch)];
  for (const mod of [http, https] as HttpModule[]) {
    for (const name of ["request", "get"] as const) {
      const real = mod[name] as (...args: unknown[]) => unknown;
      (mod as unknown as Record<string, unknown>)[name] = (
        first: unknown,
        second?: unknown,
        ...rest: unknown[]
      ) => {
        check(
          name === "get" ? "GET" : methodOf(first, second),
          targetOf(first, second),
        );
        return real.call(mod, first, second, ...rest);
      };
      restores.push(() => {
        (mod as unknown as Record<string, unknown>)[name] = real;
      });
    }
  }
  // `new http.ClientRequest(...)` is what `request` builds, and it takes the
  // same arguments. https has no class of its own: an https request is a
  // ClientRequest given the https agent and protocol, so this covers both.
  const RealClientRequest = http.ClientRequest;
  (http as unknown as Record<string, unknown>).ClientRequest = new Proxy(
    RealClientRequest,
    {
      construct(target, args: unknown[], newTarget) {
        check(methodOf(args[0], args[1]), targetOf(args[0], args[1]));
        return Reflect.construct(target, args, newTarget);
      },
    },
  );
  restores.push(() => {
    (http as unknown as Record<string, unknown>).ClientRequest =
      RealClientRequest;
  });
  syncBuiltinESMExports();

  return {
    violations,
    assertNoViolations() {
      if (violations.length > 0) throw new NetworkGuardError(violations[0]!);
    },
    uninstall() {
      for (const restore of restores.reverse()) restore();
      syncBuiltinESMExports();
    },
  };
}
