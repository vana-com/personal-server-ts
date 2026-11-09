/**
 * NO_REMOTE_WRITES: a guard on the routes out of the process that the Personal
 * Server stack uses: global `fetch`, `http`/`https` `request`/`get`, and the
 * agent queue that every `http`/`https` request passes through.
 *
 * Any request that is not a GET, and any request to a host outside the allowed
 * list, throws at once. The guard also records the violation, so a caller that
 * swallows the error still finds it afterwards and aborts the run
 * (`assertNoViolations`). Only `GET` to an allowed host passes.
 *
 * Install it before anything else starts. The host is the one Node connects to
 * (options `hostname`, else `host`, over the URL; a `socketPath` or a
 * `createConnection` is refused, as its host is not known). The port must be a
 * default port unless the allowed entry names it. A request's own `agent` may
 * name another host or port that Node connects to instead, so the agent's
 * `host`, `hostname` and `port` are checked too.
 *
 * What is checked, and where:
 * - `fetch`: each call, through `globalThis.fetch` as it is when called. Its
 *   redirects are never followed (the init sets the error mode), so a reply
 *   from an allowed host cannot send the request to another one.
 * - `http.request`, `http.get`, `https.request`, `https.get`: the target above.
 * - Every request queued on an agent (`Agent.prototype.addRequest`): the target
 *   above and the agent's own host and port. This covers a `ClientRequest` built
 *   directly, and a subclass declared before install, when the request has an
 *   agent (`agent: null` and the default agent both queue, unless a
 *   `createConnection` is given).
 *
 * Not checked:
 * - A `ClientRequest` built directly with `createConnection`: Node opens the
 *   socket without queuing, so only the `http.request`/`get` wrappers see it.
 * - An agent's `createConnection` (it picks the socket), and a `createConnection`
 *   on an agent object whose own `addRequest` does not come from
 *   `http.Agent.prototype`.
 * - A `fetch` reference taken before install, which still calls the real `fetch`.
 *   The dry run never allows this: `run.ts` installs the guard before it loads
 *   any package module (`run-entry-order.test.ts`).
 * - A `dispatcher` in a `fetch` init (undici), and raw `net`/`tls` sockets or
 *   other HTTP clients that bypass `http`/`https`.
 * - The IP addresses a host name resolves to: only the names are checked.
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
  return targetOfOptions({ ...base, ...given });
}

function targetOfOptions(merged: Record<string, unknown>): Target {
  if (merged.socketPath !== undefined) return { host: "(socket)", port: "" };
  // createConnection makes the socket itself, so no host is connected to that
  // the guard can read. Refusing it here also covers the queue check: a
  // request that carries one is refused whether or not it has an agent.
  if (merged.createConnection !== undefined) {
    return { host: "(createConnection)", port: "" };
  }
  const port = merged.port;
  return {
    host: firstHost(merged.hostname, merged.host),
    port: port === undefined || port === null ? "" : String(port),
  };
}

/**
 * The targets a queued request can reach. An agent that sets its own `host`,
 * `hostname` or `port` can send the request elsewhere, so each one it sets is a
 * target too, next to the request's own.
 */
function agentTargets(request: Target, agent: unknown): Target[] {
  const own = isOptions(agent) && isOptions(agent.options) ? agent.options : {};
  const targets = [request];
  const port =
    own.port === undefined || own.port === null
      ? request.port
      : String(own.port);
  for (const name of ["host", "hostname"] as const) {
    if (own[name] !== undefined) {
      targets.push({ host: firstHost(own[name]), port });
    }
  }
  if (own.port !== undefined) targets.push({ host: request.host, port });
  return targets;
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
  // Every request that has an agent is queued through this method, with the
  // options it was built with. Checking here covers a `ClientRequest` built
  // directly, a subclass declared before install, and an agent that names
  // another host or port (checked as well). https inherits the method from
  // `http.Agent`. A request with `createConnection` is refused by
  // `targetOfOptions` here as well (it is shared), and a request without an
  // agent is not queued at all.
  const agentProto = http.Agent.prototype as unknown as Record<string, unknown>;
  const RealAddRequest = agentProto.addRequest as (
    this: unknown,
    ...args: unknown[]
  ) => unknown;
  agentProto.addRequest = function addRequest(
    this: unknown,
    request: { method?: string },
    options: unknown,
    ...rest: unknown[]
  ) {
    const requested = targetOfOptions(isOptions(options) ? options : {});
    for (const target of agentTargets(requested, this)) {
      check(request.method ?? "GET", target);
    }
    return RealAddRequest.call(this, request, options, ...rest);
  };
  restores.push(() => {
    agentProto.addRequest = RealAddRequest;
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
