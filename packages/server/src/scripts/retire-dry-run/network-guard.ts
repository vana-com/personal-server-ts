/**
 * NO_REMOTE_WRITES: a guard on every route out of the process that the Personal
 * Server stack uses: global `fetch`, and `http`/`https` `request`/`get`.
 *
 * Any request that is not a GET, and any request to a host outside the allowed
 * list, throws at once. The guard also records the violation, so a caller that
 * swallows the error still finds it afterwards and aborts the run
 * (`assertNoViolations`).
 *
 * Install it before anything else starts. Only `GET` to an allowed host passes.
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

function hostOf(input: unknown, options: unknown): string {
  const parts = [input, options];
  for (const part of parts) {
    if (part instanceof URL) return part.hostname;
    if (typeof part === "string") {
      try {
        return new URL(part).hostname;
      } catch {
        continue;
      }
    }
    if (part && typeof part === "object") {
      const o = part as { hostname?: unknown; host?: unknown };
      const host = o.hostname ?? o.host;
      if (typeof host === "string") return host.split(":")[0]!;
    }
  }
  return "";
}

function methodOf(input: unknown, options: unknown): string {
  for (const part of [options, input]) {
    if (part && typeof part === "object" && !(part instanceof URL)) {
      const m = (part as { method?: unknown }).method;
      if (typeof m === "string") return m.toUpperCase();
    }
  }
  return "GET";
}

export function installNetworkGuard(input: {
  readonly allowedHosts: readonly string[];
}): NetworkGuard {
  const allowed = new Set(input.allowedHosts.map((h) => h.toLowerCase()));
  const violations: GuardViolation[] = [];

  const check = (method: string, host: string): void => {
    const reason =
      method !== "GET"
        ? "method_not_get"
        : !allowed.has(host.toLowerCase())
          ? "host_not_allowed"
          : null;
    if (reason === null) return;
    const violation: GuardViolation = { method, host, reason };
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
      check(
        (init?.method ?? request?.method ?? "GET").toUpperCase(),
        url.hostname,
      );
    } catch (error) {
      return Promise.reject(error);
    }
    return realFetch(target, init);
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
          hostOf(first, second),
        );
        return real.call(mod, first, second, ...rest);
      };
      restores.push(() => {
        (mod as unknown as Record<string, unknown>)[name] = real;
      });
    }
  }
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
