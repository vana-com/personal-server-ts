/**
 * §2.10 the one eligibility predicate, used by reads, consent readiness and
 * memory totals.
 *
 * For connector c and a requested name:
 *   1. If every stream the name needs is live and `complete` in the selected
 *      connection → serve the stream view. A legacy file is never compared
 *      with a complete view (one-way).
 *   2. Else, if any connection of c is deleted and not since reconnected →
 *      `unavailable` (no legacy or raw fallback).
 *   3. Else, if a legacy or raw file of that name exists → serve it.
 *   4. Else `unavailable`.
 *
 * Selected connection: live (control `active`, so never `foreign`) with the
 * most recently registered heads. A physical name selects its own connection.
 */

import type { ControlState } from "./control.js";
import { InvalidArgumentError } from "./errors.js";
import { hasOwn } from "./json.js";

export interface StreamHeadView {
  /** §2.4 liveness (`isHeadLive`). */
  readonly live: boolean;
  readonly complete: boolean;
}

export interface ConnectionView {
  readonly ns: string;
  /** This server's last synced control state for the connection. */
  readonly control: ControlState;
  /**
   * Registration order of the connection's most recently registered live
   * head (larger is more recent), or `null` when it has none.
   */
  readonly latestHeadRegistration: number | null;
  readonly streams: Readonly<Record<string, StreamHeadView>>;
}

export type ReadTarget =
  /** `pdpp.<c>.<s>` or a legacy binding: the streams it needs. */
  | { readonly kind: "logical"; readonly streams: readonly string[] }
  /** `pdpp.<c>~<ns>.<s>`: its own connection. */
  | {
      readonly kind: "physical";
      readonly ns: string;
      readonly streams: readonly string[];
    };

export interface EligibilityInput {
  /** Every connection of the connector known to this server. */
  readonly connections: readonly ConnectionView[];
  readonly target: ReadTarget;
  /** A legacy or raw file of the requested name exists. */
  readonly legacyFile: boolean;
}

export type Eligibility =
  | { readonly kind: "view"; readonly ns: string }
  | { readonly kind: "legacy" }
  | { readonly kind: "unavailable"; readonly reason: "deleted" | "no_data" };

function rank(a: ConnectionView, b: ConnectionView): number {
  const ra = a.latestHeadRegistration ?? -Infinity;
  const rb = b.latestHeadRegistration ?? -Infinity;
  if (ra !== rb) return rb > ra ? 1 : -1;
  // Tie: lowest ns (DESIGN-QUESTIONS.md Q6).
  return a.ns < b.ns ? -1 : a.ns > b.ns ? 1 : 0;
}

/** The connection a plain (logical) name of the connector reads. */
export function selectConnection(
  connections: readonly ConnectionView[],
): ConnectionView | null {
  const live = connections.filter((c) => c.control.kind === "active");
  return live.length === 0 ? null : [...live].sort(rank)[0]!;
}

export function eligible(input: EligibilityInput): Eligibility {
  const { connections, target } = input;
  if (target.streams.length === 0) {
    throw new InvalidArgumentError("a read target needs at least one stream");
  }
  const selected =
    target.kind === "physical"
      ? (connections.find(
          (c) => c.ns === target.ns && c.control.kind === "active",
        ) ?? null)
      : selectConnection(connections);
  if (
    selected &&
    target.streams.every((s) => {
      if (!hasOwn(selected.streams, s)) return false;
      const head = selected.streams[s]!;
      return head.live && head.complete;
    })
  ) {
    return { kind: "view", ns: selected.ns };
  }
  if (connections.some((c) => c.control.kind === "deleted")) {
    return { kind: "unavailable", reason: "deleted" };
  }
  if (input.legacyFile) return { kind: "legacy" };
  return { kind: "unavailable", reason: "no_data" };
}

/** Readiness is exactly "a read would not be `unavailable`". */
export function isReady(input: EligibilityInput): boolean {
  return eligible(input).kind !== "unavailable";
}
