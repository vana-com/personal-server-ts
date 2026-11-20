import type { ControlState } from "./control.js";

/**
 * A run's start state, as decide() reads it at publish. `unknown` is a run
 * that recorded no start snapshot (for example, before the snapshot existed).
 * The other kinds are the control states the snapshot can hold.
 */
export type AdmissionStart = { readonly kind: "unknown" } | ControlState;

/**
 * The inputs a deleted start depends on, as decide() reads them: an explicit
 * connect that is a full run (no checkpoint).
 */
export interface AdmissionFlags {
  readonly userConnect: boolean;
  readonly full: boolean;
}

/**
 * What the start-to-current rule says about a run:
 * - `publish`: the writer takes the run's target. decide() writes first when
 *   the connection must be created or reconnected, then publishes.
 * - `wait`: the connection moved away from an active start (absent, or active
 *   at a lower generation). The run stays pending; the writer rereads.
 * - `discard`: the run never publishes under this current state.
 */
export type Admission = "publish" | "wait" | "discard";

/**
 * §2.4 start-to-current rule, the one owner of it. decide() maps each verdict
 * to its cell's decision, and the reader filters pending runs on `publish` or
 * `wait` and published runs on `publish` only.
 *
 * `unknown` is typed as `discard`: no start snapshot never publishes, so no
 * caller needs a second answer for it.
 */
export function admitStart(
  start: { readonly kind: "unknown" },
  current: ControlState,
  flags: AdmissionFlags,
): "discard";
export function admitStart(
  start: AdmissionStart,
  current: ControlState,
  flags: AdmissionFlags,
): Admission;
export function admitStart(
  start: AdmissionStart,
  current: ControlState,
  flags: AdmissionFlags,
): Admission {
  switch (start.kind) {
    case "unknown":
      return "discard";
    case "absent":
      return current.kind === "absent" ||
        (current.kind === "active" && current.generation === 1)
        ? "publish"
        : "discard";
    case "active":
      if (
        current.kind === "active" &&
        current.generation === start.generation
      ) {
        return "publish";
      }
      if (
        current.kind === "absent" ||
        (current.kind === "active" && current.generation < start.generation)
      ) {
        return "wait";
      }
      return "discard";
    case "deleted": {
      // A full connect publishes at version + 1 when the connection is still
      // deleted at that version (decide writes it first) or already reconnected.
      if (!flags.userConnect || !flags.full) return "discard";
      const sameDelete =
        current.kind === "deleted" && current.version === start.version;
      const reconnected =
        current.kind === "active" && current.generation === start.version + 1;
      return sameDelete || reconnected ? "publish" : "discard";
    }
    case "foreign":
      // decide() has no row that starts from a foreign start.
      return "discard";
  }
}
