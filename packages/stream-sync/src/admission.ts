import type { ControlState } from "./control.js";

/**
 * A run's start state, as decide() reads it at publish. `unknown` is a run
 * that recorded no start snapshot (for example, before the snapshot existed).
 */
export type AdmissionStart =
  | { readonly kind: "unknown" }
  | { readonly kind: "absent" }
  | { readonly kind: "active"; readonly generation: number };

/**
 * What the start-to-current rule says about a run:
 * - `publish`: the run may take its target. Absent-to-absent creates the
 *   connection; absent-to-active-1 and active(g)-to-active(g) publish.
 * - `wait`: the connection moved away from an active start (absent, or active
 *   at a lower generation). The run stays pending; the writer rereads.
 * - `discard`: the run never publishes under this current state.
 */
export type Admission = "publish" | "wait" | "discard";

/**
 * §2.4 start-to-current rule, the one owner of it. decide() maps `wait` to
 * its reread/keep_pending cells and `discard` to its DISCARD flags, and the
 * reader filters pending runs on `publish` or `wait` and published runs on
 * `publish` only. A deleted or foreign start is not decided here: decide()
 * keeps its own deleted cell and the reader handles those starts itself.
 */
export function admitStart(
  start: AdmissionStart,
  current: ControlState,
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
  }
}
