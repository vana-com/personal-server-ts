import type { ControlState } from "./control.js";

/** The start states the admission rule covers: absent, or active at a generation. */
export type AdmissionStart =
  | { readonly kind: "absent" }
  | { readonly kind: "active"; readonly generation: number };

/**
 * §2.4 start-to-current admission: may a run that started under `start`
 * publish under `current`? Absent admits absent (the run creates the
 * connection) and active generation 1 (the run publishes at 1). Active
 * generation g admits active generation g only. Every other pair does not.
 *
 * This is the one owner of the rule. `decide()` picks create, publish or
 * reread from the same cells, and the reader's pending and in-flight filter
 * uses this test alone, so the two cannot disagree on which runs are admitted.
 */
export function admitsCurrent(
  start: AdmissionStart,
  current: ControlState,
): boolean {
  switch (start.kind) {
    case "absent":
      return (
        current.kind === "absent" ||
        (current.kind === "active" && current.generation === 1)
      );
    case "active":
      return (
        current.kind === "active" && current.generation === start.generation
      );
  }
}
