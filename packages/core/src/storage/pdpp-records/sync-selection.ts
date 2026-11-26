import type { ChangesSinceOptions, PdppRecordRow } from "./types.js";
import { redactResourceRefs } from "./served-values.js";

/** Decide one historical change from the authorized states at both horizons. */
export function selectSyncChange(
  current: PdppRecordRow,
  previous: PdppRecordRow | undefined,
  options: ChangesSinceOptions,
): PdppRecordRow | undefined {
  const visibleNow =
    !current.deleted && (!options.isVisible || options.isVisible(current));
  const visibleBefore =
    previous &&
    !previous.deleted &&
    (!options.isVisible || options.isVisible(previous));
  if (options.isVisible && !visibleNow) {
    // Candidate removals need prior authorization. Deletion-payload fields
    // never establish visibility, and a first sync has no prior disclosure.
    if (!visibleBefore) return undefined;
    return current.deleted
      ? current
      : {
          instance: current.instance,
          stream: current.stream,
          recordKey: current.recordKey,
          version: current.version,
          emittedAt: current.emittedAt,
          deletedAt: current.emittedAt,
          deleted: true,
          // spec-core §4 "Tombstones": the record still exists but left
          // the query context; an owner tombstone says so (RS item 20).
          removal: "left_query",
        };
  }
  if (current.deleted) return current; // existing current-protocol tombstones
  if (visibleBefore && options.fields) {
    // The comparison uses references as served: redacted (spec-core §4
    // "Cross-stream references", `changes_since` comparison projection).
    const project = (data: Record<string, unknown>) =>
      redactResourceRefs(
        Object.fromEntries(
          options
            .fields!.filter((f) => Object.hasOwn(data, f))
            .map((f) => [f, data[f]]),
        ),
      );
    if (
      !previous!.deleted &&
      JSON.stringify(project(previous!.data)) ===
        JSON.stringify(project(current.data))
    )
      return undefined;
  }
  return current;
}
