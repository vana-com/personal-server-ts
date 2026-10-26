import type { ChangesSinceOptions, PdppRecordRow } from "./types.js";

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
        };
  }
  if (current.deleted) return current; // existing current-protocol tombstones
  if (visibleBefore && options.fields) {
    const project = (data: Record<string, unknown>) =>
      Object.fromEntries(
        options
          .fields!.filter((f) => Object.hasOwn(data, f))
          .map((f) => [f, data[f]]),
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
