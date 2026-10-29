/**
 * Declaration rebinding: what a changed set of retained declarations does to
 * a replicating database (host contract §4.5).
 *
 * Every operation carries the exact declaration binding it was written
 * under, so a binding is its own version tag. A rebinding therefore journals
 * nothing. The database records a new binding generation, keeps trusting
 * every binding it ever retained, and writes new operations under the new
 * one. Older operations, own or received, in flight or retained, keep their
 * binding and validate against its schema. Versions of one stream merge by
 * revision (`declarationShape`), so devices that upgrade at different times
 * converge once each trusts the bindings the other wrote.
 *
 * A changed shape (semantics or primary key) of a stream the database ever
 * retained changes record identity. That is refused: the database keeps its
 * current generation and the host reports the reason.
 */
import {
  canonicalJson,
  declarationShape,
  type DeclarationBinding,
} from "./envelope.js";

export interface ReplicaBindingEntry {
  sourceId: string;
  binding: DeclarationBinding;
}

export type ReplicaRebinding =
  | { tag: "unchanged" }
  | {
      tag: "rebind";
      /** Bindings no generation retained before. */
      added: ReplicaBindingEntry[];
      /** Bindings of the current generation the next one drops. Still trusted. */
      retired: ReplicaBindingEntry[];
    }
  | { tag: "refused"; reason: string };

const entryKey = (e: ReplicaBindingEntry) =>
  canonicalJson([e.sourceId, e.binding]);
const streamKey = (e: ReplicaBindingEntry) =>
  canonicalJson([e.sourceId, e.binding.stream]);

/**
 * Decide the move from the current generation to `next`.
 *
 * @param current The bindings of the current generation.
 * @param history Every binding any generation retained (`current` included).
 * @param next The host's bindings for this boot.
 */
export function planReplicaRebinding(
  current: readonly ReplicaBindingEntry[],
  history: readonly ReplicaBindingEntry[],
  next: readonly ReplicaBindingEntry[],
): ReplicaRebinding {
  const nextKeys = new Set(next.map(entryKey));
  const currentKeys = new Set(current.map(entryKey));
  if (
    nextKeys.size === currentKeys.size &&
    [...nextKeys].every((key) => currentKeys.has(key))
  )
    return { tag: "unchanged" };
  const shapes = new Map<string, string>();
  for (const entry of history)
    shapes.set(streamKey(entry), declarationShape(entry.binding));
  for (const entry of next) {
    const prior = shapes.get(streamKey(entry));
    if (prior !== undefined && prior !== declarationShape(entry.binding))
      return {
        tag: "refused",
        reason: `replication rebinding refused: ${entry.sourceId} stream ${entry.binding.stream} changed its semantics or primary key`,
      };
  }
  const known = new Set(history.map(entryKey));
  return {
    tag: "rebind",
    added: next.filter((entry) => !known.has(entryKey(entry))),
    retired: current.filter((entry) => !nextKeys.has(entryKey(entry))),
  };
}
