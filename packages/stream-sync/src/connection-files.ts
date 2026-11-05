import { placeholderNaming, type StorageNaming } from "./naming.js";

/**
 * Every file that belongs to one connection: heads and parts of all its
 * streams. Ownership comes from the naming parser, never from "the text before
 * the first dot": that shortcut files `pdpp.<connection>.*` under a source
 * called `pdpp`, so deleting the connection would miss them.
 *
 * Names the scheme does not own are ignored. The result is sorted and unique,
 * so the same inventory always gives the same list.
 */
export function filesOfConnection(
  names: Iterable<string>,
  connectionId: string,
  naming: StorageNaming = placeholderNaming,
): string[] {
  const found = new Set<string>();
  for (const name of names) {
    const parsed = naming.parse(name);
    if (parsed !== null && parsed.connectionId === connectionId)
      found.add(name);
  }
  return [...found].sort();
}
