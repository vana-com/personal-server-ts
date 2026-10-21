import type { DataStoragePort } from "../ports/index.js";
import { inputHasPdppOrigin } from "../sync/pdpp-import.js";

/**
 * Whether any cited source is PDPP-origin, decided on the exact input a
 * derivative consumes: the latest version of the scope a data point id names,
 * read through the SAME served storage port the compute path reads, so the
 * provenance of a joined projection's siblings is included. Applies
 * `inputHasPdppOrigin` (index row AND bytes), the rule compute applies to each
 * source it reads. A source with no row, or one that cannot be read, has no
 * trustworthy provenance and counts as PDPP. No sources (an attested root)
 * means no PDPP input.
 */
export async function sourcesHavePdppOrigin(
  storage: Pick<DataStoragePort, "findEntry" | "readEnvelope">,
  scopes: readonly string[],
): Promise<boolean> {
  for (const scope of scopes) {
    const entry = storage.findEntry({ scope });
    if (!entry) return true;
    if (entry.pdppOrigin === true) return true;
    let envelope;
    try {
      envelope = await storage.readEnvelope(scope, entry.collectedAt);
    } catch {
      return true;
    }
    if (inputHasPdppOrigin(entry, envelope)) return true;
  }
  return false;
}
