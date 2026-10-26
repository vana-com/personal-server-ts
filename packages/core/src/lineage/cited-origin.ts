import type { DataStoragePort } from "../ports/index.js";
import { inputHasPdppOrigin } from "../sync/pdpp-import.js";

/**
 * Whether any SOURCE A WRITER CITES is PDPP-origin: the latest local version
 * of each scope a data point id names, read through the served storage port,
 * so a joined projection's siblings are included. It applies
 * `inputHasPdppOrigin` (index row AND bytes). A source with no row, or one that
 * cannot be read, counts as PDPP. No sources means no PDPP citation.
 *
 * This checks a CLAIM, not what the writer consumed: it cannot see inputs the
 * writer left uncited, or an older version it read before a newer one was
 * published. It is only used where no PDPP data can exist (a PDPP-disabled
 * server, see `nonOwnerPublicationIsPdpp`) and for the owner's own derivatives;
 * only server compute knows its real inputs.
 */
export async function citedSourcesHavePdppOrigin(
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
