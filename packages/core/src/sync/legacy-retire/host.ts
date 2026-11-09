import type { StreamSyncWriter } from "../../stream-sync/writer.js";
import type { StreamSyncReadService } from "../../stream-sync-read/service.js";
import type { RetireHost } from "./retire.js";
import type { RetireLedger } from "./ledger.js";

/**
 * The stream side of a retire pass, from the published read service (imported
 * heads only), the writer's record of full runs, and the import ledger.
 */
export function createRetireHost(input: {
  reader: Pick<StreamSyncReadService, "publishedBody" | "retireBasis">;
  writer: Pick<StreamSyncWriter, "fullRunSince">;
  ledger: RetireLedger;
}): RetireHost {
  return {
    publishedBody: (scope) => input.reader.publishedBody(scope),
    deleteBasis: (scope) => {
      const basis = input.reader.retireBasis(scope);
      // Authority: the registry for this owner says the scope is either
      // covered by live complete heads or deleted whole, and no second active
      // connection makes the answer ambiguous. Anything else is no basis, and
      // the scope is neither fenced nor passed.
      if (!basis || basis.ambiguous || !(basis.covered || basis.deleted)) {
        return null;
      }
      return {
        streams: basis.streams,
        viewDeleted: basis.deleted,
        allTargetsKnown: basis.allTargetsKnown,
      };
    },
    importDone: (connector) => input.ledger.importProven(connector),
    importStaged: (connector, stream) => input.ledger.staged(connector, stream),
    fullRunSince: (connector, stream, deleteVersion) =>
      input.writer.fullRunSince(connector, stream, deleteVersion),
  };
}
