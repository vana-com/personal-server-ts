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
    streamDeletes: (scope) => input.reader.retireBasis(scope)?.streams ?? null,
    importDone: (connector) => input.ledger.importDone(connector),
    fullRunSince: (connector, stream, deleteVersion) =>
      input.writer.fullRunSince(connector, stream, deleteVersion),
  };
}
