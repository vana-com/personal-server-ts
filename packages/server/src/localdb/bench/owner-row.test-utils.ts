import type { LocalSyncDeps } from "../../../../core/src/localdb/deps.js";
import { createLocalResolver } from "../../../../core/src/localdb/resolve.js";
import { createRecordQuery } from "../../../../core/src/localdb/query.js";

/** Read the actual owner decision/body; raw records are never a milestone. */
export async function firstOwnerRow(deps: LocalSyncDeps, scope: string) {
  const decision = await createLocalResolver(deps, {
    query: createRecordQuery(deps.db),
  }).resolve({
    scope,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });
  if (decision.kind !== "view") return null;
  const reader = decision.body.getReader();
  const decoder = new TextDecoder();
  let records = false;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) return null;
      const chunk = decoder.decode(next.value);
      if (chunk === '{"records":[') {
        records = true;
        continue;
      }
      // Both partialBody and completeBody yield each canonical row as one
      // chunk. Envelope/header and empty-array chunks cannot count as a row.
      if (records && chunk.startsWith("{")) return JSON.parse(chunk);
    }
  } finally {
    await reader.cancel();
  }
}
