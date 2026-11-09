/**
 * Readback: prove, for one local legacy version, that the stream data holds
 * it. The published view of the scope (imported registry heads, read as a
 * grant reads; never this device's spool or overlay) is compared with the
 * legacy file entity by entity: every entity of the file must be in the view
 * with an equal content hash (SHA-256 of its canonical JSON, keyed by the
 * reviewed entity key), or be explained by the delete fence. A count alone
 * never passes: a changed body fails.
 */

import { sha256 } from "@noble/hashes/sha2";
import {
  entityHashes,
  type EntityHashes,
} from "../../storage/legacy-entity-key-sets.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { ReadbackRecord, RetireLedger } from "./ledger.js";
import { versionKey } from "./ledger.js";

/** What a readback needs from the stream read side. */
export interface ReadbackView {
  /** The legacy body of the PUBLISHED view, or null when none serves it. */
  publishedBody(scope: string): Promise<unknown | null>;
  /** Target streams of the scope with the version of their last delete. */
  streamDeletes(
    scope: string,
  ):
    | readonly { connector: string; stream: string; deleteVersion: number }[]
    | null;
}

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function aggregateOf(matched: string[]): string {
  return hex(sha256(new TextEncoder().encode(matched.sort().join("\n"))));
}

export function compareEntities(
  local: EntityHashes,
  published: EntityHashes | null,
  fenceOpen: boolean,
): Pick<ReadbackRecord, "pass" | "reason" | "counts" | "fenced" | "aggregate"> {
  let total = 0;
  let matchedCount = 0;
  let missing = 0;
  let changed = 0;
  const matched: string[] = [];
  for (const [path, entities] of local) {
    const held = published?.get(path);
    for (const [key, hash] of entities) {
      total += 1;
      const other = held?.get(key);
      if (other === undefined) missing += 1;
      else if (other !== hash) changed += 1;
      else {
        matchedCount += 1;
        matched.push(`${path}|${key}|${hash}`);
      }
    }
  }
  const unmatched = missing + changed;
  const counts = { local: total, matched: matchedCount, missing, changed };
  const aggregate = aggregateOf(matched);
  if (total === 0) {
    return { pass: false, reason: "empty", counts, fenced: 0, aggregate };
  }
  if (unmatched === 0) {
    return { pass: true, reason: "ok", counts, fenced: 0, aggregate };
  }
  // Fence: every target stream of the scope has seen a delete, so the
  // publish may have dropped these records on purpose. The retire step still
  // requires a full re-collect on this device before it deletes the file.
  if (fenceOpen) {
    return {
      pass: true,
      reason: "ok",
      counts,
      fenced: unmatched,
      aggregate,
    };
  }
  return { pass: false, reason: "mismatch", counts, fenced: 0, aggregate };
}

/**
 * Read back one local legacy version and store the result. Never throws for
 * an unreadable file or view: that is a failed readback, stored as such.
 */
export async function readbackVersion(
  deps: {
    storage: Pick<DataStoragePort, "readEnvelope">;
    view: ReadbackView;
    ledger: RetireLedger;
    now?: () => Date;
  },
  scope: string,
  row: IndexEntry,
): Promise<ReadbackRecord> {
  const at = (deps.now?.() ?? new Date()).toISOString();
  const base = {
    scope,
    version: versionKey(row),
    counts: { local: 0, matched: 0, missing: 0, changed: 0 },
    fenced: 0,
    aggregate: aggregateOf([]),
    at,
  };
  const store = async (
    record: Pick<ReadbackRecord, "pass" | "reason"> & Partial<ReadbackRecord>,
  ): Promise<ReadbackRecord> => {
    const full: ReadbackRecord = { ...base, ...record };
    await deps.ledger.update((data) => {
      data.readbacks[`${scope}|${full.version}`] = full;
    });
    return full;
  };

  let local: EntityHashes | null;
  try {
    const envelope = await deps.storage.readEnvelope(scope, row.collectedAt);
    local = entityHashes(scope, envelope.data);
  } catch {
    return store({ pass: false, reason: "unreadable" });
  }
  if (!local) return store({ pass: false, reason: "unkeyed" });

  const body = await deps.view.publishedBody(scope).catch(() => null);
  const deletes = deps.view.streamDeletes(scope);
  const fenceOpen =
    deletes !== null &&
    deletes.length > 0 &&
    deletes.every((s) => s.deleteVersion > 0);
  let published: EntityHashes | null = null;
  if (body !== null) published = entityHashes(scope, body);
  if (published === null && !fenceOpen) {
    return store({ pass: false, reason: "no_published_view" });
  }
  return store(compareEntities(local, published, fenceOpen));
}
