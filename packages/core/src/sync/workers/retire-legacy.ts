import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";
import { isPhysicalScope } from "../../stream-sync/scope-routing.js";
import { isGatewayReservedScope } from "../delete-data-port.js";
import type { DeleteScopeResult } from "./delete.js";

/** Scopes deleted per cycle: each costs a tombstone and a storage batch. */
export const RETIRE_LEGACY_SCOPES_PER_CYCLE = 10;

const SCOPE_PAGE_SIZE = 200;

export interface RetireLegacyDeps {
  storage: Pick<DataStoragePort, "listScopes">;
  /**
   * The stream-sync reader would serve a view of `scope` instead of its
   * legacy file: every stream the name needs is live and complete. The same
   * decision as the read path (`eligible()` kind `view`).
   */
  viewIsComplete(scope: string): boolean;
  /** Durable scope deletion: gateway tombstone, storage blobs, local copy. */
  deleteScope(scope: string): Promise<DeleteScopeResult>;
  logger: Pick<Logger, "info" | "warn">;
}

export interface RetireLegacyResult {
  /** Legacy scopes held locally. */
  considered: number;
  /** Scopes whose view is complete and whose delete finished or is queued. */
  deleted: number;
  /** Scopes kept: view not complete, or the delete did not reach the gateway. */
  kept: number;
}

/**
 * Delete the legacy files of every scope whose stream-sync view is complete.
 * The caller runs it only once the account has switched to stream sync.
 *
 * Idempotent and safe between devices: a scope with no local files is not
 * listed, so a finished delete is not repeated; a device racing another one
 * gets `already-deleted` from the gateway and `missing` blobs from storage,
 * both of which `deleteScope` treats as success.
 *
 * Only legacy scopes are listed and deleted. A stream-sync name (`~`) or a
 * gateway-reserved scope is skipped even if the storage lists it. A scope
 * whose view is not complete keeps its legacy file: it is still the only
 * copy a read can serve. A failed delete leaves the local copy (the
 * deleteScope order), so the next cycle retries it.
 *
 * Logs counts only.
 */
export async function retireLegacyScopes(
  deps: RetireLegacyDeps,
): Promise<RetireLegacyResult> {
  const result: RetireLegacyResult = { considered: 0, deleted: 0, kept: 0 };
  // Snapshot the listing first: deleting while paging would shift offsets.
  const scopes: string[] = [];
  for (let offset = 0; ; offset += SCOPE_PAGE_SIZE) {
    const page = deps.storage.listScopes({ limit: SCOPE_PAGE_SIZE, offset });
    for (const { scope } of page.scopes) {
      if (isPhysicalScope(scope) || isGatewayReservedScope(scope)) continue;
      scopes.push(scope);
    }
    if (page.scopes.length < SCOPE_PAGE_SIZE) break;
  }
  result.considered = scopes.length;

  let budget = RETIRE_LEGACY_SCOPES_PER_CYCLE;
  for (const scope of scopes) {
    if (!deps.viewIsComplete(scope)) {
      result.kept += 1;
      continue;
    }
    if (budget === 0) continue; // next cycle
    budget -= 1;
    try {
      const outcome = await deps.deleteScope(scope);
      if (outcome.durable) result.deleted += 1;
      else result.kept += 1;
    } catch {
      result.kept += 1;
    }
  }
  if (result.deleted > 0 || result.kept > 0) {
    deps.logger.info(
      { ...result },
      "Retired legacy scopes after the stream-sync switch",
    );
  }
  return result;
}

const IDENTIFYING_FIELDS = new Set([
  "scope",
  "dataPointId",
  "error",
  "version",
]);

/**
 * A logger for the retire step's `deleteScope` calls: log payloads keep their
 * counts and statuses and lose the scope name, data point id, version and
 * error text. The message string is fixed text and stays.
 */
export function countsOnlyLogger(logger: Logger): Logger {
  const strip = (payloadOrMessage?: unknown): unknown => {
    if (
      typeof payloadOrMessage !== "object" ||
      payloadOrMessage === null ||
      Array.isArray(payloadOrMessage)
    ) {
      return payloadOrMessage;
    }
    return Object.fromEntries(
      Object.entries(payloadOrMessage).filter(
        ([key]) => !IDENTIFYING_FIELDS.has(key),
      ),
    );
  };
  return {
    debug: (p, m) => logger.debug(strip(p), m),
    info: (p, m) => logger.info(strip(p), m),
    warn: (p, m) => logger.warn(strip(p), m),
    error: (p, m) => logger.error(strip(p), m),
  };
}
