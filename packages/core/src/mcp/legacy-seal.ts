/**
 * Deps for an MCP read of a switched account: the same handler and ports, with
 * legacy storage sealed.
 *
 * Once an account has moved to stream sync, stream data is its only store.
 * An MCP read still goes through the `/v1/data` handler, which owns the grant
 * check, the charge and the access log, so the handler is handed deps whose
 * legacy storage answers "no entry" to every lookup and refuses every content
 * read. The wrong action, serving a legacy file to a switched account, is then
 * impossible from these paths rather than avoided by each caller. The stream
 * reader is the only thing left that can answer.
 *
 * Only an owner that is switched gets sealed deps. An unswitched account keeps
 * the deps it was given.
 */

import type { PersonalServerDataApiDeps } from "../api/index.js";

/** Lookups that read "nothing there" when legacy storage is sealed. */
const EMPTY_ANSWERS: Record<string, () => unknown> = {
  findEntry: () => undefined,
  findByFileId: () => undefined,
  findByDataPointId: () => undefined,
};

export class LegacyStorageSealedError extends Error {
  constructor(method: string) {
    super(
      `legacy storage is sealed for an account on stream sync (${method} called)`,
    );
    this.name = "LegacyStorageSealedError";
  }
}

function sealedStorage(
  storage: PersonalServerDataApiDeps["storage"],
): PersonalServerDataApiDeps["storage"] {
  return new Proxy(storage, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (typeof value !== "function") return value;
      const empty = EMPTY_ANSWERS[String(prop)];
      if (empty) return empty;
      return () => {
        throw new LegacyStorageSealedError(String(prop));
      };
    },
  });
}

export function sealLegacyReads(
  deps: PersonalServerDataApiDeps,
): PersonalServerDataApiDeps {
  const { legacyScopeView: _canonicalView, ...rest } = deps;
  return { ...rest, storage: sealedStorage(deps.storage) };
}
