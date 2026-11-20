import { openLegacyWriteSealForTests } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { LegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import {
  createPersistentPsLiteStorage,
  createIndexedDbPsLitePersistence,
  type PsLiteDataFileStore,
  type PsLitePersistenceAdapter,
  type PsLiteStoragePort,
} from "../storage.js";
import type { PsLiteStorageAdapter } from "../runtime.js";

/**
 * Persistent Lite storage for a test that is not about the account switch:
 * its legacy-write seal is an unswitched account. Pass a seal to test with
 * another mode. Production code never builds storage this way: it hands the
 * storage the seal over the host's account-mode authority.
 */
export function createOpenPersistentPsLiteStorage(
  adapter: PsLiteStorageAdapter,
  persistence: PsLitePersistenceAdapter = createIndexedDbPsLitePersistence(),
  dataFileStore?: PsLiteDataFileStore,
  legacyWriteSeal: LegacyWriteSeal = openLegacyWriteSealForTests(),
): Promise<PsLiteStoragePort> {
  return createPersistentPsLiteStorage(
    adapter,
    persistence,
    dataFileStore,
    legacyWriteSeal,
  );
}
