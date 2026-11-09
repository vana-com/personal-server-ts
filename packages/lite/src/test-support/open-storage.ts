import { unswitchedAccountStorageModeForTests } from "@opendatalabs/personal-server-ts-core/test-utils/legacy-write-seal";
import { createPersistentPsLiteStorage } from "../storage.js";

/**
 * Persistent Lite storage for a test that is not about the account switch: the
 * legacy-write seal is bound to an unswitched account. Production never does
 * this; a runtime binds the seal to the host's account mode, and unbound
 * storage refuses every legacy write.
 */
export async function createOpenPersistentPsLiteStorage(
  ...args: Parameters<typeof createPersistentPsLiteStorage>
): Promise<Awaited<ReturnType<typeof createPersistentPsLiteStorage>>> {
  const storage = await createPersistentPsLiteStorage(...args);
  storage.legacyWriteSeal.bind({
    mode: unswitchedAccountStorageModeForTests(),
  });
  return storage;
}
