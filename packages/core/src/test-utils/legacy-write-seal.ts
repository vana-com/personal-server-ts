import { createAccountStorageMode } from "../api/account-storage-mode.js";
import {
  createLegacyWriteSeal,
  type BindableLegacyWriteSeal,
} from "../storage/legacy-write-seal.js";

/**
 * A seal for a test that is not about the switch: bound to an account that is
 * known unswitched. Production code never builds one; a store with no seal
 * does not compile and an unbound seal refuses.
 */
export function openLegacyWriteSealForTests(): BindableLegacyWriteSeal {
  return createLegacyWriteSeal({
    mode: unswitchedAccountStorageModeForTests(),
  });
}

/** An account storage mode for a test that is not about the switch: unswitched. */
export function unswitchedAccountStorageModeForTests() {
  return createAccountStorageMode({ source: () => false });
}
