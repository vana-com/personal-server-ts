/**
 * Test-only: build the default Lite runtime and let its account-mode module
 * hear an explicit Off from the Account, as a host does after sign-in. The
 * records live in memory, so a test needs no IndexedDB for them.
 */
import {
  createIndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntimeOptions,
} from "../browser-runtime.js";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

export async function createUnswitchedIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
): Promise<IndexedDbPsLiteRuntime> {
  const runtime = await createIndexedDbPsLiteRuntime({
    accountModeStore: createMemoryModeRecordStore(),
    ...options,
  });
  const owner = options.ownerAddress ?? "";
  await runtime.accountModeAuthority.submitEvidence({
    owner,
    authOwner: owner,
    state: "off",
    fetchStartedAt: Date.now(),
    rawStatus: 200,
  });
  return runtime;
}
