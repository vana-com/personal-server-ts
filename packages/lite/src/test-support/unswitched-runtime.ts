/**
 * Test-only: build the default Lite runtime and let its account-mode module
 * hear an explicit Off (or On) from the Account, as a host does after sign-in.
 * The records live in memory, so a test needs no IndexedDB for them.
 *
 * Legacy writes need an account that is not switched; stream writes need a
 * saved On. A test picks the one its subject needs.
 */
import {
  createIndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntimeOptions,
} from "../browser-runtime.js";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

async function createHearingIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
  state: "off" | "on",
): Promise<IndexedDbPsLiteRuntime> {
  const runtime = await createIndexedDbPsLiteRuntime({
    accountModeStore: createMemoryModeRecordStore(),
    ...options,
  });
  const owner = options.ownerAddress ?? "";
  await runtime.accountModeAuthority.submitEvidence({
    owner,
    state,
  });
  return runtime;
}

export function createUnswitchedIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
): Promise<IndexedDbPsLiteRuntime> {
  return createHearingIndexedDbPsLiteRuntime(options, "off");
}

export function createSwitchedIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
): Promise<IndexedDbPsLiteRuntime> {
  return createHearingIndexedDbPsLiteRuntime(options, "on");
}
