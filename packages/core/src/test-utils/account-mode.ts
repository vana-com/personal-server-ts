import type {
  AccountStorageMode,
  AccountStorageModeValue,
  OwnedAccountStorageMode,
} from "../api/account-storage-mode.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
} from "../sync/account-mode/index.js";

/**
 * A mode that always answers `value`, for tests that exercise a route or a
 * runtime and need a known mode. Production code never uses this: the real
 * mode comes from the account-mode module.
 */
export function fixedAccountStorageMode(
  value: AccountStorageModeValue,
): AccountStorageMode {
  return { read: () => value };
}

/** The same fixed answer, already bound to an owner (a consumer's view). */
export function fixedOwnedAccountStorageMode(
  value: AccountStorageModeValue,
  owner = "",
): OwnedAccountStorageMode {
  return { owner, read: () => value };
}

/**
 * A real mode authority over a memory store that has already heard an explicit
 * answer for `owner`. For tests of consumers that must see the real module.
 */
export async function authorityHearing(
  owner: string,
  state: "off" | "on",
): Promise<ModeAuthority> {
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
    bootId: "test-boot",
  });
  await authority.ready;
  await authority.submitEvidence({
    owner,
    authOwner: owner,
    state,
    fetchStartedAt: Date.now(),
    rawStatus: 200,
  });
  return authority;
}
