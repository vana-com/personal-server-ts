import type { AccountStorageModeValue } from "../api/account-storage-mode.js";
import {
  createLegacyWriteSeal,
  type LegacyWriteHold,
  type LegacyWriteSeal,
} from "../storage/legacy-write-seal.js";
import { fixedModeAuthority } from "./account-mode.js";

/**
 * A seal over a module that always answers `value`, for a test that is not
 * about the module's own logic. Production code never builds one.
 */
export function fixedLegacyWriteSeal(
  value: AccountStorageModeValue,
  owner = "",
): LegacyWriteSeal {
  return createLegacyWriteSeal({ authority: fixedModeAuthority(value), owner });
}

/** A seal for a test that is not about the switch: an unswitched account. */
export function openLegacyWriteSealForTests(): LegacyWriteSeal {
  return fixedLegacyWriteSeal("unswitched");
}

/**
 * A hold for a test that calls a sealed storage primitive directly (an index
 * insert, a file publish) to set up state. Production code gets a hold only
 * inside `LegacyWriteSeal.commit`.
 */
export const HOLD_FOR_TESTS = {} as LegacyWriteHold;
