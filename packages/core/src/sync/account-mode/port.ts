/**
 * The bridge from the module to the `AccountStorageMode` port that every
 * consumer (core API, server routes, Lite runtime, MCP engines, the write
 * gate) reads. One source: the authority.
 */

import type {
  AccountStorageMode,
  AccountStorageModeValue,
} from "../../api/account-storage-mode.js";
import type { ModeAuthority } from "./authority.js";
import type { ModeDecision } from "./record.js";

export function decisionToModeValue(
  decision: ModeDecision,
): AccountStorageModeValue {
  switch (decision.kind) {
    case "streams":
      return "switched";
    case "legacy":
      return "unswitched";
    case "refuse":
      return decision.code === "LEGACY_REFUSED_SWITCHED"
        ? "switched"
        : "unknown";
  }
}

export function accountStorageModeOf(
  authority: Pick<ModeAuthority, "read">,
): AccountStorageMode {
  return { read: (owner) => decisionToModeValue(authority.read(owner)) };
}
