import type {
  AccountStorageMode,
  AccountStorageModeValue,
  OwnedAccountStorageMode,
} from "../api/account-storage-mode.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
  type ModeDecision,
  decisionToModeValue,
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

const FIXED_DECISION: Record<AccountStorageModeValue, ModeDecision> = {
  unswitched: { kind: "legacy" },
  switched: { kind: "streams", importRequired: false },
  unknown: { kind: "refuse", code: "ACCOUNT_MODE_UNKNOWN", status: 503 },
};

/**
 * A module that always gives the same answer, for tests of a server or runtime
 * that needs one known mode and does not exercise the module itself. It has no
 * records and no store; the app derives its mode port from it exactly as it
 * does from the real module. Production code never uses this.
 */
export function fixedModeAuthority(
  value: AccountStorageModeValue,
): ModeAuthority {
  const decision = FIXED_DECISION[value];
  const sealed = (write: () => unknown) =>
    decision.kind === "legacy"
      ? Promise.resolve(write()).then((v) => ({ ok: true as const, value: v }))
      : Promise.resolve({
          ok: false as const,
          decision:
            decision.kind === "refuse"
              ? decision
              : ({
                  kind: "refuse",
                  code: "LEGACY_REFUSED_SWITCHED",
                  status: 426,
                } as const),
        });
  return {
    ready: Promise.resolve(),
    submitEvidence: async () => decision,
    submitEvidenceMono: async () => decision,
    read: () => decision,
    admit: () => decision,
    commitLegacy: ((_owner: string, _op: string, write: () => unknown) =>
      sealed(write)) as ModeAuthority["commitLegacy"],
    commitStream: () => decision,
    commitImportSeed: () => decision,
    importPending: async () =>
      decision.kind === "streams" && decision.importRequired,
    importDone: async () => decision,
    close: async () => {},
    snapshot: () => new Map(),
  };
}

/** Who the mode was asked about and what it answered. */
export interface ModeAsked {
  owner: string;
  answer: AccountStorageModeValue;
}

/**
 * The same module, with every read recorded. The app derives its mode port
 * from the module, so the record shows what each consumer asked.
 */
export function spyOnModeAuthority(authority: ModeAuthority): {
  authority: ModeAuthority;
  calls: ModeAsked[];
} {
  const calls: ModeAsked[] = [];
  return {
    calls,
    authority: {
      ...authority,
      read(owner) {
        const decision = authority.read(owner);
        calls.push({ owner, answer: decisionToModeValue(decision) });
        return decision;
      },
    },
  };
}
