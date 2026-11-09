/**
 * The shared account-mode port, as this package needs it: what the Account
 * says of an owner, with the three values every consumer shares. A host injects
 * it; this package never decides the mode and never reads a flag itself.
 * `unknown` is no decision: nothing acts on it and nothing is reported as zero.
 */
export type AccountStorageModeValue = "switched" | "unswitched" | "unknown";

export interface AccountStorageMode {
  read(requestOwner: string): AccountStorageModeValue;
}
