/**
 * A refusal to start, with fixed text. The message never holds input from the
 * environment, the data folder or a library error: those can carry the owner's
 * signature or a file name.
 */

export type DryRunSetupCode =
  | "no_owner_signature"
  | "bad_owner_signature"
  | "bad_config"
  | "host_not_pinned";

export class DryRunSetupError extends Error {
  constructor(
    readonly code: DryRunSetupCode,
    message: string,
  ) {
    super(message);
    this.name = "DryRunSetupError";
  }
}
