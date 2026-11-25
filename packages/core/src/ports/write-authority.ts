/** A destructive port refused an effect because the host lost write authority. */
export class WriteAuthorityLostError extends Error {
  constructor() {
    super("the host has no write authority now; nothing was sent");
    this.name = "WriteAuthorityLostError";
  }
}

/** Read live authority synchronously at the effect, never before an await. */
export function gatedPort<A extends unknown[], R>(
  ready: (() => boolean) | undefined,
  effect: (...args: A) => R,
): (...args: A) => R {
  return (...args) => {
    if (ready && !ready()) throw new WriteAuthorityLostError();
    return effect(...args);
  };
}
