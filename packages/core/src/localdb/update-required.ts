// A connection whose log this build cannot read.
//
// The protocol a connection uses is recorded in the registry by its first log
// write (the log row); nothing removes it. A device reads and writes the
// connection through it, whatever its own flag says. A log whose segment or
// snapshot is in a format this build does not know (an older build's format 1,
// or a newer build's) is read by no part of this build, so this device cannot
// show the connection's data as current and cannot write to it without
// diverging from the devices that can. It refuses both and says so, typed: it
// publishes nothing for the connection, its pending changes stay pending, and
// the cycle reports `update_required` for the connection (`CycleReport`). Rows
// the device applied before it reached the unreadable object stay applied: the
// refusal promises no publication, not an unchanged database. The
// sync manager shows it as `blocked.reason` of the sync status.

/** The log of a connection is in a format this build cannot read. */
export class UpdateRequiredError extends Error {
  readonly code = "update_required";
  constructor(
    message: string,
    /** The format the object names; `LOG_FORMAT` is the one this build reads. */
    readonly format: unknown,
  ) {
    super(message);
    this.name = "UpdateRequiredError";
  }
}
