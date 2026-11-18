import {
  controlScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { IntakeDeclarations } from "../stream-sync/intake.js";

/** Server-owned descriptors are passed by composition code, never request bodies. */
export interface SystemStreamDescriptor {
  readonly connector: string;
  readonly stream: string;
  readonly version: string;
  readonly primaryKey: readonly string[];
}

export function systemStreamIdentity(descriptor: SystemStreamDescriptor) {
  if (
    !/^vana-system-[a-z0-9][a-z0-9-]*$/.test(descriptor.connector) ||
    !descriptor.version ||
    descriptor.primaryKey.length === 0
  )
    throw new Error("Invalid system stream descriptor");
  return {
    connectionId: controlScope(descriptor.connector, ""),
    scope: streamScope(descriptor.connector, "", descriptor.stream),
    declarations: {
      connector: descriptor.connector,
      version: descriptor.version,
      streams: [
        {
          name: descriptor.stream,
          primaryKey: descriptor.primaryKey,
          semantics: "mutable_state",
          incremental: true,
        },
      ],
    } satisfies IntakeDeclarations,
  };
}
