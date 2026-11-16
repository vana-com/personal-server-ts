/**
 * The stream-sync design flags: features that are off until a host turns them
 * on. This table is the one place a flag's name is tied to the environment
 * variable that also turns it on. A host passes the names it wants as one
 * comma list (`streamSyncFlags` option, or the `PS_STREAM_SYNC_FLAGS`
 * variable) and holds no table of its own; a name left out stays off and an
 * unknown name is ignored.
 *
 * A flag's own explicit option (for example `streamSyncLogProtocol`) still
 * wins over this list. What a flag means is owned where it is consumed (see
 * `LocalSyncDeps`), not here.
 */

export const STREAM_SYNC_DESIGN_FLAGS = [
  { name: "publishWhileCollecting", env: "PS_PUBLISH_WHILE_COLLECTING" },
  { name: "logProtocol", env: "PS_STREAM_SYNC_LOG_PROTOCOL" },
  {
    name: "progressiveFirstLoad",
    env: "PS_STREAM_SYNC_PROGRESSIVE_FIRST_LOAD",
  },
] as const;

export type StreamSyncDesignFlagName =
  (typeof STREAM_SYNC_DESIGN_FLAGS)[number]["name"];

/** The environment variable that carries the whole comma list. */
export const STREAM_SYNC_FLAGS_ENV = "PS_STREAM_SYNC_FLAGS";

function namesIn(list: string | undefined): Set<string> {
  return new Set((list ?? "").split(",").map((name) => name.trim()));
}

/**
 * Which flags are on: those the list names, those the list variable names, and
 * those whose own variable is exactly `"true"`. Pass no environment in a
 * runtime that has none (a browser).
 */
export function streamSyncFlagsOn(
  list: string | undefined,
  env: Readonly<Record<string, string | undefined>> = {},
): Record<StreamSyncDesignFlagName, boolean> {
  const named = namesIn(list);
  const envNamed = namesIn(env[STREAM_SYNC_FLAGS_ENV]);
  const on = {} as Record<StreamSyncDesignFlagName, boolean>;
  for (const flag of STREAM_SYNC_DESIGN_FLAGS) {
    on[flag.name] =
      named.has(flag.name) ||
      envNamed.has(flag.name) ||
      env[flag.env] === "true";
  }
  return on;
}
