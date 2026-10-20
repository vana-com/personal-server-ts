export interface ConnectionIdentity {
  owner: string;
  sourceId: string;
  connectionId: string;
}

/** Verified local mapping, supplied by the host; never inferred from source alone. */
export interface LocalConnectionMapping extends ConnectionIdentity {
  localInstanceId: string;
}

export function connectionKey(identity: ConnectionIdentity): string {
  return JSON.stringify([
    identity.owner,
    identity.sourceId,
    identity.connectionId,
  ]);
}

/** Local instance handles carry no replicated grant or token authority. */
export function resolveLocalInstance(
  identity: ConnectionIdentity,
  mappings: readonly LocalConnectionMapping[],
): string | undefined {
  const matches = mappings.filter(
    (entry) => connectionKey(entry) === connectionKey(identity),
  );
  const handles = new Set(matches.map((entry) => entry.localInstanceId));
  if (handles.size > 1) throw new Error("ambiguous local connection mapping");
  const handle = matches[0]?.localInstanceId;
  if (
    handle !== undefined &&
    mappings.some(
      (entry) =>
        entry.localInstanceId === handle &&
        connectionKey(entry) !== connectionKey(identity),
    )
  ) {
    throw new Error("local instance maps independent connections together");
  }
  return handle;
}
