// The lifetime of a connection, as a delete names it.
//
// A connector's control row, one per namespace, only moves forward in the
// registry: active at version `g`, tombstoned at `g + 1`, reconnected active
// at a later version. So "the connection the person deleted" is, per
// namespace, the version it was active at. A delete that carries that
// (the lifetime it was read at) can tell its own connection from a later one,
// which a bare delete of "the connector" cannot: planned again against the
// current rows, it would end whatever is there, including a connection made
// after the person chose to delete.
//
// The token is the server's: clients store it and send it back unread.
//   v1:<ns>@<generation>,<ns>@<generation>...      sorted by namespace
// `<ns>` is empty (the default namespace) or 16 lowercase hex characters.
// Only live rows are named; `v1:` names none.

/** The delete names a lifetime the connector no longer holds. */
export class ConnectionLifetimeChanged extends Error {
  constructor(readonly connector: string) {
    super(
      `connection of ${connector} is not the one this delete names: it was connected again`,
    );
    this.name = "ConnectionLifetimeChanged";
  }
}

/** The delete names something this server never gave out as a lifetime. */
export class InvalidConnectionLifetime extends Error {
  constructor() {
    super("lifetime is not one this server names");
    this.name = "InvalidConnectionLifetime";
  }
}

/** Generation by namespace: the live control rows of one connector. */
export type Lifetime = ReadonlyMap<string, number>;

const PREFIX = "v1:";
const ENTRY = /^([0-9a-f]{16})?@([1-9][0-9]{0,15})$/;

export function formatLifetime(live: Lifetime): string {
  return (
    PREFIX +
    [...live]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([ns, generation]) => `${ns}@${generation}`)
      .join(",")
  );
}

export function parseLifetime(token: string): Lifetime {
  if (!token.startsWith(PREFIX)) throw new InvalidConnectionLifetime();
  const body = token.slice(PREFIX.length);
  const lifetime = new Map<string, number>();
  if (body === "") return lifetime;
  for (const entry of body.split(",")) {
    const match = ENTRY.exec(entry);
    const generation = match ? Number(match[2]) : NaN;
    const ns = match?.[1] ?? "";
    if (!Number.isSafeInteger(generation) || lifetime.has(ns))
      throw new InvalidConnectionLifetime();
    lifetime.set(ns, generation);
  }
  // One spelling per lifetime: a token the server did not write is refused.
  if (formatLifetime(lifetime) !== token) throw new InvalidConnectionLifetime();
  return lifetime;
}

/**
 * Whether the connector's rows now are the lifetime `named` names, or the end
 * of it. `live` is each live row's version by namespace, `ended` each
 * tombstoned row's. A live row the lifetime does not name at its version is a
 * connection made since; a named row that is not live must be tombstoned at its
 * generation + 1, the end this lifetime met (a tombstone at a later version is
 * the end of a later one).
 */
export function holdsLifetime(
  named: Lifetime,
  live: ReadonlyMap<string, number>,
  ended: ReadonlyMap<string, number>,
): boolean {
  for (const [ns, version] of live) if (named.get(ns) !== version) return false;
  for (const [ns, generation] of named)
    if (!live.has(ns) && ended.get(ns) !== generation + 1) return false;
  return true;
}
