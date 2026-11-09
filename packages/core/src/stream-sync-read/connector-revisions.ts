/**
 * One write counter per connector, shared by every store of the read side
 * that writes state a derived decision reads: the registry mirror (rows and
 * deletion floors) and the imported views.
 *
 * A writer bumps a connector's counter only after its new state is in memory,
 * so a reader that keys on the counter never pairs a new key with old state.
 * Counters are not persisted: a restart starts with empty caches too.
 */
export class ConnectorRevisions {
  private readonly counts = new Map<string, number>();

  bump(connector: string): void {
    this.counts.set(connector, (this.counts.get(connector) ?? 0) + 1);
  }

  of(connector: string): number {
    return this.counts.get(connector) ?? 0;
  }
}
