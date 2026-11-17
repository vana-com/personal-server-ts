import type { SqlReader, SqlValue } from "./driver.js";

export interface StagedKey extends Record<string, SqlValue> {
  seq: number;
  connection_id: string;
  stream: string;
  pk_hash: string;
  kind: string;
  rank: number;
  stamp_o: number;
  stamp_r: string;
  stamp_n: number;
  body_sha256: string | null;
  position: number;
  entry_order: number;
}
type Cell = { upsert: number; deletion: number };
export type WinnerGroup = {
  connectionId: string;
  stream: string;
  keys: [string, number, number][];
};
const newer = (a: StagedKey, b: StagedKey, deletion: boolean) =>
  a.stamp_o !== b.stamp_o
    ? a.stamp_o > b.stamp_o
    : a.stamp_r !== b.stamp_r
      ? a.stamp_r > b.stamp_r
      : deletion
        ? a.rank > b.rank
        : a.stamp_n !== b.stamp_n
          ? a.stamp_n > b.stamp_n
          : a.body_sha256 !== b.body_sha256
            ? String(a.body_sha256) > String(b.body_sha256)
            : a.position !== b.position
              ? a.position < b.position
              : a.entry_order < b.entry_order;
const outlives = (u: StagedKey, d: StagedKey) =>
  u.stamp_o > d.stamp_o ||
  (u.stamp_o === d.stamp_o &&
    (u.stamp_r > d.stamp_r || (u.stamp_r === d.stamp_r && d.rank === 0)));

/** Only key strings and rowids survive a segment. Bodies remain in the heap. */
export class BootstrapKeys {
  private groups = new Map<
    string,
    { connectionId: string; stream: string; cells: Map<string, Cell> }
  >();
  private count = 0;
  constructor(
    private db: SqlReader,
    private lookup?: (seq: number) => Promise<StagedKey>,
  ) {}
  private async get(seq: number) {
    if (this.lookup) return this.lookup(seq);
    const [row] = await this.db.query<StagedKey>(
      "SELECT seq,connection_id,stream,pk_hash,kind,rank,stamp_o,stamp_r,stamp_n,body_sha256,seq position,0 entry_order FROM bootstrap_rows WHERE seq=?",
      [seq],
    );
    if (!row) throw new Error("bootstrap: missing staged key");
    return row;
  }
  async add(row: StagedKey) {
    const id = JSON.stringify([row.connection_id, row.stream]);
    let group = this.groups.get(id);
    if (!group)
      this.groups.set(
        id,
        (group = {
          connectionId: row.connection_id,
          stream: row.stream,
          cells: new Map(),
        }),
      );
    let cell = group.cells.get(row.pk_hash);
    if (!cell) {
      group.cells.set(row.pk_hash, (cell = { upsert: 0, deletion: 0 }));
      this.count++;
    }
    const field = row.kind === "u" ? "upsert" : "deletion";
    if (
      !cell[field] ||
      newer(row, await this.get(cell[field]), field === "deletion")
    )
      cell[field] = row.seq;
  }
  get keyPayloadBytes() {
    return this.count * (64 + 8 + 8);
  }
  async sorted(): Promise<WinnerGroup[]> {
    const result: WinnerGroup[] = [];
    for (const group of this.groups.values()) {
      const keys: WinnerGroup["keys"] = [];
      for (const [hash, cell] of group.cells) {
        let upsert = cell.upsert;
        if (
          upsert &&
          cell.deletion &&
          !outlives(await this.get(upsert), await this.get(cell.deletion))
        )
          upsert = 0;
        keys.push([hash, upsert, cell.deletion]);
      }
      keys.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      result.push({
        connectionId: group.connectionId,
        stream: group.stream,
        keys,
      });
    }
    result.sort((a, b) =>
      a.connectionId < b.connectionId
        ? -1
        : a.connectionId > b.connectionId
          ? 1
          : a.stream < b.stream
            ? -1
            : a.stream > b.stream
              ? 1
              : 0,
    );
    this.groups.clear();
    return result;
  }
}
