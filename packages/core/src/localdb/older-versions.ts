import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  canonicalJson,
  deriveKeyCheck,
  linesOfParts,
  parseBlobName,
  parseScope,
  partBlobName,
  verifyHead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlValue } from "./driver.js";

/** A version a read can fetch now. */
export interface VersionInfo {
  readonly version: number;
  /** `stream_versions.head_blob`; the `?fileId=` value. */
  readonly fileId: string;
  readonly observedAt: number;
  readonly recordCount: number;
  readonly complete: boolean;
}

/** `/sync/status` field; counted since process start (D.3 usage count). */
export interface OlderVersionCounts {
  readonly served: number;
  readonly gone: number;
  readonly off: number;
}

/**
 * D.3: everything about older versions lives behind this one interface, in
 * this one module. Route code calls `list` and `read` and knows nothing else.
 * Deleting the feature later = this file, the flag and the call; the 410
 * remains. Current-version reads never come here.
 *
 * The `/additions`, `/versions` and `/lineage` routes on the database live in
 * `history.ts` (r5.2 1.4), not here; this interface is unchanged by them.
 *
 * Flag on: versions come from `stream_versions` of the connection's CURRENT
 * generation; head and parts are fetched on demand, decrypted, projected, and
 * nothing is stored. A missing part = `"gone"` and that `stream_versions` row
 * is removed. Flag off: `read` = `"gone"` and `list` = the current version
 * only. Each `read` logs `older-version read outcome=<served|gone|off>` with
 * no scope or owner, and bumps `counts()`.
 */
export interface OlderVersions {
  list(connectionId: string, stream: string): Promise<readonly VersionInfo[]>;
  read(
    scope: string,
    select: { readonly fileId?: string; readonly at?: string },
  ): Promise<ReadableStream<Uint8Array> | "gone">;
  counts(): OlderVersionCounts;
}

type VersionRow = {
  connection_id: string;
  stream: string;
  version: number;
  generation: number;
  head_blob: string;
  head_format: number;
  observed_at: number;
  record_count: number;
  complete: number;
};

const versionInfo = (row: VersionRow): VersionInfo => ({
  version: row.version,
  fileId: row.head_blob,
  observedAt: row.observed_at,
  recordCount: row.record_count,
  complete: row.complete === 1,
});

const currentVersions = `SELECT v.* FROM stream_versions v
  JOIN connections c ON c.connection_id = v.connection_id
  WHERE c.control_state = 'active' AND v.generation = c.generation`;
const newestFirst = " ORDER BY v.observed_at DESC, v.version DESC";
const sha = async (bytes: Uint8Array) => sha256(bytes);
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);

class MissingVersionBlob extends Error {}

export function createOlderVersions(
  deps: LocalSyncDeps,
  options: {
    /** The `olderVersionReads` server config value, read at each call (default true). */
    readonly enabled: () => boolean;
  },
): OlderVersions {
  const totals = { served: 0, gone: 0, off: 0 };
  return {
    async list(connectionId, stream) {
      const currentOnly = options.enabled()
        ? ""
        : ` AND EXISTS (SELECT 1 FROM stream_state s
            WHERE s.connection_id = v.connection_id AND s.stream = v.stream
              AND s.head_generation = v.generation AND s.head_version = v.version
              AND s.head_blob = v.head_blob)`;
      const rows = await deps.db.query<VersionRow>(
        currentVersions +
          " AND v.connection_id = ? AND v.stream = ?" +
          currentOnly +
          newestFirst,
        [connectionId, stream],
      );
      return rows.map(versionInfo);
    },

    async read(scope, select) {
      let outcome: keyof OlderVersionCounts = "gone";
      try {
        if (!options.enabled()) {
          outcome = "off";
          return "gone";
        }
        const name = parseScope(scope);
        if (name?.kind !== "stream") return "gone";
        // Current reads belong to the resolver, not this history interface.
        if (!select.fileId && !select.at) return "gone";
        const params: SqlValue[] = [name.connector, name.ns, name.stream];
        let selection: string;
        if (select.fileId) {
          selection = " AND v.head_blob = ?";
          params.push(select.fileId);
        } else {
          const text = select.at!;
          const at = /^[0-9]+$/.test(text) ? Number(text) : Date.parse(text);
          if (!Number.isSafeInteger(at) || at < 0) return "gone";
          selection = " AND v.observed_at <= ?";
          params.push(at);
        }
        const [version] = await deps.db.query<VersionRow>(
          currentVersions +
            " AND c.connector = ? AND c.ns = ? AND v.stream = ?" +
            selection +
            newestFirst +
            " LIMIT 1",
          params,
        );
        if (!version) return "gone";
        const blob = parseBlobName(version.head_blob);
        if (blob?.kind !== "head") return "gone";
        const evict = () =>
          deps.db.batch([
            {
              sql: `DELETE FROM stream_versions
            WHERE connection_id = ? AND stream = ? AND version = ?
              AND generation = ? AND head_blob = ?`,
              params: [
                version.connection_id,
                version.stream,
                version.version,
                version.generation,
                version.head_blob,
              ],
            },
          ]);
        try {
          const encrypted = await deps.blobs.get(
            `${scope}/${version.head_blob}`,
          );
          if (encrypted === null) throw new MissingVersionBlob();
          const verified = await verifyHead(
            keccak,
            await deps.keys.decrypt(scope, encrypted),
            {
              dataHash: `0x${blob.keccak}`,
              connector: name.connector,
              ns: name.ns,
              stream: name.stream,
              keyCheck: await deriveKeyCheck((message) =>
                deps.keys.namespaceHmac(message),
              ),
            },
          );
          if (verified.kind !== "ok") return "gone";
          const { head } = verified;
          if (
            head.generation !== version.generation ||
            head.format !== version.head_format
          )
            return "gone";

          // Finish loading before returning a response: a missing later part
          // must become "gone", not a failure after response headers were sent.
          // These response chunks are ephemeral; no record or blob is persisted.
          const encoder = new TextEncoder();
          const chunks: Uint8Array[] = [encoder.encode("[")];
          let count = 0;
          for await (const line of linesOfParts(sha, head, async (part) => {
            const key = `${scope}/${partBlobName(head.generation, part.hash)}`;
            const cipher = await deps.blobs.get(key);
            if (cipher === null) throw new MissingVersionBlob();
            return deps.keys.decrypt(scope, cipher);
          })) {
            chunks.push(
              encoder.encode(
                (count++ === 0 ? "" : ",") + canonicalJson(line.v),
              ),
            );
          }
          chunks.push(encoder.encode("]"));
          if (count !== head.recordCount) return "gone";

          // A delete or generation change during network I/O must not revive data.
          const stillCurrent = await deps.db.query<VersionRow>(
            currentVersions +
              " AND v.connection_id = ? AND v.stream = ?" +
              " AND v.version = ? AND v.generation = ? AND v.head_blob = ?",
            [
              version.connection_id,
              version.stream,
              version.version,
              version.generation,
              version.head_blob,
            ],
          );
          if (stillCurrent.length === 0) return "gone";
          const body = new ReadableStream<Uint8Array>({
            start(controller) {
              for (const chunk of chunks) controller.enqueue(chunk);
              controller.close();
            },
          });
          outcome = "served";
          return body;
        } catch (error) {
          if (!(error instanceof MissingVersionBlob)) throw error;
          await evict();
          return "gone";
        }
      } finally {
        totals[outcome] += 1;
        deps.logger.info({}, `older-version read outcome=${outcome}`);
      }
    },

    counts: () => ({ ...totals }),
  };
}
