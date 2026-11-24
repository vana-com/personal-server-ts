// Memory of the legacy sync path (`sync/workers/upload.ts`, `download.ts`) on
// one data point of N records, for the table in scripts/log-memory/README.md.
//
//   node --expose-gc --import tsx <this file> --records N --pad BYTES
//
// The legacy path sends a scope's whole data file as one object, and refuses a
// file whose upload body would pass `MAX_UPLOAD_BODY_BYTES`: a source that big
// is reported as refused (`refused: true`, no measure) and is never sent. It
// uses real crypto (OpenPGP) and in-memory fakes for the storage and the
// gateway, so `aboveIdleMiB` includes the bytes the fakes keep (about the
// stored size on upload, the same again on download): `endMiB - idleMiB` says
// how much stayed.
import type {
  DataFileEnvelope,
  DataPointRecord,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import { exceedsUploadCap } from "../../../../core/src/sync/upload-state.js";
import { uploadOne } from "../../../../core/src/sync/workers/upload.js";
import { downloadOne } from "../../../../core/src/sync/workers/download.js";
import { createMemoryDataStorage } from "../../../../core/src/test-utils/memory-storage.js";
import type { StorageAdapter } from "../../../../core/src/storage/adapters/interface.js";
import type { Logger } from "../../../../core/src/logger/index.js";
import { measure } from "./measure.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCOPE = "bench.records";
const COLLECTED_AT = "2026-01-21T10:00:00Z";
const DATA_POINT_ID = `0x${"fe".repeat(32)}`;

const flag = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? fallback : process.argv[i + 1]!;
};

class BlobAdapter implements StorageAdapter {
  readonly blobs = new Map<string, Uint8Array>();
  async upload(key: string, data: Uint8Array) {
    this.blobs.set(key, new Uint8Array(data));
    return `memory://blob/${key}`;
  }
  urlForKey = (key: string) => `memory://blob/${key}`;
  async download(url: string) {
    const blob = this.blobs.get(url.slice("memory://blob/".length));
    if (!blob) throw new Error("missing blob");
    return new Uint8Array(blob);
  }
  async delete(url: string) {
    return this.blobs.delete(url.slice("memory://blob/".length));
  }
  async exists(url: string) {
    return this.blobs.has(url.slice("memory://blob/".length));
  }
}

const records = Number(flag("records", "10000"));
const pad = Number(flag("pad", "1024"));
const quiet = () => undefined;
const logger = {
  info: quiet,
  error: quiet,
  warn: quiet,
  debug: quiet,
} as unknown as Logger;

const stored = records * (pad + 60);
if (exceedsUploadCap(stored)) {
  process.stdout.write(
    `${JSON.stringify({ step: "legacy-upload", refused: true, storedBytes: stored })}\n`,
  );
} else {
  const masterKey = new Uint8Array(65).fill(0xaa);
  const storageAdapter = new BlobAdapter();
  const producer = createMemoryDataStorage();
  const grantee = createMemoryDataStorage();
  {
    const text = "p".repeat(pad);
    const envelope: DataFileEnvelope = {
      version: "1.0",
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      data: {
        records: Array.from({ length: records }, (_, id) => ({
          id,
          v: 1,
          pad: text,
        })),
      },
    };
    const write = await producer.writeEnvelope(envelope);
    producer.insertEntry({
      fileId: null,
      schemaId: null,
      path: write.relativePath,
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      sizeBytes: write.sizeBytes,
      version: 1,
      dataPointId: null,
    });
  }
  let registered: DataPointRecord | null = null;
  const gateway = {
    registerDataPoint: async (request: {
      ownerAddress: string;
      scope: string;
      dataHash: string;
      metadataHash: string;
      expectedVersion: number;
    }) => {
      registered = {
        id: DATA_POINT_ID,
        ownerAddress: request.ownerAddress,
        scope: request.scope,
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
        expectedVersion: request.expectedVersion,
        addedAt: COLLECTED_AT,
      } as DataPointRecord;
      return { dataPointId: DATA_POINT_ID };
    },
    getDataPoint: async () => registered,
    listDataPointsByOwner: async () => [],
  } as unknown as GatewayClient;
  const signer = {
    signAddData: async () => `0x${"11".repeat(65)}` as `0x${string}`,
    signLineageAttestation: async () => `0x${"22".repeat(65)}` as `0x${string}`,
  };
  const entry = producer.entries[0]!;

  const up = await measure("legacy-upload", () =>
    uploadOne(
      {
        storage: producer,
        storageAdapter,
        gateway,
        signer,
        masterKey,
        serverOwner: OWNER,
        logger,
      },
      entry,
    ),
  );
  process.stdout.write(`${JSON.stringify(up.report)}\n`);
  const down = await measure("legacy-download", () =>
    downloadOne(
      {
        storage: grantee,
        storageAdapter,
        gateway,
        cursor: { read: async () => null, write: async () => undefined },
        masterKey,
        serverOwner: OWNER,
        logger,
      } as never,
      registered!,
    ),
  );
  process.stdout.write(`${JSON.stringify(down.report)}\n`);
}
