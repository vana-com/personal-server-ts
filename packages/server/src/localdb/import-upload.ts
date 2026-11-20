import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, realpath, link, unlink } from "node:fs/promises";
import { resolve, join } from "node:path";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  importLegacySource,
  createImportLedger,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { ResolveArtifact } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type {
  ImportSource,
  LegacyImportResult,
  LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";

export interface LegacyImportUpload {
  /** Authenticated install provenance; never used to derive a sync namespace. */
  readonly source: string;
  /** Lowercase SHA-256 of the exact complete NDJSON bytes. */
  readonly revision: string;
  readonly artifactDigest: string;
  readonly stream: string;
  readonly body: AsyncIterable<Uint8Array>;
}
interface UploadOptions {
  readonly owner: string;
  readonly network: string;
  readonly upload: LegacyImportUpload;
  readonly stagingRoot: string;
  readonly resolveArtifact: ResolveArtifact;
  readonly resolveTarget: (
    upload: LegacyImportUpload,
  ) => Promise<ImportSource["target"] | null>;
}

/** Only local staging formats change: bytes are fsynced, then installed without
 * replacing an existing file. A separate atomic seal binds authenticated
 * identity, verified declaration fields and target. Partial files never reopen.
 * The source tuple uses the verified connector key; install id is provenance. */
export async function stageLegacyImportUpload(
  options: UploadOptions,
): Promise<ImportSource> {
  const context = await uploadContext(options);
  const temporary = join(context.root, `.upload-${randomUUID()}.pending`);
  const file = await open(temporary, "wx", 0o600);
  const hash = createHash("sha256");
  try {
    async function* persisted() {
      for await (const chunk of options.upload.body) {
        let offset = 0;
        while (offset < chunk.byteLength) {
          const result = await file.write(
            chunk,
            offset,
            chunk.byteLength - offset,
            null,
          );
          if (!result.bytesWritten) throw new Error("upload_write_failed");
          offset += result.bytesWritten;
        }
        hash.update(chunk);
        yield chunk;
      }
    }
    for await (const record of decodeRecords(persisted())) {
      try {
        computeRecordKeyFromData(record, [...context.target.primaryKey]);
      } catch {
        throw new Error("invalid_record");
      }
    }
    if (hash.digest("hex") !== context.revision)
      throw new Error("source_changed");
    await file.sync();
    await file.close();
    try {
      await link(temporary, context.data);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    // Check any existing bytes before allowing a new seal to reference them.
    if ((await fileHash(context.data)) !== context.revision)
      throw new Error("source_changed");
    const sealTemporary = join(context.root, `.seal-${randomUUID()}.pending`);
    try {
      const seal = await open(sealTemporary, "wx", 0o600);
      try {
        await seal.writeFile(context.seal);
        await seal.sync();
      } finally {
        await seal.close();
      }
      try {
        await link(sealTemporary, context.sealPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      const directory = await open(context.root, "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    } finally {
      await removeTemporary(sealTemporary);
    }
    return await sealedSource(options, context);
  } finally {
    await file.close().catch(() => {});
    await removeTemporary(temporary);
  }
}

/** Reopen by authenticated tuple after restart, without a new upload or writer.
 * The resolver must still verify the retained artifact and the same target. */
export async function openStagedLegacyImportUpload(
  options: Omit<UploadOptions, "upload"> & {
    readonly upload: Omit<LegacyImportUpload, "body">;
  },
): Promise<ImportSource> {
  const complete = {
    ...options,
    upload: { ...options.upload, body: (async function* () {})() },
  };
  return sealedSource(complete, await uploadContext(complete));
}

/** Caller owns authentication and switched-owner admission; SQL import owns
 * owner/network, generation, deletion and publication-proof boundaries. */
export function acceptLegacyImportUpload(
  deps: LocalSyncDeps,
  source: ImportSource,
): Promise<LegacyImportResult> {
  return importLegacySource(deps, createImportLedger(deps.db), source);
}
async function uploadContext(options: UploadOptions) {
  const { upload } = options;
  if (
    !options.owner.trim() ||
    !options.network.trim() ||
    !upload.source.trim() ||
    !upload.stream ||
    !/^[0-9a-f]{64}$/.test(upload.revision)
  )
    throw new Error("upload_identity_invalid");
  const declarations = await options.resolveArtifact(upload.artifactDigest);
  const streams =
    declarations?.streams.filter((s) => s.name === upload.stream) ?? [];
  if (!declarations || streams.length !== 1 || !streams[0]!.primaryKey.length)
    throw new Error("upload_artifact_unverified");
  const resolved = await options.resolveTarget(upload);
  if (
    !resolved ||
    !resolved.connectionId ||
    resolved.connector !== declarations.connector ||
    resolved.stream !== upload.stream
  )
    throw new Error("upload_identity_invalid");
  const stream = streams[0]!;
  const target = Object.freeze({
    ...resolved,
    primaryKey: Object.freeze([...stream.primaryKey]),
    semantics: stream.semantics,
    incremental: stream.incremental !== false,
  });
  const identity = {
    owner: options.owner.toLowerCase(),
    network: options.network,
    installId: upload.source,
    artifactDigest: upload.artifactDigest,
    stream: upload.stream,
    revision: upload.revision,
    target,
  };
  const seal = canonicalJson(identity);
  // Reject a symlinked existing ancestor before recursive mkdir can follow it.
  let ancestor = resolve(options.stagingRoot);
  for (;;) {
    try {
      if ((await realpath(ancestor)) !== ancestor)
        throw new Error("upload_path_refused");
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = resolve(ancestor, "..");
      if (parent === ancestor) throw error;
      ancestor = parent;
    }
  }
  await mkdir(options.stagingRoot, { recursive: true });
  const root = await realpath(options.stagingRoot);
  if (root !== resolve(options.stagingRoot))
    throw new Error("upload_path_refused");
  const key = createHash("sha256")
    .update(
      canonicalJson([
        identity.owner,
        identity.network,
        identity.installId,
        identity.artifactDigest,
        identity.stream,
        identity.revision,
      ]),
    )
    .digest("hex");
  return {
    root,
    data: join(root, `${key}.ndjson`),
    sealPath: join(root, `${key}.seal.json`),
    seal,
    target,
    connector: declarations.connector,
    revision: identity.revision,
    owner: identity.owner,
    network: identity.network,
    installId: identity.installId,
  };
}
async function sealedSource(
  options: UploadOptions,
  context: Awaited<ReturnType<typeof uploadContext>>,
): Promise<ImportSource> {
  const checkSeal = async () => {
    const file = await open(
      context.sealPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    try {
      const stat = await file.stat();
      if (
        stat.size !== Buffer.byteLength(context.seal) ||
        (await file.readFile("utf8")) !== context.seal
      )
        throw new Error("upload_identity_changed");
    } finally {
      await file.close();
    }
  };
  await checkSeal();
  if ((await fileHash(context.data)) !== context.revision)
    throw new Error("source_changed");
  return {
    source: JSON.stringify([
      context.installId,
      context.connector,
      context.revision,
    ]),
    owner: context.owner,
    network: context.network,
    revision: context.revision,
    target: context.target,
    exclusions: [],
    async *records() {
      await checkSeal();
      // Validate before yielding as well as at EOF. Consumers must never see
      // a changed sealed file as the start of the claimed revision.
      if ((await fileHash(context.data)) !== context.revision)
        throw new Error("source_changed");
      const file = await open(
        context.data,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      const hash = createHash("sha256");
      try {
        async function* chunks() {
          for await (const chunk of file.createReadStream({
            autoClose: false,
          })) {
            hash.update(chunk);
            yield chunk as Uint8Array;
          }
        }
        for await (const record of decodeRecords(chunks())) yield record;
        if (hash.digest("hex") !== context.revision)
          throw new Error("source_changed");
        await checkSeal();
      } finally {
        await file.close();
      }
    },
  };
}
async function* decodeRecords(
  chunks: AsyncIterable<Uint8Array>,
): AsyncIterable<Record<string, unknown>> {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let pending = "";
  const parse = (line: string) => {
    try {
      const record: unknown = JSON.parse(line);
      if (!record || typeof record !== "object" || Array.isArray(record))
        throw new Error();
      return record as Record<string, unknown>;
    } catch {
      throw new Error("invalid_record");
    }
  };
  try {
    for await (const chunk of chunks) {
      pending += decoder.decode(chunk, { stream: true });
      let newline: number;
      while ((newline = pending.indexOf("\n")) !== -1) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        yield parse(line);
      }
    }
    pending += decoder.decode();
    if (pending) yield parse(pending);
  } catch (error) {
    if (error instanceof TypeError) throw new Error("invalid_record");
    throw error;
  }
}
async function fileHash(path: string) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const hash = createHash("sha256");
    const bytes = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const { bytesRead } = await file.read(bytes, 0, bytes.length, null);
      if (!bytesRead) break;
      hash.update(bytes.subarray(0, bytesRead));
    }
    return hash.digest("hex");
  } finally {
    await file.close();
  }
}
async function removeTemporary(path: string) {
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
