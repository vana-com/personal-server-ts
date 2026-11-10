import { createHash } from "node:crypto";
import type {
  LocalSync,
  ConnectionLink,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { PdppTokenContext } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  resolveReadScope,
  recordKeyWithinGrantResources,
  recordWithinGrantTimeConstraint,
  type StreamDeclarationRegistry,
  type PdppStoredRecord,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { BlobReadStore } from "../routes/pdpp-blobs.js";

/** Prepare only authorized references; the route still enforces its normal blob policy. */
export async function grantBlobStore(input: {
  local: LocalSync;
  link: ConnectionLink;
  context: PdppTokenContext;
  blobId: string;
  declarations: StreamDeclarationRegistry;
  ownerInstances: string[];
}): Promise<BlobReadStore> {
  const { local, link, context, blobId, declarations } = input;
  const query = local.recordsFor(link);
  const rows: PdppStoredRecord[] = [];
  const streams =
    context.tokenKind === "owner"
      ? declarations.list().map((d) => d.name)
      : (context.grant?.streams ?? []).map((s) => s.name);
  for (const stream of new Set(streams)) {
    const declaration = declarations.get(
      stream,
      context.sourceId ?? context.grant?.source.id,
    );
    let scope;
    try {
      scope = resolveReadScope(context, stream, declaration);
    } catch {
      continue;
    }
    if (context.tokenKind !== "owner" && !scope.fields?.includes("blob_ref"))
      continue;
    const instances =
      context.tokenKind === "owner"
        ? input.ownerInstances.filter(
            (i) => !context.instanceIds || context.instanceIds.includes(i),
          )
        : scope.instanceIds;
    for (const instance of instances) {
      for await (const row of query.streamRecords(instance, stream)) {
        const data = JSON.parse(row.body) as Record<string, unknown>;
        const ref = data.blob_ref;
        if (
          !ref ||
          typeof ref !== "object" ||
          !("blob_id" in ref) ||
          ref.blob_id !== blobId
        )
          continue;
        if (
          !recordKeyWithinGrantResources(row.recordKey, scope.streamGrant) ||
          !recordWithinGrantTimeConstraint(data, scope.streamGrant)
        )
          continue;
        rows.push({
          instance,
          stream,
          recordKey: row.recordKey,
          data,
          emittedAt: new Date(row.emittedAt).toISOString(),
          version: 1,
          deleted: false,
        });
      }
    }
  }
  const hash = blobId.startsWith("sha256:") ? blobId.slice(7) : blobId;
  const blob =
    rows.length && /^[0-9a-f]{64}$/.test(hash)
      ? await local.blobs.get(hash)
      : null;
  const available = () =>
    rows.some((row) => link(row.instance, row.stream) !== null);
  return {
    getBlobMeta: () =>
      blob && available()
        ? {
            blobId,
            mimeType: blob.mimeType,
            sizeBytes: blob.bytes.byteLength,
            sha256: createHash("sha256").update(blob.bytes).digest("hex"),
          }
        : undefined,
    getBlobBytes: () => (blob && available() ? blob.bytes : undefined),
    findBlobReferences: () =>
      rows
        .filter((r) => link(r.instance, r.stream) !== null)
        .map(({ instance, stream, recordKey }) => ({
          instance,
          stream,
          recordKey,
        })),
    getRecord: (instance, stream, key) =>
      rows.find(
        (r) =>
          r.instance === instance &&
          r.stream === stream &&
          r.recordKey === key &&
          link(instance, stream) !== null,
      ),
    async validate() {
      for (const row of rows) {
        const current = await query.getRecord({
          connectionId: row.instance,
          stream: row.stream,
          recordKey: row.recordKey,
        });
        if (current && current.body === JSON.stringify(row.data)) return true;
      }
      return false;
    },
  };
}
