import type { DataStoragePort } from "../../ports/index.js";
import { isBinaryEnvelope } from "../../contracts/binary.js";
import { LINEAGE_KEY } from "../../lineage/lineage.js";

/**
 * Block sidecars are built from the FULL stored envelope, so they carry the
 * server-stamped `$writtenBy` / `$lineage` keys and the consumed caller
 * lineage field that grantee reads of the record itself never see. The same
 * redaction applies here at serve time: dedicated blocks under those paths
 * are dropped, data-level object payloads (`$.data`, grouped-key blocks,
 * `$.data.metadata`) have the keys stripped, and group labels naming a
 * redacted key are rewritten. The caller lineage field follows the envelope
 * path's contract — dropped from the location the write path consumed
 * (top-level `lineage` for JSON, `metadata.lineage` for binary) only when
 * `$lineage` is stamped — which is why redaction reads the envelope for
 * stamped-ness; if that read fails, both locations are dropped (fail
 * closed).
 */
export interface BlockRedactionContext {
  dropTopLevelLineage: boolean;
  dropMetadataLineage: boolean;
}

const FAIL_CLOSED_CONTEXT: BlockRedactionContext = {
  dropTopLevelLineage: true,
  dropMetadataLineage: true,
};

function pathUnder(path: string, prefix: string): boolean {
  return (
    path === prefix ||
    (path.startsWith(prefix) && /[.[{]/.test(path.charAt(prefix.length)))
  );
}

function groupLabelSegments(path: string): string[] {
  const match = /^\$\.data(?:\.metadata)?\.\{(.+):(.+)\}$/.exec(path);
  return match ? [match[1]!, match[2]!] : [];
}

/**
 * Whether the served blocks carry anything the caller-lineage rule could
 * apply to. When they don't (the overwhelmingly common case — ordinary
 * content blocks), no stamped-ness decision is needed and the envelope is
 * never read, keeping bounded reads bounded.
 */
function servedLineageShaped(
  blocks: readonly { path: string; value?: unknown }[],
): boolean {
  return blocks.some((block) => {
    if (
      pathUnder(block.path, "$.data.lineage") ||
      pathUnder(block.path, "$.data.metadata.lineage")
    ) {
      return true;
    }
    if (
      groupLabelSegments(block.path).some(
        (segment) => segment === "lineage" || segment === LINEAGE_KEY,
      )
    ) {
      return true;
    }
    if (!("value" in block) || !isPlainObject(block.value)) return false;
    const data =
      block.path === "$" ? (block.value["data"] ?? null) : block.value;
    return (
      isPlainObject(data) &&
      ("lineage" in data ||
        (isPlainObject(data["metadata"]) && "lineage" in data["metadata"]))
    );
  });
}

/**
 * Stamped-ness evidence visible in the served blocks themselves: a
 * `$.data.$lineage` path (dedicated block or manifest ref) or a `$lineage`
 * key inside a data-level payload. Both occur only on JSON records — the
 * binary block emitter never serializes the stamped keys — so visible
 * evidence always means "JSON record, drop the top-level field".
 */
function visibleStampEvidence(
  blocks: readonly { path: string; value?: unknown }[],
): BlockRedactionContext | null {
  for (const block of blocks) {
    if (
      pathUnder(block.path, `$.data.${LINEAGE_KEY}`) ||
      groupLabelSegments(block.path).includes(LINEAGE_KEY)
    ) {
      return { dropTopLevelLineage: true, dropMetadataLineage: false };
    }
    if ("value" in block && isPlainObject(block.value)) {
      const data =
        block.path === "$" ? (block.value["data"] ?? null) : block.value;
      if (isPlainObject(data) && LINEAGE_KEY in data) {
        return { dropTopLevelLineage: true, dropMetadataLineage: false };
      }
    }
  }
  return null;
}

/**
 * The caller-lineage decision for a set of served blocks or manifest refs.
 * Decided from the blocks themselves when possible; the stored envelope is
 * read only when lineage-shaped content is present without visible
 * stamped-ness evidence (a pagination or blockIds slice), and an unreadable
 * envelope redacts both locations rather than serving them.
 */
export async function resolveBlockRedactionContext(
  storage: Pick<DataStoragePort, "readEnvelope">,
  scope: string,
  collectedAt: string,
  blocks: readonly { path: string; value?: unknown }[],
): Promise<BlockRedactionContext> {
  if (!servedLineageShaped(blocks)) {
    return { dropTopLevelLineage: false, dropMetadataLineage: false };
  }
  const visible = visibleStampEvidence(blocks);
  if (visible) return visible;
  try {
    const envelope = await storage.readEnvelope(scope, collectedAt);
    if (!(LINEAGE_KEY in envelope.data)) {
      return { dropTopLevelLineage: false, dropMetadataLineage: false };
    }
    return isBinaryEnvelope(envelope)
      ? { dropTopLevelLineage: false, dropMetadataLineage: true }
      : { dropTopLevelLineage: true, dropMetadataLineage: false };
  } catch {
    return FAIL_CLOSED_CONTEXT;
  }
}

function redactedBlockPathPrefixes(ctx: BlockRedactionContext): string[] {
  return [
    "$.data.$writtenBy",
    "$.data.$lineage",
    ...(ctx.dropTopLevelLineage ? ["$.data.lineage"] : []),
    ...(ctx.dropMetadataLineage ? ["$.data.metadata.lineage"] : []),
  ];
}

function isRedactedBlockPath(
  path: string,
  ctx: BlockRedactionContext,
): boolean {
  return redactedBlockPathPrefixes(ctx).some(
    (prefix) =>
      path === prefix ||
      (path.startsWith(prefix) && /[.[{]/.test(path.charAt(prefix.length))),
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isRedactedKeyName(
  parent: "data" | "metadata",
  key: string,
  ctx: BlockRedactionContext,
): boolean {
  if (parent === "data") {
    return (
      key === "$writtenBy" ||
      key === "$lineage" ||
      (ctx.dropTopLevelLineage && key === "lineage")
    );
  }
  return ctx.dropMetadataLineage && key === "lineage";
}

/**
 * Group blocks are labeled `<parent>.{first:last}` after the first and last
 * key they pack; a redacted key name in the label is rewritten so not even
 * the key's existence is served.
 */
function sanitizeGroupLabel(path: string, ctx: BlockRedactionContext): string {
  const match = /^(\$\.data(?:\.metadata)?)\.\{(.+):(.+)\}$/.exec(path);
  if (!match) return path;
  const parent = match[1] === "$.data" ? "data" : "metadata";
  const first = isRedactedKeyName(parent, match[2]!, ctx) ? "…" : match[2]!;
  const last = isRedactedKeyName(parent, match[3]!, ctx) ? "…" : match[3]!;
  return `${match[1]}.{${first}:${last}}`;
}

function stripMetadataLineage(
  value: Record<string, unknown>,
  ctx: BlockRedactionContext,
): Record<string, unknown> {
  if (!ctx.dropMetadataLineage || !isPlainObject(value["metadata"])) {
    return value;
  }
  const { lineage: _metadataLineage, ...metadataRest } = value["metadata"];
  if (Object.keys(metadataRest).length === 0) {
    const { metadata: _emptied, ...rest } = value;
    return rest;
  }
  return { ...value, metadata: metadataRest };
}

function stripDataLevelKeys(
  value: Record<string, unknown>,
  ctx: BlockRedactionContext,
): Record<string, unknown> {
  const { $writtenBy: _writtenBy, $lineage: _lineage, ...rest } = value;
  let data: Record<string, unknown> = rest;
  if (ctx.dropTopLevelLineage) {
    const { lineage: _callerLineage, ...dataRest } = data;
    data = dataRest;
  }
  return stripMetadataLineage(data, ctx);
}

function redactBlockValue(
  path: string,
  value: unknown,
  ctx: BlockRedactionContext,
): unknown {
  if (!isPlainObject(value)) return value;
  if (path === "$.data" || /^\$\.data\.\{.*\}$/.test(path)) {
    return stripDataLevelKeys(value, ctx);
  }
  if (path === "$.data.metadata" || /^\$\.data\.metadata\.\{.*\}$/.test(path)) {
    if (!ctx.dropMetadataLineage) return value;
    const { lineage: _metadataLineage, ...rest } = value;
    return rest;
  }
  if (path === "$" && isPlainObject(value["data"])) {
    return { ...value, data: stripDataLevelKeys(value["data"], ctx) };
  }
  return value;
}

export function redactBlockRefsForGrantee<T extends { path: string }>(
  blocks: T[],
  ctx: BlockRedactionContext,
): T[] {
  return blocks
    .filter((block) => !isRedactedBlockPath(block.path, ctx))
    .map((block) => ({ ...block, path: sanitizeGroupLabel(block.path, ctx) }));
}

export function redactBlockPayloadsForGrantee<
  T extends { path: string; value: unknown },
>(blocks: T[], ctx: BlockRedactionContext): T[] {
  return blocks
    .filter((block) => !isRedactedBlockPath(block.path, ctx))
    .flatMap((block) => {
      const value = redactBlockValue(block.path, block.value, ctx);
      // A group emptied by the strip carried only redacted keys.
      if (
        isPlainObject(block.value) &&
        Object.keys(block.value).length > 0 &&
        isPlainObject(value) &&
        Object.keys(value).length === 0
      ) {
        return [];
      }
      return [{ ...block, path: sanitizeGroupLabel(block.path, ctx), value }];
    });
}

/** Captured from the same envelope used to build the sidecar. */
export function blockRedactionContext(content: unknown): BlockRedactionContext {
  if (
    !isPlainObject(content) ||
    !isPlainObject(content.data) ||
    !(LINEAGE_KEY in content.data)
  ) {
    return { dropTopLevelLineage: false, dropMetadataLineage: false };
  }
  return isBinaryEnvelope(content as never)
    ? { dropTopLevelLineage: false, dropMetadataLineage: true }
    : { dropTopLevelLineage: true, dropMetadataLineage: false };
}
