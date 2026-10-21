export type ContentKind =
  "vana-envelope" | "json" | "zip" | "text" | "binary" | "unsupported";

export interface DataBlockManifest {
  version: 1;
  scope: string;
  collectedAt: string;
  schemaId?: string;
  contentKind: ContentKind;
  rawSizeBytes?: number;
  /**
   * Whether the envelope these blocks were built from has PDPP origin (see
   * `hasPdppOrigin`). Absent on manifests written before this field.
   */
  pdppOrigin?: boolean;
  /**
   * The generation (`envelopeGeneration`) of the envelope these blocks were
   * built from. With a `digest` on every block, it binds the sidecar to one
   * published version. Absent on manifests written before this field.
   */
  envelopeDigest?: string;
  /** Redaction evidence from the envelope that generated this sidecar. */
  redaction?: { dropTopLevelLineage: boolean; dropMetadataLineage: boolean };
  /** Ordered layout and serialization identity, separate from envelopeDigest. */
  representationId?: string;
  /** Continuation namespace of a read-time projection; not stored envelope identity. */
  cursorView?: string;
  blocks: DataBlockRef[];
  warnings: DataBlockWarning[];
}

export interface DataBlockRef {
  id: string;
  path: string;
  mediaType: string;
  sizeBytes: number;
  itemCount?: number;
  truncated?: boolean;
  /**
   * `canonicalDigest` of the full stored block payload. Storage checks it on
   * every read of the payload, before paging. Absent on old manifests.
   */
  digest?: string;
}

export interface DataBlockWarning {
  code: string;
  message: string;
  fileId?: string;
  path?: string;
}

export interface ReadScopeBlocksRequest {
  scope: string;
  collectedAt?: string;
  cursor?: string;
  maxBytes?: number;
  /**
   * Read only these blocks, in this order, instead of paging the scope from
   * `cursor`. Ids come from a manifest listing or from a search hit's
   * `blockRef`. When set, cursor positions are ignored but version/layout binding is checked; no `nextCursor` is returned;
   * `maxBytes` still bounds the response.
   */
  blockIds?: string[];
}

export interface ReadScopeBlocksResponse {
  scope: string;
  collectedAt: string;
  schemaId?: string;
  contentKind: ContentKind;
  representationId?: string;
  redaction?: { dropTopLevelLineage: boolean; dropMetadataLineage: boolean };
  blocks: DataScopeBlock[];
  nextCursor?: string;
  warnings: DataBlockWarning[];
  /** The manifest's `pdppOrigin`, for the disclosure policy; never served. */
  pdppOrigin?: boolean;
  /**
   * The manifest's `envelopeDigest`, only when every block is bound by a
   * digest and every served block matched it. For the disclosure policy;
   * never served.
   */
  envelopeDigest?: string;
}

export interface DataScopeBlock {
  id: string;
  path: string;
  mediaType: string;
  value: unknown;
  sizeBytes: number;
  truncated?: boolean;
}
