export type ContentKind =
  "vana-envelope" | "json" | "zip" | "text" | "binary" | "unsupported";

export interface DataBlockManifest {
  version: 1;
  scope: string;
  collectedAt: string;
  schemaId?: string;
  contentKind: ContentKind;
  rawSizeBytes?: number;
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
   * `blockRef`. When set, `cursor` is ignored and no `nextCursor` is returned;
   * `maxBytes` still bounds the response.
   */
  blockIds?: string[];
}

export interface ReadScopeBlocksResponse {
  scope: string;
  collectedAt: string;
  schemaId?: string;
  contentKind: ContentKind;
  blocks: DataScopeBlock[];
  nextCursor?: string;
  warnings: DataBlockWarning[];
}

export interface DataScopeBlock {
  id: string;
  path: string;
  mediaType: string;
  value: unknown;
  sizeBytes: number;
  truncated?: boolean;
}
