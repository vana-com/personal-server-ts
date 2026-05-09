export interface HierarchyManagerOptions {
  dataDir: string;
}

export interface WriteResult {
  path: string;
  relativePath: string;
  sizeBytes: number;
}
