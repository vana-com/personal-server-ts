export interface SyncCursor {
  /** Read the lastProcessedTimestamp from cursor state. */
  read(): Promise<string | null>;

  /** Write the lastProcessedTimestamp to cursor state. */
  write(timestamp: string): Promise<void>;
}

export interface SyncCursorOptions {
  legacyConfigPath?: string;
}
