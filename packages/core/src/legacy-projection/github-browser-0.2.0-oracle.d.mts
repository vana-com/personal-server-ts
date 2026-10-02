export interface GithubBrowserOracleContext {
  emit(message: { type: string; [key: string]: unknown }): Promise<void>;
  emitRecord(stream: string, record: Record<string, unknown>): Promise<void>;
  progress(message: string): Promise<void>;
  requested: ReadonlySet<string>;
  state: Record<string, unknown>;
}

export interface GithubBrowserOracleServices {
  fetchPublicJson(url: string): Promise<unknown>;
  now(): Date;
  openPage(url: string): Promise<string>;
  sleep(ms: number): Promise<void>;
}

export function collectGitHubBrowser(
  context: GithubBrowserOracleContext,
  services: GithubBrowserOracleServices,
): Promise<void>;
