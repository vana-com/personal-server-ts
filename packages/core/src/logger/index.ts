import type { LoggingConfig } from "../schemas/server-config.js";

export interface Logger {
  debug(payloadOrMessage?: unknown, message?: string): void;
  info(payloadOrMessage?: unknown, message?: string): void;
  warn(payloadOrMessage?: unknown, message?: string): void;
  error(payloadOrMessage?: unknown, message?: string): void;
}

export function createLogger(config: LoggingConfig): Logger {
  void config;
  return console;
}
