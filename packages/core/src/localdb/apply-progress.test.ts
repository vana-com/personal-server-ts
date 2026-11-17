import { expect, it } from "vitest";
import { announceApplied, nextApplied } from "./apply-progress.js";
import type { SqlDriver } from "./driver.js";

it("wakes an early reader when the metered apply wraps the same database", async () => {
  const db: SqlDriver = {
    info: { host: "web", persistent: true, sqliteVersion: "3.54.1" },
    query: async () => [],
    batch: async () => ({ changes: [] }),
    close: async () => {},
  };
  const reader = { db };
  const apply = { db: new Proxy(db, {}) };
  let woke = false;
  void nextApplied(reader, "connection").then(() => {
    woke = true;
  });
  announceApplied(apply, "connection");
  await Promise.resolve();
  expect(woke).toBe(true);
});
