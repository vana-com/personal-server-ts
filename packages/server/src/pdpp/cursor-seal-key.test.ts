import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cursorSealKeyFor } from "./records-bootstrap.js";

/** The persisted key that seals RS cursors (spec-core §4; RS item 21). */
describe("cursorSealKeyFor", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });
  function setup() {
    const dir = mkdtempSync(join(tmpdir(), "pdpp-seal-key-"));
    dirs.push(dir);
    const name = join(dir, "index.db");
    const logger = { warn: vi.fn() };
    return { name, file: `${name}.pdpp-cursor-key`, logger, db: { name } };
  }

  it("creates an owner-only 32-byte key once and reuses it", () => {
    const { db, file, logger } = setup();
    const first = cursorSealKeyFor(db, logger);
    expect(first.byteLength).toBe(32);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(Buffer.from(cursorSealKeyFor(db, logger))).toEqual(Buffer.from(first));
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("replaces a wrong-length file once, so the next boot reads the same key", () => {
    const { db, file, logger } = setup();
    writeFileSync(file, Buffer.alloc(7), { mode: 0o600 });
    const replaced = cursorSealKeyFor(db, logger);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(readFileSync(file)).toEqual(Buffer.from(replaced));
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(Buffer.from(cursorSealKeyFor(db, logger))).toEqual(Buffer.from(replaced));
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });

  it("repairs a group- or world-readable file to 0600 and logs it", () => {
    const { db, file, logger } = setup();
    const key = Buffer.alloc(32, 9);
    writeFileSync(file, key);
    chmodSync(file, 0o644);
    expect(Buffer.from(cursorSealKeyFor(db, logger))).toEqual(key);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(logger.warn).toHaveBeenCalledWith(
      { file },
      expect.stringMatching(/readable by others/),
    );
  });

  it("draws a fresh key for an in-memory database", () => {
    const logger = { warn: vi.fn() };
    const a = cursorSealKeyFor({ name: ":memory:" }, logger);
    const b = cursorSealKeyFor({ name: ":memory:" }, logger);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });
});
