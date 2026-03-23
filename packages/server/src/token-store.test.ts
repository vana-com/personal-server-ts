import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTokenStore } from "./token-store.js";
import pino from "pino";

const logger = pino({ level: "silent" });

describe("createTokenStore", () => {
  let tempDir: string;
  let tokensPath: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "token-store-test-"));
    tokensPath = join(tempDir, "tokens.json");
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("starts with no tokens when file does not exist", async () => {
    const store = createTokenStore(tokensPath, logger);
    expect(await store.getTokens()).toEqual([]);
  });

  it("adds a token and persists to disk", async () => {
    const store = createTokenStore(tokensPath, logger);
    await store.addToken("vana_ps_abc123");

    expect(await store.isValid("vana_ps_abc123")).toBe(true);
    expect(await store.getTokens()).toEqual(["vana_ps_abc123"]);

    // Verify persisted
    const raw = await readFile(tokensPath, "utf-8");
    const data = JSON.parse(raw);
    expect(data.tokens).toEqual(["vana_ps_abc123"]);
  });

  it("persists expiry metadata when provided", async () => {
    const store = createTokenStore(tokensPath, logger);
    const expiresAt = new Date(Date.now() + 60_000).toISOString();

    await store.addToken("vana_ps_expiring", { expiresAt });

    const raw = await readFile(tokensPath, "utf-8");
    const data = JSON.parse(raw);
    expect(data.tokens).toEqual([{ token: "vana_ps_expiring", expiresAt }]);
  });

  it("supports multiple tokens", async () => {
    const store = createTokenStore(tokensPath, logger);
    await store.addToken("vana_ps_token1");
    await store.addToken("vana_ps_token2");

    expect(await store.isValid("vana_ps_token1")).toBe(true);
    expect(await store.isValid("vana_ps_token2")).toBe(true);
    expect(await store.getTokens()).toHaveLength(2);
  });

  it("removes a token", async () => {
    const store = createTokenStore(tokensPath, logger);
    await store.addToken("vana_ps_token1");
    await store.addToken("vana_ps_token2");

    await store.removeToken("vana_ps_token1");

    expect(await store.isValid("vana_ps_token1")).toBe(false);
    expect(await store.isValid("vana_ps_token2")).toBe(true);
  });

  it("loads tokens from existing file on creation", async () => {
    // Write a file first
    const store1 = createTokenStore(tokensPath, logger);
    await store1.addToken("vana_ps_persisted");

    // Create new store pointing at same file
    const store2 = createTokenStore(tokensPath, logger);
    // Need to wait for async load
    await store2.addToken("vana_ps_new"); // triggers await ready

    expect(await store2.isValid("vana_ps_persisted")).toBe(true);
    expect(await store2.isValid("vana_ps_new")).toBe(true);
  });

  it("returns false for invalid tokens", async () => {
    const store = createTokenStore(tokensPath, logger);
    expect(await store.isValid("nonexistent")).toBe(false);
    expect(await store.isValid("")).toBe(false);
  });

  it("does not treat expired tokens as valid", async () => {
    const store = createTokenStore(tokensPath, logger);
    const expiresAt = new Date(Date.now() - 60_000).toISOString();

    await store.addToken("vana_ps_expired", { expiresAt });

    expect(await store.isValid("vana_ps_expired")).toBe(false);
    expect(await store.getTokens()).toEqual([]);
  });
});
