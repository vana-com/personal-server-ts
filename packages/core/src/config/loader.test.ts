import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { access, mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { loadConfig } from "./loader.js";
import { DEFAULTS } from "../schemas/server-config.js";

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "config-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true });
  }
}

describe("loadConfig", () => {
  it("returns defaults when file is missing", async () => {
    const config = await loadConfig({
      configPath: "/tmp/nonexistent-config-path/config.json",
    });

    expect(config.server.port).toBe(8080);
    expect(config.gateway.url).toBe(
      "https://data-gateway-env-dev-opendatalabs.vercel.app",
    );
    expect(config.logging.level).toBe("info");
    expect(config.logging.pretty).toBe(false);
    expect(config.storage.backend).toBe("local");
  });

  it("parses valid config", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      await writeFile(
        configPath,
        JSON.stringify({
          server: { port: 3000 },
          logging: { level: "debug", pretty: true },
          storage: { backend: "vana" },
        }),
      );

      const config = await loadConfig({ configPath });

      expect(config.server.port).toBe(3000);
      expect(config.logging.level).toBe("debug");
      expect(config.logging.pretty).toBe(true);
      expect(config.storage.backend).toBe("vana");
    });
  });

  it("merges partial config with defaults", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      await writeFile(
        configPath,
        JSON.stringify({
          server: { port: 9090 },
        }),
      );

      const config = await loadConfig({ configPath });

      expect(config.server.port).toBe(9090);
      // Defaults fill in the rest
      expect(config.gateway.url).toBe(
        "https://data-gateway-env-dev-opendatalabs.vercel.app",
      );
      expect(config.logging.level).toBe("info");
      expect(config.storage.backend).toBe("local");
    });
  });

  // BUI-539: an existing install's persisted config.json carries a full gateway
  // block (incl. contracts). When the bundled defaults move (DPv1→DPv2 contract
  // flip) the stale persisted contracts must be overwritten, or EIP-712 signing
  // keeps using the V1 verifyingContract and the gateway 401s on upload.
  describe("gateway reconcile", () => {
    it("overwrites stale persisted gateway contracts with current defaults", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(
          configPath,
          JSON.stringify({
            gateway: {
              url: "https://gateway.v1.example",
              chainId: 999,
              contracts: {
                dataRegistry: "0xV1dataRegistry",
                dataPortabilityPermissions: "0xV1permissions",
                dataPortabilityServer: "0xV1server",
                dataPortabilityGrantees: "0xV1grantees",
              },
            },
          }),
        );

        const config = await loadConfig({ configPath });

        // Every gateway field follows the current defaults, not the stale file.
        expect(config.gateway.url).toBe(DEFAULTS.gateway.url);
        expect(config.gateway.chainId).toBe(DEFAULTS.gateway.chainId);
        expect(config.gateway.contracts).toEqual(DEFAULTS.gateway.contracts);
      });
    });

    it("preserves unrelated user config while reconciling the gateway", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(
          configPath,
          JSON.stringify({
            server: { port: 7777, origin: "https://my-node.example" },
            storage: { backend: "vana" },
            sync: {
              enabled: true,
              lastProcessedTimestamp: "2026-01-01T00:00:00.000Z",
            },
            gateway: {
              contracts: { dataPortabilityServer: "0xStaleV1server" },
            },
          }),
        );

        const config = await loadConfig({ configPath });

        // Gateway reconciled to defaults...
        expect(config.gateway.contracts.dataPortabilityServer).toBe(
          DEFAULTS.gateway.contracts.dataPortabilityServer,
        );
        // ...but unrelated user/instance config is untouched.
        expect(config.server.port).toBe(7777);
        expect(config.server.origin).toBe("https://my-node.example");
        expect(config.storage.backend).toBe("vana");
        expect(config.sync.enabled).toBe(true);
        expect(config.sync.lastProcessedTimestamp).toBe(
          "2026-01-01T00:00:00.000Z",
        );
      });
    });

    it("re-persists the reconciled gateway block to disk", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(
          configPath,
          JSON.stringify({
            server: { port: 7777 },
            gateway: {
              contracts: { dataPortabilityServer: "0xStaleV1server" },
            },
          }),
        );

        await loadConfig({ configPath });

        const onDisk = JSON.parse(await readFile(configPath, "utf-8"));
        expect(onDisk.gateway.contracts.dataPortabilityServer).toBe(
          DEFAULTS.gateway.contracts.dataPortabilityServer,
        );
        // Unrelated value still on disk.
        expect(onDisk.server.port).toBe(7777);
      });
    });
  });

  it("throws ZodError for invalid config", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      await writeFile(
        configPath,
        JSON.stringify({
          server: { port: -1 },
        }),
      );

      await expect(loadConfig({ configPath })).rejects.toThrow();
    });
  });

  it("throws for malformed JSON", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      await writeFile(configPath, "{ invalid json }}}");

      await expect(loadConfig({ configPath })).rejects.toThrow(SyntaxError);
    });
  });

  it("writes defaults to disk when file is missing", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "subdir", "config.json");
      await loadConfig({ configPath });

      // File should now exist with defaults
      await expect(access(configPath)).resolves.toBeUndefined();
      const contents = JSON.parse(await readFile(configPath, "utf-8"));
      expect(contents.server.port).toBe(8080);
      expect(contents.gateway.url).toBe(
        "https://data-gateway-env-dev-opendatalabs.vercel.app",
      );
    });
  });

  it("writes missing defaults back to existing partial file", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");
      await writeFile(configPath, JSON.stringify({ server: { port: 9090 } }));

      await loadConfig({ configPath });

      const onDisk = JSON.parse(await readFile(configPath, "utf-8"));
      // User's value preserved
      expect(onDisk.server.port).toBe(9090);
      // Defaults filled in
      expect(onDisk.gateway.url).toBe(
        "https://data-gateway-env-dev-opendatalabs.vercel.app",
      );
      expect(onDisk.logging.level).toBe("info");
      expect(onDisk.storage.backend).toBe("local");
    });
  });

  it("does not rewrite file when config already has all defaults", async () => {
    await withTempDir(async (dir) => {
      const configPath = join(dir, "config.json");

      // First load writes defaults
      await loadConfig({ configPath });
      const firstWrite = await readFile(configPath, "utf-8");

      // Second load should not rewrite (content identical)
      await loadConfig({ configPath });
      const secondRead = await readFile(configPath, "utf-8");

      expect(secondRead).toBe(firstWrite);
    });
  });

  it("accepts custom configPath", async () => {
    await withTempDir(async (dir) => {
      const customPath = join(dir, "custom-config.json");
      await writeFile(
        customPath,
        JSON.stringify({
          logging: { level: "warn" },
        }),
      );

      const config = await loadConfig({ configPath: customPath });

      expect(config.logging.level).toBe("warn");
      expect(config.server.port).toBe(8080);
    });
  });

  it("uses rootPath when configPath is not provided", async () => {
    await withTempDir(async (dir) => {
      const rootPath = join(dir, "personal-server-root");
      const config = await loadConfig({ rootPath });

      expect(config.server.port).toBe(8080);

      const configPath = join(rootPath, "config.json");
      await expect(access(configPath)).resolves.toBeUndefined();
      const onDisk = JSON.parse(await readFile(configPath, "utf-8"));
      expect(onDisk.server.port).toBe(8080);
    });
  });

  describe("env var overrides", () => {
    function withEnv(
      vars: Record<string, string>,
      fn: () => Promise<void>,
    ): Promise<void> {
      const originals: Record<string, string | undefined> = {};
      for (const key of Object.keys(vars)) {
        originals[key] = process.env[key];
        process.env[key] = vars[key];
      }
      return fn().finally(() => {
        for (const [key, val] of Object.entries(originals)) {
          if (val === undefined) delete process.env[key];
          else process.env[key] = val;
        }
      });
    }

    it("SERVER_PORT overrides config file value", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(configPath, JSON.stringify({ server: { port: 3000 } }));

        await withEnv({ CLOUD_MODE: "true", SERVER_PORT: "9999" }, async () => {
          const config = await loadConfig({ configPath });
          expect(config.server.port).toBe(9999);
        });
      });
    });

    it("SERVER_ORIGIN overrides default", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(configPath, JSON.stringify({}));

        await withEnv(
          { CLOUD_MODE: "true", SERVER_ORIGIN: "https://ps.example.com" },
          async () => {
            const config = await loadConfig({ configPath });
            expect(config.server.origin).toBe("https://ps.example.com");
          },
        );
      });
    });

    it("TUNNEL_ENABLED overrides default", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(configPath, JSON.stringify({}));

        await withEnv(
          { CLOUD_MODE: "true", TUNNEL_ENABLED: "false" },
          async () => {
            const config = await loadConfig({ configPath });
            expect(config.tunnel.enabled).toBe(false);
          },
        );
      });
    });

    it("DEV_UI_ENABLED overrides default", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(configPath, JSON.stringify({}));

        await withEnv(
          { CLOUD_MODE: "true", DEV_UI_ENABLED: "false" },
          async () => {
            const config = await loadConfig({ configPath });
            expect(config.devUi.enabled).toBe(false);
          },
        );
      });
    });

    it("ignores env vars when CLOUD_MODE is not set", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(configPath, JSON.stringify({ server: { port: 3000 } }));

        await withEnv({ SERVER_PORT: "9999" }, async () => {
          const config = await loadConfig({ configPath });
          expect(config.server.port).toBe(3000);
        });
      });
    });

    it("env vars override config file values", async () => {
      await withTempDir(async (dir) => {
        const configPath = join(dir, "config.json");
        await writeFile(
          configPath,
          JSON.stringify({
            server: { port: 3000 },
            tunnel: { enabled: true },
            devUi: { enabled: true },
          }),
        );

        await withEnv(
          {
            CLOUD_MODE: "true",
            SERVER_PORT: "4000",
            SERVER_ORIGIN: "https://cloud.example.com",
            TUNNEL_ENABLED: "false",
            DEV_UI_ENABLED: "false",
          },
          async () => {
            const config = await loadConfig({ configPath });
            expect(config.server.port).toBe(4000);
            expect(config.server.origin).toBe("https://cloud.example.com");
            expect(config.tunnel.enabled).toBe(false);
            expect(config.devUi.enabled).toBe(false);
          },
        );
      });
    });
  });

  it("prefers configPath over rootPath when both are provided", async () => {
    await withTempDir(async (dir) => {
      const rootPath = join(dir, "root-a");
      const configPath = join(dir, "root-b", "config.json");

      const config = await loadConfig({ rootPath, configPath });
      expect(config.server.port).toBe(8080);

      await expect(access(configPath)).resolves.toBeUndefined();
      await expect(access(join(rootPath, "config.json"))).rejects.toThrow();
    });
  });
});
