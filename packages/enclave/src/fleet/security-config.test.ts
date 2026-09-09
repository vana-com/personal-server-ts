import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { expect, it, vi } from "vitest";
import {
  verifiedFleetEnvironment,
  canonicalFleetConfigPayload,
  isVerifiedFleetEnvironment,
  type FleetSecurityConfigPayload,
} from "./security-config.js";

const now = Date.parse("2026-09-09T04:00:00.000Z");
const keys = generateKeyPairSync("ed25519");
const publicKey = keys.publicKey
  .export({ format: "der", type: "spki" })
  .toString("base64");
function payload(): FleetSecurityConfigPayload {
  return {
    version: 1,
    purpose: "vana.fleet.security-config",
    role: "controller",
    appId: "controller-app",
    instanceId: "controller-instance",
    nodeId: "controller-1",
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 4 * 60 * 60 * 1000).toISOString(),
    env: {
      CHAIN_ID: "14800",
      NODE_ID: "controller-1",
      CONTROLLER_TERM: "1",
      GATEWAY_URL: "https://gateway.invalid",
      FLEET_STATE_PATH: "/fleet-state/placements.json",
      FLEET_WORKERS_JSON: "[]",
      FLEET_GATEWAY_TOKEN: "g".repeat(32),
      FLEET_CONTROLLER_GATEWAY_TOKEN: "r".repeat(32),
      FLEET_CONTROLLER_ADMIN_TOKEN: "a".repeat(32),
      MCP_PUBLIC_ORIGIN: "https://mcp.invalid",
      MCP_APPROVAL_URL: "https://approve.invalid",
      MCP_STATE_PATH: "/mcp-state/state.sealed",
      MCP_REDIRECT_URIS: '["https://client.invalid/callback"]',
      MCP_MIGRATION_REQUIRED: "1",
    },
  };
}
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, item]) => [key, canonical(item)]),
    );
  return value;
}
function wire(document: string): string {
  return `base64:${Buffer.from(document).toString("base64")}`;
}
function bundle(body: FleetSecurityConfigPayload) {
  const bytes = Buffer.from(
    "vana.fleet.security-config.v1\0" + JSON.stringify(canonical(body)),
  );
  return wire(
    JSON.stringify({
      payload: body,
      signature: sign(null, bytes, keys.privateKey).toString("base64"),
    }),
  );
}
it("authenticates an instance-bound complete config without inheriting host overrides", async () => {
  const body = payload();
  const identity = vi.fn(async () => ({
    appId: body.appId,
    instanceId: body.instanceId,
  }));
  const env = await verifiedFleetEnvironment(
    {
      FLEET_CONFIG_PUBLIC_KEY: publicKey,
      FLEET_SIGNED_CONFIG: bundle(body),
      FLEET_CONTROLLER_ADMIN_TOKEN: "attacker",
      FLEET_WORKERS_JSON: '["attacker"]',
      NODE_OPTIONS: "--import /attacker.js",
    },
    { role: "controller", identity, now: () => now },
  );
  expect(env).toEqual(body.env);
  expect(Object.isFrozen(env)).toBe(true);
  expect(isVerifiedFleetEnvironment(env)).toBe(true);
  expect(isVerifiedFleetEnvironment({ ...env })).toBe(false);
  expect(identity).toHaveBeenCalledOnce();
});
it("rejects forged policy/admin replacement before reading public identity or releasing config", async () => {
  const original = payload();
  const signed = JSON.parse(
    Buffer.from(bundle(original).slice(7), "base64").toString("utf8"),
  );
  signed.payload.env.FLEET_WORKERS_JSON =
    '[{"url":"https://attacker.invalid"}]';
  signed.payload.env.FLEET_CONTROLLER_ADMIN_TOKEN = "attacker-knows-this";
  const identity = vi.fn();
  await expect(
    verifiedFleetEnvironment(
      {
        FLEET_CONFIG_PUBLIC_KEY: publicKey,
        FLEET_SIGNED_CONFIG: wire(JSON.stringify(signed)),
      },
      { role: "controller", identity, now: () => now },
    ),
  ).rejects.toThrow("Invalid fleet security configuration");
  expect(identity).not.toHaveBeenCalled();
});
it("binds signed bundles to role, node, app and instance", async () => {
  const body = payload();
  const raw = {
    FLEET_CONFIG_PUBLIC_KEY: publicKey,
    FLEET_SIGNED_CONFIG: bundle(body),
  };
  const identity = vi.fn(async () => ({
    appId: body.appId,
    instanceId: body.instanceId,
  }));
  await expect(
    verifiedFleetEnvironment(raw, { role: "worker", identity, now: () => now }),
  ).rejects.toThrow();
  expect(identity).not.toHaveBeenCalled();
  for (const actual of [
    { appId: "other-app", instanceId: body.instanceId },
    { appId: body.appId, instanceId: "other-instance" },
  ]) {
    await expect(
      verifiedFleetEnvironment(raw, {
        role: "controller",
        identity: async () => actual,
        now: () => now,
      }),
    ).rejects.toThrow();
  }
  body.env.NODE_ID = "other-node";
  await expect(
    verifiedFleetEnvironment(
      { ...raw, FLEET_SIGNED_CONFIG: bundle(body) },
      {
        role: "controller",
        identity,
        now: () => now,
      },
    ),
  ).rejects.toThrow();
});
it("requires exact version/purpose/fields and forbids boot injection even when signed", async () => {
  const changes = [
    (p: FleetSecurityConfigPayload) => {
      (p as { version: number }).version = 2;
    },
    (p: FleetSecurityConfigPayload) => {
      (p as { purpose: string }).purpose = "other-domain";
    },
    (p: FleetSecurityConfigPayload) => {
      Object.assign(p, { ignoredAuthority: "attacker" });
    },
    (p: FleetSecurityConfigPayload) => {
      p.env.NODE_OPTIONS = "--import attacker";
    },
    (p: FleetSecurityConfigPayload) => {
      p.env.DSTACK_FAKE = "1";
    },
    (p: FleetSecurityConfigPayload) => {
      delete p.env.GATEWAY_URL;
    },
    (p: FleetSecurityConfigPayload) => {
      p.env.CHAIN_ID = "1480";
    },
  ];
  for (const change of changes) {
    const body = payload();
    change(body);
    const identity = vi.fn();
    await expect(
      verifiedFleetEnvironment(
        {
          FLEET_CONFIG_PUBLIC_KEY: publicKey,
          FLEET_SIGNED_CONFIG: bundle(body),
        },
        { role: "controller", identity, now: () => now },
      ),
    ).rejects.toThrow();
    expect(identity).not.toHaveBeenCalled();
  }
});
it("rejects expired, future-issued and excessive validity windows before any identity call", async () => {
  for (const [issued, expires] of [
    [now - 3_600_000, now],
    [now + 60_001, now + 3_600_000],
    [now, now + 86_400_001],
  ]) {
    const body = payload();
    body.issuedAt = new Date(issued!).toISOString();
    body.expiresAt = new Date(expires!).toISOString();
    const identity = vi.fn();
    await expect(
      verifiedFleetEnvironment(
        {
          FLEET_CONFIG_PUBLIC_KEY: publicKey,
          FLEET_SIGNED_CONFIG: bundle(body),
        },
        { role: "controller", identity, now: () => now },
      ),
    ).rejects.toThrow();
    expect(identity).not.toHaveBeenCalled();
  }
});
it("does not release configuration if its validity expires during public identity lookup", async () => {
  const body = payload();
  body.expiresAt = new Date(now + 1_000).toISOString();
  let current = now;
  await expect(
    verifiedFleetEnvironment(
      { FLEET_CONFIG_PUBLIC_KEY: publicKey, FLEET_SIGNED_CONFIG: bundle(body) },
      {
        role: "controller",
        now: () => current,
        identity: async () => {
          current = now + 2_000;
          return { appId: body.appId, instanceId: body.instanceId };
        },
      },
    ),
  ).rejects.toThrow();
});
it("uses canonical domain-separated bytes and accepts equivalent JSON key order", async () => {
  const body = payload();
  const reordered = Object.fromEntries(
    Object.entries(body).reverse(),
  ) as unknown as FleetSecurityConfigPayload;
  reordered.env = Object.fromEntries(Object.entries(body.env).reverse());
  expect(canonicalFleetConfigPayload(reordered)).toEqual(
    canonicalFleetConfigPayload(body),
  );
  expect(canonicalFleetConfigPayload(body)).toEqual(
    Buffer.from(
      "vana.fleet.security-config.v1\0" + JSON.stringify(canonical(body)),
    ),
  );
  const identity = async () => ({
    appId: body.appId,
    instanceId: body.instanceId,
  });
  await expect(
    verifiedFleetEnvironment(
      {
        FLEET_CONFIG_PUBLIC_KEY: publicKey,
        FLEET_SIGNED_CONFIG: bundle(reordered),
      },
      { role: "controller", identity, now: () => now },
    ),
  ).resolves.toEqual(body.env);
  const noDomainSignature = sign(
    null,
    Buffer.from(JSON.stringify(canonical(body))),
    keys.privateKey,
  ).toString("base64");
  await expect(
    verifiedFleetEnvironment(
      {
        FLEET_CONFIG_PUBLIC_KEY: publicKey,
        FLEET_SIGNED_CONFIG: wire(
          JSON.stringify({
            payload: body,
            signature: noDomainSignature,
          }),
        ),
      },
      { role: "controller", identity, now: () => now },
    ),
  ).rejects.toThrow();
});
it("authenticates a production worker configuration and excludes unsigned fallback values", async () => {
  const body: FleetSecurityConfigPayload = {
    ...payload(),
    role: "worker",
    appId: "worker-app",
    instanceId: "worker-instance",
    nodeId: "worker-1",
    env: {
      CHAIN_ID: "14800",
      NODE_ID: "worker-1",
      GATEWAY_URL: "https://gateway.invalid",
      ENCLAVE_AGENT_SECRET: "agent-secret",
      NODE_SECRET: "node-secret",
      STORAGE_API_URL: "https://storage.invalid",
      PS_IMAGE: `image@sha256:${"ab".repeat(32)}`,
      SANDBOX_RUNTIME: "docker",
      FLEET_ENABLED: "true",
      FLEET_PEER_POLICIES: "[]",
    },
  };
  const identity = async () => ({
    appId: body.appId,
    instanceId: body.instanceId,
  });
  const raw = {
    FLEET_CONFIG_PUBLIC_KEY: publicKey,
    FLEET_SIGNED_CONFIG: bundle(body),
    FLEET_ENABLED: "false",
    PS_ENTRY: "/attacker.ts",
  };
  const env = await verifiedFleetEnvironment(raw, {
    role: "worker",
    identity,
    now: () => now,
  });
  expect(env.FLEET_ENABLED).toBe("true");
  expect(env.PS_ENTRY).toBeUndefined();
  body.env.SANDBOX_RUNTIME = "fake";
  await expect(
    verifiedFleetEnvironment(
      { ...raw, FLEET_SIGNED_CONFIG: bundle(body) },
      { role: "worker", identity, now: () => now },
    ),
  ).rejects.toThrow();
});
it("rejects absent, oversized and malformed inputs without disclosing secret contents", async () => {
  const body = payload();
  const wrongKeys = generateKeyPairSync("ed25519");
  const invalidInputs: NodeJS.ProcessEnv[] = [
    {},
    { FLEET_SIGNED_CONFIG: bundle(body) },
    { FLEET_CONFIG_PUBLIC_KEY: publicKey },
    { FLEET_CONFIG_PUBLIC_KEY: publicKey, FLEET_SIGNED_CONFIG: '{"TOP_SECRET' },
    {
      FLEET_CONFIG_PUBLIC_KEY: publicKey,
      FLEET_SIGNED_CONFIG: "s".repeat(128 * 1024 + 1),
    },
    {
      FLEET_CONFIG_PUBLIC_KEY: wrongKeys.publicKey
        .export({ type: "spki", format: "der" })
        .toString("base64"),
      FLEET_SIGNED_CONFIG: bundle(body),
    },
    {
      FLEET_CONFIG_PUBLIC_KEY: publicKey,
      FLEET_SIGNED_CONFIG: wire(
        JSON.stringify({
          payload: body,
          signature: "not-base64",
          extra: true,
        }),
      ),
    },
  ];
  for (const raw of invalidInputs) {
    const identity = vi.fn();
    await expect(
      verifiedFleetEnvironment(raw, {
        role: "controller",
        identity,
        now: () => now,
      }),
    ).rejects.toThrow(/^Invalid fleet security configuration$/);
    expect(identity).not.toHaveBeenCalled();
  }
});

// dstack 0.5.9 parse_env_file::escape_value does not escape pre-existing
// backslashes. Its systemd EnvironmentFile uses POSIX double-quote escapes.
// This helper executes only local, generated test data, with no runtime secrets.
function dstackEnvironmentRoundTrip(value: string): string {
  const escaped = value.replace(/[\n"$`]/g, (c) =>
    c === "\n" ? "\\n" : `\\${c}`,
  );
  const assignment = /[ \t|&;<>()$`\\"'\n]/.test(value)
    ? `"${escaped}"`
    : escaped;
  return execFileSync(
    "/bin/sh",
    [
      "-c",
      `FLEET_SIGNED_CONFIG=${assignment}\nprintf '%s' "$FLEET_SIGNED_CONFIG"`,
    ],
    { encoding: "utf8" },
  );
}
it("preserves signed nested JSON through dstack environment quoting using explicit base64 transport", async () => {
  const body = payload();
  const document = Buffer.from(bundle(body).slice(7), "base64").toString(
    "utf8",
  );
  const damaged = dstackEnvironmentRoundTrip(document);
  expect(damaged).not.toBe(document);
  expect(() => JSON.parse(damaged)).toThrow();
  const wire = `base64:${Buffer.from(document).toString("base64")}`;
  expect(dstackEnvironmentRoundTrip(wire)).toBe(wire);
  await expect(
    verifiedFleetEnvironment(
      {
        FLEET_CONFIG_PUBLIC_KEY: publicKey,
        FLEET_SIGNED_CONFIG: dstackEnvironmentRoundTrip(wire),
      },
      {
        role: "controller",
        now: () => now,
        identity: async () => ({
          appId: body.appId,
          instanceId: body.instanceId,
        }),
      },
    ),
  ).resolves.toEqual(body.env);
});

it("rejects noncanonical base64, invalid UTF-8 and raw JSON before identity lookup", async () => {
  const valid = bundle(payload());
  for (const document of [
    valid + "\n",
    valid.slice(0, 12) + "!" + valid.slice(12),
    "base64:",
    "base64:" + Buffer.from([0xff, 0xfe]).toString("base64"),
    Buffer.from(valid.slice(7), "base64").toString("utf8"),
    "base64:" + "A".repeat(128 * 1024),
  ]) {
    const identity = vi.fn();
    await expect(
      verifiedFleetEnvironment(
        { FLEET_CONFIG_PUBLIC_KEY: publicKey, FLEET_SIGNED_CONFIG: document },
        { role: "controller", identity, now: () => now },
      ),
    ).rejects.toThrow(/^Invalid fleet security configuration$/);
    expect(identity).not.toHaveBeenCalled();
  }
});
