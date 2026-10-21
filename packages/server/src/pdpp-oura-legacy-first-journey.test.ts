/**
 * The owner's legacy Oura file stays authoritative over an `oura-browser`
 * connection until the owner chooses otherwise.
 *
 * One owner has legacy Oura data (written the way oura-playwright 3.1.2 and
 * Desktop write it: POST /v1/data/<scope>) and an opt-in `oura-browser`
 * connection on source `oura` holding synced sleep, readiness and activity
 * rows. OpenPet reads the legacy scopes with a builder grant. Every read goes
 * through a real `createServer` app, the real SQLite record store, real P7
 * replaces and real legacy files, for both the owner token and the builder.
 *
 * Rule under test: while a scope has an eligible legacy head and no recorded
 * takeover, an `oura-browser` connection is not a takeover candidate. Without a
 * legacy head it still serves the scope, and a recorded takeover is kept.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createServer,
  type CreateServerOptions,
  type ServerContext,
} from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

// Each case boots a real server (some boot twice); the 5s default flakes under load.
vi.setConfig({ testTimeout: 60_000 });

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const CONTROL_PLANE_TOKEN = "oura-legacy-first-control-plane";
const OURA = "https://registry.pdpp.dev/sources/oura";
const SECOND_ACCOUNT = "conn_123e4567-e89b-42d3-a456-426614174000";
const GRANT_ID = `0x${"11".repeat(32)}`;
const BUILDER_ID = "builder-openpet";
const builder = createTestWallet(0);

const SCOPES = ["oura.sleep", "oura.readiness", "oura.activity"] as const;
type Scope = (typeof SCOPES)[number];
const STREAM_OF: Record<Scope, string> = {
  "oura.sleep": "sleep",
  "oura.readiness": "readiness",
  "oura.activity": "activity",
};

// Clock: the legacy collector ran first; the owner then ran oura-browser.
const T_LEGACY = "2026-10-14T00:00:00Z";
const T_PDPP = "2026-10-15T00:00:00Z";
const T_LEGACY_NEWER = "2026-10-16T00:00:00Z";

/** The real oura-browser 0.1.2 stream field lists, as the declaration. */
async function ouraBrowserDeclaration(): Promise<string> {
  const profile = JSON.parse(
    await readFile(
      new URL(
        "../../core/src/legacy-projection/declarations/oura-browser.collection-profile.json",
        import.meta.url,
      ),
      "utf-8",
    ),
  ) as {
    streams: {
      name: string;
      primary_key: string[];
      schema: { properties: Record<string, unknown>; required: string[] };
    }[];
  };
  return JSON.stringify({
    source_id: OURA,
    source_kind: "connector",
    version: "1",
    streams: profile.streams.map((stream) => ({
      name: stream.name,
      fields: Object.keys(stream.schema.properties),
      required_fields: stream.schema.required,
      primary_key: stream.primary_key,
    })),
  });
}

let tempDir: string;
let ctx: ServerContext | undefined;
let owner: string;
let accountOne: string;

function grant(): GatewayGrantResponse {
  return {
    id: GRANT_ID,
    grantorAddress: owner,
    granteeId: BUILDER_ID,
    scopes: ["oura.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  };
}

/** `methodIds`: the pdpp.methods Desktop configures for source oura. */
async function boot(
  methodIds: string[] = ["oura-browser"],
  dataPointFeed?: CreateServerOptions["dataPointFeed"],
) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "declaration.json");
  await writeFile(path, await ouraBrowserDeclaration(), "utf-8");
  const gateway = {
    getBuilder: vi.fn().mockResolvedValue({
      id: BUILDER_ID,
      ownerAddress: owner,
      granteeAddress: builder.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    } satisfies Builder),
    getGrant: vi.fn().mockResolvedValue(grant()),
  } as unknown as GatewayClient;
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      payment: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [path],
        methods: methodIds.map((method_id) => ({
          method_id,
          declaration_path: path,
        })),
      },
    }),
    {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: gateway,
      ...(dataPointFeed ? { dataPointFeed } : {}),
    },
  );
}

async function ownerPdppToken(instanceId?: string): Promise<string> {
  if (!instanceId) {
    return registerTestConnection(
      ctx!.app,
      ctx!.devToken!,
      owner,
      OURA,
      "oura-browser",
    );
  }
  const response = await ctx!.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: OURA, instance_id: instanceId }),
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { access_token: string }).access_token;
}

/** Mint a source-level owner token without registering any connection. */
async function mintSourceToken(): Promise<string> {
  const response = await ctx!.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: OURA }),
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { access_token: string }).access_token;
}

async function registerAccount(
  token: string,
  connectionId: string,
  method: string,
) {
  const response = await ctx!.app.request(
    `/pdpp/connections/${encodeURIComponent(connectionId)}`,
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        source_id: OURA,
        method_id: method,
        label: "Second",
      }),
    },
  );
  expect(response.status).toBe(200);
}

/** P7 full replace of one stream. */
async function replace(
  token: string,
  stream: string,
  rows: Record<string, unknown>[],
  sourceCollectedAt: string,
  { instance = accountOne, method = "oura-browser" } = {},
) {
  const response = await ctx!.app.request(
    `/v1/streams/${stream}/records/replace?method=${method}&binding_generation=1`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance,
        emitted_at: sourceCollectedAt,
        source_collected_at: sourceCollectedAt,
        records: rows.map((data) => ({
          key: String(data.id),
          data,
          emitted_at: sourceCollectedAt,
        })),
      }),
    },
  );
  expect(response.status).toBe(200);
}

/** The route Desktop's legacy path uses: apps/desktop/src/services/personalServerIngest.ts `ingestData`. */
async function legacyWrite(scope: string, data: object) {
  const response = await ctx!.app.request(
    `/v1/data/${encodeURIComponent(scope)}`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${ctx!.devToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(data),
    },
  );
  expect(response.status).toBe(201);
}

interface Outcome {
  status: number;
  source: string | null;
  reason: string | null;
  body: unknown;
}

async function ownerRead(scope: string): Promise<Outcome> {
  const response = await ctx!.app.request(`/v1/data/${scope}`, {
    headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
  });
  return outcome(response);
}

/** OpenPet's path: a builder reading under its grant. */
async function builderRead(scope: string): Promise<Outcome> {
  const response = await ctx!.app.request(`/v1/data/${scope}`, {
    headers: {
      authorization: await buildWeb3SignedHeader({
        wallet: builder,
        aud: ctx!.config.server.origin,
        method: "GET",
        uri: `/v1/data/${scope}`,
        grantId: GRANT_ID,
      }),
    },
  });
  return outcome(response);
}

async function outcome(response: Response): Promise<Outcome> {
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // keep text
  }
  return {
    status: response.status,
    source: response.headers.get("X-Vana-Data-Source"),
    reason:
      typeof body === "object" && body !== null && "reason" in body
        ? String((body as { reason: unknown }).reason)
        : null,
    body,
  };
}

/**
 * Which producer wrote the body: the envelope's `collectedAt` is the legacy
 * write time (T_LEGACY, T_LEGACY_NEWER) for a file and the stream's
 * `source_collected_at` (T_PDPP) for a projection. Independent of the
 * X-Vana-Data-Source header the same code sets.
 */
function bodyProducer(o: Outcome): "L" | "P" | "?" {
  const at = (o.body as { collectedAt?: string }).collectedAt ?? "";
  if (at.startsWith(T_PDPP.slice(0, 10))) return "P";
  if (
    at.startsWith(T_LEGACY.slice(0, 10)) ||
    at.startsWith(T_LEGACY_NEWER.slice(0, 10))
  )
    return "L";
  return "?";
}

function label(o: Outcome): string {
  if (o.status === 200) {
    const body = bodyProducer(o);
    if (o.source === "legacy" && body === "L") return "FILE (legacy body L)";
    if (o.source === "canonical" && body === "P")
      return "CANONICAL (projection P)";
    return `200 header=${o.source} body=${body}`;
  }
  return `${o.status} ${o.reason}`;
}

/** The scope's day rows (sleep keeps its daily scores under `dailyScores`). */
function dayRows(o: Outcome, scope: Scope): { id: string; score: number }[] {
  const data = (o.body as { data: Record<string, any> }).data;
  return scope === "oura.sleep" ? data.dailyScores : data.days;
}

async function observe(
  scope: Scope,
): Promise<{ owner: Outcome; builder: Outcome }> {
  const ownerOutcome = await ownerRead(scope);
  const builderOutcome = await builderRead(scope);
  // OpenPet's builder read and the owner read must agree on what is served.
  expect(label(builderOutcome)).toBe(label(ownerOutcome));
  return { owner: ownerOutcome, builder: builderOutcome };
}

// ── Fixtures: one raw Oura API day, in both producers' shapes ───────────────

const SLEEP_CONTRIB = {
  deep_sleep: 80,
  efficiency: 90,
  latency: 70,
  rem_sleep: 75,
  restfulness: 60,
  timing: 85,
  total_sleep: 88,
};
const READINESS_CONTRIB = {
  activity_balance: 70,
  body_temperature: 90,
  hrv_balance: 60,
  previous_day_activity: 80,
  previous_night: 85,
  recovery_index: 75,
  resting_heart_rate: 95,
  sleep_balance: 65,
};
const ACTIVITY_CONTRIB = {
  meet_daily_targets: 70,
  move_every_hour: 80,
  recovery_time: 90,
  stay_active: 60,
  training_frequency: 50,
  training_volume: 40,
};

/**
 * oura-playwright 3.1.2 (verified: mapReadiness / mapSleep / mapActivity at
 * /home/tnunamak/.t3/worktrees/data-connectors/t3-0a13df8d/artifacts/oura-playwright/oura-playwright-3.1.2/script.js:2397-2460,
 * identical to 2.0.0 in unity-surfaces) emits `timestamp` on readiness/activity
 * days and on sleep dailyScores. `LEGACY_TS = false` models a collector
 * without it, to isolate that field's effect.
 */
let LEGACY_TS = true;
const withTs = (n: number) => (LEGACY_TS ? { timestamp: ts(n) } : {});

interface Day {
  n: number;
  score: number;
}
const date = (n: number) => `2026-09-${String(n).padStart(2, "0")}`;
const ts = (n: number) => `${date(n)}T07:00:00+00:00`;

/** What oura-playwright's mapReadiness emits for a raw daily_readiness row. */
const legacyReadiness = ({ n, score }: Day) => ({
  id: `rd${n}`,
  day: date(n),
  score,
  ...withTs(n),
  temperatureDeviation: 0.12,
  temperatureTrendDeviation: -0.05,
  contributors: READINESS_CONTRIB,
});
/** What oura-browser 0.1.2 stores for the same day. */
const pdppReadiness = ({ n, score }: Day) => ({
  id: `rd${n}`,
  day: date(n),
  score,
  temperature_deviation: 0.12,
  temperature_trend_deviation: -0.05,
  contributors: READINESS_CONTRIB,
});

const legacyActivity = ({ n, score }: Day) => ({
  id: `ac${n}`,
  day: date(n),
  score,
  ...withTs(n),
  activeCalories: 400,
  totalCalories: 2300,
  steps: 9000,
  equivalentWalkingDistance: 7000,
  highActivityTime: 600,
  mediumActivityTime: 1800,
  lowActivityTime: 9000,
  sedentaryTime: 30000,
  restingTime: 40000,
  inactivityAlerts: 1,
  contributors: ACTIVITY_CONTRIB,
});
const pdppActivity = ({ n, score }: Day) => ({
  id: `ac${n}`,
  day: date(n),
  score,
  active_calories: 400,
  total_calories: 2300,
  steps: 9000,
  target_calories: 500,
  equivalent_walking_distance: 7000,
  high_activity_time: 600,
  medium_activity_time: 1800,
  low_activity_time: 9000,
  sedentary_time: 30000,
  resting_time: 40000,
  inactivity_alerts: 1,
  contributors: ACTIVITY_CONTRIB,
});

const legacySleep = (days: Day[]) => ({
  dailyScores: days.map(({ n, score }) => ({
    id: `ds${n}`,
    day: date(n),
    score,
    ...withTs(n),
    contributors: SLEEP_CONTRIB,
  })),
  sleepPeriods: days.map(({ n }) => ({
    id: `sp${n}`,
    day: date(n),
    type: "long_sleep",
    bedtimeStart: `${date(n)}T22:00:00+00:00`,
    bedtimeEnd: `${date(n)}T06:00:00+00:00`,
    totalSleepDuration: 27000,
    timeInBed: 28800,
    deepSleepDuration: 5400,
    lightSleepDuration: 14400,
    remSleepDuration: 7200,
    awakeTime: 1800,
    efficiency: 94,
    latency: 600,
    averageHeartRate: 55.5,
    averageHrv: 48,
    lowestHeartRate: 50,
    averageBreath: 14.5,
    restlessPeriods: 12,
  })),
});
const pdppSleep = (days: Day[]) =>
  days.flatMap(({ n, score }) => [
    {
      record_type: "daily_score",
      id: `ds${n}`,
      day: date(n),
      sleep_score: score,
      daily_sleep_id: `ds${n}`,
      daily_sleep_timestamp: ts(n),
      contributors: SLEEP_CONTRIB,
    },
    {
      record_type: "sleep_session",
      id: `sp${n}`,
      day: date(n),
      type: "long_sleep",
      bedtime_start: `${date(n)}T22:00:00+00:00`,
      bedtime_end: `${date(n)}T06:00:00+00:00`,
      total_sleep_duration: 27000,
      time_in_bed: 28800,
      deep_sleep_duration: 5400,
      light_sleep_duration: 14400,
      rem_sleep_duration: 7200,
      awake_time: 1800,
      efficiency: 94,
      latency: 600,
      average_heart_rate: 55.5,
      average_hrv: 48,
      lowest_heart_rate: 50,
      average_breath: 14.5,
      restless_periods: 12,
    },
  ]);

const DAYS: Day[] = [
  { n: 1, score: 80 },
  { n: 2, score: 82 },
];

function legacyBody(scope: Scope, days: Day[]): object {
  switch (scope) {
    case "oura.sleep":
      return legacySleep(days);
    case "oura.readiness":
      return { days: days.map(legacyReadiness) };
    case "oura.activity":
      return { days: days.map(legacyActivity) };
  }
}
function pdppRows(scope: Scope, days: Day[]): Record<string, unknown>[] {
  switch (scope) {
    case "oura.sleep":
      return pdppSleep(days);
    case "oura.readiness":
      return days.map(pdppReadiness);
    case "oura.activity":
      return days.map(pdppActivity);
  }
}

/** Legacy Desktop writes all three scopes at `at`. */
async function writeLegacy(days: Day[], at: string) {
  vi.setSystemTime(new Date(at));
  for (const scope of SCOPES) await legacyWrite(scope, legacyBody(scope, days));
}

/** The owner ran oura-browser once; Desktop's PDPP writer replaced all three streams. */
async function writePdpp(
  days: Day[],
  at: string,
  token?: string,
  options?: { instance?: string; method?: string },
) {
  vi.setSystemTime(new Date(at));
  const t = token ?? (await ownerPdppToken());
  for (const scope of SCOPES) {
    await replace(t, STREAM_OF[scope], pdppRows(scope, days), at, options);
  }
  return t;
}

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-13T00:00:00Z"));
  tempDir = await mkdtemp(join(tmpdir(), "oura-legacy-first-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  vi.stubEnv("PS_ACCESS_TOKEN", CONTROL_PLANE_TOKEN);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  accountOne = `oura:${owner}`;
  ctx = await boot();
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

/** Run `read` for all three scopes, return label per scope. */
async function readAll() {
  const out: Record<string, string> = {};
  for (const scope of SCOPES) {
    out[scope] = label((await observe(scope)).owner);
  }
  return out;
}
const FILE = "FILE (legacy body L)";
const CANON = "CANONICAL (projection P)";

const ALL = (served: string) => ({
  "oura.sleep": served,
  "oura.readiness": served,
  "oura.activity": served,
});

/** Start over in a fresh data dir with another `pdpp.methods` configuration. */
async function freshBoot(methods: string[]) {
  await ctx!.cleanup();
  await rm(tempDir, { recursive: true, force: true });
  tempDir = await mkdtemp(join(tmpdir(), "oura-legacy-first-"));
  ctx = await boot(methods);
}

/** Restart the same data dir with another `pdpp.methods` configuration. */
async function restartWithMethods(methods: string[]) {
  await ctx!.cleanup();
  ctx = await boot(methods);
}

describe("an owner with a legacy Oura file and an oura-browser connection", () => {
  beforeEach(() => {
    LEGACY_TS = true;
  });

  describe("serves the legacy file while the legacy head has no recorded takeover", () => {
    it("with no oura-browser rows at all", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("with a registered but empty oura-browser connection", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      await ownerPdppToken();
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("when the projection covers the file exactly (collector shape, with timestamp)", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("when the projection covers a file without the timestamp field", async () => {
      LEGACY_TS = false;
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it.each([
      ["has an extra day", [...DAYS, { n: 3, score: 90 }]],
      ["is missing a day", DAYS.slice(0, 1)],
      ["has a different score", [DAYS[0]!, { n: 2, score: 99 }]],
    ])("when the projection %s", async (_name, pdppDays) => {
      LEGACY_TS = false;
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(pdppDays, T_PDPP);
      expect(await readAll()).toEqual(ALL(FILE));
      // The body is the file's two days and scores, not the projection's.
      for (const scope of SCOPES) {
        const rows = dayRows((await observe(scope)).builder, scope);
        expect(rows.map((row) => row.score)).toEqual(
          DAYS.map((day) => day.score),
        );
      }
    });

    it("when the file is newer than the projection and differs", async () => {
      LEGACY_TS = false;
      await writePdpp([DAYS[0]!, { n: 2, score: 99 }], T_PDPP);
      await writeLegacy(DAYS, T_LEGACY_NEWER);
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("across a newer legacy write after the projection arrived", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      await writeLegacy([...DAYS, { n: 3, score: 91 }], T_LEGACY_NEWER);
      expect(await readAll()).toEqual(ALL(FILE));
      const read = await ownerRead("oura.activity");
      expect(
        (read.body as { data: { days: unknown[] } }).data.days,
      ).toHaveLength(3);
    });

    it("when the collector re-delivers an identical file after the projection arrived", async () => {
      LEGACY_TS = false;
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      await writeLegacy(DAYS, T_LEGACY_NEWER);
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("with a second oura-browser connection that also holds data (no 409)", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      const token = await writePdpp(DAYS, T_PDPP);
      await registerAccount(token, SECOND_ACCOUNT, "oura-browser");
      const second = await ownerPdppToken(SECOND_ACCOUNT);
      await writePdpp([{ n: 5, score: 70 }], T_PDPP, second, {
        instance: SECOND_ACCOUNT,
      });
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("when the owner reconnects under a new connection id and both sync", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      const token = await writePdpp(DAYS, T_PDPP);
      await registerAccount(token, SECOND_ACCOUNT, "oura-browser");
      const second = await ownerPdppToken(SECOND_ACCOUNT);
      await writePdpp(DAYS, T_PDPP, second, { instance: SECOND_ACCOUNT });
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("beside a PAT `oura` connection from an earlier boot (ungated: it alone is the candidate; sleep and readiness stay on the file)", async () => {
      await freshBoot(["oura"]);
      await writeLegacy(DAYS, T_LEGACY);
      vi.setSystemTime(new Date(T_PDPP));
      const pat = await registerTestConnection(
        ctx!.app,
        ctx!.devToken!,
        owner,
        OURA,
        "oura",
      );
      // The PAT method is not gated: it alone is a candidate, and with the
      // browser method out of the count it is the one that serves.
      await replace(pat, "activity", [pdppActivity(DAYS[0]!)], T_PDPP, {
        method: "oura",
      });
      await restartWithMethods(["oura-browser"]);
      vi.setSystemTime(new Date(T_PDPP));
      const second = await mintSourceToken();
      await registerAccount(second, SECOND_ACCOUNT, "oura-browser");
      const browser = await ownerPdppToken(SECOND_ACCOUNT);
      await writePdpp(DAYS, T_PDPP, browser, { instance: SECOND_ACCOUNT });
      const labels = await readAll();
      expect(labels["oura.sleep"]).toBe(FILE);
      expect(labels["oura.readiness"]).toBe(FILE);
    });

    it("records no takeover verdict for the scope", async () => {
      LEGACY_TS = false;
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(FILE));
      for (const scope of SCOPES) {
        const r = await ctx!.app.request(`/v1/data/${scope}/takeover`, {
          headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
        });
        expect(await r.json()).toMatchObject({ verdicts: [] });
      }
    });
  });

  describe("still serves the oura-browser projection", () => {
    it("when there is no legacy file", async () => {
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(CANON));
    });

    it("and then yields to a legacy file written afterwards", async () => {
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(CANON));
      await writeLegacy(DAYS, T_LEGACY_NEWER);
      expect(await readAll()).toEqual(ALL(FILE));
    });

    it("with two accounts and no legacy file, still refuses as ambiguous (409)", async () => {
      const token = await writePdpp(DAYS, T_PDPP);
      await registerAccount(token, SECOND_ACCOUNT, "oura-browser");
      const second = await ownerPdppToken(SECOND_ACCOUNT);
      await writePdpp(DAYS, T_PDPP, second, { instance: SECOND_ACCOUNT });
      const r = await observe("oura.sleep");
      expect(r.owner.status).toBe(409);
      expect(r.owner.reason).toBe("ambiguous_connection");
    });
  });

  describe("keeps its safety refusals", () => {
    it("refuses (503) when oura-browser holds data and the method is no longer configured", async () => {
      LEGACY_TS = false;
      await writePdpp(DAYS, T_PDPP);
      await ctx!.cleanup();
      ctx = await boot(["oura"]);
      vi.setSystemTime(new Date(T_PDPP));
      // No legacy file: nothing makes the browser method yield.
      for (const scope of SCOPES) {
        expect((await observe(scope)).owner.status).toBe(503);
      }
    });

    it("refuses to delete a scope whose oura-browser rows exist, though the file is what reads serve", async () => {
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(FILE));
      const del = await ctx!.app.request("/v1/data/oura.sleep", {
        method: "DELETE",
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect(del.status).toBe(409);
      expect(await del.json()).toMatchObject({
        error: "CANONICAL_DELETE_UNSUPPORTED",
      });
    });
  });
});

describe("an owner who disconnects or reconnects oura-browser while the legacy file is the served body", () => {
  beforeEach(() => {
    LEGACY_TS = false;
  });

  /** The owner removes the connection, the natural way to undo the opt-in. */
  async function disconnect(token: string, connectionId = accountOne) {
    const deleted = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(connectionId)}`,
      { method: "DELETE", headers: { authorization: `Bearer ${token}` } },
    );
    expect(deleted.status).toBe(200);
  }

  it("keeps serving the file after the connection is deleted", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    const token = await writePdpp(DAYS, T_PDPP);
    await disconnect(token);
    expect(await readAll()).toEqual(ALL(FILE));
  });

  it.each([1, 2])(
    "keeps serving the file after delete and reconnect with %i live connection(s) holding data",
    async (live) => {
      await writeLegacy(DAYS, T_LEGACY);
      const first = await writePdpp(DAYS, T_PDPP);
      await disconnect(first);
      const source = await mintSourceToken();
      const ids = [SECOND_ACCOUNT, "conn_223e4567-e89b-42d3-a456-426614174001"];
      for (const id of ids.slice(0, live)) {
        await registerAccount(source, id, "oura-browser");
        const token = await ownerPdppToken(id);
        await writePdpp(DAYS, T_PDPP, token, { instance: id });
      }
      expect(await readAll()).toEqual(ALL(FILE));
    },
  );

  it("still refuses (503) a deleted connection when there is no legacy file", async () => {
    const token = await writePdpp(DAYS, T_PDPP);
    await disconnect(token);
    for (const scope of SCOPES) {
      const r = await observe(scope);
      expect(r.owner.status).toBe(503);
      expect(r.owner.reason).toBe("no_connection");
    }
  });
});

describe("deletion history and the legacy file that is served", () => {
  beforeEach(() => {
    LEGACY_TS = false;
  });

  it("serves a legacy file re-added after a gateway tombstone while oura-browser rows exist (no 410)", async () => {
    let deleted = false;
    const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      getDataPoint: async ({ ownerAddress, scope }) =>
        deleted
          ? {
              id: "synthetic-point",
              ownerAddress,
              scope,
              dataHash: `0x${"00".repeat(32)}`,
              metadataHash: `0x${"00".repeat(32)}`,
              expectedVersion: "1",
              addedAt: "2026-09-01T00:00:00Z",
              deletedAt: "2026-09-11T00:00:00Z",
            }
          : null,
    };
    await ctx!.cleanup();
    ctx = await boot(["oura-browser"], dataPointFeed);
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);

    // The owner deletes the scope elsewhere; the old file is covered.
    deleted = true;
    for (const scope of SCOPES) {
      expect((await observe(scope)).owner.status).toBe(410);
    }

    // The collector runs again and re-adds the file after that tombstone.
    const readded: Day[] = [{ n: 7, score: 71 }];
    await writeLegacy(readded, T_LEGACY_NEWER);
    expect(await readAll()).toEqual(ALL(FILE));
    for (const scope of SCOPES) {
      const rows = dayRows((await observe(scope)).builder, scope);
      expect(rows.map((row) => row.score)).toEqual([71]);
    }
    // The listing agrees with the read.
    const listing = await ctx!.app.request("/v1/data", {
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(listing.status).toBe(200);
    const listed = (
      (await listing.json()) as { scopes: { scope: string }[] }
    ).scopes.map((entry) => entry.scope);
    expect(listed).toEqual(expect.arrayContaining([...SCOPES]));
  });
});
