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
 * Rule under test: while a scope has an eligible legacy head and no takeover
 * that an `oura-browser` connection earned, an `oura-browser` connection is not
 * a takeover candidate. Without a legacy head it still serves the scope, and a
 * recorded takeover is kept. The deletion history judging a read is the one
 * the view decided with the body.
 */

import Database from "better-sqlite3";
import { createServer as createHttpServer } from "node:http";
import { spawn } from "node:child_process";
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
import type * as LegacyScopeViewModule from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";

/**
 * A pass-through to the real view. A case may arm `afterReadLatest` to run
 * a concurrent write after the view has chosen a body and before the API
 * judges that body's deletion history.
 */
const barrier = vi.hoisted(() => ({
  afterReadLatest: null as null | ((scope: string) => Promise<void>),
}));
vi.mock(
  "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view",
  async (importOriginal) => {
    const actual = await importOriginal<typeof LegacyScopeViewModule>();
    return {
      ...actual,
      createLegacyScopeView: (
        input: Parameters<typeof actual.createLegacyScopeView>[0],
      ) => {
        const view = actual.createLegacyScopeView(input);
        return {
          ...view,
          async readLatest(scope: string) {
            const latest = await view.readLatest(scope);
            const after = barrier.afterReadLatest;
            barrier.afterReadLatest = null;
            if (after) await after(scope);
            return latest;
          },
        };
      },
    };
  },
);

// Each case boots a real server (some boot twice); the 5s default flakes under load.
vi.setConfig({ testTimeout: 60_000 });

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const CONTROL_PLANE_TOKEN = "oura-legacy-first-control-plane";
const OURA = "https://registry.pdpp.dev/sources/oura";
const SECOND_ACCOUNT = "conn_123e4567-e89b-42d3-a456-426614174000";
const PAT_ACCOUNT = "conn_323e4567-e89b-42d3-a456-426614174002";
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

/**
 * The connector manifests of PDP-Connect/data-connectors 14ec4e7e1
 * (oura-browser 0.1.41, oura 0.1.23), copied verbatim. Their readiness and
 * activity streams declare `timestamp`, as the legacy collector's files do.
 */
const MANIFESTS: Record<string, string> = {
  "oura-browser": "oura-browser.manifest.json",
  oura: "oura.manifest.json",
};

/** A method's manifest stream field lists, as the declaration Desktop passes. */
async function declarationFor(method: string): Promise<string> {
  const manifest = JSON.parse(
    await readFile(
      new URL(
        `./__fixtures__/oura-14ec4e7e1/${MANIFESTS[method]}`,
        import.meta.url,
      ),
      "utf-8",
    ),
  ) as {
    version: string;
    streams: {
      name: string;
      primary_key: string[];
      schema: { properties: Record<string, unknown>; required: string[] };
    }[];
  };
  return JSON.stringify({
    source_id: OURA,
    source_kind: "connector",
    version: manifest.version,
    streams: manifest.streams.map((stream) => ({
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
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  };
}

/**
 * `methodIds`: the pdpp.methods Desktop configures for source oura.
 * `optIn`: those it marks opt-in. A stable build marks oura-browser (it runs
 * only from the owner's deep link); a dev build marks nothing.
 */
async function boot(
  methodIds: string[] = ["oura-browser"],
  dataPointFeed?: CreateServerOptions["dataPointFeed"],
  optIn: readonly string[] = ["oura-browser"],
) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const paths = new Map<string, string>();
  for (const method of methodIds) {
    const path = join(dir, `${method}.json`);
    await writeFile(path, await declarationFor(method), "utf-8");
    paths.set(method, path);
  }
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
        declarationPaths: [...paths.values()],
        methods: methodIds.map((method_id) => ({
          method_id,
          declaration_path: paths.get(method_id)!,
        })),
        optInMethods: [...optIn],
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
  { instance = accountOne, method = "oura-browser", complete = true } = {},
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
        ...(complete ? { source_collected_at: sourceCollectedAt } : {}),
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
/** What oura-browser 0.1.41 stores for the same day. */
const pdppReadiness = ({ n, score }: Day) => ({
  id: `rd${n}`,
  day: date(n),
  score,
  timestamp: ts(n),
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
  timestamp: ts(n),
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
  barrier.afterReadLatest = null;
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
async function freshBoot(methods: string[], optIn?: readonly string[]) {
  await ctx!.cleanup();
  await rm(tempDir, { recursive: true, force: true });
  tempDir = await mkdtemp(join(tmpdir(), "oura-legacy-first-"));
  ctx = await boot(methods, undefined, optIn);
}

/** Restart the same data dir with another `pdpp.methods` configuration. */
async function restartWithMethods(
  methods: string[],
  optIn?: readonly string[],
) {
  await ctx!.cleanup();
  ctx = await boot(methods, undefined, optIn);
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

    it("keeps serving the file after a restart where oura-browser is opt-in but not configured", async () => {
      // Desktop drops a method whose retained declaration no longer matches
      // its pin (a re-pin before the owner reinstalls). The opt-in policy is
      // a boot input of its own and still applies.
      LEGACY_TS = false;
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS, T_PDPP);
      expect(await readAll()).toEqual(ALL(FILE));
      await restartWithMethods([], ["oura-browser"]);
      vi.setSystemTime(new Date(T_PDPP));
      expect(await readAll()).toEqual(ALL(FILE));
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

  it("lets the owner delete the legacy scope once the connection that held rows is gone", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    const token = await writePdpp(DAYS, T_PDPP);
    const blocked = await ctx!.app.request("/v1/data/oura.sleep", {
      method: "DELETE",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(blocked.status).toBe(409);
    await disconnect(token);
    const deleted = await ctx!.app.request("/v1/data/oura.sleep", {
      method: "DELETE",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(deleted.status).toBe(200);
  });

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

describe("a read whose legacy file is re-added while the canonical body is chosen", () => {
  beforeEach(() => {
    LEGACY_TS = false;
  });

  it("refuses (410) the canonical body its deletion history covers, though the file arrives before the API judges it", async () => {
    let deleted = true;
    const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      getDataPoint: async ({ ownerAddress, scope }) => ({
        id: "synthetic-point",
        ownerAddress,
        scope,
        dataHash: `0x${"00".repeat(32)}`,
        metadataHash: `0x${"00".repeat(32)}`,
        expectedVersion: "1",
        addedAt: "2026-09-01T00:00:00Z",
        deletedAt: deleted ? "2026-09-11T00:00:00Z" : null,
      }),
    };
    await ctx!.cleanup();
    ctx = await boot(["oura-browser"], dataPointFeed);
    // No legacy file; the oura-browser projection is the body, and the
    // owner has deleted the scope elsewhere: the projection is refused.
    await writePdpp(DAYS, T_PDPP);
    expect((await observe("oura.activity")).owner.status).toBe(410);

    // The collector re-adds a file elsewhere. Once the remembered tombstone
    // is stale the gateway shows the scope live, but the canonical body is
    // still covered by its deletion history.
    deleted = false;
    vi.setSystemTime(new Date(T_LEGACY_NEWER));
    expect((await observe("oura.activity")).owner.status).toBe(410);

    // The re-added file is indexed locally after the view has chosen the
    // canonical body and before the API judges it.
    barrier.afterReadLatest = async (scope) => {
      await writeLegacy([{ n: 7, score: 71 }], T_LEGACY_NEWER);
      expect(scope).toBe("oura.activity");
    };
    const raced = await ownerRead("oura.activity");
    expect(barrier.afterReadLatest).toBeNull();
    expect(raced.status).toBe(410);
    expect(raced.source).not.toBe("canonical");

    // Settled, the re-added file is what every reader is served.
    expect(await readAll()).toEqual(ALL(FILE));
  });
});

describe("an owner with the PAT `oura` and the `oura-browser` method both configured", () => {
  beforeEach(() => {
    LEGACY_TS = false;
  });

  it("keeps the PAT takeover of activity on repeated reads, while oura-browser stays gated (no 409)", async () => {
    // Each boot registers connections of its one active method.
    await freshBoot(["oura"]);
    await writeLegacy(DAYS, T_LEGACY);
    vi.setSystemTime(new Date(T_PDPP));
    // The PAT connection's activity covers the file's two days.
    await registerAccount(await mintSourceToken(), PAT_ACCOUNT, "oura");
    await replace(
      await ownerPdppToken(PAT_ACCOUNT),
      "activity",
      DAYS.map(pdppActivity),
      T_PDPP,
      { instance: PAT_ACCOUNT, method: "oura" },
    );
    // A browser account with a distinguishable day.
    await restartWithMethods(["oura-browser"]);
    vi.setSystemTime(new Date(T_PDPP));
    await registerAccount(
      await mintSourceToken(),
      SECOND_ACCOUNT,
      "oura-browser",
    );
    await writePdpp(
      [{ n: 5, score: 70 }],
      T_PDPP,
      await ownerPdppToken(SECOND_ACCOUNT),
      { instance: SECOND_ACCOUNT },
    );
    // Desktop configures both methods where both are admitted.
    await restartWithMethods(["oura", "oura-browser"]);
    vi.setSystemTime(new Date(T_PDPP));

    const scores = (o: Outcome) =>
      dayRows(o, "oura.activity").map((row) => row.score);
    for (let read = 1; read <= 3; read++) {
      const activity = await observe("oura.activity");
      expect(label(activity.owner), `read ${read}`).toBe(CANON);
      expect(scores(activity.owner)).toEqual(DAYS.map((day) => day.score));
      expect(scores(activity.builder)).toEqual(DAYS.map((day) => day.score));
      // No PAT rows, no takeover: the browser method stays gated.
      expect(label((await observe("oura.sleep")).owner)).toBe(FILE);
      expect(label((await observe("oura.readiness")).owner)).toBe(FILE);
    }

    const listing = await ctx!.app.request("/v1/data", {
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(listing.status).toBe(200);
    const listed = (
      (await listing.json()) as { scopes: { scope: string }[] }
    ).scopes.map((entry) => entry.scope);
    expect(listed).toEqual(expect.arrayContaining([...SCOPES]));
    expect(label((await observe("oura.activity")).owner)).toBe(CANON);
  });
});

describe("a dev build, where oura-browser is the default Oura method (not opt-in)", () => {
  beforeEach(() => {
    LEGACY_TS = true;
  });

  it("lets a covering oura-browser projection take over the legacy file", async () => {
    await freshBoot(["oura-browser"], []);
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    expect((await readAll())["oura.sleep"]).toBe(CANON);
  });

  it("keeps that takeover after a restart into a stable opt-in boot", async () => {
    await freshBoot(["oura-browser"], []);
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    expect((await readAll())["oura.sleep"]).toBe(CANON);
    await restartWithMethods(["oura-browser"], ["oura-browser"]);
    vi.setSystemTime(new Date(T_PDPP));
    // oura-browser earned this takeover itself, so the gate does not apply.
    expect((await readAll())["oura.sleep"]).toBe(CANON);
  });
});

describe("a takeover that oura-browser did not earn", () => {
  beforeEach(() => {
    LEGACY_TS = false;
  });

  it("names the method of an older unknown record from a fresh proof, so a later opt-in boot keeps it", async () => {
    // Dev boot: oura-browser is the default method.
    await freshBoot(["oura-browser"], []);
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    // A takeover of the same key, as a runtime pinned before takeovers
    // named their method wrote it.
    const db = new Database(join(tempDir, "index.db"));
    try {
      for (const scope of SCOPES) {
        const head = db
          .prepare(
            "SELECT version, cas_revision, collected_at, path FROM data_files WHERE scope = ? ORDER BY id DESC LIMIT 1",
          )
          .get(scope) as {
          version: number;
          cas_revision: number;
          collected_at: string;
          path: string;
        };
        db.prepare(
          `INSERT INTO legacy_scope_takeovers
            (scope, instance, generation, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
            VALUES (?, ?, 1, ?, ?, ?, ?)`,
        ).run(
          scope,
          accountOne,
          head.version,
          head.cas_revision,
          head.collected_at,
          head.path,
        );
      }
    } finally {
      db.close();
    }
    expect((await readAll())["oura.sleep"]).toBe(CANON);
    await restartWithMethods(["oura-browser"], ["oura-browser"]);
    vi.setSystemTime(new Date(T_PDPP));
    expect((await readAll())["oura.sleep"]).toBe(CANON);
  });

  it("keeps it gated for a takeover recorded without its method", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    // As a runtime pinned before takeovers named their method would write.
    const db = new Database(join(tempDir, "index.db"));
    try {
      for (const scope of SCOPES) {
        const head = db
          .prepare(
            "SELECT version, cas_revision, collected_at, path FROM data_files WHERE scope = ? ORDER BY id DESC LIMIT 1",
          )
          .get(scope) as {
          version: number;
          cas_revision: number;
          collected_at: string;
          path: string;
        };
        db.prepare(
          `INSERT INTO legacy_scope_takeovers
            (scope, instance, generation, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
            VALUES (?, '', 1, ?, ?, ?, ?)`,
        ).run(
          scope,
          head.version,
          head.cas_revision,
          head.collected_at,
          head.path,
        );
      }
    } finally {
      db.close();
    }
    // Unknown provenance does not let oura-browser serve; the recorded
    // takeover still marks the file superseded, so the read refuses.
    expect(await readAll()).toEqual(ALL("503 no_connection"));
  });
});

describe("Oura default admission cutover", () => {
  it("retains distinct 2025 history when a completed truncated opt-in snapshot is promoted", async () => {
    vi.setSystemTime(new Date(T_LEGACY));
    for (const scope of SCOPES) {
      const body = JSON.parse(
        JSON.stringify(legacyBody(scope, DAYS)).replaceAll(
          "2026-09-01",
          "2025-01-01",
        ),
      );
      await legacyWrite(scope, body);
    }
    await writePdpp(DAYS.slice(1), T_PDPP);
    expect(await readAll()).toEqual(ALL(FILE));
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    for (const scope of SCOPES) {
      const read = await observe(scope);
      expect(dayRows(read.owner, scope)).toHaveLength(DAYS.length - 1);
      expect(dayRows(read.builder, scope)).toHaveLength(DAYS.length - 1);
      expect(JSON.stringify(read.owner.body)).not.toContain("2025-01-01");
      expect(JSON.stringify(read.builder.body)).not.toContain("2025-01-01");
      const stored = await ctx!.app.request(`/v1/data/${scope}?view=stored`, {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect(stored.status).toBe(200);
      expect(JSON.stringify(await stored.json())).toContain("2025-01-01");
    }
  });

  it.each([false, true])(
    "revalidates persisted version-8 proven-deletion verdicts after restart (takeover=%s)",
    async (withTakeover) => {
      await writeLegacy(DAYS, T_LEGACY);
      await writePdpp(DAYS.slice(1), T_PDPP);
      await restartWithMethods(["oura-browser"], []);
      await readAll();
      // Seed historical v8 evidence explicitly. Today's completed-replacement
      // reader intentionally does not manufacture parity verdicts.
      const db = new Database(join(tempDir, "index.db"));
      try {
        const cursors = db
          .prepare(
            "SELECT scope, replacement_cursor FROM legacy_scope_takeovers",
          )
          .all() as { scope: string; replacement_cursor: string }[];
        expect(cursors).toHaveLength(3);
        db.prepare("DELETE FROM legacy_scope_takeovers").run();
        db.prepare("DELETE FROM legacy_scope_takeover_verdicts").run();
        db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
          accountOne,
        );
        const heads = db
          .prepare(
            "SELECT id, scope FROM data_files WHERE scope IN ('oura.sleep', 'oura.readiness', 'oura.activity') ORDER BY id",
          )
          .all() as { id: number; scope: string }[];
        expect(heads).toHaveLength(3);
        for (const head of heads) {
          const replacement = cursors.find(
            (row) => row.scope === head.scope,
          )!.replacement_cursor;
          expect(replacement.startsWith(`${head.id}:`)).toBe(true);
          const currentCursor = replacement.slice(String(head.id).length + 1);
          const oldCursor = currentCursor.replace(
            /:[0-9]+:1\.5:262144$/,
            ":8:1.5:262144",
          );
          expect(oldCursor).not.toBe(currentCursor);
          db.prepare(
            `INSERT INTO legacy_scope_takeover_verdicts
            (scope, instance, generation, legacy_version_id, canonical_cursor,
             verdict, comparison_case, reason_counts_json, applied_exceptions_json,
             reason_json, legacy_bytes, canonical_bytes, byte_delta, evaluated_at)
            VALUES (?, ?, 1, ?, ?, 'covered', 'canonical_newer', '{}', '[]', ?, 1, 1, 0, ?)`,
          ).run(
            head.scope,
            accountOne,
            head.id,
            oldCursor,
            JSON.stringify({
              reason: "proven_deletion",
              missingEntityCount: 1,
              mismatchedFieldPaths: [],
            }),
            T_PDPP,
          );
        }
        expect(
          db
            .prepare("SELECT verdict FROM legacy_scope_takeover_verdicts")
            .all(),
        ).toEqual(SCOPES.map(() => ({ verdict: "covered" })));
        if (withTakeover)
          db.prepare(
            `INSERT INTO legacy_scope_takeovers
        (scope, instance, generation, method, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
        SELECT scope, ?, 1, 'oura-browser', version, cas_revision, collected_at, path FROM data_files`,
          ).run(accountOne);
      } finally {
        db.close();
      }
      await restartWithMethods(["oura-browser"], []);
      const listing = await ctx!.app.request("/v1/data", {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      const listed = (await listing.json()).scopes as { scope: string }[];
      expect(
        listed.some((entry) =>
          (SCOPES as readonly string[]).includes(entry.scope),
        ),
      ).toBe(!withTakeover);
      expect(await readAll()).toEqual(
        ALL(withTakeover ? "503 canonical_view_incomplete" : FILE),
      );
      const verified = new Database(join(tempDir, "index.db"));
      try {
        expect(
          verified
            .prepare("SELECT verdict FROM legacy_scope_takeover_verdicts")
            .all(),
        ).toEqual(
          SCOPES.map(() => ({
            verdict: withTakeover ? "not_covered" : "covered",
          })),
        );
      } finally {
        verified.close();
      }
      // A new, actually complete run is the positive control; old verdicts
      // alone did not authorize it. The same source/records now have receipts.
      await writePdpp(DAYS.slice(1), T_PDPP);
      expect(await readAll()).toEqual(ALL(CANON));
      await restartWithMethods(["oura-browser"], []);
      expect(await readAll()).toEqual(ALL(CANON));
    },
  );

  const T_NEWEST = "2026-10-17T00:00:00Z";
  const scoresOf = (days: Day[]) => days.map((day) => day.score);
  /** A token valid at `at`: the owner token expires within a day of its horizon. */
  const mintAt = async (at: string) => {
    vi.setSystemTime(new Date(at));
    return ownerPdppToken(accountOne);
  };

  it("wholesale replacement: a newer complete smaller set replaces the expanded set exactly across restart", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    // Strictly increasing horizons: the expanded set, then the smaller set.
    await writePdpp(
      [...DAYS, { n: 3, score: 91 }],
      T_LEGACY_NEWER,
      await mintAt(T_LEGACY_NEWER),
    );
    for (const scope of SCOPES)
      expect(dayRows((await observe(scope)).owner, scope)).toHaveLength(3);
    await writePdpp(DAYS, T_NEWEST, await mintAt(T_NEWEST));
    for (const scope of SCOPES) {
      const read = await observe(scope);
      expect(read.owner.status).toBe(200);
      expect(read.builder.status).toBe(200);
      expect(dayRows(read.owner, scope).map((row) => row.score)).toEqual(
        scoresOf(DAYS),
      );
      expect(dayRows(read.builder, scope).map((row) => row.score)).toEqual(
        scoresOf(DAYS),
      );
    }
    await restartWithMethods(["oura-browser"], []);
    for (const scope of SCOPES) {
      const read = await observe(scope);
      expect(read.owner.status).toBe(200);
      expect(read.builder.status).toBe(200);
      expect(dayRows(read.owner, scope).map((row) => row.score)).toEqual(
        scoresOf(DAYS),
      );
      expect(dayRows(read.builder, scope).map((row) => row.score)).toEqual(
        scoresOf(DAYS),
      );
    }
    for (const scope of SCOPES) {
      const stored = await ctx!.app.request(`/v1/data/${scope}?view=stored`, {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect((await stored.json()).data).toEqual(legacyBody(scope, DAYS));
    }
  });

  it("wholesale replacement: an unreceipted deletion refuses across restart and a complete smaller newer batch restores exactly", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    // A real incomplete deletion of the second day: no completion receipts.
    const newer = await mintAt(T_LEGACY_NEWER);
    for (const scope of SCOPES)
      await replace(
        newer,
        STREAM_OF[scope],
        pdppRows(scope, DAYS.slice(0, 1)),
        T_LEGACY_NEWER,
        { complete: false },
      );
    for (const scope of SCOPES) {
      const read = await observe(scope);
      expect(read.owner.status).toBe(503);
      expect(read.builder.status).toBe(503);
    }
    await restartWithMethods(["oura-browser"], []);
    for (const scope of SCOPES)
      expect((await observe(scope)).owner.status).toBe(503);
    // Recovery: a genuinely complete newer batch whose current set is smaller.
    const smaller = DAYS.slice(0, 1);
    const restored = await ctx!.app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        collectedAt: T_NEWEST,
        records: SCOPES.flatMap((scope) =>
          pdppRows(scope, smaller).map((data) => ({
            stream: STREAM_OF[scope],
            data,
          })),
        ),
        selection: { streams: SCOPES.map((name) => ({ name })) },
        completion: {
          streams: SCOPES.map((scope) => ({
            stream: STREAM_OF[scope],
            status: "complete",
            recordCount: pdppRows(scope, smaller).length,
          })),
        },
      }),
    });
    expect(restored.status, await restored.clone().text()).toBe(200);
    expect((await restored.json()).receipts).toHaveLength(3);
    for (const scope of SCOPES) {
      const read = await observe(scope);
      expect(read.owner.status).toBe(200);
      expect(read.builder.status).toBe(200);
      expect(dayRows(read.owner, scope).map((row) => row.score)).toEqual(
        scoresOf(smaller),
      );
      expect(dayRows(read.builder, scope).map((row) => row.score)).toEqual(
        scoresOf(smaller),
      );
    }
    await restartWithMethods(["oura-browser"], []);
    for (const scope of SCOPES)
      expect(dayRows((await observe(scope)).owner, scope)).toHaveLength(1);
  });

  it("wholesale replacement: sequential three-stream replacements at one new horizon serve the exact smaller set", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    const smaller = DAYS.slice(0, 1);
    const newest = await mintAt(T_NEWEST);
    const replaced: Scope[] = [];
    for (const scope of SCOPES) {
      vi.setSystemTime(new Date(T_NEWEST));
      await replace(
        newest,
        STREAM_OF[scope],
        pdppRows(scope, smaller),
        T_NEWEST,
      );
      replaced.push(scope);
      if (replaced.length < SCOPES.length) {
        // Peer receipts still carry T_PDPP, so every replaced stream is refused.
        for (const done of replaced) {
          const read = await observe(done);
          expect(read.owner.status).toBe(503);
          expect(read.builder.status).toBe(503);
        }
      }
    }
    for (const scope of SCOPES) {
      const read = await observe(scope);
      expect(read.owner.status).toBe(200);
      expect(read.builder.status).toBe(200);
      expect(dayRows(read.owner, scope).map((row) => row.score)).toEqual(
        scoresOf(smaller),
      );
      expect(dayRows(read.builder, scope).map((row) => row.score)).toEqual(
        scoresOf(smaller),
      );
    }
    await restartWithMethods(["oura-browser"], []);
    for (const scope of SCOPES) {
      const stored = await ctx!.app.request(`/v1/data/${scope}?view=stored`, {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect((await stored.json()).data).toEqual(legacyBody(scope, DAYS));
    }
  });

  it("keeps earned canonical reads available after a partial refresh without completion receipts", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    const token = await writePdpp(DAYS, T_PDPP);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    const refreshedDays = [...DAYS, { n: 3, score: 91 }];
    await replace(
      token,
      "activity",
      pdppRows("oura.activity", refreshedDays),
      T_PDPP,
      { complete: false },
    );
    const refreshed = await observe("oura.activity");
    expect(refreshed.owner.status).toBe(200);
    expect(refreshed.owner.source).toBe("canonical");
    expect(
      dayRows(refreshed.builder, "oura.activity").map((row) => row.score),
    ).toEqual(refreshedDays.map((day) => day.score));
    for (const scope of ["oura.sleep", "oura.readiness"] as const) {
      await replace(token, STREAM_OF[scope], pdppRows(scope, DAYS), T_PDPP);
      expect((await observe("oura.activity")).owner.status).toBe(200);
    }
    const stored = await ctx!.app.request(
      "/v1/data/oura.activity?view=stored",
      { headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` } },
    );
    expect((await stored.json()).data).toEqual(
      legacyBody("oura.activity", DAYS),
    );
  });

  it("keeps every legacy scope at each mixed-run boundary until all three streams complete the same run", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(FILE));
    vi.setSystemTime(new Date(T_PDPP));
    const token = await ownerPdppToken();
    for (const scope of SCOPES) {
      await replace(token, STREAM_OF[scope], pdppRows(scope, DAYS), T_PDPP, {
        complete: false,
      });
      expect(await readAll(), `rows arrived for ${scope}`).toEqual(ALL(FILE));
    }
    for (const [index, scope] of SCOPES.entries()) {
      await replace(token, STREAM_OF[scope], pdppRows(scope, DAYS), T_PDPP);
      if (index === 0) {
        // Old receipts on untouched streams cannot complete this new run.
        for (const olderScope of SCOPES.slice(1)) {
          await replace(
            token,
            STREAM_OF[olderScope],
            pdppRows(olderScope, DAYS),
            T_LEGACY,
          );
          expect(
            await readAll(),
            `old completion arrived for ${olderScope}`,
          ).toEqual(ALL(FILE));
        }
      }
      expect(await readAll(), `completion arrived for ${scope}`).toEqual(
        ALL(index === SCOPES.length - 1 ? CANON : FILE),
      );
    }
    for (const scope of SCOPES) {
      const stored = await ctx!.app.request(`/v1/data/${scope}?view=stored`, {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect((await stored.json()).data).toEqual(legacyBody(scope, DAYS));
    }
  });

  it("automatically gives OpenPet all three complete scopes when opt-in admission is promoted", async () => {
    LEGACY_TS = true;
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    expect(await readAll()).toEqual(ALL(FILE));
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    for (const scope of SCOPES) {
      const stored = await ctx!.app.request(`/v1/data/${scope}?view=stored`, {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect(stored.status).toBe(200);
      expect((await stored.json()).data).toEqual(legacyBody(scope, DAYS));
    }
  });

  it("keeps all legacy scopes after promotion when the run has no completion receipts", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    vi.setSystemTime(new Date(T_PDPP));
    const token = await ownerPdppToken();
    for (const scope of SCOPES) {
      await replace(token, STREAM_OF[scope], pdppRows(scope, DAYS), T_PDPP, {
        complete: false,
      });
    }
    expect(await readAll()).toEqual(ALL(FILE));
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(FILE));
  });

  it("covers the real legacy fractional HRV defect while retaining integer projection", async () => {
    vi.setSystemTime(new Date(T_LEGACY));
    for (const scope of SCOPES) {
      const body = legacyBody(scope, DAYS) as Record<string, any>;
      if (scope === "oura.sleep") {
        for (const period of body.sleepPeriods) period.averageHrv = 48.6;
      }
      await legacyWrite(scope, body);
    }
    vi.setSystemTime(new Date(T_PDPP));
    const token = await ownerPdppToken();
    for (const scope of SCOPES) {
      const rows = pdppRows(scope, DAYS);
      if (scope === "oura.sleep") {
        for (const row of rows)
          if (row.record_type === "sleep_session") row.average_hrv = 48.6;
      }
      await replace(token, STREAM_OF[scope], rows, T_PDPP);
    }
    expect(await readAll()).toEqual(ALL(FILE));
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    const data = (
      (await observe("oura.sleep")).builder.body as {
        data: { sleepPeriods: { averageHrv: number }[] };
      }
    ).data;
    expect(data.sleepPeriods.every((period) => period.averageHrv === 49)).toBe(
      true,
    );
  });
});

describe("Oura collection requirements", () => {
  it.skipIf(!process.env.F2_NATIVE_PUBLICATION_ORACLE)(
    "recollects after empty native success and saved checkpoints with no retained history date",
    async () => {
      await restartWithMethods(["oura-browser"], []);
      const profile = JSON.parse(
        await readFile(
          join(
            process.env.F2_DESKTOP_SOURCE!,
            "src-tauri/tests/fixtures/oura-browser-0.1.41.collection-profile.json",
          ),
          "utf8",
        ),
      );
      const fixturePath = join(tempDir, "empty-native-upstream.json");
      const listener = createHttpServer(async (incoming, outgoing) => {
        const chunks: Buffer[] = [];
        for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
        const response = await ctx!.app.fetch(
          new Request(`http://localhost${incoming.url}`, {
            method: incoming.method,
            headers: incoming.headers as HeadersInit,
            ...(chunks.length ? { body: Buffer.concat(chunks) } : {}),
          }),
        );
        outgoing.writeHead(
          response.status,
          Object.fromEntries(response.headers),
        );
        outgoing.end(Buffer.from(await response.arrayBuffer()));
      });
      await new Promise<void>((resolve) =>
        listener.listen(0, "127.0.0.1", resolve),
      );
      try {
        const address = listener.address() as { port: number };
        const token = await ownerPdppToken();
        let state: unknown = {};
        const empty = {
          sleep: [],
          daily_sleep: [],
          daily_readiness: [],
          daily_activity: [],
        };
        const populated = {
          daily_sleep: DAYS.map(({ n, score }) => ({
            id: `ds${n}`,
            day: date(n),
            score,
            timestamp: ts(n),
            contributors: SLEEP_CONTRIB,
          })),
          sleep: pdppSleep(DAYS).filter(
            (row) => row.record_type === "sleep_session",
          ),
          daily_readiness: DAYS.map(pdppReadiness),
          daily_activity: DAYS.map(pdppActivity),
        };
        for (const [index, upstream] of [empty, empty, populated].entries()) {
          const requirements = await ctx!.app.request(
            "/v1/import/oura-browser/requirements",
            { headers: { authorization: `Bearer ${token}` } },
          );
          expect(requirements.status).toBe(200);
          const since = (await requirements.json()).since;
          expect(since).toBeNull();
          const at = `2026-10-${15 + index}T00:00:00.000Z`;
          await writeFile(
            fixturePath,
            JSON.stringify({ ...upstream, emittedAt: at }),
          );
          const child = spawn(
            process.env.F2_NATIVE_PUBLICATION_ORACLE!,
            [
              `http://127.0.0.1:${address.port}`,
              ctx!.devToken!,
              owner,
              process.execPath,
              join(
                process.env.F2_NATIVE_ORACLE_ROOT!,
                "signed-collector-runner.mjs",
              ),
              process.env.F2_OURA_SIGNED_CODE!,
              fixturePath,
            ],
            { stdio: ["pipe", "pipe", "pipe"] },
          );
          let stdout = "",
            stderr = "";
          child.stdout.on("data", (chunk) => {
            stdout += chunk;
          });
          child.stderr.on("data", (chunk) => {
            stderr += chunk;
          });
          child.stdin.end(
            JSON.stringify({
              generation: 1,
              profile,
              collectedAt: at,
              historySince: since,
              scope: {
                streams: SCOPES.map((scope) => ({ name: STREAM_OF[scope] })),
              },
              state,
            }),
          );
          const exit = await new Promise<number | null>((resolve, reject) => {
            child.once("error", reject);
            child.once("close", resolve);
          });
          expect(exit, stderr).toBe(0);
          const result = JSON.parse(stdout);
          expect(result.err, stdout + stderr).toBeUndefined();
          expect(result.ok.start.state).toBeNull();
          expect(result.ok.receipts).toHaveLength(3);
          expect(result.ok.records).toBe(index === 2 ? 8 : 0);
          state = result.ok.checkpoints;
          expect(Object.keys(state as object)).toHaveLength(3);
          if (index < 2) await restartWithMethods(["oura-browser"], []);
        }
        for (const scope of SCOPES) {
          const read = await observe(scope);
          expect(read.owner.status).toBe(200);
          expect(read.builder.status).toBe(200);
          expect(dayRows(read.owner, scope)).toHaveLength(2);
          expect(dayRows(read.builder, scope)).toHaveLength(2);
        }
      } finally {
        await new Promise<void>((resolve) => listener.close(() => resolve()));
      }
    },
  );
  it("accepts a minted source owner token for requirements before the first connection and after registration", async () => {
    const db = new Database(join(tempDir, "index.db"));
    try {
      db.prepare("DELETE FROM pdpp_instance_binding WHERE source_id = ?").run(
        OURA,
      );
    } finally {
      db.close();
    }
    vi.setSystemTime(new Date(T_LEGACY));
    const token = await mintSourceToken();
    const requirements = () =>
      ctx!.app.request("/v1/import/oura-browser/requirements", {
        headers: { authorization: `Bearer ${token}` },
      });
    const initial = await requirements();
    expect(initial.status, await initial.clone().text()).toBe(200);
    expect(await initial.json()).toEqual({
      ok: true,
      contract: "oura-legacy-takeover-v1",
      takeoverSelection: "unrestricted-three-streams-v1",
      since: null,
    });
    await registerAccount(token, accountOne, "oura-browser");
    await writeLegacy(DAYS, T_LEGACY);
    const connected = await requirements();
    expect(connected.status, await connected.clone().text()).toBe(200);
    expect(await connected.json()).toMatchObject({ since: "2026-09-01" });
    const arbitraryOwner = await ctx!.app.request("/v1/data/oura.activity", {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(arbitraryOwner.status).toBe(401);
    const importResponse = await ctx!.app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(importResponse.status).toBe(401);
  });

  it.skipIf(!process.env.F2_NATIVE_PUBLICATION_ORACLE)(
    "publishes the immutable signed collector through native supervision and HTTP before OpenPet takeover",
    async () => {
      const desktop = process.env.F2_DESKTOP_SOURCE!;
      const root = process.env.F2_NATIVE_ORACLE_ROOT!;
      const profile = JSON.parse(
        await readFile(
          join(
            desktop,
            "src-tauri/tests/fixtures/oura-browser-0.1.41.collection-profile.json",
          ),
          "utf8",
        ),
      );
      const historic = <T>(value: T): T =>
        JSON.parse(
          JSON.stringify(value).replaceAll("2026-09-01", "2025-01-01"),
        );
      vi.setSystemTime(new Date(T_LEGACY));
      for (const scope of SCOPES)
        await legacyWrite(scope, historic(legacyBody(scope, DAYS)));
      await restartWithMethods(["oura-browser"], []);
      expect(await readAll()).toEqual(ALL(FILE));
      const token = await ownerPdppToken();
      const requirements = await ctx!.app.request(
        "/v1/import/oura-browser/requirements",
        { headers: { authorization: `Bearer ${token}` } },
      );
      const since = (await requirements.json()).since;
      expect(since).toBe("2025-01-01");
      const fixtures = {
        emittedAt: T_PDPP,
        daily_sleep: historic(
          DAYS.map(({ n, score }) => ({
            id: `ds${n}`,
            day: date(n),
            score,
            timestamp: ts(n),
            contributors: SLEEP_CONTRIB,
          })),
        ),
        sleep: historic(
          pdppSleep(DAYS).filter((row) => row.record_type === "sleep_session"),
        ),
        daily_readiness: historic(DAYS.map(pdppReadiness)),
        daily_activity: historic(DAYS.map(pdppActivity)),
      };
      const fixturePath = join(tempDir, "upstream.json");
      await writeFile(fixturePath, JSON.stringify(fixtures));
      const listener = createHttpServer(async (incoming, outgoing) => {
        const chunks: Buffer[] = [];
        for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
        const response = await ctx!.app.fetch(
          new Request(`http://localhost${incoming.url}`, {
            method: incoming.method,
            headers: incoming.headers as HeadersInit,
            ...(chunks.length ? { body: Buffer.concat(chunks) } : {}),
          }),
        );
        outgoing.writeHead(
          response.status,
          Object.fromEntries(response.headers),
        );
        outgoing.end(Buffer.from(await response.arrayBuffer()));
      });
      await new Promise<void>((resolve) =>
        listener.listen(0, "127.0.0.1", resolve),
      );
      try {
        const address = listener.address() as { port: number };
        const invokeNative = async (collectedAt = T_PDPP) => {
          const native = spawn(
            process.env.F2_NATIVE_PUBLICATION_ORACLE!,
            [
              `http://127.0.0.1:${address.port}`,
              ctx!.devToken!,
              owner,
              process.execPath,
              join(root, "signed-collector-runner.mjs"),
              process.env.F2_OURA_SIGNED_CODE!,
              fixturePath,
            ],
            { stdio: ["pipe", "pipe", "pipe"] },
          );
          let stdout = "",
            stderr = "";
          native.stdout.on("data", (chunk) => {
            stdout += chunk;
          });
          native.stderr.on("data", (chunk) => {
            stderr += chunk;
          });
          native.stdin.end(
            JSON.stringify({
              generation: 1,
              profile,
              historySince: since,
              collectedAt,
              scope: {
                streams: SCOPES.map((scope) => ({
                  name: STREAM_OF[scope],
                  time_range: { since },
                })),
              },
              state: Object.fromEntries(
                SCOPES.map((scope) => [
                  STREAM_OF[scope],
                  {
                    api_v2: true,
                    account: "fixture-account",
                    next_day: "2026-10-21",
                    refresh_from: "2026-10-19",
                  },
                ]),
              ),
            }),
          );
          const exit = await new Promise<number | null>((resolve, reject) => {
            native.once("error", reject);
            native.once("close", resolve);
          });
          expect(exit, stderr).toBe(0);
          const result = JSON.parse(stdout);
          return { result, stdout, stderr };
        };
        const truncated = structuredClone(fixtures);
        truncated.daily_sleep = truncated.daily_sleep.filter(
          (row) => row.day !== "2025-01-01",
        );
        truncated.sleep = truncated.sleep.filter(
          (row) => row.day !== "2025-01-01",
        );
        truncated.daily_readiness = truncated.daily_readiness.filter(
          (row) => row.day !== "2025-01-01",
        );
        truncated.daily_activity = truncated.daily_activity.filter(
          (row) => row.day !== "2025-01-01",
        );
        await writeFile(fixturePath, JSON.stringify(truncated));
        const refused = await invokeNative();
        expect(refused.result.err).toContain("returned 409");
        expect(await readAll()).toEqual(ALL(FILE));
        await writeFile(fixturePath, JSON.stringify(fixtures));
        const { result, stdout, stderr } = await invokeNative();
        expect(result.err, stdout + stderr).toBeUndefined();
        expect(result.ok.receipts).toHaveLength(3);
        expect(result.ok.records).toBe(8);
        for (const checkpoint of Object.values(result.ok.checkpoints) as {
          requested_since: string;
        }[])
          expect(checkpoint.requested_since).toBe("2025-01-01");
        expect(await readAll()).toEqual(ALL(CANON));
        for (const scope of SCOPES) {
          const read = await observe(scope);
          expect(JSON.stringify(read.builder.body)).toContain("2025-01-01");
          const receipt = result.ok.receipts.find(
            (r: { scope: string }) => r.scope === scope,
          );
          expect(receipt.collectedAt).toBe(
            (read.owner.body as { collectedAt: string }).collectedAt,
          );
          expect(receipt.plaintextBytes).toBe(
            Buffer.byteLength(JSON.stringify(read.owner.body)),
          );
        }
        // A direct replacement can damage canonical state; a real native retry
        // must still plan and restore every retained entity after restart.
        for (const scope of SCOPES)
          await replace(
            token,
            STREAM_OF[scope],
            historic(pdppRows(scope, DAYS.slice(1))),
            T_PDPP,
          );
        await restartWithMethods(["oura-browser"], []);
        for (const scope of SCOPES) {
          const read = await observe(scope);
          expect(read.owner.status).toBe(503);
          expect(read.builder.status).toBe(503);
        }
        const retryPlan = await ctx!.app.request(
          "/v1/import/oura-browser/requirements",
          {
            headers: { authorization: `Bearer ${token}` },
          },
        );
        expect(retryPlan.status, await retryPlan.clone().text()).toBe(200);
        expect(await retryPlan.json()).toMatchObject({ since });
        await writeFile(
          fixturePath,
          JSON.stringify({ ...truncated, emittedAt: T_LEGACY_NEWER }),
        );
        expect((await invokeNative(T_LEGACY_NEWER)).result.err).toContain(
          "returned 409",
        );
        for (const scope of SCOPES)
          expect((await observe(scope)).owner.status).toBe(503);
        await writeFile(
          fixturePath,
          JSON.stringify({ ...fixtures, emittedAt: T_LEGACY_NEWER }),
        );
        const restored = await invokeNative(T_LEGACY_NEWER);
        expect(
          restored.result.err,
          restored.stdout + restored.stderr,
        ).toBeUndefined();
        expect(restored.result.ok.receipts).toHaveLength(3);
        for (const scope of SCOPES) {
          const read = await observe(scope);
          expect(read.owner.status).toBe(200);
          expect(read.builder.status).toBe(200);
          expect(JSON.stringify(read.builder.body)).toContain("2025-01-01");
          const receipt = restored.result.ok.receipts.find(
            (r: { scope: string }) => r.scope === scope,
          );
          expect(receipt.collectedAt).toBe(
            (read.owner.body as { collectedAt: string }).collectedAt,
          );
          expect(receipt.plaintextBytes).toBe(
            Buffer.byteLength(JSON.stringify(read.owner.body)),
          );
        }
      } finally {
        await new Promise<void>((resolve) => listener.close(() => resolve()));
      }
    },
  );

  it("refuses a guarded batch if canonical history advances during asynchronous preflight", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    const token = await writePdpp(DAYS, T_PDPP);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    const concurrent = [...DAYS, { n: 3, score: 91 }];
    const afterRead = async (scope: string) => {
      if (scope !== "oura.activity") {
        barrier.afterReadLatest = afterRead;
        return;
      }
      await writePdpp(concurrent, T_PDPP, token);
    };
    barrier.afterReadLatest = afterRead;
    const body = {
      collectedAt: T_PDPP,
      records: SCOPES.flatMap((scope) =>
        pdppRows(scope, DAYS).map((data) => ({
          stream: STREAM_OF[scope],
          data,
        })),
      ),
      selection: { streams: SCOPES.map((name) => ({ name })) },
      completion: {
        streams: SCOPES.map((scope) => ({
          stream: STREAM_OF[scope],
          status: "complete",
          recordCount: pdppRows(scope, DAYS).length,
        })),
      },
    };
    const response = await ctx!.app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      reason: "canonical_history_changed",
    });
    for (const scope of SCOPES)
      expect(dayRows((await observe(scope)).owner, scope)).toHaveLength(3);
  });

  it("accepts a complete current native batch with only its Oura source owner token", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    await restartWithMethods(["oura-browser"], []);
    const token = await mintSourceToken();
    const body = {
      native: {
        sourceId: OURA,
        instance: accountOne,
        method: "oura-browser",
        generation: 1,
        artifactDigest:
          "sha256:45d044af6e263a5121033df51f7ad5eaed1e19f1263cffe95ae63737259888c5",
      },
      collectedAt: T_PDPP,
      records: SCOPES.flatMap((scope) =>
        pdppRows(scope, DAYS).map((data) => ({
          stream: STREAM_OF[scope],
          data,
        })),
      ),
      selection: { streams: SCOPES.map((name) => ({ name })) },
      completion: {
        streams: SCOPES.map((scope) => ({
          stream: STREAM_OF[scope],
          status: "complete",
          recordCount: pdppRows(scope, DAYS).length,
        })),
      },
    };
    for (const patch of [
      { generation: 2 },
      { method: "oura" },
      { artifactDigest: "sha256:changed" },
      { sourceId: "https://example.invalid/sources/oura" },
    ]) {
      const refused = await ctx!.app.request("/v1/import/oura-browser", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ ...body, native: { ...body.native, ...patch } }),
      });
      expect(refused.status).toBe("sourceId" in patch ? 403 : 409);
      expect(await readAll()).toEqual(ALL(FILE));
    }
    const response = await ctx!.app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    expect((await response.json()).receipts).toHaveLength(3);
    expect(await readAll()).toEqual(ALL(CANON));
    expect(
      (
        await ctx!.app.request("/v1/data/oura.activity", {
          method: "DELETE",
          headers: { authorization: `Bearer ${token}` },
        })
      ).status,
    ).toBe(401);
  });

  it("keeps opt-in and incomplete phone batches on legacy, then admits one complete batch through canonical reads", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    const body = {
      collectedAt: T_PDPP,
      records: SCOPES.flatMap((scope) =>
        pdppRows(scope, DAYS).map((data) => ({
          stream: STREAM_OF[scope],
          data,
        })),
      ),
      selection: { streams: SCOPES.map((name) => ({ name })) },
      completion: {
        streams: SCOPES.map((scope) => ({
          stream: STREAM_OF[scope],
          status: "complete",
          recordCount: pdppRows(scope, DAYS).length,
        })),
      },
    };
    const post = (input: unknown) =>
      ctx!.app.request("/v1/import/oura-browser", {
        method: "POST",
        headers: {
          authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(input),
      });
    const optIn = await post(body);
    expect(optIn.status).toBe(409);
    expect(await optIn.json()).toMatchObject({ reason: "method_opt_in" });
    expect(await readAll()).toEqual(ALL(FILE));
    await restartWithMethods(["oura-browser"], []);
    const partial = structuredClone(body);
    partial.completion.streams.pop();
    expect((await post(partial)).status).toBe(409);
    expect(await readAll()).toEqual(ALL(FILE));
    const admitted = await post(body);
    expect(admitted.status, await admitted.clone().text()).toBe(200);
    expect(await readAll()).toEqual(ALL(CANON));
  });

  it("refuses a since-only owner batch that starts after the history it would replace", async () => {
    const signer = createTestWallet(12);
    await ctx!.cleanup();
    vi.stubEnv(
      "VANA_MASTER_KEY_SIGNATURE",
      await signer.signMessage("vana-master-key-v1"),
    );
    owner = signer.address.toLowerCase();
    accountOne = `oura:${owner}`;
    await freshBoot(["oura-browser"], []);
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    expect(await readAll()).toEqual(ALL(CANON));
    const requirements = await ctx!.app.request(
      "/v1/import/oura-browser/requirements",
      { headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` } },
    );
    expect(await requirements.json()).toMatchObject({ since: "2026-09-01" });
    const before = await Promise.all(SCOPES.map((scope) => observe(scope)));
    // Completed and empty: the batch would replace every current head with nothing.
    const body = {
      collectedAt: "2026-10-16T00:00:00.000Z",
      records: [],
      selection: {
        streams: SCOPES.map((name) => ({
          name,
          time_range: { since: "2026-10-01" },
        })),
      },
      completion: {
        streams: SCOPES.map((scope) => ({
          stream: STREAM_OF[scope],
          status: "complete",
          recordCount: 0,
        })),
      },
    };
    const uri = "/v1/import/oura-browser";
    const authorization = await buildWeb3SignedHeader({
      wallet: signer,
      aud: ctx!.config.server.origin,
      method: "POST",
      uri,
      body: new TextEncoder().encode(JSON.stringify(body)),
    });
    const refused = await ctx!.app.request(uri, {
      method: "POST",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(refused.status, await refused.clone().text()).toBe(409);
    expect(await refused.json()).toEqual({
      ok: false,
      reason: "selection_narrower_than_history",
    });
    expect(await Promise.all(SCOPES.map((scope) => observe(scope)))).toEqual(
      before,
    );
  });

  it("returns null only without history and refuses malformed Node history", async () => {
    const requirements = () =>
      ctx!.app.request("/v1/import/oura-browser/requirements", {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
    expect(await (await requirements()).json()).toEqual({
      ok: true,
      contract: "oura-legacy-takeover-v1",
      takeoverSelection: "unrestricted-three-streams-v1",
      since: null,
    });
    await legacyWrite("oura.activity", {
      days: [{ id: "bad-day", day: "2026-02-30", score: 80 }],
    });
    const malformed = await requirements();
    expect(malformed.status).toBeGreaterThanOrEqual(400);
    expect(await malformed.json()).not.toHaveProperty("since");
  });

  it("imports a signed owner phone batch into the real canonical store and returns served receipts to owner and OpenPet", async () => {
    const signer = createTestWallet(12);
    await ctx!.cleanup();
    vi.stubEnv(
      "VANA_MASTER_KEY_SIGNATURE",
      await signer.signMessage("vana-master-key-v1"),
    );
    owner = signer.address.toLowerCase();
    accountOne = `oura:${owner}`;
    await freshBoot(["oura-browser"], []);
    await writeLegacy(DAYS, T_LEGACY);
    await writePdpp(DAYS, T_PDPP);
    expect(await readAll()).toEqual(ALL(CANON));
    const changed = DAYS.map((day) => ({ ...day, score: day.score + 1 }));
    const body = {
      collectedAt: "2026-10-16T00:00:00.000Z",
      records: SCOPES.flatMap((scope) =>
        pdppRows(scope, changed).map((data) => ({
          stream: STREAM_OF[scope],
          data,
        })),
      ),
      selection: { streams: SCOPES.map((name) => ({ name })) },
      completion: {
        streams: SCOPES.map((scope) => ({
          stream: STREAM_OF[scope],
          status: "complete",
          recordCount: pdppRows(scope, changed).length,
        })),
      },
    };
    const uri = "/v1/import/oura-browser";
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    const authorization = await buildWeb3SignedHeader({
      wallet: signer,
      aud: ctx!.config.server.origin,
      method: "POST",
      uri,
      body: bytes,
    });
    const imported = await ctx!.app.request(uri, {
      method: "POST",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(imported.status, await imported.clone().text()).toBe(200);
    const success = await imported.json();
    expect(success.scopes).toEqual(SCOPES);
    for (const scope of SCOPES) {
      const current = await observe(scope);
      expect(current.owner.status).toBe(200);
      expect(current.owner.source).toBe("canonical");
      expect(dayRows(current.builder, scope).map((day) => day.score)).toEqual(
        changed.map((day) => day.score),
      );
      expect(
        success.receipts.find(
          (receipt: { scope: string }) => receipt.scope === scope,
        ),
      ).toEqual({
        scope,
        collectedAt: (current.owner.body as { collectedAt: string })
          .collectedAt,
        plaintextBytes: new TextEncoder().encode(
          JSON.stringify(current.owner.body),
        ).byteLength,
      });
    }
    const replayAuth = await buildWeb3SignedHeader({
      wallet: signer,
      aud: ctx!.config.server.origin,
      method: "POST",
      uri,
      body: bytes,
    });
    const replay = await ctx!.app.request(uri, {
      method: "POST",
      headers: {
        authorization: replayAuth,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    expect(await replay.json()).toEqual(success);
    const getUri = `${uri}/requirements`;
    const requirement = await ctx!.app.request(getUri, {
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: signer,
          aud: ctx!.config.server.origin,
          method: "GET",
          uri: getUri,
        }),
      },
    });
    expect(requirement.status).toBe(200);
    expect(await requirement.json()).toMatchObject({ since: "2026-09-01" });
    const refused = await ctx!.app.request(getUri, {
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: builder,
          aud: ctx!.config.server.origin,
          method: "GET",
          uri: getUri,
        }),
      },
    });
    expect(refused.status).toBe(401);
    const builderPost = await ctx!.app.request(uri, {
      method: "POST",
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: builder,
          aud: ctx!.config.server.origin,
          method: "POST",
          uri,
          body: bytes,
        }),
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    expect(builderPost.status).toBe(401);
    const tampered = await ctx!.app.request(uri, {
      method: "POST",
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: signer,
          aud: ctx!.config.server.origin,
          method: "POST",
          uri,
          body: bytes,
        }),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        ...body,
        collectedAt: "2026-10-17T00:00:00.000Z",
      }),
    });
    expect(tampered.status).toBe(401);
    const preflight = await ctx!.app.request(uri, {
      method: "OPTIONS",
      headers: {
        origin: "https://phone.test",
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    expect(preflight.status).toBe(204);
    expect(
      preflight.headers.get("access-control-allow-headers")?.toLowerCase(),
    ).toContain("authorization");
    const smaller = structuredClone(body);
    smaller.collectedAt = "2026-10-17T00:00:00.000Z";
    smaller.records = smaller.records.filter(
      (record) => record.data.day !== "2026-09-01",
    );
    smaller.completion.streams = smaller.completion.streams.map((proof) => ({
      ...proof,
      recordCount: smaller.records.filter(
        (record) => record.stream === proof.stream,
      ).length,
    }));
    const smallerBytes = new TextEncoder().encode(JSON.stringify(smaller));
    const replacement = await ctx!.app.request(uri, {
      method: "POST",
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: signer,
          aud: ctx!.config.server.origin,
          method: "POST",
          uri,
          body: smallerBytes,
        }),
        "content-type": "application/json",
      },
      body: JSON.stringify(smaller),
    });
    expect(replacement.status, await replacement.clone().text()).toBe(200);
    expect((await replacement.json()).receipts).toHaveLength(3);
    for (const scope of SCOPES) {
      const current = await observe(scope);
      expect(dayRows(current.owner, scope)).toHaveLength(DAYS.length - 1);
      expect(dayRows(current.builder, scope)).toHaveLength(DAYS.length - 1);
    }
    const refresh = structuredClone(body);
    refresh.collectedAt = "2026-10-18T00:00:00.000Z";
    const refreshBytes = new TextEncoder().encode(JSON.stringify(refresh));
    const refreshed = await ctx!.app.request(uri, {
      method: "POST",
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: signer,
          aud: ctx!.config.server.origin,
          method: "POST",
          uri,
          body: refreshBytes,
        }),
        "content-type": "application/json",
      },
      body: JSON.stringify(refresh),
    });
    expect(refreshed.status, await refreshed.clone().text()).toBe(200);
    for (const scope of SCOPES)
      expect(dayRows((await observe(scope)).builder, scope)).toHaveLength(
        DAYS.length,
      );
  });

  it("finds the aged legacy minimum and includes older current canonical days before each run", async () => {
    await writeLegacy(DAYS, T_LEGACY);
    const requirements = () =>
      ctx!.app.request("/v1/import/oura-browser/requirements", {
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
    expect((await requirements()).status).toBe(200);
    expect(await (await requirements()).json()).toEqual({
      ok: true,
      contract: "oura-legacy-takeover-v1",
      takeoverSelection: "unrestricted-three-streams-v1",
      since: "2026-09-01",
    });
    await writePdpp(DAYS, T_PDPP);
    await restartWithMethods(["oura-browser"], []);
    expect(await readAll()).toEqual(ALL(CANON));
    const expanded = [{ n: 0, score: 70 }, ...DAYS];
    // Use a valid earlier day, outside the stored legacy head.
    const token = await ownerPdppToken();
    for (const scope of SCOPES) {
      const rows = pdppRows(scope, expanded);
      for (const row of rows)
        if (row.day === "2026-09-00") row.day = "2026-08-31";
      await replace(token, STREAM_OF[scope], rows, T_PDPP);
    }
    expect(await (await requirements()).json()).toMatchObject({
      since: "2026-08-31",
    });
    expect(await readAll()).toEqual(ALL(CANON));
  });
});

describe("complete signed replacement", () => {
  for (const [name, days] of [
    ["fewer", DAYS.slice(1)],
    ["disjoint", [{ n: 7, score: 97 }]],
    ["empty", []],
  ] as [string, Day[]][])
    it(
      name + " complete signed replacement persists after restart",
      async () => {
        const signer = createTestWallet(7);
        vi.stubEnv(
          "VANA_MASTER_KEY_SIGNATURE",
          await signer.signMessage("vana-master-key-v1"),
        );
        owner = signer.address.toLowerCase();
        accountOne = "oura:" + owner;
        await freshBoot(["oura-browser"], []);
        await writeLegacy(DAYS, T_LEGACY);
        await writePdpp(DAYS, T_PDPP);
        expect(await readAll()).toEqual(ALL(CANON));
        const storedBefore: Record<string, unknown> = {};
        for (const scope of SCOPES) {
          const response = await ctx!.app.request(
            "/v1/data/" + scope + "?view=stored",
            { headers: { authorization: "Bearer " + CONTROL_PLANE_TOKEN } },
          );
          expect(response.status).toBe(200);
          storedBefore[scope] = await response.json();
        }
        const body = {
          collectedAt: "2026-10-17T00:00:00.000Z",
          records: SCOPES.flatMap((scope) =>
            pdppRows(scope, days).map((data) => ({
              stream: STREAM_OF[scope],
              data,
            })),
          ),
          selection: { streams: SCOPES.map((name) => ({ name })) },
          completion: {
            streams: SCOPES.map((scope) => ({
              stream: STREAM_OF[scope],
              status: "complete",
              recordCount: pdppRows(scope, days).length,
            })),
          },
        };
        const uri = "/v1/import/oura-browser";
        const post = async (input: typeof body) =>
          ctx!.app.request(uri, {
            method: "POST",
            headers: {
              authorization: await buildWeb3SignedHeader({
                wallet: signer,
                aud: ctx!.config.server.origin,
                method: "POST",
                uri,
                body: new TextEncoder().encode(JSON.stringify(input)),
              }),
              "content-type": "application/json",
            },
            body: JSON.stringify(input),
          });
        // Malformed completion is not a complete smaller snapshot.
        const snapshot = () => {
          const db = new Database(join(tempDir, "index.db"));
          try {
            return {
              records: db
                .prepare(
                  "SELECT * FROM pdpp_records ORDER BY instance,stream,record_key",
                )
                .all(),
              receipts: db
                .prepare(
                  "SELECT * FROM pdpp_stream_completion ORDER BY instance,stream",
                )
                .all(),
              files: db.prepare("SELECT * FROM data_files ORDER BY id").all(),
            };
          } finally {
            db.close();
          }
        };
        for (const mode of ["missing", "partial", "count"]) {
          const invalid = structuredClone(body);
          if (mode === "missing") invalid.completion.streams.pop();
          if (mode === "partial")
            invalid.completion.streams[0]!.status = "partial";
          if (mode === "count") invalid.completion.streams[0]!.recordCount += 1;
          const before = snapshot();
          expect((await post(invalid)).status).toBe(409);
          expect(snapshot()).toEqual(before);
          expect(await readAll()).toEqual(ALL(CANON));
        }
        const response = await post(body);
        expect(response.status, await response.clone().text()).toBe(200);
        const success = await response.json();
        expect(success.scopes).toEqual(SCOPES);
        expect(success.receipts).toHaveLength(3);
        const verify = async () => {
          for (const scope of SCOPES) {
            const current = await observe(scope);
            expect(current.owner.status).toBe(200);
            expect(current.owner.source).toBe("canonical");
            expect(current.builder.status).toBe(200);
            expect(current.builder.source).toBe("canonical");
            for (const read of [current.owner, current.builder]) {
              expect(dayRows(read, scope).map((row) => row.score)).toEqual(
                days.map((day) => day.score),
              );
              expect(dayRows(read, scope)).toHaveLength(days.length);
            }
            expect(
              success.receipts.find(
                (r: { scope: string }) => r.scope === scope,
              ),
            ).toEqual({
              scope,
              collectedAt: (current.owner.body as { collectedAt: string })
                .collectedAt,
              plaintextBytes: new TextEncoder().encode(
                JSON.stringify(current.owner.body),
              ).byteLength,
            });
            const stored = await ctx!.app.request(
              "/v1/data/" + scope + "?view=stored",
              { headers: { authorization: "Bearer " + CONTROL_PLANE_TOKEN } },
            );
            expect(stored.status).toBe(200);
            // Historical bytes are read by their indexed path below; current stored
            // head may legitimately be the newly written projection.
          }
          const listing = await ctx!.app.request("/v1/data", {
            headers: { authorization: "Bearer " + CONTROL_PLANE_TOKEN },
          });
          expect(listing.status).toBe(200);
          expect(
            (await listing.json()).scopes.map(
              (s: { scope: string }) => s.scope,
            ),
          ).toEqual(expect.arrayContaining([...SCOPES]));
          const db = new Database(join(tempDir, "index.db"));
          try {
            const receipts = db
              .prepare(
                "SELECT stream,generation,live_count,source_collected_at FROM pdpp_stream_completion WHERE instance=? ORDER BY stream",
              )
              .all(accountOne);
            expect(receipts).toEqual(
              body.completion.streams
                .map(({ stream, recordCount }) => ({
                  stream,
                  generation: 1,
                  live_count: recordCount,
                  source_collected_at: body.collectedAt,
                }))
                .sort((a, b) => a.stream.localeCompare(b.stream)),
            );
            const tombstones = db
              .prepare(
                "SELECT COUNT(*) AS n FROM pdpp_records WHERE instance=? AND deleted=1",
              )
              .get(accountOne) as { n: number };
            expect(tombstones.n).toBeGreaterThan(0);
            for (const scope of SCOPES) {
              const head = db
                .prepare(
                  "SELECT path FROM data_files WHERE scope=? ORDER BY id ASC LIMIT 1",
                )
                .get(scope) as { path: string };
              const stored = JSON.parse(
                await readFile(join(tempDir, "data", head.path), "utf8"),
              );
              expect(stored).toEqual(storedBefore[scope]);
            }
          } finally {
            db.close();
          }
        };
        await verify();
        await restartWithMethods(["oura-browser"], []);
        await verify();
      },
    );
});
