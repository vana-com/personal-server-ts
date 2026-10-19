/**
 * Client-token stream listings must not scan without bound.
 *
 * `GET /v1/streams` reports `record_count`/`last_updated` over only the
 * records a grant exposes. The grant predicate cannot be pushed into the
 * store (`time_constraint` is evaluated in JS against each record's data), so
 * counting exactly costs a full scan plus a JSON parse per row. Unbounded,
 * that makes the cheap metadata call more expensive than the data call it
 * summarizes, multiplied by the number of streams in the grant.
 *
 * These cases pin the two properties that keep it safe and honest:
 *   - past the cap, `record_count` is null WITH a warning — never a
 *     confidently wrong number a client cannot detect;
 *   - `last_updated` still answers, because it scans newest-first and stops
 *     at the first grant-visible row rather than walking the stream.
 *
 * Regression for a HIGH finding from the independent review of this lane's
 * own code: the first implementation walked up to 100,000 records and
 * returned the truncated count as if it were exact (measured 17.5s at 120k).
 */

import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";

/** Mirrors STREAM_COUNT_CAP in pdpp-records.ts. */
const CAP = 1_000;
const INSTANCE = "i1";
const AUTH = { Authorization: "Bearer t" };

const declarations = createStreamDeclarationRegistry([
  {
    name: "s",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    consentTimeField: "created_at",
    requiredFields: ["id"],
  },
]);

/**
 * `count` records, all inside the grant window. `emitted_at` increases with
 * the index, so the newest record is the last one seeded.
 */
function seed(count: number) {
  const store = createMemoryRecordStore();
  store.ingestBatch(
    Array.from({ length: count }, (_, i) => ({
      instance: INSTANCE,
      stream: "s",
      key: `r${i}`,
      data: {
        id: `r${i}`,
        name: `n${i}`,
        created_at: "2026-04-01T00:00:00.000Z",
      },
      // Zero-padded so lexical order matches numeric order.
      emitted_at: `2026-05-01T00:00:${String(i % 60).padStart(2, "0")}.${String(i).padStart(6, "0")}Z`,
    })),
    () => "mutable_state",
    () => ["id"],
  );
  return store;
}

const GRANT = {
  version: "0.1.0",
  grant_id: "g1",
  issued_at: "2026-01-01T00:00:00.000Z",
  subject: { id: "sub" },
  client: { client_id: "c1" },
  source: { kind: "connector" as const, id: "src" },
  source_declaration: { version: "v1" },
  purpose_code: "p",
  access_mode: "continuous" as const,
  streams: [
    {
      name: "s",
      instance_ids: [INSTANCE],
      fields: ["id", "name"],
      time_constraint: {
        field: "created_at",
        since: "2026-01-01T00:00:00.000Z",
      },
    },
  ],
};

const clientAuth: PdppAuthorizationService = {
  async resolveToken() {
    return {
      active: true,
      tokenKind: "client" as const,
      subjectId: "sub",
      grant: GRANT as never,
      clientId: "c1",
    };
  },
};

function app(count: number) {
  const a = new Hono();
  a.route(
    "/v1",
    pdppRecordsRoutes({
      store: seed(count),
      auth: clientAuth,
      declarations,
      instancesForSubject: () => [INSTANCE],
    }),
  );
  return a;
}

describe("client stream listing bounds its count", () => {
  it("reports an exact count at or below the cap", async () => {
    const res = await app(50).request("/v1/streams", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.data[0].record_count).toBe(50);
    expect(body.data[0].last_updated).toBeTruthy();
    // An exact count carries no truncation warning.
    expect(body.meta).toBeUndefined();
  });

  it("reports null with a warning rather than a wrong count past the cap", async () => {
    const res = await app(CAP + 25).request("/v1/streams", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();

    // Never a confidently wrong number: null is the honest answer.
    expect(body.data[0].record_count).toBeNull();
    expect(body.meta.warnings[0].code).toBe("record_count_not_counted");
    expect(body.meta.warnings[0].message).toContain("s");

    // `last_updated` still answers: it stops at the first visible row
    // scanning newest-first, so the cap does not blind it.
    expect(body.data[0].last_updated).toBeTruthy();
  });

  /**
   * REGRESSION for a HIGH found by the combined server review.
   *
   * The first bounded version capped the COUNT walk but left the
   * `last_updated` walk scanning up to 1000 pages of 100 rows. It exits early
   * only on the first grant-VISIBLE row, so a grant whose time_constraint
   * excludes the newest records walked every page: measured 25s at 100k rows
   * and 38s at 150k, versus 137ms for an all-visible grant at 60k. That
   * inverts the incentive — the filtering grant became the expensive one, and
   * one ordinary request with a time window excluding recent records was a
   * DoS.
   *
   * Here EVERY record is outside the grant window, which is exactly the
   * adversarial shape: the `last_updated` walk can never exit early.
   */
  it("stays responsive when the grant excludes every record", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      Array.from({ length: 20_000 }, (_, i) => ({
        instance: INSTANCE,
        stream: "s",
        key: `r${i}`,
        data: {
          id: `r${i}`,
          name: `n${i}`,
          // Before the grant's `since`, so nothing is ever visible.
          created_at: "2020-01-01T00:00:00.000Z",
        },
        emitted_at: `2026-05-01T00:00:${String(i % 60).padStart(2, "0")}.${String(i).padStart(6, "0")}Z`,
      })),
      () => "mutable_state",
      () => ["id"],
    );

    const a = new Hono();
    a.route(
      "/v1",
      pdppRecordsRoutes({
        store,
        auth: clientAuth,
        declarations,
        instancesForSubject: () => [INSTANCE],
      }),
    );

    const started = Date.now();
    const res = await a.request("/v1/streams", { headers: AUTH });
    const elapsedMs = Date.now() - started;

    expect(res.status).toBe(200);
    const body = await res.json();

    // Nothing is visible, and the scan was truncated — so the response must
    // NOT claim a confident count of 0, which would be indistinguishable
    // from a genuinely empty grant.
    expect(body.data[0].record_count).toBeNull();
    expect(body.meta.warnings[0].code).toBe("record_count_not_counted");
    // Machine-readable, so a client need not parse the prose.
    expect(body.meta.warnings[0].streams).toEqual(["s"]);

    expect(elapsedMs).toBeLessThan(5_000);
  });

  it("stays responsive on a stream far larger than the cap", async () => {
    const started = Date.now();
    const res = await app(20_000).request("/v1/streams", { headers: AUTH });
    const elapsedMs = Date.now() - started;

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data[0].record_count).toBeNull();

    // The pre-fix implementation scanned every record here. Generous bound so
    // this is not flaky on a loaded machine, but it fails loudly if the walk
    // ever becomes unbounded again.
    expect(elapsedMs).toBeLessThan(5_000);
  });
});
