import { beforeAll, describe, expect, it } from "vitest";
import { MemoryFixtureSink, type FixtureSource } from "../fixtures/sink.js";
import { generateCorpus } from "../fixtures/generate.js";
import { DEFAULT_SEED } from "../fixtures/profiles.js";
import {
  absenceReference,
  anomalyReference,
  conditionalReference,
  identityReference,
  needleReference,
  recurringReference,
  scanLiteral,
  tripReference,
} from "./compute.js";
import { DISTINCT_PEOPLE } from "../fixtures/text.js";
import { Q5_SPEAKER_ALIAS } from "../fixtures/planted.js";

let source: FixtureSource;

beforeAll(async () => {
  const sink = new MemoryFixtureSink();
  await generateCorpus(sink, { profile: "small", seed: DEFAULT_SEED });
  source = sink;
}, 60_000);

describe("needleReference", () => {
  it("finds the single planted occurrence", async () => {
    const needle = await needleReference(source);
    expect(needle.occurrences).toBe(1);
    expect(needle.answer).toBe("Baan Saothong");
  });

  it("attributes it to the handle, not the display name", async () => {
    const needle = await needleReference(source);
    expect(needle.speakerAlias).toBe(Q5_SPEAKER_ALIAS);
  });

  it("places it far enough back that recency truncation misses it", async () => {
    const needle = await needleReference(source);
    expect(needle.daysBeforeEnd).toBeGreaterThan(900);
  });
});

describe("absenceReference", () => {
  it("counts readable and unreadable documents exactly", async () => {
    const absence = await absenceReference(source);
    expect(absence.documents).toBe(340);
    expect(absence.unreadable).toBe(22);
    expect(absence.readable).toBe(318);
  });

  it("confirms no conflicting agreement exists", async () => {
    const absence = await absenceReference(source);
    expect(absence.conflictMarkerOccurrences).toBe(0);
  });

  it("plants near-misses so a keyword scan alone is not enough", async () => {
    const absence = await absenceReference(source);
    expect(absence.nearMisses).toBeGreaterThanOrEqual(2);
  });
});

describe("identityReference", () => {
  it("resolves aliases to fewer people than raw handles", async () => {
    const identity = await identityReference(source);
    expect(identity.distinctPeople).toBeLessThanOrEqual(DISTINCT_PEOPLE);
    expect(identity.distinctAliases).toBeGreaterThan(identity.distinctPeople);
  });
});

describe("recurringReference", () => {
  it("detects the fixed-cadence subscriptions", async () => {
    const recurring = await recurringReference(source);
    expect(recurring.recurringMerchants).toContain("NETFLIX.COM");
    expect(recurring.recurringMerchants).toContain("RENT ACH");
  });

  it("detects the two that crept up and not the flat ones", async () => {
    const recurring = await recurringReference(source);
    const crept = recurring.crept.map((c) => c.merchant);
    expect(crept).toContain("NETFLIX.COM");
    expect(crept).toContain("SPOTIFY P0A2");
    expect(crept).not.toContain("RENT ACH");
  });
});

describe("anomalyReference", () => {
  it("detects the planted final-week excursion", async () => {
    const anomaly = await anomalyReference(source);
    expect(anomaly.deltaBpm).toBeGreaterThan(6);
    expect(anomaly.zScore).toBeGreaterThan(1);
  });
});

describe("tripReference", () => {
  it("includes the pre-paid flight charged outside the date window", async () => {
    const trip = await tripReference(source);
    expect(trip.flightUsd).toBeGreaterThan(1000);
    expect(trip.totalUsd).toBeGreaterThan(trip.inWindowOnlyUsd);
  });

  it("converts the JPY spend", async () => {
    const trip = await tripReference(source);
    expect(trip.jpyTransactions).toBeGreaterThan(20);
  });
});

describe("conditionalReference", () => {
  it("reports n for both sides of the join", async () => {
    const conditional = await conditionalReference(source);
    expect(conditional.matchedDays).toBeGreaterThan(0);
    expect(conditional.matchedDays + conditional.unmatchedDays).toBeGreaterThan(
      conditional.matchedDays,
    );
  });
});

describe("scanLiteral", () => {
  it("reports the bytes it scanned, so coverage is host-produced", async () => {
    const scan = await scanLiteral(source, "zzz-not-present-zzz");
    expect(scan.occurrences).toBe(0);
    expect(scan.bytesScanned).toBeGreaterThan(0);
  });
});
