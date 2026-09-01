import { beforeAll, describe, expect, it } from "vitest";
import { MemoryFixtureSink, type FixtureSource } from "./sink.js";
import { generateCorpus, type CorpusManifest } from "./generate.js";
import {
  Q5_RESTAURANT,
  Q8_CONFLICT_MARKER,
  Q8_DOCUMENT_COUNT,
  Q8_UNREADABLE_COUNT,
} from "./planted.js";
import {
  scanLiteral,
  spotifySpan,
  timeAxisAudit,
} from "../reference/compute.js";
import { CORPUS_DAYS } from "./time.js";

let source: FixtureSource;
let manifest: CorpusManifest;

beforeAll(async () => {
  const sink = new MemoryFixtureSink();
  manifest = await generateCorpus(sink, { profile: "small" });
  source = sink;
}, 60_000);

describe("generateCorpus", () => {
  it("is byte-identical for the same seed", async () => {
    const a = new MemoryFixtureSink();
    const b = new MemoryFixtureSink();
    await generateCorpus(a, { profile: "lite", seed: 99 });
    await generateCorpus(b, { profile: "lite", seed: 99 });
    for (const file of await a.list()) {
      expect(await b.read(file)).toBe(await a.read(file));
    }
  }, 30_000);

  it("differs for a different seed", async () => {
    const a = new MemoryFixtureSink();
    const b = new MemoryFixtureSink();
    await generateCorpus(a, { profile: "lite", seed: 1 });
    await generateCorpus(b, { profile: "lite", seed: 2 });
    expect(await b.read("oura_sleep.json")).not.toBe(
      await a.read("oura_sleep.json"),
    );
  }, 30_000);

  it("emits every scope with records", () => {
    expect(manifest.scopes.length).toBeGreaterThanOrEqual(13);
    for (const scope of manifest.scopes) {
      expect(scope.records, `${scope.scope} is empty`).toBeGreaterThan(0);
    }
  });

  it("writes valid JSON for every file", async () => {
    for (const file of await source.list()) {
      const parsed = JSON.parse(await source.read(file)) as unknown;
      expect(Array.isArray(parsed), file).toBe(true);
    }
  });
});

describe("time axes", () => {
  // The whole point of the rewrite. The old generator spaced every source by a
  // fixed delta, compressing most of them into a fraction of the window.
  it("spreads every time-bearing source across the full window", async () => {
    const spans = [...(await timeAxisAudit(source)), await spotifySpan(source)];
    for (const span of spans) {
      expect(
        span.spanDays,
        `${span.scope} spans only ${span.spanDays} days`,
      ).toBeGreaterThan(CORPUS_DAYS * 0.9);
    }
  });

  it("gives ChatGPT conversations a multi-year spread", async () => {
    const spans = await timeAxisAudit(source);
    const chat = spans.find((s) => s.scope === "chatgpt.conversations");
    // The artifact this replaces produced ~10 days here.
    expect(chat!.spanDays).toBeGreaterThan(900);
  });
});

describe("planted facts", () => {
  it("plants the Q5 needle exactly once in the whole corpus", async () => {
    const scan = await scanLiteral(source, Q5_RESTAURANT);
    expect(scan.occurrences).toBe(1);
    expect(scan.files).toEqual(["slack_messages.json"]);
  });

  it("never emits the Q8 conflict marker", async () => {
    const scan = await scanLiteral(source, Q8_CONFLICT_MARKER);
    expect(scan.occurrences).toBe(0);
  });

  it("gives Q8 exact readable and unreadable counts", async () => {
    const docs = JSON.parse(await source.read("documents.json")) as {
      text_extracted: string | null;
    }[];
    expect(docs).toHaveLength(Q8_DOCUMENT_COUNT);
    expect(docs.filter((d) => d.text_extracted === null)).toHaveLength(
      Q8_UNREADABLE_COUNT,
    );
  });

  it("keeps the document count fixed across profiles", async () => {
    const lite = new MemoryFixtureSink();
    await generateCorpus(lite, { profile: "lite" });
    const docs = JSON.parse(await lite.read("documents.json")) as unknown[];
    expect(docs).toHaveLength(Q8_DOCUMENT_COUNT);
  }, 30_000);
});

describe("implicit rules the profiles have to describe", () => {
  it("emits multiple sleep periods on some days", async () => {
    const rows = JSON.parse(await source.read("oura_sleep.json")) as {
      type: string;
    }[];
    const naps = rows.filter((r) => r.type === "late_nap").length;
    expect(naps).toBeGreaterThan(0);
    expect(naps / rows.length).toBeLessThan(0.2);
  });

  it("emits all five Oura sleep types, including rest and deleted", async () => {
    const rows = JSON.parse(await source.read("oura_sleep.json")) as {
      type: string;
    }[];
    const types = new Set(rows.map((r) => r.type));
    expect(types.has("long_sleep")).toBe(true);
    expect(types.has("late_nap")).toBe(true);
    expect(types.has("rest")).toBe(true);
    expect(types.has("deleted")).toBe(true);
  });

  it("emits nullable total_sleep_duration", async () => {
    const rows = JSON.parse(await source.read("oura_sleep.json")) as {
      total_sleep_duration: number | null;
    }[];
    expect(rows.some((r) => r.total_sleep_duration === null)).toBe(true);
  });

  it("gives daily_sleep a score and no duration field", async () => {
    const rows = JSON.parse(
      await source.read("oura_daily_sleep.json"),
    ) as Record<string, unknown>[];
    expect(rows[0]).toHaveProperty("score");
    expect(rows[0]).toHaveProperty("contributors");
    expect(rows[0]).not.toHaveProperty("total_sleep_duration");
  });

  it("emits workout distances in metres with duplicate sessions", async () => {
    const rows = JSON.parse(await source.read("oura_workout.json")) as {
      day: string;
      distance: number;
      source: string;
    }[];
    expect(rows.some((r) => r.distance > 1000)).toBe(true);
    expect(new Set(rows.map((r) => r.source))).toEqual(
      new Set(["autodetected", "manual"]),
    );
    expect(rows.length).toBeGreaterThan(new Set(rows.map((r) => r.day)).size);
  });

  it("tags heart-rate samples with a source enum", async () => {
    const rows = JSON.parse(await source.read("oura_heartrate.json")) as {
      source: string;
    }[];
    const sources = new Set(rows.map((r) => r.source));
    expect(sources.has("workout")).toBe(true);
    expect(sources.has("sleep")).toBe(true);
  });

  it("emits audio, podcast and video rows sharing one schema", async () => {
    const files = (await source.list()).filter((f) =>
      f.startsWith("Streaming_History_Audio_"),
    );
    const rows = JSON.parse(await source.read(files[0]!)) as {
      master_metadata_track_name: string | null;
      episode_name: string | null;
      spotify_video_uri: string | null;
    }[];
    expect(rows.some((r) => r.master_metadata_track_name !== null)).toBe(true);
    expect(rows.some((r) => r.episode_name !== null)).toBe(true);
    expect(rows.some((r) => r.spotify_video_uri !== null)).toBe(true);
  });

  it("never emits the PII fields the real export carries", async () => {
    const files = (await source.list()).filter((f) =>
      f.startsWith("Streaming_History_Audio_"),
    );
    const rows = JSON.parse(await source.read(files[0]!)) as Record<
      string,
      unknown
    >[];
    for (const field of ["ip_addr", "user_agent", "username"]) {
      expect(rows[0]).not.toHaveProperty(field);
    }
  });

  it("ships the account-data streaming file with its own schema and one year of range", async () => {
    const rows = JSON.parse(
      await source.read("StreamingHistory_music_0.json"),
    ) as {
      endTime: string;
      msPlayed: number;
      trackName: string;
    }[];
    expect(rows[0]).toHaveProperty("endTime");
    expect(rows[0]).toHaveProperty("msPlayed");
    expect(rows[0]).not.toHaveProperty("ts");
    const days =
      (Date.parse(rows[rows.length - 1]!.endTime) -
        Date.parse(rows[0]!.endTime)) /
      86_400_000;
    expect(days).toBeLessThan(370);
  });

  it("emits nullable create_time and dict content parts in ChatGPT messages", async () => {
    const convs = JSON.parse(await source.read("conversations.json")) as {
      mapping: Record<
        string,
        {
          message: {
            create_time: number | null;
            content: { parts: unknown[] | null };
          } | null;
        }
      >;
    }[];
    const messages = convs.flatMap((c) =>
      Object.values(c.mapping).map((n) => n.message),
    );
    expect(messages.some((m) => m && m.create_time === null)).toBe(true);
    expect(messages.some((m) => m && m.content.parts === null)).toBe(true);
    expect(
      messages.some((m) =>
        m?.content.parts?.some((p) => typeof p === "object" && p !== null),
      ),
    ).toBe(true);
  });

  it("emits abandoned sibling branches in ChatGPT conversations", async () => {
    const convs = JSON.parse(await source.read("conversations.json")) as {
      mapping: Record<string, { children: string[] }>;
    }[];
    const branched = convs.filter((c) =>
      Object.values(c.mapping).some((n) => n.children.length > 1),
    );
    expect(branched.length).toBeGreaterThan(0);
  });
});
