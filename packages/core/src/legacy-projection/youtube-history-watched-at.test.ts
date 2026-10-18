import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import frozenSchema from "./legacy-schemas/youtube.history.json";
import { projectPdppRecordsToLegacyPayload } from "./index.js";

const row = (
  id: string,
  position: number,
  watched_date: string | null,
  watched_date_label?: string | null,
) => ({
  stream: "watch_history",
  data: {
    id,
    position,
    watched_date,
    ...(watched_date_label === undefined ? {} : { watched_date_label }),
    video_id: id,
    video_url: `https://youtube.com/watch?v=${id}`,
    video_title: "Video",
    channel_title: "Channel",
    channel_url: null,
    view_count: 3,
    description: null,
  },
});

describe("youtube.history watchedAt (frozen 1.1.0 contract)", () => {
  const project = (records: ReturnType<typeof row>[]) =>
    projectPdppRecordsToLegacyPayload("youtube.history", records, {
      fetchedStreams: ["watch_history"],
    });

  it("carries watched_date as both watchedAt and watchedAtText, null unchanged", () => {
    const result = project([row("a", 0, "2026-09-23"), row("b", 1, null)]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const history = result.payload.history as Record<string, unknown>[];
    expect(history[0]).toMatchObject({
      watchedAt: "2026-09-23",
      watchedAtText: "2026-09-23",
    });
    expect(history[1]).toMatchObject({ watchedAt: null, watchedAtText: null });
  });

  it("carries watched_date_label as watchedAtText and keeps watchedAt on watched_date", () => {
    const result = project([row("a", 0, "2026-09-23", "Yesterday")]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const history = result.payload.history as Record<string, unknown>[];
    expect(history[0]).toMatchObject({
      watchedAt: "2026-09-23",
      watchedAtText: "Yesterday",
    });
  });

  it("falls back to watched_date for watchedAtText only when the label is absent, null or empty", () => {
    const result = project([
      row("a", 0, "2026-09-23"),
      row("b", 1, "2026-09-22", null),
      row("c", 2, "2026-09-21", ""),
      row("d", 3, null, "Today"),
    ]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const texts = (result.payload.history as Record<string, unknown>[]).map(
      (entry) => entry.watchedAtText,
    );
    expect(texts).toEqual(["2026-09-23", "2026-09-22", "2026-09-21", "Today"]);
  });

  it("validates against the Vana-owned active schema, which is frozen 1.1.0", () => {
    expect(frozenSchema.version).toBe("1.1.0");
    const result = project([row("a", 0, "2026-09-23")]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const validate = new Ajv({ strict: false }).compile(
      frozenSchema.schema as Record<string, unknown>,
    );
    expect(validate(result.payload), JSON.stringify(validate.errors)).toBe(
      true,
    );
  });
});
