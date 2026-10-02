import { describe, expect, it } from "vitest";
import cases from "./__fixtures__/semantic-parity-gaps.json";
import hebInput from "./__fixtures__/heb.orders.pdpp-input.json";
import {
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import type { PdppRecord } from "./types.js";

const project = (scope: string, records: PdppRecord[]) =>
  projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams: LEGACY_SCOPE_BINDINGS.get(scope)?.pdppStreams ?? [],
  });

describe("production DCR semantic parity fixtures", () => {
  it("fails H-E-B order projection when a declaration-valid nullable product id cannot be represented", () => {
    expect(
      project("heb.orders", hebInput.records as PdppRecord[]),
    ).toMatchObject({
      ok: false,
      error: {
        kind: "incomplete_scope",
        scope: "heb.orders",
        reason: expect.stringContaining("order_items.product_id"),
      },
    });
  });

  it("fails Whole Foods orders instead of silently dropping a nullable product id", () => {
    expect(
      project("wholefoods.orders", cases["wholefoods.orders"] as PdppRecord[]),
    ).toMatchObject({
      ok: false,
      error: {
        kind: "incomplete_scope",
        scope: "wholefoods.orders",
        reason: expect.stringContaining("order_items.product_id"),
      },
    });
  });

  it("retains Instagram posts with the old collector's null sentinels", () => {
    expect(
      project("instagram.posts", cases["instagram.posts"] as PdppRecord[]),
    ).toMatchObject({
      ok: true,
      payload: {
        posts: [
          { img_url: "https://img.test/1", caption: "kept", num_of_likes: 2 },
          {
            img_url: "",
            caption: "nullable media is declared",
            num_of_likes: 0,
          },
        ],
      },
    });
    expect(project("instagram.posts", [])).toMatchObject({
      ok: true,
      payload: { posts: [] },
    });
  });

  it("fails authored GitHub history when required repository text is absent", () => {
    expect(
      project("github.history", cases["github.history"] as PdppRecord[]),
    ).toMatchObject({
      ok: false,
      error: {
        kind: "incomplete_scope",
        scope: "github.history",
        reason: expect.stringContaining("repository_full_name"),
      },
    });
  });

  it("uses fetched Spotify rows, converts bare IDs, and retains the missing URI sentinel", () => {
    expect(
      project("spotify.playlists", cases["spotify.playlists"] as PdppRecord[]),
    ).toMatchObject({
      ok: true,
      payload: {
        playlists: [
          {
            tracks_total: 2,
            tracks: [
              { uri: "spotify:track:11dFghVXANMlKmJXsNCbNl" },
              { uri: "" },
            ],
          },
        ],
      },
    });
  });

  it("retains Spotify saved-track sentinels from the browser collector", () => {
    expect(
      project(
        "spotify.savedTracks",
        cases["spotify.savedTracks"] as PdppRecord[],
      ),
    ).toMatchObject({
      ok: true,
      payload: {
        savedTracks: [
          {
            added_at: "",
            album: { name: "", artists: [] },
            duration_ms: 0,
            explicit: false,
            uri: "",
          },
        ],
        total: 1,
      },
    });
  });

  it("keeps YouTube browser history page order and the retained top-50 window", () => {
    const records = Array.from({ length: 51 }, (_, position) => ({
      stream: "watch_history",
      data: {
        id: `history-${position}`,
        position: 50 - position,
        watched_date: position === 0 ? "Yesterday" : "Today",
        video_id: `video-${position}`,
        video_url: `https://www.youtube.com/watch?v=video${position}`,
        video_title: `Video ${position}`,
        channel_title: `Channel ${position}`,
        view_count: position,
        description: `Description ${position}`,
      },
    })) as PdppRecord[];

    const result = project("youtube.history", records);
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;
    // copy-assertion-ok: timeWindow is a public DCR payload value emitted by the legacy collector.
    expect(result.payload).toMatchObject({
      timeWindow: "top 50 most recent items",
    });
    expect(result.payload.history as unknown[]).toHaveLength(50);
    expect(
      (result.payload.history as Record<string, unknown>[])[0],
    ).toMatchObject({
      videoId: "video-50",
    });
    expect(
      (result.payload.history as Record<string, unknown>[]).at(-1),
    ).toMatchObject({
      videoId: "video-1",
    });
  });

  it("keeps complete GitHub authored history when an assigned issue has unknown author", () => {
    expect(
      project(
        "github.history",
        cases["github.history.assigned"] as PdppRecord[],
      ),
    ).toMatchObject({
      ok: true,
      payload: {
        issues: [{ id: "issue-authored" }],
        pullRequests: [{ id: "pr-1" }],
      },
    });
  });

  it("projects product-linked grocery lines without reducing their counts", () => {
    const heb = (hebInput.records as PdppRecord[])
      .filter((r) => r.data.id !== "HEB12345|unknown-product")
      .map((r) =>
        r.stream === "orders"
          ? { ...r, data: { ...r.data, item_count: 1 } }
          : r,
      );
    expect(project("heb.orders", heb)).toMatchObject({
      ok: true,
      payload: {
        totalItems: 1,
        orders: [{ items: [{ productId: "12345678" }] }],
      },
    });
    const wholefoods = (cases["wholefoods.orders"] as PdppRecord[]).map((r) =>
      r.stream === "order_items"
        ? { ...r, data: { ...r.data, product_id: "B000000001" } }
        : r,
    );
    expect(project("wholefoods.orders", wholefoods)).toMatchObject({
      ok: true,
      payload: {
        totalItems: 1,
        orders: [{ items: [{ productId: "B000000001" }] }],
      },
    });
  });

  it("rejects purchase lines whose orders are absent instead of publishing reduced totals", () => {
    const orphan = {
      stream: "order_items",
      data: {
        id: "orphan",
        order_id: "missing",
        name: "Apples",
        product_id: "12345678",
      },
    } as PdppRecord;
    expect(
      project("heb.orders", [...(hebInput.records as PdppRecord[]), orphan]),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
    expect(
      project("wholefoods.orders", [
        { stream: "orders", data: { id: "order-1" } },
        orphan,
      ]),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
  });

  it("rejects Spotify child rows without a fetched parent playlist", () => {
    const orphan = {
      stream: "playlist_items",
      data: {
        id: "missing:1",
        playlist_id: "missing",
        track_id: null,
        position: 0,
        name: "Orphan",
      },
    } as PdppRecord;
    expect(
      project("spotify.playlists", [
        ...(cases["spotify.playlists"] as PdppRecord[]),
        orphan,
      ]),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "spotify.playlists" },
    });
  });
});
