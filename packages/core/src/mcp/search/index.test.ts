import { describe, expect, it } from "vitest";
import { MiniSearchIndex, type SearchDocument } from "./index.js";

const documents: SearchDocument[] = [
  {
    id: "instagram-1",
    scope: "instagram.profile",
    source: "instagram",
    title: "Profile",
    text: "Ava builds ceramics and posts kiln notes.",
    preview: "Ava posts kiln notes",
    blockRef: "block://instagram/profile/1",
  },
  {
    id: "chatgpt-1",
    scope: "chatgpt.history",
    source: "chatgpt",
    title: "Chat history",
    text: "Planning notes about durable objects and workers.",
    preview: "Durable Objects planning",
    blockRef: "block://chatgpt/history/1",
  },
];

describe("MiniSearchIndex", () => {
  it("builds an index and finds matching documents", () => {
    const index = MiniSearchIndex.build(documents);

    const results = index.search({ query: "kiln" });

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      id: "instagram-1",
      scope: "instagram.profile",
      source: "instagram",
      title: "Profile",
      preview: "Ava posts kiln notes",
      blockRef: "block://instagram/profile/1",
    });
    expect(results[0].score).toBeGreaterThan(0);
    expect(results[0].terms).toContain("kiln");
  });

  it("adds documents after construction", () => {
    const index = MiniSearchIndex.empty();
    index.add([documents[0]]);

    expect(index.search({ query: "ceramics" })).toHaveLength(1);
    expect(index.search({ query: "durable" })).toHaveLength(0);

    index.add([documents[1]]);

    expect(index.search({ query: "durable" })).toHaveLength(1);
  });

  it("filters results by scope", () => {
    const index = MiniSearchIndex.build(documents);

    const results = index.search({
      query: "notes",
      scopes: ["chatgpt.history"],
    });

    expect(results.map((result) => result.id)).toEqual(["chatgpt-1"]);
  });

  it("round-trips through serialized storage", () => {
    const index = MiniSearchIndex.build(documents);
    const loaded = MiniSearchIndex.load(index.serialize());

    expect(loaded.search({ query: "workers" })[0]).toMatchObject({
      id: "chatgpt-1",
      scope: "chatgpt.history",
    });
  });

  it("indexes plain text documents without JSON/schema inference", () => {
    const index = MiniSearchIndex.build([
      {
        id: "plain-1",
        scope: "notes.plain",
        text: "free-form meeting transcript mentions quarterly billing",
      },
    ]);

    expect(index.search({ query: "quarterly billing" })[0]).toMatchObject({
      id: "plain-1",
      scope: "notes.plain",
    });
  });
});
