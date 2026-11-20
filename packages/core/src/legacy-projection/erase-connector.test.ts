import { describe, expect, it } from "vitest";
import {
  eraseLegacyScopesOf,
  legacyScopesOfConnector,
} from "./erase-connector.js";

describe("legacyScopesOfConnector", () => {
  it("names the data sets bound to a connector, and only those", () => {
    const oura = legacyScopesOfConnector("oura");
    expect(oura).toEqual(
      expect.arrayContaining(["oura.sleep", "oura.activity"]),
    );
    expect(oura.every((scope) => scope.startsWith("oura."))).toBe(true);
  });

  it("names nothing for a connector no binding names", () => {
    expect(legacyScopesOfConnector("no-such-connector")).toEqual([]);
  });
});

describe("eraseLegacyScopesOf", () => {
  it("deletes each bound scope of the connector and nothing else", async () => {
    const deleted: string[] = [];
    await eraseLegacyScopesOf("oura", {
      deleteScope: async (scope) => {
        deleted.push(scope);
        return 0;
      },
    });
    expect(deleted.sort()).toEqual(legacyScopesOfConnector("oura").sort());
    expect(deleted).not.toContain("spotify.playlists");
  });
});
