import { describe, expect, it } from "vitest";
import {
  ANTHROPIC_LIVE_BINDINGS,
  GITHUB_BROWSER_BINDINGS,
  LEGACY_SCOPE_BINDINGS,
  META_040_BINDINGS,
  OURA_BROWSER_BINDINGS,
  STRAVA_BROWSER_BINDINGS,
  legacyNamespacesOfSource,
  publicSourceForConnector,
} from "./index.js";

const SOURCES = "https://registry.pdpp.dev/sources/";
const CONNECTORS = "https://registry.pdpp.dev/connectors/";

describe("each connector collects its own public source", () => {
  it.each([
    ["anthropic", "claude_export"],
    ["anthropic-live", "claude"],
    ["oura", "oura_pat"],
    ["oura-browser", "oura"],
    ["strava", "strava_api"],
    ["strava-browser", "strava"],
  ])("%s collects sources/%s", (connector, source) => {
    expect(publicSourceForConnector(`${CONNECTORS}${connector}`)).toBe(
      `${SOURCES}${source}`,
    );
  });

  it("derives every other connector's source from its key", () => {
    expect(publicSourceForConnector(`${CONNECTORS}spotify`)).toBe(
      `${SOURCES}spotify`,
    );
  });

  it("gives no source two connectors, so no source can hold two methods", () => {
    const connectorsBySource = new Map<string, Set<string>>();
    for (const profile of [
      LEGACY_SCOPE_BINDINGS,
      ANTHROPIC_LIVE_BINDINGS,
      GITHUB_BROWSER_BINDINGS,
      META_040_BINDINGS,
      OURA_BROWSER_BINDINGS,
      STRAVA_BROWSER_BINDINGS,
    ]) {
      for (const binding of profile.values()) {
        const source = publicSourceForConnector(binding.pdppSource);
        const connectors = connectorsBySource.get(source) ?? new Set<string>();
        connectors.add(binding.pdppSource);
        connectorsBySource.set(source, connectors);
      }
    }
    const shared = [...connectorsBySource]
      .filter(([, connectors]) => connectors.size > 1)
      .map(([source]) => source);
    expect(shared).toEqual([]);
  });

  it.each([
    ["claude_export", "claude"],
    ["claude", "claude"],
    ["oura_pat", "oura"],
    ["oura", "oura"],
    ["strava_api", "strava"],
    ["strava", "strava"],
  ])("serves the %s source from the %s scope namespace", (source, ns) => {
    expect(legacyNamespacesOfSource(`${SOURCES}${source}`)).toEqual([ns]);
  });
});
