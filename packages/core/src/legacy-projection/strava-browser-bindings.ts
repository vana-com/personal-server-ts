import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import type { LegacyScopeBinding } from "./types.js";

// Signed strava-browser 0.1.35 writes the export's activity fields, with
// freshness "live", plus start_date_local. The export binding is an identity
// over native records, so this profile reuses its projection unchanged.
// strava.coverage_diagnostics stays bound to the export method only: the
// browser method declares no diagnostics stream.
const source = "https://registry.pdpp.dev/connectors/strava-browser";
const digest =
  "sha256:026018b79ca78789326a6f14a88899e1f346cee04fcaba9afedc5b885f86804f";

const original = LEGACY_SCOPE_BINDINGS.get("strava.activities");
if (!original) throw new Error("Missing retained Strava activities binding");

const stravaBrowserActivities: LegacyScopeBinding = {
  ...original,
  pdppSource: source,
  fieldsRead: {
    activities: [...original.fieldsRead.activities, "start_date_local"],
  },
  lossy: [
    ...original.lossy.filter((item) => !item.startsWith("Coverage:")),
    "Coverage: the browser method writes no strava.coverage_diagnostics; that scope keeps serving the export method's rows or file.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/strava-browser:0.1.35",
      digest,
      path: "collection-profile.json#streams[name=activities]",
    },
  ],
};

export const STRAVA_BROWSER_BINDINGS: ReadonlyMap<string, LegacyScopeBinding> =
  new Map([["strava.activities", stravaBrowserActivities]]);
