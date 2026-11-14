import type { ImportProjectionPort } from "../../../core/src/localdb/legacy-import-types.js";

/** Generic host catalogue; no global mocks or product identities. */
export const fixtureProjections: ImportProjectionPort = {
  bindings: new Map([
    ["fixture.profile", { connector: "profile-source", streams: ["profile"] }],
  ]),
};
