/**
 * The independent review's finding 1 repro, held as a standing regression.
 *
 * The finding (reviewed `e3a7142..5da38d0`): "a v0.2 grant containing only
 * `name` and a declaration requiring `id`: `resolveReadScope` returns
 * `['name', 'id']`. A v0.2 client can therefore receive a field it did not
 * approve."
 *
 * This file is the reviewer's exact repro, written as an oracle rather than a
 * narrative. It states the requirement (`v0.2-4-1`) in the assertion, and it
 * pairs the v0.2 case with the v0.1 case so a future "fix" that removes the
 * floor everywhere fails here rather than silently retiring v0.1's consent
 * floor.
 */

import { describe, expect, it } from "vitest";
import { resolveReadScope } from "./enforcement.js";
import {
  GRANT_VERSION_V02,
  type Grant,
  type PdppTokenContext,
} from "../../ports/pdpp-auth.js";
import type { StreamDeclaration } from "./stream-declaration.js";

/** Declares `id` as schema-required, and does not declare it as granted. */
const requiresId: StreamDeclaration = {
  name: "artists",
  semantics: "mutable_state",
  primaryKey: ["id"],
  cursorField: "source_updated_at",
  requiredFields: ["id"],
  declaredFields: ["id", "name", "genres"],
};

function grantApproving(version: string, fields: string[]): Grant {
  return {
    version,
    grant_id: "grant_review_1",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "sub_1" },
    client: { client_id: "client_1" },
    source: { kind: "connector", id: "src_1" },
    source_declaration: { version: "1" },
    purpose_code: "https://pdpp.dev/purpose/test",
    access_mode: "continuous",
    streams: [{ name: "artists", instance_ids: ["inst_1"], fields }],
  };
}

function clientContext(grant: Grant): PdppTokenContext {
  return {
    active: true,
    tokenKind: "client",
    subjectId: "sub_1",
    grant,
  };
}

describe("review finding 1 — v0.2 reads must not re-add schema-required fields", () => {
  it("does not add the declaration's required `id` to a v0.2 grant approving only `name`", () => {
    const scope = resolveReadScope(
      clientContext(grantApproving(GRANT_VERSION_V02, ["name"])),
      "artists",
      requiresId,
    );
    // `v0.2-4-1`: a field is not added merely because the schema requires it.
    expect(scope.fields).toEqual(["name"]);
    expect(scope.schemaRequiredFloor).toBe(false);
  });

  it("keeps the schema-required floor for the same shape under a v0.1 grant", () => {
    const scope = resolveReadScope(
      clientContext(grantApproving("0.1.0", ["name"])),
      "artists",
      requiresId,
    );
    // v0.1 §8's consent floor is unchanged: this is the behavior the v0.2
    // case must NOT inherit, and the one a blanket removal would break.
    expect(scope.fields).toEqual(expect.arrayContaining(["name", "id"]));
    expect(scope.schemaRequiredFloor).toBe(true);
  });
});
