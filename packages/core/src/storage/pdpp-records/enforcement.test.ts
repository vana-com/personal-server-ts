import { describe, it, expect } from "vitest";
import {
  resolveReadScope,
  recordWithinGrantTimeConstraint,
  recordKeyWithinGrantResources,
} from "./enforcement.js";
import { PdppError } from "../../errors/pdpp-catalog.js";
import type { PdppTokenContext, Grant } from "../../ports/pdpp-auth.js";
import type { StreamDeclaration } from "./stream-declaration.js";

const messagesDecl: StreamDeclaration = {
  name: "messages",
  semantics: "append_only",
  primaryKey: ["id"],
  cursorField: "source_created_at",
  requiredFields: ["id"],
};

function clientGrant(overrides: Partial<Grant["streams"][number]> = {}): Grant {
  return {
    version: "0.1.0",
    grant_id: "grant_1",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "sub_1" },
    client: { client_id: "client_1" },
    source: { kind: "provider_native", id: "src_1" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "messages",
        instance_ids: ["inst_1"],
        fields: ["id", "content"],
        ...overrides,
      },
    ],
  };
}

describe("resolveReadScope", () => {
  it("gives an owner token an unrestricted field projection", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "owner",
      subjectId: "sub_1",
    };
    const scope = resolveReadScope(context, "messages", messagesDecl);
    expect(scope.fields).toBeUndefined();
  });

  it("scopes a client token to the matching StreamGrant's fields and instance_ids", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
      grant: clientGrant(),
    };
    const scope = resolveReadScope(context, "messages", messagesDecl);
    expect(scope.instanceIds).toEqual(["inst_1"]);
    expect(scope.fields).toEqual(expect.arrayContaining(["id", "content"]));
  });

  it("always includes schema-required fields even if the grant omitted them", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
      grant: clientGrant({ fields: ["content"] }), // omits required "id"
    };
    const scope = resolveReadScope(context, "messages", messagesDecl);
    expect(scope.fields).toContain("id");
  });

  it("rejects a client token whose grant does not include the requested stream", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
      grant: { ...clientGrant(), streams: [] },
    };
    expect(() => resolveReadScope(context, "messages", messagesDecl)).toThrow(
      PdppError,
    );
    try {
      resolveReadScope(context, "messages", messagesDecl);
    } catch (err) {
      expect((err as PdppError).code).toBe("grant_stream_not_allowed");
      expect((err as PdppError).status).toBe(403);
    }
  });

  it("fails closed on a malformed grant with empty fields", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
      grant: clientGrant({ fields: [] }),
    };
    expect(() => resolveReadScope(context, "messages", messagesDecl)).toThrow(
      PdppError,
    );
  });

  it("rejects a client token with no resolved grant at all", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
    };
    try {
      resolveReadScope(context, "messages", messagesDecl);
      expect.unreachable();
    } catch (err) {
      expect((err as PdppError).code).toBe("grant_invalid");
    }
  });

  it("returns not_found for an undeclared stream", () => {
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "owner",
      subjectId: "sub_1",
    };
    try {
      resolveReadScope(context, "unknown_stream", undefined);
      expect.unreachable();
    } catch (err) {
      expect((err as PdppError).code).toBe("not_found");
    }
  });

  it("maps grant_revoked inactiveReason to a 403 grant_revoked error", () => {
    const context: PdppTokenContext = {
      active: false,
      tokenKind: "client",
      subjectId: "sub_1",
      inactiveReason: "grant_revoked",
    };
    try {
      resolveReadScope(context, "messages", messagesDecl);
      expect.unreachable();
    } catch (err) {
      expect((err as PdppError).code).toBe("grant_revoked");
      expect((err as PdppError).status).toBe(403);
    }
  });

  it("maps an unknown/inactive token to 401 authentication_error", () => {
    const context: PdppTokenContext = {
      active: false,
      tokenKind: "client",
      subjectId: "sub_1",
    };
    try {
      resolveReadScope(context, "messages", messagesDecl);
      expect.unreachable();
    } catch (err) {
      expect((err as PdppError).code).toBe("authentication_error");
      expect((err as PdppError).status).toBe(401);
    }
  });
});

describe("recordWithinGrantTimeConstraint", () => {
  it("excludes a record at or after the exclusive `until` bound", () => {
    const streamGrant = clientGrant({
      time_constraint: {
        field: "source_created_at",
        until: "2026-06-01T00:00:00Z",
      },
    }).streams[0];
    expect(
      recordWithinGrantTimeConstraint(
        { source_created_at: "2026-06-01T00:00:00Z" },
        streamGrant,
      ),
    ).toBe(false);
  });

  it("includes a record strictly before `until`", () => {
    const streamGrant = clientGrant({
      time_constraint: {
        field: "source_created_at",
        until: "2026-06-01T00:00:00Z",
      },
    }).streams[0];
    expect(
      recordWithinGrantTimeConstraint(
        { source_created_at: "2026-05-31T23:59:59Z" },
        streamGrant,
      ),
    ).toBe(true);
  });
});

describe("recordKeyWithinGrantResources", () => {
  it("allows any record when resources is absent", () => {
    const streamGrant = clientGrant().streams[0];
    expect(recordKeyWithinGrantResources("any_key", streamGrant)).toBe(true);
  });

  it("restricts to the resources allowlist when present", () => {
    const streamGrant = clientGrant({ resources: ["msg_1"] }).streams[0];
    expect(recordKeyWithinGrantResources("msg_1", streamGrant)).toBe(true);
    expect(recordKeyWithinGrantResources("msg_2", streamGrant)).toBe(false);
  });
});
