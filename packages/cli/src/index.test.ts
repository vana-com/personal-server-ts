import { describe, expect, it } from "vitest";
import * as shared from "./index.js";
import * as lite from "./lite.js";
import * as node from "./node.js";

describe("personal-server-ts facade", () => {
  it("keeps the root entrypoint runtime-neutral", () => {
    expect(shared).toHaveProperty("PersonalServerClientError");
    expect(shared).toHaveProperty("createPersonalServerRegistrationRequest");
    expect(shared).toHaveProperty("grantRevokePath");
    expect(shared).not.toHaveProperty("startPersonalServer");
    expect(shared).not.toHaveProperty("createServer");
  });

  it("exposes runtime starters only from runtime-specific entrypoints", () => {
    expect(typeof node.startPersonalServer).toBe("function");
    expect(typeof node.createServer).toBe("function");
    expect(typeof lite.startPersonalServer).toBe("function");
  });
});
