import { expectTypeOf, it } from "vitest";
import type { PsLiteStoragePort } from "./storage.js";
import type { RetirementRows } from "@opendatalabs/personal-server-ts-core/localdb";

it("allows custom storage to omit retirementRows", () => {
  expectTypeOf<Pick<PsLiteStoragePort, "retirementRows">>().toEqualTypeOf<{
    readonly retirementRows?: RetirementRows;
  }>();
});
