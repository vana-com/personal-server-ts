import "hono";
import type { GatewayGrantResponse } from "@opendatalabs/personal-server-ts-core/grants";
import type { AuthMechanism, RequestAuth } from "./middleware/web3-auth.js";

declare module "hono" {
  interface ContextVariableMap {
    auth: RequestAuth | undefined;
    grant: GatewayGrantResponse | undefined;
    authMechanism: AuthMechanism | undefined;
    isPolicyBypass: boolean | undefined;
    devBypass: boolean | undefined;
  }
}

export {};
