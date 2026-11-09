/**
 * Test-only: boot a server and let its account-mode module hear an explicit
 * Off from the Account, as a host does after sign-in. Tests that exercise
 * legacy storage need this: with no answer the server refuses legacy work.
 */
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createServer,
  type CreateServerOptions,
  type ServerContext,
} from "../bootstrap.js";

export async function declareAccountMode(
  context: Pick<ServerContext, "accountModeAuthority" | "serverOwner">,
  state: "on" | "off",
): Promise<void> {
  const owner = context.serverOwner ?? "";
  await context.accountModeAuthority.submitEvidence({
    owner,
    state,
  });
}

export async function createUnswitchedServer(
  config: ServerConfig,
  options?: CreateServerOptions,
): Promise<ServerContext> {
  const context = await createServer(config, options);
  await declareAccountMode(context, "off");
  return context;
}
