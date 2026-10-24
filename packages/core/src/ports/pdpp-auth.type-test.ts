/**
 * Compile-time checks of the PDPP authorization-server capability. `npm run
 * lint` fails if any `@ts-expect-error` below stops being an error.
 */
import type {
  PdppAuthorizationService,
  PdppTokenContext,
} from "./pdpp-auth.js";

const inactive: PdppTokenContext = {
  active: false,
  tokenKind: "client",
  subjectId: "",
};

/** A co-located AS must resolve synchronously. */
// @ts-expect-error -- a local AS without `resolveTokenNow`
export const localWithoutSyncResolution: PdppAuthorizationService = {
  locality: "local",
  resolveToken: async () => inactive,
};

/** An AS must say which kind it is; there is no implicit fallback. */
// @ts-expect-error -- no declared locality
export const undeclaredLocality: PdppAuthorizationService = {
  resolveToken: async () => inactive,
};

/** A remote AS is the explicit, asynchronous capability. */
export const remoteIntrospection: PdppAuthorizationService = {
  locality: "remote",
  resolveToken: async () => inactive,
};
