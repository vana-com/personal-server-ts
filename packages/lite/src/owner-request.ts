import {
  createOwnerSignedPersonalServerRequest,
  type PersonalServerAuthRequestOptions,
  type PersonalServerOwnerAuth,
  type PersonalServerPostDataOptions,
} from "@opendatalabs/personal-server-ts-core/client";

/**
 * A request to the Personal Server, owner-signed or bearer-authorised when the
 * options carry an auth, plain otherwise. Shared by the Lite handle and
 * `createPersonalServerClient` so both build the same request.
 */
export async function createOwnerRequest(params: {
  origin: string;
  path: string;
  method: string;
  body?: unknown;
  authOptions: PersonalServerAuthRequestOptions | PersonalServerPostDataOptions;
  headers?: Record<string, string>;
}): Promise<Request> {
  const encoded =
    params.body === undefined
      ? undefined
      : new TextEncoder().encode(JSON.stringify(params.body));
  const auth = authFromOptions(params.authOptions);
  if (auth) {
    return createOwnerSignedPersonalServerRequest({
      origin: params.origin,
      path: params.path,
      method: params.method,
      body: encoded,
      auth,
      headers: params.headers,
    });
  }
  return new Request(`${params.origin}${params.path}`, {
    method: params.method,
    body: encoded,
    headers: params.headers,
  });
}

export function authFromOptions(
  options: PersonalServerAuthRequestOptions | PersonalServerPostDataOptions,
): PersonalServerOwnerAuth | undefined {
  if ("auth" in options && options.auth) return options.auth;
  if ("signMessage" in options) return { signMessage: options.signMessage };
  if ("bearerToken" in options) return { bearerToken: options.bearerToken };
  return undefined;
}
