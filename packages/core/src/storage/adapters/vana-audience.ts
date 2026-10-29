import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import type { ServerAccount } from "../../keys/server-account.js";
import { StoredBlobConflictError, type StorageAdapter } from "./interface.js";

interface VanaBlobNamespace {
  endpoint: string;
  audience: string;
  chainId: number;
  owner: string;
  signer: Pick<ServerAccount, "signMessage">;
}

/**
 * The URL layout and Web3Signed authorization of one owner's blobs. A host
 * that moves the bytes itself (PS-Lite native transfers) signs with this, so
 * its requests match the adapter below.
 */
export function vanaBlobRequests(input: VanaBlobNamespace) {
  const prefix = `${input.endpoint}/v1/chains/${input.chainId}/blobs/${input.owner}/`;
  function validate(url: string) {
    const parsed = new URL(url);
    if (!parsed.href.startsWith(prefix) || /%(?:2f|5c)/i.test(parsed.pathname))
      throw new Error("Blob URL does not match configured namespace");
    return parsed;
  }
  return {
    urlForKey: (key: string) =>
      prefix + key.split("/").map(encodeURIComponent).join("/"),
    validate,
    authorization: (
      method: "PUT" | "GET" | "DELETE",
      url: string,
      body?: Uint8Array,
    ) =>
      buildWeb3SignedHeader({
        aud: input.audience,
        method,
        uri: validate(url).pathname,
        body,
        signMessage: (message) => input.signer.signMessage(message),
      }),
  };
}

/** SDK 3.x couples routing and authentication origins. This adapter supplies the
 * explicit audience needed by preview workers without rewriting a signed claim. */
export function createAudienceVanaAdapter(
  input: VanaBlobNamespace,
): StorageAdapter {
  const { urlForKey, validate, authorization: sign } = vanaBlobRequests(input);
  async function request(
    url: string,
    method: "PUT" | "GET" | "DELETE",
    body?: Uint8Array,
  ) {
    const parsed = validate(url);
    const authorization = await sign(method, url, body);
    const response = await fetch(parsed.href, {
      method,
      headers: {
        authorization,
        ...(body ? { "content-type": "application/octet-stream" } : {}),
      },
      body: body ? Uint8Array.from(body) : undefined,
      redirect: "error",
    });
    if (!response.ok && response.status !== 404) {
      await response.body?.cancel();
      if (method === "PUT" && response.status === 409)
        throw new StoredBlobConflictError(new URL(url).pathname);
      throw new Error(`Storage ${method} failed (${response.status})`);
    }
    return response;
  }
  return {
    urlForKey,
    async upload(key, bytes) {
      const url = urlForKey(key);
      const response = await request(url, "PUT", bytes);
      await response.body?.cancel();
      if (!response.ok) throw new Error("Storage upload not found");
      return url;
    },
    async download(url) {
      const response = await request(url, "GET");
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error("Storage blob not found");
      }
      return new Uint8Array(await response.arrayBuffer());
    },
    async delete(url) {
      const response = await request(url, "DELETE");
      await response.body?.cancel();
      return response.ok;
    },
    async exists(url) {
      validate(url);
      const response = await fetch(url, { method: "HEAD", redirect: "error" });
      await response.body?.cancel();
      if (response.status === 404) return false;
      if (!response.ok)
        throw new Error(`Storage probe failed (${response.status})`);
      return true;
    },
  };
}
