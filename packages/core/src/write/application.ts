import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import type { WriterAttribution } from "./attribution.js";

/** Internal proof of policy and signature verification. Not a public factory. */
export interface VerifiedApplicationAuthority {
  readonly kind: "verified-application-authority";
}
export interface ApplicationAuthority {
  readonly scope: string;
  readonly owner: string;
  readonly builder: `0x${string}`;
  readonly grant?: GatewayGrantResponse;
  readonly attribution: WriterAttribution;
}
const authorities = new WeakMap<
  VerifiedApplicationAuthority,
  ApplicationAuthority
>();
export function verifiedApplicationAuthority(
  value: ApplicationAuthority,
): VerifiedApplicationAuthority {
  const token = Object.freeze({
    kind: "verified-application-authority" as const,
  });
  authorities.set(
    token,
    JSON.parse(JSON.stringify(value)) as ApplicationAuthority,
  );
  return token;
}
export function applicationAuthority(
  token: VerifiedApplicationAuthority,
): ApplicationAuthority {
  const value = authorities.get(token);
  if (!value) throw new Error("unverified application authority");
  return value;
}
