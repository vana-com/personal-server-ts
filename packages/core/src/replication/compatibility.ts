import { getAddress } from "viem";

/** Reader requirements for writing the current fragment-address format. */
export const REPLICA_FRAGMENT_READER_FORMAT = "fragments-v2" as const;
export const REPLICA_READER_FORMATS = [
  "fragments-slash-v1",
  REPLICA_FRAGMENT_READER_FORMAT,
] as const;

export interface ReplicaCompatibilityDevice {
  address: string;
  name?: string | null;
  registrationId: string;
  revokedAt: string | null;
  readerFormats: readonly string[];
  /** Set only after the gateway verified the registration-bound signature. */
  capabilityValid: boolean;
}

/** The gateway must mark complete only after reading its full active roster. */
export interface ReplicaCompatibilityRoster {
  complete: boolean;
  epoch: number;
  devices: readonly ReplicaCompatibilityDevice[];
  /** Durable minimum set by the gateway once new-only publication is authorized. */
  minimumReaderFormats?: readonly string[];
}

export interface ReplicaPublicationBlocker {
  address: string;
  name: string;
  reason: "capability_unknown" | "reader_format_unsupported";
}

export class ReplicaPublicationBlockedError extends Error {
  readonly code = "replica_publication_blocked";

  constructor(readonly blockers: readonly ReplicaPublicationBlocker[]) {
    super("replica_publication_blocked");
    this.name = "ReplicaPublicationBlockedError";
  }
}

/** Refuse unknown, partial, or old rosters; offline status never removes a member. */
export function assertReplicaPublicationCompatible(
  roster: ReplicaCompatibilityRoster,
): { epoch: number; format: typeof REPLICA_FRAGMENT_READER_FORMAT } {
  if (
    !roster.complete ||
    !Number.isSafeInteger(roster.epoch) ||
    roster.epoch < 0 ||
    !Array.isArray(roster.devices) ||
    (roster.minimumReaderFormats !== undefined &&
      !Array.isArray(roster.minimumReaderFormats))
  )
    throw new Error("replica_roster_incomplete");

  const blockers = roster.devices
    .filter((device) => device.revokedAt === null)
    .flatMap((device) => {
      const reason: ReplicaPublicationBlocker["reason"] | undefined =
        !device.capabilityValid
          ? "capability_unknown"
          : device.readerFormats.includes(REPLICA_FRAGMENT_READER_FORMAT)
            ? undefined
            : "reader_format_unsupported";
      return reason
        ? [
            {
              address: device.address,
              name: device.name?.trim() || device.registrationId,
              reason,
            },
          ]
        : [];
    });
  if (blockers.length > 0) throw new ReplicaPublicationBlockedError(blockers);
  return { epoch: roster.epoch, format: REPLICA_FRAGMENT_READER_FORMAT };
}

export interface ReplicaCapabilitySigner {
  address: `0x${string}`;
  signMessage(message: string): Promise<`0x${string}`>;
}

/** Advertise this boot's reader support, then read one authoritative full roster. */
export function createGatewayReplicaCompatibility(input: {
  gatewayUrl: string;
  chainId: number;
  owner: `0x${string}`;
  signer: ReplicaCapabilitySigner;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  bootId?: string;
}): () => Promise<ReplicaCompatibilityRoster> {
  const gateway = input.gatewayUrl.replace(/\/+$/, "");
  const gatewayOrigin = new URL(input.gatewayUrl).origin;
  const owner = getAddress(input.owner);
  const serverAddress = getAddress(input.signer.address);
  const get = input.fetch ?? globalThis.fetch;
  const now = input.now ?? Date.now;
  const bootId =
    input.bootId ??
    Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
  let registrationId: string | undefined;
  let advertised: Promise<void> | undefined;
  const statementText = (statement: {
    owner: string;
    server: string;
    registrationId: string;
    bootId: string;
    revision: string;
    challenge: string;
    issuedAt: string;
    readerFormats: string[];
    gatewayOrigin: string;
    chainId: string;
  }) => `vana.replica-reader-capability.v1\n${JSON.stringify(statement)}`;

  async function json(response: Response) {
    if (!response.ok)
      throw new Error(`replica_compatibility_http_${response.status}`);
    return (await response.json()) as Record<string, unknown>;
  }

  async function advertise() {
    const address = serverAddress.toLowerCase();
    const challengeUrl = `${gateway}/v1/servers/${address}/replica-capabilities`;
    const challenge = await json(
      await get(challengeUrl, { headers: { accept: "application/json" } }),
    );
    if (
      typeof challenge.owner !== "string" ||
      challenge.owner.toLowerCase() !== owner.toLowerCase() ||
      typeof challenge.server !== "string" ||
      challenge.server.toLowerCase() !== address ||
      typeof challenge.registrationId !== "string" ||
      !/^0x[0-9a-f]{64}$/i.test(challenge.registrationId) ||
      typeof challenge.revision !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(challenge.revision) ||
      typeof challenge.challenge !== "string" ||
      !/^0x[0-9a-f]{64}$/i.test(challenge.challenge) ||
      typeof challenge.expiresAt !== "string" ||
      Date.parse(challenge.expiresAt) <= now() ||
      challenge.gatewayOrigin !== gatewayOrigin ||
      challenge.chainId !== String(input.chainId)
    )
      throw new Error("replica_capability_challenge_invalid");
    registrationId = challenge.registrationId;
    const statement = {
      owner,
      server: serverAddress,
      registrationId: challenge.registrationId,
      bootId,
      revision: (BigInt(challenge.revision) + 1n).toString(),
      challenge: challenge.challenge,
      issuedAt: new Date(now()).toISOString(),
      readerFormats: [...REPLICA_READER_FORMATS],
      gatewayOrigin,
      chainId: String(input.chainId),
    };
    const signature = await input.signer.signMessage(statementText(statement));
    const accepted = await get(challengeUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ ...statement, signature }),
    });
    await json(accepted);
  }

  const check = async (
    selfRefreshAttempted = false,
  ): Promise<ReplicaCompatibilityRoster> => {
    if (!advertised) {
      advertised = advertise().catch((error) => {
        advertised = undefined;
        throw error;
      });
    }
    await advertised;

    const rosterBody = await json(
      await get(
        `${gateway}/v1/replica-compatibility?owner=${encodeURIComponent(owner)}`,
        { headers: { accept: "application/json" } },
      ),
    );
    if (
      rosterBody.complete !== true ||
      typeof rosterBody.owner !== "string" ||
      rosterBody.owner.toLowerCase() !== owner.toLowerCase() ||
      typeof rosterBody.epoch !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(rosterBody.epoch) ||
      !Array.isArray(rosterBody.devices)
    )
      throw new Error("replica_roster_incomplete");
    const epoch = Number(rosterBody.epoch);
    if (!Number.isSafeInteger(epoch))
      throw new Error("replica_roster_incomplete");
    const devices = rosterBody.devices.map(
      (raw): ReplicaCompatibilityDevice => {
        if (!raw || typeof raw !== "object")
          throw new Error("replica_roster_incomplete");
        const row = raw as Record<string, unknown>;
        if (
          typeof row.address !== "string" ||
          !/^0x[0-9a-f]{40}$/i.test(row.address) ||
          typeof row.registrationId !== "string" ||
          !/^0x[0-9a-f]{64}$/i.test(row.registrationId) ||
          row.revokedAt !== null ||
          typeof row.capabilityValid !== "boolean" ||
          (row.readerFormats !== null &&
            (!Array.isArray(row.readerFormats) ||
              !row.readerFormats.every((f) => typeof f === "string")))
        )
          throw new Error("replica_roster_incomplete");
        return {
          address: row.address,
          name: typeof row.name === "string" ? row.name : null,
          registrationId: row.registrationId,
          revokedAt: null,
          readerFormats: Array.isArray(row.readerFormats)
            ? (row.readerFormats as string[])
            : [],
          capabilityValid: row.capabilityValid,
        };
      },
    );
    const self = devices.find(
      (device) => device.address.toLowerCase() === serverAddress.toLowerCase(),
    );
    const selfDeclarationStale =
      !self ||
      self.registrationId.toLowerCase() !== registrationId!.toLowerCase() ||
      !self.capabilityValid;
    if (selfDeclarationStale && selfRefreshAttempted) {
      advertised = undefined;
      registrationId = undefined;
      throw new Error("replica_self_registration_changed");
    }
    if (selfDeclarationStale) {
      advertised = undefined;
      registrationId = undefined;
      return check(true);
    }
    const roster: ReplicaCompatibilityRoster = {
      complete: true,
      epoch,
      devices,
      minimumReaderFormats: Array.isArray(rosterBody.minimumReaderFormats)
        ? rosterBody.minimumReaderFormats.filter(
            (f): f is string => typeof f === "string",
          )
        : undefined,
    };
    const decision = assertReplicaPublicationCompatible(roster);
    const authorization = {
      owner,
      server: serverAddress,
      registrationId: registrationId!,
      expectedEpoch: String(decision.epoch),
      writeFormat: decision.format,
      gatewayOrigin,
      chainId: String(input.chainId),
    };
    const signature = await input.signer.signMessage(
      `vana.replica-publication-authorization.v1\n${JSON.stringify(authorization)}`,
    );
    const activationResponse = await get(
      `${gateway}/v1/replica-compatibility`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ ...authorization, signature }),
      },
    );
    const activated = (await activationResponse.json()) as Record<
      string,
      unknown
    >;
    if (!activationResponse.ok) {
      if (
        activated.error === "Writer registration is not active" ||
        activated.error === "Invalid publication authorization signature"
      ) {
        advertised = undefined;
        registrationId = undefined;
      }
      if (
        activated.error === "replica_publication_blocked" &&
        Array.isArray(activated.blockers)
      ) {
        const blockers = activated.blockers.flatMap((raw) => {
          if (!raw || typeof raw !== "object") return [];
          const row = raw as Record<string, unknown>;
          if (
            typeof row.address !== "string" ||
            typeof row.registrationId !== "string"
          )
            return [];
          return [
            {
              address: row.address,
              name: row.registrationId,
              reason: "capability_unknown" as const,
            },
          ];
        });
        throw new ReplicaPublicationBlockedError(blockers);
      }
      throw new Error(
        activated.error === "replica_epoch_changed"
          ? "replica_epoch_changed"
          : `replica_compatibility_http_${activationResponse.status}`,
      );
    }
    if (
      activated.success !== true ||
      typeof activated.epoch !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(activated.epoch) ||
      !Array.isArray(activated.minimumReaderFormats) ||
      !activated.minimumReaderFormats.includes(decision.format)
    )
      throw new Error("replica_publication_authorization_invalid");
    const authorizedEpoch = Number(activated.epoch);
    if (!Number.isSafeInteger(authorizedEpoch))
      throw new Error("replica_publication_authorization_invalid");
    return {
      ...roster,
      epoch: authorizedEpoch,
      minimumReaderFormats: activated.minimumReaderFormats as string[],
    };
  };
  return () => check();
}
