/**
 * A real `GET /v1/aci/attestation?nonce=...` report captured from
 * https://inference.phala.com on 2026-08-28 (the TDX quote, event log,
 * app compose and vm config are omitted: they are not part of the
 * structural binding chain). The nonce below is the one the report was
 * requested with, so `report_data` recomputes from the keyset digest.
 */

export const LIVE_ACI_ATTESTATION_NONCE =
  "434fe0866976bf566484a1f11dbb0a55d9d4554b84f25ccd1ddd9095375722b1";

/** Unix seconds inside the fixture keyset's validity window. */
export const LIVE_ACI_ATTESTATION_CLOCK_S = 1788220800;

export const LIVE_ACI_X25519_PUBLIC_KEY_HEX =
  "408e82d159832cfae15007781bcade0badee7d50e9f76d50eaa1777464006537";

export const LIVE_ACI_ATTESTATION_REPORT = {
  api_version: "aci/1",
  workload_keyset_digest:
    "sha256:4f3dc45eeb18a5aefa49dfe5c0f2b6dbc77dd37276adc0cee87f1c1f70b73072",
  attestation: {
    tee_type: "tdx",
    workload_keyset: {
      subject: null,
      not_after: 1790498751,
      receipt_signing_keys: [
        {
          key_id: "dstack-kms-receipt-ed25519-v1",
          algo: "ed25519",
          public_key:
            "110f3824daeeef29dbeba9677a5794ffed257b1082d9fd4599b3c0819953aa0a",
        },
      ],
      e2ee_public_keys: [
        {
          key_id: "dstack-kms-e2ee-v1",
          algo: "secp256k1-aes-256-gcm-hkdf-sha256",
          public_key:
            "04943cea0b4babf60f6e2031e9a00866a37c4ae696fb45895b3a9b38ab8cbb898f42c85b704aceaa0a396cf26f7fdf79d83205be7e11d3a5d70419a68277158c3d",
        },
        {
          key_id: "dstack-kms-e2ee-x25519-v1",
          algo: "x25519-aes-256-gcm-hkdf-sha256",
          public_key:
            "408e82d159832cfae15007781bcade0badee7d50e9f76d50eaa1777464006537",
        },
      ],
      tls_public_keys: [
        {
          spki_sha256:
            "4586d125aaef3d1b33a3c34f12a5c235af3016dddd35e56a99b6b3ed3ba57dcb",
          domain: "tee.redpill.ai",
        },
        {
          spki_sha256:
            "8e89a8a01e12098065037be187dcd2f03071dc1e7c9bb8527160f4c56ebc728f",
          domain: "inference.phala.com",
        },
        {
          spki_sha256:
            "e52fdca52c039def33e51cd2b5eded43eae1949030e47866f5f09e90b6940a88",
          domain: "api.redpill.ai",
        },
      ],
    },
    report_data:
      "9ba90c1e314b8feb6c48be5de2f6b41d7174103056845e27d6e835c4202e5954",
    source_provenance: {
      repo_url: "https://github.com/Dstack-TEE/private-ai-gateway.git",
      repo_commit: "d567f6b4c4d93e33037ea202db04db86a8ad881c",
      image_digest: null,
      image_provenance: null,
    },
    evidence: {
      quote_report_data:
        "9ba90c1e314b8feb6c48be5de2f6b41d7174103056845e27d6e835c4202e59540000000000000000000000000000000000000000000000000000000000000000",
      key_custody: {
        provider: "dstack-kms",
        keys: [
          {
            role: "receipt",
            path: "aci/receipt-ed25519/v1",
            purpose: "aci.receipt.ed25519.v1",
            algo: "ed25519",
            public_key:
              "110f3824daeeef29dbeba9677a5794ffed257b1082d9fd4599b3c0819953aa0a",
            kms_public_key:
              "02f7fb3ed8c352d316dfdc19458a9f29c06eb7e74130b3808d784e2fd401a2c12d",
            signature_chain: [
              "d1f59335effc2688acdf502ee34d8d3373b0e7e6be493075383714ce5673a29973f224690437c483ae3fdd37172df3abad82877c4023ed7c5a64d5acaf18477c00",
              "5c2fe36bdb1e434c0a371579bcbce07c4e7b89eba45affa089191baec84f23ad77b24a594aa28427b6b7a5f348b0ecf5597abfd9a2add05ddb55c521ba38a38501",
            ],
          },
          {
            role: "e2ee-secp256k1",
            path: "aci/e2ee/v1",
            purpose: "aci.e2ee.v1",
            algo: "secp256k1-aes-256-gcm-hkdf-sha256",
            public_key:
              "04943cea0b4babf60f6e2031e9a00866a37c4ae696fb45895b3a9b38ab8cbb898f42c85b704aceaa0a396cf26f7fdf79d83205be7e11d3a5d70419a68277158c3d",
            kms_public_key:
              "03943cea0b4babf60f6e2031e9a00866a37c4ae696fb45895b3a9b38ab8cbb898f",
            signature_chain: [
              "452d6f86a807fef0ce0d65e6c5cd25a0a249b1fd8608d26c3efe17fc10346f4c2d3dfb8969d10dc1feac1d595b3816f63faa40ac370a3a233ce1d712d418c89701",
              "5c2fe36bdb1e434c0a371579bcbce07c4e7b89eba45affa089191baec84f23ad77b24a594aa28427b6b7a5f348b0ecf5597abfd9a2add05ddb55c521ba38a38501",
            ],
          },
          {
            role: "e2ee-x25519",
            path: "aci/e2ee-x25519/v1",
            purpose: "aci.e2ee.x25519.v1",
            algo: "x25519-aes-256-gcm-hkdf-sha256",
            public_key:
              "408e82d159832cfae15007781bcade0badee7d50e9f76d50eaa1777464006537",
            kms_public_key:
              "03892f86b3f55f78cc0760cec933cf8e2a92862fb173c2d221cc25895847cbb5eb",
            signature_chain: [
              "358cd661ca4f5e986ed950ca083bf7bcfef6ab4b839ca11a953b156d64f82b1c51a213730d5777b4c845170827680d41e8220c2f950a38081025ff16eb3789ba00",
              "5c2fe36bdb1e434c0a371579bcbce07c4e7b89eba45affa089191baec84f23ad77b24a594aa28427b6b7a5f348b0ecf5597abfd9a2add05ddb55c521ba38a38501",
            ],
          },
        ],
      },
      downstream_tls_binding: {
        domain: "inference.phala.com",
        spki_sha256:
          "8e89a8a01e12098065037be187dcd2f03071dc1e7c9bb8527160f4c56ebc728f",
      },
      quote: "<omitted in fixture>",
    },
  },
  service_capabilities: {
    supported_e2ee_versions: ["2"],
    serving: "aggregator",
  },
} as const;
