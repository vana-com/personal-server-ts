import type { PsLiteRuntimeOptions } from "../runtime.js";

export function createMockPsLiteGateway(): NonNullable<
  PsLiteRuntimeOptions["gateway"]
> {
  return {
    async listGrantsByUser() {
      return [];
    },
    async getBuilder() {
      return null;
    },
    async createGrant() {
      return { grantId: "grant-1" };
    },
    async isRegisteredBuilder() {
      return false;
    },
    async getGrant() {
      return null;
    },
    async getSchemaForScope(scope) {
      return {
        id: "0xschema1",
        ownerAddress: "0xOwner",
        name: scope,
        definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
        scope,
        addedAt: "2026-05-08T00:00:00.000Z",
      };
    },
    async getServer() {
      return null;
    },
    async getDataPoint() {
      return null;
    },
    async listDataPointsByOwner() {
      return { dataPoints: [], cursor: null };
    },
    async getSchema() {
      return null;
    },
    async registerServer() {
      return { alreadyRegistered: false };
    },
    async registerDataPoint() {
      return { dataPointId: "data-point-1" };
    },
    async revokeGrant() {},
  };
}
