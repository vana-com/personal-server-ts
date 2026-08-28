export {
  createTestWallet,
  buildWeb3SignedHeader,
  type TestWallet,
} from "./wallet.js";
export {
  createMemoryDataStorage,
  type MemoryDataStorage,
} from "./memory-storage.js";
export {
  TEST_VECTOR_SERVICE_PUBLIC_KEY_HEX,
  TEST_VECTOR_SERVICE_SEED,
  createFakeE2eeGateway,
  testVectorServiceKeyPair,
  type FakeE2eeGateway,
  type FakeE2eeGatewayOptions,
  type FakeE2eeGatewayRequest,
} from "./e2ee-gateway.js";
export {
  LIVE_ACI_ATTESTATION_CLOCK_S,
  LIVE_ACI_ATTESTATION_NONCE,
  LIVE_ACI_ATTESTATION_REPORT,
  LIVE_ACI_X25519_PUBLIC_KEY_HEX,
} from "./e2ee-fixtures.js";
