const BAD_REQUEST = 400;
const CONFLICT = 409;
const UNPROCESSABLE_CONTENT = 422;

export class AgentError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class OwnerMismatch extends AgentError {
  constructor() {
    super(
      "Owner does not match the delivery signature",
      UNPROCESSABLE_CONTENT,
      "OWNER_MISMATCH",
    );
  }
}

export class EpochRetired extends AgentError {
  constructor() {
    super("Requested epoch is retired", CONFLICT, "EPOCH_RETIRED");
  }
}

export class StaleDelivery extends AgentError {
  constructor() {
    super("Delivery timestamp is stale", BAD_REQUEST, "STALE_DELIVERY");
  }
}

export class DeliveryInvalid extends AgentError {
  constructor() {
    super("Delivery is invalid", BAD_REQUEST, "DELIVERY_INVALID");
  }
}

export class EnclaveAddressMismatch extends AgentError {
  constructor() {
    super(
      "Enclave address does not match",
      UNPROCESSABLE_CONTENT,
      "ENCLAVE_MISMATCH",
    );
  }
}
