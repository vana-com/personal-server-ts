import { defineReducerConformance } from "@opendatalabs/personal-server-ts-core/replication/policy-v3/reducer-conformance";
import { createLitePolicyV3Reducer } from "./replication-policy-v3.js";
defineReducerConformance("Lite", createLitePolicyV3Reducer);
