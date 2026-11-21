import { defineReducerConformance } from "@opendatalabs/personal-server-ts-core/replication/policy-v3/reducer-conformance";
import { createNodePolicyV3Reducer } from "./pdpp-replication-policy-v3.js";
defineReducerConformance("Node", createNodePolicyV3Reducer);
