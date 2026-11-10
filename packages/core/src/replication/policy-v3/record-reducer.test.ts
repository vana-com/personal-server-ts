import { defineReducerConformance } from "./reducer-conformance.js";
import { createBoundedReplicaReducer } from "./record-reducer.js";
defineReducerConformance("portable", createBoundedReplicaReducer);
