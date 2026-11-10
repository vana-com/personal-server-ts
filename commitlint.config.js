import conventional from "@commitlint/config-conventional";

export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [2, "always", [...conventional.rules["type-enum"][2], "ps2"]],
  },
};
