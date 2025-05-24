// eslint.config.ts
import eslint from "@eslint/js";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import perfectionist from "eslint-plugin-perfectionist";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  tseslint.configs.recommended,
  perfectionist.configs["recommended-alphabetical"],
  eslintConfigPrettier,
  {
    ignores: [
      "**/*.js",
      "dist/**", // Ignore compiled output
      "build/**", // Ignore build output
      "node_modules/**", // Ignore dependencies
      "**/*.d.ts", // Ignore all declaration files
    ],
  },
  {
    rules: {
      // Disable the problematic rule for now, or make it less strict
      "no-unused-private-class-members": "warn",
      // You can also completely disable it if needed:
      // 'no-unused-private-class-members': 'off',
    },
  },
);
