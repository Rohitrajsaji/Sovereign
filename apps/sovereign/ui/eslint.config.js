// Callers: `npm run lint` and `scripts/verify-ui.sh`.
// API: ESLint flat config for the Sovereign SPA.
// Schema: none. Bans `dangerouslySetInnerHTML` via `react/no-danger`.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Prioritize turning the existing SPA into the exceptional polished Sovereign UI specified by the plan, using the intended frontend stack and replacing placeholder frontend tooling with real tests/linting.

import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "../ui-dist/**", "e2e/**", "scripts/**"],
  },
  ...tseslint.configs.strict,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      react,
      "react-hooks": reactHooks,
      "jsx-a11y": jsxA11y,
      "react-refresh": reactRefresh,
    },
    settings: {
      react: { version: "detect" },
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.recommended.rules,
      "react/no-danger": "error",
      "react/jsx-no-target-blank": "error",
      "react-refresh/only-export-components": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
);
