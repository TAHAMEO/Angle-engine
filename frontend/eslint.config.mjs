import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const restrictedImports = [
  { name: "next/font/google", message: "Fonts are vendored (next/font/local); no third-party requests." },
  { name: "next/image", message: "Evidence images are served sanitized by the API; use <img>." },
];
const zodImport = { name: "zod", message: 'Import { z } from "@/lib/zod" (jitless mode: no eval under the CSP).' };

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      // Never inject HTML: AI output and evidence are rendered from structured, escaped segments.
      "react/no-danger": "error",
      "no-restricted-syntax": [
        "error",
        { selector: "MemberExpression[property.name='innerHTML']", message: "Do not write innerHTML." },
        { selector: "MemberExpression[property.name='outerHTML']", message: "Do not write outerHTML." },
      ],
      "no-restricted-imports": ["error", { paths: [...restrictedImports, zodImport] }],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    files: ["src/lib/zod.ts"],
    rules: { "no-restricted-imports": ["error", { paths: restrictedImports }] },
  },
  {
    // Playwright fixtures call `use(...)`, which is not React's `use` hook.
    files: ["e2e/**/*.ts"],
    rules: { "react-hooks/rules-of-hooks": "off" },
  },
  globalIgnores([
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    "src/lib/api/schema.d.ts",
    "playwright-report/**",
    "test-results/**",
    "e2e/.auth/**",
  ]),
]);
