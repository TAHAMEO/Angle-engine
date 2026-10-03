import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

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
      "no-restricted-imports": [
        "error",
        {
          paths: [
            { name: "next/font/google", message: "Fonts are vendored (next/font/local); no third-party requests." },
            { name: "next/image", message: "Evidence images are served sanitized by the API; use <img>." },
          ],
        },
      ],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  globalIgnores([".next/**", "out/**", "build/**", "next-env.d.ts", "src/lib/api/schema.d.ts", "playwright-report/**"]),
]);
