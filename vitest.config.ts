import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 120_000,
    hookTimeout: 60_000,
    include: [
      "packages/**/*.test.ts",
      "services/**/*.test.ts",
      "apps/**/*.test.ts",
      "tests/**/*.test.ts"
    ],
    exclude: ["**/node_modules/**", "**/dist/**", "**/.next/**"]
  },
  resolve: {
    alias: {
      "@indicative/config": path.resolve(__dirname, "packages/config/src/index.ts"),
      "@indicative/contracts": path.resolve(__dirname, "packages/contracts/src/index.ts"),
      "@indicative/security": path.resolve(__dirname, "packages/security/src/index.ts"),
      "@indicative/shared": path.resolve(__dirname, "packages/shared/src/index.ts"),
      "@indicative/database": path.resolve(__dirname, "packages/database/src/index.ts"),
      "@indicative/scanners": path.resolve(__dirname, "packages/scanners/src/index.ts"),
      "@indicative/cicd-security": path.resolve(__dirname, "packages/cicd-security/src/index.ts"),
      "@indicative/findings": path.resolve(__dirname, "packages/findings/src/index.ts"),
      "@indicative/ai": path.resolve(__dirname, "packages/ai/src/index.ts"),
      "@indicative/scanner-runner": path.resolve(__dirname, "services/scanner-runner/src/index.ts")
    }
  }
});
