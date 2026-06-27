import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // jsdom gives the redirect guard a real window.location to resolve URLs against.
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
