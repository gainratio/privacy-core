import { defineConfig, devices } from "@playwright/test";

/**
 * Headless-chromium e2e gate for the redact → send → rehydrate loop.
 *
 * The demo server is booted with VITE_USE_OPENROUTER=1 so the app selects the
 * OpenRouter path (via its same-origin dev proxy); the test intercepts the
 * request with `page.route` before it reaches the proxy, so nothing actually
 * leaves the machine. No API key is set — the interceptor stands in for the
 * network, and the real key never enters the browser in any case.
 */
export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: "list",
  use: {
    baseURL: "http://localhost:5173",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "pnpm --filter @gainratio/privacy-core-demo dev",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI,
    env: {
      VITE_USE_OPENROUTER: "1",
      VITE_OPENROUTER_MODEL: "openai/gpt-4o-mini",
    },
  },
});
