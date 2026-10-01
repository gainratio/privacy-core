import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";

// Resolve the library's PUBLIC entry points from source so the demo runs without
// a prior `pnpm build` — and so it exercises exactly the published surface
// (the main barrel + the ./testing subpath), nothing internal.
const libRoot = fileURLToPath(new URL("../../src", import.meta.url));

export default defineConfig(({ mode }) => {
  // Load .env at config time (prefix "" so the NON-`VITE_` key is included). The
  // OpenRouter key is read here in the Node dev server and injected by the proxy
  // below; it is never `VITE_`-prefixed, so it never reaches the client bundle —
  // that server-side confinement is the whole point of the proxy.
  const env = loadEnv(mode, process.cwd(), "");
  const openRouterKey = env.OPENROUTER_API_KEY ?? "";

  return {
    resolve: {
      alias: [
        {
          find: /^@gainratio\/privacy-core\/testing$/,
          replacement: `${libRoot}/testing.ts`,
        },
        {
          find: /^@gainratio\/privacy-core$/,
          replacement: `${libRoot}/index.ts`,
        },
      ],
    },
    server: {
      // Same-origin dev proxy: the browser calls `/openrouter/*`, this Node
      // process rewrites to OpenRouter and injects the server-side Authorization
      // header. The real credential is never shipped to the browser.
      proxy: {
        "/openrouter": {
          target: "https://openrouter.ai",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/openrouter/, ""),
          headers: openRouterKey
            ? { authorization: `Bearer ${openRouterKey}` }
            : {},
        },
      },
    },
  };
});
