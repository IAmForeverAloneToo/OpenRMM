import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build is embedded into the Go server binary (internal/server/web.go).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../internal/server/webui/dist",
    emptyOutDir: true,
    assetsDir: "assets",
    sourcemap: false,
    // Keep everything in hashed same-origin files: the CSP forbids inline script.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
});
