import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies API + health calls to the Rust backend so the browser
// talks to a single origin (no CORS dance during development).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8080",
      "/health": "http://localhost:8080",
    },
  },
});
