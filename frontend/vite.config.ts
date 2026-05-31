import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend (FastAPI) localhost:8000 deer ajilна. /api bolon /ws-iig proxy hiine.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
});
