import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: {
    "import.meta.env.VITE_STATIC_DEMO": JSON.stringify(mode === "demo" ? "true" : process.env.VITE_STATIC_DEMO || ""),
  },
  server: {
    host: "0.0.0.0",
    port: 8050,
    proxy: {
      "/api": "http://localhost:8051",
    },
  },
}));
