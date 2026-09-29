import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/web",
    emptyOutDir: true,
    cssTarget: ["chrome123", "firefox120", "safari17.5"],
  },
  test: {
    css: true,
    environment: "jsdom",
  },
});
