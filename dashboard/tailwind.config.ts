import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: "#132033",
        soft: "#3d4f63",
        mute: "#6b7c8f",
        accent: "#0f766e",
        paper: "#ffffff",
      },
      fontFamily: {
        display: ["var(--font-display)", "Syne", "sans-serif"],
        ui: ["var(--font-ui)", "Figtree", "sans-serif"],
        mono: ["var(--font-mono)", "IBM Plex Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;