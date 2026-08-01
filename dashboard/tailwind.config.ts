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
        ink: "#070b14",
        panel: "#0e182a",
        teal: "#2ee6a6",
        amber: "#f0a202",
        rose: "#ff5d7a",
        sky: "#7ec8ff",
        mist: "#c5d4e8",
        mute: "#7f92ad",
      },
      fontFamily: {
        display: ["var(--font-display)", "Syne", "sans-serif"],
        mono: ["var(--font-body)", "IBM Plex Mono", "monospace"],
      },
      boxShadow: {
        glow: "0 0 40px rgba(46, 230, 166, 0.12)",
      },
    },
  },
  plugins: [],
};
export default config;