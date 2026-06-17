/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./src/**/*.{js,jsx,ts,tsx}", "./design/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        app: {
          background: "#F8FAFC",
          card: "#FFFFFF",
          border: "#E5E7EB",
          text: "#111827",
          muted: "#6B7280",
          primary: "#2563EB",
          success: "#22C55E",
          warning: "#F59E0B",
          danger: "#EF4444",
        },
      },
      boxShadow: {
        soft: "0 8px 24px rgba(15, 23, 42, 0.06)",
      },
      keyframes: {
        "progress-fill": {
          "0%": { transform: "scaleX(0)" },
          "100%": { transform: "scaleX(1)" },
        },
      },
      animation: {
        "progress-fill": "progress-fill 700ms ease-out both",
      },
    },
  },
  plugins: [],
};
