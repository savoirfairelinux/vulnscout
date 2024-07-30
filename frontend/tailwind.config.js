/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'selector',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'sfl': {
          'light': '#56b0c9',
          'dark': '#1d799e',
        }
      }
    },
  },
  plugins: [],
}
