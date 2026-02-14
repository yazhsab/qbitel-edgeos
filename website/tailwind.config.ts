import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        qedge: {
          bg: '#060b16',
          panel: '#111d33',
          line: '#2a4269',
          cyan: '#58f3ff',
          teal: '#47c4b8',
          amber: '#ffb64d',
          ink: '#dce9ff',
          muted: '#95accf',
        },
      },
      fontFamily: {
        sans: ['Sora', 'Space Grotesk', 'Avenir Next', 'Segoe UI', 'sans-serif'],
        mono: ['IBM Plex Mono', 'JetBrains Mono', 'Consolas', 'monospace'],
        display: ['Orbitron', 'Audiowide', 'Bank Gothic', 'sans-serif'],
      },
      boxShadow: {
        'signal-cyan': '0 0 30px rgba(88, 243, 255, 0.28)',
        'signal-amber': '0 0 32px rgba(255, 182, 77, 0.25)',
      },
      keyframes: {
        floaty: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
      },
      animation: {
        floaty: 'floaty 6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}

export default config
