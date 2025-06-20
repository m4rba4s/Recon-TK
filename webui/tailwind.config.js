/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        'elite': {
          50: '#f0f9ff',
          100: '#e0f2fe', 
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
        },
        'matrix': {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b',
        },
        'cyber': {
          50: '#fdf4ff',
          100: '#fae8ff',
          200: '#f5d0fe',
          300: '#f0abfc',
          400: '#e879f9',
          500: '#d946ef',
          600: '#c026d3',
          700: '#a21caf',
          800: '#86198f',
          900: '#701a75',
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'bounce-slow': 'bounce 2s infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'matrix-rain': 'matrix-rain 20s linear infinite',
        'scan-line': 'scan-line 3s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          'from': { 
            'box-shadow': '0 0 20px #10b981, 0 0 30px #10b981, 0 0 40px #10b981' 
          },
          'to': { 
            'box-shadow': '0 0 10px #10b981, 0 0 20px #10b981, 0 0 30px #10b981' 
          }
        },
        'matrix-rain': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' }
        },
        'scan-line': {
          '0%, 100%': { transform: 'translateX(-100%)' },
          '50%': { transform: 'translateX(100%)' }
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        'cyber': ['Orbitron', 'system-ui', 'sans-serif'],
      },
      backdropBlur: {
        xs: '2px',
      },
      boxShadow: {
        'glow-sm': '0 0 10px rgb(16, 185, 129)',
        'glow-md': '0 0 20px rgb(16, 185, 129)',
        'glow-lg': '0 0 30px rgb(16, 185, 129)',
        'cyber': '0 0 20px rgba(217, 70, 239, 0.5)',
        'elite': '0 0 25px rgba(14, 165, 233, 0.4)',
      }
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}