import './globals.css'
import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { Toaster } from 'react-hot-toast'
import { TelemetryProvider } from '@/components/providers/TelemetryProvider'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'RTK Elite - Professional Reconnaissance Toolkit',
  description: 'Elite security assessment framework with <1% false positives and real-time telemetry',
  keywords: 'security, reconnaissance, penetration testing, OWASP, NIST, elite hacking tools',
  authors: [{ name: 'RTK Elite Team' }],
  robots: 'noindex, nofollow', // Security tool - не индексируем
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-slate-950 text-green-400 overflow-x-hidden`}>
        <div className="matrix-bg fixed inset-0 opacity-5 pointer-events-none">
          <div className="matrix-rain"></div>
        </div>
        
        <TelemetryProvider>
          <div className="relative z-10 min-h-screen">
            {children}
          </div>
        </TelemetryProvider>
        
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#0f172a',
              color: '#10b981',
              border: '1px solid #10b981',
              borderRadius: '8px',
              fontFamily: 'JetBrains Mono, monospace',
            },
            success: {
              iconTheme: {
                primary: '#10b981',
                secondary: '#0f172a',
              },
            },
            error: {
              iconTheme: {
                primary: '#ef4444',
                secondary: '#0f172a',
              },
              style: {
                border: '1px solid #ef4444',
                color: '#ef4444',
              },
            },
          }}
        />
      </body>
    </html>
  )
}