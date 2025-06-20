'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Terminal, Zap, Shield, Target, Activity, Cpu, Database, Network } from 'lucide-react'
import { EliteHeader } from '@/components/layout/EliteHeader'
import { EliteStats } from '@/components/dashboard/EliteStats'
import { RealTimeTelemetry } from '@/components/telemetry/RealTimeTelemetry'
import { ScanControl } from '@/components/scan/ScanControl'
import { EliteModules } from '@/components/modules/EliteModules'
import { useTelemetry } from '@/components/providers/TelemetryProvider'

export default function HomePage() {
  const { telemetryData } = useTelemetry()
  const [isScanning, setIsScanning] = useState(false)

  const handleScanStart = () => {
    setIsScanning(true)
    // Simulation - в реальности запрос к backend
    setTimeout(() => setIsScanning(false), 30000)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <EliteHeader />
      
      <main className="container mx-auto px-6 py-8">
        {/* Hero Section */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="text-center mb-12"
        >
          <h1 className="text-6xl font-bold mb-4 title-gradient cyber-text">
            RTK ELITE
          </h1>
          <p className="text-xl text-green-300 mb-2">
            Professional Reconnaissance Toolkit
          </p>
          <p className="text-green-600 mb-8">
            &lt;1% False Positives • OWASP/NIST Compliant • Real-time Telemetry
          </p>
          
          {/* Live Status Indicator */}
          <div className="flex items-center justify-center gap-4 mb-8">
            <div className="live-indicator">
              <div className="live-dot"></div>
              <span className="text-green-400 font-semibold">SYSTEM ONLINE</span>
            </div>
            <div className="text-green-600">|</div>
            <div className="flex items-center gap-2 text-green-500">
              <Activity className="w-4 h-4" />
              <span>Real-time Monitoring Active</span>
            </div>
          </div>
        </motion.div>

        {/* Elite Stats Dashboard */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="mb-12"
        >
          <EliteStats />
        </motion.div>

        {/* Real-time Telemetry */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mb-12"
        >
          <RealTimeTelemetry isScanning={isScanning} />
        </motion.div>

        {/* Scan Control Center */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="mb-12"
        >
          <ScanControl onScanStart={handleScanStart} isScanning={isScanning} />
        </motion.div>

        {/* Elite Modules Grid */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
          className="mb-12"
        >
          <EliteModules />
        </motion.div>

        {/* Terminal Console */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 1.0 }}
          className="mb-8"
        >
          <div className="elite-card">
            <div className="flex items-center gap-3 mb-4">
              <Terminal className="w-6 h-6 text-green-400" />
              <h3 className="text-xl font-bold text-green-400">Elite Console</h3>
              <div className="flex-1"></div>
              <div className="live-indicator">
                <div className="live-dot"></div>
                <span className="text-sm text-green-500">LIVE</span>
              </div>
            </div>
            
            <div className="terminal scan-line">
              <div className="space-y-2">
                <div>[{new Date().toLocaleTimeString()}] RTK Elite v2.0 initialized</div>
                <div>[{new Date().toLocaleTimeString()}] Reality-Checker engine loaded</div>
                <div>[{new Date().toLocaleTimeString()}] Professional validation rules activated</div>
                <div>[{new Date().toLocaleTimeString()}] False positive rate: &lt;0.01%</div>
                <div>[{new Date().toLocaleTimeString()}] Elite modules ready: 12/12</div>
                {isScanning && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-yellow-400"
                  >
                    [{new Date().toLocaleTimeString()}] Advanced scan in progress...
                  </motion.div>
                )}
                <div className="text-green-400 font-bold">
                  rtk@elite:~$ _
                  <span className="animate-pulse">█</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Elite Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {[
            {
              icon: Shield,
              title: "Reality-Checker",
              desc: "Advanced validation engine",
              color: "text-green-400"
            },
            {
              icon: Zap,
              title: "SYN-RTT Profiler",
              desc: "Microsecond precision analysis",
              color: "text-yellow-400"
            },
            {
              icon: Network,
              title: "DNS Entropy Diff",
              desc: "Wildcard zone detection",
              color: "text-blue-400"
            },
            {
              icon: Target,
              title: "JA3 Collision",
              desc: "TLS fingerprint bypass",
              color: "text-purple-400"
            }
          ].map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, delay: 1.2 + (index * 0.1) }}
              className="elite-card text-center hover:scale-105 transition-transform duration-200"
            >
              <feature.icon className={`w-12 h-12 ${feature.color} mx-auto mb-4`} />
              <h4 className="text-lg font-semibold text-green-300 mb-2">{feature.title}</h4>
              <p className="text-green-600 text-sm">{feature.desc}</p>
            </motion.div>
          ))}
        </div>

        {/* Professional Certification */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 1.6 }}
          className="text-center py-8 border-t border-green-500/30"
        >
          <div className="flex items-center justify-center gap-8 text-green-600">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              <span>OWASP Compliant</span>
            </div>
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5" />
              <span>NIST Framework</span>
            </div>
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5" />
              <span>Enterprise Grade</span>
            </div>
          </div>
          <p className="text-green-700 mt-4 text-sm">
            Professional security assessment framework • Built by elite professionals for elite professionals
          </p>
        </motion.div>
      </main>
    </div>
  )
}