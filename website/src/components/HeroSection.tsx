import { SITE_CONFIG } from '@/lib/constants'

export default function HeroSection() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Animated Grid Background */}
      <div className="cyber-grid" />

      {/* Floating Particles */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {Array.from({ length: 20 }).map((_, i) => (
          <div
            key={i}
            className="particle"
            style={{
              left: `${Math.random() * 100}%`,
              animationDuration: `${8 + Math.random() * 12}s`,
              animationDelay: `${Math.random() * 10}s`,
            }}
          />
        ))}
      </div>

      {/* Content */}
      <div className="relative z-10 mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 text-center pt-20">
        {/* Version Badge */}
        <div className="inline-flex items-center gap-2 mb-8 px-4 py-1.5 rounded-full border border-cyber-cyan/20 bg-cyber-cyan/5">
          <span className="h-1.5 w-1.5 rounded-full bg-cyber-green animate-pulse" />
          <span className="text-xs font-mono text-cyber-cyan tracking-wider">
            v{SITE_CONFIG.version} — ACTIVE DEVELOPMENT
          </span>
        </div>

        {/* Main Headline */}
        <h1 className="font-display text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-black tracking-tight leading-[1.1]">
          <span className="text-white">Post-Quantum</span>
          <br />
          <span className="gradient-text">Secure OS</span>
          <br />
          <span className="text-white">for Edge Devices</span>
        </h1>

        {/* Subheadline */}
        <p className="mt-6 text-lg sm:text-xl text-gray-400 max-w-3xl mx-auto leading-relaxed">
          NIST-standardized PQC. Hardware-rooted identity. Secure boot. Mesh networking.
          <br className="hidden sm:block" />
          <span className="text-gray-300">Purpose-built for critical infrastructure. Written in Rust.</span>
        </p>

        {/* CTA Buttons */}
        <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
          <a href={SITE_CONFIG.github} target="_blank" rel="noopener noreferrer" className="btn-neon-fill text-base px-8 py-4 flex items-center gap-3">
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" /></svg>
            View on GitHub
          </a>
          <a href="#quickstart" className="btn-neon text-base px-8 py-4">
            Quick Start →
          </a>
        </div>

        {/* Tech badges */}
        <div className="mt-16 flex flex-wrap items-center justify-center gap-3">
          {['Rust', 'no_std', 'ML-KEM-768', 'ML-DSA-65', 'Apache-2.0'].map((badge) => (
            <span key={badge} className="px-3 py-1 rounded-md border border-cyber-border bg-cyber-surface/50 text-xs font-mono text-gray-400">
              {badge}
            </span>
          ))}
        </div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-cyber-bg to-transparent" />
    </section>
  )
}
