import { SITE_CONFIG } from '@/lib/constants'

const highlights = [
  { label: 'PQC Algorithms', value: 'ML-KEM-768, ML-DSA-65, FN-DSA-512' },
  { label: 'Runtime Model', value: 'Rust no_std, zero-heap deterministic core' },
  { label: 'Identity Primitive', value: 'PUF/eFUSE certificate-less trust' },
]

const risks = [
  'Encrypted telemetry captured today can be decrypted later.',
  'Infrastructure lifespans exceed classical cryptography timelines.',
  'Regulatory migration windows are fixed for 2030-2035.',
]

export default function HeroSection() {
  return (
    <section className="scanline-layer relative overflow-hidden pt-24">
      <div className="grid-mesh" />
      <div className="glow-orb left-0 top-16 h-56 w-56 bg-qedge-cyan/70" />
      <div className="glow-orb bottom-8 right-6 h-48 w-48 bg-qedge-amber/70" style={{ animationDelay: '1.6s' }} />

      <div className="section-wrap relative z-10 py-16 sm:py-20 lg:py-24">
        <div className="grid items-start gap-8 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="reveal-up" style={{ animationDelay: '80ms' }}>
            <span className="eyebrow">
              <span className="signal-dot" />
              Post-Quantum Foundation
            </span>
            <h1 className="mt-5 max-w-4xl text-4xl font-semibold leading-tight text-white sm:text-5xl lg:text-6xl">
              <span className="title-gradient">Securing Critical Infrastructure</span>
              <br />
              Before Quantum Decryption Becomes Operational
            </h1>
            <p className="text-muted mt-6 max-w-2xl text-base leading-relaxed sm:text-lg">
              {SITE_CONFIG.name} is a Rust-based edge runtime engineered for long-lifecycle systems that cannot wait for
              retrofitted security. Native PQC, hardware-rooted identity, and deterministic execution are built into the
              core.
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              <a href="#architecture" className="btn-primary">
                Explore Framework
              </a>
              <a href={SITE_CONFIG.github} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                Open Repository
              </a>
            </div>

            <div className="mt-8 flex flex-wrap gap-2">
              {['Rust no_std', 'Critical Infrastructure', 'Certificate-less Identity', 'Air-gapped Updates'].map((tag) => (
                <span key={tag} className="tech-chip">
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <div className="reveal-up space-y-5" style={{ animationDelay: '180ms' }}>
            <div className="surface-panel p-6">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-qedge-cyan">Threat Pressure</p>
              <ul className="mt-4 space-y-3">
                {risks.map((risk) => (
                  <li key={risk} className="flex gap-3 text-sm text-qedge-ink/90">
                    <span className="mt-1 h-2 w-2 rounded-full bg-qedge-amber" />
                    <span>{risk}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="surface-panel p-6">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-qedge-cyan">EdgeOS Signal Board</p>
              <div className="mt-4 space-y-4">
                {highlights.map((item) => (
                  <div key={item.label} className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                    <p className="text-xs uppercase tracking-[0.13em] text-qedge-muted">{item.label}</p>
                    <p className="mt-1 text-sm text-white">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
