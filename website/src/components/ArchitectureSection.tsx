import { ARCHITECTURE_LAYERS } from '@/lib/constants'

export default function ArchitectureSection() {
  return (
    <section id="architecture" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <span className="eyebrow">EdgeOS Framework</span>
            <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">Layered architecture for auditable trust.</h2>
            <p className="text-muted mt-4 text-base leading-relaxed">
              The stack is intentionally modular: cryptography, identity, attestation, recovery, and updates are isolated
              for independent validation and release control.
            </p>
          </div>
          <div className="surface-panel max-w-sm p-4">
            <p className="font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">Design Constraints</p>
            <p className="mt-2 text-sm text-qedge-ink/90">No heap allocation, deterministic scheduling, hardware-anchored identity.</p>
          </div>
        </div>

        <div className="space-y-3">
          {ARCHITECTURE_LAYERS.map((layer, index) => (
            <article
              key={layer.label}
              className="reveal-up flex flex-col gap-3 rounded-xl border border-white/10 bg-[#0c172b]/80 p-4 sm:flex-row sm:items-center sm:justify-between"
              style={{ animationDelay: `${100 + index * 65}ms` }}
            >
              <div>
                <p className="font-mono text-sm uppercase tracking-[0.14em] text-qedge-cyan">{layer.label}</p>
                <p className="mt-1 text-sm text-qedge-ink/85 sm:text-base">{layer.description}</p>
              </div>
              <span className="inline-flex rounded-full border border-qedge-amber/40 bg-qedge-amber/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.1em] text-qedge-amber">
                {layer.signal}
              </span>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
