import { EXAMPLES } from '@/lib/constants'

export default function ExamplesSection() {
  return (
    <section id="examples" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Operational Scenarios</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">Reference implementations for real deployments.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            Example pipelines demonstrate how to combine PQC, identity attestation, and secure lifecycle operations under
            production-like constraints.
          </p>
        </div>

        <div className="grid gap-5 lg:grid-cols-3">
          {EXAMPLES.map((example, index) => (
            <article
              key={example.name}
              className="reveal-up rounded-2xl border border-white/10 bg-[#0b162b]/90 p-5"
              style={{ animationDelay: `${100 + index * 90}ms` }}
            >
              <p className="font-mono text-xs uppercase tracking-[0.14em] text-qedge-cyan">{example.name}</p>
              <h3 className="mt-2 text-lg font-semibold text-white">{example.title}</h3>
              <p className="text-muted mt-3 text-sm leading-relaxed">{example.description}</p>
              <p className="mt-3 text-sm text-qedge-amber">{example.outcome}</p>

              <div className="terminal-shell mt-4">
                <p className="text-qedge-muted">$ {example.command}</p>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                {example.metrics.map((metric) => (
                  <span key={metric} className="tech-chip">
                    {metric}
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
