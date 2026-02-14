import { COMPLIANCE } from '@/lib/constants'

export default function ComplianceSection() {
  return (
    <section id="compliance" className="pb-20 pt-16 sm:pt-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Compliance Roadmap</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">Aligned to mandatory migration and sector standards.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            Transition plans and technical controls are mapped against evolving public standards and domain-specific
            requirements.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {COMPLIANCE.map((item, index) => (
            <article
              key={item.name}
              className="reveal-up rounded-2xl border border-white/10 bg-[#0b162a]/88 p-5"
              style={{ animationDelay: `${90 + index * 65}ms` }}
            >
              <div className="flex items-start justify-between gap-3">
                <h3 className="text-base font-semibold text-white">{item.name}</h3>
                <span
                  className={`rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] ${
                    item.status === 'implemented'
                      ? 'border border-qedge-cyan/35 bg-qedge-cyan/10 text-qedge-cyan'
                      : 'border border-qedge-amber/40 bg-qedge-amber/10 text-qedge-amber'
                  }`}
                >
                  {item.status === 'implemented' ? 'Implemented' : 'In Progress'}
                </span>
              </div>
              <p className="text-muted mt-2 text-sm">{item.domain}</p>
              <p className="mt-3 font-mono text-xs uppercase tracking-[0.14em] text-qedge-ink/75">{item.window}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
