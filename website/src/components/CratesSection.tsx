import { CRATES, SITE_CONFIG } from '@/lib/constants'

export default function CratesSection() {
  return (
    <section id="crates" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Core Components</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">10 crates, one security operating model.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            Each crate can be inspected, tested, and integrated independently without compromising the full trust model.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          {CRATES.map((crateItem, index) => (
            <a
              key={crateItem.name}
              href={`${SITE_CONFIG.github}/tree/main/crates/${crateItem.name}`}
              target="_blank"
              rel="noopener noreferrer"
              className="reveal-up group rounded-xl border border-white/10 bg-[#0a1528]/85 p-4 transition-all duration-300 hover:-translate-y-1 hover:border-qedge-cyan/45"
              style={{ animationDelay: `${80 + index * 40}ms` }}
            >
              <p className="font-mono text-sm uppercase tracking-[0.14em] text-qedge-cyan">{crateItem.name}</p>
              <p className="mt-2 text-sm font-semibold text-white">{crateItem.focus}</p>
              <p className="text-muted mt-2 text-xs leading-relaxed">{crateItem.description}</p>
            </a>
          ))}
        </div>
      </div>
    </section>
  )
}
