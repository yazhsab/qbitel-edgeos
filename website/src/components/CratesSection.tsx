import { CRATES, SITE_CONFIG } from '@/lib/constants'

export default function CratesSection() {
  return (
    <section id="crates" className="py-24 relative bg-cyber-surface/30">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">10 Modular Crates</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            Each crate is independently compilable, testable, and auditable. Use what you need.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {CRATES.map((crate) => (
            <a
              key={crate.name}
              href={`${SITE_CONFIG.github}/tree/main/crates/${crate.name}`}
              target="_blank"
              rel="noopener noreferrer"
              className="card-cyber group flex flex-col"
            >
              <div className="flex items-center gap-2 mb-3">
                <span className="text-cyber-cyan font-mono text-xs">$</span>
                <h3 className="font-mono text-sm font-bold text-white group-hover:text-cyber-cyan transition-colors">
                  {crate.name}
                </h3>
              </div>
              <p className="text-xs text-gray-500 leading-relaxed flex-1">
                {crate.description}
              </p>
            </a>
          ))}
        </div>
      </div>
    </section>
  )
}
