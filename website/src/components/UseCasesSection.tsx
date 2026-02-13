import { USE_CASES } from '@/lib/constants'

export default function UseCasesSection() {
  return (
    <section id="usecases" className="py-24 relative">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Built for Critical Infrastructure</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            From power grids to defense networks. Qbitel EdgeOS protects the systems that society depends on.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {USE_CASES.map((uc, i) => (
            <div key={i} className="card-cyber group">
              <div className="text-4xl mb-4 group-hover:scale-110 transition-transform">{uc.icon}</div>
              <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyber-cyan transition-colors">
                {uc.title}
              </h3>
              <p className="text-sm text-gray-400 leading-relaxed mb-4">
                {uc.description}
              </p>
              <div className="flex flex-wrap gap-2">
                {uc.standards.map((std) => (
                  <span key={std} className="px-2 py-0.5 rounded text-xs font-mono bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/20">
                    {std}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
