import { COMPLIANCE } from '@/lib/constants'

export default function ComplianceSection() {
  return (
    <section id="compliance" className="py-24 relative">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Compliance Targets</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            Designed to meet the most demanding security and safety standards in critical infrastructure.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {COMPLIANCE.map((std) => (
            <div key={std.name} className="card-cyber flex items-start gap-4">
              <div className="flex-shrink-0 mt-0.5">
                {std.status === 'implemented' ? (
                  <div className="w-5 h-5 rounded-full bg-cyber-green/10 border border-cyber-green/30 flex items-center justify-center">
                    <svg className="w-3 h-3 text-cyber-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                ) : (
                  <div className="w-5 h-5 rounded-full bg-cyber-yellow/10 border border-cyber-yellow/30 flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-cyber-yellow/60 animate-pulse" />
                  </div>
                )}
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">{std.name}</h3>
                <p className="text-xs text-gray-500 mt-0.5">{std.domain}</p>
                <span className={`inline-flex mt-2 px-2 py-0.5 rounded text-xs font-mono ${
                  std.status === 'implemented'
                    ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/20'
                    : 'bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20'
                }`}>
                  {std.status === 'implemented' ? 'Implemented' : 'In Progress'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
