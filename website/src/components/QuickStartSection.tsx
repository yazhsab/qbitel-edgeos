import { QUICKSTART_STEPS } from '@/lib/constants'

export default function QuickStartSection() {
  return (
    <section id="quickstart" className="py-24 relative bg-cyber-surface/30">
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Quick Start</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            From zero to running firmware in under 10 minutes.
          </p>
        </div>

        <div className="space-y-4">
          {QUICKSTART_STEPS.map((step, i) => (
            <div key={i} className="flex gap-4 items-start">
              {/* Step number */}
              <div className="flex-shrink-0 w-8 h-8 rounded-full border border-cyber-cyan/30 bg-cyber-cyan/5 flex items-center justify-center">
                <span className="text-xs font-mono font-bold text-cyber-cyan">{i + 1}</span>
              </div>

              {/* Terminal */}
              <div className="flex-1 terminal-block">
                <div className="terminal-header">
                  <div className="terminal-dot bg-cyber-red/80" />
                  <div className="terminal-dot bg-cyber-yellow/80" />
                  <div className="terminal-dot bg-cyber-green/80" />
                  <span className="ml-2 text-xs text-gray-600 font-mono">{step.label}</span>
                </div>
                <div className="p-4">
                  <div className="flex gap-2">
                    <span className="text-cyber-cyan select-none">$</span>
                    <code className="text-cyber-green text-xs sm:text-sm break-all">{step.cmd}</code>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-12 text-center">
          <p className="text-sm text-gray-500 mb-4">
            Need more detail? Check the full guides:
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            {[
              ['Installation Guide', 'docs/INSTALLATION.md'],
              ['Deployment Guide', 'docs/DEPLOYMENT.md'],
              ['API Reference', 'docs/API.md'],
            ].map(([label, path]) => (
              <a
                key={label}
                href={`https://github.com/yazhsab/qbitel-edgeos/blob/main/${path}`}
                target="_blank"
                rel="noopener noreferrer"
                className="btn-neon text-xs"
              >
                {label}
              </a>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
