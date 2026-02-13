import { EXAMPLES, SITE_CONFIG } from '@/lib/constants'

export default function ExamplesSection() {
  return (
    <section id="examples" className="py-24 relative bg-cyber-surface/30">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Real-World Examples</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            Complete, working applications demonstrating Qbitel EdgeOS in production scenarios.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {EXAMPLES.map((example) => (
            <a
              key={example.name}
              href={`${SITE_CONFIG.github}/tree/main/examples/${example.name}`}
              target="_blank"
              rel="noopener noreferrer"
              className="card-cyber group flex flex-col"
            >
              <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyber-cyan transition-colors">
                {example.title}
              </h3>
              <p className="text-sm text-gray-400 leading-relaxed mb-4 flex-1">
                {example.description}
              </p>

              {/* Feature tags */}
              <div className="flex flex-wrap gap-2 mb-4">
                {example.features.map((f) => (
                  <span key={f} className="px-2 py-0.5 rounded text-xs bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20">
                    {f}
                  </span>
                ))}
              </div>

              {/* Terminal block */}
              <div className="terminal-block">
                <div className="terminal-header">
                  <div className="terminal-dot bg-cyber-red/80" />
                  <div className="terminal-dot bg-cyber-yellow/80" />
                  <div className="terminal-dot bg-cyber-green/80" />
                  <span className="ml-2 text-xs text-gray-600 font-mono">{example.name}</span>
                </div>
                <div className="p-4">
                  <div className="flex gap-2">
                    <span className="text-cyber-cyan select-none">$</span>
                    <code className="text-cyber-green text-xs break-all">{example.command}</code>
                  </div>
                </div>
              </div>
            </a>
          ))}
        </div>
      </div>
    </section>
  )
}
